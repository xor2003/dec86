from __future__ import annotations

import contextlib
import logging
import os
import re
import sys

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypePointer
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import summarize_x86_16_callsite as _summarize_x86_16_callsite_fallback
from .decompiler_postprocess_calls import _cod_metadata_for_function_8616
from .decompiler_postprocess_utils import (
    _match_bp_stack_dereference_8616,
    _match_segmented_dereference_8616,
    _same_c_expression_8616,
    _stack_bp_displacement_8616,
    _structured_codegen_node_8616,
)

__all__ = [
    "TAIL_VALIDATION_FINGERPRINT_VERSION",
    "_bool_projection_fingerprint",
    "_c_constant_int_value",
    "_expr_fingerprint",
    "_extract_same_zero_compare_expr_8616",
    "_extract_zero_flag_source_expr_8616",
    "_function_for_call_context_8616",
    "build_x86_16_contextual_call_fingerprints",
    "_lookup_function_for_call_context_8616",
    "_location_fingerprint",
    "_normalize_zero_flag_comparison_8616",
    "_register_name",
    "_wrap_not_fingerprint",
]


TAIL_VALIDATION_FINGERPRINT_VERSION = 10
_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
log = logging.getLogger(__name__)
_EXPR_FINGERPRINT_CACHE_LIMIT_8616 = 50000


def _expr_fingerprint_cache_8616(project) -> dict[tuple[object, int, str], str]:
    cache = getattr(project, "_inertia_tail_validation_expr_fingerprint_cache_8616", None)
    if not isinstance(cache, dict) or len(cache) > _EXPR_FINGERPRINT_CACHE_LIMIT_8616:
        cache = {}
        with contextlib.suppress(Exception):
            setattr(project, "_inertia_tail_validation_expr_fingerprint_cache_8616", cache)
    return cache


def _first_codegen_8616(*nodes) -> object | None:
    for node in nodes:
        codegen = getattr(node, "codegen", None)
        if codegen is not None:
            return codegen
    return None


def _safe_rebuild_binary_8616(op: str, lhs, rhs, template) -> object:
    if lhs is getattr(template, "lhs", None) and rhs is getattr(template, "rhs", None):
        return template
    codegen = _first_codegen_8616(template, lhs, rhs)
    if codegen is None:
        return template
    return CBinaryOp(op, lhs, rhs, codegen=codegen)


def _safe_rebuild_unary_8616(op: str, operand, template) -> object:
    if operand is getattr(template, "operand", None):
        return template
    codegen = _first_codegen_8616(template, operand)
    if codegen is None:
        return template
    return CUnaryOp(op, operand, codegen=codegen)


def _segment_linear_lowering_allowed(node, segment_reg: str, project=None) -> bool:
    codegen = getattr(node, "codegen", None)
    for owner in (codegen, project):
        lowering = getattr(owner, "_inertia_segmented_memory_lowering", None)
        if not isinstance(lowering, dict):
            continue
        entry = lowering.get(segment_reg.upper())
        if isinstance(entry, dict) and bool(entry.get("allow_linear_lowering", False)):
            return True
    return False


def _register_name(project, reg_offset: int) -> str:
    name = project.arch.register_names.get(reg_offset)
    return name if isinstance(name, str) else f"reg@{reg_offset}"


def _dirty_attr_8616(obj, attr: str):
    try:
        return getattr(obj, attr, None)
    except (AttributeError, TypeError, ValueError):
        return None


def _dirty_register_fingerprint_8616(node, project) -> str | None:
    dirty = getattr(node, "dirty", None)
    if dirty is None:
        return None
    reg_offset = None
    for attr in ("reg_offset", "reg", "variable_offset"):
        value = _dirty_attr_8616(dirty, attr)
        if isinstance(value, int):
            reg_offset = value
            break
    if not isinstance(reg_offset, int):
        return None
    bits = _dirty_attr_8616(dirty, "bits")
    size = _dirty_attr_8616(dirty, "size")
    size_bytes = int(bits // 8) if isinstance(bits, int) and bits > 0 else int(size) if isinstance(size, int) else None
    registers = getattr(getattr(project, "arch", None), "registers", None)
    if isinstance(registers, dict) and isinstance(size_bytes, int) and size_bytes > 0:
        exact_names = sorted(
            name
            for name, reg_info in registers.items()
            if (
                isinstance(name, str)
                and isinstance(reg_info, tuple)
                and len(reg_info) >= 2
                and reg_info[0] == reg_offset
                and reg_info[1] == size_bytes
            )
        )
        if exact_names:
            return f"reg:{exact_names[0]}"
    register_names = getattr(getattr(project, "arch", None), "register_names", None)
    if not isinstance(register_names, dict) or reg_offset not in register_names:
        return None
    return f"reg:{_register_name(project, reg_offset)}"


def _c_constant_int_value(node) -> int | None:
    if isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int):
        return node.value
    return None


def _tail_validation_stack_alias_refusal_stats_8616(codegen) -> dict[str, int]:
    stats = getattr(codegen, "_inertia_tail_validation_stack_alias_refusals", None)
    if not isinstance(stats, dict):
        stats = {}
        codegen._inertia_tail_validation_stack_alias_refusals = stats
    return stats


def _record_stack_alias_refusal_8616(codegen, reason: str) -> None:
    if codegen is None or not isinstance(reason, str) or not reason:
        return
    stats = _tail_validation_stack_alias_refusal_stats_8616(codegen)
    stats[reason] = int(stats.get(reason, 0) or 0) + 1


def _stack_slot_fingerprint_from_slot_8616(offset: int, size: int | None = None) -> str:
    size_text = f":size{size}" if isinstance(size, int) and size > 0 else ""
    return f"stack_slot:SS:BP{offset:+#x}{size_text}"


def _source_arg_fingerprint_from_slot_8616(name: str, offset: int, size: int | None = None) -> str:
    size_text = f":size{size}" if isinstance(size, int) and size > 0 else ""
    return f"stack_arg:{name}{size_text}:bp{offset:+#x}"


def _type_size_bytes_8616(type_, *, default: int = 2) -> int:
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _target_abi_type_size_bytes_8616(type_, project, *, default: int = 2) -> int:
    arch_name = getattr(getattr(project, "arch", None), "name", None)
    if arch_name == "86_16":
        type_name = type(type_).__name__
        if type_name in {"SimTypeChar", "SimTypeNum"}:
            return 1
        if type_name in {"SimTypeShort", "SimTypeInt", "SimTypeBool"}:
            return 2
        if type_name == "SimTypeLong":
            return 4
        if type_name == "SimTypeLongLong":
            return 8
        if type_name == "SimTypePointer":
            return 2
    return _type_size_bytes_8616(type_, default=default)


def _source_arg_names_by_offset_8616(function) -> dict[int, str]:
    prototype = getattr(function, "prototype", None) if function is not None else None
    arg_names = tuple(arg_name for arg_name in (getattr(prototype, "arg_names", ()) or ()) if isinstance(arg_name, str))
    arg_types = tuple(getattr(prototype, "args", ()) or ())
    if not arg_names or len(arg_names) != len(arg_types):
        return {}
    offset = 4
    names_by_offset: dict[int, str] = {}
    for arg_name, arg_type in zip(arg_names, arg_types, strict=False):
        names_by_offset[offset] = arg_name
        offset += max(2, _type_size_bytes_8616(arg_type))
    return names_by_offset


def _source_arg_sizes_by_offset_8616(function, project) -> dict[int, int]:
    prototype = getattr(function, "prototype", None) if function is not None else None
    arg_names = tuple(arg_name for arg_name in (getattr(prototype, "arg_names", ()) or ()) if isinstance(arg_name, str))
    arg_types = tuple(getattr(prototype, "args", ()) or ())
    if not arg_names or len(arg_names) != len(arg_types):
        return {}
    offset = 4
    sizes_by_offset: dict[int, int] = {}
    for _arg_name, arg_type in zip(arg_names, arg_types, strict=False):
        size = _target_abi_type_size_bytes_8616(arg_type, project)
        sizes_by_offset[offset] = size
        offset += max(2, size)
    return sizes_by_offset


def _cfunc_source_arg_names_by_offset_8616(cfunc) -> dict[int, str]:
    names_by_offset: dict[int, str] = {}
    for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset <= 0:
            continue
        name = getattr(arg, "name", None) or getattr(variable, "name", None)
        if not isinstance(name, str) or not name or _stack_name_is_generic_for_validation_8616(name):
            continue
        names_by_offset[offset] = name
    return names_by_offset


def _cfunc_source_arg_sizes_by_offset_8616(cfunc) -> dict[int, int]:
    sizes_by_offset: dict[int, int] = {}
    for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = getattr(variable, "offset", None)
        size = getattr(variable, "size", None)
        if isinstance(offset, int) and offset > 0 and isinstance(size, int) and size > 0:
            sizes_by_offset[offset] = size
    return sizes_by_offset


def _source_arg_match_by_offset_8616(
    function,
    project,
    offset: int,
    *,
    size: int | None,
) -> tuple[str, int, int | None] | None:
    source_names_by_offset = _source_arg_names_by_offset_8616(function)
    source_sizes_by_offset = _source_arg_sizes_by_offset_8616(function, project)
    source_name = source_names_by_offset.get(offset)
    if isinstance(source_name, str) and source_name:
        return source_name, offset, source_sizes_by_offset.get(offset, size)
    if len(source_names_by_offset) != 1:
        return None
    [(only_offset, only_name)] = source_names_by_offset.items()
    source_size = source_sizes_by_offset.get(only_offset)
    if not isinstance(only_name, str) or not only_name:
        return None
    if isinstance(size, int) and isinstance(source_size, int) and size != source_size:
        return None
    # Some MSC switch-helper lowering snapshots expose the sole source argument
    # through a transient positive-BP helper slot. In one-argument functions the
    # source prototype gives a stronger storage identity than that helper slot.
    return only_name, only_offset, source_size if isinstance(source_size, int) else size


def _source_arg_location_fingerprint_8616(node, project) -> str | None:
    codegen = getattr(node, "codegen", None)
    active_codegen = getattr(project, "_inertia_tail_validation_active_codegen", None)
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        codegen = active_codegen
        cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        codegen = active_codegen
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
        return None
    offset = getattr(variable, "offset", None)
    if not isinstance(offset, int) or offset <= 0:
        return None
    name = getattr(node, "name", None) or getattr(variable, "name", None)
    if not isinstance(name, str) or not name:
        return None
    function = _lookup_function_for_call_context_8616(project, func_addr)
    variable_size = getattr(variable, "size", None)
    source_names_by_offset = _source_arg_names_by_offset_8616(function)
    source_name = source_names_by_offset.get(offset)
    if isinstance(source_name, str) and source_name:
        source_size = _source_arg_sizes_by_offset_8616(function, project).get(offset, variable_size)
        return _source_arg_fingerprint_from_slot_8616(
            source_name,
            offset,
            source_size if isinstance(source_size, int) and source_size > 0 else None,
        )
    source_name = _cfunc_source_arg_names_by_offset_8616(cfunc).get(offset)
    if not isinstance(source_name, str) or not source_name:
        return None
    size = _cfunc_source_arg_sizes_by_offset_8616(cfunc).get(offset, variable_size)
    return _source_arg_fingerprint_from_slot_8616(
        source_name,
        offset,
        size if isinstance(size, int) and size > 0 else None,
    )


def _lookup_widened_carrier_proof_8616(value, codegen):
    def _impl():
        mapping = getattr(codegen, "_inertia_tail_validation_widened_carriers", None)
        if not isinstance(mapping, dict):
            return None
        variable = getattr(value, "variable", None)
        name = getattr(value, "name", None) or getattr(variable, "name", None)
        size = getattr(variable, "size", None)
        offset = getattr(variable, "offset", None)
        keys = [
            id(value),
            id(variable) if variable is not None else None,
            name,
            (name, size) if isinstance(name, str) and isinstance(size, int) else None,
            (offset, size) if isinstance(offset, int) and isinstance(size, int) else None,
        ]
        for key in keys:
            if key is not None and key in mapping:
                return mapping[key]
        return None

    return _impl()


def _candidate_widened_keys_8616(value) -> tuple[object, ...]:
    variable = getattr(value, "variable", None)
    name = getattr(value, "name", None) or getattr(variable, "name", None)
    size = getattr(variable, "size", None)
    offset = getattr(variable, "offset", None)
    return tuple(
        key
        for key in (
            id(value),
            id(variable) if variable is not None else None,
            name,
            (name, size) if isinstance(name, str) and isinstance(size, int) else None,
            (offset, size) if isinstance(offset, int) and isinstance(size, int) else None,
        )
        if key is not None
    )


def _widened_carrier_slot_fingerprint_8616(var_name: str | None, *, value=None, variable=None, codegen) -> str | None:
    proof = _lookup_widened_carrier_proof_8616(value, codegen) if value is not None else None
    if proof is None and isinstance(var_name, str):
        mapping = getattr(codegen, "_inertia_tail_validation_widened_carriers", None)
        if isinstance(mapping, dict):
            proof = mapping.get(var_name)
    if not isinstance(proof, dict):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_recurrence_proof")
        return None
    offset = proof.get("offset")
    size = proof.get("size")
    carrier_size = proof.get("carrier_size")
    if not isinstance(offset, int):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_stable_slot")
        return None
    if not isinstance(size, int):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_materialized_local")
        return None
    if isinstance(carrier_size, int) and size <= carrier_size:
        _record_stack_alias_refusal_8616(codegen, "carrier_width_not_widened")
        return None
    return _stack_slot_fingerprint_from_slot_8616(offset, size)


def _stack_name_is_generic_for_validation_8616(name: object) -> bool:
    return (
        isinstance(name, str)
        and re.fullmatch(
            r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)",
            name,
        )
        is not None
    )


def _resolve_validation_copy_alias_expr_8616(node, *, seen_var_ids: set[int] | None = None):
    def _impl():
        nonlocal node, seen_var_ids
        node = _strip_validation_casts(node)
        if not isinstance(node, CVariable):
            return None
        variable = getattr(node, "variable", None)
        if variable is None:
            return None
        codegen = getattr(node, "codegen", None)
        if codegen is None:
            return None
        name = getattr(node, "name", None) or getattr(variable, "name", None)
        if not _stack_name_is_generic_for_validation_8616(name) and not isinstance(variable, SimRegisterVariable):
            return None
        variable_id = id(variable)
        if seen_var_ids is None:
            seen_var_ids = set()
        if variable_id in seen_var_ids:
            return None
        seen_var_ids.add(variable_id)
        assignment_maps = _validation_assignment_maps_8616(codegen)
        if assignment_maps is None:
            return None
        var_id_map, name_map, reg_map, first_name_map, first_reg_map = assignment_maps

        rhs = _validation_alias_rhs_lookup_8616(
            variable=variable,
            variable_id=variable_id,
            name=name,
            var_id_map=var_id_map,
            name_map=name_map,
            reg_map=reg_map,
        )
        resolved_rhs = _acceptable_validation_expr_rhs_8616(rhs)
        if (
            resolved_rhs is not None
            and resolved_rhs is not node
            and not _rhs_references_same_variable_8616(resolved_rhs, variable)
        ):
            return resolved_rhs
        if rhs is None and isinstance(variable, SimRegisterVariable):
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                first_rhs = _acceptable_validation_expr_rhs_8616(first_reg_map.get((reg, size)))
                if (
                    first_rhs is not None
                    and first_rhs is not node
                    and not _rhs_references_same_variable_8616(first_rhs, variable)
                ):
                    return first_rhs
        if isinstance(name, str):
            # Validation-only fallback: generic stack carriers often receive a
            # final trivial/non-stack update after their initial widened stack-slot
            # seed is established. Preserve the earliest explicit stack proof for
            # fingerprint canonicalization when the direct map is non-stack noise.
            first_rhs = _acceptable_validation_expr_rhs_8616(first_name_map.get(name))
            if (
                first_rhs is not None
                and first_rhs is not node
                and not _rhs_references_same_variable_8616(first_rhs, variable)
            ):
                return first_rhs
        return None

    return _impl()


def _validation_assignment_maps_8616(codegen):
    try:
        from .lowering.real_mode_linear import _ensure_assignment_maps_8616
    except Exception as ex:
        log.debug("assignment map import failed: %s", ex)
        return None
    try:
        var_id_map, name_map, reg_map, _multi_var, _multi_name, _multi_reg, first_name_map, first_reg_map = (
            _ensure_assignment_maps_8616(codegen)
        )
    except Exception:
        return None
    return var_id_map, name_map, reg_map, first_name_map, first_reg_map


def _validation_alias_rhs_lookup_8616(*, variable, variable_id: int, name, var_id_map, name_map, reg_map):
    rhs = var_id_map.get(variable_id)
    if rhs is None and isinstance(name, str):
        rhs = name_map.get(name)
    if rhs is None and isinstance(variable, SimRegisterVariable):
        reg = getattr(variable, "reg", None)
        size = getattr(variable, "size", None)
        if isinstance(reg, int) and isinstance(size, int):
            rhs = reg_map.get((reg, size))
    return rhs


def _acceptable_stack_alias_rhs_8616(value):
    value = _strip_validation_casts(value)
    if isinstance(value, (CVariable, CIndexedVariable)):
        return value
    if isinstance(value, CUnaryOp) and value.op in {"Dereference", "Reference"}:
        return value
    return None


def _dirty_virtual_name_8616(node) -> str | None:
    dirty = getattr(node, "dirty", None)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        return f"vvar_{varid}"
    tmp_idx = getattr(dirty, "tmp_idx", None)
    if isinstance(tmp_idx, int):
        return f"tmp_{tmp_idx}"
    return None


def _acceptable_validation_expr_rhs_8616(value):
    value = _strip_validation_casts(value)
    if isinstance(value, (CConstant, CVariable, CIndexedVariable, CDirtyExpression)):
        return value
    if isinstance(value, CUnaryOp):
        if value.op in {"Dereference", "Reference"}:
            return value
        operand = _acceptable_validation_expr_rhs_8616(value.operand)
        return value if operand is not None else None
    if isinstance(value, CBinaryOp):
        lhs = _acceptable_validation_expr_rhs_8616(value.lhs)
        rhs = _acceptable_validation_expr_rhs_8616(value.rhs)
        return value if lhs is not None and rhs is not None else None
    if isinstance(value, CITE):
        cond = _acceptable_validation_expr_rhs_8616(value.cond)
        iftrue = _acceptable_validation_expr_rhs_8616(value.iftrue)
        iffalse = _acceptable_validation_expr_rhs_8616(value.iffalse)
        return value if cond is not None and iftrue is not None and iffalse is not None else None
    return None


def _resolve_validation_dirty_alias_expr_8616(node):
    codegen = getattr(node, "codegen", None)
    if codegen is None:
        return None
    name = _dirty_virtual_name_8616(node)
    if not isinstance(name, str):
        return None
    assignment_maps = _validation_assignment_maps_8616(codegen)
    if assignment_maps is None:
        return None
    _var_id_map, name_map, _reg_map, first_name_map, _first_reg_map = assignment_maps
    rhs = name_map.get(name)
    resolved = _acceptable_validation_expr_rhs_8616(rhs)
    if os.environ.get("INERTIA_DEBUG_TAIL_DIRTY_ALIAS"):
        log.warning(
            "[tail-dirty-alias] name=%r rhs=%r resolved=%r first_rhs=%r",
            name,
            rhs,
            resolved,
            first_name_map.get(name),
        )
    if resolved is not None and resolved is not node:
        return resolved
    first_rhs = first_name_map.get(name)
    resolved = _acceptable_validation_expr_rhs_8616(first_rhs)
    if resolved is not None and resolved is not node:
        return resolved
    return None


def _rhs_references_same_variable_8616(value, variable) -> bool:
    pending = [_strip_validation_casts(value)]
    seen_nodes: set[int] = set()
    while pending:
        current = _strip_validation_casts(pending.pop())
        if current is None:
            continue
        current_id = id(current)
        if current_id in seen_nodes:
            continue
        seen_nodes.add(current_id)
        if isinstance(current, CVariable) and getattr(current, "variable", None) is variable:
            return True
        for attr in ("variable", "index", "operand", "lhs", "rhs", "expr"):
            if hasattr(current, attr):
                pending.append(getattr(current, attr, None))
    return False


def _debug_tail_stack_alias_8616(
    codegen,
    *,
    node=None,
    candidate: str | None = None,
    alias_keys: tuple[str, ...] = (),
    binding: str | None = None,
    final: str | None = None,
) -> None:
    def _impl():
        if not os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            return
        cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        delta = (
            getattr(getattr(codegen, "project", None), "_inertia_original_linear_delta", None)
            if codegen is not None
            else None
        )
        original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
        target_text = os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and original != target_addr:
            return
        try:
            c_repr = node.c_repr(indent=0) if node is not None else None
        except Exception:  # noqa: BLE001
            c_repr = str(node) if node is not None else None
        sys.stderr.write(
            "[TAIL_STACK_ALIAS] "
            f"func={original:#x} raw={c_repr!r} candidate={candidate!r} "
            f"alias_keys={alias_keys!r} binding={binding!r} final={final!r}\n"
        )
        sys.stderr.flush()

    return _impl()


def _debug_tail_stack_alias_indexed_8616(
    codegen,
    *,
    node=None,
    base_var=None,
    index_value=None,
    bridge_key=None,
    bridge_value=None,
    alias_base_offset=None,
    fallback_offset=None,
    selected=None,
    note: str,
) -> None:
    def _impl():
        if not os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            return
        cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        delta = (
            getattr(getattr(codegen, "project", None), "_inertia_original_linear_delta", None)
            if codegen is not None
            else None
        )
        original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
        target_text = os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and original != target_addr:
            return
        try:
            c_repr = node.c_repr(indent=0) if node is not None else None
        except Exception:  # noqa: BLE001
            c_repr = str(node) if node is not None else None
        base_offset = getattr(base_var, "offset", None)
        base_size = getattr(base_var, "size", None)
        base_name = getattr(base_var, "name", None)
        sys.stderr.write(
            "[TAIL_STACK_ALIAS_INDEXED] "
            f"func={original:#x} note={note} raw={c_repr!r} "
            f"base_name={base_name!r} base_offset={base_offset!r} base_size={base_size!r} "
            f"index={index_value!r} bridge_key={bridge_key!r} bridge_value={bridge_value!r} "
            f"alias_base_offset={alias_base_offset!r} fallback_offset={fallback_offset!r} "
            f"selected={selected!r}\n"
        )
        sys.stderr.flush()

    return _impl()


def _stack_alias_map_8616(codegen) -> dict[int, tuple[object, int]]:
    def _impl():
        cached = getattr(codegen, "_inertia_stack_pointer_aliases_for_cvars", None)
        cfunc = getattr(codegen, "cfunc", None)
        root = getattr(cfunc, "statements", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is root and isinstance(cached[1], dict):
            return cached[1]
        if root is None:
            return {}

        def _is_pointer_capable_stack_variable(var: object, cvar: object | None = None) -> bool:
            if not isinstance(var, SimStackVariable):
                return False
            if getattr(var, "base", None) != "bp":
                return False
            size = getattr(var, "size", None)
            if isinstance(size, int) and size >= 2:
                return True
            var_type = getattr(cvar, "variable_type", None)
            return isinstance(var_type, SimTypePointer)

        def _is_bp_stack_var(expr) -> bool:
            expr = _strip_validation_casts(expr)
            if isinstance(expr, CUnaryOp) and expr.op == "Reference":
                expr = _strip_validation_casts(expr.operand)
            if not isinstance(expr, CVariable):
                return False
            var = getattr(expr, "variable", None)
            return isinstance(var, SimStackVariable) and getattr(var, "base", None) == "bp"

        def _resolve_alias_expr(expr, aliases):
            expr = _strip_validation_casts(expr)
            if isinstance(expr, CVariable):
                var = getattr(expr, "variable", None)
                if not isinstance(var, SimStackVariable) or getattr(var, "base", None) != "bp":
                    return None
                alias = aliases.get(id(var))
                if alias is not None:
                    return alias
                if _is_pointer_capable_stack_variable(var, expr):
                    return expr, 0
                return None
            if isinstance(expr, CUnaryOp) and expr.op == "Reference":
                operand = _strip_validation_casts(expr.operand)
                if _is_bp_stack_var(operand):
                    return operand, 0
                return None
            if isinstance(expr, CBinaryOp) and expr.op in {"Add", "Sub"}:
                lhs = _resolve_alias_expr(expr.lhs, aliases)
                rhs = _resolve_alias_expr(expr.rhs, aliases)
                lhs_value = _c_constant_int_value(_strip_validation_casts(expr.lhs))
                rhs_value = _c_constant_int_value(_strip_validation_casts(expr.rhs))
                if lhs is not None and isinstance(rhs_value, int):
                    base, offset = lhs
                    return base, offset + (rhs_value if expr.op == "Add" else -rhs_value)
                if rhs is not None and isinstance(lhs_value, int) and expr.op == "Add":
                    base, offset = rhs
                    return base, offset + lhs_value
            return None

        def _alias_stable_key(resolved: tuple[object, int]) -> tuple[int, int]:
            base, offset = resolved
            variable = getattr(base, "variable", None)
            return (id(variable) if variable is not None else id(base), offset)

        def _iter_alias_assignment_candidates(start):
            seen: set[int] = set()
            stack = [start]
            visited = 0
            while stack:
                current = stack.pop()
                current_id = id(current)
                if current_id in seen:
                    continue
                seen.add(current_id)
                visited += 1
                if visited > max_nodes:
                    setattr(codegen, "_inertia_tail_validation_stack_alias_candidate_budget_exceeded", True)
                    break
                if isinstance(current, CAssignment):
                    yield current
                    continue
                if isinstance(current, CStatements):
                    stack.extend(reversed(tuple(getattr(current, "statements", ()) or ())))
                    continue
                if isinstance(current, CExpressionStatement):
                    expr = getattr(current, "expr", None)
                    if expr is not None:
                        stack.append(expr)
                    continue
                if isinstance(current, CIfElse):
                    else_node = getattr(current, "else_node", None)
                    if else_node is not None:
                        stack.append(else_node)
                    for _, body in reversed(tuple(getattr(current, "condition_and_nodes", ()) or ())):
                        stack.append(body)
                    continue
                if isinstance(current, (CForLoop, CWhileLoop, CDoWhileLoop)):
                    for attr in ("body", "iterator", "initializer"):
                        child = getattr(current, attr, None)
                        if child is not None:
                            stack.append(child)
                    continue
                if isinstance(current, (list, tuple)):
                    stack.extend(reversed(tuple(current)))

        aliases: dict[int, tuple[object, int]] = {}
        alias_keys: dict[int, tuple[int, int]] = {}
        changed = True
        iteration_count = 0
        max_iterations = 32
        visited_nodes = 0
        max_nodes = 4096
        budget_exceeded = False
        while changed and iteration_count < max_iterations:
            iteration_count += 1
            changed = False
            for node in _iter_alias_assignment_candidates(root):
                visited_nodes += 1
                if visited_nodes > max_nodes:
                    budget_exceeded = True
                    changed = False
                    break
                if not isinstance(node, CAssignment):
                    continue
                lhs = _strip_validation_casts(getattr(node, "lhs", None))
                if not isinstance(lhs, CVariable):
                    continue
                lhs_var = getattr(lhs, "variable", None)
                if not isinstance(lhs_var, SimStackVariable) or getattr(lhs_var, "base", None) != "bp":
                    continue
                resolved = _resolve_alias_expr(getattr(node, "rhs", None), aliases)
                if resolved is None:
                    continue
                if not _is_pointer_capable_stack_variable(lhs_var, lhs):
                    rhs_expr = _strip_validation_casts(getattr(node, "rhs", None))
                    if not (
                        isinstance(rhs_expr, CUnaryOp) and rhs_expr.op == "Reference" or isinstance(rhs_expr, CBinaryOp)
                    ):
                        continue
                lhs_key = id(lhs_var)
                resolved_key = _alias_stable_key(resolved)
                if alias_keys.get(lhs_key) != resolved_key:
                    aliases[lhs_key] = resolved
                    alias_keys[lhs_key] = resolved_key
                    changed = True
            if budget_exceeded:
                break
        if changed or budget_exceeded:
            aliases = {}
            setattr(codegen, "_inertia_tail_validation_stack_alias_incomplete", True)
        setattr(codegen, "_inertia_tail_validation_stack_alias_iterations", iteration_count)
        setattr(codegen, "_inertia_tail_validation_stack_alias_nodes", visited_nodes)
        setattr(codegen, "_inertia_stack_pointer_aliases_for_cvars", (root, aliases))
        setattr(codegen, "_inertia_tail_validation_stack_pointer_aliases", aliases)
        return aliases

    return _impl()


def _materialized_local_map_8616(codegen) -> dict[int, tuple[int | None, str | None]]:
    def _impl():
        materialized: dict[int, tuple[int | None, str | None]] = {}

        def _record(offset: int, size: int | None, name: str | None) -> None:
            current = materialized.get(offset)
            if current is None:
                materialized[offset] = (size, name)
                return
            current_size, current_name = current
            if isinstance(size, int) and (not isinstance(current_size, int) or size > current_size):
                materialized[offset] = (size, name if name is not None else current_name)

        cfunc = getattr(codegen, "cfunc", None)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
                    continue
                offset = getattr(variable, "offset", None)
                if not isinstance(offset, int):
                    continue
                size = getattr(variable, "size", None)
                name = getattr(variable, "name", None) or getattr(cvar, "name", None)
                _record(offset, size if isinstance(size, int) else None, name if isinstance(name, str) else None)
        bindings = getattr(codegen, "_inertia_stack_variable_bindings", None)
        if isinstance(bindings, tuple | list):
            for binding in bindings:
                offset = getattr(binding, "bp_offset", None)
                size = getattr(binding, "size", None)
                name = getattr(binding, "var_name", None)
                if isinstance(offset, int):
                    _record(offset, size if isinstance(size, int) else None, name if isinstance(name, str) else None)
        return materialized

    return _impl()


def _stack_canonicalization_bridges_8616(codegen) -> dict[tuple[str, int, int], int]:
    bridges = getattr(codegen, "_inertia_stack_canonicalization_bridges", None)
    return bridges if isinstance(bridges, dict) else {}


def canonicalize_stack_alias_fingerprint_8616(value, *, stack_alias_map, materialized_local_map):
    if not isinstance(value, int):
        return None
    entry = materialized_local_map.get(value)
    if entry is None:
        return None
    size, name = entry
    return _stack_slot_fingerprint_from_slot_8616(value, size)


def _source_arg_stack_slot_fingerprint_8616(offset: int, codegen, *, size: int | None = None) -> str | None:
    if not isinstance(offset, int) or offset <= 0 or codegen is None:
        return None
    cfunc = getattr(codegen, "cfunc", None)
    project = getattr(codegen, "project", None)
    active_codegen = getattr(project, "_inertia_tail_validation_active_codegen", None)
    func_addr = getattr(cfunc, "addr", None)
    if (cfunc is None or not isinstance(func_addr, int)) and active_codegen is not None:
        codegen = active_codegen
        cfunc = getattr(codegen, "cfunc", None)
        project = getattr(codegen, "project", project)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int) or project is None:
        _debug_source_arg_stack_slot_8616(
            codegen,
            offset=offset,
            size=size,
            reason="missing_function_context",
            final=None,
        )
        return None
    function = _lookup_function_for_call_context_8616(project, func_addr)
    source_match = _source_arg_match_by_offset_8616(function, project, offset, size=size)
    if source_match is not None:
        source_name, source_offset, source_size = source_match
    else:
        source_name = _cfunc_source_arg_names_by_offset_8616(cfunc).get(offset)
        source_offset = offset
        source_size = _cfunc_source_arg_sizes_by_offset_8616(cfunc).get(offset, size)
    if not isinstance(source_name, str) or not source_name:
        _debug_source_arg_stack_slot_8616(
            codegen,
            offset=offset,
            size=size,
            reason="no_source_arg_name",
            final=None,
        )
        return None
    final = _source_arg_fingerprint_from_slot_8616(
        source_name,
        source_offset,
        source_size if isinstance(source_size, int) and source_size > 0 else None,
    )
    _debug_source_arg_stack_slot_8616(
        codegen,
        offset=offset,
        size=size,
        reason="matched",
        final=final,
    )
    return final


def _debug_source_arg_stack_slot_8616(
    codegen,
    *,
    offset: int,
    size: int | None,
    reason: str,
    final: str | None,
) -> None:
    if not os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
        return
    cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    delta = (
        getattr(getattr(codegen, "project", None), "_inertia_original_linear_delta", None)
        if codegen is not None
        else None
    )
    original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
    target_text = os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and original != target_addr:
        return
    sys.stderr.write(
        "[TAIL_SOURCE_ARG_SLOT] "
        f"func={original!r} offset={offset:+#x} size={size!r} reason={reason!r} final={final!r}\n"
    )
    sys.stderr.flush()


def _canonical_or_unresolved_stack_fingerprint_8616(offset: int, codegen, *, source: str, node=None) -> str:
    def _impl():
        if source == "stack_var":
            variable = getattr(node, "variable", None)
            size = getattr(variable, "size", None)
            if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
                materialized_local_map = _materialized_local_map_8616(codegen) if codegen is not None else {}
                materialized_size = materialized_local_map.get(offset, (None, None))[0]
                if isinstance(materialized_size, int) and (not isinstance(size, int) or materialized_size > size):
                    size = materialized_size
                if offset > 0:
                    source_arg = _source_arg_stack_slot_fingerprint_8616(
                        offset,
                        codegen,
                        size=size if isinstance(size, int) and size > 0 else None,
                    )
                    if source_arg is not None:
                        return source_arg
                return _stack_slot_fingerprint_from_slot_8616(
                    offset,
                    size if isinstance(size, int) and size > 0 else None,
                )
        if source == "word_pair":
            source_arg = _source_arg_stack_slot_fingerprint_8616(offset, codegen, size=2)
            if source_arg is not None:
                return source_arg
            return _stack_slot_fingerprint_from_slot_8616(offset, 2)
        source_arg = _source_arg_stack_slot_fingerprint_8616(offset, codegen)
        if source_arg is not None:
            return source_arg
        materialized_local_map = _materialized_local_map_8616(codegen) if codegen is not None else {}
        normalized = canonicalize_stack_alias_fingerprint_8616(
            offset,
            stack_alias_map={},
            materialized_local_map=materialized_local_map,
        )
        if normalized is not None:
            _debug_tail_stack_alias_8616(
                codegen,
                node=node,
                candidate=f"stack:{offset:+#x}",
                alias_keys=(),
                binding=f"bp{offset:+#x}",
                final=normalized,
            )
            return normalized
        stack_alias_map = _stack_alias_map_8616(codegen) if codegen is not None else {}
        if codegen is None:
            return f"stack:{offset:+#x}"
        has_alias_context = bool(
            stack_alias_map or materialized_local_map or getattr(codegen, "_inertia_stack_variable_bindings", None)
        )
        if has_alias_context:
            unresolved = f"unresolved_stack_carrier:SS:BP{offset:+#x}:{source}"
            _debug_tail_stack_alias_8616(
                codegen,
                node=node,
                candidate=f"stack:{offset:+#x}",
                alias_keys=tuple(sorted(str(key) for key in stack_alias_map.keys())),
                binding=None,
                final=unresolved,
            )
            return unresolved
        return f"stack:{offset:+#x}"

    return _impl()


def _resolve_stack_alias_base_offset_8616(base_expr, codegen, *, seen: set[int] | None = None) -> int | None:
    def _impl():
        nonlocal base_expr, seen
        if seen is None:
            seen = set()
        while isinstance(base_expr, CTypeCast):
            base_expr = base_expr.expr
        if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
            base_expr = base_expr.operand
            while isinstance(base_expr, CTypeCast):
                base_expr = base_expr.expr
        if not isinstance(base_expr, CVariable):
            return None
        variable = getattr(base_expr, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            return None
        variable_id = id(variable)
        if variable_id in seen:
            return None
        seen.add(variable_id)
        alias_entry = _stack_alias_map_8616(codegen).get(variable_id)
        if alias_entry is not None:
            alias_base_expr, alias_offset = alias_entry
            base_offset = _resolve_stack_alias_base_offset_8616(alias_base_expr, codegen, seen=seen)
            if isinstance(base_offset, int) and isinstance(alias_offset, int):
                return base_offset + alias_offset
            _record_stack_alias_refusal_8616(codegen, "stack_alias_ambiguous_offset")
            return None
        offset = getattr(variable, "offset", None)
        return offset if isinstance(offset, int) else None

    return _impl()


def _resolve_stack_offset_from_indexed_8616(node, project=None) -> int | None:
    def _impl():
        nonlocal node
        node = _strip_validation_casts(node)
        if isinstance(node, CUnaryOp) and node.op == "Reference":
            node = _strip_validation_casts(node.operand)
        if not isinstance(node, CIndexedVariable):
            return None
        base = _strip_validation_casts(getattr(node, "variable", None))
        index = _strip_validation_casts(getattr(node, "index", None))
        index_value = _c_constant_int_value(index)
        if not isinstance(index_value, int):
            return None
        codegen = getattr(node, "codegen", None)
        if isinstance(base, CVariable):
            base_var = getattr(base, "variable", None)
            if isinstance(base_var, SimStackVariable) and codegen is not None:
                bridge_key = ("indexed_value", id(base_var), index_value)
                bridged = _stack_canonicalization_bridges_8616(codegen).get(bridge_key)
                _debug_tail_stack_alias_indexed_8616(
                    codegen,
                    node=node,
                    base_var=base_var,
                    index_value=index_value,
                    bridge_key=bridge_key,
                    bridge_value=bridged,
                    note="resolve_indexed_before_alias",
                )
                if isinstance(bridged, int):
                    return bridged
        if codegen is None:
            return None
        combined = CBinaryOp(
            "Add",
            base,
            CConstant(index_value, getattr(index, "type", None), codegen=codegen),
            codegen=codegen,
        )
        displacement = _stack_bp_displacement_8616(combined, project, codegen)
        if isinstance(displacement, int):
            return displacement
        canonical_offset = _resolve_stack_alias_base_offset_8616(base, codegen) if codegen is not None else None
        if isinstance(canonical_offset, int):
            _debug_tail_stack_alias_indexed_8616(
                codegen,
                node=node,
                base_var=getattr(base, "variable", None) if isinstance(base, CVariable) else None,
                index_value=index_value,
                alias_base_offset=canonical_offset,
                selected=canonical_offset + index_value,
                note="resolve_indexed_alias_base",
            )
            return canonical_offset + index_value
        if isinstance(base, CVariable):
            variable = getattr(base, "variable", None)
            offset = getattr(variable, "offset", None)
            if isinstance(variable, SimStackVariable) and isinstance(offset, int):
                _debug_tail_stack_alias_indexed_8616(
                    codegen,
                    node=node,
                    base_var=variable,
                    index_value=index_value,
                    fallback_offset=offset,
                    selected=offset + index_value,
                    note="resolve_indexed_fallback",
                )
                return offset + index_value
        return None

    return _impl()


def _strip_validation_casts(node):
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


def _strip_validation_casts_and_dirty_aliases_8616(node):
    node = _strip_validation_casts(node)
    if isinstance(node, CDirtyExpression):
        resolved = _resolve_validation_dirty_alias_expr_8616(node)
        if resolved is not None and resolved is not node:
            return _strip_validation_casts_and_dirty_aliases_8616(resolved)
    return node


def _wrap_not_fingerprint(fingerprint: str) -> str:
    if fingerprint.startswith("Not(") and fingerprint.endswith(")"):
        return fingerprint[4:-1]
    return f"Not({fingerprint})"


def _invert_cmp_op_8616(op: str) -> str | None:
    return {
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
    }.get(op)


def _stack_word_pair_fingerprint(node, project) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    low_offset = _stack_byte_offset_from_expr_8616(left, project)
    high_offset = _stack_byte_offset_from_scaled_expr_8616(right, project, scale=256)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        low_offset = _stack_byte_offset_from_expr_8616(right, project)
        high_offset = _stack_byte_offset_from_scaled_expr_8616(left, project, scale=256)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return _canonical_or_unresolved_stack_fingerprint_8616(
        low_offset,
        getattr(node, "codegen", None),
        source="word_pair",
        node=node,
    )


def _global_word_pair_fingerprint_8616(node, project) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    low_offset = _global_byte_offset_from_expr_8616(left, project)
    high_offset = _global_byte_offset_from_scaled_expr_8616(right, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        low_offset = _global_byte_offset_from_expr_8616(right, project)
        high_offset = _global_byte_offset_from_scaled_expr_8616(left, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return f"global:{low_offset:#x}"


def _global_word_pair_from_proven_byte_8616(node, project) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    low_offset = _proven_global_byte_offset_8616(left, project)
    high_offset = _ds_linear_byte_offset_from_scaled_expr_8616(right, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        low_offset = _proven_global_byte_offset_8616(right, project)
        high_offset = _ds_linear_byte_offset_from_scaled_expr_8616(left, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return f"global:{low_offset:#x}"


def _proven_global_byte_offset_8616(node, project) -> int | None:
    offset = _materialized_global_byte_offset_8616(node)
    if isinstance(offset, int):
        return offset
    offset = _global_byte_offset_from_expr_8616(node, project)
    if isinstance(offset, int):
        return offset
    fingerprint = _expr_fingerprint(node, project, set())
    if isinstance(fingerprint, str) and fingerprint.startswith("global:"):
        try:
            return int(fingerprint[len("global:") :], 16)
        except ValueError:
            return None
    return None


def _materialized_global_byte_offset_8616(node) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) and addr >= 0 else None


def _global_byte_offset_from_expr_8616(node, project) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimMemoryVariable):
            addr = getattr(variable, "addr", None)
            if isinstance(addr, int) and addr >= 0:
                return addr
    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        location = _deref_location_fingerprint_8616(node, project)
        if isinstance(location, str) and location.startswith("global:"):
            try:
                return int(location[len("global:") :], 16)
            except ValueError:
                return None
        segmented_offset = _global_offset_from_segmented_deref_operand_8616(node, project)
        if isinstance(segmented_offset, int):
            return segmented_offset
    return None


def _ds_linear_byte_offset_from_expr_8616(node, project) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    matched = _segment_linear_offset_from_deref_operand_8616(node, project)
    if matched is None:
        return None
    segment_name, offset = matched
    return offset if segment_name == "ds" else None


def _ds_linear_byte_offset_from_scaled_expr_8616(node, project) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _c_constant_int_value(node.lhs) == 256:
            return _ds_linear_byte_offset_from_expr_8616(node.rhs, project)
        if _c_constant_int_value(node.rhs) == 256:
            return _ds_linear_byte_offset_from_expr_8616(node.lhs, project)
    if node.op == "Shl" and _c_constant_int_value(node.rhs) == 8:
        return _ds_linear_byte_offset_from_expr_8616(node.lhs, project)
    return None


def _global_offset_from_segmented_deref_operand_8616(node, project) -> int | None:
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    matched = _segment_linear_offset_from_deref_operand_8616(node, project)
    if matched is None:
        return None
    segment_name, offset = matched
    if segment_name == "ss":
        return None
    if not _segment_linear_lowering_allowed(node, segment_name, project):
        return None
    return offset


def _segment_linear_offset_from_deref_operand_8616(node, project) -> tuple[str, int] | None:
    segment_name: str | None = None
    offset = 0
    for sign, term in _flatten_additive_terms_8616(node.operand):
        term_segment = _linear_segment_term_name_8616(term, project)
        if term_segment is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = term_segment
            continue
        value = _c_constant_int_value(term)
        if not isinstance(value, int):
            return None
        offset += sign * value
    if segment_name is None:
        return None
    return segment_name, offset


def _linear_segment_term_name_8616(node, project) -> str | None:
    node = _strip_validation_casts(node)
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Shl":
        if _c_constant_int_value(node.rhs) == 4:
            return _segment_register_expr_name_8616(node.lhs, project)
        if _c_constant_int_value(node.lhs) == 4:
            return _segment_register_expr_name_8616(node.rhs, project)
        return None
    if node.op != "Mul":
        return None
    if _c_constant_int_value(node.rhs) == 16:
        return _segment_register_expr_name_8616(node.lhs, project)
    if _c_constant_int_value(node.lhs) == 16:
        return _segment_register_expr_name_8616(node.rhs, project)
    return None


def _segment_register_expr_name_8616(node, project) -> str | None:
    node = _strip_validation_casts(node)
    dirty_fingerprint = _dirty_register_fingerprint_8616(node, project) if isinstance(node, CDirtyExpression) else None
    if isinstance(dirty_fingerprint, str) and dirty_fingerprint.startswith("reg:"):
        name = dirty_fingerprint[len("reg:") :].lower()
        return name if name in {"cs", "ds", "es", "ss"} else None
    if not isinstance(node, CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return None
    reg = getattr(variable, "reg", None)
    if not isinstance(reg, int):
        return None
    name = getattr(getattr(project, "arch", None), "register_names", {}).get(reg)
    if not isinstance(name, str):
        return None
    name = name.lower()
    return name if name in {"cs", "ds", "es", "ss"} else None


def _global_byte_offset_from_scaled_expr_8616(node, project) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _c_constant_int_value(node.lhs) == 256:
            return _global_byte_offset_from_expr_8616(node.rhs, project)
        if _c_constant_int_value(node.rhs) == 256:
            return _global_byte_offset_from_expr_8616(node.lhs, project)
    if node.op == "Shl" and _c_constant_int_value(node.rhs) == 8:
        return _global_byte_offset_from_expr_8616(node.lhs, project)
    return None


def _stack_byte_offset_from_expr_8616(node, project) -> int | None:
    def _impl():
        nonlocal node
        node = _strip_validation_casts_and_dirty_aliases_8616(node)
        if isinstance(node, CVariable):
            variable = getattr(node, "variable", None)
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                return offset
        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            bp_disp = _match_bp_stack_dereference_8616(node, project)
            if isinstance(bp_disp, int):
                return bp_disp
            operand = _strip_validation_casts(node.operand)
            if isinstance(operand, CIndexedVariable):
                base = _strip_validation_casts(getattr(operand, "variable", None))
                index = _strip_validation_casts(getattr(operand, "index", None))
                if isinstance(base, CUnaryOp) and base.op == "Reference":
                    base = _strip_validation_casts(base.operand)
                base_var = getattr(base, "variable", None) if isinstance(base, CVariable) else None
                index_value = _c_constant_int_value(index)
                codegen = getattr(node, "codegen", None)
                if isinstance(base_var, SimStackVariable) and isinstance(index_value, int) and codegen is not None:
                    bridged = _stack_canonicalization_bridges_8616(codegen).get(
                        ("indexed_deref", id(base_var), index_value)
                    )
                    if isinstance(bridged, int):
                        return bridged
            indexed_offset = _resolve_stack_offset_from_indexed_8616(node.operand, project)
            if isinstance(indexed_offset, int):
                return indexed_offset
            return _match_bp_stack_dereference_8616(node, project)
        indexed_offset = _resolve_stack_offset_from_indexed_8616(node, project)
        if isinstance(indexed_offset, int):
            return indexed_offset
        return None

    return _impl()


def _stack_indexed_location_fingerprint_8616(node, project=None) -> str | None:
    def _impl():
        nonlocal node
        node = _strip_validation_casts_and_dirty_aliases_8616(node)
        if isinstance(node, CUnaryOp) and node.op == "Reference":
            node = node.operand
            while isinstance(node, CTypeCast):
                node = node.expr
        if not isinstance(node, CIndexedVariable):
            return None
        base = getattr(node, "variable", None)
        index = getattr(node, "index", None)
        while isinstance(base, CTypeCast):
            base = base.expr
        while isinstance(index, CTypeCast):
            index = index.expr
        if isinstance(base, CUnaryOp) and base.op == "Reference":
            base = base.operand
            while isinstance(base, CTypeCast):
                base = base.expr
        index_value = _c_constant_int_value(index)
        if not isinstance(index_value, int):
            return None
        codegen = getattr(node, "codegen", None)
        bridged = _indexed_location_bridge_8616(node=node, base=base, index_value=index_value, codegen=codegen)
        if bridged is not None:
            return bridged
        if codegen is None:
            return None
        combined = CBinaryOp(
            "Add",
            base,
            CConstant(index_value, getattr(index, "type", None), codegen=codegen),
            codegen=codegen,
        )
        displacement = _stack_bp_displacement_8616(combined, project, codegen)
        if isinstance(displacement, int):
            return _canonical_or_unresolved_stack_fingerprint_8616(
                displacement,
                codegen,
                source="indexed_combined",
                node=node,
            )
        alias_fingerprint = _indexed_location_alias_or_fallback_8616(
            node=node, base=base, index_value=index_value, codegen=codegen
        )
        return alias_fingerprint

    return _impl()


def _indexed_location_bridge_8616(*, node, base, index_value: int, codegen) -> str | None:
    if not (isinstance(base, CVariable) and codegen is not None):
        return None
    base_var = getattr(base, "variable", None)
    if not isinstance(base_var, SimStackVariable):
        return None
    bridge_key = ("indexed_value", id(base_var), index_value)
    bridged = _stack_canonicalization_bridges_8616(codegen).get(bridge_key)
    _debug_tail_stack_alias_indexed_8616(
        codegen,
        node=node,
        base_var=base_var,
        index_value=index_value,
        bridge_key=bridge_key,
        bridge_value=bridged,
        note="indexed_location_before_alias",
    )
    if not isinstance(bridged, int):
        return None
    return _canonical_or_unresolved_stack_fingerprint_8616(bridged, codegen, source="indexed_bridge", node=node)


def _indexed_location_alias_or_fallback_8616(*, node, base, index_value: int, codegen) -> str | None:
    def _impl():
        canonical_offset = _resolve_stack_alias_base_offset_8616(base, codegen) if codegen is not None else None
        if isinstance(canonical_offset, int):
            _debug_tail_stack_alias_indexed_8616(
                codegen,
                node=node,
                base_var=getattr(base, "variable", None) if isinstance(base, CVariable) else None,
                index_value=index_value,
                alias_base_offset=canonical_offset,
                selected=canonical_offset + index_value,
                note="indexed_location_alias_base",
            )
            normalized = canonicalize_stack_alias_fingerprint_8616(
                canonical_offset + index_value,
                stack_alias_map=_stack_alias_map_8616(codegen),
                materialized_local_map=_materialized_local_map_8616(codegen),
            )
            if normalized is not None:
                return normalized
            _record_stack_alias_refusal_8616(codegen, "stack_alias_no_materialized_local")
        if not isinstance(base, CVariable):
            _record_stack_alias_refusal_8616(codegen, "stack_alias_missing_binding")
            return None
        variable = getattr(base, "variable", None)
        offset = getattr(variable, "offset", None)
        if not isinstance(variable, SimStackVariable) or not isinstance(offset, int):
            _record_stack_alias_refusal_8616(codegen, "stack_alias_missing_binding")
            return None
        size = getattr(variable, "size", None)
        if isinstance(size, int) and size > 0:
            direct_slot = _stack_slot_fingerprint_from_slot_8616(offset + index_value, size)
            if direct_slot is not None:
                return direct_slot
        if codegen is not None:
            _record_stack_alias_refusal_8616(codegen, "stack_alias_ambiguous_offset")
            _debug_tail_stack_alias_indexed_8616(
                codegen,
                node=node,
                base_var=variable if isinstance(variable, SimStackVariable) else None,
                index_value=index_value,
                fallback_offset=offset,
                selected=offset + index_value,
                note="indexed_location_fallback",
            )
        return _canonical_or_unresolved_stack_fingerprint_8616(
            offset + index_value, codegen, source="indexed_fallback", node=node
        )

    return _impl()


def _stack_byte_offset_from_scaled_expr_8616(node, project, *, scale: int) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _c_constant_int_value(node.lhs) == scale:
            return _stack_byte_offset_from_expr_8616(node.rhs, project)
        if _c_constant_int_value(node.rhs) == scale:
            return _stack_byte_offset_from_expr_8616(node.lhs, project)
    if node.op == "Shl":
        shift_bits = _c_constant_int_value(node.rhs)
        if shift_bits == 8:
            return _stack_byte_offset_from_expr_8616(node.lhs, project)
    return None


def _extract_deref_node(node):
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        return node
    return None


def _extract_deref_scaled_node(node, *, scale: int):
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or node.op != "Mul":
        return None
    if _c_constant_int_value(node.lhs) == scale:
        return _extract_deref_node(node.rhs)
    if _c_constant_int_value(node.rhs) == scale:
        return _extract_deref_node(node.lhs)
    return None


def _bool_projection_fingerprint(node, project) -> str | None:
    def _impl():
        nonlocal node
        while isinstance(node, CTypeCast):
            node = node.expr

        if isinstance(node, CUnaryOp) and node.op == "Not":
            operand = getattr(node, "operand", None)
            inner = _bool_projection_fingerprint(operand, project)
            if inner is not None:
                return _wrap_not_fingerprint(inner)
            if isinstance(operand, CUnaryOp) and operand.op == "Not":
                return _expr_fingerprint(operand.operand, project)
            return None

        if not isinstance(node, CITE):
            return None

        iftrue = _c_constant_int_value(getattr(node, "iftrue", None))
        iffalse = _c_constant_int_value(getattr(node, "iffalse", None))
        if (iftrue, iffalse) == (1, 0):
            inner = _bool_projection_fingerprint(node.cond, project)
            return inner if inner is not None else _expr_fingerprint(node.cond, project)
        if (iftrue, iffalse) == (0, 1):
            inner = _bool_projection_fingerprint(node.cond, project)
            if inner is None:
                inner = _expr_fingerprint(node.cond, project)
            return _wrap_not_fingerprint(inner)
        return None

    return _impl()


def _extract_same_zero_compare_expr_8616(node):
    if not isinstance(node, CBinaryOp) or node.op != "CmpEQ":
        return None
    if _c_constant_int_value(node.rhs) == 0:
        return node.lhs
    if _c_constant_int_value(node.lhs) == 0:
        return node.rhs
    return None


def _extract_zero_flag_source_expr_8616(node):
    def _impl():
        if isinstance(node, CBinaryOp):
            if node.op == "Mul":
                for maybe_logic, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                    if _c_constant_int_value(maybe_scale) != 64:
                        continue
                    source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                    if source_expr is not None:
                        return source_expr
                    if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                        continue
                    lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                    rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                    if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                        return lhs_expr

            for child in (node.lhs, node.rhs):
                if _structured_codegen_node_8616(child):
                    extracted = _extract_zero_flag_source_expr_8616(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(node, CUnaryOp):
            child = getattr(node, "operand", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        elif isinstance(node, CTypeCast):
            child = getattr(node, "expr", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        return None

    return _impl()


def _normalize_zero_flag_comparison_8616(node):
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _c_constant_int_value(node.rhs) == 0:
        source = node.lhs
    elif _c_constant_int_value(node.lhs) == 0:
        source = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr_8616(source)
    if source_expr is None:
        return node
    if node.op == "CmpEQ":
        return source_expr
    return _safe_rebuild_unary_8616("Not", source_expr, node)


def _simplify_expr_for_fingerprint_8616(node):
    def _impl():
        nonlocal node
        node = _strip_validation_casts(node)
        if isinstance(node, CUnaryOp):
            operand = _simplify_expr_for_fingerprint_8616(getattr(node, "operand", None))
            if operand is not getattr(node, "operand", None):
                return _safe_rebuild_unary_8616(node.op, operand, node)
            return node
        if not isinstance(node, CBinaryOp):
            return node
        lhs = _simplify_expr_for_fingerprint_8616(node.lhs)
        rhs = _simplify_expr_for_fingerprint_8616(node.rhs)
        lhs_zero = _c_constant_int_value(lhs) == 0
        rhs_zero = _c_constant_int_value(rhs) == 0
        if node.op == "Mul" and (lhs_zero or rhs_zero):
            return lhs if lhs_zero else rhs
        if node.op in {"Or", "Add", "Xor"}:
            if lhs_zero:
                return rhs
            if rhs_zero:
                return lhs
        if node.op in {"Sub"} and rhs_zero:
            return lhs
        if lhs is not node.lhs or rhs is not node.rhs:
            return _safe_rebuild_binary_8616(node.op, lhs, rhs, node)
        return node

    return _impl()


def _flatten_additive_terms_8616(node, sign: int = 1) -> tuple[tuple[int, object], ...]:
    node = _strip_validation_casts(node)
    if isinstance(node, CBinaryOp) and node.op == "Add":
        return _flatten_additive_terms_8616(node.lhs, sign) + _flatten_additive_terms_8616(node.rhs, sign)
    if isinstance(node, CBinaryOp) and node.op == "Sub":
        return _flatten_additive_terms_8616(node.lhs, sign) + _flatten_additive_terms_8616(node.rhs, -sign)
    return ((sign, node),)


def _is_register_expr_8616(node, project, reg_name: str) -> bool:
    node = _strip_validation_casts(node)
    if not isinstance(node, CVariable):
        return False
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return False
    reg = getattr(variable, "reg", None)
    if not isinstance(reg, int):
        return False
    try:
        expected = project.arch.registers[reg_name][0]
    except (AttributeError, KeyError, TypeError):
        expected = None
    if isinstance(expected, int) and reg == expected:
        return True
    name = getattr(node, "name", None) or getattr(variable, "name", None)
    return isinstance(name, str) and name.lower() == reg_name


def _is_ss_linear_segment_term_8616(node, project) -> bool:
    node = _strip_validation_casts(node)
    if not isinstance(node, CBinaryOp):
        return False
    if node.op == "Shl":
        return _is_register_expr_8616(node.lhs, project, "ss") and _c_constant_int_value(node.rhs) == 4
    if node.op != "Mul":
        return False
    return (_is_register_expr_8616(node.lhs, project, "ss") and _c_constant_int_value(node.rhs) == 16) or (
        _is_register_expr_8616(node.rhs, project, "ss") and _c_constant_int_value(node.lhs) == 16
    )


def _contains_bp_stack_location_expr_8616(node, *, seen: set[int] | None = None) -> bool:
    node = _strip_validation_casts(node)
    if node is None:
        return False
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return False
    seen.add(node_id)
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        return isinstance(variable, SimStackVariable) and getattr(variable, "base", "bp") == "bp"
    if isinstance(node, CIndexedVariable):
        return _contains_bp_stack_location_expr_8616(getattr(node, "variable", None), seen=seen)
    if isinstance(node, CUnaryOp):
        return _contains_bp_stack_location_expr_8616(getattr(node, "operand", None), seen=seen)
    if isinstance(node, CBinaryOp):
        return _contains_bp_stack_location_expr_8616(node.lhs, seen=seen) or _contains_bp_stack_location_expr_8616(
            node.rhs, seen=seen
        )
    return False


def _additive_terms_fingerprint_8616(terms: tuple[tuple[int, object], ...], project) -> str:
    parts: list[str] = []
    const_total = 0
    for sign, term in terms:
        const_value = _c_constant_int_value(term)
        if isinstance(const_value, int):
            const_total += sign * const_value
            continue
        part = _expr_fingerprint(term, project, set())
        if sign < 0:
            part = f"Neg({part})"
        parts.append(part)
    if const_total != 0 or not parts:
        parts.append(f"const:{const_total!r}")
    return f"Add({','.join(parts)})"


def _deref_operand_fingerprint_8616(operand, project) -> str:
    operand = _strip_validation_casts(operand)
    if not isinstance(operand, CBinaryOp) or operand.op not in {"Add", "Sub"}:
        return _expr_fingerprint(operand, project)
    terms = _flatten_additive_terms_8616(operand)
    has_bp_stack_location = any(_contains_bp_stack_location_expr_8616(term) for _sign, term in terms)
    if not has_bp_stack_location:
        return _additive_terms_fingerprint_8616(terms, project)
    filtered_terms = tuple(
        (sign, term) for sign, term in terms if not (sign > 0 and _is_ss_linear_segment_term_8616(term, project))
    )
    if len(filtered_terms) == len(terms):
        return _expr_fingerprint(operand, project)
    return _additive_terms_fingerprint_8616(filtered_terms, project)


def _expr_fingerprint(node, project, _seen: set[int] | None = None) -> str:
    def _impl():
        nonlocal node, _seen
        if _seen is None:
            _seen = set()
        if node is None:
            return "none"
        node_id = id(node)
        if node_id in _seen:
            return "expr_cycle"
        _seen.add(node_id)

        def _child_seen() -> set[int]:
            return set(_seen)

        node = _simplify_expr_for_fingerprint_8616(node)
        cache_key = (
            getattr(project, "_inertia_tv_active_function_addr", None),
            id(node),
            type(node).__name__,
        )
        cacheable = not _contains_bp_stack_location_expr_8616(node)
        cache = _expr_fingerprint_cache_8616(project) if cacheable else {}
        cached = cache.get(cache_key) if cacheable else None
        if isinstance(cached, str):
            return cached

        def _cached(result: str) -> str:
            if cacheable and len(cache) <= _EXPR_FINGERPRINT_CACHE_LIMIT_8616:
                cache[cache_key] = result
            return result

        stack_pair = _stack_word_pair_fingerprint(node, project)
        if stack_pair is not None:
            return _cached(stack_pair)
        global_pair = _global_word_pair_fingerprint_8616(node, project)
        if global_pair is not None:
            return _cached(global_pair)
        materialized_global_pair = _global_word_pair_from_proven_byte_8616(node, project)
        if materialized_global_pair is not None:
            return _cached(materialized_global_pair)
        bool_projection = _bool_projection_fingerprint(node, project)
        if bool_projection is not None:
            return _cached(bool_projection)
        node = _normalize_zero_flag_comparison_8616(node)
        if isinstance(node, CDirtyExpression):
            resolved_dirty = _resolve_validation_dirty_alias_expr_8616(node)
            if resolved_dirty is not None and resolved_dirty is not node:
                return _cached(_expr_fingerprint(resolved_dirty, project, _child_seen()))
            dirty_register = _dirty_register_fingerprint_8616(node, project)
            if dirty_register is not None:
                return _cached(dirty_register)
            dirty_name = _dirty_virtual_name_8616(node)
            if isinstance(dirty_name, str):
                return _cached(f"virtual:{dirty_name}")
            return _cached("virtual:unknown")
        if isinstance(node, CConstant):
            return _cached(f"const:{node.value!r}")
        if isinstance(node, CVariable):
            return _cached(_location_fingerprint(node, project))
        indexed_global_location = _global_indexed_location_fingerprint_8616(node)
        if indexed_global_location is not None:
            return _cached(indexed_global_location)
        indexed_stack_location = _stack_indexed_location_fingerprint_8616(node, project)
        if indexed_stack_location is not None:
            return _cached(indexed_stack_location)
        if isinstance(node, CUnaryOp):
            indexed_stack_location = _stack_indexed_location_fingerprint_8616(node, project)
            if indexed_stack_location is not None:
                return _cached(indexed_stack_location)
            if node.op == "Dereference":
                deref_location = _location_fingerprint(node, project)
                if isinstance(deref_location, str) and deref_location.startswith(
                    ("global:", "stack:", "stack_slot:", "unresolved_stack_carrier:")
                ):
                    return _cached(deref_location)
                operand_fp = _expr_fingerprint(node.operand, project, _child_seen())
                if isinstance(operand_fp, str) and operand_fp.startswith("stack_slot:"):
                    return _cached(operand_fp)
            operand = getattr(node, "operand", None)
            if node.op == "Not" and isinstance(operand, CBinaryOp):
                inverted = _invert_cmp_op_8616(operand.op)
                if inverted is not None:
                    lhs = _expr_fingerprint(operand.lhs, project, _child_seen())
                    rhs = _expr_fingerprint(operand.rhs, project, _child_seen())
                    return _cached(f"{inverted}({lhs},{rhs})")
            return _cached(f"{node.op}({_expr_fingerprint(node.operand, project, _child_seen())})")
        if isinstance(node, CBinaryOp):
            if node.op in {"Add", "Sub"}:
                parts: list[str] = []
                const_total = 0
                for sign, term in _flatten_additive_terms_8616(node):
                    const_value = _c_constant_int_value(term)
                    if isinstance(const_value, int):
                        const_total += sign * const_value
                        continue
                    part = _expr_fingerprint(term, project, _child_seen())
                    if sign < 0:
                        part = f"Neg({part})"
                    parts.append(part)
                if const_total != 0 or not parts:
                    parts.append(f"const:{const_total!r}")
                return _cached(f"Add({','.join(parts)})")
            if node.op == "Shl" and _c_constant_int_value(node.rhs) == 4:
                return _cached(f"Mul({_expr_fingerprint(node.lhs, project, _child_seen())},const:16)")
            lhs = _expr_fingerprint(node.lhs, project, _child_seen())
            rhs = _expr_fingerprint(node.rhs, project, _child_seen())
            return _cached(f"{node.op}({lhs},{rhs})")
        if isinstance(node, CFunctionCall):
            runtime_helper = _runtime_segment_helper_fingerprint_8616(node, project)
            if runtime_helper is not None:
                return _cached(runtime_helper)
            callee = _call_target_name(node, project)
            args = ",".join(_expr_fingerprint(arg, project, _child_seen()) for arg in getattr(node, "args", ()) or ())
            return _cached(f"call:{callee}({args})")
        return _cached(type(node).__name__)

    return _impl()


def _call_target_name(node: CFunctionCall, project) -> str:
    callee_func = getattr(node, "callee_func", None)
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        return f"addr:{callee_addr:#x}"
    callee = getattr(node, "callee_target", None)
    normalized_callee = normalize_callee_name_8616(callee)
    if isinstance(normalized_callee, str):
        match = _SUB_TARGET_RE.match(normalized_callee)
        if match is not None:
            try:
                return f"addr:{int(match.group('addr'), 16):#x}"
            except ValueError:
                pass
        resolved_addr = _resolve_call_symbol_addr_8616(project, normalized_callee)
        if isinstance(resolved_addr, int):
            return f"addr:{resolved_addr:#x}"
    if isinstance(normalized_callee, str):
        return normalized_callee
    name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if isinstance(name, str):
        resolved_addr = _resolve_call_symbol_addr_8616(project, name)
        if isinstance(resolved_addr, int):
            return f"addr:{resolved_addr:#x}"
    if isinstance(name, str):
        return name
    return "<indirect>"


def _resolve_call_symbol_addr_8616(project, name: str) -> int | None:
    for candidate_project in _call_symbol_lookup_projects_8616(project):
        resolved_addr = _resolve_call_symbol_addr_in_project_8616(candidate_project, name)
        if isinstance(resolved_addr, int):
            return resolved_addr
    return None


def _call_symbol_lookup_projects_8616(project) -> tuple[object, ...]:
    projects: list[object] = []
    for candidate in (project, getattr(project, "_inertia_original_project", None)):
        if candidate is not None and all(candidate is not existing for existing in projects):
            projects.append(candidate)
    return tuple(projects)


def _resolve_call_symbol_addr_in_project_8616(project, name: str) -> int | None:
    function_addr = _function_addr_by_name_8616(project, name)
    if isinstance(function_addr, int):
        return function_addr
    for addr, label in getattr(getattr(project, "kb", None), "labels", {}).items():
        if isinstance(addr, int) and _call_symbol_names_equivalent_8616(label, name):
            return addr
    metadata = getattr(project, "_inertia_lst_metadata", None)
    code_labels = getattr(metadata, "code_labels", None)
    if isinstance(code_labels, dict):
        for addr, label in code_labels.items():
            if isinstance(addr, int) and _call_symbol_names_equivalent_8616(label, name):
                return addr
    return None


def _function_addr_by_name_8616(project, name: str) -> int | None:
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    for lookup_name in _call_symbol_lookup_names_8616(name):
        try:
            function = lookup(name=lookup_name, create=False)
        except TypeError:
            continue
        addr = getattr(function, "addr", None)
        if isinstance(addr, int):
            return addr
    return None


def _call_symbol_lookup_names_8616(name: str) -> tuple[str, ...]:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return ()
    names = [normalized]
    undecorated = normalized.lstrip("_")
    decorated = f"_{undecorated}" if undecorated else None
    if decorated is not None and decorated not in names:
        names.append(decorated)
    if undecorated and undecorated not in names:
        names.append(undecorated)
    return tuple(names)


def _call_symbol_names_equivalent_8616(left: str | None, right: str | None) -> bool:
    left_name = normalize_callee_name_8616(left)
    right_name = normalize_callee_name_8616(right)
    if not isinstance(left_name, str) or not isinstance(right_name, str):
        return False
    return left_name == right_name or left_name.lstrip("_") == right_name.lstrip("_")


def _call_symbol_name_8616(node: CFunctionCall) -> str | None:
    callee_func = getattr(node, "callee_func", None)
    for raw in (
        getattr(callee_func, "name", None),
        getattr(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def _fingerprint_target_addr_from_summary_8616(summary) -> int | None:
    if isinstance(summary, dict):
        target_addr = summary.get("target_addr")
    else:
        target_addr = getattr(summary, "target_addr", None)
    return target_addr if isinstance(target_addr, int) else None


def _summarize_x86_16_callsite_for_fingerprint_8616(function, callsite_addr: int):
    tail_validation_module = sys.modules.get("angr_platforms.X86_16.tail_validation")
    summarize = getattr(tail_validation_module, "summarize_x86_16_callsite", None)
    if callable(summarize):
        return summarize(function, callsite_addr)
    return _summarize_x86_16_callsite_fallback(function, callsite_addr)


def build_x86_16_contextual_call_fingerprints(root, project) -> dict[int, str]:
    def _impl():
        if root is None:
            return {}
        call_nodes = list(_iter_observable_call_nodes_8616(root))
        if not call_nodes:
            return {}
        fingerprints: dict[int, str] = {}
        function = _function_for_call_context_8616(root, project)
        if function is not None:
            callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
            if not callsite_addrs:
                callsite_addrs = _collect_direct_capstone_callsite_addrs_8616(function)
            for node, callsite_addr in zip(call_nodes, callsite_addrs):
                summary = _summarize_x86_16_callsite_for_fingerprint_8616(function, callsite_addr)
                target_addr = _fingerprint_target_addr_from_summary_8616(summary)
                if isinstance(target_addr, int):
                    fingerprints[id(node)] = f"addr:{target_addr:#x}"
                else:
                    fingerprints[id(node)] = f"callsite:{callsite_addr:#x}"
        if len(fingerprints) < len(call_nodes):
            for node_id, fingerprint in _build_cod_call_name_fingerprints_8616(root, project, call_nodes).items():
                fingerprints.setdefault(node_id, fingerprint)
        if len(fingerprints) < len(call_nodes):
            for node in call_nodes:
                node_addr = _call_node_addr_8616(node)
                if isinstance(node_addr, int):
                    fingerprints.setdefault(id(node), f"callsite:{node_addr:#x}")
        return fingerprints

    return _impl()


def _function_for_call_context_8616(root, project):
    codegen = getattr(root, "codegen", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if isinstance(func_addr, int):
        function = _lookup_function_for_call_context_8616(project, func_addr)
        if function is not None:
            return function
    if cfunc is not None and (
        callable(getattr(cfunc, "get_call_sites", None)) or getattr(cfunc, "block_addrs_set", None)
    ):
        return cfunc
    return None


def _collect_direct_capstone_callsite_addrs_8616(function) -> tuple[int, ...]:
    def _impl():
        project = getattr(function, "project", None)
        factory = getattr(project, "factory", None)
        if project is None or factory is None:
            return ()
        callsites: list[int] = []
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            try:
                block = factory.block(block_addr, opt_level=0)
            except Exception:
                continue
            for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                if str(getattr(insn, "mnemonic", "") or "").strip().lower() != "call":
                    continue
                address = getattr(insn, "address", None)
                if isinstance(address, int):
                    callsites.append(address)
        return tuple(callsites)

    return _impl()


def _call_node_addr_8616(node) -> int | None:
    for attr in ("ins_addr", "addr"):
        value = getattr(node, attr, None)
        if isinstance(value, int):
            return value
    return None


def _build_cod_call_name_fingerprints_8616(root, project, call_nodes) -> dict[int, str]:
    def _impl():
        codegen = getattr(root, "codegen", None)
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return {}
        cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
        cod_call_names = tuple(
            normalized
            for raw in (getattr(cod_metadata, "call_names", ()) or ())
            for normalized in (normalize_callee_name_8616(raw),)
            if isinstance(normalized, str) and normalized
        )
        if not cod_call_names:
            return {}
        fingerprints: dict[int, str] = {}
        cod_idx = 0
        for node in call_nodes:
            current_name = _call_symbol_name_8616(node)
            if current_name not in {None, "<indirect>"} and not current_name.startswith("sub_"):
                while cod_idx < len(cod_call_names) and cod_call_names[cod_idx] != current_name:
                    cod_idx += 1
                if cod_idx < len(cod_call_names) and cod_call_names[cod_idx] == current_name:
                    fingerprints[id(node)] = f"codcall:{current_name}"
                    cod_idx += 1
                continue
            if cod_idx >= len(cod_call_names):
                break
            replacement = cod_call_names[cod_idx]
            cod_idx += 1
            if replacement.startswith("sub_"):
                continue
            fingerprints[id(node)] = f"codcall:{replacement}"
        return fingerprints

    return _impl()


def _lookup_function_for_call_context_8616(project, func_addr: int):
    addr_candidates = []
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        addr_candidates.append(func_addr + original_delta)
        rebased = func_addr - original_delta
        if rebased >= 0:
            addr_candidates.append(rebased)
    addr_candidates.append(func_addr)
    deduped_addrs: list[int] = []
    for addr in addr_candidates:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)

    project_variants: list[tuple[object, tuple[int, ...]]] = [(project, tuple(deduped_addrs))]
    original_project = getattr(project, "_inertia_original_project", None)
    if original_project is not None:
        original_addrs = [func_addr]
        if isinstance(original_delta, int):
            original_addrs = [func_addr + original_delta]
        deduped_original_addrs: list[int] = []
        for addr in original_addrs:
            if addr >= 0 and addr not in deduped_original_addrs:
                deduped_original_addrs.append(addr)
        project_variants.append((original_project, tuple(deduped_original_addrs)))

    for candidate_project, candidate_addrs in project_variants:
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", lambda **_: None)
        for candidate_addr in candidate_addrs:
            function = lookup(addr=candidate_addr, create=False)
            if function is not None:
                return function
    return None


def _iter_observable_call_nodes_8616(node):
    def _impl():
        if node is None:
            return
        if isinstance(node, CStatements):
            for stmt in getattr(node, "statements", ()) or ():
                yield from _iter_observable_call_nodes_8616(stmt)
            return
        if isinstance(node, CFunctionCall):
            if not _is_runtime_segment_helper_call_8616(node):
                yield node
            return
        if isinstance(node, CAssignment):
            rhs = getattr(node, "rhs", None)
            if isinstance(rhs, CFunctionCall) and not _is_runtime_segment_helper_call_8616(rhs):
                yield rhs
            return
        for attr in ("retval", "condition", "cond", "expr"):
            child = getattr(node, attr, None)
            if isinstance(child, CFunctionCall) and not _is_runtime_segment_helper_call_8616(child):
                yield child
            elif child is not None:
                yield from _iter_observable_call_nodes_8616(child)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                if isinstance(cond, CFunctionCall) and not _is_runtime_segment_helper_call_8616(cond):
                    yield cond
                elif cond is not None:
                    yield from _iter_observable_call_nodes_8616(cond)
                yield from _iter_observable_call_nodes_8616(body)
        else_node = getattr(node, "else_node", None)
        if else_node is not None:
            yield from _iter_observable_call_nodes_8616(else_node)
        for attr in ("body", "initializer", "iterator"):
            child = getattr(node, attr, None)
            if child is not None:
                yield from _iter_observable_call_nodes_8616(child)

    return _impl()


def _location_fingerprint(node, project, _seen: set[int] | None = None, *, resolve_copy_alias: bool = True) -> str:
    def _impl():
        nonlocal node, _seen
        if _seen is None:
            _seen = set()
        node_id = id(node)
        if node_id in _seen:
            return "alias_cycle"
        _seen.add(node_id)
        if isinstance(node, CFunctionCall):
            runtime_location = _runtime_segment_helper_location_8616(node, project)
            if runtime_location is not None:
                return runtime_location
        if isinstance(node, CVariable):
            variable_fingerprint = _cvariable_location_fingerprint_8616(
                node, project, _seen=_seen, resolve_copy_alias=resolve_copy_alias
            )
            if isinstance(variable_fingerprint, str):
                return variable_fingerprint
        if isinstance(node, CIndexedVariable):
            indexed_global_location = _global_indexed_location_fingerprint_8616(node)
            if indexed_global_location is not None:
                return indexed_global_location

        if isinstance(node, CTypeCast):
            return _location_fingerprint(node.expr, project, _seen, resolve_copy_alias=resolve_copy_alias)

        indexed_stack_location = _stack_indexed_location_fingerprint_8616(node)
        if indexed_stack_location is not None:
            return indexed_stack_location

        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            deref_fingerprint = _deref_location_fingerprint_8616(node, project)
            if isinstance(deref_fingerprint, str):
                return deref_fingerprint

        return _expr_fingerprint(node, project, _seen)

    return _impl()


def _cvariable_location_fingerprint_8616(node, project, *, _seen: set[int], resolve_copy_alias: bool) -> str | None:
    def _impl():
        variable = getattr(node, "variable", None)
        codegen = getattr(node, "codegen", None)
        name = getattr(node, "name", None) or getattr(variable, "name", None)
        if codegen is not None and isinstance(name, str):
            if os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
                log.warning(
                    "[tail-carrier] cvar_id=%s name=%r obj=%r var=%r unified=%r keys=%r widened_hit=%r",
                    id(node),
                    name,
                    node,
                    variable,
                    getattr(node, "unified_variable", None),
                    _candidate_widened_keys_8616(node),
                    _lookup_widened_carrier_proof_8616(node, codegen),
                )
            widened = _widened_carrier_slot_fingerprint_8616(name, value=node, variable=variable, codegen=codegen)
            if widened is not None:
                return widened
        if isinstance(variable, SimStackVariable):
            source_arg_fingerprint = _source_arg_location_fingerprint_8616(node, project)
            if source_arg_fingerprint is not None:
                return source_arg_fingerprint
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                return _canonical_or_unresolved_stack_fingerprint_8616(offset, codegen, source="stack_var", node=node)
            return "stack:unknown"
        resolved_alias = _resolve_validation_copy_alias_expr_8616(node) if resolve_copy_alias else None
        if resolved_alias is not None and resolved_alias is not node:
            resolved_location = _location_fingerprint(resolved_alias, project, _seen)
            if isinstance(resolved_location, str):
                return resolved_location
        if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
            return f"reg:{_register_name(project, variable.reg)}"
        if isinstance(variable, SimMemoryVariable):
            addr = getattr(variable, "addr", None)
            if isinstance(addr, int) and addr < 0:
                return f"stack:{addr:+#x}"
            return f"global:{addr:#x}" if isinstance(addr, int) else "global:unknown"
        return None

    return _impl()


def _global_indexed_location_fingerprint_8616(node) -> str | None:
    node = _strip_validation_casts(node)
    if not isinstance(node, CIndexedVariable):
        return None
    base = _strip_validation_casts(getattr(node, "variable", None))
    index = _strip_validation_casts(getattr(node, "index", None))
    if isinstance(base, CUnaryOp) and base.op == "Reference":
        base = _strip_validation_casts(base.operand)
    if not isinstance(base, CVariable):
        return None
    variable = getattr(base, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    elem_size = getattr(variable, "size", None)
    index_value = _c_constant_int_value(index)
    if not isinstance(addr, int) or not isinstance(elem_size, int) or not isinstance(index_value, int):
        return None
    if addr < 0 or elem_size <= 0:
        return None
    return f"global:{(addr + index_value * elem_size) & 0xFFFF:#x}"


def _deref_location_fingerprint_8616(node, project) -> str | None:
    stack_disp = _match_bp_stack_dereference_8616(node, project)
    if isinstance(stack_disp, int):
        return _canonical_or_unresolved_stack_fingerprint_8616(
            stack_disp,
            getattr(node, "codegen", None),
            source="bp_deref",
            node=node,
        )
    codegen = getattr(node, "codegen", None)
    if codegen is not None:
        try:
            from .lowering.real_mode_linear import match_stable_ss_linear_stack_access_8616
        except Exception:
            stable_ss_access = None
        else:
            stable_ss_access = match_stable_ss_linear_stack_access_8616(node, project, codegen)
        if stable_ss_access is not None and isinstance(getattr(stable_ss_access, "displacement", None), int):
            return _canonical_or_unresolved_stack_fingerprint_8616(
                stable_ss_access.displacement,
                codegen,
                source="stable_ss_linear",
                node=node,
            )
    operand = _strip_validation_casts(node.operand)
    bridged = _indexed_deref_bridge_fingerprint_8616(node, operand)
    if isinstance(bridged, str):
        return bridged
    indexed_stack_location = _stack_indexed_location_fingerprint_8616(node.operand, project)
    if indexed_stack_location is not None:
        return indexed_stack_location
    seg_name, linear = _match_segmented_dereference_8616(node, project)
    if seg_name is not None:
        if isinstance(linear, int) and _segment_linear_lowering_allowed(node, seg_name, project):
            return f"global:{linear:#x}"
        return f"deref:{seg_name}:{linear:#x}" if isinstance(linear, int) else f"deref:{seg_name}:unknown"
    return f"deref:{_deref_operand_fingerprint_8616(node.operand, project)}"


def _indexed_deref_bridge_fingerprint_8616(node, operand) -> str | None:
    if not isinstance(operand, CIndexedVariable):
        return None
    base = _strip_validation_casts(getattr(operand, "variable", None))
    index = _strip_validation_casts(getattr(operand, "index", None))
    if isinstance(base, CUnaryOp) and base.op == "Reference":
        base = _strip_validation_casts(base.operand)
    base_var = getattr(base, "variable", None) if isinstance(base, CVariable) else None
    index_value = _c_constant_int_value(index)
    codegen = getattr(node, "codegen", None)
    if not (isinstance(base_var, SimStackVariable) and isinstance(index_value, int) and codegen is not None):
        return None
    bridged = _stack_canonicalization_bridges_8616(codegen).get(("indexed_deref", id(base_var), index_value))
    if not isinstance(bridged, int):
        return None
    return _canonical_or_unresolved_stack_fingerprint_8616(
        bridged,
        codegen,
        source="indexed_deref_bridge",
        node=node,
    )


def _runtime_segment_helper_name_8616(node: CFunctionCall) -> str | None:
    tags = getattr(node, "tags", None)
    marker_name = tags.get("inertia_x86_16_runtime_segment_helper") if isinstance(tags, dict) else None
    if isinstance(marker_name, str):
        return marker_name
    callee = normalize_callee_name_8616(getattr(node, "callee_target", None))
    if isinstance(callee, str):
        return callee
    callee_func = getattr(node, "callee_func", None)
    callee = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if isinstance(callee, str):
        return callee
    return None


def _runtime_segment_helper_args_8616(node: CFunctionCall) -> tuple[object, ...] | None:
    args = tuple(getattr(node, "args", ()) or ())
    name = _runtime_segment_helper_name_8616(node)
    if name in {"MEM_U8", "MEM_U16", "MEM_U32"}:
        return args if len(args) == 1 else None
    if len(args) != 2:
        return None
    return args[0], args[1]


def _is_runtime_segment_helper_call_8616(node: CFunctionCall) -> bool:
    name = _runtime_segment_helper_name_8616(node)
    return name in {"SEG_U8", "SEG_U16", "SEG_U32", "MK_FP", "SEG_PTR", "MEM_U8", "MEM_U16", "MEM_U32"}


def _runtime_segment_linear_fingerprint_8616(seg_expr, off_expr, project) -> str:
    off_fp = _expr_fingerprint(off_expr, project)
    if off_fp.startswith("Add(") and off_fp.endswith(")"):
        inner = off_fp[4:-1]
        return f"Add(Mul({_expr_fingerprint(seg_expr, project)},const:16),{inner})"
    return f"Add(Mul({_expr_fingerprint(seg_expr, project)},const:16),{off_fp})"


def _runtime_segment_helper_fingerprint_8616(node: CFunctionCall, project) -> str | None:
    name = _runtime_segment_helper_name_8616(node)
    args = _runtime_segment_helper_args_8616(node)
    if name is None or args is None:
        return None
    if name in {"MEM_U8", "MEM_U16", "MEM_U32"} and len(args) == 1:
        return f"Dereference({_expr_fingerprint(args[0], project)})"
    seg_expr, off_expr = args
    linear = _runtime_segment_linear_fingerprint_8616(seg_expr, off_expr, project)
    if name in {"MK_FP", "SEG_PTR"}:
        return linear
    if name in {"SEG_U8", "SEG_U16", "SEG_U32"}:
        return f"Dereference({linear})"
    return None


def _runtime_segment_helper_location_8616(node: CFunctionCall, project) -> str | None:
    name = _runtime_segment_helper_name_8616(node)
    args = _runtime_segment_helper_args_8616(node)
    if name in {"MEM_U8", "MEM_U16", "MEM_U32"} and args is not None and len(args) == 1:
        return f"deref:{_expr_fingerprint(args[0], project)}"
    if name not in {"SEG_U8", "SEG_U16", "SEG_U32"} or args is None:
        return None
    seg_expr, off_expr = args
    if isinstance(seg_expr, CVariable):
        variable = getattr(seg_expr, "variable", None)
        if isinstance(variable, SimRegisterVariable):
            seg_name = _register_name(project, variable.reg)
            off_value = _c_constant_int_value(off_expr)
            if isinstance(off_value, int):
                return f"deref:{seg_name}:{off_value:#x}"
    return f"deref:{_runtime_segment_linear_fingerprint_8616(seg_expr, off_expr, project)}"
