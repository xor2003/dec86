from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CGoto,
    CLabel,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import (
    SimTypeBottom,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)

try:
    from angr.analyses.typehoon import lifter as _typehoon_lifter
except ImportError:
    _typehoon_lifter = None
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .alias.alias_model import _stack_slot_identity_can_join, _stack_slot_identity_for_variable
from .analysis_helpers import preferred_known_helper_signature_decl
from .annotations import (
    ANNOTATION_KEY,
    _parse_c_prototype_8616,
    _source_decl_from_cod_source_lines,
    annotate_function,
)
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _iter_c_nodes_deep_8616,
    _match_bp_stack_load_8616,
    _replace_c_children_8616,
    _structured_codegen_node_8616,
)
from .decompiler_return_compat import x86_16_msvc_x87_scalar_stack_args


def _source_annotation_lines_8616(func) -> tuple[str, ...]:
    info = getattr(func, "info", None)
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, dict) else None
    if not isinstance(annotations, dict):
        return ()
    return tuple(annotations.get("source_lines", ()) or ())


def _merge_source_annotations_if_missing_8616(target_func, source_func) -> bool:
    if target_func is None or source_func is None or target_func is source_func:
        return False
    source_info = getattr(source_func, "info", None)
    source_annotations = source_info.get(ANNOTATION_KEY) if isinstance(source_info, dict) else None
    if not isinstance(source_annotations, dict):
        return False
    changed = False
    target_info = getattr(target_func, "info", None)
    if not isinstance(target_info, dict):
        target_func.info = {}
        target_info = target_func.info
    target_annotations = target_info.setdefault(
        ANNOTATION_KEY,
        {
            "stack_vars": {},
            "global_vars": {},
            "source_lines": (),
            "source_return_lines": (),
        },
    )
    if not isinstance(target_annotations, dict):
        return False
    for key in ("source_lines", "source_return_lines"):
        source_value = tuple(source_annotations.get(key, ()) or ())
        if source_value and not tuple(target_annotations.get(key, ()) or ()):
            target_annotations[key] = source_value
            changed = True
    return changed


def _attach_project_cod_source_annotations_if_missing_8616(project, func_addr: int, func) -> bool:
    metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if not isinstance(metadata_by_addr, dict):
        return False
    candidates = [func_addr]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        candidates.append(func_addr + delta)
        rebased = func_addr - delta
        if rebased >= 0:
            candidates.append(rebased)
    metadata = None
    matched_candidate = None
    for candidate in candidates:
        metadata = metadata_by_addr.get(candidate)
        if metadata is not None:
            matched_candidate = candidate
            break
    source_lines = tuple(getattr(metadata, "source_lines", ()) or ()) if metadata is not None else ()
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
        print(
            "[dbg-x87-proto] "
            f"attach_project_cod_source func={func_addr!r} "
            f"candidates={candidates!r} matched={matched_candidate!r} "
            f"source_lines={len(source_lines)}",
            file=sys.stderr,
            flush=True,
        )
    if not source_lines:
        return False
    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        func.info = {}
        info = func.info
    annotations = info.setdefault(
        ANNOTATION_KEY,
        {
            "stack_vars": {},
            "global_vars": {},
            "source_lines": (),
            "source_return_lines": (),
        },
    )
    if not isinstance(annotations, dict) or tuple(annotations.get("source_lines", ()) or ()):
        return False
    annotations["source_lines"] = source_lines
    annotations["source_return_lines"] = tuple(
        line.strip() for line in source_lines if re.match(r"^return\s+[^;]+;\s*$", line.strip())
    )
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
        print(
            "[dbg-x87-proto] "
            f"attach_project_cod_source wrote func={func_addr!r} source_lines={len(source_lines)}",
            file=sys.stderr,
            flush=True,
        )
    return True


def _metadata_function_for_codegen_addr_8616(project, func_addr: int):
    func = None
    with contextlib.suppress(Exception):
        func = project.kb.functions.function(addr=func_addr, create=False)
    has_metadata = False
    if func is not None:
        info = getattr(func, "info", None)
        has_metadata = getattr(func, "prototype", None) is not None or (
            isinstance(info, dict) and bool(info.get(ANNOTATION_KEY))
        )
    if has_metadata:
        _attach_project_cod_source_annotations_if_missing_8616(project, func_addr, func)
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(delta, int):
            with contextlib.suppress(Exception):
                rebased_func = project.kb.functions.function(addr=int(func_addr) + delta, create=False)
                _merge_source_annotations_if_missing_8616(func, rebased_func)
        original_project = getattr(project, "_inertia_original_project", None)
        if isinstance(delta, int) and original_project is not None and not _source_annotation_lines_8616(func):
            with contextlib.suppress(Exception):
                original_func = original_project.kb.functions.function(addr=int(func_addr) + delta, create=False)
                _merge_source_annotations_if_missing_8616(func, original_func)
        return func
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        with contextlib.suppress(Exception):
            rebased_func = project.kb.functions.function(addr=int(func_addr) + delta, create=False)
            if rebased_func is not None:
                info = getattr(rebased_func, "info", None)
                if getattr(rebased_func, "prototype", None) is not None or (
                    isinstance(info, dict) and bool(info.get(ANNOTATION_KEY))
                ):
                    return rebased_func
    original_project = getattr(project, "_inertia_original_project", None)
    if isinstance(delta, int) and original_project is not None:
        with contextlib.suppress(Exception):
            original_func = original_project.kb.functions.function(addr=int(func_addr) + delta, create=False)
            if original_func is not None:
                return original_func
    return func


def _strip_typed_suffix_8616(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos > 0:
            return name[:brace_pos]
    return name


def _function_complexity_8616(project, function) -> tuple[int, int]:
    block_addrs = sorted(getattr(function, "block_addrs_set", ()) or ())
    byte_count = 0
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        byte_count += len(block.bytes)
    return len(block_addrs), byte_count


def _is_tiny_function_8616(project, function) -> bool:
    block_count, byte_count = _function_complexity_8616(project, function)
    return block_count <= 4 and byte_count <= 32


def _unwrap_synthetic_wide_return_8616(retval):
    if not isinstance(retval, CBinaryOp):
        return None

    candidates = []
    if retval.op == "Or":
        candidates.extend(((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)))
    elif retval.op == "Concat":
        candidates.extend(((retval.lhs, retval.rhs),))
    else:
        return None

    for maybe_wide, maybe_low in candidates:
        if isinstance(maybe_wide, CBinaryOp):
            if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                return maybe_low
            if maybe_wide.op == "Concat":
                return maybe_low

    return None


def _normalize_arg_names_8616(
    arg_names: tuple[str | None, ...] | list[str | None] | None, count: int
) -> list[str | None]:
    normalized: list[str | None] = []
    used: set[str] = set()
    source = list(arg_names or ())
    for index in range(count):
        base_name = source[index] if index < len(source) else None
        if not isinstance(base_name, str) or not base_name:
            base_name = f"a{index}"
        candidate = base_name
        suffix_match = re.fullmatch(r"(?P<base>.+?)_(?P<suffix>\d+)", base_name)
        if suffix_match is not None:
            unsuffixed = suffix_match.group("base")
            if unsuffixed and unsuffixed not in used:
                candidate = unsuffixed
        suffix = 2
        while candidate in used:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        normalized.append(candidate)
        used.add(candidate)
    return normalized


def _known_helper_arg_names_8616(name: str | None) -> list[str] | None:
    if not isinstance(name, str) or not name:
        return None

    decl = preferred_known_helper_signature_decl(name)
    if decl is None:
        return None

    try:
        _, proto, _ = _parse_c_prototype_8616(decl)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "_parse_c_prototype_8616 failed for decl=%r: %s",
            decl,
            ex,
        )
        return None

    if proto is None:
        return None

    arg_names = list(getattr(proto, "arg_names", None) or ())
    return arg_names or None


def _set_codegen_prototype_8616(codegen, prototype) -> None:
    functy_ok = False
    proto_ok = False
    try:
        codegen.cfunc.functy = prototype
        functy_ok = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "setting cfunc.functy failed for %#x: %s",
            getattr(codegen.cfunc, "addr", 0),
            ex,
        )
    try:
        codegen.cfunc.prototype = prototype
        proto_ok = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "setting cfunc.prototype failed for %#x: %s",
            getattr(codegen.cfunc, "addr", 0),
            ex,
        )
    if not functy_ok and not proto_ok:
        logging.getLogger(__name__).warning(
            "codegen prototype set failed for %#x (neither functy nor prototype attribute)",
            getattr(codegen.cfunc, "addr", 0),
        )
    for attr in ("_function", "function", "func"):
        owner = getattr(codegen, attr, None)
        if owner is None:
            continue
        with contextlib.suppress(Exception):
            owner.prototype = prototype
            owner.is_prototype_guessed = False
    with contextlib.suppress(Exception):
        setattr(codegen, "_inertia_codegen_decl_refresh_required_8616", True)
        setattr(
            codegen,
            "_inertia_codegen_prototype_sync_count_8616",
            int(getattr(codegen, "_inertia_codegen_prototype_sync_count_8616", 0) or 0) + 1,
        )


def _prune_return_address_stack_arguments_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    def _impl():
        debug = os.environ.get("INERTIA_DEBUG_RETADDR_PRUNE") == "1"

        def _debug_stack_variable(container: str, variable) -> None:
            if not debug or not isinstance(variable, SimStackVariable):
                return
            identity = _stack_slot_identity_for_variable(variable)
            logging.getLogger(__name__).warning(
                "[retaddr-prune] %s name=%r offset=%r size=%r base=%r identity=%r",
                container,
                getattr(variable, "name", None),
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                getattr(variable, "base", None),
                identity,
            )

        def _return_address_stack_offset(variable) -> int | None:
            if not isinstance(variable, SimStackVariable):
                return None
            identity = _stack_slot_identity_for_variable(variable)
            if identity is None or getattr(identity, "base", None) != "bp":
                return None
            slot_offset = getattr(identity, "offset", None)
            return slot_offset if isinstance(slot_offset, int) else None

        def _should_drop_arg(variable, stack_specs) -> bool:
            slot_offset = _return_address_stack_offset(variable)
            if slot_offset != 0:
                return False
            # BP+2 is the near return IP, not a source-level argument. Metadata
            # can label object-file stack slots with a different bias, but it
            # must not override the architectural return-address exclusion.
            return True

        def _prune_return_address_variable_maps() -> bool:
            changed_maps = False
            cfunc = getattr(codegen, "cfunc", None)
            if cfunc is None:
                return False
            variables_in_use = getattr(cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                for variable in tuple(variables_in_use.keys()):
                    _debug_stack_variable("variables_in_use", variable)
                    if _return_address_stack_offset(variable) == 0:
                        del variables_in_use[variable]
                        changed_maps = True
            unified = getattr(cfunc, "unified_local_vars", None)
            if isinstance(unified, dict):
                for variable in tuple(unified.keys()):
                    _debug_stack_variable("unified_local_vars", variable)
                    if _return_address_stack_offset(variable) == 0:
                        del unified[variable]
                        changed_maps = True
            return changed_maps

        def _arg_name_from_stack_spec(variable, stack_specs):
            arg_name = getattr(variable, "name", None)
            if not isinstance(variable, SimStackVariable):
                return arg_name
            offset = getattr(variable, "offset", None)
            if not (isinstance(offset, int) and offset > 0):
                return arg_name
            spec = stack_specs.get(offset - 2)
            if isinstance(spec, str):
                return spec
            if isinstance(spec, dict):
                spec_name = spec.get("name")
                if isinstance(spec_name, str) and spec_name:
                    return spec_name
            return arg_name

        def _sync_arg_name(arg, variable, arg_name) -> None:
            if arg_name is None:
                return
            try:
                arg.name = arg_name
            except Exception:
                pass
            if variable is not None and getattr(variable, "name", None) != arg_name:
                variable.name = arg_name
            unified = getattr(arg, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != arg_name:
                unified.name = arg_name

        def _build_proto_args_and_names(kept_args, proto_args, stack_specs):
            arg_types = []
            arg_names = []
            for index, arg in enumerate(kept_args):
                arg_type = getattr(arg, "variable_type", None)
                if arg_type is None and index < len(proto_args):
                    arg_type = proto_args[index]
                arg_types.append(arg_type)
                variable = getattr(arg, "variable", None)
                arg_name = _arg_name_from_stack_spec(variable, stack_specs)
                _sync_arg_name(arg, variable, arg_name)
                arg_names.append(arg_name)
            return arg_types, arg_names

        if getattr(codegen, "cfunc", None) is None:
            return False

        func_addr = getattr(codegen.cfunc, "addr", None)
        if func_addr is None:
            return False

        func = _metadata_function_for_codegen_addr_8616(project, func_addr)
        if func is None:
            return False

        prototype = getattr(func, "prototype", None)
        annotations = getattr(func, "info", {}).get(ANNOTATION_KEY, {})
        stack_specs = annotations.get("stack_vars", {}) if isinstance(annotations, dict) else {}
        arg_list = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        if prototype is None or not arg_list:
            return _prune_return_address_variable_maps()

        kept_args = []
        changed = False
        for arg in arg_list:
            variable = getattr(arg, "variable", None)
            _debug_stack_variable("arg_list", variable)
            if _should_drop_arg(variable, stack_specs):
                changed = True
                continue
            kept_args.append(arg)

        changed = _prune_return_address_variable_maps() or changed
        if not changed:
            return False
        codegen.cfunc.arg_list = kept_args
        proto_args = list(getattr(prototype, "args", ()) or ())
        arg_types, arg_names = _build_proto_args_and_names(kept_args, proto_args, stack_specs)

        new_proto = prototype.__class__(
            arg_types,
            prototype.returnty,
            arg_names=_normalize_arg_names_8616(arg_names, len(arg_types)),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        return True

    return _impl()


def _normalize_function_prototype_arg_names_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False

    arg_names = getattr(prototype, "arg_names", None)
    if arg_names is None:
        return False

    normalized = _normalize_arg_names_8616(arg_names, len(getattr(prototype, "args", ()) or ()))
    if list(arg_names) == normalized:
        return False

    new_proto = prototype.__class__(
        list(getattr(prototype, "args", ()) or ()),
        prototype.returnty,
        arg_names=normalized,
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    func.prototype = new_proto
    _set_codegen_prototype_8616(codegen, new_proto)
    return True


def _unify_positive_bp_arg_stack_variables_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    cfunc = codegen.cfunc
    arg_by_identity: dict[object, CVariable] = {}
    arg_variable_ids: set[int] = set()
    for cvar in getattr(cfunc, "arg_list", ()) or ():
        if not isinstance(cvar, CVariable):
            continue
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset <= 0:
            continue
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        arg_by_identity[identity] = cvar
        arg_variable_ids.add(id(variable))

    if not arg_by_identity:
        return False

    changed = False

    def transform(node):
        if not isinstance(node, CVariable):
            return node
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return node
        identity = _stack_slot_identity_for_variable(variable)
        replacement = arg_by_identity.get(identity)
        if replacement is None or replacement is node:
            return node
        return replacement

    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if not isinstance(variable, SimStackVariable) or id(variable) in arg_variable_ids:
                if isinstance(variable, SimStackVariable):
                    identity = _stack_slot_identity_for_variable(variable)
                    replacement = arg_by_identity.get(identity)
                    if replacement is not None and cvar is not replacement:
                        variables_in_use[variable] = replacement
                        changed = True
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity in arg_by_identity:
                del variables_in_use[variable]
                changed = True

    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for variable in tuple(unified.keys()):
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity in arg_by_identity:
                del unified[variable]
                changed = True

    if changed:
        with contextlib.suppress(Exception):
            setattr(codegen, "_inertia_codegen_decl_refresh_required_8616", True)
        codegen._inertia_arg_stack_identity_unified_8616 = (
            int(getattr(codegen, "_inertia_arg_stack_identity_unified_8616", 0) or 0) + 1
        )
    return changed


def _collect_goto_label_names_8616(root) -> set[str]:
    names: set[str] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CLabel):
            label_name = getattr(node, "name", None)
            if isinstance(label_name, str) and label_name:
                names.add(label_name)
    return names


def _collect_mapped_goto_label_names_8616(cfunc) -> set[str]:
    mapping = getattr(cfunc, "map_addr_to_label", None)
    if not isinstance(mapping, dict):
        return set()
    names: set[str] = set()
    for value in mapping.values():
        if isinstance(value, CLabel):
            mapped_name = getattr(value, "name", None)
            if isinstance(mapped_name, str) and mapped_name:
                names.add(mapped_name)
    return names


def _repair_unresolved_function_exit_gotos_8616(project, codegen) -> bool:
    def _impl():
        """Repair unresolved CGoto that are definitely function-exit candidates.

        This is a conservative pass: only jump targets proven to be out-of-procedure
        become ``return``. Any ambiguous in-procedure target remains unchanged.
        """

        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        root = getattr(cfunc, "statements", None)
        if root is None:
            return False

        stats = getattr(codegen, "_inertia_unresolved_goto_exit_stats_8616", None)
        if not isinstance(stats, dict):
            stats = {
                "unresolved_goto_exit_candidates": 0,
                "unresolved_goto_exit_repaired": 0,
                "unresolved_goto_exit_refused": 0,
            }
            codegen._inertia_unresolved_goto_exit_stats_8616 = stats

        func_addr = getattr(cfunc, "addr", None)
        function = None
        if func_addr is not None and project is not None:
            try:
                function = project.kb.functions.function(addr=func_addr, create=False)
            except Exception:
                function = None

        block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
        min_block_addr = block_addrs[0] if block_addrs else None
        max_block_addr = block_addrs[-1] if block_addrs else None

        defined_labels = _collect_goto_label_names_8616(root)
        mapped_labels = _collect_mapped_goto_label_names_8616(cfunc)
        defined_all_labels = defined_labels | mapped_labels

        map_addr_to_label = getattr(cfunc, "map_addr_to_label", None)

        def _is_known_target(target: int, target_idx: int | None) -> bool:
            if not block_addrs:
                return False
            if target in block_addrs:
                return True
            if not isinstance(map_addr_to_label, dict):
                return False
            mapped_label = map_addr_to_label.get((target, target_idx))
            if mapped_label is None and target_idx is not None:
                mapped_label = map_addr_to_label.get((target, None))
            mapped_name = getattr(mapped_label, "name", None) if isinstance(mapped_label, CLabel) else None
            if isinstance(mapped_name, str):
                return mapped_name in defined_all_labels
            return False

        def _is_function_exit_target(target: int) -> bool:
            if not block_addrs:
                return False
            if target in block_addrs:
                return False
            if min_block_addr is None or max_block_addr is None:
                return False
            if target < min_block_addr or target > max_block_addr:
                return True
            return False

        changed = False

        for goto in tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CGoto)):
            target = getattr(goto, "target", None)
            target_idx = getattr(goto, "target_idx", None)
            if not isinstance(target, int):
                stats["unresolved_goto_exit_refused"] = int(stats["unresolved_goto_exit_refused"]) + 1
                continue

            if _is_known_target(target, target_idx):
                continue

            stats["unresolved_goto_exit_candidates"] = int(stats["unresolved_goto_exit_candidates"]) + 1

            if _is_function_exit_target(target):
                candidate_return = CReturn(None, codegen=codegen)
                replaced = _replace_c_children_8616(
                    root,
                    lambda node: candidate_return if node is goto else node,
                )
                if replaced:
                    changed = True
                    stats["unresolved_goto_exit_repaired"] = int(stats["unresolved_goto_exit_repaired"]) + 1
                else:
                    stats["unresolved_goto_exit_refused"] = int(stats["unresolved_goto_exit_refused"]) + 1
                continue

            stats["unresolved_goto_exit_refused"] = int(stats["unresolved_goto_exit_refused"]) + 1

        return changed

    return _impl()


def _make_unique_identifier_8616(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _dedupe_codegen_variable_names_8616(codegen) -> bool:
    # Name dedup is readability-only. If it perturbs canonicalized semantics it must
    # not run in the correctness pipeline by default.
    def _impl():
        if os.environ.get("INERTIA_ENABLE_NAME_DEDUP", "").strip().lower() not in {"1", "true", "yes", "on"}:
            return False

        if getattr(codegen, "cfunc", None) is None:
            return False

        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
            return False

        def is_generic_name(name: object) -> bool:
            normalized = _strip_typed_suffix_8616(name)
            if not isinstance(normalized, str):
                return False
            return re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", normalized) is not None

        def preferred_name(variable, cvar) -> str | None:
            candidates = [
                getattr(variable, "name", None),
                getattr(cvar, "name", None),
                getattr(getattr(cvar, "unified_variable", None), "name", None),
            ]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate and not is_generic_name(candidate):
                    return candidate
            for candidate in candidates:
                if isinstance(candidate, str) and candidate:
                    return candidate
            return None

        def sort_key(item):
            variable, cvar = item
            variable_name = getattr(variable, "name", None)
            cvar_name = getattr(cvar, "name", None)
            variable_name_key = variable_name if isinstance(variable_name, str) else ""
            cvar_name_key = cvar_name if isinstance(cvar_name, str) else ""
            if isinstance(variable, SimStackVariable):
                offset = getattr(variable, "offset", 0)
                base_rank = 0 if isinstance(offset, int) and offset > 0 else 1
                return (
                    0,
                    base_rank,
                    offset if isinstance(offset, int) else 0,
                    getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                    variable_name_key,
                )
            if isinstance(variable, SimRegisterVariable):
                reg = getattr(variable, "reg", 0)
                return (
                    1,
                    reg if isinstance(reg, int) else 0,
                    getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                    variable_name_key,
                )
            if isinstance(variable, SimMemoryVariable):
                addr = getattr(variable, "addr", 0)
                return (
                    2,
                    addr if isinstance(addr, int) else 0,
                    getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                    variable_name_key,
                )
            return (3, variable_name_key, cvar_name_key)

        ordered_items = list(variables_in_use.items()) if isinstance(variables_in_use, dict) else []
        if isinstance(unified_locals, dict):
            for variable, cvars in unified_locals.items():
                if variable not in variables_in_use and cvars:
                    ordered_items.append((variable, next(iter(cvars))[0]))

        ordered_items.sort(key=sort_key)

        used_names: set[str] = set()
        seen_variables: set[int] = set()
        changed = False

        def apply_name(variable, cvar, new_name: str) -> None:
            nonlocal changed
            if getattr(variable, "name", None) != new_name:
                variable.name = new_name
                changed = True
            if getattr(cvar, "name", None) != new_name:
                try:
                    cvar.name = new_name
                except Exception:
                    pass
                else:
                    changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != new_name:
                unified.name = new_name
                changed = True

        for variable, cvar in ordered_items:
            if id(variable) in seen_variables:
                continue
            seen_variables.add(id(variable))
            name = preferred_name(variable, cvar)
            if name is None:
                continue
            if name in used_names:
                name = _make_unique_identifier_8616(name, used_names)
            else:
                used_names.add(name)
            apply_name(variable, cvar, name)

        return changed

    return _impl()


def _return_value_shape_8616(retval) -> str | None:
    def _impl():
        if retval is None:
            return None
        if isinstance(retval, CFunctionCall) and getattr(retval, "callee_target", None) == "MK_FP":
            return "wide_fp"
        if isinstance(retval, CBinaryOp):
            if retval.op in {"Or", "Concat"}:
                for maybe_wide, maybe_low in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                    if _c_constant_value_8616(maybe_low) == 0:
                        return _return_value_shape_8616(maybe_wide) or "wide_fp"
                    if isinstance(maybe_wide, CBinaryOp):
                        if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                            return "wide_fp"
                        if maybe_wide.op == "Concat":
                            return "wide_fp"
            return "scalar"
        if isinstance(retval, CConstant):
            return "scalar"
        if isinstance(retval, CVariable):
            return "scalar"
        if isinstance(retval, CTypeCast):
            return _return_value_shape_8616(retval.expr)
        if isinstance(retval, CUnaryOp):
            return "scalar" if retval.op in {"Neg", "Not", "Reference"} else None
        return "scalar"

    return _impl()


def _stack_arg_has_pointer_evidence_8616(codegen, variable) -> bool:
    identity = _stack_slot_identity_for_variable(variable)
    if identity is None:
        return False

    statements = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for stmt in getattr(statements, "statements", ()) or ():
        for node in _iter_c_nodes_deep_8616(stmt):
            if not isinstance(node, CUnaryOp) or node.op != "Dereference":
                continue
            for operand_node in _iter_c_nodes_deep_8616(node.operand):
                if not isinstance(operand_node, CVariable):
                    continue
                operand_var = getattr(operand_node, "variable", None)
                if _stack_slot_identity_for_variable(operand_var) == identity:
                    return True
    return False


def _source_return_shape_8616(source_return_lines) -> str | None:
    if not source_return_lines:
        return None

    found_value_return = False
    for line in source_return_lines:
        stripped = line.strip()
        if not stripped.startswith("return "):
            continue
        expr = stripped[len("return ") :].rstrip(";").strip()
        if not expr:
            continue
        if expr == "0":
            found_value_return = True
            continue
        found_value_return = True
        if "MK_FP(" in expr or re.search(r"<<\s*16\b", expr) is not None or "Concat(" in expr:
            return "wide_fp"

    if found_value_return:
        return "scalar"
    return None


def _promote_stack_prototype_from_bp_loads_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        func_addr = getattr(codegen.cfunc, "addr", None)
        if func_addr is None:
            return False

        func = _metadata_function_for_codegen_addr_8616(project, func_addr)
        if func is None:
            return False

        prototype = getattr(func, "prototype", None)
        if prototype is None:
            return _promote_positive_bp_stack_slots_to_args_8616(project, codegen)
        if not list(getattr(prototype, "args", ()) or ()):
            if _promote_positive_bp_stack_slots_to_args_8616(project, codegen):
                return True
        current_proto = getattr(getattr(codegen, "cfunc", None), "functy", None) or prototype
        existing_args = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        c_target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat").strip().lower()
        promote_near_pointers = c_target != "portable-flat"

        annotations, source_pointer_flags, stack_specs, annotated_args = _collect_stack_promotion_inputs_8616(func)
        if not source_pointer_flags:
            source_pointer_flags = _source_pointer_flags_from_project_cod_metadata_8616(project, func_addr)
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"promote_stack_proto func={func_addr!r} "
                f"source_pointer_flags={source_pointer_flags!r} "
                f"annotated_args={annotated_args!r}",
                file=sys.stderr,
                flush=True,
            )
        arg_names = list(getattr(prototype, "arg_names", None) or ())

        if _sync_arg_list_from_prototype_stack_layout_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=prototype,
            arg_names=arg_names,
            source_pointer_flags=source_pointer_flags,
        ):
            return True

        if _promote_from_annotated_args_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=prototype,
            arg_names=arg_names,
            existing_args=existing_args,
            annotated_args=annotated_args,
            source_pointer_flags=source_pointer_flags,
            promote_near_pointers=promote_near_pointers,
        ):
            return True

        if _promote_from_fallback_args_8616(
            project=project,
            codegen=codegen,
            func=func,
            current_proto=current_proto,
            existing_args=existing_args,
            source_pointer_flags=source_pointer_flags,
            promote_near_pointers=promote_near_pointers,
        ):
            return True

        return _promote_from_legacy_arg_names_8616(project=project, codegen=codegen, func=func, prototype=prototype, arg_names=arg_names)

    return _impl()


def _promote_positive_bp_stack_slots_to_args_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    candidates: dict[int, tuple[SimStackVariable, CVariable]] = {}
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable) or not isinstance(cvar, CVariable):
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset < 4:
            continue
        candidates.setdefault(offset, (variable, cvar))
    if not candidates:
        return False
    desired_args = []
    arg_types = []
    arg_names = []
    changed = False
    for index, (offset, (variable, cvar)) in enumerate(sorted(candidates.items())):
        width = max(2, int(getattr(variable, "size", 0) or 2))
        name = getattr(variable, "name", None)
        if not isinstance(name, str) or not name or re.fullmatch(r"(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|local_\d+)", name):
            name = f"arg_{offset:x}"
            variable.name = name
            with contextlib.suppress(Exception):
                cvar.name = name
            changed = True
        arg_type = getattr(cvar, "variable_type", None)
        if arg_type is None:
            arg_type = SimTypeShort(False)
            cvar.variable_type = arg_type
            changed = True
        if width > 2 and getattr(arg_type, "size", None) in {None, 16}:
            arg_type = SimTypeLong(False)
            cvar.variable_type = arg_type
            changed = True
        desired_args.append(cvar)
        arg_types.append(arg_type)
        arg_names.append(name if isinstance(name, str) and name else f"arg_{index}")
    existing_args = list(getattr(cfunc, "arg_list", ()) or ())
    if len(existing_args) != len(desired_args) or any(existing is not desired for existing, desired in zip(existing_args, desired_args)):
        cfunc.arg_list = desired_args
        changed = True
    current_proto = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    return_type = getattr(current_proto, "returnty", None) if current_proto is not None else SimTypeShort(False)
    if return_type is None or isinstance(return_type, SimTypeBottom):
        return_type = SimTypeShort(False)
    prototype = SimTypeFunction(arg_types, return_type, arg_names=arg_names).with_arch(project.arch)
    if getattr(cfunc, "functy", None) is not prototype:
        _set_codegen_prototype_8616(codegen, prototype)
        changed = True
    if changed:
        codegen._inertia_positive_bp_args_materialized_8616 = (
            int(getattr(codegen, "_inertia_positive_bp_args_materialized_8616", 0) or 0) + len(desired_args)
        )
    return changed


def _type_size_bytes_8616(type_, *, default: int = 2) -> int:
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _sync_arg_list_from_prototype_stack_layout_8616(
    *, project, codegen, func, prototype, arg_names: list[str], source_pointer_flags: tuple[bool, ...] = ()
) -> bool:
    def _impl():
        proto_args = list(getattr(prototype, "args", ()) or ())
        if not proto_args:
            return False
        original_proto_args = list(proto_args)
        x87_scalar_arg_types = _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen)
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        func_addr = getattr(cfunc, "addr", None)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if not isinstance(variables_in_use, dict):
            return False
        unified = getattr(cfunc, "unified_local_vars", None)
        stack_cvars_by_offset: dict[int, CVariable] = {}
        for variable, cvar in variables_in_use.items():
            if isinstance(variable, SimStackVariable) and isinstance(cvar, CVariable):
                stack_cvars_by_offset.setdefault(getattr(variable, "offset", None), cvar)

        desired_args = []
        expected_offsets: set[int] = set()
        offset = 4
        changed = False
        for index, arg_type in enumerate(proto_args):
            scalar_type = x87_scalar_arg_types.get(offset)
            if scalar_type is not None:
                arg_type = scalar_type
                if proto_args[index] != scalar_type:
                    proto_args[index] = scalar_type
                    changed = True
            elif (
                index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and isinstance(arg_type, SimTypePointer)
            ):
                arg_type = SimTypeShort(False).with_arch(project.arch)
                if proto_args[index] != arg_type:
                    proto_args[index] = arg_type
                    changed = True
            width = max(2, _type_size_bytes_8616(arg_type))
            expected_offsets.add(offset)
            name = arg_names[index] if index < len(arg_names) and isinstance(arg_names[index], str) else f"a{index}"
            cvar = stack_cvars_by_offset.get(offset)
            variable = getattr(cvar, "variable", None) if cvar is not None else None
            if not isinstance(variable, SimStackVariable) or getattr(variable, "size", None) != width:
                variable = SimStackVariable(offset, width, base="bp", name=name, region=func_addr)
                cvar = CVariable(variable, variable_type=arg_type, codegen=codegen)
                variables_in_use[variable] = cvar
                if isinstance(unified, dict):
                    unified[variable] = {(cvar, arg_type)}
                changed = True
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            if getattr(cvar, "name", None) != name:
                with contextlib.suppress(Exception):
                    cvar.name = name
                changed = True
            if getattr(cvar, "variable_type", None) != arg_type:
                cvar.variable_type = arg_type
                changed = True
            desired_args.append(cvar)
            offset += width

        first_arg_offset = min(expected_offsets) if expected_offsets else 4
        for variable in tuple(variables_in_use.keys()):
            if not isinstance(variable, SimStackVariable):
                continue
            var_offset = getattr(variable, "offset", None)
            if isinstance(var_offset, int) and 0 < var_offset < first_arg_offset:
                del variables_in_use[variable]
                changed = True
        if isinstance(unified, dict):
            for variable in tuple(unified.keys()):
                if not isinstance(variable, SimStackVariable):
                    continue
                var_offset = getattr(variable, "offset", None)
                if isinstance(var_offset, int) and 0 < var_offset < first_arg_offset:
                    del unified[variable]
                    changed = True

        existing_args = list(getattr(cfunc, "arg_list", ()) or ())
        if len(existing_args) != len(desired_args) or any(existing is not desired for existing, desired in zip(existing_args, desired_args)):
            cfunc.arg_list = desired_args
            changed = True
        active_prototype = prototype
        if proto_args != original_proto_args:
            active_prototype = prototype.__class__(
                proto_args,
                prototype.returnty,
                arg_names=getattr(prototype, "arg_names", None),
                variadic=getattr(prototype, "variadic", False),
            ).with_arch(project.arch)
            func.prototype = active_prototype
            func.is_prototype_guessed = False
        if getattr(cfunc, "functy", None) is not active_prototype:
            _set_codegen_prototype_8616(codegen, active_prototype)
            changed = True
        return changed

    return _impl()


def _collect_stack_promotion_inputs_8616(func):
    def _impl():
        annotations = {}
        info = getattr(func, "info", None)
        if isinstance(info, dict):
            maybe_annotations = info.get(ANNOTATION_KEY)
            if isinstance(maybe_annotations, dict):
                annotations = maybe_annotations
        source_pointer_flags: tuple[bool, ...] = ()
        source_lines = annotations.get("source_lines", ()) if isinstance(annotations, dict) else ()
        source_decl = _source_decl_from_cod_source_lines(source_lines) if source_lines else None
        if isinstance(source_decl, str) and source_decl:
            try:
                _, parsed_proto, _ = _parse_c_prototype_8616(source_decl)
            except Exception:
                parsed_proto = None
            else:
                if parsed_proto is not None:
                    source_pointer_flags = tuple(
                        isinstance(arg, SimTypePointer) for arg in (getattr(parsed_proto, "args", ()) or ())
                    )
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"collect_inputs func={getattr(func, 'addr', None)!r} "
                f"source_lines={len(tuple(source_lines or ())) if source_lines else 0} "
                f"source_decl={source_decl!r} "
                f"source_pointer_flags={source_pointer_flags!r}",
                file=sys.stderr,
                flush=True,
            )
        stack_specs = annotations.get("stack_vars", {}) if isinstance(annotations, dict) else {}
        annotated_args: list[tuple[int, str | None]] = []
        if isinstance(stack_specs, dict):
            for offset, spec in sorted(stack_specs.items(), key=lambda item: item[0]):
                if not isinstance(offset, int) or offset <= 0:
                    continue
                name = None
                if isinstance(spec, str):
                    name = spec
                elif isinstance(spec, dict):
                    spec_name = spec.get("name")
                    if isinstance(spec_name, str) and spec_name:
                        name = spec_name
                annotated_args.append((offset, name))
        return annotations, source_pointer_flags, stack_specs, annotated_args

    return _impl()


def _source_pointer_flags_from_lines_8616(source_lines) -> tuple[bool, ...]:
    source_lines = tuple(source_lines or ())
    source_decl = _source_decl_from_cod_source_lines(source_lines) if source_lines else None
    if not isinstance(source_decl, str) or not source_decl:
        return ()
    try:
        _, parsed_proto, _ = _parse_c_prototype_8616(source_decl)
    except Exception:
        return ()
    if parsed_proto is None:
        return ()
    return tuple(isinstance(arg, SimTypePointer) for arg in (getattr(parsed_proto, "args", ()) or ()))


def _source_pointer_flags_from_project_cod_metadata_8616(project, func_addr: int | None) -> tuple[bool, ...]:
    if not isinstance(func_addr, int):
        return ()
    metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if not isinstance(metadata_by_addr, dict):
        return ()
    candidates = [func_addr]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        candidates.append(func_addr + delta)
        rebased = func_addr - delta
        if rebased >= 0:
            candidates.append(rebased)
    for candidate in candidates:
        metadata = metadata_by_addr.get(candidate)
        flags = _source_pointer_flags_from_lines_8616(getattr(metadata, "source_lines", ()) if metadata is not None else ())
        if flags:
            return flags
    return ()


def _source_decl_from_project_cod_metadata_8616(project, func_addr: int | None) -> str | None:
    if not isinstance(func_addr, int):
        return None
    metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if not isinstance(metadata_by_addr, dict):
        return None
    candidates = [func_addr]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        candidates.append(func_addr + delta)
        rebased = func_addr - delta
        if rebased >= 0:
            candidates.append(rebased)
    for candidate in candidates:
        metadata = metadata_by_addr.get(candidate)
        source_decl = _source_decl_from_cod_source_lines(
            tuple(getattr(metadata, "source_lines", ()) or ()) if metadata is not None else ()
        )
        if isinstance(source_decl, str) and source_decl:
            return source_decl
    return None


def _pointer_type_for_codegen_8616(codegen):
    pointer_type = SimTypePointer(SimTypeShort(False))
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is not None and hasattr(pointer_type, "with_arch"):
        pointer_type = pointer_type.with_arch(arch)
    return pointer_type


def _x87_scalar_stack_arg_types_8616(project, func, *, codegen=None) -> dict[int, object]:
    candidates = [getattr(codegen, "_func", None) if codegen is not None else None, func]
    seen: set[int] = set()
    for candidate in candidates:
        if candidate is None or id(candidate) in seen:
            continue
        seen.add(id(candidate))
        try:
            result = x86_16_msvc_x87_scalar_stack_args(project, candidate)
        except Exception:
            logging.getLogger(__name__).debug(
                "x87 scalar stack evidence failed for %#x",
                getattr(candidate, "addr", 0),
                exc_info=True,
            )
            continue
        if result:
            if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
                print(
                    "[dbg-x87-proto] "
                    f"func={getattr(func, 'addr', None)!r} "
                    f"candidate={getattr(candidate, 'addr', None)!r} "
                    f"args={sorted(result)}",
                    file=sys.stderr,
                    flush=True,
                )
            return result
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"func={getattr(func, 'addr', None)!r} "
                f"candidate={getattr(candidate, 'addr', None)!r} "
                "args=[]",
                file=sys.stderr,
                flush=True,
            )
    return {}


def _apply_stack_arg_cvar_type_8616(codegen, cvar, variable_type) -> bool:
    changed = False
    if getattr(cvar, "variable_type", None) != variable_type:
        with contextlib.suppress(Exception):
            cvar.variable_type = variable_type
            changed = True
    variable = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
    variable_manager = getattr(getattr(codegen, "cfunc", None), "variable_manager", None)
    if variable_manager is not None and variable is not None:
        with contextlib.suppress(Exception):
            variable_manager.set_variable_type(variable, variable_type)
    return changed


def _promote_from_annotated_args_8616(
    *,
    project,
    codegen,
    func,
    prototype,
    arg_names: list[str],
    existing_args: list,
    annotated_args: list[tuple[int, str | None]],
    source_pointer_flags: tuple[bool, ...],
    promote_near_pointers: bool,
) -> bool:
    def _impl():
        if not annotated_args:
            return False
        target_arg_count = len(annotated_args)
        new_args = list(getattr(prototype, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(SimTypeShort(False).with_arch(project.arch) for _ in range(target_arg_count - len(new_args)))
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]
        desired_names = []
        for index in range(target_arg_count):
            annotated_name = annotated_args[index][1] if index < len(annotated_args) else None
            existing_name = arg_names[index] if index < len(arg_names) else None
            desired_names.append(annotated_name or existing_name)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
        stack_cvars_by_offset = {}
        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if isinstance(variable, SimStackVariable):
                stack_cvars_by_offset.setdefault(getattr(variable, "offset", None), cvar)
        pointer_promoted = False
        scalar_materialized = False
        resolved_args = []
        pointer_type = _pointer_type_for_codegen_8616(codegen)
        x87_scalar_arg_types = _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen)
        for index in range(target_arg_count):
            annotated_offset = annotated_args[index][0] if index < len(annotated_args) else None
            resolved_arg = existing_args[index] if index < len(existing_args) else stack_cvars_by_offset.get(annotated_offset)
            resolved_args.append(resolved_arg)
            scalar_type = x87_scalar_arg_types.get(annotated_offset)
            if scalar_type is not None:
                if resolved_arg is not None:
                    scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if (
                resolved_arg is not None
                and isinstance(new_args[index], SimTypePointer)
                and index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None))
            ):
                scalar_type = SimTypeShort(False).with_arch(project.arch)
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if resolved_arg is None or not promote_near_pointers:
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                resolved_arg.variable_type = pointer_type
                pointer_promoted = True
            if new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True
        if not (
            scalar_materialized
            or pointer_promoted
            or target_arg_count > len(getattr(prototype, "args", ()) or ())
            or list(arg_names) != normalized_names
        ):
            return False
        new_proto = prototype.__class__(
            new_args,
            prototype.returnty,
            arg_names=normalized_names,
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        arg_list = getattr(codegen.cfunc, "arg_list", None)
        if isinstance(arg_list, list) and len(arg_list) > target_arg_count:
            codegen.cfunc.arg_list = arg_list[:target_arg_count]
        elif not arg_list and any(resolved_arg is not None for resolved_arg in resolved_args):
            codegen.cfunc.arg_list = [resolved_arg for resolved_arg in resolved_args if resolved_arg is not None]
        return True



    return _impl()
def _promote_from_fallback_args_8616(
    *,
    project,
    codegen,
    func,
    current_proto,
    existing_args: list,
    source_pointer_flags: tuple[bool, ...],
    promote_near_pointers: bool,
) -> bool:
    def _impl():
        fallback_args = [arg for arg in existing_args if isinstance(getattr(arg, "variable", None), SimStackVariable)]
        if not fallback_args:
            return False
        target_arg_count = len(fallback_args)
        new_args = list(getattr(current_proto, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(SimTypeShort(False).with_arch(project.arch) for _ in range(target_arg_count - len(new_args)))
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]
        pointer_promoted = False
        scalar_materialized = False
        pointer_type = _pointer_type_for_codegen_8616(codegen)
        x87_scalar_arg_types = _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen)
        for index, resolved_arg in enumerate(fallback_args):
            variable = getattr(resolved_arg, "variable", None)
            var_offset = getattr(variable, "offset", None)
            scalar_type = x87_scalar_arg_types.get(var_offset)
            if scalar_type is not None:
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if index < len(new_args) and new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if (
                index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and index < len(new_args)
                and isinstance(new_args[index], SimTypePointer)
            ):
                scalar_type = SimTypeShort(False).with_arch(project.arch)
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if not promote_near_pointers:
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                resolved_arg.variable_type = pointer_type
                pointer_promoted = True
            if index < len(new_args) and new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True
        if not (scalar_materialized or pointer_promoted):
            return False
        desired_names = []
        for index in range(target_arg_count):
            if index < len(fallback_args):
                desired_names.append(
                    getattr(getattr(fallback_args[index], "unified_variable", None), "name", None)
                    or fallback_args[index].name
                )
            elif index < len(getattr(current_proto, "arg_names", ()) or ()):
                desired_names.append(current_proto.arg_names[index])
            else:
                desired_names.append(None)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
        new_proto = current_proto.__class__(
            new_args,
            current_proto.returnty,
            arg_names=normalized_names,
            variadic=getattr(current_proto, "variadic", False),
        )
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        if arch is not None and hasattr(new_proto, "with_arch"):
            new_proto = new_proto.with_arch(arch)
        func.prototype = new_proto
        codegen.cfunc.functy = new_proto
        codegen.cfunc.arg_list = fallback_args
        return True

    return _impl()


def _legacy_arg_names_only_8616(arg_names: list[str]) -> bool:
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return False
    return True


def _has_wide_return_pattern_8616(codegen) -> bool:
    def _impl():
        for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
            if not isinstance(stmt, CReturn):
                continue
            retval = getattr(stmt, "retval", None)
            if not isinstance(retval, CBinaryOp) or retval.op != "Or":
                continue
            for maybe_shl, maybe_other in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                if not isinstance(maybe_shl, CBinaryOp) or maybe_shl.op != "Shl":
                    continue
                if _c_constant_value_8616(maybe_shl.rhs) != 16:
                    continue
                if isinstance(maybe_other, CVariable):
                    return True
        return False

    return _impl()


def _promote_from_legacy_arg_names_8616(*, project, codegen, func, prototype, arg_names: list[str]) -> bool:
    def _impl():
        if not _legacy_arg_names_only_8616(arg_names):
            return False
        if not getattr(codegen, "cfunc", None):
            return False
        stack_slots_by_offset = {}
        for variable, _cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity is not None:
                stack_slots_by_offset[getattr(variable, "offset", None)] = identity
        offsets = set()
        slot_identities = set()
        for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
            if not isinstance(stmt, CReturn):
                continue
            retval = getattr(stmt, "retval", None)
            if retval is None:
                continue
            for node in _iter_c_nodes_deep_8616(retval):
                offset = _match_bp_stack_load_8616(node, project)
                if offset is not None and offset > 2:
                    offsets.add(offset)
                    slot_identity = stack_slots_by_offset.get(offset)
                    if slot_identity is not None:
                        slot_identities.add(slot_identity)
        if len(slot_identities) > 1:
            return False
        existing_args = list(getattr(prototype, "args", ()) or ())
        if offsets:
            target_arg_count = max(len(existing_args), max(((offset - 2) // 2) for offset in offsets))
            if target_arg_count > len(existing_args):
                new_args = list(existing_args)
                new_args.extend(SimTypeShort(False).with_arch(project.arch) for _ in range(target_arg_count - len(existing_args)))
            else:
                new_args = list(existing_args)
            normalized_names = _normalize_arg_names_8616(getattr(prototype, "arg_names", None), len(new_args))
            if target_arg_count > len(existing_args):
                new_proto = prototype.__class__(
                    new_args,
                    prototype.returnty,
                    arg_names=normalized_names,
                    variadic=getattr(prototype, "variadic", False),
                ).with_arch(project.arch)
                func.prototype = new_proto
                func.is_prototype_guessed = False
                _set_codegen_prototype_8616(codegen, new_proto)
                return True
        if not isinstance(prototype.returnty, SimTypeLong) or not _has_wide_return_pattern_8616(codegen):
            return False
        wide_ty = SimTypeLong().with_arch(project.arch)
        new_proto = prototype.__class__(
            [wide_ty],
            wide_ty,
            arg_names=_normalize_arg_names_8616(getattr(prototype, "arg_names", None), 1),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        return True

    return _impl()


def _classify_return_shape_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    # Return-shape reclassification mutates function prototypes and can affect
    # observable memory/ABI behavior. Keep it opt-in until fully proven stable.
    def _impl():
        if os.environ.get("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "").strip().lower() not in {"1", "true", "yes", "on"}:
            return False

        func, prototype = _resolve_codegen_function_and_prototype_8616(project, codegen)
        if func is None or prototype is None:
            return False

        source_return_lines, source_lines, source_decl_is_void = _collect_source_return_annotation_8616(func)

        return_nodes = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CReturn)]
        if not return_nodes:
            source_shape = _source_return_shape_8616(source_return_lines)
            if source_shape is None and not source_decl_is_void:
                return False
            return_nodes = []
        else:
            source_shape = _source_return_shape_8616(source_return_lines)

        tiny_function = _is_tiny_function_8616(project, func)
        changed = False
        value_returns = 0
        return_shapes: set[str] = set()

        for ret in return_nodes:
            retval = getattr(ret, "retval", None)
            if retval is None:
                continue
            value_returns += 1
            shape = _return_value_shape_8616(retval)
            replacement = _unwrap_synthetic_wide_return_8616(retval)
            if tiny_function and replacement is not None:
                ret.retval = None
                changed = True
                if shape is not None and shape != "wide_fp":
                    return_shapes.add(shape)
                continue
            if shape is not None:
                return_shapes.add(shape)

        has_value_return = any(getattr(ret, "retval", None) is not None for ret in return_nodes)
        if not has_value_return and not return_nodes and source_shape is None and not source_decl_is_void:
            return changed

        shape = "void" if not has_value_return and source_shape is None else "scalar_ax"

        info = getattr(func, "info", None)
        if isinstance(info, dict):
            return_info = info.setdefault("x86_16_return_shape", {})
            return_info["shape"] = shape
            return_info["tiny_function"] = tiny_function
            return_info["value_returns"] = value_returns

        new_returnty = _choose_return_type_for_shape_8616(
            shape=shape,
            return_shapes=return_shapes,
            source_shape=source_shape,
            existing_returnty=getattr(prototype, "returnty", None),
        )

        if new_returnty is None:
            return changed

        new_proto = prototype.__class__(
            list(getattr(prototype, "args", ()) or ()),
            new_returnty,
            arg_names=getattr(prototype, "arg_names", None),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        return True

    return _impl()


def _resolve_codegen_function_and_prototype_8616(project: SimpleNamespace, codegen: SimpleNamespace):
    if getattr(codegen, "cfunc", None) is None:
        return None, None
    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return None, None
    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return None, None
    prototype = getattr(func, "prototype", None)
    return func, prototype


def _collect_source_return_annotation_8616(func) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    source_return_lines: tuple[str, ...] = ()
    source_lines: tuple[str, ...] = ()
    info = getattr(func, "info", None)
    if isinstance(info, dict):
        annotations = info.get(ANNOTATION_KEY)
        if isinstance(annotations, dict):
            source_return_lines = tuple(annotations.get("source_return_lines", ()) or ())
            source_lines = tuple(annotations.get("source_lines", ()) or ())
    source_decl = _source_decl_from_cod_source_lines(source_lines) if source_lines else None
    if not (isinstance(source_decl, str) and source_decl):
        return source_return_lines, source_lines, False
    try:
        _, source_proto, _ = _parse_c_prototype_8616(source_decl)
    except Exception as ex:
        logging.getLogger(__name__).debug("source decl proto parsing failed decl=%r: %s", source_decl, ex)
        source_proto = None
    source_decl_is_void = _is_void_return_type_8616(getattr(source_proto, "returnty", None))
    return source_return_lines, source_lines, source_decl_is_void


def _is_void_return_type_8616(return_type) -> bool:
    return isinstance(return_type, SimTypeBottom) and getattr(return_type, "label", None) == "void"


def _function_has_void_return_prototype_8616(func) -> bool:
    prototype = getattr(func, "prototype", None)
    if _is_void_return_type_8616(getattr(prototype, "returnty", None)):
        return True
    return _collect_source_return_annotation_8616(func)[2]


def _choose_return_type_for_shape_8616(
    *,
    shape: str,
    return_shapes: set[str],
    source_shape: str | None,
    existing_returnty,
):
    def _impl():
        if shape == "void":
            return SimTypeBottom(label="void")
        if shape == "scalar_ax" and ((return_shapes and return_shapes <= {"scalar"}) or source_shape == "scalar"):
            return None if isinstance(existing_returnty, SimTypeShort) else SimTypeShort(False)
        if (return_shapes and return_shapes <= {"wide_fp"}) or source_shape == "wide_fp":
            return None if isinstance(existing_returnty, SimTypeLong) else SimTypeLong()
        return None

    return _impl()


def _prune_void_function_return_values_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    if not _function_has_void_return_prototype_8616(func):
        return False

    changed = False
    for container in tuple(_iter_c_nodes_deep_8616(codegen.cfunc.statements)):
        if not isinstance(container, CStatements):
            continue
        statements = list(getattr(container, "statements", ()) or ())
        if not statements:
            continue
        is_root_container = container is codegen.cfunc.statements
        rewritten: list[object] = []
        local_changed = False
        for index, stmt in enumerate(statements):
            if not isinstance(stmt, CReturn):
                rewritten.append(stmt)
                continue
            retval = getattr(stmt, "retval", None)
            if retval is None:
                rewritten.append(stmt)
                continue
            if isinstance(retval, CFunctionCall):
                rewritten.append(CExpressionStatement(retval, codegen=getattr(stmt, "codegen", codegen)))
                if not (is_root_container and index == len(statements) - 1):
                    rewritten.append(CReturn(None, codegen=getattr(stmt, "codegen", codegen)))
                local_changed = True
                continue
            rewritten.append(stmt)
        if local_changed:
            container.statements = rewritten
            changed = True
    if changed:
        with contextlib.suppress(Exception):
            setattr(codegen, "_inertia_codegen_decl_refresh_required_8616", True)
    return changed


def _apply_annotations_8616(project, codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        func_addr = getattr(codegen.cfunc, "addr", None)
        if func_addr is None:
            return False

        func = _metadata_function_for_codegen_addr_8616(project, func_addr)
        if func is None:
            return False

        changed = False
        source_decl = _source_decl_from_project_cod_metadata_8616(project, func_addr)
        source_proto_applied = False
        if isinstance(source_decl, str) and source_decl:
            with contextlib.suppress(Exception):
                annotate_function(project, func_addr, name=getattr(func, "name", None), c_decl=source_decl)
                refreshed = project.kb.functions.function(addr=func_addr, create=False)
                if refreshed is not None:
                    func = refreshed
                    if getattr(codegen, "cfunc", None) is not None and getattr(func, "prototype", None) is not None:
                        _set_codegen_prototype_8616(codegen, func.prototype)
                        for index, cvar in enumerate(getattr(codegen.cfunc, "arg_list", ()) or ()):
                            if index >= len(getattr(func.prototype, "args", ()) or ()):
                                break
                            _apply_stack_arg_cvar_type_8616(codegen, cvar, func.prototype.args[index])
                    source_proto_applied = True
                    changed = True
                    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
                        print(
                            "[dbg-x87-proto] "
                            f"source_proto_applied func={func_addr!r} decl={source_decl!r} "
                            f"proto={getattr(func, 'prototype', None)!r}",
                            file=sys.stderr,
                            flush=True,
                        )
        if not source_proto_applied:
            changed_helper, func = _apply_helper_signature_annotation_8616(project, codegen, func_addr, func)
            changed |= changed_helper
            if func is None:
                return False
        changed |= _attach_project_cod_source_annotations_if_missing_8616(project, func_addr, func)
        annotations = func.info.get(ANNOTATION_KEY)
        if not annotations:
            return False

        stack_specs = annotations.get("stack_vars", {})
        global_specs = annotations.get("global_vars", {})
        c_target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat").strip().lower()
        promote_near_pointers = c_target != "portable-flat"
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"apply_annotations func={getattr(func, 'addr', None)!r} "
                f"cfunc={getattr(codegen.cfunc, 'addr', None)!r} "
                f"project_id={id(project)} "
                f"cod_map_keys={sorted(getattr(project, '_inertia_cod_metadata_by_func_addr_8616', {}) or {})} "
                f"stack_offsets={sorted(k for k in stack_specs if isinstance(k, int))}",
                file=sys.stderr,
                flush=True,
            )

        def global_spec_for(addr: int):
            spec = global_specs.get(addr)
            if isinstance(spec, str):
                return spec, None
            if isinstance(spec, dict):
                name = spec.get("name")
                vartype = spec.get("type")
                if isinstance(name, str):
                    return name, vartype
            return None, None

        arg_slot_identities = {
            _stack_slot_identity_for_variable(getattr(arg, "variable", None))
            for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
            if isinstance(getattr(arg, "variable", None), SimStackVariable)
        }
        helper_arg_names = list(getattr(getattr(func, "prototype", None), "arg_names", ()) or ())
        helper_arg_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
        helper_arg_name_by_offset = {
            offset: helper_arg_names[index]
            for index, offset in enumerate(helper_arg_offsets)
            if index < len(helper_arg_names) and isinstance(helper_arg_names[index], str) and helper_arg_names[index]
        }
        stack_vars_by_offset = {}
        used_stack_names: set[str] = set()
        name_owner_offsets: dict[str, int] = {}
        exact_stack_candidates: dict[int, list[tuple[tuple[int, int, int, int, int], CVariable]]] = {}

        def _stack_name_is_generic(name: object) -> bool:
            normalized = _strip_typed_suffix_8616(name)
            if not isinstance(normalized, str):
                return False
            return (
                isinstance(normalized, str)
                and re.fullmatch(r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", normalized)
                is not None
            )

        def _stack_candidate_score(variable, cvar, *, exact: bool) -> tuple[int, int, int, int, int]:
            identity = _stack_slot_identity_for_variable(variable)
            if identity is None:
                return (-1, -1, -1, -1, -1)
            variable_name = getattr(variable, "name", None)
            cvar_name = getattr(cvar, "name", None)
            unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
            preferred_name = next(
                (
                    name
                    for name in (variable_name, cvar_name, unified_name)
                    if isinstance(name, str) and name and not _stack_name_is_generic(name)
                ),
                None,
            )
            is_arg_slot = 1 if identity in arg_slot_identities else 0
            has_preferred_name = 1 if preferred_name is not None else 0
            size = getattr(variable, "size", None)
            size_rank = -size if isinstance(size, int) else 0
            exact_rank = 1 if exact else 0
            return (exact_rank, is_arg_slot, has_preferred_name, size_rank, -getattr(variable, "offset", 0))

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if isinstance(variable, SimStackVariable):
                offset = getattr(variable, "offset", None)
                if not isinstance(offset, int):
                    continue
                score = _stack_candidate_score(variable, cvar, exact=True)
                exact_stack_candidates.setdefault(offset, []).append((score, cvar))

        for offset, candidates in exact_stack_candidates.items():
            best_score, best_cvar = max(candidates, key=lambda item: item[0])
            stack_vars_by_offset[offset] = best_cvar

        materialized_stack_cvars: dict[int, CVariable] = {}

        def _stack_spec_for_offset(offset: int):
            spec = stack_specs.get(offset)
            if spec is None and isinstance(offset, int) and offset < 0:
                spec = stack_specs.get(offset + 2)
            return spec

        def _materialize_stack_cvar(offset: int, type_):
            existing = materialized_stack_cvars.get(offset)
            if existing is not None:
                return existing

            spec = _stack_spec_for_offset(offset)
            if spec is None:
                return None

            name = None
            spec_type = None
            if isinstance(spec, str):
                name = spec
            elif isinstance(spec, dict):
                spec_name = spec.get("name")
                if isinstance(spec_name, str) and spec_name:
                    name = spec_name
                spec_type = spec.get("type")

            if name is None:
                return None

            size = max((getattr(type_, "size", None) or 8) // 8, 1)
            stack_var = SimStackVariable(offset, size, base="bp", name=name, region=func_addr)
            vartype = type_ if type_ is not None else spec_type
            cvar = CVariable(stack_var, variable_type=vartype, codegen=codegen)
            materialized_stack_cvars[offset] = cvar

            variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                variables_in_use[stack_var] = cvar

            unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
            if isinstance(unified_locals, dict):
                unified_locals[stack_var] = {
                    (cvar, vartype if vartype is not None else getattr(cvar, "variable_type", None))
                }

            stack_vars_by_offset[offset] = cvar
            return cvar

        def resolve_stack_cvar(offset: int):
            direct = stack_vars_by_offset.get(offset)
            if direct is not None:
                return direct

            normalized_offset = offset - 2
            if normalized_offset != offset:
                direct = stack_vars_by_offset.get(normalized_offset)
                if direct is not None:
                    return direct

            # Positive stack slots are arguments in the x86-16 calling
            # convention model we use here. If we have no exact materialization
            # yet, synthesize the slot rather than aliasing it to a covering local
            # variable. That keeps argument storage distinct from locals and avoids
            # collapsing different stack objects onto the same C variable name.
            if offset > 0:
                return _materialize_stack_cvar(offset, None)

            best = None
            best_size = None
            for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
                if not isinstance(variable, SimStackVariable):
                    continue
                base_offset = getattr(variable, "offset", None)
                size = getattr(variable, "size", None)
                if not isinstance(base_offset, int) or not isinstance(size, int):
                    continue
                if base_offset <= offset < base_offset + size:
                    if best is None or size < best_size:
                        best = cvar
                        best_size = size
            if best is not None:
                return best
            return _materialize_stack_cvar(offset, None)

        changed |= _rename_stack_variables_from_specs_8616(
            codegen=codegen,
            stack_specs=stack_specs,
            helper_arg_name_by_offset=helper_arg_name_by_offset,
            used_stack_names=used_stack_names,
            name_owner_offsets=name_owner_offsets,
        )

        changed |= _apply_annotation_rewrites_8616(
            project=project,
            codegen=codegen,
            stack_vars_by_offset=stack_vars_by_offset,
            global_spec_for=global_spec_for,
            resolve_stack_cvar=resolve_stack_cvar,
            materialize_stack_cvar=_materialize_stack_cvar,
            stack_candidate_score=_stack_candidate_score,
        )

        arg_list_synced = _sync_arg_list_from_annotations_8616(
            codegen=codegen,
            func=func,
            stack_specs=stack_specs,
            resolve_stack_cvar=resolve_stack_cvar,
            promote_near_pointers=promote_near_pointers,
        )
        if arg_list_synced:
            changed = True

        return changed

    return _impl()


def _rename_stack_variables_from_specs_8616(
    *,
    codegen,
    stack_specs,
    helper_arg_name_by_offset: dict[int, str],
    used_stack_names: set[str],
    name_owner_offsets: dict[str, int],
) -> bool:
    def _impl():
        def unique_stack_name(base_name: str | None) -> str | None:
            if not isinstance(base_name, str) or not base_name:
                return None
            candidate = base_name
            suffix = 2
            while candidate in used_stack_names:
                candidate = f"{base_name}_{suffix}"
                suffix += 1
            used_stack_names.add(candidate)
            return candidate

        def spec_name_for(variable):
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int) and offset > 0:
                helper_name = helper_arg_name_by_offset.get(offset)
                if helper_name is not None:
                    return helper_name, None
            spec = stack_specs.get(offset)
            if spec is None and isinstance(offset, int) and offset < 0:
                spec = stack_specs.get(offset + 2)
            if isinstance(spec, str):
                return spec, None
            if isinstance(spec, dict):
                return spec.get("name"), spec.get("type")
            return None, None

        changed = False
        stack_items = sorted(
            [
                (variable, cvar)
                for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items()
                if isinstance(variable, SimStackVariable)
            ],
            key=lambda item: (
                0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
                abs(getattr(item[0], "offset", 0)) if isinstance(getattr(item[0], "offset", None), int) else 0,
                getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
                getattr(item[0], "name", "") or "",
            ),
        )
        for variable, cvar in stack_items:
            name, vartype = spec_name_for(variable)
            if name is None:
                current = getattr(variable, "name", None)
                if current and not current.startswith(("arg_", "s_", "v")):
                    name = current
            current_name = getattr(variable, "name", None)
            if isinstance(current_name, str) and current_name and current_name == name:
                used_stack_names.add(current_name)
                name_owner_offsets[current_name] = (
                    getattr(variable, "offset", 0) if isinstance(getattr(variable, "offset", None), int) else 0
                )
                unified = getattr(cvar, "unified_variable", None)
                if unified is not None and getattr(unified, "name", None) != current_name:
                    unified.name = current_name
                    changed = True
                if getattr(cvar, "name", None) != current_name:
                    try:
                        cvar.name = current_name
                    except Exception:
                        pass
                    else:
                        changed = True
                continue
            if name is not None and name in used_stack_names:
                owner_offset = name_owner_offsets.get(name)
                offset = getattr(variable, "offset", None)
                if owner_offset != offset:
                    name = unique_stack_name(name)
                    if name is not None:
                        name_owner_offsets[name] = offset if isinstance(offset, int) else 0
            else:
                name = unique_stack_name(name)
                if name is not None:
                    offset = getattr(variable, "offset", None)
                    name_owner_offsets[name] = offset if isinstance(offset, int) else 0
            if name is not None:
                target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
                if target is not None and getattr(target, "name", None) != name:
                    target.name = name
                    changed = True
                if getattr(variable, "name", None) != name:
                    variable.name = name
                    changed = True
            if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
                cvar.variable_type = vartype
                changed = True
        return changed



    return _impl()
def _sync_arg_list_from_annotations_8616(
    *,
    codegen,
    func,
    stack_specs,
    resolve_stack_cvar,
    promote_near_pointers: bool,
) -> bool:
    def _impl():
        arg_offsets = [offset for offset in sorted(stack_specs) if isinstance(offset, int) and offset > 0]
        if not arg_offsets:
            return False
        resolved_args = []
        for offset in arg_offsets:
            cvar = resolve_stack_cvar(offset)
            if isinstance(cvar, CVariable):
                resolved_args.append(cvar)
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"sync_annotations func={getattr(func, 'addr', None)!r} "
                f"arg_offsets={arg_offsets} resolved={len(resolved_args)}",
                file=sys.stderr,
                flush=True,
            )
        if not resolved_args:
            return False
        current_proto = getattr(codegen.cfunc, "functy", None) or getattr(func, "prototype", None)
        if current_proto is None:
            return False
        existing_args = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        target_arg_count = len(resolved_args)
        new_args = list(getattr(current_proto, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(getattr(getattr(codegen, "project", None), "arch", None))
                for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]
        pointer_promoted = False
        scalar_materialized = False
        pointer_type = _pointer_type_for_codegen_8616(codegen)
        project = getattr(codegen, "project", None)
        _, source_pointer_flags, _, _ = _collect_stack_promotion_inputs_8616(func)
        if not source_pointer_flags:
            source_pointer_flags = _source_pointer_flags_from_project_cod_metadata_8616(
                project,
                getattr(getattr(codegen, "cfunc", None), "addr", getattr(func, "addr", None)),
            )
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"sync_annotations source_pointer_flags={source_pointer_flags!r}",
                file=sys.stderr,
                flush=True,
            )
        x87_scalar_arg_types = (
            _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen) if project is not None else {}
        )
        for index, resolved_arg in enumerate(resolved_args):
            variable = getattr(resolved_arg, "variable", None)
            scalar_type = x87_scalar_arg_types.get(getattr(variable, "offset", None))
            if scalar_type is not None:
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if index < len(new_args) and new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False and isinstance(
                new_args[index], SimTypePointer
            ):
                arch = getattr(project, "arch", None)
                scalar_type = SimTypeShort(False).with_arch(arch) if arch is not None else SimTypeShort(False)
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if index < len(new_args) and new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if not promote_near_pointers:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, variable):
                continue
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                resolved_arg.variable_type = pointer_type
                pointer_promoted = True
            if index < len(new_args) and new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True
        desired_names = []
        for index in range(target_arg_count):
            if index < len(resolved_args):
                desired_names.append(
                    getattr(getattr(resolved_args[index], "unified_variable", None), "name", None)
                    or resolved_args[index].name
                )
            elif index < len(getattr(current_proto, "arg_names", ()) or ()):
                desired_names.append(current_proto.arg_names[index])
            else:
                desired_names.append(None)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
        if (
            len(existing_args) == target_arg_count
            and len(getattr(current_proto, "args", ()) or ()) == target_arg_count
            and list(getattr(current_proto, "arg_names", ()) or ()) == normalized_names
            and all(existing is resolved for existing, resolved in zip(existing_args, resolved_args))
            and not pointer_promoted
            and not scalar_materialized
        ):
            return False
        new_proto = current_proto.__class__(
            new_args,
            current_proto.returnty,
            arg_names=normalized_names,
            variadic=getattr(current_proto, "variadic", False),
        )
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        if arch is not None and hasattr(new_proto, "with_arch"):
            new_proto = new_proto.with_arch(arch)
        func.prototype = new_proto
        codegen.cfunc.functy = new_proto
        codegen.cfunc.arg_list = resolved_args
        return True



    return _impl()
def _apply_annotation_rewrites_8616(
    *,
    project,
    codegen,
    stack_vars_by_offset: dict[int, CVariable],
    global_spec_for,
    resolve_stack_cvar,
    materialize_stack_cvar,
    stack_candidate_score,
) -> bool:
    def _impl():
        changed = False
        preferred_stack_cvars_by_identity: dict[object, CVariable] = {}
        for cvar in getattr(codegen.cfunc, "arg_list", ()) or ():
            if not isinstance(cvar, CVariable):
                continue
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity is not None:
                preferred_stack_cvars_by_identity[identity] = cvar
        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity is None:
                continue
            current_best = preferred_stack_cvars_by_identity.get(identity)
            if current_best is None:
                preferred_stack_cvars_by_identity[identity] = cvar
                continue
            current_best_var = getattr(current_best, "variable", None)
            if not isinstance(current_best_var, SimStackVariable):
                preferred_stack_cvars_by_identity[identity] = cvar
                continue
            current_score = stack_candidate_score(current_best_var, current_best, exact=True)
            new_score = stack_candidate_score(variable, cvar, exact=True)
            if new_score > current_score:
                preferred_stack_cvars_by_identity[identity] = cvar

        def transform_stack_aliases(node):
            if not isinstance(node, CVariable):
                return node
            variable = getattr(node, "variable", None)
            if not isinstance(variable, SimStackVariable):
                return node
            identity = _stack_slot_identity_for_variable(variable)
            if identity is None:
                return node
            preferred = preferred_stack_cvars_by_identity.get(identity)
            if preferred is None or preferred is node:
                return node
            return preferred

        if _replace_c_children_8616(codegen.cfunc.statements, transform_stack_aliases):
            changed = True

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimMemoryVariable):
                continue
            name, vartype = global_spec_for(getattr(variable, "addr", None))
            if not isinstance(name, str):
                continue
            current = getattr(variable, "name", None)
            if current and not current.startswith(("g_", "field_")) and current != name:
                continue
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            if target is not None and getattr(target, "name", None) != name:
                target.name = name
                changed = True
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
                cvar.variable_type = vartype
                changed = True

        def transform_globals(node):
            nonlocal changed
            if not isinstance(node, CVariable):
                return node
            variable = getattr(node, "variable", None)
            if not isinstance(variable, SimMemoryVariable):
                return node
            name, vartype = global_spec_for(getattr(variable, "addr", None))
            if not isinstance(name, str):
                return node
            current = getattr(variable, "name", None)
            if current and not current.startswith(("g_", "field_")) and current != name:
                return node
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            return CVariable(
                variable,
                variable_type=vartype if vartype is not None else getattr(node, "variable_type", None),
                codegen=codegen,
            )

        if _replace_c_children_8616(codegen.cfunc.statements, transform_globals):
            changed = True

        def transform(node):
            if not _structured_codegen_node_8616(node):
                return node
            direct_offset = _match_bp_stack_load_8616(node, project)
            if direct_offset is not None:
                type_ = getattr(node, "type", None)
                stack_cvar = resolve_stack_cvar(direct_offset) or materialize_stack_cvar(direct_offset, type_)
                if stack_cvar is not None:
                    return stack_cvar
            if isinstance(node, CBinaryOp) and node.op in {"Or", "Add"}:
                for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                    low_offset = _match_bp_stack_load_8616(low_expr, project)
                    if low_offset is None:
                        continue
                    high_offset = _match_bp_stack_load_8616(high_expr, project)
                    if high_offset != low_offset + 1:
                        continue
                    low_cvar = stack_vars_by_offset.get(low_offset)
                    high_cvar = stack_vars_by_offset.get(high_offset)
                    if low_cvar is not None and high_cvar is not None:
                        low_var = getattr(low_cvar, "variable", None)
                        high_var = getattr(high_cvar, "variable", None)
                        if isinstance(low_var, SimStackVariable) and isinstance(high_var, SimStackVariable):
                            if not _stack_slot_identity_can_join(low_var, high_var):
                                continue
                    if low_cvar is not None:
                        return low_cvar
            return node

        if _replace_c_children_8616(codegen.cfunc.statements, transform):
            changed = True
        return changed

    return _impl()


def _apply_helper_signature_annotation_8616(project, codegen, func_addr: int, func):
    def _impl():
        nonlocal func
        changed = False
        func_name = getattr(func, "name", None)
        if isinstance(func_name, str) and func_name.startswith("_") and not func_name.startswith("__"):
            stripped_name = func_name.lstrip("_")
            if (
                isinstance(stripped_name, str)
                and stripped_name
                and preferred_known_helper_signature_decl(func_name) is not None
                and preferred_known_helper_signature_decl(stripped_name) is not None
                and getattr(func, "name", None) != stripped_name
            ):
                func.name = stripped_name
                if getattr(codegen, "cfunc", None) is not None and getattr(codegen.cfunc, "name", None) != stripped_name:
                    codegen.cfunc.name = stripped_name
                changed = True
                func_name = stripped_name
            stripped_decl = preferred_known_helper_signature_decl(stripped_name) if isinstance(stripped_name, str) else None
            if isinstance(stripped_decl, str) and stripped_decl:
                existing = tuple(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
                if stripped_decl not in existing:
                    codegen._inertia_callsite_prototype_decls = existing + (stripped_decl,)
                    changed = True
        helper_decl = preferred_known_helper_signature_decl(func_name)
        if helper_decl is None:
            return changed, func
        annotate_function(project, func_addr, name=func_name, c_decl=helper_decl)
        func = project.kb.functions.function(addr=func_addr, create=False)
        if func is None:
            return changed, None
        if getattr(codegen, "cfunc", None) is not None and getattr(func, "prototype", None) is not None:
            codegen.cfunc.functy = func.prototype
            prototype_arg_names = tuple(getattr(func.prototype, "arg_names", ()) or ())
            for index, cvar in enumerate(getattr(codegen.cfunc, "arg_list", ()) or ()):
                if index >= len(prototype_arg_names):
                    break
                arg_name = prototype_arg_names[index]
                if not isinstance(arg_name, str) or not arg_name:
                    continue
                variable = getattr(cvar, "variable", None)
                unified = getattr(cvar, "unified_variable", None)
                if variable is not None and getattr(variable, "name", None) != arg_name:
                    variable.name = arg_name
                if unified is not None and getattr(unified, "name", None) != arg_name:
                    unified.name = arg_name
                if getattr(cvar, "name", None) != arg_name:
                    cvar.name = arg_name
        return True, func



    return _impl()
def _prune_unused_unnamed_memory_declarations_8616(codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        used_variables: set[int] = set()
        for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
            if not isinstance(node, CVariable):
                continue
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))

        changed = False
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable in list(variables_in_use):
                if not isinstance(variable, SimMemoryVariable):
                    continue
                name = getattr(variable, "name", None)
                if not isinstance(name, str) or not name.startswith("g_"):
                    continue
                if id(variable) in used_variables:
                    continue
                cvar = variables_in_use[variable]
                unified = getattr(cvar, "unified_variable", None)
                if unified is not None and id(unified) in used_variables:
                    continue
                del variables_in_use[variable]
                changed = True

        return changed

    return _impl()


def _prune_unused_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    used_registers: set[int] = set()
    used_variables: set[int] = set()

    def collect_reads(node, *, assignment_lhs: bool = False):
        if not _structured_codegen_node_8616(node):
            return
        if isinstance(node, CVariable) and not assignment_lhs:
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
                if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
                    used_registers.add(variable.reg)
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))
                if isinstance(unified, SimRegisterVariable) and getattr(unified, "reg", None) is not None:
                    used_registers.add(unified.reg)
            return

        for attr in (
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "callee_target",
            "else_node",
            "retval",
        ):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                collect_reads(child)
        lhs = getattr(node, "lhs", None)
        if _structured_codegen_node_8616(lhs):
            collect_reads(lhs, assignment_lhs=isinstance(node, CAssignment))
        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    collect_reads(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            collect_reads(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    collect_reads(cond)
                if _structured_codegen_node_8616(body):
                    collect_reads(body)

    collect_reads(codegen.cfunc.statements)

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            for stmt in node.statements:
                visit(stmt)
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if (
                        isinstance(variable, SimRegisterVariable)
                        and getattr(variable, "reg", None) == flags_offset
                        and id(variable) not in used_variables
                        and getattr(variable, "reg", None) not in used_registers
                    ):
                        changed = True
                        continue
                new_statements.append(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed


def _c_expr_uses_register_8616(node, reg_offset: int) -> bool:
    def _impl():
        if not _structured_codegen_node_8616(node):
            return False
        if isinstance(node, CVariable):
            variable = getattr(node, "variable", None)
            return isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == reg_offset

        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iftrue",
            "iffalse",
            "callee_target",
            "else_node",
            "retval",
        ):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child) and _c_expr_uses_register_8616(child, reg_offset):
                return True

        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item) and _c_expr_uses_register_8616(item, reg_offset):
                    return True
                if isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem) and _c_expr_uses_register_8616(subitem, reg_offset):
                            return True

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                    return True
                if _structured_codegen_node_8616(body) and _c_expr_uses_register_8616(body, reg_offset):
                    return True

        return False

    return _impl()


def _stmt_reads_reg_before_write_8616(stmt, reg_offset: int) -> tuple[bool, bool]:
    def _impl():
        if not _structured_codegen_node_8616(stmt):
            return False, False

        if isinstance(stmt, CAssignment):
            lhs = stmt.lhs
            writes = (
                isinstance(lhs, CVariable)
                and isinstance(getattr(lhs, "variable", None), SimRegisterVariable)
                and getattr(lhs.variable, "reg", None) == reg_offset
            )
            reads = _c_expr_uses_register_8616(stmt.rhs, reg_offset)
            return reads, writes

        if isinstance(stmt, CStatements):
            for substmt in stmt.statements:
                reads, writes = _stmt_reads_reg_before_write_8616(substmt, reg_offset)
                if reads:
                    return True, writes
                if writes:
                    return False, True
            return False, False

        if type(stmt).__name__ == "CIfElse":
            cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
            for cond, body in cond_nodes:
                if _c_expr_uses_register_8616(cond, reg_offset):
                    return True, False
                reads, writes = _stmt_reads_reg_before_write_8616(body, reg_offset)
                if reads:
                    return True, writes
            else_node = getattr(stmt, "else_node", None)
            if else_node is not None:
                reads, writes = _stmt_reads_reg_before_write_8616(else_node, reg_offset)
                if reads:
                    return True, writes
            return False, False

        if type(stmt).__name__ == "CWhileLoop":
            cond = getattr(stmt, "condition", None)
            if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                return True, False
            body = getattr(stmt, "body", None)
            if body is not None:
                return _stmt_reads_reg_before_write_8616(body, reg_offset)
            return False, False

        return _c_expr_uses_register_8616(stmt, reg_offset), False

    return _impl()


def _prune_overwritten_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            statements = list(node.statements)
            for idx, stmt in enumerate(statements):
                remove = False
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == flags_offset:
                        remainder = CStatements(statements[idx + 1 :], codegen=codegen)
                        reads, _writes = _stmt_reads_reg_before_write_8616(remainder, flags_offset)
                        if not reads:
                            remove = True
                if not remove:
                    new_statements.append(stmt)
                    visit(stmt)
                else:
                    changed = True
            node.statements = new_statements
            return

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed
