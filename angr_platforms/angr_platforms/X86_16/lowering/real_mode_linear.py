"""Typed helpers for recognizing real-mode segment:offset linearizations.

The x86-16 lifter represents a real-mode memory address as
``(segment << 4) + offset`` (or equivalently ``segment * 16 + offset``).
This module centralizes that structural recognition so stack lowering can
consume a typed SS address fact instead of re-learning the arithmetic shape in
late cleanup code.
"""

from __future__ import annotations

import logging
import contextlib
import os
import sys
from dataclasses import dataclass
from enum import Enum

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable
from capstone.x86_const import (
    X86_INS_ADC,
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_DEC,
    X86_INS_INC,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_SAL,
    X86_INS_SHL,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_DX,
    X86_REG_INVALID,
    X86_REG_SP,
)

from ..alias.alias_model import _stack_storage_facts_for_segmented_address_8616
from .stack_lowering_from_facts import _canonical_stack_offset_8616, _stack_object_name

_SEGMENT_REGISTER_NAMES_8616 = {"cs", "ds", "es", "ss"}
log = logging.getLogger(__name__)


def _dirty_reg_offset_8616(dirty) -> int | None:
    for attr in ("reg", "reg_offset", "parameter_reg_offset"):
        try:
            value = getattr(dirty, attr, None)
        except TypeError:
            # AIL DirtyExpression exposes register-only properties that raise
            # for memory/tmp-backed expressions. That is negative evidence, not
            # a lowering failure.
            continue
        if isinstance(value, int):
            return value
    return None


@dataclass(frozen=True, slots=True)
class RealModeLinearStackAccess8616:
    """Stable SS stack access recovered from real-mode linear address math."""

    displacement: int
    width: int | None


@dataclass(frozen=True, slots=True)
class RealModeLinearGlobalAddress8616:
    """Stable DS/ES address-valued expression recovered from real-mode linear math."""

    segment_name: str
    displacement: int
    residual_terms: tuple[tuple[int, object], ...]
    width: int | None = None


@dataclass(frozen=True, slots=True)
class DirectGlobalUpdateFact8616:
    """Binary-proven direct no-base/no-index global INC/DEC side effect."""

    displacement: int
    width: int
    delta: int
    ins_addr: int


@dataclass(frozen=True, slots=True)
class DirectStackUpdateFact8616:
    """Binary-proven direct BP-relative stack INC/DEC side effect."""

    offset: int
    width: int
    delta: int
    ins_addr: int


class DirectStackMoveSourceKind8616(Enum):
    """Binary-proven source kind for a direct BP-relative stack MOV store."""

    IMMEDIATE = "immediate"
    STACK_SLOT = "stack_slot"
    STACK_SLOT_EXPR = "stack_slot_expr"
    WIDE_CALL_RETURN_STACK_ARITH = "wide_call_return_stack_arith"


class DirectStackMoveExpressionOp8616(Enum):
    """Pure expression operation in a binary-proven stack MOV source."""

    ADD = "Add"
    SHL = "Shl"


class DirectGlobalUpdateMaterializationKind8616(Enum):
    """How a binary-proven direct global update was materialized in C."""

    REPLACED_TAGGED_ASSIGNMENT = "replace"
    INSERTED_BEFORE_NEXT_TAGGED_STATEMENT = "insert_before_next"
    INSERTED_AT_BODY_START = "insert_body_start"


@dataclass(frozen=True, slots=True)
class DirectStackMoveFact8616:
    """Binary-proven direct BP-relative stack MOV side effect."""

    dst_offset: int
    width: int
    source_kind: DirectStackMoveSourceKind8616
    ins_addr: int
    source_value: int | None = None
    source_offset: int | None = None
    source_op: DirectStackMoveExpressionOp8616 | None = None
    source_immediate: int | None = None
    source_call_target: int | None = None
    source_call_name: str | None = None


class StackCarrierDeltaSource8616(Enum):
    """Evidence source for a recovered virtual stack-pointer carrier delta."""

    SP_REGISTER_SEED = 1
    STACK_REFERENCE_SEED = 2
    ALIAS_OBSERVATION = 3


_STACK_CARRIER_DELTA_SOURCE_PRIORITY_8616 = {
    StackCarrierDeltaSource8616.SP_REGISTER_SEED: 1,
    StackCarrierDeltaSource8616.STACK_REFERENCE_SEED: 2,
    StackCarrierDeltaSource8616.ALIAS_OBSERVATION: 3,
}


_UNRESOLVED_STACK_OFFSET_8616 = object()


def _type_for_access_width_8616(width: int | None):
    if width == 1:
        return SimTypeChar(False)
    if width == 4:
        return SimTypeLong(False)
    return SimTypeShort(False)


def _dereference_access_width_bytes_8616(node) -> int | None:
    width_bits = getattr(getattr(node, "type", None), "size", None)
    if isinstance(width_bits, int) and width_bits > 0:
        return max(width_bits // 8, 1)
    operand = getattr(node, "operand", None)
    if isinstance(operand, structured_c.CTypeCast):
        dst_type = getattr(operand, "dst_type", None)
        pts_to = getattr(dst_type, "pts_to", None) if isinstance(dst_type, SimTypePointer) else None
        width = _type_size_bytes_8616(pts_to, default=0)
        if width > 0:
            return width
    return None


def _cvar_storage_size_bytes_8616(cvar, variable) -> int | None:
    candidates: list[int] = []
    size = getattr(variable, "size", None)
    if isinstance(size, int) and size > 0:
        candidates.append(size)
    type_size = _type_size_bytes_8616(getattr(cvar, "variable_type", None), default=0)
    if isinstance(type_size, int) and type_size > 0:
        candidates.append(type_size)
    if not candidates:
        return None
    return min(candidates)


def _apply_preferred_stack_cvar_name_8616(cvar, displacement: int, codegen) -> None:
    preferred_name = _preferred_stack_object_name_8616(displacement, codegen=codegen)
    if not isinstance(preferred_name, str) or not preferred_name:
        return
    for target in (
        getattr(cvar, "variable", None),
        getattr(cvar, "unified_variable", None),
    ):
        if target is None:
            continue
        with contextlib.suppress(Exception):
            if getattr(target, "name", None) != preferred_name:
                target.name = preferred_name
    with contextlib.suppress(Exception):
        if getattr(cvar, "name", None) != preferred_name:
            cvar.name = preferred_name


def _prototype_arg_type_for_bp_offset_8616(codegen, offset: int) -> object | None:
    if not isinstance(offset, int) or offset < 4:
        return None
    for proto in _candidate_function_prototypes_8616(codegen):
        current_offset = 4
        for arg_type in tuple(getattr(proto, "args", ()) or ()):
            if current_offset == offset:
                return arg_type
            current_offset += max(2, _type_size_bytes_8616(arg_type))
    return None


def _ensure_positive_bp_stack_arg_8616(codegen, cvar, target_type) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    variable = getattr(cvar, "variable", None)
    if cfunc is None or not isinstance(variable, SimStackVariable):
        return
    offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
    if not isinstance(offset, int) or offset <= 2:
        return
    if getattr(variable, "base", None) != "bp":
        return
    prototype_type = _prototype_arg_type_for_bp_offset_8616(codegen, offset)
    effective_type = prototype_type if prototype_type is not None else target_type
    if getattr(cvar, "variable_type", None) != effective_type:
        cvar.variable_type = effective_type
        if prototype_type is not None:
            codegen._inertia_stack_arg_source_prototype_type_materialized_8616 = (
                int(getattr(codegen, "_inertia_stack_arg_source_prototype_type_materialized_8616", 0) or 0) + 1
            )

    arg_by_offset: dict[int, object] = {}
    for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
        arg_var = getattr(arg, "variable", None)
        arg_offset = _canonical_stack_offset_8616(getattr(arg_var, "offset", None))
        if isinstance(arg_var, SimStackVariable) and isinstance(arg_offset, int) and arg_offset > 2:
            arg_by_offset[arg_offset] = arg
    arg_by_offset[offset] = cvar
    cfunc.arg_list = [arg_by_offset[key] for key in sorted(arg_by_offset)]

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for existing in tuple(unified.keys()):
            existing_offset = _canonical_stack_offset_8616(getattr(existing, "offset", None))
            if isinstance(existing, SimStackVariable) and existing_offset == offset:
                del unified[existing]

    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    return_type = getattr(prototype, "returnty", None) if prototype is not None else SimTypeShort(False)
    arg_types = []
    for arg in cfunc.arg_list:
        arg_var = getattr(arg, "variable", None)
        arg_offset = _canonical_stack_offset_8616(getattr(arg_var, "offset", None))
        proto_arg_type = _prototype_arg_type_for_bp_offset_8616(codegen, arg_offset)
        arg_type = proto_arg_type or getattr(arg, "variable_type", None) or SimTypeShort(False)
        if proto_arg_type is not None and getattr(arg, "variable_type", None) != proto_arg_type:
            arg.variable_type = proto_arg_type
        arg_types.append(arg_type)
    arg_names = [
        getattr(getattr(arg, "variable", None), "name", None) or getattr(arg, "name", None) or f"arg_{idx}"
        for idx, arg in enumerate(cfunc.arg_list)
    ]
    new_proto = SimTypeFunction(arg_types, return_type, arg_names=arg_names)
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is not None:
        new_proto = new_proto.with_arch(arch)
    with contextlib.suppress(Exception):
        cfunc.functy = new_proto
    with contextlib.suppress(Exception):
        cfunc.prototype = new_proto


def stack_cvar_for_stable_ss_linear_access_8616(codegen, access: RealModeLinearStackAccess8616):
    """Materialize a proven SS linear stack access as a C stack variable."""

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    displacement = _canonical_stack_offset_8616(access.displacement)
    if not isinstance(displacement, int):
        return None
    target_type = _type_for_access_width_8616(access.width)
    requested_size = int(access.width or 1)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    for arg in getattr(cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if (
            isinstance(arg, structured_c.CVariable)
            and isinstance(variable, SimStackVariable)
            and _canonical_stack_offset_8616(getattr(variable, "offset", None)) == displacement
        ):
            existing_size = _cvar_storage_size_bytes_8616(arg, variable)
            if isinstance(existing_size, int) and existing_size < requested_size:
                continue
            if getattr(arg, "variable_type", None) is None:
                arg.variable_type = target_type
            _apply_preferred_stack_cvar_name_8616(arg, displacement, codegen)
            if isinstance(variables_in_use, dict):
                variables_in_use.setdefault(variable, arg)
            _ensure_positive_bp_stack_arg_8616(codegen, arg, target_type)
            return arg
    if isinstance(variables_in_use, dict):
        for variable, cvar in variables_in_use.items():
            if (
                isinstance(variable, SimStackVariable)
                and _canonical_stack_offset_8616(getattr(variable, "offset", None)) == displacement
            ):
                existing_size = _cvar_storage_size_bytes_8616(cvar, variable)
                if isinstance(existing_size, int) and existing_size < requested_size:
                    continue
                if getattr(cvar, "variable_type", None) is None:
                    cvar.variable_type = target_type
                _apply_preferred_stack_cvar_name_8616(cvar, displacement, codegen)
                _ensure_positive_bp_stack_arg_8616(codegen, cvar, target_type)
                return cvar
    variable = SimStackVariable(
        displacement,
        access.width or 1,
        base="bp",
        name=_preferred_stack_object_name_8616(displacement, codegen=codegen),
        region=getattr(cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
    _ensure_positive_bp_stack_arg_8616(codegen, cvar, target_type)
    return cvar


def _positive_stack_spec_lookup_bias_8616(stack_specs: dict[object, object]) -> int:
    positive_offsets = {
        int(key)
        for key in stack_specs
        if isinstance(key, int) and key > 0
    }
    # Some debug/object-file stack maps are biased by the near return address:
    # source arg0 is recorded at +2 while the linked binary uses BP+4. Pick one
    # bias for all positive argument slots; probing offset and offset-2 per slot
    # can collapse BP+4 and BP+6 onto the same source name.
    if 2 in positive_offsets and 6 not in positive_offsets:
        return -2
    return 0


def _preferred_stack_object_name_8616(offset: int, codegen=None) -> str:
    default_name = _stack_object_name(offset, codegen=codegen)
    cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
    func = getattr(codegen, "_func", None) if codegen is not None else None
    if func is None and cfunc is not None:
        project = getattr(codegen, "project", None)
        kb = getattr(project, "kb", None) if project is not None else None
        funcs = getattr(kb, "functions", None) if kb is not None else None
        func_addr = getattr(cfunc, "addr", None)
        if funcs is not None and isinstance(func_addr, int):
            with contextlib.suppress(Exception):
                func = funcs.function(addr=func_addr, create=False)
    info = getattr(func, "info", None)
    annotations = info.get("x86_16_annotations") if isinstance(info, dict) else None
    stack_specs = annotations.get("stack_vars") if isinstance(annotations, dict) else None
    if not isinstance(stack_specs, dict):
        return default_name
    candidate_offsets = (offset,)
    if isinstance(offset, int) and offset > 2:
        bias = _positive_stack_spec_lookup_bias_8616(stack_specs)
        if bias != 0:
            candidate_offsets = (offset + bias,)
    for candidate_offset in candidate_offsets:
        spec = stack_specs.get(candidate_offset)
        if isinstance(spec, str) and spec:
            return spec
        if isinstance(spec, dict):
            name = spec.get("name")
            if isinstance(name, str) and name:
                return name
    return default_name


def _strip_casts_8616(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _sim_variable_global_address_8616(variable) -> int | None:
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", None)
        return (int(addr) & 0xFFFF) if isinstance(addr, int) else None
    if isinstance(variable, SimVariable):
        # Internal fallback used by the structured codegen when a global address
        # label exists without a SimMemoryVariable identity.
        name = getattr(variable, "name", None)
        if isinstance(name, str) and len(name) == 6 and name.startswith("g_"):
            try:
                return int(name[2:], 16) & 0xFFFF
            except ValueError:
                return None
    return None


def _address_label_value_8616(node, *, allow_sp_anchor: bool = False) -> int | None:
    """Return an address literal carried by an address-label C expression.

    This is intentionally narrower than `_constant_value_8616`: it only applies
    inside real-mode effective-address decomposition, where a materialized
    `&global` label is evidence for an offset, not a pointer-valued data use.
    """

    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Reference":
        return None
    operand = _strip_casts_8616(getattr(node, "operand", None))
    if not isinstance(operand, structured_c.CVariable):
        return None
    variable = getattr(operand, "variable", None)
    addr = _sim_variable_global_address_8616(variable)
    if addr is not None:
        return addr
    if allow_sp_anchor and isinstance(variable, SimStackVariable):
        base = getattr(variable, "base", None)
        offset = getattr(variable, "offset", None)
        if base == "sp" and offset == 0:
            return 0
    return None


def _term_contains_memory_address_label_8616(node) -> bool:
    pending: list[object] = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            continue
        expr_id = id(expr)
        if expr_id in seen:
            continue
        seen.add(expr_id)
        if isinstance(expr, structured_c.CUnaryOp) and expr.op == "Reference":
            operand = _strip_casts_8616(getattr(expr, "operand", None))
            variable = getattr(operand, "variable", None)
            if _sim_variable_global_address_8616(variable) is not None:
                return True
            pending.append(operand)
            continue
        for attr in ("lhs", "rhs", "operand", "expr", "index"):
            child = getattr(expr, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = getattr(expr, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in children if child is not None)
    return False


def _normalize_address_label_terms_8616(
    node,
    codegen=None,
    *,
    allow_sp_anchor: bool = False,
) -> tuple[object, int]:
    """Fold address-label references to integer offsets inside EA arithmetic."""

    folded_value = _address_label_value_8616(node, allow_sp_anchor=allow_sp_anchor)
    if folded_value is not None:
        ctype = SimTypeShort(False)
        return structured_c.CConstant(
            folded_value,
            ctype,
            codegen=getattr(node, "codegen", None) or codegen,
        ), 1

    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp):
        operand, count = _normalize_address_label_terms_8616(
            getattr(node, "operand", None),
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        if count:
            return structured_c.CUnaryOp(node.op, operand, codegen=getattr(node, "codegen", None) or codegen), count
        return node, 0
    if isinstance(node, structured_c.CBinaryOp):
        lhs, lhs_count = _normalize_address_label_terms_8616(
            getattr(node, "lhs", None),
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        rhs, rhs_count = _normalize_address_label_terms_8616(
            getattr(node, "rhs", None),
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        count = lhs_count + rhs_count
        if count:
            return structured_c.CBinaryOp(node.op, lhs, rhs, codegen=getattr(node, "codegen", None) or codegen), count
        return node, 0
    return node, 0


def _has_bp_stack_alias_evidence_8616(codegen) -> bool:
    facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(facts, list):
        for fact in facts:
            identity = getattr(fact, "identity", None)
            if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
                continue
            if getattr(identity[1], "base", None) == "bp":
                return True

    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in variables_in_use:
            if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
                return True
    return False


def _known_bp_stack_offsets_8616(codegen) -> set[int]:
    offsets: set[int] = set()

    facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(facts, list):
        for fact in facts:
            identity = getattr(fact, "identity", None)
            if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
                continue
            slot = identity[1]
            if getattr(slot, "base", None) != "bp":
                continue
            offset = _canonical_stack_offset_8616(getattr(slot, "offset", None))
            if isinstance(offset, int):
                offsets.add(offset)

    bindings = getattr(codegen, "_inertia_stack_variable_bindings", None)
    if isinstance(bindings, tuple):
        for binding in bindings:
            offset = _canonical_stack_offset_8616(getattr(binding, "bp_offset", None))
            if offset is None:
                offset = _canonical_stack_offset_8616(getattr(binding, "offset", None))
            if isinstance(offset, int):
                offsets.add(offset)

    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in variables_in_use:
            if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
                continue
            offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
            if isinstance(offset, int):
                offsets.add(offset)

    for arg in getattr(getattr(codegen, "cfunc", None), "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
        if isinstance(offset, int):
            offsets.add(offset)

    offsets.update(_prototype_bp_stack_offsets_8616(codegen))
    offsets.update(_bp_memory_operand_offsets_from_function_blocks_8616(codegen))

    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[ss-linear-lowering] known-bp-offsets function=%#x offsets=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            tuple(sorted(offsets)),
        )

    return offsets


def _bp_stack_arg_offsets_8616(codegen) -> set[int]:
    offsets: set[int] = set()
    for arg in getattr(getattr(codegen, "cfunc", None), "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
        if isinstance(offset, int):
            offsets.add(offset)

    offsets.update(_prototype_bp_stack_offsets_8616(codegen))
    return offsets


def _bp_stack_abi_argument_region_offsets_8616(offsets: set[int]) -> set[int]:
    # In near BP-framed 16-bit C functions, BP+0 is saved BP and BP+2 is the
    # return address. Positive data arguments begin at BP+4. If this filtered
    # set is still ambiguous, carrier inference refuses instead of guessing.
    return {offset for offset in offsets if offset >= 4}


def _type_size_bytes_8616(type_, *, default: int = 2) -> int:
    if isinstance(type_, SimTypeChar):
        return 1
    if isinstance(type_, SimTypeShort):
        return 2
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _candidate_function_prototypes_8616(codegen) -> tuple[object, ...]:
    prototypes: list[object] = []
    cfunc = getattr(codegen, "cfunc", None)
    project = getattr(codegen, "project", None)
    func_addr = getattr(cfunc, "addr", None)
    owner_candidates = [
        getattr(codegen, "_func", None),
        getattr(codegen, "function", None),
        getattr(codegen, "func", None),
    ]
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is not None and isinstance(func_addr, int):
        try:
            owner_candidates.append(kb.functions.function(addr=func_addr, create=False))
        except Exception:
            pass

    deferred_owner_prototypes: list[object] = []
    for owner in owner_candidates:
        proto = getattr(owner, "prototype", None) if owner is not None else None
        if proto is None:
            continue
        if getattr(owner, "is_prototype_guessed", True) is False:
            if proto not in prototypes:
                prototypes.append(proto)
        elif proto not in deferred_owner_prototypes:
            deferred_owner_prototypes.append(proto)

    for attr in ("functy", "prototype"):
        proto = getattr(cfunc, attr, None)
        if proto is not None and proto not in prototypes:
            prototypes.append(proto)
    for proto in deferred_owner_prototypes:
        if proto not in prototypes:
            prototypes.append(proto)
    return tuple(prototypes)


def _prototype_bp_stack_offsets_8616(codegen) -> set[int]:
    offsets: set[int] = set()
    for proto in _candidate_function_prototypes_8616(codegen):
        proto_args = tuple(getattr(proto, "args", ()) or ())
        if not proto_args:
            continue
        offset = 4
        for arg_type in proto_args:
            offsets.add(offset)
            offset += max(2, _type_size_bytes_8616(arg_type))
    if offsets:
        codegen._inertia_stack_arg_offsets_from_prototype_count_8616 = len(offsets)
    return offsets


def _bp_memory_operand_offsets_from_function_blocks_8616(codegen) -> set[int]:
    offsets: set[int] = set()
    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is None or not isinstance(func_addr, int):
        return offsets
    try:
        func = kb.functions.function(addr=func_addr, create=False)
    except Exception:
        return offsets
    if func is None:
        return offsets
    for block in getattr(func, "blocks", ()) or ():
        capstone = getattr(block, "capstone", None)
        for insn in getattr(capstone, "insns", ()) or ():
            for operand in getattr(insn, "operands", ()) or ():
                if getattr(operand, "type", None) != X86_OP_MEM:
                    continue
                mem = getattr(operand, "mem", None)
                if getattr(mem, "base", None) != X86_REG_BP:
                    continue
                disp = getattr(mem, "disp", None)
                if isinstance(disp, int):
                    offsets.add(disp)
    if offsets:
        codegen._inertia_stack_bp_offsets_from_capstone_count_8616 = len(offsets)
    return offsets


def _iter_stack_base_displacements_8616(root) -> tuple[int, ...]:
    def stack_base_displacement(node) -> int | None:
        node = _strip_casts_8616(node)
        if _is_stack_base_placeholder_8616(node):
            return 0
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = stack_base_displacement(getattr(node, "lhs", None))
            rhs = stack_base_displacement(getattr(node, "rhs", None))
            lhs_const = _constant_value_8616(getattr(node, "lhs", None))
            rhs_const = _constant_value_8616(getattr(node, "rhs", None))
            if lhs is not None and isinstance(rhs_const, int):
                return lhs + (rhs_const if node.op == "Add" else -rhs_const)
            if rhs is not None and isinstance(lhs_const, int) and node.op == "Add":
                return rhs + lhs_const
        return None

    stack = [root]
    seen: set[int] = set()
    displacements: set[int] = set()
    while stack:
        node = stack.pop()
        if node is None:
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)

        disp = stack_base_displacement(node)
        if isinstance(disp, int):
            displacements.add(disp)
            # Consume the maximal stack_base expression. Recursing into its
            # children would add the bare stack_base as a separate zero-offset
            # observation and can make BP-bias evidence ambiguous.
            continue

        if isinstance(node, structured_c.CIndexedVariable):
            base_disp = stack_base_displacement(getattr(node, "variable", None))
            index_value = _constant_value_8616(getattr(node, "index", None))
            if isinstance(base_disp, int) and isinstance(index_value, int):
                displacements.add(base_disp + index_value)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            disp = stack_base_displacement(getattr(node, "operand", None))
            if isinstance(disp, int):
                displacements.add(disp)

        for attr in (
            "statements",
            "condition_and_nodes",
            "else_node",
            "lhs",
            "rhs",
            "operand",
            "variable",
            "index",
            "expr",
            "stmts",
            "init",
            "initializer",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "iteration",
            "iterator",
            "body",
            "args",
            "operands",
        ):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:  # noqa: BLE001
                continue
            if value is None:
                continue
            if isinstance(value, (list, tuple)):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)

    return tuple(sorted(displacements))


def _infer_stack_base_bp_bias_8616(codegen) -> int | None:
    cached = getattr(codegen, "_inertia_stack_base_bp_bias_evidence_8616", None)
    cache_key = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is cache_key:
        return cached[1]

    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    displacements = _iter_stack_base_displacements_8616(root)
    inferred: int | None = None

    if len(displacements) >= 2 and known_offsets:
        best_bias = None
        best_score = 0
        tied = False
        for disp in displacements:
            for offset in known_offsets:
                bias = offset - disp
                score = len({candidate + bias for candidate in displacements if candidate + bias in known_offsets})
                if score > best_score:
                    best_bias = bias
                    best_score = score
                    tied = False
                elif score == best_score and score > 0 and bias != best_bias:
                    tied = True
        if isinstance(best_bias, int) and best_score >= 2 and not tied:
            inferred = best_bias

    setattr(codegen, "_inertia_stack_base_bp_bias_evidence_8616", (cache_key, inferred))
    if isinstance(inferred, int):
        codegen._inertia_stack_base_bp_bias_inferred_count_8616 = int(
            getattr(codegen, "_inertia_stack_base_bp_bias_inferred_count_8616", 0) or 0
        ) + 1
    return inferred


def _stack_base_bp_bias_8616(node, codegen=None) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base":
        active_bias = getattr(codegen, "_inertia_active_stack_base_bp_bias_8616", None) if codegen is not None else None
        if isinstance(active_bias, int):
            return active_bias
        inferred = _infer_stack_base_bp_bias_8616(codegen) if codegen is not None else None
        if isinstance(inferred, int):
            return inferred
        # angr's stack_base is the entry-SP placeholder. In BP-framed 16-bit
        # functions, `push bp; mov bp, sp` makes BP two bytes below entry SP.
        return 2 if _has_bp_stack_alias_evidence_8616(codegen) else None
    return None


def _is_stack_base_placeholder_8616(node) -> bool:
    node = _strip_casts_8616(node)
    return isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base"


def _segment_base_name_8616(node, project, codegen=None) -> str | None:
    """Return the segment register name for ``seg << 4`` or ``seg * 16``.

    If the segment term is a temporary name (for example ``vvar_*``), resolve
    its defining expression and retry. This keeps SS/DS/ES lowering sound while
    still avoiding speculative text-driven matching.
    """

    return _segment_base_name_8616_impl(node, project, codegen, set())


def _segment_base_name_8616_impl(
    node,
    project,
    codegen,
    seen: set[int],
) -> str | None:
    node = _strip_casts_8616(node)
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)

    if not isinstance(node, structured_c.CBinaryOp):
        dirty = getattr(node, "dirty", None)
        if dirty is not None:
            reg = _dirty_reg_offset_8616(dirty)
            if isinstance(reg, int):
                reg_name = getattr(project.arch, "register_names", {}).get(reg)
                if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
                    return reg_name
            dirty_name = getattr(dirty, "name", None)
            varid = getattr(dirty, "varid", None)
            if isinstance(varid, int):
                dirty_name = f"vvar_{varid}"
            if isinstance(dirty_name, str) and dirty_name.startswith(("vvar_", "tmp_", "ir_")) and codegen is not None:
                rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
                if rhs is not None:
                    return _segment_base_name_8616_impl(rhs, project, codegen, seen)
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                reg_name = getattr(project.arch, "register_names", {}).get(variable.reg)
                if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
                    return reg_name
                return None

            variable_name = getattr(node, "name", None) or getattr(variable, "name", None)
            if isinstance(variable_name, str) and variable_name.startswith(("vvar_", "tmp_", "ir_")) and codegen is not None:
                rhs = _single_assignment_rhs_8616(codegen, node)
                if rhs is not None:
                    return _segment_base_name_8616_impl(rhs, project, codegen, seen)
        return None

    expected_scale = 4 if node.op == "Shl" else 16 if node.op == "Mul" else None
    if expected_scale is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[ss-linear-lowering] segment-base non-scale op=%r expr=%s",
                getattr(node, "op", None),
                _debug_c_repr_8616(node),
            )
        return None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        scale_value = _constant_value_8616(maybe_scale)
        if scale_value != expected_scale:
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[ss-linear-lowering] segment-base scale mismatch op=%r expected=%r got=%r seg=%s scale=%s expr=%s",
                    node.op,
                    expected_scale,
                    scale_value,
                    _debug_c_repr_8616(maybe_seg),
                    _debug_c_repr_8616(maybe_scale),
                    _debug_c_repr_8616(node),
                )
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        segment_name = _segment_base_name_8616_impl(maybe_seg, project, codegen, seen)
        if segment_name is not None:
            return segment_name
    return None


def _flatten_signed_terms_8616(
    node,
    sign: int = 1,
) -> tuple[tuple[int, object], ...] | None:
    def _impl():
        terms: list[tuple[int, object]] = []
        # We use an explicit stack to avoid recursion depth crashes on very deep trees.
        # active path markers prevent infinite loops from cyclic expressions.
        pending: list[tuple[object, int, bool]] = [(node, sign, False)]
        active: set[int] = set()

        while pending:
            current, current_sign, exiting = pending.pop()
            current = _strip_casts_8616(current)
            if current is None:
                return None
            if exiting:
                if isinstance(current, int):
                    active.discard(current)
                continue

            node_id = id(current)
            if node_id in active:
                return None
            if len(active) > 1024:
                return None

            if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
                active.add(node_id)
                pending.append((node_id, 0, True))
                pending.append((current.rhs, current_sign, False))
                pending.append((current.lhs, current_sign, False))
                continue
            if isinstance(current, structured_c.CBinaryOp) and current.op == "Sub":
                active.add(node_id)
                pending.append((node_id, 0, True))
                pending.append((current.rhs, -current_sign, False))
                pending.append((current.lhs, current_sign, False))
                continue

            terms.append((current_sign, current))
            if len(terms) > 4096:
                return None

        return tuple(terms)

    return _impl()


def _decompose_linear_global_terms_8616(
    node,
    project,
    codegen=None,
) -> tuple[str | None, int, tuple[tuple[int, object], ...]] | None:
    segment_name: str | None = None
    displacement = 0
    residual_terms: list[tuple[int, object]] = []

    terms = _flatten_signed_terms_8616(node)
    if terms is None:
        return None
    allow_sp_anchor = any(_term_contains_memory_address_label_8616(term) for _sign, term in terms)
    for sign, term in terms:
        seg = _segment_base_name_8616(term, project, codegen=codegen)
        if seg is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = seg
            continue
        label_value = _address_label_value_8616(term, allow_sp_anchor=allow_sp_anchor)
        if label_value is not None:
            displacement += sign * label_value
            if codegen is not None:
                codegen._inertia_real_mode_global_address_label_constants = int(
                    getattr(codegen, "_inertia_real_mode_global_address_label_constants", 0) or 0
                ) + 1
            continue
        term, folded_count = _normalize_address_label_terms_8616(
            term,
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        if folded_count and codegen is not None:
            codegen._inertia_real_mode_global_address_label_constants = int(
                getattr(codegen, "_inertia_real_mode_global_address_label_constants", 0) or 0
            ) + folded_count
        const = _constant_value_8616(term)
        if const is not None:
            displacement += sign * const
            continue
        if not _address_projection_term_is_safe_8616(term):
            return None
        residual_terms.append((sign, term))

    return segment_name, displacement, tuple(residual_terms)


def _global_displacement_known_8616(codegen, displacement: int) -> bool:
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    addr = displacement & 0xFFFF
    global_name = f"g_{addr:04X}"
    for variable in variables_in_use:
        variable_addr = _sim_variable_global_address_8616(variable)
        if variable_addr == addr:
            return True
        if isinstance(variable, SimVariable) and getattr(variable, "name", None) == global_name:
            return True
    return False


def _global_size_from_displacement_8616(codegen, displacement: int) -> int | None:
    def _impl():
        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if not isinstance(variables_in_use, dict):
            return None
        addr = displacement & 0xFFFF
        global_name = f"g_{addr:04X}"
        for variable in variables_in_use:
            if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
                size = getattr(variable, "size", None)
                if isinstance(size, int) and size > 0:
                    return size
            if isinstance(variable, SimVariable) and getattr(variable, "name", None) == global_name:
                cvar = variables_in_use[variable]
                declared = getattr(cvar, "variable", None)
                if isinstance(declared, SimMemoryVariable):
                    size = getattr(declared, "size", None)
                    if isinstance(size, int) and size > 0:
                        return size
                size = getattr(declared, "size", None) if declared is not None else None
                if isinstance(size, int) and size > 0:
                    return size
        return None

    return _impl()


def _cvar_has_array_type_8616(cvar) -> bool:
    type_name = type(getattr(cvar, "variable_type", None)).__name__
    return "Array" in type_name


def _iter_statement_nodes_8616(root):
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current is None or not type(current).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "condition", "init", "iteration"):
            value = getattr(current, attr, None)
            if value is None:
                continue
            if isinstance(value, list | tuple):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)


def _iter_structured_c_nodes_8616(root):
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current is None or not type(current).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in (
            "statements",
            "condition_and_nodes",
            "else_node",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "init",
            "condition",
            "iteration",
            "body",
            "args",
            "operands",
        ):
            if not hasattr(current, attr):
                continue
            value = getattr(current, attr, None)
            if value is None:
                continue
            if isinstance(value, list | tuple):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)


def _same_variable_storage_8616(lhs, rhs) -> bool:
    def _impl():
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = getattr(lhs, "variable", None)
        rhs_var = getattr(rhs, "variable", None)
        if lhs_var is rhs_var:
            return True
        lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
        rhs_name = getattr(rhs, "name", None) or getattr(rhs_var, "name", None)
        if isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name:
            return True
        return (
            isinstance(lhs_var, SimRegisterVariable)
            and isinstance(rhs_var, SimRegisterVariable)
            and getattr(lhs_var, "reg", None) == getattr(rhs_var, "reg", None)
            and getattr(lhs_var, "size", None) == getattr(rhs_var, "size", None)
        )

    return _impl()


# ── Precomputed maps (built once per lowering pass) ──


def _build_assignment_maps_8616(codegen):
    def _impl():
        """Precompute assignment maps used by lowering and validation fingerprinting."""
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return ({}, {}, {}, set(), set(), set(), {}, {})

        var_id_map: dict[int, object] = {}
        name_map: dict[str, object] = {}
        reg_map: dict[tuple, object] = {}
        multi_var: set[int] = set()
        multi_name: set[str] = set()
        multi_reg: set[tuple] = set()
        first_name_map: dict[str, object] = {}
        first_reg_map: dict[tuple, object] = {}

        for stmt in _iter_statement_nodes_8616(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            rhs = getattr(stmt, "rhs", None)

            if not isinstance(lhs, structured_c.CVariable):
                # CDirtyExpression lhs — record via dirty.name / dirty.varid
                dirty_lhs = getattr(lhs, "dirty", None) if lhs is not None else None
                if dirty_lhs is not None and os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                    log.warning(
                        "[ss-linear-lowering] assignment-map dirty lhs text=%s varid=%r tmp_idx=%r reg_offset=%r variable_offset=%r category=%r was_reg=%r was_tmp=%r rhs=%s",
                        _debug_c_repr_8616(lhs),
                        getattr(dirty_lhs, "varid", None),
                        getattr(dirty_lhs, "tmp_idx", None),
                        getattr(dirty_lhs, "reg_offset", None),
                        getattr(dirty_lhs, "variable_offset", None),
                        getattr(dirty_lhs, "category", None),
                        getattr(dirty_lhs, "was_reg", None),
                        getattr(dirty_lhs, "was_tmp", None),
                        _debug_c_repr_8616(rhs),
                    )
                dirty_name = getattr(dirty_lhs, "name", None)
                dirty_varid = getattr(dirty_lhs, "varid", None)
                if isinstance(dirty_name, str):
                    if dirty_name not in first_name_map:
                        first_name_map[dirty_name] = rhs
                    if dirty_name in name_map:
                        multi_name.add(dirty_name)
                        name_map[dirty_name] = None
                    elif dirty_name not in multi_name:
                        name_map[dirty_name] = rhs
                if isinstance(dirty_varid, int):
                    vvar_name = f"vvar_{dirty_varid}"
                    if vvar_name not in first_name_map:
                        first_name_map[vvar_name] = rhs
                    if vvar_name in name_map:
                        multi_name.add(vvar_name)
                        name_map[vvar_name] = None
                    elif vvar_name not in multi_name:
                        name_map[vvar_name] = rhs
                continue

            var = getattr(lhs, "variable", None)

            var_id = id(var) if var is not None else None
            if var_id is not None:
                if var_id in var_id_map:
                    multi_var.add(var_id)
                    var_id_map[var_id] = None
                elif var_id not in multi_var:
                    var_id_map[var_id] = rhs

            name = getattr(lhs, "name", None) or getattr(var, "name", None)
            if isinstance(name, str) and name:
                if name not in first_name_map:
                    first_name_map[name] = rhs
                if name in name_map:
                    multi_name.add(name)
                    name_map[name] = None
                elif name not in multi_name:
                    name_map[name] = rhs

            if isinstance(var, SimRegisterVariable):
                reg = getattr(var, "reg", None)
                size = getattr(var, "size", None)
                if isinstance(reg, int) and isinstance(size, int):
                    reg_key = (reg, size)
                    if reg_key not in first_reg_map:
                        first_reg_map[reg_key] = rhs
                    if reg_key in reg_map:
                        multi_reg.add(reg_key)
                        reg_map[reg_key] = None
                    elif reg_key not in multi_reg:
                        reg_map[reg_key] = rhs

        return (var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, first_name_map, first_reg_map)

    return _impl()


def _ensure_assignment_maps_8616(codegen) -> tuple:
    """Return cached maps or build and cache them on codegen."""
    cached = getattr(codegen, "_inertia_assignment_maps", None)
    if cached is not None:
        return cached
    maps = _build_assignment_maps_8616(codegen)
    setattr(codegen, "_inertia_assignment_maps", maps)
    return maps


def _single_virtual_carrier_offset_observation_8616(expr) -> tuple[int, int] | None:
    terms = _flatten_signed_terms_8616(expr)
    if terms is None:
        return None
    base_ids: list[tuple[int, int]] = []
    const_total = 0
    for sign, term in terms:
        base_id = _extract_vvar_id_8616(term)
        if isinstance(base_id, int):
            base_ids.append((sign, base_id))
            continue
        const = _constant_value_8616(term)
        if const is not None:
            const_total += sign * const
            continue
        return None
    if len(base_ids) != 1:
        return None
    sign, base_id = base_ids[0]
    if sign != 1:
        return None
    return base_id, const_total


def _ss_virtual_carrier_offset_observations_8616(root, project, codegen) -> dict[int, set[int]]:
    observations: dict[int, set[int]] = {}
    for node in _iter_structured_c_nodes_8616(root):
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue
        terms = _flatten_signed_terms_8616(getattr(node, "operand", None))
        if terms is None:
            continue

        segment_name: str | None = None
        const_total = 0
        offset_terms: list[object] = []
        malformed = False
        for sign, term in terms:
            seg = _segment_base_name_8616(term, project, codegen=codegen)
            if seg is not None:
                if sign != 1 or segment_name is not None:
                    malformed = True
                    break
                segment_name = seg
                continue
            const = _constant_value_8616(term)
            if const is not None:
                const_total += sign * const
                continue
            offset_terms.append(
                term
                if sign == 1
                else structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeInt(signed=False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            )
        if malformed or segment_name != "ss" or len(offset_terms) != 1:
            continue

        observation = _single_virtual_carrier_offset_observation_8616(offset_terms[0])
        if observation is None:
            continue
        base_id, carrier_const = observation
        observations.setdefault(base_id, set()).add(const_total + carrier_const)
    return observations


def _infer_vvar_carrier_deltas_from_ss_alias_observations_8616(root, project, codegen) -> dict[int, int]:
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    if not known_offsets:
        return {}
    strong_arg_offsets = _bp_stack_arg_offsets_8616(codegen)
    abi_arg_region_offsets = _bp_stack_abi_argument_region_offsets_8616(known_offsets)
    observations = _ss_virtual_carrier_offset_observations_8616(root, project, codegen)
    inferred: dict[int, int] = {}

    def infer_delta(constants: set[int], offsets: set[int]) -> int | None:
        if len(constants) < 2 or len(offsets) < 2:
            return None
        best_delta: int | None = None
        best_score = 0
        tied = False
        for const in constants:
            for offset in offsets:
                delta = offset - const
                score = len({candidate for candidate in constants if candidate + delta in offsets})
                if score > best_score:
                    best_delta = delta
                    best_score = score
                    tied = False
                elif score == best_score and score > 0 and delta != best_delta:
                    tied = True
        if isinstance(best_delta, int) and best_score == len(constants) and best_score >= 2 and not tied:
            return best_delta
        return None

    for varid, constants in observations.items():
        strong_delta = infer_delta(constants, strong_arg_offsets)
        if isinstance(strong_delta, int):
            inferred[varid] = strong_delta
            codegen._inertia_stack_carrier_delta_inferred_from_arg_offsets_count_8616 = int(
                getattr(codegen, "_inertia_stack_carrier_delta_inferred_from_arg_offsets_count_8616", 0) or 0
            ) + 1
            continue
        abi_arg_region_delta = infer_delta(constants, abi_arg_region_offsets)
        if isinstance(abi_arg_region_delta, int):
            inferred[varid] = abi_arg_region_delta
            codegen._inertia_stack_carrier_delta_inferred_from_abi_arg_region_count_8616 = int(
                getattr(codegen, "_inertia_stack_carrier_delta_inferred_from_abi_arg_region_count_8616", 0) or 0
            ) + 1
            continue
        delta = infer_delta(constants, known_offsets)
        if isinstance(delta, int):
            inferred[varid] = delta
    if inferred:
        codegen._inertia_stack_carrier_delta_inferred_from_alias_count_8616 = int(
            getattr(codegen, "_inertia_stack_carrier_delta_inferred_from_alias_count_8616", 0) or 0
        ) + len(inferred)
    return inferred


def _build_vvar_carrier_delta_map_8616(codegen) -> dict[int, int]:
    def _impl():
        """Precompute vvar_id → carrier_delta in a single pass, caching on codegen."""
        project = getattr(codegen, "project", None)
        sp_reg, _sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
        facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
        has_ss_facts = any(getattr(fact, "segment_space", None) == "ss" for fact in facts.values())
        deltas: dict[int, int] = {}
        delta_sources: dict[int, StackCarrierDeltaSource8616] = {}
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return deltas

        def _delta_source_priority(source: StackCarrierDeltaSource8616) -> int:
            return _STACK_CARRIER_DELTA_SOURCE_PRIORITY_8616[source]

        def _record_delta(lhs_id: int, delta: int, source: StackCarrierDeltaSource8616) -> bool:
            old_delta = deltas.get(lhs_id)
            old_source = delta_sources.get(lhs_id)
            if old_source is None:
                deltas[lhs_id] = delta
                delta_sources[lhs_id] = source
                return True
            if old_delta == delta:
                if _delta_source_priority(source) > _delta_source_priority(old_source):
                    delta_sources[lhs_id] = source
                return False
            if _delta_source_priority(source) <= _delta_source_priority(old_source):
                return False
            deltas[lhs_id] = delta
            delta_sources[lhs_id] = source
            codegen._inertia_stack_carrier_delta_alias_override_count_8616 = int(
                getattr(codegen, "_inertia_stack_carrier_delta_alias_override_count_8616", 0) or 0
            ) + 1
            return True

        def _seed_from_init(expr, lhs_id):
            if expr is None:
                return None
            rhs_stripped = _strip_casts_8616(expr)
            ref_node: object = None
            const_delta: int = 0
            if isinstance(rhs_stripped, structured_c.CUnaryOp) and rhs_stripped.op == "Reference":
                ref_node = rhs_stripped.operand
            elif isinstance(rhs_stripped, structured_c.CBinaryOp) and rhs_stripped.op in {"Add", "Sub"}:
                if isinstance(_strip_casts_8616(rhs_stripped.lhs), structured_c.CUnaryOp):
                    lhs_u = _strip_casts_8616(rhs_stripped.lhs)
                    if lhs_u.op == "Reference":
                        ref_node = lhs_u.operand
                        rhs_const = _constant_value_8616(rhs_stripped.rhs)
                        if rhs_const is not None:
                            const_delta = rhs_const if rhs_stripped.op == "Add" else -rhs_const
                if ref_node is None and isinstance(_strip_casts_8616(rhs_stripped.rhs), structured_c.CUnaryOp):
                    rhs_u = _strip_casts_8616(rhs_stripped.rhs)
                    if rhs_u.op == "Reference" and rhs_stripped.op == "Add":
                        ref_node = rhs_u.operand
                        lhs_const = _constant_value_8616(rhs_stripped.lhs)
                        if lhs_const is not None:
                            const_delta = lhs_const
            if ref_node is not None:
                operand = _strip_casts_8616(ref_node)
                if isinstance(operand, structured_c.CVariable):
                    var = getattr(operand, "variable", None)
                    if isinstance(var, SimStackVariable):
                        offset = getattr(var, "offset", None)
                        if isinstance(offset, int):
                            _record_delta(
                                lhs_id,
                                offset + const_delta,
                                StackCarrierDeltaSource8616.STACK_REFERENCE_SEED,
                            )
                            return True
            if isinstance(rhs_stripped, structured_c.CVariable):
                var = getattr(rhs_stripped, "variable", None)
                if isinstance(var, SimRegisterVariable) and getattr(var, "reg", None) == sp_reg and has_ss_facts:
                    _record_delta(lhs_id, 0, StackCarrierDeltaSource8616.SP_REGISTER_SEED)
                    return True
            return None

        for stmt in _iter_statement_nodes_8616(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs_id = _extract_vvar_id_8616(getattr(stmt, "lhs", None))
            if not isinstance(lhs_id, int):
                continue
            _seed_from_init(getattr(stmt, "rhs", None), lhs_id)

        if project is not None:
            for lhs_id, delta in _infer_vvar_carrier_deltas_from_ss_alias_observations_8616(root, project, codegen).items():
                _record_delta(lhs_id, delta, StackCarrierDeltaSource8616.ALIAS_OBSERVATION)

        changed = True
        while changed:
            changed = False
            for stmt in _iter_statement_nodes_8616(root):
                if not isinstance(stmt, structured_c.CAssignment):
                    continue
                lhs_id = _extract_vvar_id_8616(getattr(stmt, "lhs", None))
                if not isinstance(lhs_id, int) or lhs_id in deltas:
                    continue
                base_ids: list[tuple[int, int]] = []
                const_total = 0
                unknown = False
                terms = _flatten_signed_terms_8616(getattr(stmt, "rhs", None))
                if terms is None:
                    continue
                for sign, term in terms:
                    base_id = _extract_vvar_id_8616(term)
                    if isinstance(base_id, int):
                        base_ids.append((sign, base_id))
                        continue
                    const = _constant_value_8616(term)
                    if const is not None:
                        const_total += sign * const
                        continue
                    unknown = True
                if unknown or len(base_ids) != 1:
                    continue
                sign, base_id = base_ids[0]
                if sign != 1 or base_id not in deltas:
                    continue
                if _record_delta(lhs_id, deltas[base_id] + const_total, delta_sources[base_id]):
                    changed = True
        codegen._inertia_stack_carrier_delta_sources_8616 = dict(delta_sources)
        return deltas

    return _impl()


def _ensure_vvar_carrier_delta_map_8616(codegen) -> dict[int, int]:
    """Return cached vvar_deltas or build and cache them on codegen."""
    cached = getattr(codegen, "_inertia_vvar_carrier_deltas", None)
    if cached is not None:
        return cached
    deltas = _build_vvar_carrier_delta_map_8616(codegen)
    setattr(codegen, "_inertia_vvar_carrier_deltas", deltas)
    return deltas


# ── O(1) lookup wrappers ──


def _single_assignment_rhs_8616(codegen, target):
    def _impl():
        if not isinstance(target, structured_c.CVariable):
            return None
        var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, _first_name_map, _first_reg_map = (
            _ensure_assignment_maps_8616(codegen)
        )
        var = getattr(target, "variable", None)
        var_id = id(var) if var is not None else None
        if var_id is not None and var_id in var_id_map and var_id not in multi_var:
            return var_id_map[var_id]
        name = getattr(target, "name", None) or getattr(var, "name", None)
        if isinstance(name, str) and name in name_map and name not in multi_name:
            return name_map[name]
        if isinstance(var, SimRegisterVariable):
            reg = getattr(var, "reg", None)
            size = getattr(var, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                reg_key = (reg, size)
                if reg_key in reg_map and reg_key not in multi_reg:
                    return reg_map[reg_key]
        return None

    return _impl()


def _stack_pointer_carrier_offset_8616(
    node,
    project,
    codegen,
    seen: set[int] | None = None,
) -> int | None:
    def _impl():
        nonlocal seen
        """Recover a stack-pointer carrier from existing stack-probe facts."""

        if seen is None:
            seen = set()

        variable = getattr(node, "variable", None) if isinstance(node, structured_c.CVariable) else None
        dirty = getattr(node, "dirty", None)
        if isinstance(variable, SimRegisterVariable):
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
        else:
            reg = _dirty_reg_offset_8616(dirty)
            bits = getattr(dirty, "bits", None)
            size = (bits // 8) if isinstance(bits, int) else None
            varid = getattr(dirty, "varid", None)
            if not isinstance(reg, int) and isinstance(varid, int):
                target_name = f"vvar_{varid}"
                resolved = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name)
                if resolved is not None:
                    return _stack_offset_from_expr_8616(resolved, project, codegen, seen)
                delta = _stack_probe_carrier_delta_8616(node, codegen)
                if delta is not None:
                    return delta
        bp_reg, bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
        if isinstance(bp_reg, int) and reg == bp_reg and (size is None or size == bp_size):
            return 0

        sp_reg, sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
        if not (isinstance(sp_reg, int) and reg == sp_reg and (size is None or size == sp_size)):
            return None
        if getattr(codegen, "_inertia_allow_direct_sp_for_callee_save_spill", False):
            return 0
        facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
        if not facts:
            return None
        for fact in facts.values():
            if getattr(fact, "segment_space", None) != "ss":
                continue
            width = getattr(fact, "width", None)
            if isinstance(width, int) and width > 0:
                return 0
        return None

    return _impl()


def _lhs_name_8616(lhs) -> str | None:
    """Extract variable name from CVariable or CDirtyExpression LHS."""
    if isinstance(lhs, structured_c.CVariable):
        return getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
    dirty = getattr(lhs, "dirty", None)
    if dirty is not None:
        name = getattr(dirty, "name", None)
        if isinstance(name, str):
            return name
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
    return None


def _single_assignment_rhs_for_virtual_name_8616(codegen, target_name: str, *, allow_multi: bool = False):
    (
        _unused_var_id_map,
        name_map,
        _unused_reg_map,
        _unused_multi_var,
        multi_name,
        _unused_multi_reg,
        first_name_map,
        _first_reg_map,
    ) = _ensure_assignment_maps_8616(codegen)
    if allow_multi:
        # O(1) lookup from precomputed first-assignment map
        return first_name_map.get(target_name)
    if target_name in name_map and target_name not in multi_name:
        return name_map[target_name]
    return None


def _extract_vvar_id_8616(node) -> int | None:
    dirty = getattr(node, "dirty", None)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        return varid
    if isinstance(node, structured_c.CVariable):
        for candidate in (getattr(node, "name", None), getattr(getattr(node, "variable", None), "name", None)):
            if not (isinstance(candidate, str) and candidate.startswith("vvar_")):
                continue
            try:
                return int(candidate.removeprefix("vvar_"), 10)
            except ValueError:
                return None
    return None


def _stack_probe_carrier_delta_8616(node, codegen) -> int | None:
    carrier = _stack_probe_carrier_delta_with_source_8616(node, codegen)
    return carrier[0] if carrier is not None else None


def _stack_probe_carrier_delta_with_source_8616(
    node, codegen
) -> tuple[int, StackCarrierDeltaSource8616 | None] | None:
    varid = _extract_vvar_id_8616(node)
    if not isinstance(varid, int):
        return None
    deltas = _ensure_vvar_carrier_delta_map_8616(codegen)
    delta = deltas.get(varid)
    if not isinstance(delta, int):
        return None
    sources = getattr(codegen, "_inertia_stack_carrier_delta_sources_8616", None)
    source = sources.get(varid) if isinstance(sources, dict) else None
    source = source if isinstance(source, StackCarrierDeltaSource8616) else None
    return delta, source


def _vvar_carrier_delta_from_name_8616(
    node_name: str,
    codegen,
) -> tuple[int, StackCarrierDeltaSource8616 | None] | None:
    if not node_name.startswith("vvar_"):
        return None
    suffix = node_name.removeprefix("vvar_")
    if not suffix.isdigit():
        return None
    varid = int(suffix)
    deltas = _ensure_vvar_carrier_delta_map_8616(codegen)
    delta = deltas.get(varid)
    if not isinstance(delta, int):
        return None
    sources = getattr(codegen, "_inertia_stack_carrier_delta_sources_8616", None)
    source = sources.get(varid) if isinstance(sources, dict) else None
    source = source if isinstance(source, StackCarrierDeltaSource8616) else None
    return delta, source


def _resolve_virtual_name_offset_8616(node_name: str, project, codegen, seen: set[int]) -> int | None:
    if not (
        node_name.startswith("vvar_")
        or node_name.startswith("tmp_")
        or node_name.startswith("ir_")
    ):
        return None
    carrier_delta = _vvar_carrier_delta_from_name_8616(node_name, codegen)
    if carrier_delta is not None and carrier_delta[1] is StackCarrierDeltaSource8616.ALIAS_OBSERVATION:
        return carrier_delta[0]
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, node_name)
    if rhs is None:
        return None
    resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
    if resolved is not None:
        return resolved
    return carrier_delta[0] if carrier_delta is not None else None


def _resolve_stack_offset_from_variable_8616(node, project, codegen, seen: set[int]) -> int | None:
    variable = getattr(node, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
        if carrier_offset is not None:
            return carrier_offset
    rhs = _single_assignment_rhs_8616(codegen, node)
    if rhs is not None:
        return _stack_offset_from_expr_8616(rhs, project, codegen, seen)
    node_name = getattr(node, "name", None) or getattr(variable, "name", None)
    if isinstance(node_name, str):
        resolved = _resolve_virtual_name_offset_8616(node_name, project, codegen, seen)
        if resolved is not None:
            return resolved
        if node_name.startswith("vvar_"):
            return _stack_probe_carrier_delta_8616(node, codegen)
    return None


def _dirty_varid_offset_8616(varid: int, node, project, codegen, seen: set[int], diag: dict[str, object]) -> int | None:
    diag["varid"] = varid
    carrier = _stack_probe_carrier_delta_with_source_8616(node, codegen)
    if carrier is not None and carrier[1] is StackCarrierDeltaSource8616.ALIAS_OBSERVATION:
        return carrier[0]
    target_name = f"vvar_{varid}"
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name, allow_multi=True)
    if rhs is not None:
        resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
        if resolved is not None:
            return resolved
        diag["rhs_found_but_unresolvable"] = True
    else:
        diag["rhs_not_found"] = True
    if carrier is not None:
        return carrier[0]
    diag["carrier_delta_none"] = True
    return None


def _dirty_name_offset_8616(dirty_name: str, project, codegen, seen: set[int], diag: dict[str, object]) -> int | None:
    diag["dirty_name"] = dirty_name
    resolved = _resolve_virtual_name_offset_8616(dirty_name, project, codegen, seen)
    if resolved is not None:
        return resolved
    if dirty_name.startswith("vvar_") or dirty_name.startswith("tmp_") or dirty_name.startswith("ir_"):
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
        if rhs is None:
            diag["rhs_not_found"] = True
        else:
            diag["rhs_found_but_unresolvable"] = True
    return None


def _resolve_stack_offset_from_dirty_8616(node, project, codegen, seen: set[int]) -> int | None:
    dirty = getattr(node, "dirty", None)
    if dirty is None:
        return None
    varid = getattr(dirty, "varid", None)
    dirty_name = getattr(dirty, "name", None)
    diag: dict[str, object] = {}
    if isinstance(varid, int):
        resolved = _dirty_varid_offset_8616(varid, node, project, codegen, seen, diag)
        if resolved is not None:
            return resolved
    elif isinstance(dirty_name, str):
        resolved = _dirty_name_offset_8616(dirty_name, project, codegen, seen, diag)
        if resolved is not None:
            return resolved
    else:
        diag["no_varid_or_name"] = True
    carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
    if carrier_offset is not None:
        return carrier_offset
    dirty_reg = _dirty_reg_offset_8616(dirty)
    bp_reg, _bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
    if isinstance(dirty_reg, int) and isinstance(bp_reg, int) and dirty_reg == bp_reg:
        return 0
    diag["carrier_none"] = True
    _log_refusal_8616(codegen, "cdirty_diag", **diag)
    return None


def _resolve_binary_stack_base_shortcuts_8616(node, codegen) -> int | None:
    if _is_stack_base_placeholder_8616(node.lhs):
        rhs_const = _constant_value_8616(node.rhs)
        if rhs_const is not None:
            base = _stack_base_bp_bias_8616(node.lhs, codegen)
            if base is not None:
                return base + (int(rhs_const) if node.op == "Add" else -int(rhs_const))
    if node.op == "Add" and _is_stack_base_placeholder_8616(node.rhs):
        lhs_const = _constant_value_8616(node.lhs)
        if lhs_const is not None:
            base = _stack_base_bp_bias_8616(node.rhs, codegen)
            if base is not None:
                return base + int(lhs_const)
    return None


def _is_unresolved_segment_scale_candidate_8616(node) -> bool:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return False
    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        expected_scale = 16
    elif node.op == "Shl":
        pairs = ((node.lhs, node.rhs),)
        expected_scale = 4
    else:
        return False
    for maybe_segment, maybe_scale in pairs:
        if _constant_value_8616(maybe_scale) == expected_scale and _constant_value_8616(maybe_segment) is None:
            return True
    return False


def _is_stack_offset_term_direct_8616(node) -> bool:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
        variable = getattr(getattr(node, "operand", None), "variable", None)
        return isinstance(variable, SimStackVariable)

    variable = getattr(node, "variable", None)
    if isinstance(variable, SimStackVariable):
        return True

    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = node.lhs
        rhs = node.rhs
        lhs_is_const = _constant_value_8616(lhs) is not None
        rhs_is_const = _constant_value_8616(rhs) is not None
        if lhs_is_const and _is_stack_offset_term_direct_8616(rhs):
            return True
        if rhs_is_const and _is_stack_offset_term_direct_8616(lhs):
            return True

    return _constant_value_8616(node) is not None


def _stack_offset_term_stackish_8616(node, project, codegen) -> bool:
    if _is_stack_offset_term_direct_8616(node):
        return True
    return _stack_offset_from_expr_8616(node, project, codegen) is not None


def _ss_probe_enabled_8616(codegen) -> bool:
    facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
    return any(getattr(fact, "segment_space", None) == "ss" for fact in facts.values())


def _has_stack_alias_fact_for_displacement_8616(codegen, displacement: int, width: int | None) -> bool:
    facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if not isinstance(facts, list):
        return False
    displacement = _canonical_stack_offset_8616(displacement)
    for fact in facts:
        identity = getattr(fact, "identity", None)
        if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
            continue
        slot = identity[1]
        slot_offset = _canonical_stack_offset_8616(getattr(slot, "offset", None))
        if slot_offset != displacement:
            continue
        slot_width = getattr(slot, "width", None)
        if not isinstance(width, int) or width <= 0:
            return True
        if not isinstance(slot_width, int) or slot_width >= width:
            return True
    return False


def _resolve_binary_stack_probe_fallback_8616(node, lhs, rhs, codegen) -> int | None:
    if lhs is None:
        rhs_const = _constant_value_8616(node.rhs)
        lhs_delta = _stack_probe_carrier_delta_8616(_strip_casts_8616(node.lhs), codegen)
        if isinstance(rhs_const, int) and isinstance(lhs_delta, int):
            return lhs_delta + (rhs_const if node.op == "Add" else -rhs_const)
    if rhs is None and node.op == "Add":
        lhs_const = _constant_value_8616(node.lhs)
        rhs_delta = _stack_probe_carrier_delta_8616(_strip_casts_8616(node.rhs), codegen)
        if isinstance(lhs_const, int) and isinstance(rhs_delta, int):
            return lhs_const + rhs_delta
    return None


def _resolve_stack_offset_from_binary_8616(node, project, codegen, seen: set[int]) -> int | None:
    def _impl():
        shortcut = _resolve_binary_stack_base_shortcuts_8616(node, codegen)
        if shortcut is not None:
            return shortcut
        lhs = _stack_offset_from_expr_8616(node.lhs, project, codegen, seen)
        rhs = _stack_offset_from_expr_8616(node.rhs, project, codegen, seen)
        fallback = _resolve_binary_stack_probe_fallback_8616(node, lhs, rhs, codegen)
        if fallback is not None:
            return fallback
        if lhs is None and _constant_value_8616(node.rhs) is not None:
            return None
        if rhs is None and _constant_value_8616(node.lhs) is not None and node.op == "Add":
            return None
        if lhs is None or rhs is None:
            return None
        return lhs + rhs if node.op == "Add" else lhs - rhs

    return _impl()


def _stack_offset_from_expr_8616(node, project, codegen, seen: set[int] | None = None) -> int | None:
    def _impl():
        nonlocal node, seen
        if seen is None:
            seen = set()
        node = _strip_casts_8616(node)
        node_id = id(node)
        offset_cache = getattr(codegen, "_inertia_stack_offset_cache", None)
        if not isinstance(offset_cache, dict):
            offset_cache = {}
            setattr(codegen, "_inertia_stack_offset_cache", offset_cache)

        if node_id in offset_cache:
            cached = offset_cache.get(node_id)
            if cached is _UNRESOLVED_STACK_OFFSET_8616:
                return None
            return cached

        if node_id in seen:
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        if len(seen) > 8192:
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        seen.add(node_id)

        const = _constant_value_8616(node)
        if const is not None:
            offset_cache[node_id] = const
            return const

        stack_base_bias = _stack_base_bp_bias_8616(node, codegen)
        if stack_base_bias is not None:
            offset_cache[node_id] = stack_base_bias
            return stack_base_bias

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = _strip_casts_8616(node.operand)
            variable = getattr(operand, "variable", None) if isinstance(operand, structured_c.CVariable) else None
            if isinstance(variable, SimStackVariable) and isinstance(getattr(variable, "offset", None), int):
                offset_cache[node_id] = variable.offset
                return variable.offset
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None

        if isinstance(node, structured_c.CVariable):
            resolved = _resolve_stack_offset_from_variable_8616(node, project, codegen, seen)
            offset_cache[node_id] = resolved if resolved is not None else _UNRESOLVED_STACK_OFFSET_8616
            return resolved

        dirty_resolved = _resolve_stack_offset_from_dirty_8616(node, project, codegen, seen)
        if dirty_resolved is not None:
            offset_cache[node_id] = dirty_resolved
            return dirty_resolved

        dirty_carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
        if dirty_carrier_offset is not None:
            offset_cache[node_id] = dirty_carrier_offset
            return dirty_carrier_offset

        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            resolved = _resolve_stack_offset_from_binary_8616(node, project, codegen, seen)
            offset_cache[node_id] = resolved if resolved is not None else _UNRESOLVED_STACK_OFFSET_8616
            return resolved

        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None

    return _impl()


def _log_refusal_8616(codegen, kind: str, /, **details: object) -> None:
    refusals = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
    normalized = {k: str(v) for k, v in details.items()}
    if isinstance(refusals, list):
        refusals.append({"kind": kind, **normalized})
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning("[ss-linear-lowering] refusal kind=%s details=%r", kind, normalized)


def _debug_c_repr_8616(node) -> str:
    try:
        chunks = node.c_repr_chunks(asexpr=True)
        return "".join(str(text) for text, _obj in chunks)
    except Exception:
        return repr(node)


def match_stable_ss_linear_stack_access_8616(node, project, codegen) -> RealModeLinearStackAccess8616 | None:
    def _impl():
        nonlocal node
        """Match a dereference of ``(ss << 4) + stack_offset`` with stack proof."""
        if not hasattr(codegen, "_inertia_ss_segment_inferred_from_stack_offset_count"):
            codegen._inertia_ss_segment_inferred_from_stack_offset_count = 0

        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None
        access_width = _dereference_access_width_bytes_8616(node)

        segment_name: str | None = None
        offset_total = 0
        offset_terms: list[object] = []
        unresolved_segment_terms: list[object] = []
        terms = _flatten_signed_terms_8616(node.operand)
        if terms is None:
            return None
        for sign, term in terms:
            seg = _segment_base_name_8616(term, project, codegen=codegen)
            if seg is not None:
                if sign != 1 or segment_name is not None:
                    return None
                segment_name = seg
                continue
            const = _constant_value_8616(term)
            if const is not None:
                offset_total += sign * const
                continue
            if sign == 1 and _is_unresolved_segment_scale_candidate_8616(term):
                unresolved_segment_terms.append(term)
                continue
            offset_terms.append(
                term
                if sign == 1
                else structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeInt(signed=False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            )

        inferred_ss_from_stack_fact = False
        base_offset: int | None = None
        width = access_width

        if segment_name is None and len(unresolved_segment_terms) == 1 and len(offset_terms) == 1:
            candidate_base_offset = _stack_offset_from_expr_8616(offset_terms[0], project, codegen)
            if candidate_base_offset is not None:
                candidate_displacement = candidate_base_offset + offset_total
                if _has_stack_alias_fact_for_displacement_8616(codegen, candidate_displacement, width):
                    segment_name = "ss"
                    base_offset = candidate_base_offset
                    inferred_ss_from_stack_fact = True
                    codegen._inertia_ss_segment_inferred_from_stack_offset_count = int(
                        getattr(codegen, "_inertia_ss_segment_inferred_from_stack_offset_count", 0) or 0
                    ) + 1

        if segment_name != "ss" or (unresolved_segment_terms and not inferred_ss_from_stack_fact) or len(offset_terms) > 1:
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                _log_refusal_8616(
                    codegen,
                    "segment_or_terms",
                    segment=segment_name,
                    terms=len(offset_terms),
                    unresolved_segments=len(unresolved_segment_terms),
                    operand=repr(node.operand),
                    offset_term_types=tuple(type(term).__name__ for term in offset_terms),
                    offset_terms=tuple(_debug_c_repr_8616(term) for term in offset_terms),
                )
            else:
                _log_refusal_8616(codegen, "segment_or_terms", segment=segment_name, terms=len(offset_terms))
            return None

        known_offsets = _known_bp_stack_offsets_8616(codegen)
        if base_offset is None and len(offset_terms) == 0:
            base_offset = 0
        elif base_offset is None:
            base_offset = _stack_offset_from_expr_8616(offset_terms[0], project, codegen)
        if base_offset is None and len(offset_terms) == 1 and offset_total in known_offsets:
            base_offset = 0

        if base_offset is None:
            _log_refusal_8616(
                codegen,
                "offset_unresolved",
                segment=segment_name,
                offset_expr_type=type(offset_terms[0]).__name__ if offset_terms else "None",
                const_offset=offset_total,
            )
            return None

        if segment_name == "ss" and not all(_is_stack_offset_term_direct_8616(term) for term in offset_terms):
            if _has_stack_alias_fact_for_displacement_8616(codegen, base_offset + offset_total, width):
                codegen._inertia_ss_segment_inferred_from_stack_offset_count += 1
            elif all(_stack_offset_term_stackish_8616(term, project, codegen) for term in offset_terms):
                codegen._inertia_ss_segment_inferred_from_stack_offset_count += 1
            elif base_offset + offset_total in known_offsets:
                codegen._inertia_ss_segment_inferred_from_stack_offset_count += 1
            elif _ss_probe_enabled_8616(codegen) and all(
                _stack_offset_term_stackish_8616(term, project, codegen) for term in offset_terms
            ):
                codegen._inertia_ss_segment_inferred_from_stack_offset_count += 1
            else:
                _log_refusal_8616(
                    codegen,
                    "no_stack_alias_fact_for_ss_offset",
                    segment=segment_name,
                    displacement=base_offset + offset_total,
                    width=width,
                )
                return None

        displacement = base_offset + offset_total
        region = getattr(getattr(codegen, "cfunc", None), "addr", None)
        facts = _stack_storage_facts_for_segmented_address_8616("ss", displacement, width, region=region)
        if facts is None or facts.identity is None:
            _log_refusal_8616(codegen, "no_stack_facts", displacement=displacement, width=width, region=region)
            return None
        if inferred_ss_from_stack_fact and not _has_stack_alias_fact_for_displacement_8616(codegen, displacement, width):
            _log_refusal_8616(codegen, "no_inferred_ss_stack_alias_fact", displacement=displacement, width=width)
            return None
        return RealModeLinearStackAccess8616(displacement=displacement, width=width)

    return _impl()


def match_stable_ds_es_linear_global_access_8616(node, project, codegen) -> RealModeLinearGlobalAddress8616 | None:
    def _impl():
        nonlocal node
        """Match a dereference of ``(ds << 4) + addr`` or ``(es << 4) + addr``."""

        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None

        decomposed = _decompose_linear_global_terms_8616(node.operand, project, codegen=codegen)
        if decomposed is None:
            return None
        segment_name, displacement, residual_terms = decomposed

        if segment_name in {"ds", "es"}:
            width_bits = getattr(getattr(node, "type", None), "size", None)
            width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
            if width is None:
                inferred_width = _global_size_from_displacement_8616(codegen, displacement)
                if isinstance(inferred_width, int) and inferred_width > 0:
                    width = inferred_width
            return RealModeLinearGlobalAddress8616(
                segment_name=segment_name,
                displacement=displacement,
                residual_terms=tuple(residual_terms),
                width=width,
            )

        if segment_name is not None or not _global_displacement_known_8616(codegen, displacement):
            return None

        width_bits = getattr(getattr(node, "type", None), "size", None)
        width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
        if width is None:
            inferred_width = _global_size_from_displacement_8616(codegen, displacement)
            if isinstance(inferred_width, int) and inferred_width > 0:
                width = inferred_width
        return RealModeLinearGlobalAddress8616(
            segment_name="segless",
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=width,
        )

    return _impl()


def _address_projection_term_is_safe_8616(node) -> bool:
    allowed_unary = {"Neg", "BitNot", "Reference"}
    allowed_binary = {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
    pending: list[object] = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            return False
        expr_id = id(expr)
        if expr_id in seen:
            return False
        seen.add(expr_id)
        if _constant_value_8616(expr) is not None:
            continue
        if isinstance(expr, structured_c.CVariable):
            continue
        if isinstance(expr, structured_c.CUnaryOp) and expr.op in allowed_unary:
            pending.append(expr.operand)
            continue
        if isinstance(expr, structured_c.CBinaryOp) and expr.op in allowed_binary:
            pending.append(expr.rhs)
            pending.append(expr.lhs)
            continue
        return False
    return True


def _contains_materialized_global_reference_8616(node) -> bool:
    pending: list[object] = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            continue
        expr_id = id(expr)
        if expr_id in seen:
            continue
        seen.add(expr_id)
        if isinstance(expr, structured_c.CUnaryOp) and expr.op == "Reference":
            variable = getattr(getattr(expr, "operand", None), "variable", None)
            if isinstance(variable, SimMemoryVariable):
                return True
            pending.append(getattr(expr, "operand", None))
            continue
        for attr in ("lhs", "rhs", "operand", "expr", "index"):
            child = getattr(expr, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = getattr(expr, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in children if child is not None)
    return False


def _return_register_virtual_name_8616(node, project) -> str | None:
    ax_reg, _ax_size = getattr(getattr(project, "arch", None), "registers", {}).get("ax", (None, None))
    pending = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        dirty = getattr(current, "dirty", None)
        if dirty is not None:
            reg = _dirty_reg_offset_8616(dirty)
            varid = getattr(dirty, "varid", None)
            if isinstance(ax_reg, int) and reg == ax_reg and isinstance(varid, int):
                return f"vvar_{varid}"
        if isinstance(current, structured_c.CVariable):
            variable = getattr(current, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                reg = getattr(variable, "reg", None)
                name = getattr(current, "name", None) or getattr(variable, "name", None)
                if isinstance(ax_reg, int) and reg == ax_reg and isinstance(name, str) and name.startswith("vvar_"):
                    return name
        for attr in ("lhs", "rhs", "operand", "expr", "cond", "iftrue", "iffalse"):
            child = getattr(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("operands", "args"):
            seq = getattr(current, attr, None)
            if seq:
                pending.extend(item for item in seq if item is not None)
    return None


def _return_rhs_is_safe_8616(expr) -> bool:
    expr = _strip_casts_8616(expr)
    if isinstance(expr, (structured_c.CConstant, structured_c.CVariable, structured_c.CDirtyExpression)):
        return True
    if isinstance(expr, structured_c.CTypeCast):
        return _return_rhs_is_safe_8616(expr.expr)
    if isinstance(expr, structured_c.CUnaryOp):
        return expr.op != "Dereference" and _return_rhs_is_safe_8616(expr.operand)
    if isinstance(expr, structured_c.CBinaryOp):
        return _return_rhs_is_safe_8616(expr.lhs) and _return_rhs_is_safe_8616(expr.rhs)
    return False


def _materialize_return_register_assignments_8616(codegen, project) -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False
    changed = False
    stack = [root]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if node is None:
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        if isinstance(node, structured_c.CReturn):
            retval = getattr(node, "retval", None)
            virtual_name = _return_register_virtual_name_8616(retval, project)
            if virtual_name is not None:
                rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, virtual_name)
                if rhs is not None and _return_rhs_is_safe_8616(rhs):
                    node.retval = rhs
                    changed = True
                    codegen._inertia_return_register_materialized_count = int(
                        getattr(codegen, "_inertia_return_register_materialized_count", 0) or 0
                    ) + 1
                    continue
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "condition", "init", "iteration"):
            value = getattr(node, attr, None)
            if value is None:
                continue
            if isinstance(value, list | tuple):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)
    return changed


def _op_reg_id_8616(insn, index: int) -> int | None:
    operands = getattr(insn, "operands", None)
    if operands is None or len(operands) <= index:
        return None
    operand = operands[index]
    if getattr(operand, "type", None) != 1:
        return None
    reg = getattr(operand, "reg", None)
    return int(reg) if isinstance(reg, int) else None


def _is_mov_sp_bp_8616(insn) -> bool:
    if getattr(insn, "id", None) != X86_INS_MOV:
        return False
    return _op_reg_id_8616(insn, 0) == X86_REG_SP and _op_reg_id_8616(insn, 1) == X86_REG_BP


def _decode_function_insns_at_8616(project, function_addr: int, *, limit: int = 0x100) -> tuple:
    try:
        code = bytes(project.loader.memory.load(function_addr, limit))
        capstone = project.arch.capstone
        previous_detail = getattr(capstone, "detail", False)
        try:
            capstone.detail = True
            insns = []
            for insn in capstone.disasm(code, function_addr):
                insns.append(insn)
                if getattr(insn, "id", None) == X86_INS_RET:
                    break
            return tuple(insns) if any(getattr(insn, "id", None) == X86_INS_RET for insn in insns) else ()
        finally:
            capstone.detail = previous_detail
    except Exception:
        return ()


def _decode_function_insns_8616(project, function_addr: int, *, limit: int = 0x100) -> tuple:
    insns = _decode_function_insns_at_8616(project, function_addr, limit=limit)
    if insns:
        return insns
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        return _decode_function_insns_at_8616(project, function_addr + delta, limit=limit)
    return ()


def _callee_saved_register_names_from_frame_evidence_8616(project, function_addr: int) -> frozenset[str]:
    insns = _decode_function_insns_8616(project, function_addr)
    if not insns:
        return frozenset()
    callee_saved = {"bx", "si", "di"}
    pushed: list[str] = []
    for insn in insns:
        if getattr(insn, "id", None) == X86_INS_PUSH:
            reg_id = _op_reg_id_8616(insn, 0)
            if isinstance(reg_id, int):
                reg_name = insn.reg_name(reg_id)
                if reg_name in callee_saved:
                    pushed.append(reg_name)
        if getattr(insn, "id", None) == X86_INS_RET:
            break
    if not pushed:
        return frozenset()

    ret_index = next((idx for idx, insn in enumerate(insns) if getattr(insn, "id", None) == X86_INS_RET), None)
    if ret_index is None:
        return frozenset()
    restored: list[str] = []
    scan = ret_index - 1
    while scan >= 0:
        insn = insns[scan]
        insn_id = getattr(insn, "id", None)
        if insn_id == X86_INS_POP:
            reg_id = _op_reg_id_8616(insn, 0)
            if reg_id == X86_REG_BP:
                scan -= 1
                continue
            if isinstance(reg_id, int):
                reg_name = insn.reg_name(reg_id)
                if reg_name in callee_saved:
                    restored.append(reg_name)
                    scan -= 1
                    continue
        if _is_mov_sp_bp_8616(insn):
            scan -= 1
            continue
        break
    if not restored:
        return frozenset()
    return frozenset(set(pushed) & set(restored))


def _expr_register_name_8616(node, project) -> str | None:
    node = _strip_casts_8616(node)
    dirty = getattr(node, "dirty", None)
    reg_offset = _dirty_reg_offset_8616(dirty) if dirty is not None else None
    if reg_offset is None and isinstance(node, structured_c.CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimRegisterVariable):
            reg_offset = getattr(variable, "reg", None)
    if not isinstance(reg_offset, int):
        return None
    reg_name = getattr(project.arch, "register_names", {}).get(reg_offset)
    return reg_name.lower() if isinstance(reg_name, str) else None


def _remove_callee_saved_stack_spills_8616(codegen, project) -> bool:
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(function_addr, int):
        return False
    saved_regs = _callee_saved_register_names_from_frame_evidence_8616(project, function_addr)
    if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
        log.warning("[callee-save-prune] func=%#x saved_regs=%r", function_addr, sorted(saved_regs))
    if not saved_regs:
        return False
    stats = getattr(codegen, "_inertia_callee_saved_spill_prune_stats", None)
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "pruned": 0, "refused": 0}
        codegen._inertia_callee_saved_spill_prune_stats = stats

    def is_prunable(stmt) -> bool:
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _strip_casts_8616(getattr(stmt, "lhs", None))
        if not isinstance(lhs, structured_c.CUnaryOp) or lhs.op != "Dereference":
            return False
        previous_allow_sp = getattr(codegen, "_inertia_allow_direct_sp_for_callee_save_spill", False)
        previous_offset_cache = getattr(codegen, "_inertia_stack_offset_cache", None)
        codegen._inertia_allow_direct_sp_for_callee_save_spill = True
        codegen._inertia_stack_offset_cache = None
        try:
            access = match_stable_ss_linear_stack_access_8616(lhs, project, codegen)
        finally:
            codegen._inertia_allow_direct_sp_for_callee_save_spill = previous_allow_sp
            codegen._inertia_stack_offset_cache = previous_offset_cache
        if access is None:
            if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
                log.warning("[callee-save-prune] refuse no-ss-access lhs=%s", _debug_c_repr_8616(lhs))
            return False
        if not isinstance(access.displacement, int) or access.displacement >= 0:
            if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
                log.warning(
                    "[callee-save-prune] refuse displacement=%r lhs=%s",
                    getattr(access, "displacement", None),
                    _debug_c_repr_8616(lhs),
                )
            return False
        rhs_reg = _expr_register_name_8616(getattr(stmt, "rhs", None), project)
        if rhs_reg not in saved_regs:
            stats["refused"] = int(stats.get("refused", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
                log.warning(
                    "[callee-save-prune] refuse rhs_reg=%r saved=%r rhs=%s",
                    rhs_reg,
                    sorted(saved_regs),
                    _debug_c_repr_8616(getattr(stmt, "rhs", None)),
                )
            return False
        stats["candidates"] = int(stats.get("candidates", 0) or 0) + 1
        if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
            log.warning(
                "[callee-save-prune] prune displacement=%r rhs_reg=%s stmt=%s",
                access.displacement,
                rhs_reg,
                _debug_c_repr_8616(stmt),
            )
        return True

    changed = False

    def rewrite_statement_list(statements: list) -> None:
        nonlocal changed
        kept = []
        for stmt in statements:
            if is_prunable(stmt):
                stats["pruned"] = int(stats.get("pruned", 0) or 0) + 1
                changed = True
                continue
            kept.append(stmt)
        if len(kept) != len(statements):
            statements[:] = kept
        for stmt in tuple(kept):
            for attr in ("statements", "body", "else_node"):
                value = getattr(stmt, attr, None)
                if isinstance(value, structured_c.CStatements):
                    rewrite_statement_list(value.statements)
                elif isinstance(value, list):
                    rewrite_statement_list(value)
            condition_nodes = getattr(stmt, "condition_and_nodes", None)
            if isinstance(condition_nodes, list | tuple):
                for item in condition_nodes:
                    if isinstance(item, tuple) and len(item) >= 2:
                        body = item[1]
                        if isinstance(body, structured_c.CStatements):
                            rewrite_statement_list(body.statements)

    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if isinstance(root, structured_c.CStatements):
        rewrite_statement_list(root.statements)
    elif isinstance(root, list):
        rewrite_statement_list(root)
    return changed


def match_stable_ds_es_linear_global_address_8616(node, project, codegen) -> RealModeLinearGlobalAddress8616 | None:
    """Match an address-valued ``(ds << 4) + base + projection`` expression."""

    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
        return None
    if _contains_materialized_global_reference_8616(node):
        return None

    decomposed = _decompose_linear_global_terms_8616(node, project, codegen=codegen)
    if decomposed is None:
        return None
    segment_name, displacement, residual_terms = decomposed

    if segment_name in {"ds", "es"}:
        return RealModeLinearGlobalAddress8616(
            segment_name=segment_name,
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=None,
        )

    if segment_name is not None or not residual_terms or not _global_displacement_known_8616(codegen, displacement):
        return None
    return RealModeLinearGlobalAddress8616(
        segment_name="segless",
        displacement=displacement & 0xFFFF,
        residual_terms=tuple(residual_terms),
        width=None,
    )


def lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable DS/ES real-mode linear dereferences with global variable references."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def global_cvar(access: RealModeLinearGlobalAddress8616):
        addr = access.displacement & 0xFFFF
        name = f"g_{addr:04X}"
        scalar_width = min(access.width or 1, 2)
        target_type = _type_for_access_width_8616(scalar_width)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
                    existing_size = getattr(variable, "size", None)
                    if _cvar_has_array_type_8616(cvar) or (isinstance(existing_size, int) and existing_size > 2):
                        continue
                    if getattr(variable, "size", None) != scalar_width:
                        variable.size = scalar_width
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if isinstance(variable, SimVariable) and getattr(variable, "name", None) == name:
                    if _cvar_has_array_type_8616(cvar):
                        continue
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) == access.displacement:
                    replacement = SimMemoryVariable(
                        addr,
                        scalar_width,
                        name=name,
                        region=getattr(codegen.cfunc, "addr", None),
                    )
                    replacement_type = getattr(cvar, "variable_type", None) or target_type
                    replacement_cvar = structured_c.CVariable(
                        replacement, variable_type=replacement_type, codegen=codegen
                    )
                    variables_in_use.pop(variable, None)
                    variables_in_use[replacement] = replacement_cvar
                    unified = getattr(codegen.cfunc, "unified_local_vars", None)
                    if isinstance(unified, dict):
                        unified.pop(variable, None)
                        unified[replacement] = {(replacement_cvar, getattr(replacement_cvar, "variable_type", None))}
                    return replacement_cvar
        variable = SimMemoryVariable(
            addr, scalar_width, name=f"mem_{addr:04X}", region=getattr(codegen.cfunc, "addr", None)
        )
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    def global_expr(access: RealModeLinearGlobalAddress8616):
        if not access.residual_terms:
            return global_cvar(access)
        target_type = _type_for_access_width_8616(access.width)
        ptr_type = SimTypePointer(target_type).with_arch(project.arch)
        rebuilt = structured_c.CUnaryOp(
            "Reference",
            global_cvar(access),
            codegen=codegen,
        )
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=codegen,
            )
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=codegen),
            codegen=codegen,
        )

    changed = False

    def transform(node):
        nonlocal changed
        access = match_stable_ds_es_linear_global_access_8616(node, project, codegen)
        if access is not None:
            changed = True
            return global_expr(access)
        return node

    _seen = set()

    def replace_children(root_node) -> bool:
        if root_node is None:
            return False
        node_stack: list[object] = [root_node]
        local_changed = False
        while node_stack:
            node = node_stack.pop()
            if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                continue
            node_id = id(node)
            if node_id in _seen:
                continue
            _seen.add(node_id)

            for attr in (
                "statements",
                "lhs",
                "rhs",
                "operand",
                "expr",
                "init",
                "condition",
                "iteration",
                "body",
                "else_node",
            ):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue

                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        if not type(item).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                            continue
                        replacement = transform(item)
                        if replacement is not item:
                            value[index] = replacement
                            local_changed = True
                            continue
                        candidate = value[index]
                        if type(candidate).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                            node_stack.append(candidate)
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        local_changed = True
                        continue
                    node_stack.append(value)

            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                new_pairs = []
                pair_changed = False
                for cond, body in condition_and_nodes:
                    new_cond = (
                        transform(cond)
                        if type(cond).__module__.startswith("angr.analyses.decompiler.structured_codegen")
                        else cond
                    )
                    new_body = (
                        transform(body)
                        if type(body).__module__.startswith("angr.analyses.decompiler.structured_codegen")
                        else body
                    )
                    if new_cond is not cond:
                        pair_changed = True
                        local_changed = True
                    if new_body is not body:
                        pair_changed = True
                        local_changed = True
                    if new_cond is cond and type(new_cond).__module__.startswith(
                        "angr.analyses.decompiler.structured_codegen"
                    ):
                        node_stack.append(new_cond)
                    if new_body is body and type(new_body).__module__.startswith(
                        "angr.analyses.decompiler.structured_codegen"
                    ):
                        node_stack.append(new_body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    had_active_bias = hasattr(codegen, "_inertia_active_stack_base_bp_bias_8616")
    previous_active_bias = getattr(codegen, "_inertia_active_stack_base_bp_bias_8616", None)
    pass_stack_base_bias = _infer_stack_base_bp_bias_8616(codegen)
    if isinstance(pass_stack_base_bias, int):
        codegen._inertia_active_stack_base_bp_bias_8616 = pass_stack_base_bias
    try:
        if replace_children(root):
            changed = True
    finally:
        if had_active_bias:
            codegen._inertia_active_stack_base_bp_bias_8616 = previous_active_bias
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_active_stack_base_bp_bias_8616")
    if _remove_callee_saved_stack_spills_8616(codegen, project):
        changed = True
    if _materialize_return_register_assignments_8616(codegen, project):
        changed = True
    return changed


def lower_stable_ds_es_linear_global_addresses_8616(codegen, project=None) -> bool:
    """Replace stable DS/ES address-valued expressions with data-space object references."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def global_address_cvar(displacement: int):
        addr = displacement & 0xFFFF
        name = f"g_{addr:04X}"
        target_type = SimTypeChar(False)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if (
                    isinstance(variable, SimMemoryVariable)
                    and getattr(variable, "addr", None) == addr
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if (
                    isinstance(variable, SimVariable)
                    and getattr(variable, "name", None) == name
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
        variable = SimMemoryVariable(addr, 1, name=name, region=getattr(codegen.cfunc, "addr", None))
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    changed = False

    def _reference_expr(displacement: int):
        base_cvar = global_address_cvar(displacement)
        return structured_c.CUnaryOp(
            "Reference",
            base_cvar,
            codegen=codegen,
        )

    def transform(node):
        nonlocal changed
        access = match_stable_ds_es_linear_global_address_8616(node, project, codegen)
        if access is None:
            return node
        base_expr = _reference_expr(access.displacement)
        rebuilt = base_expr
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=codegen,
            )
        ptr_type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
        changed = True
        return structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=codegen)

    _seen: set[int] = set()

    def replace_children(root_node) -> bool:
        if root_node is None:
            return False
        node_stack: list[object] = [root_node]
        local_changed = False
        while node_stack:
            node = node_stack.pop()
            if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                continue
            node_id = id(node)
            if node_id in _seen:
                continue
            _seen.add(node_id)

            for attr in (
                "statements",
                "lhs",
                "rhs",
                "operand",
                "expr",
                "init",
                "condition",
                "iteration",
                "body",
                "else_node",
            ):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        if not type(item).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                            continue
                        replacement = transform(item)
                        if replacement is not item:
                            value[index] = replacement
                            local_changed = True
                            continue
                        item_candidate = value[index]
                        if type(item_candidate).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                            node_stack.append(item_candidate)
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        local_changed = True
                        continue
                    node_stack.append(value)

            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                new_pairs = []
                pair_changed = False
                for cond, body in condition_and_nodes:
                    new_cond = (
                        transform(cond)
                        if type(cond).__module__.startswith("angr.analyses.decompiler.structured_codegen")
                        else cond
                    )
                    if new_cond is not cond:
                        pair_changed = True
                        local_changed = True
                    new_body = (
                        transform(body)
                        if type(body).__module__.startswith("angr.analyses.decompiler.structured_codegen")
                        else body
                    )
                    if new_body is not body:
                        pair_changed = True
                        local_changed = True
                    if new_cond is cond and type(new_cond).__module__.startswith(
                        "angr.analyses.decompiler.structured_codegen"
                    ):
                        node_stack.append(new_cond)
                    if new_body is body and type(new_body).__module__.startswith(
                        "angr.analyses.decompiler.structured_codegen"
                    ):
                        node_stack.append(new_body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_children(root):
        changed = True
    if _materialize_return_register_assignments_8616(codegen, project):
        changed = True
    return changed


def _direct_global_update_name_8616(project, func_addr: int | None, displacement: int) -> str:
    metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if isinstance(metadata_by_addr, dict) and isinstance(func_addr, int):
        candidates = [func_addr]
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(delta, int):
            candidates.extend([func_addr + delta, func_addr - delta])
        for candidate in candidates:
            metadata = metadata_by_addr.get(candidate)
            names = tuple(
                name.lstrip("_")
                for name in getattr(metadata, "global_names", ()) or ()
                if isinstance(name, str) and name.strip()
            )
            if len(names) == 1:
                return names[0]
    labels = getattr(getattr(project, "kb", None), "labels", None)
    if isinstance(labels, dict):
        label = labels.get(displacement & 0xFFFF)
        if isinstance(label, str) and label.strip():
            return label.lstrip("_")
    return f"g_{displacement & 0xFFFF:04X}"


def _direct_global_update_blocks_8616(project, function):
    local_blocks = tuple((getattr(function, "_local_blocks", {}) or {}).values())
    if local_blocks:
        return local_blocks
    blocks = tuple(getattr(function, "blocks", ()) or ())
    if blocks:
        return blocks
    block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
    if not block_addrs or project is None:
        return ()
    decoded = []
    for block_addr in block_addrs:
        try:
            decoded.append(project.factory.block(block_addr, opt_level=0))
        except Exception:
            continue
    return tuple(decoded)


def _capstone_insns_for_direct_global_update_8616(project, block) -> tuple[object, ...]:
    capstone = getattr(block, "capstone", None)
    insns = tuple(getattr(capstone, "insns", ()) or ())
    if insns or project is None:
        return insns
    block_addr = getattr(block, "addr", None)
    if not isinstance(block_addr, int):
        return ()
    block_size = getattr(block, "size", None)
    if not isinstance(block_size, int) or block_size <= 0:
        block_bytes = getattr(block, "bytes", None)
        if isinstance(block_bytes, (bytes, bytearray)):
            block_size = len(block_bytes)
        else:
            block_size = None
    with contextlib.suppress(Exception):
        if isinstance(block_size, int) and block_size > 0:
            decoded = project.factory.block(block_addr, size=block_size, opt_level=0)
        else:
            decoded = project.factory.block(block_addr, opt_level=0)
        return tuple(getattr(getattr(decoded, "capstone", None), "insns", ()) or ())
    return ()


def _direct_global_update_instruction_facts_8616(project, function) -> tuple[DirectGlobalUpdateFact8616, ...]:
    cached = getattr(function, "_inertia_direct_global_update_instruction_facts_8616", None)
    if isinstance(cached, tuple):
        return cached
    facts: list[DirectGlobalUpdateFact8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            insn_id = getattr(insn, "id", None)
            operands = tuple(getattr(insn, "operands", ()) or ())
            if insn_id in {X86_INS_INC, X86_INS_DEC}:
                if len(operands) != 1:
                    continue
                operand = operands[0]
                width = getattr(operand, "size", None)
                delta = 1 if insn_id == X86_INS_INC else -1
            elif insn_id in {X86_INS_ADD, X86_INS_SUB}:
                if len(operands) != 2 or getattr(operands[1], "type", None) != X86_OP_IMM:
                    continue
                operand = operands[0]
                width = getattr(operand, "size", None)
                imm = int(getattr(operands[1], "imm", 0) or 0)
                if width == 1:
                    imm &= 0xFF
                    if imm & 0x80:
                        imm -= 0x100
                else:
                    imm &= 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                delta = imm if insn_id == X86_INS_ADD else -imm
            else:
                continue
            width = getattr(operand, "size", None)
            if getattr(operand, "type", None) != X86_OP_MEM or width not in {1, 2}:
                continue
            mem = getattr(operand, "mem", None)
            if mem is None:
                continue
            base = getattr(mem, "base", X86_REG_INVALID)
            index = getattr(mem, "index", X86_REG_INVALID)
            if base not in {0, X86_REG_INVALID} or index not in {0, X86_REG_INVALID}:
                continue
            displacement = getattr(mem, "disp", None)
            ins_addr = getattr(insn, "address", None)
            if not isinstance(displacement, int) or not isinstance(ins_addr, int):
                continue
            facts.append(
                DirectGlobalUpdateFact8616(
                    displacement & 0xFFFF,
                    int(width),
                    int(delta),
                    ins_addr,
                )
            )
    result = tuple(dict.fromkeys(facts))
    with contextlib.suppress(Exception):
        setattr(function, "_inertia_direct_global_update_instruction_facts_8616", result)
    return result


def _direct_stack_update_instruction_facts_8616(project, function) -> tuple[DirectStackUpdateFact8616, ...]:
    cached = getattr(function, "_inertia_direct_stack_update_instruction_facts_8616", None)
    if isinstance(cached, tuple):
        return cached
    facts: list[DirectStackUpdateFact8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            insn_id = getattr(insn, "id", None)
            if insn_id not in {X86_INS_INC, X86_INS_DEC}:
                continue
            operands = tuple(getattr(insn, "operands", ()) or ())
            if len(operands) != 1:
                continue
            operand = operands[0]
            width = getattr(operand, "size", None)
            if getattr(operand, "type", None) != X86_OP_MEM or width not in {1, 2}:
                continue
            mem = getattr(operand, "mem", None)
            if mem is None:
                continue
            base = getattr(mem, "base", X86_REG_INVALID)
            index = getattr(mem, "index", X86_REG_INVALID)
            if base != X86_REG_BP or index not in {0, X86_REG_INVALID}:
                continue
            offset = _canonical_stack_offset_8616(getattr(mem, "disp", None))
            ins_addr = getattr(insn, "address", None)
            if not isinstance(offset, int) or not isinstance(ins_addr, int):
                continue
            facts.append(DirectStackUpdateFact8616(offset, int(width), 1 if insn_id == X86_INS_INC else -1, ins_addr))
    result = tuple(dict.fromkeys(facts))
    with contextlib.suppress(Exception):
        setattr(function, "_inertia_direct_stack_update_instruction_facts_8616", result)
    return result


def _stack_mem_operand_offset_width_8616(operand) -> tuple[int, int] | None:
    width = getattr(operand, "size", None)
    if getattr(operand, "type", None) != X86_OP_MEM or width not in {1, 2}:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = getattr(mem, "base", X86_REG_INVALID)
    index = getattr(mem, "index", X86_REG_INVALID)
    if base != X86_REG_BP or index not in {0, X86_REG_INVALID}:
        return None
    offset = _canonical_stack_offset_8616(getattr(mem, "disp", None))
    if not isinstance(offset, int):
        return None
    return offset, int(width)


def _previous_stack_load_for_register_8616(insns: tuple[object, ...], index: int, reg_id: int) -> tuple[int, int] | None:
    if index <= 0:
        return None
    prev = getattr(insns[index - 1], "insn", insns[index - 1])
    if getattr(prev, "id", None) != X86_INS_MOV:
        return None
    operands = tuple(getattr(prev, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, src = operands
    if getattr(dst, "type", None) != X86_OP_REG or getattr(dst, "reg", None) != reg_id:
        return None
    return _stack_mem_operand_offset_width_8616(src)


def _previous_shifted_stack_load_for_register_8616(
    insns: tuple[object, ...], index: int, reg_id: int, width: int
) -> tuple[int, int, DirectStackMoveExpressionOp8616] | None:
    if index <= 1:
        return None
    shift = getattr(insns[index - 1], "insn", insns[index - 1])
    if getattr(shift, "id", None) not in {X86_INS_SAL, X86_INS_SHL}:
        return None
    operands = tuple(getattr(shift, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, amount = operands
    if getattr(dst, "type", None) != X86_OP_REG or getattr(dst, "reg", None) != reg_id:
        return None
    if getattr(amount, "type", None) != X86_OP_IMM:
        return None
    immediate = getattr(amount, "imm", None)
    if not isinstance(immediate, int) or immediate < 0 or immediate >= width * 8:
        return None
    source = _previous_stack_load_for_register_8616(insns, index - 1, reg_id)
    if source is None:
        return None
    source_offset, source_width = source
    if source_width != width:
        return None
    return source_offset, immediate, DirectStackMoveExpressionOp8616.SHL


def _register_operand_is_8616(operand, reg_id: int) -> bool:
    return getattr(operand, "type", None) == X86_OP_REG and getattr(operand, "reg", None) == reg_id


def _direct_call_target_from_operand_8616(operand) -> int | None:
    if getattr(operand, "type", None) != X86_OP_IMM:
        return None
    target = getattr(operand, "imm", None)
    return target if isinstance(target, int) else None


def _direct_stack_move_call_target_candidates_8616(project, target: int) -> tuple[tuple[object, int], ...]:
    candidates: list[tuple[object, int]] = [(project, int(target))]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    original_project = getattr(project, "_inertia_original_project", None)
    if original_project is not None:
        candidates.append((original_project, int(target)))
        if isinstance(delta, int) and delta:
            candidates.append((original_project, int(target) + delta))
            rebased = int(target) - delta
            if rebased >= 0:
                candidates.append((project, rebased))
    deduped: list[tuple[object, int]] = []
    seen: set[tuple[int, int]] = set()
    for candidate_project, candidate_target in candidates:
        key = (id(candidate_project), int(candidate_target))
        if key in seen:
            continue
        seen.add(key)
        deduped.append((candidate_project, int(candidate_target)))
    return tuple(deduped)


def _callee_name_for_direct_stack_move_8616(project, target: int) -> tuple[str, object | None, int]:
    for candidate_project, candidate_target in _direct_stack_move_call_target_candidates_8616(project, target):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        callee = None
        if functions is not None:
            with contextlib.suppress(Exception):
                callee = functions.function(addr=int(candidate_target), create=False)
        name = getattr(callee, "name", None)
        if isinstance(name, str) and name:
            return name, callee, int(candidate_target)
        for labels in (
            getattr(getattr(candidate_project, "kb", None), "labels", None),
            getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
        ):
            if labels is None:
                continue
            with contextlib.suppress(Exception):
                label = labels.get(int(candidate_target))
                if isinstance(label, str) and label.strip():
                    return label.lstrip("_"), callee, int(candidate_target)
    return f"sub_{int(target):x}", None, int(target)


def _is_stack_probe_helper_name_for_linear_lowering_8616(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    lowered = name.strip().lower().lstrip("_")
    return lowered in {"anchkstk", "chkstk"}


def _callee_has_zero_args_8616(callee, callee_name: str) -> bool:
    prototype = getattr(callee, "prototype", None)
    args = getattr(prototype, "args", None)
    if isinstance(args, (list, tuple)):
        return len(args) == 0
    return callee_name in {"clock"}


def _wide_call_return_stack_arith_fact_at_8616(project, insns: tuple[object, ...], index: int):
    if index + 4 >= len(insns):
        return None
    call_insn = getattr(insns[index], "insn", insns[index])
    add_insn = getattr(insns[index + 1], "insn", insns[index + 1])
    adc_insn = getattr(insns[index + 2], "insn", insns[index + 2])
    mov_lo = getattr(insns[index + 3], "insn", insns[index + 3])
    mov_hi = getattr(insns[index + 4], "insn", insns[index + 4])
    if getattr(call_insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
        return None
    call_operands = tuple(getattr(call_insn, "operands", ()) or ())
    if len(call_operands) != 1:
        return None
    call_target = _direct_call_target_from_operand_8616(call_operands[0])
    if call_target is None:
        return None
    callee_name, callee, resolved_call_target = _callee_name_for_direct_stack_move_8616(project, call_target)
    if not _callee_has_zero_args_8616(callee, callee_name):
        return None
    if getattr(add_insn, "id", None) != X86_INS_ADD or getattr(adc_insn, "id", None) != X86_INS_ADC:
        return None
    add_operands = tuple(getattr(add_insn, "operands", ()) or ())
    adc_operands = tuple(getattr(adc_insn, "operands", ()) or ())
    if len(add_operands) != 2 or len(adc_operands) != 2:
        return None
    if not _register_operand_is_8616(add_operands[0], X86_REG_AX):
        return None
    if not _register_operand_is_8616(adc_operands[0], X86_REG_DX):
        return None
    arg_lo = _stack_mem_operand_offset_width_8616(add_operands[1])
    arg_hi = _stack_mem_operand_offset_width_8616(adc_operands[1])
    if arg_lo is None or arg_hi is None:
        return None
    arg_offset, arg_width = arg_lo
    arg_hi_offset, arg_hi_width = arg_hi
    if arg_width != 2 or arg_hi_width != 2 or arg_hi_offset != arg_offset + 2:
        return None
    if getattr(mov_lo, "id", None) != X86_INS_MOV or getattr(mov_hi, "id", None) != X86_INS_MOV:
        return None
    mov_lo_operands = tuple(getattr(mov_lo, "operands", ()) or ())
    mov_hi_operands = tuple(getattr(mov_hi, "operands", ()) or ())
    if len(mov_lo_operands) != 2 or len(mov_hi_operands) != 2:
        return None
    if not _register_operand_is_8616(mov_lo_operands[1], X86_REG_AX):
        return None
    if not _register_operand_is_8616(mov_hi_operands[1], X86_REG_DX):
        return None
    dst_lo = _stack_mem_operand_offset_width_8616(mov_lo_operands[0])
    dst_hi = _stack_mem_operand_offset_width_8616(mov_hi_operands[0])
    if dst_lo is None or dst_hi is None:
        return None
    dst_offset, dst_width = dst_lo
    dst_hi_offset, dst_hi_width = dst_hi
    if dst_width != 2 or dst_hi_width != 2 or dst_hi_offset != dst_offset + 2:
        return None
    ins_addr = getattr(mov_lo, "address", None)
    if not isinstance(ins_addr, int):
        return None
    return DirectStackMoveFact8616(
        dst_offset,
        4,
        DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH,
        ins_addr,
        source_offset=arg_offset,
        source_op=DirectStackMoveExpressionOp8616.ADD,
        source_call_target=resolved_call_target,
        source_call_name=callee_name,
    )


def _direct_stack_move_instruction_facts_8616(project, function) -> tuple[DirectStackMoveFact8616, ...]:
    cached = getattr(function, "_inertia_direct_stack_move_instruction_facts_8616", None)
    if isinstance(cached, tuple):
        return cached
    facts: list[DirectStackMoveFact8616] = []
    blocks = tuple(_direct_global_update_blocks_8616(project, function))
    merged_insns = tuple(
        sorted(
            (
                wrapper
                for block in blocks
                for wrapper in _capstone_insns_for_direct_global_update_8616(project, block)
            ),
            key=lambda wrapper: int(getattr(getattr(wrapper, "insn", wrapper), "address", 0) or 0),
        )
    )
    for index in range(len(merged_insns)):
        wide_fact = _wide_call_return_stack_arith_fact_at_8616(project, merged_insns, index)
        if wide_fact is not None:
            facts.append(wide_fact)
    for block in blocks:
        insns = _capstone_insns_for_direct_global_update_8616(project, block)
        for index, wrapper in enumerate(insns):
            insn = getattr(wrapper, "insn", wrapper)
            if getattr(insn, "id", None) != X86_INS_MOV:
                continue
            operands = tuple(getattr(insn, "operands", ()) or ())
            if len(operands) != 2:
                continue
            dst_slot = _stack_mem_operand_offset_width_8616(operands[0])
            if dst_slot is None:
                continue
            dst_offset, width = dst_slot
            ins_addr = getattr(insn, "address", None)
            if not isinstance(ins_addr, int):
                continue
            src = operands[1]
            src_type = getattr(src, "type", None)
            if src_type == X86_OP_IMM:
                value = getattr(src, "imm", None)
                if isinstance(value, int):
                    facts.append(
                        DirectStackMoveFact8616(
                            dst_offset,
                            width,
                            DirectStackMoveSourceKind8616.IMMEDIATE,
                            ins_addr,
                            source_value=value,
                        )
                    )
                continue
            if src_type != X86_OP_REG:
                continue
            reg_id = getattr(src, "reg", None)
            if not isinstance(reg_id, int):
                continue
            prev_load = _previous_stack_load_for_register_8616(insns, index, reg_id)
            if prev_load is not None:
                source_offset, source_width = prev_load
                if source_width != width:
                    continue
                facts.append(
                    DirectStackMoveFact8616(
                        dst_offset,
                        width,
                        DirectStackMoveSourceKind8616.STACK_SLOT,
                        ins_addr,
                        source_offset=source_offset,
                    )
                )
                continue

            shifted_load = _previous_shifted_stack_load_for_register_8616(insns, index, reg_id, width)
            if shifted_load is None:
                continue
            source_offset, immediate, source_op = shifted_load
            facts.append(
                DirectStackMoveFact8616(
                    dst_offset,
                    width,
                    DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
                    ins_addr,
                    source_offset=source_offset,
                    source_op=source_op,
                    source_immediate=immediate,
                )
            )
    result = tuple(dict.fromkeys(facts))
    with contextlib.suppress(Exception):
        setattr(function, "_inertia_direct_stack_move_instruction_facts_8616", result)
    return result


def _has_direct_global_update_assignment_8616(root, addr: int) -> bool:
    for stmt in tuple(getattr(root, "statements", ()) or ()):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs = _strip_casts_8616(getattr(stmt, "lhs", None))
        variable = getattr(lhs, "variable", None) if isinstance(lhs, structured_c.CVariable) else None
        if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
            return True
    return False


def _global_cvar_identity_8616(cvar) -> tuple[int, int | None] | None:
    cvar = _strip_casts_8616(cvar)
    if not isinstance(cvar, structured_c.CVariable):
        return None
    variable = getattr(cvar, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    if not isinstance(addr, int):
        return None
    size = getattr(variable, "size", None)
    return addr, size if isinstance(size, int) else None


def _same_global_cvar_8616(lhs, rhs) -> bool:
    lhs_id = _global_cvar_identity_8616(lhs)
    rhs_id = _global_cvar_identity_8616(rhs)
    return lhs_id is not None and lhs_id == rhs_id


def _is_same_global_update_assignment_8616(stmt, dst_cvar, delta: int) -> bool:
    if not isinstance(stmt, structured_c.CAssignment):
        return False
    if not _same_global_cvar_8616(getattr(stmt, "lhs", None), dst_cvar):
        return False
    rhs = _strip_casts_8616(getattr(stmt, "rhs", None))
    if not isinstance(rhs, structured_c.CBinaryOp):
        return False
    expected_op = "Add" if delta > 0 else "Sub"
    if getattr(rhs, "op", None) != expected_op:
        return False
    if not _same_global_cvar_8616(getattr(rhs, "lhs", None), dst_cvar):
        return False
    rhs_const = _strip_casts_8616(getattr(rhs, "rhs", None))
    return isinstance(rhs_const, structured_c.CConstant) and getattr(rhs_const, "value", None) == abs(int(delta))


def _list_has_global_update_assignment_8616(statements: list[object], dst_cvar, delta: int) -> bool:
    for stmt in statements:
        if _is_same_global_update_assignment_8616(stmt, dst_cvar, delta):
            return True
    return False


def _insertion_point_has_global_update_assignment_8616(
    statements: list[object],
    insert_index: int,
    dst_cvar,
    delta: int,
) -> bool:
    if insert_index > 0:
        previous_assignment = _last_transparent_assignment_8616(statements[insert_index - 1])
        if _is_same_global_update_assignment_8616(previous_assignment, dst_cvar, delta):
            return True
    if insert_index < len(statements):
        next_assignment = _first_transparent_assignment_8616(statements[insert_index])
        if _is_same_global_update_assignment_8616(next_assignment, dst_cvar, delta):
            return True
    return False


def _candidate_ins_addrs_8616(project, ins_addr: int) -> frozenset[int]:
    candidates = {ins_addr}
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        candidates.add(ins_addr + delta)
        candidates.add(ins_addr - delta)
    return frozenset(candidates)


def _node_has_instruction_address_8616(node, project, ins_addr: int) -> bool:
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return False
    tagged_addr = tags.get("ins_addr")
    return isinstance(tagged_addr, int) and tagged_addr in _candidate_ins_addrs_8616(project, ins_addr)


def _resolve_direct_stack_update_cvar_8616(codegen, offset: int, width: int):
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
                continue
            if _canonical_stack_offset_8616(getattr(variable, "offset", None)) != offset:
                continue
            size = getattr(variable, "size", None)
            if isinstance(size, int) and size > 0 and size < width:
                continue
            if isinstance(cvar, structured_c.CVariable):
                return cvar

    target_type = _type_for_access_width_8616(width)
    variable = SimStackVariable(
        offset,
        width,
        base="bp",
        name=_preferred_stack_object_name_8616(offset, codegen=codegen),
        region=getattr(getattr(codegen, "cfunc", None), "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(getattr(codegen, "cfunc", None), "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
    return cvar


def _direct_stack_update_assignment_8616(codegen, cvar, width: int, delta: int, tags=None):
    target_type = _type_for_access_width_8616(width)
    rhs = structured_c.CBinaryOp(
        "Add" if delta > 0 else "Sub",
        cvar,
        structured_c.CConstant(1, target_type, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    return structured_c.CAssignment(cvar, rhs, codegen=codegen, tags=tags)


def _direct_stack_move_source_expr_8616(codegen, fact: DirectStackMoveFact8616):
    target_type = _type_for_access_width_8616(fact.width)
    if fact.source_kind is DirectStackMoveSourceKind8616.IMMEDIATE:
        if not isinstance(fact.source_value, int):
            return None
        mask = (1 << (fact.width * 8)) - 1
        return structured_c.CConstant(fact.source_value & mask, target_type, codegen=codegen)
    if fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT:
        if not isinstance(fact.source_offset, int):
            return None
        return _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
    if fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR:
        if (
            not isinstance(fact.source_offset, int)
            or not isinstance(fact.source_immediate, int)
            or fact.source_op is not DirectStackMoveExpressionOp8616.SHL
        ):
            return None
        source = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
        if source is None:
            return None
        return structured_c.CBinaryOp(
            fact.source_op.value,
            source,
            structured_c.CConstant(fact.source_immediate, target_type, codegen=codegen),
            codegen=codegen,
        )
    if fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
        if (
            not isinstance(fact.source_offset, int)
            or fact.source_op is not DirectStackMoveExpressionOp8616.ADD
            or not isinstance(fact.source_call_target, int)
        ):
            return None
        project = getattr(codegen, "project", None)
        call_name = fact.source_call_name
        callee = None
        if project is not None:
            call_name, callee, _resolved_call_target = _callee_name_for_direct_stack_move_8616(
                project,
                fact.source_call_target,
            )
        if not isinstance(call_name, str) or not call_name:
            call_name = f"sub_{int(fact.source_call_target):x}"
        call_expr = structured_c.CFunctionCall(call_name, callee, [], codegen=codegen)
        stack_expr = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, 4)
        if stack_expr is None:
            return None
        return structured_c.CBinaryOp(
            fact.source_op.value,
            call_expr,
            stack_expr,
            codegen=codegen,
        )
    return None


def _direct_stack_move_assignment_8616(codegen, dst_cvar, source_expr, tags=None):
    return structured_c.CAssignment(dst_cvar, source_expr, codegen=codegen, tags=tags)


def _replace_tagged_assignment_8616(root, project, ins_addr: int, replacement_factory) -> bool:
    changed = False
    materialized = False
    seen: set[int] = set()

    def transform(node):
        nonlocal changed, materialized
        if isinstance(node, structured_c.CAssignment) and _node_has_instruction_address_8616(node, project, ins_addr):
            if materialized:
                return node
            materialized = True
            changed = True
            return replacement_factory(getattr(node, "tags", None))
        return node

    def is_duplicate_tagged_assignment(node) -> bool:
        return (
            materialized
            and isinstance(node, structured_c.CAssignment)
            and _node_has_instruction_address_8616(node, project, ins_addr)
        )

    def replace_children(node) -> None:
        nonlocal changed
        if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        for attr in (
            "statements",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "stmts",
            "init",
            "initializer",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "iteration",
            "iterator",
            "body",
            "else_node",
        ):
            if not hasattr(node, attr):
                continue
            with contextlib.suppress(Exception):
                value = getattr(node, attr)
                if isinstance(value, list):
                    new_items = []
                    list_changed = False
                    for item in tuple(value):
                        if is_duplicate_tagged_assignment(item):
                            changed = True
                            list_changed = True
                            continue
                        replacement = transform(item)
                        if replacement is not item:
                            list_changed = True
                        replace_children(replacement)
                        new_items.append(replacement)
                    if list_changed:
                        value[:] = new_items
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        value = replacement
                    replace_children(value)

        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            new_pairs = []
            pair_changed = False
            for condition, body in tuple(condition_and_nodes):
                new_condition = transform(condition)
                new_body = transform(body)
                if new_condition is not condition or new_body is not body:
                    pair_changed = True
                replace_children(new_condition)
                replace_children(new_body)
                new_pairs.append((new_condition, new_body))
            if pair_changed:
                with contextlib.suppress(Exception):
                    setattr(node, "condition_and_nodes", new_pairs)

    replacement_root = transform(root)
    if replacement_root is not root:
        return True
    replace_children(root)
    return changed


def _stack_cvar_identity_8616(cvar) -> tuple[int, int | None] | None:
    if not isinstance(cvar, structured_c.CVariable):
        return None
    variable = getattr(cvar, "variable", None)
    if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
        return None
    offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
    if not isinstance(offset, int):
        return None
    size = getattr(variable, "size", None)
    return offset, size if isinstance(size, int) else None


def _same_stack_cvar_8616(lhs, rhs) -> bool:
    lhs_id = _stack_cvar_identity_8616(_strip_casts_8616(lhs))
    rhs_id = _stack_cvar_identity_8616(_strip_casts_8616(rhs))
    return lhs_id is not None and lhs_id == rhs_id


def _same_stack_low_half_cvar_8616(lhs, rhs) -> bool:
    lhs_id = _stack_cvar_identity_8616(_strip_casts_8616(lhs))
    rhs_id = _stack_cvar_identity_8616(_strip_casts_8616(rhs))
    if lhs_id is None or rhs_id is None:
        return False
    lhs_offset, lhs_size = lhs_id
    rhs_offset, rhs_size = rhs_id
    return (
        lhs_offset == rhs_offset
        and isinstance(lhs_size, int)
        and isinstance(rhs_size, int)
        and 0 < lhs_size < rhs_size
    )


def _same_stack_move_rhs_8616(lhs, rhs) -> bool:
    lhs = _strip_casts_8616(lhs)
    rhs = _strip_casts_8616(rhs)
    lhs_stack_id = _stack_cvar_identity_8616(lhs)
    rhs_stack_id = _stack_cvar_identity_8616(rhs)
    if lhs_stack_id is not None or rhs_stack_id is not None:
        return lhs_stack_id is not None and lhs_stack_id == rhs_stack_id
    if isinstance(lhs, structured_c.CConstant) and isinstance(rhs, structured_c.CConstant):
        return getattr(lhs, "value", None) == getattr(rhs, "value", None)
    return lhs is rhs


def _is_control_statement_8616(stmt) -> bool:
    return any(hasattr(stmt, attr) for attr in ("condition_and_nodes", "body", "else_node", "iterator", "iteration"))


def _call_name_from_expr_8616(expr) -> str | None:
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CFunctionCall):
        return None
    target = getattr(expr, "callee_target", None)
    if isinstance(target, str) and target.strip():
        return target.lstrip("_")
    callee = getattr(expr, "callee_func", None)
    name = getattr(callee, "name", None)
    return name.lstrip("_") if isinstance(name, str) and name.strip() else None


def _replace_precontrol_stack_assignment_8616(
    root,
    dst_cvar,
    replacement,
    *,
    allow_low_half_lhs: bool = False,
    consume_following_call_name: str | None = None,
) -> bool:
    refused: list[str] = []

    def scan_container(container, path: str) -> bool:
        statements = getattr(container, "statements", None)
        if not isinstance(statements, list):
            refused.append(f"no-statements:path={path}:type={type(container).__name__}")
            return False
        for index, stmt in enumerate(tuple(statements)):
            item_path = f"{path}.{index}"
            if _is_control_statement_8616(stmt):
                refused.append(f"control-before-match:path={item_path}:type={type(stmt).__name__}")
                setattr(root, "_inertia_stack_mov_refused_reasons_8616", tuple(refused))
                return False
            nested = getattr(stmt, "statements", None)
            if isinstance(nested, list):
                if scan_container(stmt, item_path):
                    return True
                continue
            if not isinstance(stmt, structured_c.CAssignment):
                refused.append(f"not-assignment:path={item_path}:type={type(stmt).__name__}")
                continue
            lhs = getattr(stmt, "lhs", None)
            if not _same_stack_cvar_8616(lhs, dst_cvar) and not (
                allow_low_half_lhs and _same_stack_low_half_cvar_8616(lhs, dst_cvar)
            ):
                refused.append(
                    "lhs-mismatch:"
                    f"path={item_path}:lhs={_stack_cvar_identity_8616(getattr(stmt, 'lhs', None))}:"
                    f"dst={_stack_cvar_identity_8616(dst_cvar)}"
                )
                continue
            statements[index] = replacement
            if isinstance(consume_following_call_name, str) and index + 1 < len(statements):
                next_stmt = statements[index + 1]
                next_lhs = getattr(next_stmt, "lhs", None)
                next_rhs = getattr(next_stmt, "rhs", None)
                if (
                    isinstance(next_stmt, structured_c.CAssignment)
                    and (
                        _same_stack_cvar_8616(next_lhs, dst_cvar)
                        or _same_stack_low_half_cvar_8616(next_lhs, dst_cvar)
                    )
                    and _call_name_from_expr_8616(next_rhs) == consume_following_call_name.lstrip("_")
                ):
                    del statements[index + 1]
            return True
        return False

    if scan_container(root, "root"):
        return True
    setattr(root, "_inertia_stack_mov_refused_reasons_8616", tuple(refused))
    return False


def _comparable_instruction_addr_8616(project, tagged_addr: int, ins_addr: int) -> int:
    variants = [tagged_addr]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        variants.extend([tagged_addr + delta, tagged_addr - delta])
    return min(variants, key=lambda candidate: abs(candidate - ins_addr))


def _statement_instruction_addr_8616(stmt, project, ins_addr: int) -> int | None:
    tags = getattr(stmt, "tags", None)
    if not isinstance(tags, dict):
        return None
    tagged_addr = tags.get("ins_addr")
    if not isinstance(tagged_addr, int):
        return None
    return _comparable_instruction_addr_8616(project, tagged_addr, ins_addr)


def _list_has_stack_move_assignment_8616(statements: list[object], dst_cvar, source_expr) -> bool:
    for stmt in statements:
        if _is_same_stack_move_assignment_8616(stmt, dst_cvar, source_expr):
            return True
    return False


def _is_same_stack_move_assignment_8616(stmt, dst_cvar, source_expr) -> bool:
    return (
        isinstance(stmt, structured_c.CAssignment)
        and _same_stack_cvar_8616(getattr(stmt, "lhs", None), dst_cvar)
        and _same_stack_move_rhs_8616(getattr(stmt, "rhs", None), source_expr)
    )


def _first_transparent_assignment_8616(stmt, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    if stmt is None or id(stmt) in seen:
        return None
    seen.add(id(stmt))
    if isinstance(stmt, structured_c.CAssignment):
        return stmt
    if not isinstance(stmt, structured_c.CStatements):
        return None
    for child in tuple(getattr(stmt, "statements", ()) or ()):
        found = _first_transparent_assignment_8616(child, seen)
        if found is not None:
            return found
    return None


def _last_transparent_assignment_8616(stmt, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    if stmt is None or id(stmt) in seen:
        return None
    seen.add(id(stmt))
    if isinstance(stmt, structured_c.CAssignment):
        return stmt
    if not isinstance(stmt, structured_c.CStatements):
        return None
    for child in reversed(tuple(getattr(stmt, "statements", ()) or ())):
        found = _last_transparent_assignment_8616(child, seen)
        if found is not None:
            return found
    return None


def _insertion_point_has_stack_move_assignment_8616(
    statements: list[object],
    insert_index: int,
    dst_cvar,
    source_expr,
) -> bool:
    if insert_index > 0:
        previous_assignment = _last_transparent_assignment_8616(statements[insert_index - 1])
        if _is_same_stack_move_assignment_8616(previous_assignment, dst_cvar, source_expr):
            return True
    if insert_index < len(statements):
        next_assignment = _first_transparent_assignment_8616(statements[insert_index])
        if _is_same_stack_move_assignment_8616(next_assignment, dst_cvar, source_expr):
            return True
    return False


def _insert_after_nearest_preceding_tagged_statement_8616(root, project, ins_addr: int, assignment) -> bool:
    best: tuple[int, list[object], int] | None = None
    dst_cvar = getattr(assignment, "lhs", None)
    source_expr = getattr(assignment, "rhs", None)
    seen: set[int] = set()

    def visit(node) -> None:
        nonlocal best
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            if _list_has_stack_move_assignment_8616(statements, dst_cvar, source_expr):
                setattr(root, "_inertia_stack_mov_assignment_already_present_8616", True)
                return
            for index, stmt in enumerate(tuple(statements)):
                stmt_addr = _statement_instruction_addr_8616(stmt, project, ins_addr)
                if isinstance(stmt_addr, int) and stmt_addr < ins_addr:
                    if best is None or stmt_addr > best[0]:
                        best = (stmt_addr, statements, index)
                visit(stmt)
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                visit(child)
        for attr in ("condition_and_nodes",):
            with contextlib.suppress(Exception):
                pairs = getattr(node, attr, None)
            if not pairs:
                continue
            for _condition, body in tuple(pairs):
                visit(body)

    visit(root)
    if best is None:
        return False
    _stmt_addr, statements, index = best
    if _insertion_point_has_stack_move_assignment_8616(statements, index + 1, dst_cvar, source_expr):
        setattr(root, "_inertia_stack_mov_assignment_already_present_8616", True)
        return False
    statements.insert(index + 1, assignment)
    return True


def _following_instruction_addr_in_node_8616(node, project, ins_addr: int, seen: set[int]) -> int | None:
    if node is None or id(node) in seen:
        return None
    seen.add(id(node))
    best = _statement_instruction_addr_8616(node, project, ins_addr)
    if not isinstance(best, int) or best <= ins_addr:
        best = None

    def consider(value) -> None:
        nonlocal best
        candidate = _following_instruction_addr_in_node_8616(value, project, ins_addr, seen)
        if isinstance(candidate, int) and (best is None or candidate < best):
            best = candidate

    for attr in (
        "statements",
        "lhs",
        "rhs",
        "operand",
        "expr",
        "stmts",
        "init",
        "initializer",
        "condition",
        "cond",
        "iftrue",
        "iffalse",
        "iteration",
        "iterator",
        "body",
        "else_node",
    ):
        if not hasattr(node, attr):
            continue
        with contextlib.suppress(Exception):
            value = getattr(node, attr)
        if isinstance(value, (list, tuple)):
            for item in tuple(value):
                consider(item)
        elif value is not None:
            consider(value)

    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if condition_and_nodes:
        for condition, body in tuple(condition_and_nodes):
            consider(condition)
            consider(body)
    return best


def _insert_before_nearest_following_tagged_statement_8616(root, project, ins_addr: int, assignment) -> bool:
    best: tuple[int, int, list[object], int] | None = None
    dst_cvar = getattr(assignment, "lhs", None)
    source_expr = getattr(assignment, "rhs", None)
    seen: set[int] = set()

    def visit(node, depth: int) -> None:
        nonlocal best
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            if _list_has_stack_move_assignment_8616(statements, dst_cvar, source_expr):
                setattr(root, "_inertia_stack_mov_assignment_already_present_8616", True)
                return
            for index, stmt in enumerate(tuple(statements)):
                stmt_addr = _following_instruction_addr_in_node_8616(stmt, project, ins_addr, set())
                if isinstance(stmt_addr, int):
                    distance = stmt_addr - ins_addr
                    if distance > 0 and (best is None or distance < best[0] or (distance == best[0] and depth > best[1])):
                        best = (distance, depth, statements, index)
                visit(stmt, depth + 1)
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                visit(child, depth + 1)
        for attr in ("condition_and_nodes",):
            with contextlib.suppress(Exception):
                pairs = getattr(node, attr, None)
            if not pairs:
                continue
            for _condition, body in tuple(pairs):
                visit(body, depth + 1)

    visit(root, 0)
    if best is None:
        return False
    _distance, _depth, statements, index = best
    if _insertion_point_has_stack_move_assignment_8616(statements, index, dst_cvar, source_expr):
        setattr(root, "_inertia_stack_mov_assignment_already_present_8616", True)
        return False
    statements.insert(index, assignment)
    return True


def _insert_global_update_before_nearest_following_tagged_statement_8616(
    root,
    project,
    ins_addr: int,
    assignment,
    *,
    delta: int,
) -> bool:
    best: tuple[int, int, list[object], int] | None = None
    dst_cvar = getattr(assignment, "lhs", None)
    seen: set[int] = set()

    def visit(node, depth: int) -> None:
        nonlocal best
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            if _list_has_global_update_assignment_8616(statements, dst_cvar, delta):
                setattr(root, "_inertia_global_update_assignment_already_present_8616", True)
                return
            for index, stmt in enumerate(tuple(statements)):
                stmt_addr = _following_instruction_addr_in_node_8616(stmt, project, ins_addr, set())
                if isinstance(stmt_addr, int):
                    distance = stmt_addr - ins_addr
                    if distance > 0 and (best is None or distance < best[0] or (distance == best[0] and depth > best[1])):
                        best = (distance, depth, statements, index)
                visit(stmt, depth + 1)
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                visit(child, depth + 1)
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                visit(body, depth + 1)

    visit(root, 0)
    if best is None:
        return False
    _distance, _depth, statements, index = best
    if _insertion_point_has_global_update_assignment_8616(statements, index, dst_cvar, delta):
        setattr(root, "_inertia_global_update_assignment_already_present_8616", True)
        return False
    statements.insert(index, assignment)
    return True


def _direct_global_update_ordered_insns_8616(project, function) -> tuple[object, ...]:
    ordered: list[object] = []
    for block in _direct_global_update_blocks_8616(project, function):
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            if isinstance(getattr(insn, "address", None), int):
                ordered.append(insn)
    return tuple(sorted(ordered, key=lambda insn: int(getattr(insn, "address", 0))))


def _operand_is_stack_memory_8616(operand) -> bool:
    if getattr(operand, "type", None) != X86_OP_MEM:
        return False
    mem = getattr(operand, "mem", None)
    if mem is None:
        return False
    base = getattr(mem, "base", X86_REG_INVALID)
    index = getattr(mem, "index", X86_REG_INVALID)
    return base in {X86_REG_BP, X86_REG_SP} and index in {0, X86_REG_INVALID}


def _setup_prefix_instruction_is_nonsemantic_8616(project, insn) -> bool:
    insn_id = getattr(insn, "id", None)
    operands = tuple(getattr(insn, "operands", ()) or ())
    if insn_id in {X86_INS_PUSH, X86_INS_POP}:
        return all(getattr(operand, "type", None) in {X86_OP_REG, X86_OP_IMM} for operand in operands)
    if insn_id == X86_INS_MOV:
        return all(getattr(operand, "type", None) != X86_OP_MEM or _operand_is_stack_memory_8616(operand) for operand in operands)
    if insn_id in {X86_INS_ADD, X86_INS_SUB}:
        if len(operands) != 2 or getattr(operands[0], "type", None) != X86_OP_REG:
            return False
        return getattr(operands[0], "reg", None) in {X86_REG_SP, X86_REG_BP}
    if insn_id in {X86_INS_CALL, X86_INS_LCALL}:
        if len(operands) != 1:
            return False
        target = _direct_call_target_from_operand_8616(operands[0])
        if target is None:
            return False
        callee_name, _callee, _resolved_target = _callee_name_for_direct_stack_move_8616(project, target)
        return _is_stack_probe_helper_name_for_linear_lowering_8616(callee_name)
    return False


def _direct_global_update_can_insert_at_body_start_8616(project, function, fact: DirectGlobalUpdateFact8616) -> bool:
    insns = _direct_global_update_ordered_insns_8616(project, function)
    if not insns:
        return False
    found_fact = False
    for insn in insns:
        ins_addr = getattr(insn, "address", None)
        if not isinstance(ins_addr, int):
            continue
        if ins_addr == fact.ins_addr:
            found_fact = True
            break
        if ins_addr > fact.ins_addr:
            break
        if not _setup_prefix_instruction_is_nonsemantic_8616(project, insn):
            return False
    return found_fact


def _insert_global_update_at_body_start_8616(root, assignment, *, delta: int) -> bool:
    statements = getattr(root, "statements", None)
    if not isinstance(statements, list):
        return False
    dst_cvar = getattr(assignment, "lhs", None)
    if _list_has_global_update_assignment_8616(statements, dst_cvar, delta):
        setattr(root, "_inertia_global_update_assignment_already_present_8616", True)
        return False
    statements.insert(0, assignment)
    return True


def materialize_direct_global_incdec_instructions_8616(codegen, project=None, function=None) -> bool:
    """Materialize direct no-base/no-index real-mode global INC/DEC effects."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False
    if function is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False

    stats = getattr(codegen, "_inertia_direct_global_update_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "raw_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "replaced_count": 0,
            "inserted_count": 0,
            "body_start_inserted_count": 0,
            "already_materialized_count": 0,
            "failure_count": 0,
        }
        setattr(codegen, "_inertia_direct_global_update_lowering_8616", stats)

    facts = _direct_global_update_instruction_facts_8616(project, function)
    if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
        blocks = _direct_global_update_blocks_8616(project, function)
        insn_debug = []
        for block in blocks:
            for wrapper in _capstone_insns_for_direct_global_update_8616(project, block)[:8]:
                insn = getattr(wrapper, "insn", wrapper)
                insn_debug.append(
                    (
                        getattr(insn, "address", None),
                        getattr(insn, "id", None),
                        getattr(insn, "mnemonic", None),
                        len(tuple(getattr(insn, "operands", ()) or ())),
                    )
                )
        print(
            "[dbg-global-update] "
            f"func={getattr(function, 'addr', None)!r} "
            f"cfunc={getattr(getattr(codegen, 'cfunc', None), 'addr', None)!r} "
            f"blocks={tuple(getattr(block, 'addr', None) for block in blocks)!r} "
            f"insns={tuple(insn_debug)!r} "
            f"facts={facts!r}",
            file=sys.stderr,
            flush=True,
        )
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    if not facts:
        return False

    changed = False
    for fact in facts:
        addr = fact.displacement & 0xFFFF
        width = fact.width if fact.width in {1, 2} else 2
        delta = fact.delta
        stats["classified_fact_count"] = int(stats.get("classified_fact_count", 0) or 0) + 1
        name = _direct_global_update_name_8616(project, getattr(getattr(codegen, "cfunc", None), "addr", None), addr)
        variable = SimMemoryVariable(addr, width, name=name, region=getattr(getattr(codegen, "cfunc", None), "addr", None))
        cvar = structured_c.CVariable(
            variable,
            unified_variable=variable,
            variable_type=_type_for_access_width_8616(width),
            codegen=codegen,
        )
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}

        def replacement_factory(tags, *, _cvar=cvar, _width=width, _delta=delta):
            rhs = structured_c.CBinaryOp(
                "Add" if _delta > 0 else "Sub",
                _cvar,
                structured_c.CConstant(abs(int(_delta)), _type_for_access_width_8616(_width), codegen=codegen),
                codegen=codegen,
            )
            return structured_c.CAssignment(_cvar, rhs, codegen=codegen, tags=tags)

        materialized = _replace_tagged_assignment_8616(root, project, fact.ins_addr, replacement_factory)
        materialized_by = DirectGlobalUpdateMaterializationKind8616.REPLACED_TAGGED_ASSIGNMENT if materialized else None
        if materialized:
            stats["replaced_count"] = int(stats.get("replaced_count", 0) or 0) + 1
        else:
            inserted_assignment = replacement_factory({"ins_addr": fact.ins_addr})
            materialized = _insert_global_update_before_nearest_following_tagged_statement_8616(
                root,
                project,
                fact.ins_addr,
                inserted_assignment,
                delta=delta,
            )
            if materialized:
                materialized_by = DirectGlobalUpdateMaterializationKind8616.INSERTED_BEFORE_NEXT_TAGGED_STATEMENT
                stats["inserted_count"] = int(stats.get("inserted_count", 0) or 0) + 1
            elif _direct_global_update_can_insert_at_body_start_8616(project, function, fact):
                materialized = _insert_global_update_at_body_start_8616(
                    root,
                    inserted_assignment,
                    delta=delta,
                )
                if materialized:
                    materialized_by = DirectGlobalUpdateMaterializationKind8616.INSERTED_AT_BODY_START
                    stats["body_start_inserted_count"] = int(stats.get("body_start_inserted_count", 0) or 0) + 1

        if not materialized:
            if bool(getattr(root, "_inertia_global_update_assignment_already_present_8616", False)):
                stats["already_materialized_count"] = int(stats.get("already_materialized_count", 0) or 0) + 1
                if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
                    print(
                        "[dbg-global-update] already-present "
                        f"ins={fact.ins_addr:#x} addr={addr:#x} name={name}",
                        file=sys.stderr,
                        flush=True,
                    )
                continue
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
                print(
                    "[dbg-global-update] failed-materialize "
                    f"ins={fact.ins_addr:#x} addr={addr:#x} name={name} stats={stats!r}",
                    file=sys.stderr,
                    flush=True,
                )
            continue

        ctype = "unsigned char" if width == 1 else "unsigned short"
        specs = tuple(getattr(codegen, "_inertia_global_declaration_specs_8616", ()) or ())
        setattr(
            codegen,
            "_inertia_global_declaration_specs_8616",
            tuple(dict.fromkeys(specs + ((ctype, name, None),))),
        )
        evidence = tuple(getattr(codegen, "_inertia_direct_global_update_evidence_8616", ()) or ())
        setattr(
            codegen,
            "_inertia_direct_global_update_evidence_8616",
            tuple(
                dict.fromkeys(
                    evidence
                    + (
                        (
                            ("displacement", addr),
                            ("width", width),
                            ("delta", delta),
                            ("ins_addr", fact.ins_addr),
                            ("name", name),
                        ),
                    )
                )
            ),
        )
        stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + 1
        if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
            print(
                "[dbg-global-update] materialized "
                f"kind={materialized_by.name if materialized_by is not None else None} "
                f"ins={fact.ins_addr:#x} addr={addr:#x} name={name} stats={stats!r}",
                file=sys.stderr,
                flush=True,
            )
        changed = True

    if changed and getattr(codegen.cfunc, "body", None) is root:
        codegen.cfunc.body = root
    return changed


def materialize_direct_stack_incdec_instructions_8616(codegen, project=None, function=None) -> bool:
    """Materialize direct BP-relative stack INC/DEC effects at their tagged C node."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False
    if function is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False

    stats = getattr(codegen, "_inertia_direct_stack_update_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {"raw_fact_count": 0, "classified_fact_count": 0, "materialized_count": 0, "failure_count": 0}
        setattr(codegen, "_inertia_direct_stack_update_lowering_8616", stats)

    facts = _direct_stack_update_instruction_facts_8616(project, function)
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    if not facts:
        return False

    changed = False
    for fact in facts:
        width = fact.width if fact.width in {1, 2} else 2
        stats["classified_fact_count"] = int(stats.get("classified_fact_count", 0) or 0) + 1
        cvar = _resolve_direct_stack_update_cvar_8616(codegen, fact.offset, width)
        if cvar is None:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        def replacement_factory(tags, *, _cvar=cvar, _width=width, _delta=fact.delta):
            return _direct_stack_update_assignment_8616(codegen, _cvar, _width, _delta, tags=tags)

        if not _replace_tagged_assignment_8616(root, project, fact.ins_addr, replacement_factory):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + 1
        evidence = tuple(getattr(codegen, "_inertia_direct_stack_update_evidence_8616", ()) or ())
        setattr(
            codegen,
            "_inertia_direct_stack_update_evidence_8616",
            tuple(
                dict.fromkeys(
                    evidence
                    + (
                        (
                            ("offset", fact.offset),
                            ("width", width),
                            ("delta", fact.delta),
                            ("ins_addr", fact.ins_addr),
                            ("name", getattr(getattr(cvar, "variable", None), "name", None)),
                        ),
                    )
                )
            ),
        )
        changed = True

    if changed and getattr(codegen.cfunc, "body", None) is root:
        codegen.cfunc.body = root
    return changed


def materialize_direct_stack_mov_instructions_8616(
    codegen, project=None, function=None, *, allow_stack_slot_fallback: bool = True
) -> bool:
    """Materialize direct BP-relative MOV stack stores at their tagged C node."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False
    if function is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False

    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "raw_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "already_materialized_count": 0,
            "failure_count": 0,
        }
        setattr(codegen, "_inertia_direct_stack_move_lowering_8616", stats)

    facts = _direct_stack_move_instruction_facts_8616(project, function)
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    if not facts:
        return False

    changed = False
    for fact in facts:
        setattr(root, "_inertia_stack_mov_assignment_already_present_8616", False)
        stats["classified_fact_count"] = int(stats.get("classified_fact_count", 0) or 0) + 1
        dst_cvar = _resolve_direct_stack_update_cvar_8616(codegen, fact.dst_offset, fact.width)
        source_expr = _direct_stack_move_source_expr_8616(codegen, fact)
        if dst_cvar is None or source_expr is None:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        def replacement_factory(tags, *, _dst_cvar=dst_cvar, _source_expr=source_expr):
            return _direct_stack_move_assignment_8616(codegen, _dst_cvar, _source_expr, tags=tags)

        materialized = _replace_tagged_assignment_8616(root, project, fact.ins_addr, replacement_factory)
        if not materialized:
            fallback_assignment = _direct_stack_move_assignment_8616(codegen, dst_cvar, source_expr, tags=None)
            if fact.source_kind is DirectStackMoveSourceKind8616.IMMEDIATE:
                materialized = _replace_precontrol_stack_assignment_8616(root, dst_cvar, fallback_assignment)
            elif fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
                materialized = _replace_precontrol_stack_assignment_8616(
                    root,
                    dst_cvar,
                    fallback_assignment,
                    allow_low_half_lhs=True,
                    consume_following_call_name=fact.source_call_name,
                )
            elif fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT and allow_stack_slot_fallback:
                materialized = _insert_after_nearest_preceding_tagged_statement_8616(
                    root,
                    project,
                    fact.ins_addr,
                    fallback_assignment,
                )
            elif fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR and allow_stack_slot_fallback:
                materialized = _insert_before_nearest_following_tagged_statement_8616(
                    root,
                    project,
                    fact.ins_addr,
                    fallback_assignment,
                )
        if not materialized:
            if bool(getattr(root, "_inertia_stack_mov_assignment_already_present_8616", False)):
                stats["already_materialized_count"] = int(stats.get("already_materialized_count", 0) or 0) + 1
                continue
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[direct-stack-mov] refused ins=%#x dst=%s source_kind=%s source_value=%s source_offset=%s reasons=%s",
                    fact.ins_addr,
                    _stack_cvar_identity_8616(dst_cvar),
                    fact.source_kind.name,
                    fact.source_value,
                    fact.source_offset,
                    getattr(root, "_inertia_stack_mov_refused_reasons_8616", ()),
                )
            continue
        stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + 1
        evidence = tuple(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ())
        setattr(
            codegen,
            "_inertia_direct_stack_move_evidence_8616",
            tuple(
                dict.fromkeys(
                    evidence
                    + (
                        (
                            ("dst_offset", fact.dst_offset),
                            ("width", fact.width),
                            ("source_kind", fact.source_kind),
                            ("source_value", fact.source_value),
                            ("source_offset", fact.source_offset),
                            ("source_op", fact.source_op),
                            ("source_immediate", fact.source_immediate),
                            ("source_call_target", fact.source_call_target),
                            ("source_call_name", fact.source_call_name),
                            ("ins_addr", fact.ins_addr),
                        ),
                    )
                )
            ),
        )
        changed = True

    if changed and getattr(codegen.cfunc, "body", None) is root:
        codegen.cfunc.body = root
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-mov] function=%#x facts=%d materialized=%d failures=%d changed=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            len(facts),
            int(stats.get("materialized_count", 0) or 0),
            int(stats.get("failure_count", 0) or 0),
            changed,
        )
    return changed


def lower_stable_ss_linear_stack_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable SS real-mode linear dereferences with stack variables."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    # Invalidate cached maps so they are rebuilt against current codegen state
    setattr(codegen, "_inertia_assignment_maps", None)
    setattr(codegen, "_inertia_vvar_carrier_deltas", None)
    setattr(codegen, "_inertia_stack_offset_cache", None)

    changed = False
    candidate_count = 0
    materialized_count = 0
    refused_count = 0

    def transform(node):
        nonlocal candidate_count, changed, materialized_count, refused_count
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        candidate_count += 1
        access = match_stable_ss_linear_stack_access_8616(node, project, codegen)
        if access is not None:
            cvar = stack_cvar_for_stable_ss_linear_access_8616(codegen, access)
            if cvar is None:
                refused_count += 1
                return node
            changed = True
            materialized_count += 1
            return cvar
        refused_count += 1
        return node

    _node_count = [0]
    _seen = set()

    def replace_children(node) -> bool:
        if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return False
        _node_count[0] += 1
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and _node_count[0] % 500 == 0:
            print(f"[lower_ss_linear] tree walk: {_node_count[0]} nodes", file=sys.stderr, flush=True)
        if id(node) in _seen:
            return False
        _seen.add(id(node))
        local_changed = False
        for attr in (
            "statements",
            "lhs",
            "rhs",
            "operand",
            "variable",
            "index",
            "expr",
            "stmts",
            "init",
            "initializer",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "iteration",
            "iterator",
            "body",
            "else_node",
        ):
            if not hasattr(node, attr):
                continue
            value = getattr(node, attr)
            if isinstance(value, list):
                for index, item in enumerate(tuple(value)):
                    replacement = transform(item)
                    if replacement is not item:
                        value[index] = replacement
                        local_changed = True
                    if replace_children(value[index]):
                        local_changed = True
            elif value is not None:
                replacement = transform(value)
                if replacement is not value:
                    setattr(node, attr, replacement)
                    local_changed = True
                    value = replacement
                if replace_children(value):
                    local_changed = True

        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            new_pairs = []
            pair_changed = False
            for cond, body in condition_and_nodes:
                new_cond = (
                    transform(cond)
                    if type(cond).__module__.startswith("angr.analyses.decompiler.structured_codegen")
                    else cond
                )
                new_body = (
                    transform(body)
                    if type(body).__module__.startswith("angr.analyses.decompiler.structured_codegen")
                    else body
                )
                if new_cond is not cond:
                    pair_changed = True
                    local_changed = True
                if new_body is not body:
                    pair_changed = True
                    local_changed = True
                if replace_children(new_cond):
                    local_changed = True
                if replace_children(new_body):
                    local_changed = True
                new_pairs.append((new_cond, new_body))
            if pair_changed:
                setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    if replace_children(root):
        changed = True
    codegen._inertia_ss_linear_candidate_count = int(getattr(codegen, "_inertia_ss_linear_candidate_count", 0) or 0) + candidate_count
    codegen._inertia_ss_linear_materialized_count = (
        int(getattr(codegen, "_inertia_ss_linear_materialized_count", 0) or 0) + materialized_count
    )
    codegen._inertia_ss_linear_refused_count = int(getattr(codegen, "_inertia_ss_linear_refused_count", 0) or 0) + refused_count
    debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
    if isinstance(debug_stats, dict):
        debug_stats["ss_linear_candidates"] = int(debug_stats.get("ss_linear_candidates", 0) or 0) + candidate_count
        debug_stats["ss_linear_materialized"] = int(debug_stats.get("ss_linear_materialized", 0) or 0) + materialized_count
        debug_stats["ss_linear_refused"] = int(debug_stats.get("ss_linear_refused", 0) or 0) + refused_count
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[ss-linear-lowering] function=%#x candidates=%d materialized=%d refused=%d changed=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            candidate_count,
            materialized_count,
            refused_count,
            changed,
        )
    return changed


__all__ = (
    "RealModeLinearGlobalAddress8616",
    "DirectGlobalUpdateFact8616",
    "DirectStackMoveFact8616",
    "DirectStackUpdateFact8616",
    "RealModeLinearStackAccess8616",
    "lower_stable_ds_es_linear_global_addresses_8616",
    "materialize_direct_global_incdec_instructions_8616",
    "materialize_direct_stack_incdec_instructions_8616",
    "materialize_direct_stack_mov_instructions_8616",
    "lower_stable_ss_linear_stack_dereferences_8616",
    "lower_stable_ds_es_linear_global_dereferences_8616",
    "match_stable_ds_es_linear_global_address_8616",
    "match_stable_ss_linear_stack_access_8616",
    "match_stable_ds_es_linear_global_access_8616",
)
