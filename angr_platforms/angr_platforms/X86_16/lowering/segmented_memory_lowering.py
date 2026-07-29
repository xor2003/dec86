"""Apply runtime segmented-memory lowering for proven address forms.

Layer: Types/Lowering.
Responsibility: runtime lowering for proven segmented-memory expressions.
Consumes alias, widening, and typed facts to convert segmented memory carriers
into runtime helper calls or materialized stack/global accesses.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic attribute access in this module is limited to the angr structured-C and
codegen boundary, where upstream classes expose version-dependent attributes.
"""

from __future__ import annotations

import builtins
import typing
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, Sequence, TypeAlias, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_INVALID,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616, _same_c_expression_8616
from .real_mode_linear import (
    RealModeLinearStackAccess8616,
    _canonical_stack_offset_8616,
    _decompose_linear_global_terms_8616,
    _has_stack_alias_fact_for_displacement_8616,
    _known_bp_stack_offsets_8616,
    _segment_base_name_8616,
    _single_assignment_rhs_8616,
    _single_assignment_rhs_for_virtual_name_8616,
    _stack_offset_from_expr_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from .stack_prototype_materialization import materialize_exact_trailing_stack_argument_8616

_CarrierKey8616: TypeAlias = tuple[str, int | str]


class _AngrFunctionTypeBoundary8616(Protocol):
    """Typed view of dynamic angr function-type metadata at the codegen boundary."""

    args: Sequence[object] | None


class _AngrCFunctionBoundary8616(Protocol):
    """Typed view of dynamic angr C function state at the codegen boundary."""

    addr: int
    arg_list: Sequence[object] | None
    functy: _AngrFunctionTypeBoundary8616
    statements: object


def _replace_cfunc_statements_root_8616(cfunc: _AngrCFunctionBoundary8616, root: object) -> None:
    """Replace the supported structured-C statements root."""
    cfunc.statements = root


class _AngrArchBoundary8616(Protocol):
    """Typed view of dynamic angr architecture metadata at the codegen boundary."""

    registers: dict[str, tuple[int, int]]


class _AngrProjectBoundary8616(Protocol):
    """Typed view of dynamic angr project state at the codegen boundary."""

    arch: _AngrArchBoundary8616


class _AngrCodegenBoundary8616(Protocol):
    """Typed view of dynamic angr codegen state used by this lowering pass."""

    cfunc: _AngrCFunctionBoundary8616 | None
    project: _AngrProjectBoundary8616 | None
    _func: object | None
    _inertia_stack_offset_cache: dict[int, object] | None
    _inertia_near_pointer_argument_classified_offsets_8616: set[int]
    _inertia_near_pointer_argument_facts_8616: tuple[NearPointerArgumentFact8616, ...]
    _inertia_near_pointer_argument_materialized_offsets_8616: set[int]
    _inertia_near_pointer_argument_refusals_8616: list[NearPointerArgumentRefusal8616]
    _inertia_near_pointer_argument_stats_8616: NearPointerArgumentStats8616


@dataclass(frozen=True, slots=True)
class SegmentedMemoryExpr:
    """Proven segmented-memory access recovered from structured C expressions."""

    space: str
    segment_expr: object
    offset_expr: object
    width_bits: int
    access: str


@dataclass(frozen=True, slots=True)
class NearPointerArgumentFact8616:
    """Binary proof that one BP argument is dereferenced as a near pointer."""

    stack_offset: int
    carrier_load_ins_addr: int
    dereference_ins_addr: int
    access_width_bytes: int


class NearPointerArgumentRefusalReason8616(StrEnum):
    """Typed reasons a binary-proven pointer argument cannot be materialized."""

    MISSING_FUNCTION_PROTOTYPE = "missing_function_prototype"
    NO_CANONICAL_ARGUMENT = "no_canonical_argument"
    AMBIGUOUS_CANONICAL_ARGUMENT = "ambiguous_canonical_argument"
    INTERFACE_CARDINALITY_MISMATCH = "interface_cardinality_mismatch"


@dataclass(frozen=True, slots=True)
class NearPointerArgumentRefusal8616:
    """Structured interface evidence for one refused pointer argument."""

    reason: NearPointerArgumentRefusalReason8616
    stack_offset: int
    argument_count: int
    argument_match_count: int
    prototype_argument_count: int


@dataclass(frozen=True, slots=True)
class NearPointerArgumentStats8616:
    """Closed evidence counters for near-pointer argument materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    refusals: tuple[NearPointerArgumentRefusal8616, ...] = ()


def _record_near_pointer_argument_refusal_8616(
    codegen: _AngrCodegenBoundary8616,
    *,
    reason: NearPointerArgumentRefusalReason8616,
    stack_offset: int,
    argument_count: int,
    argument_match_count: int,
    prototype_argument_count: int,
) -> None:
    """Record one deduplicated typed refusal at the dynamic codegen boundary."""
    refusal = NearPointerArgumentRefusal8616(
        reason=reason,
        stack_offset=stack_offset,
        argument_count=argument_count,
        argument_match_count=argument_match_count,
        prototype_argument_count=prototype_argument_count,
    )
    if refusal not in codegen._inertia_near_pointer_argument_refusals_8616:
        codegen._inertia_near_pointer_argument_refusals_8616.append(refusal)


def _strip_casts_8616(node: object) -> object:
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _dynamic_angr_attr_8616(obj: object, name: str, default: object | None = None) -> object | None:
    """Read version-dependent attributes at the dynamic angr/codegen boundary."""
    return builtins.getattr(obj, name, default)


def _dynamic_angr_setattr_8616(obj: object, name: str, value: object) -> None:
    """Write version-dependent attributes at the dynamic angr/codegen boundary."""
    builtins.setattr(obj, name, value)


def _dynamic_angr_int_attr_8616(obj: object, name: str, default: int = 0) -> int:
    """Read integer metadata at the dynamic angr/codegen boundary."""
    value = _dynamic_angr_attr_8616(obj, name, default)
    return value if isinstance(value, int) else default


def _dynamic_angr_sequence_attr_8616(obj: object, name: str) -> Sequence[object]:
    """Read sequence metadata at the dynamic angr/codegen boundary."""
    value = _dynamic_angr_attr_8616(obj, name, ())
    return value if isinstance(value, (list, tuple)) else ()


def _bump_codegen_counter_8616(codegen: object, name: str, amount: int = 1) -> None:
    """Update an ad-hoc metric at the dynamic angr codegen boundary."""
    _dynamic_angr_setattr_8616(codegen, name, _dynamic_angr_int_attr_8616(codegen, name) + amount)


def _constant_value_8616(node: object) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _zero_plus_pointer_arg_8616(
    expr: object,
    codegen: _AngrCodegenBoundary8616 | None,
) -> structured_c.CVariable | None:
    expr = _strip_casts_8616(expr)
    if isinstance(expr, structured_c.CVariable) and _is_near_pointer_arg_cvar_8616(expr, codegen):
        return expr
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None
    if _constant_value_8616(expr.lhs) == 0:
        return _zero_plus_pointer_arg_8616(expr.rhs, codegen)
    if _constant_value_8616(expr.rhs) == 0:
        return _zero_plus_pointer_arg_8616(expr.lhs, codegen)
    return None


def _zero_plus_cvar_8616(expr: object) -> structured_c.CVariable | None:
    """Return the sole C variable in an expression with only additive zeros."""
    expr = _strip_casts_8616(expr)
    if isinstance(expr, structured_c.CVariable):
        return expr
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None
    if _constant_value_8616(expr.lhs) == 0:
        return _zero_plus_cvar_8616(expr.rhs)
    if _constant_value_8616(expr.rhs) == 0:
        return _zero_plus_cvar_8616(expr.lhs)
    return None


def _scaled_index_for_access_width_8616(
    expr: object,
    access_width_bytes: int,
) -> structured_c.CExpression | None:
    """Return an index only when its byte scale exactly matches the access width."""
    expr = _strip_casts_8616(expr)
    if access_width_bytes <= 0 or not isinstance(expr, structured_c.CBinaryOp):
        return None
    if expr.op == "Shl":
        shift = _constant_value_8616(expr.rhs)
        if isinstance(shift, int) and shift >= 0 and 1 << shift == access_width_bytes:
            return expr.lhs
        return None
    if expr.op != "Mul":
        return None
    if _constant_value_8616(expr.lhs) == access_width_bytes:
        return expr.rhs
    if _constant_value_8616(expr.rhs) == access_width_bytes:
        return expr.lhs
    return None


def _cvar_plus_scaled_index_8616(
    expr: object,
    access_width_bytes: int,
) -> tuple[structured_c.CVariable, structured_c.CExpression] | None:
    """Match one C variable plus an index scaled by the exact element width."""
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None
    for base_expr, index_expr in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
        base = _zero_plus_cvar_8616(base_expr)
        index = _scaled_index_for_access_width_8616(index_expr, access_width_bytes)
        if base is not None and index is not None:
            return base, index
    return None


def _stack_offset_for_cvar_8616(cvar: object) -> int | None:
    if not isinstance(cvar, structured_c.CVariable):
        return None
    for variable in (cvar.variable, cvar.unified_variable):
        offset = _dynamic_angr_attr_8616(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and isinstance(offset, int):
            return offset
    return None


def _near_pointer_arg_type_8616(
    cvar: object,
    codegen: _AngrCodegenBoundary8616 | None,
) -> SimTypePointer | None:
    """Return the canonical pointer type for one proven argument storage identity."""
    if not isinstance(cvar, structured_c.CVariable):
        return None
    if isinstance(cvar.variable_type, SimTypePointer):
        return cvar.variable_type
    if codegen is None or codegen.cfunc is None:
        return None
    cfunc = codegen.cfunc
    arg_list = tuple(cfunc.arg_list or ())
    prototype_args = tuple(_dynamic_angr_sequence_attr_8616(cfunc.functy, "args"))
    cvar_offset = _stack_offset_for_cvar_8616(cvar)
    matches: list[SimTypePointer] = []
    for index, arg in enumerate(arg_list):
        if not isinstance(arg, structured_c.CVariable):
            continue
        same_object = arg is cvar
        same_offset = isinstance(cvar_offset, int) and _stack_offset_for_cvar_8616(arg) == cvar_offset
        if not same_object and not same_offset:
            continue
        proto_type = prototype_args[index] if index < len(prototype_args) else None
        if isinstance(arg.variable_type, SimTypePointer):
            matches.append(arg.variable_type)
        elif isinstance(proto_type, SimTypePointer):
            matches.append(proto_type)
    return matches[0] if len(matches) == 1 else None


def _is_near_pointer_arg_cvar_8616(cvar: object, codegen: _AngrCodegenBoundary8616 | None) -> bool:
    """Return whether a C variable joins to one canonical near-pointer argument."""
    return _near_pointer_arg_type_8616(cvar, codegen) is not None


def _pointer_element_width_bits_8616(pointer_type: SimTypePointer) -> int | None:
    """Return the pointee width in bits when angr exposes a complete type."""
    try:
        return pointer_type.pts_to.size
    except (AttributeError, ValueError):
        return None


def _active_function_for_codegen_8616(codegen: _AngrCodegenBoundary8616) -> object | None:
    """Resolve the current angr function at the dynamic project boundary."""
    if codegen.cfunc is None or codegen.project is None:
        return None
    try:
        if codegen._func is not None:
            return codegen._func
    except AttributeError:
        pass
    try:
        return typing.cast(typing.Any, codegen.project).kb.functions.get(codegen.cfunc.addr)
    except (AttributeError, KeyError, TypeError):
        return None


def _collect_near_pointer_argument_facts_8616(function: object) -> tuple[NearPointerArgumentFact8616, ...]:
    """Collect BP-argument loads that feed exact register-indirect accesses."""
    if function is None:
        return ()
    try:
        blocks = tuple(typing.cast(typing.Any, function).blocks)
    except (AttributeError, TypeError):
        return ()
    facts: list[NearPointerArgumentFact8616] = []
    seen: set[tuple[int, int, int]] = set()
    for block in sorted(blocks, key=lambda candidate: int(candidate.addr)):
        carriers: dict[int, tuple[int, int]] = {}
        try:
            wrapped_insns = tuple(block.capstone.insns)
        except AttributeError:
            continue
        for wrapped in wrapped_insns:
            insn = wrapped.insn
            operands = tuple(insn.operands)
            insn_addr = int(insn.address)
            for operand in operands:
                if operand.type != X86_OP_MEM:
                    continue
                base_register = int(operand.mem.base)
                if base_register not in carriers:
                    continue
                stack_offset, carrier_load_ins_addr = carriers[base_register]
                access_width = int(operand.size)
                if access_width <= 0:
                    continue
                key = (stack_offset, insn_addr, access_width)
                if key in seen:
                    continue
                seen.add(key)
                facts.append(
                    NearPointerArgumentFact8616(
                        stack_offset=stack_offset,
                        carrier_load_ins_addr=carrier_load_ins_addr,
                        dereference_ins_addr=insn_addr,
                        access_width_bytes=access_width,
                    )
                )
            if insn.id in {X86_INS_CALL, X86_INS_LCALL}:
                carriers.clear()
                continue
            if not operands or operands[0].type != X86_OP_REG:
                continue
            destination_register = int(operands[0].reg)
            if insn.id == X86_INS_ADD and destination_register in carriers:
                continue
            if insn.id != X86_INS_MOV or len(operands) != 2:
                carriers.pop(destination_register, None)
                continue
            source = operands[1]
            if (
                source.type == X86_OP_MEM
                and int(source.mem.base) == X86_REG_BP
                and int(source.mem.index) == X86_REG_INVALID
                and int(source.mem.disp) >= 4
                and int(source.size) == 2
            ):
                carriers[destination_register] = (int(source.mem.disp), insn_addr)
                continue
            if source.type == X86_OP_REG and int(source.reg) in carriers:
                carriers[destination_register] = carriers[int(source.reg)]
                continue
            carriers.pop(destination_register, None)
    return tuple(sorted(facts, key=lambda fact: (fact.dereference_ins_addr, fact.stack_offset)))


def _materialize_binary_proven_near_pointer_argument_8616(
    matched: SegmentedMemoryExpr,
    codegen: _AngrCodegenBoundary8616 | None,
) -> structured_c.CVariable | None:
    """Promote only the BP argument proven by binary register-indirect use."""
    if matched.space != "DS" or codegen is None or codegen.cfunc is None or codegen.project is None:
        return None
    cvar = _zero_plus_cvar_8616(matched.offset_expr)
    if cvar is None and matched.width_bits % 8 == 0:
        indexed = _cvar_plus_scaled_index_8616(
            matched.offset_expr,
            matched.width_bits // 8,
        )
        if indexed is not None:
            cvar, _index = indexed
    stack_offset = _stack_offset_for_cvar_8616(cvar)
    if cvar is None or not isinstance(stack_offset, int):
        return None
    try:
        facts = codegen._inertia_near_pointer_argument_facts_8616
    except AttributeError:
        return None
    matching_facts = tuple(
        fact
        for fact in facts
        if fact.stack_offset == stack_offset and fact.access_width_bytes * 8 == matched.width_bits
    )
    if not matching_facts:
        return None
    arguments = tuple(codegen.cfunc.arg_list or ())
    argument_matches = tuple(
        (index, argument)
        for index, argument in enumerate(arguments)
        if isinstance(argument, structured_c.CVariable) and _stack_offset_for_cvar_8616(argument) == stack_offset
    )
    prototype = codegen.cfunc.functy
    if not isinstance(prototype, SimTypeFunction):
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.MISSING_FUNCTION_PROTOTYPE,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=len(argument_matches),
            prototype_argument_count=0,
        )
        return None
    typed_prototype = cast(SimTypeFunction, prototype)
    prototype_args: tuple[SimType, ...] = tuple(typed_prototype.args or ())
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(codegen.project.arch)  # type: ignore[arg-type]
    if not argument_matches:
        materialized_argument = materialize_exact_trailing_stack_argument_8616(
            codegen.project,
            codegen,
            candidate=cvar,
            stack_offset=stack_offset,
            argument_type=pointer_type,
            width=2,
        )
        if materialized_argument is None:
            _record_near_pointer_argument_refusal_8616(
                codegen,
                reason=NearPointerArgumentRefusalReason8616.NO_CANONICAL_ARGUMENT,
                stack_offset=stack_offset,
                argument_count=len(arguments),
                argument_match_count=0,
                prototype_argument_count=len(prototype_args),
            )
            return None
        arguments = tuple(codegen.cfunc.arg_list or ())
        argument_matches = tuple(
            (index, argument)
            for index, argument in enumerate(arguments)
            if isinstance(argument, structured_c.CVariable)
            and _stack_offset_for_cvar_8616(argument) == stack_offset
        )
        typed_prototype = cast(SimTypeFunction, codegen.cfunc.functy)
        prototype_args = tuple(typed_prototype.args or ())
    if len(argument_matches) != 1:
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.AMBIGUOUS_CANONICAL_ARGUMENT,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=len(argument_matches),
            prototype_argument_count=len(prototype_args),
        )
        return None
    if len(arguments) != len(prototype_args):
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.INTERFACE_CARDINALITY_MISMATCH,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=1,
            prototype_argument_count=len(prototype_args),
        )
        return None
    argument_index, argument = argument_matches[0]
    codegen._inertia_near_pointer_argument_classified_offsets_8616.add(stack_offset)
    cvar.variable_type = pointer_type
    argument.variable_type = pointer_type
    if isinstance(cvar.variable, SimStackVariable):
        cvar.variable.size = 2
    if isinstance(argument.variable, SimStackVariable):
        argument.variable.size = 2
    updated_args: list[SimType] = list(prototype_args)
    updated_args[argument_index] = pointer_type
    codegen.cfunc.functy = SimTypeFunction(
        updated_args,
        typed_prototype.returnty,
        arg_names=tuple(typed_prototype.arg_names or ()),
        variadic=typed_prototype.variadic,
    ).with_arch(codegen.project.arch)  # type: ignore[arg-type]
    codegen._inertia_near_pointer_argument_materialized_offsets_8616.add(stack_offset)
    return cvar


def _lower_binary_proven_pointer_argument_helpers_8616(
    codegen: _AngrCodegenBoundary8616,
) -> bool:
    """Lower DS runtime helpers whose offsets are binary-proven pointer arguments."""
    if codegen.cfunc is None or codegen.project is None:
        return False
    changed = False

    def transform(node: object) -> object:
        nonlocal changed
        helper_name = _runtime_segment_helper_name_8616(node)
        width_bytes = _runtime_segment_helper_width_8616(helper_name)
        args = _runtime_segment_helper_args_8616(node)
        if width_bytes is None or args is None:
            return node
        if _segment_base_name_8616(args[0], codegen.project, codegen=codegen) != "ds":
            return node
        matched = SegmentedMemoryExpr(
            space="DS",
            segment_expr=args[0],
            offset_expr=args[1],
            width_bits=width_bytes * 8,
            access="read",
        )
        pointer_access = _near_pointer_arg_access_8616(matched, codegen)
        if pointer_access is None:
            return node
        changed = True
        return pointer_access

    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True
    return changed


def _near_pointer_arg_access_8616(
    matched: SegmentedMemoryExpr,
    codegen: _AngrCodegenBoundary8616 | None,
) -> structured_c.CIndexedVariable | None:
    if matched.space != "DS":
        return None
    if matched.width_bits % 8 == 0:
        indexed = _cvar_plus_scaled_index_8616(
            matched.offset_expr,
            matched.width_bits // 8,
        )
        if indexed is not None:
            pointer_arg, index = indexed
            pointer_type = _near_pointer_arg_type_8616(pointer_arg, codegen)
            if pointer_type is None:
                materialized_pointer = _materialize_binary_proven_near_pointer_argument_8616(
                    matched,
                    codegen,
                )
                if materialized_pointer is not None:
                    pointer_arg = materialized_pointer
                    pointer_type = _near_pointer_arg_type_8616(pointer_arg, codegen)
            if pointer_type is not None and _pointer_element_width_bits_8616(pointer_type) == matched.width_bits:
                pointer_arg.variable_type = pointer_type
                return structured_c.CIndexedVariable(
                    pointer_arg,
                    index,
                    codegen=codegen,
                )
    pointer_arg = _zero_plus_pointer_arg_8616(matched.offset_expr, codegen)
    if pointer_arg is None:
        # The zero-index fallback may promote an untyped pointer base only
        # when additive-zero normalization proves there is no residual offset.
        # An unparsed scale or index must remain explicit instead of silently
        # becoming pointer[0].
        if _zero_plus_cvar_8616(matched.offset_expr) is None:
            return None
        pointer_arg = _materialize_binary_proven_near_pointer_argument_8616(matched, codegen)
    if pointer_arg is None:
        return None
    pointer_type = _near_pointer_arg_type_8616(pointer_arg, codegen)
    if pointer_type is None or _pointer_element_width_bits_8616(pointer_type) != matched.width_bits:
        return None
    pointer_arg.variable_type = pointer_type
    index_type = SimTypeShort(False)
    arch = codegen.project.arch if codegen is not None and codegen.project is not None else None
    if arch is not None and hasattr(index_type, "with_arch"):
        index_type = index_type.with_arch(arch)  # type: ignore[arg-type]
    return structured_c.CIndexedVariable(
        pointer_arg,
        structured_c.CConstant(0, index_type, codegen=codegen),
        codegen=codegen,
    )


def _extract_segment_scale_8616(
    node: object,
    project: object,
    codegen: _AngrCodegenBoundary8616 | None = None,
) -> tuple[str | None, object | None]:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None, None
    expected_scale = 16 if node.op == "Mul" else 4 if node.op == "Shl" else None
    if expected_scale is None:
        return None, None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_value_8616(maybe_scale) != expected_scale:
            continue
        seg_name = _segment_base_name_8616(maybe_seg, project, codegen=codegen)
        if seg_name is not None:
            return seg_name, maybe_seg
    return None, None


def _linear_carrier_name_8616(node: object) -> str | None:
    node = _strip_casts_8616(node)
    dirty = _dynamic_angr_attr_8616(node, "dirty", None)
    if dirty is not None:
        varid = _dynamic_angr_attr_8616(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
        name = _dynamic_angr_attr_8616(dirty, "name", None)
        if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
            return name
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = _dynamic_angr_attr_8616(node, "variable", None)
    name = _dynamic_angr_attr_8616(node, "name", None) or _dynamic_angr_attr_8616(variable, "name", None)
    if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
        return name
    return None


def _carrier_key_8616(node: object) -> _CarrierKey8616 | None:
    node = _strip_casts_8616(node)
    dirty = _dynamic_angr_attr_8616(node, "dirty", None)
    if dirty is not None:
        varid = _dynamic_angr_attr_8616(dirty, "varid", None)
        if isinstance(varid, int):
            return ("vvar", varid)
        name = _dynamic_angr_attr_8616(dirty, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        oident = _dynamic_angr_attr_8616(dirty, "oident", None)
        category = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(dirty, "category", None), "name", None)
        if isinstance(oident, int | str) and isinstance(category, str):
            return (f"dirty-{category.lower()}", oident)
    if isinstance(node, structured_c.CVariable):
        variable = _dynamic_angr_attr_8616(node, "variable", None)
        name = _dynamic_angr_attr_8616(node, "name", None) or _dynamic_angr_attr_8616(variable, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        if variable is not None:
            return ("var", id(variable))
    return None


def _terminal_carrier_expr_8616(node: object, codegen: _AngrCodegenBoundary8616 | None) -> object:
    current = _strip_casts_8616(node)
    seen: set[str] = set()
    while True:
        rhs = _single_assignment_carrier_rhs_8616(current, codegen, seen)
        if rhs is None:
            return current
        current = _strip_casts_8616(rhs)


def _single_assignment_carrier_rhs_8616(
    node: object,
    codegen: _AngrCodegenBoundary8616 | None,
    seen: set[str],
) -> object | None:
    if codegen is None:
        return None
    name = _linear_carrier_name_8616(node)
    if name is None or name in seen:
        return None
    seen.add(name)
    node = _strip_casts_8616(node)
    rhs = _single_assignment_rhs_8616(codegen, node) if isinstance(node, structured_c.CVariable) else None
    if rhs is None:
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, name)
    if rhs is not None:
        _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_carrier_resolved_count_8616")
    return rhs


def _find_segment_expr_8616(
    node: object,
    *,
    project: object,
    codegen: _AngrCodegenBoundary8616 | None,
    segment_name: str,
    seen: set[str] | None = None,
) -> object | None:
    if seen is None:
        seen = set()
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp):
        scaled_name, scaled_expr = _extract_segment_scale_8616(node, project, codegen=codegen)
        if scaled_name is not None and scaled_name.upper() == segment_name.upper():
            return scaled_expr
        for child in (_dynamic_angr_attr_8616(node, "lhs", None), _dynamic_angr_attr_8616(node, "rhs", None)):
            found = _find_segment_expr_8616(
                child,
                project=project,
                codegen=codegen,
                segment_name=segment_name,
                seen=seen,
            )
            if found is not None:
                return found
    rhs = _single_assignment_carrier_rhs_8616(node, codegen, seen)
    if rhs is not None:
        return _find_segment_expr_8616(
            rhs,
            project=project,
            codegen=codegen,
            segment_name=segment_name,
            seen=seen,
        )
    return None


def _flatten_signed_terms_8616(node: object, sign: int = 1) -> tuple[tuple[int, object], ...]:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, sign)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, -sign)
    return ((sign, node),)


def _build_offset_expr_8616(
    terms: tuple[tuple[int, object], ...],
    codegen: _AngrCodegenBoundary8616 | None,
) -> object:
    if not terms:
        return structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)

    expr = None
    for sign, term in terms:
        term = _strip_casts_8616(term)
        if expr is None:
            if sign == 1:
                expr = term
            else:
                expr = structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            continue
        expr = structured_c.CBinaryOp("Add" if sign == 1 else "Sub", expr, term, codegen=codegen)
    return expr


def _match_segmented_memory_expr_8616(
    node: object,
    *,
    project: object,
    access: str,
) -> SegmentedMemoryExpr | None:
    def _impl() -> SegmentedMemoryExpr | None:
        nonlocal node
        if access == "read" or access == "write":
            node = _strip_casts_8616(node)
            if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
                return None
            base_expr = node.operand
            width_bits = _dynamic_angr_int_attr_8616(_dynamic_angr_attr_8616(node, "type", None), "size", 16)
            codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(node, "codegen", None))
        else:
            base_expr = node
            width_bits = 0
            codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(node, "codegen", None))

        if not _may_contain_segment_linear_terms_8616(base_expr, project, codegen=codegen):
            if codegen is not None:
                _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_lowering_fast_refused_8616")
            return None

        decomposed = _decompose_linear_global_terms_8616(base_expr, project, codegen=codegen)
        if decomposed is not None:
            segment_name, displacement, residual_terms = decomposed
            if segment_name is not None:
                segment_name = segment_name.upper()
                segment_expr = _find_segment_expr_8616(
                    base_expr,
                    project=project,
                    codegen=codegen,
                    segment_name=segment_name,
                )
                if (
                    segment_name in {"DS", "ES", "SS"}
                    and segment_expr is not None
                    and not (segment_name == "SS" and _expr_mentions_stack_variable_8616(base_expr))
                ):
                    offset_terms = list(residual_terms)
                    if displacement:
                        sign = 1 if displacement >= 0 else -1
                        offset_terms.insert(
                            0,
                            (
                                sign,
                                structured_c.CConstant(
                                    abs(displacement),
                                    SimTypeShort(False),
                                    codegen=codegen,
                                ),
                            ),
                        )
                    return SegmentedMemoryExpr(
                        space=segment_name,
                        segment_expr=segment_expr,
                        offset_expr=_build_offset_expr_8616(tuple(offset_terms), codegen),
                        width_bits=int(width_bits),
                        access=access,
                    )

        segment_name = None
        segment_expr = None
        offset_terms: list[tuple[int, object]] = []
        for sign, term in _flatten_signed_terms_8616(base_expr):
            local_name, local_expr = _extract_segment_scale_8616(term, project, codegen=codegen)
            if local_name is not None:
                if sign != 1 or segment_name is not None:
                    return None
                segment_name = local_name.upper()
                segment_expr = local_expr
                continue
            offset_terms.append((sign, term))

        if segment_name not in {"DS", "ES", "SS"} or segment_expr is None:
            return None
        return SegmentedMemoryExpr(
            space=segment_name,
            segment_expr=segment_expr,
            offset_expr=_build_offset_expr_8616(tuple(offset_terms), codegen),
            width_bits=int(width_bits),
            access=access,
        )

    return _impl()


def _may_contain_segment_linear_terms_8616(
    node: object,
    project: object,
    *,
    codegen: _AngrCodegenBoundary8616 | None = None,
) -> bool:
    pending = [_strip_casts_8616(node)]
    seen: set[int] = set()
    visited = 0
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        visited += 1
        if visited > 128:
            # Refuse to guess on very large expressions. Fall through to the
            # full matcher rather than risking a false negative.
            return True
        segment_name = _segment_base_name_8616(current, project, codegen=codegen)
        if segment_name in {"ds", "es", "ss", "DS", "ES", "SS"}:
            return True
        if _linear_carrier_name_8616(current) is not None:
            return True
        for attr in ("lhs", "rhs", "operand", "expr", "index", "variable"):
            child = _dynamic_angr_attr_8616(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = _dynamic_angr_attr_8616(current, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in children if child is not None)
    return False


def _seg_macro_for_width_bits_8616(width_bits: int) -> str | None:
    if width_bits <= 8:
        return "SEG_U8"
    if width_bits <= 16:
        return "SEG_U16"
    if width_bits <= 32:
        return "SEG_U32"
    return None


def _expr_mentions_stack_variable_8616(node: object) -> bool:
    pending = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        variable = _dynamic_angr_attr_8616(current, "variable", None)
        if isinstance(variable, SimStackVariable):
            return True
        for attr in ("lhs", "rhs", "operand", "expr", "index", "variable"):
            child = _dynamic_angr_attr_8616(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = _dynamic_angr_attr_8616(current, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in children if child is not None)
    return False


def _is_proven_ss_stack_access_8616(
    matched: SegmentedMemoryExpr,
    *,
    codegen: _AngrCodegenBoundary8616 | None,
    project: object,
) -> bool:
    if matched.space != "SS":
        return False
    if _expr_mentions_stack_variable_8616(matched.offset_expr):
        return True
    displacement = _stack_offset_from_expr_8616(matched.offset_expr, project, codegen)
    displacement = _canonical_stack_offset_8616(displacement)
    if not isinstance(displacement, int):
        return False
    width = max(int(matched.width_bits or 16) // 8, 1)
    return _has_stack_alias_fact_for_displacement_8616(
        codegen, displacement, width
    ) or displacement in _known_bp_stack_offsets_8616(codegen)


def lower_runtime_segment_access_8616(expr: object, *, target: str) -> object | None:
    """Lower a proven segmented dereference to a runtime helper or pointer access."""
    codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(expr, "codegen", None))
    project = _dynamic_angr_attr_8616(codegen, "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="read")
    if matched is None:
        return None
    if matched.space == "SS" and _is_proven_ss_stack_access_8616(matched, codegen=codegen, project=project):
        return None
    pointer_access = _near_pointer_arg_access_8616(matched, codegen)
    if pointer_access is not None:
        return pointer_access
    macro = _seg_macro_for_width_bits_8616(matched.width_bits)
    if macro is None:
        return None
    return structured_c.CFunctionCall(
        macro,
        None,
        [matched.segment_expr, matched.offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": macro},
    )


def lower_runtime_segment_address_8616(expr: object, *, target: str) -> object | None:
    """Lower a proven segmented address expression to an explicit far pointer helper."""
    codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(expr, "codegen", None))
    project = _dynamic_angr_attr_8616(codegen, "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="address")
    if matched is None:
        return None
    if matched.space not in {"DS", "ES"}:
        return None
    return structured_c.CFunctionCall(
        "MK_FP",
        None,
        [matched.segment_expr, matched.offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "MK_FP"},
    )


def _runtime_segment_helper_name_8616(node: object) -> str | None:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    for candidate in (
        _dynamic_angr_attr_8616(node, "callee_target", None),
        _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(node, "callee_func", None), "name", None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate.strip()
    return None


def _runtime_segment_helper_width_8616(name: str | None) -> int | None:
    normalized = name.upper() if isinstance(name, str) else ""
    if normalized == "SEG_U8":
        return 1
    if normalized == "SEG_U16":
        return 2
    if normalized == "SEG_U32":
        return 4
    return None


def _runtime_segment_helper_args_8616(node: object) -> tuple[object, object] | None:
    args = _dynamic_angr_attr_8616(node, "args", None)
    if not isinstance(args, (list, tuple)) or len(args) != 2:
        return None
    return args[0], args[1]


def _runtime_segment_address_helper_name_8616(node: object) -> str | None:
    name = _runtime_segment_helper_name_8616(node)
    if isinstance(name, str) and name.upper() in {"MK_FP", "SEG_PTR"}:
        return name.upper()
    return None


def _same_runtime_segment_address_helper_8616(lhs: object, rhs: object) -> bool:
    lhs_name = _runtime_segment_address_helper_name_8616(lhs)
    rhs_name = _runtime_segment_address_helper_name_8616(rhs)
    if lhs_name is None or rhs_name is None:
        return False
    lhs_args = _runtime_segment_helper_args_8616(lhs)
    rhs_args = _runtime_segment_helper_args_8616(rhs)
    if lhs_args is None or rhs_args is None:
        return False
    return _same_c_expression_8616(lhs_args[0], rhs_args[0]) and _same_c_expression_8616(lhs_args[1], rhs_args[1])


def _direct_global_offsets_for_segment_proof_8616(
    project: object,
    codegen: _AngrCodegenBoundary8616,
) -> frozenset[int]:
    offsets: set[int] = set()
    synthetic_globals = _dynamic_angr_attr_8616(codegen, "_inertia_synthetic_globals", None)
    if not isinstance(synthetic_globals, dict):
        synthetic_globals = _dynamic_angr_attr_8616(project, "_inertia_synthetic_globals", None)
    if isinstance(synthetic_globals, dict):
        offsets.update(int(offset) & 0xFFFF for offset in synthetic_globals if isinstance(offset, int))

    try:
        from ..structuring.simple_loop_recovery import _function_instruction_summaries_8616
        from .segmented_global_loads import (
            _collect_direct_global_symbol_refs_8616,
            _collect_synthetic_direct_global_symbol_refs_8616,
            _merge_direct_global_symbol_refs_8616,
        )
    except Exception:
        return frozenset(offsets)

    function = _dynamic_angr_attr_8616(codegen, "_inertia_function", None) or _dynamic_angr_attr_8616(codegen, "_func", None)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    cod_metadata = None
    func_addr = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(codegen, "cfunc", None), "addr", None)
    metadata_by_addr = _dynamic_angr_attr_8616(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if isinstance(func_addr, int) and isinstance(metadata_by_addr, dict):
        cod_metadata = metadata_by_addr.get(func_addr)
    refs = _merge_direct_global_symbol_refs_8616(
        _collect_direct_global_symbol_refs_8616(cod_metadata, summaries),
        _collect_synthetic_direct_global_symbol_refs_8616(synthetic_globals, summaries),
    )
    for ref in refs:
        offset = _dynamic_angr_attr_8616(ref, "offset", None)
        if isinstance(offset, int):
            offsets.add(offset & 0xFFFF)
    return frozenset(offsets)


def _register_segment_expr_8616(
    codegen: _AngrCodegenBoundary8616,
    project: object,
    segment_name: str,
) -> structured_c.CVariable | None:
    registers = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(project, "arch", None), "registers", None)
    reg_info = registers.get(segment_name.lower()) if isinstance(registers, dict) else None
    if not (isinstance(reg_info, tuple) and len(reg_info) >= 2):
        return None
    reg_offset, reg_size = reg_info[0], reg_info[1]
    if not isinstance(reg_offset, int) or not isinstance(reg_size, int):
        return None
    return structured_c.CVariable(
        SimRegisterVariable(reg_offset, reg_size, name=segment_name.lower()),
        codegen=codegen,
        variable_type=SimTypeShort(False),
    )


def _sp_relative_stack_offset_for_segment_proof_8616(
    offset_expr: object,
    project: object,
    codegen: _AngrCodegenBoundary8616,
) -> int | None:
    """Resolve SP-relative offsets only for SS segment proof, not stack variable recovery."""
    old_allow = _dynamic_angr_attr_8616(codegen, "_inertia_allow_runtime_helper_sp_segment_proof_8616", False)
    old_cache = _dynamic_angr_attr_8616(codegen, "_inertia_stack_offset_cache", None)
    before = _dynamic_angr_int_attr_8616(codegen, "_inertia_runtime_helper_sp_segment_proof_count_8616")
    typing.cast(typing.Any, codegen)._inertia_allow_runtime_helper_sp_segment_proof_8616 = True
    typing.cast(typing.Any, codegen)._inertia_stack_offset_cache = {}
    try:
        displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    finally:
        typing.cast(typing.Any, codegen)._inertia_allow_runtime_helper_sp_segment_proof_8616 = old_allow
        if old_cache is None:
            try:
                delattr(codegen, "_inertia_stack_offset_cache")
            except AttributeError:
                pass
        else:
            typing.cast(typing.Any, codegen)._inertia_stack_offset_cache = old_cache
    after = _dynamic_angr_int_attr_8616(codegen, "_inertia_runtime_helper_sp_segment_proof_count_8616")
    if not isinstance(displacement, int) or after <= before:
        return None
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_sp_offset_ss_proof_count_8616")
    return displacement


def _runtime_helper_segment_proof_8616(
    segment_expr: object,
    offset_expr: object,
    width: int,
    *,
    codegen: _AngrCodegenBoundary8616,
    project: object,
    global_offsets: frozenset[int],
) -> tuple[_CarrierKey8616, str | None] | tuple[None, None]:
    terminal_segment = _terminal_carrier_expr_8616(segment_expr, codegen)
    key = _carrier_key_8616(terminal_segment)
    if key is None:
        return None, None

    displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    canonical_displacement = _canonical_stack_offset_8616(displacement)
    if isinstance(canonical_displacement, int) and (
        _has_stack_alias_fact_for_displacement_8616(codegen, canonical_displacement, width)
        or canonical_displacement in _known_bp_stack_offsets_8616(codegen)
    ):
        return key, "SS"

    sp_displacement = _sp_relative_stack_offset_for_segment_proof_8616(offset_expr, project, codegen)
    if isinstance(sp_displacement, int):
        return key, "SS"

    constant_offset = _constant_value_8616(offset_expr)
    if isinstance(constant_offset, int) and (constant_offset & 0xFFFF) in global_offsets:
        return key, "DS"
    return key, None


def materialize_runtime_helper_segment_carriers_8616(
    codegen: object,
    *,
    project: object | None = None,
) -> bool:
    """Materialize proven segment-register carriers in runtime helper calls."""
    typed_codegen = cast(_AngrCodegenBoundary8616, codegen)
    if project is None:
        project = _dynamic_angr_attr_8616(codegen, "project", None)
    root = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    global_offsets = _direct_global_offsets_for_segment_proof_8616(project, typed_codegen)
    carrier_proofs: dict[_CarrierKey8616, str] = {}
    ambiguous: set[_CarrierKey8616] = set()
    candidate_count = 0

    for node in (root, *_iter_c_nodes_deep_8616(root)):
        node = _strip_casts_8616(node)
        helper_name = _runtime_segment_helper_name_8616(node)
        width = _runtime_segment_helper_width_8616(helper_name)
        if width is None:
            continue
        args = _runtime_segment_helper_args_8616(node)
        if args is None:
            continue
        candidate_count += 1
        key, proof = _runtime_helper_segment_proof_8616(
            args[0],
            args[1],
            width,
            codegen=typed_codegen,
            project=project,
            global_offsets=global_offsets,
        )
        if key is None or proof is None:
            continue
        previous = carrier_proofs.get(key)
        if previous is not None and previous != proof:
            ambiguous.add(key)
            carrier_proofs.pop(key, None)
            continue
        if key not in ambiguous:
            carrier_proofs[key] = proof

    changed = False
    materialized_count = 0
    refused_count = 0

    def transform(node: object) -> object:
        nonlocal changed, materialized_count, refused_count
        node = _strip_casts_8616(node)
        helper_name = _runtime_segment_helper_name_8616(node)
        if _runtime_segment_helper_width_8616(helper_name) is None:
            return node
        args = _runtime_segment_helper_args_8616(node)
        if args is None:
            return node
        terminal_segment = _terminal_carrier_expr_8616(args[0], typed_codegen)
        key = _carrier_key_8616(terminal_segment)
        proof = carrier_proofs.get(key) if key is not None and key not in ambiguous else None
        if proof is None:
            refused_count += 1
            return node
        segment_expr = _register_segment_expr_8616(typed_codegen, project, proof)
        if segment_expr is None:
            refused_count += 1
            return node
        changed = True
        materialized_count += 1
        args_list = _dynamic_angr_attr_8616(node, "args", None)
        if isinstance(args_list, list):
            args_list[0] = segment_expr
        return node

    if _replace_c_children_8616(root, transform):
        changed = True
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_segment_carrier_candidate_count_8616", candidate_count)
    _bump_codegen_counter_8616(
        codegen,
        "_inertia_runtime_helper_segment_carrier_materialized_count_8616",
        materialized_count,
    )
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_segment_carrier_refused_count_8616", refused_count)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_segment_carrier_ambiguous_count_8616", len(ambiguous))
    return changed



def _prune_runtime_segment_address_self_assignments_8616(codegen: _AngrCodegenBoundary8616) -> bool:
    """Prune proven identity assignments without requiring an optional body alias."""
    root = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False

    changed = False
    candidates = 0
    pruned = 0
    refused = 0
    seen: set[int] = set()

    def is_prunable(stmt: object) -> bool:
        nonlocal candidates, pruned, refused
        stmt = _strip_casts_8616(stmt)
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _strip_casts_8616(_dynamic_angr_attr_8616(stmt, "lhs", None))
        rhs = _strip_casts_8616(_dynamic_angr_attr_8616(stmt, "rhs", None))
        if _runtime_segment_address_helper_name_8616(lhs) is None:
            return False
        candidates += 1
        if _same_runtime_segment_address_helper_8616(lhs, rhs):
            pruned += 1
            return True
        refused += 1
        return False

    def visit(node: object) -> None:
        nonlocal changed
        node = _strip_casts_8616(node)
        if node is None:
            return
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)

        if isinstance(node, structured_c.CStatements):
            statements = list(_dynamic_angr_sequence_attr_8616(node, "statements"))
            rebuilt = []
            for stmt in statements:
                if is_prunable(stmt):
                    changed = True
                    continue
                visit(stmt)
                rebuilt.append(stmt)
            if len(rebuilt) != len(statements):
                node.statements = rebuilt
            return

        for attr in (
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "initializer",
            "iterator",
            "condition",
            "cond",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "statements",
            "retval",
        ):
            child = _dynamic_angr_attr_8616(node, attr, None)
            if child is not None:
                visit(child)
        for attr in ("args", "operands", "condition_and_nodes"):
            children = _dynamic_angr_attr_8616(node, attr, None)
            if isinstance(children, (list, tuple)):
                for child in children:
                    if isinstance(child, tuple):
                        for item in child:
                            visit(item)
                    else:
                        visit(child)

    visit(root)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_address_self_assign_candidates_8616", candidates)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_address_self_assign_pruned_8616", pruned)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_address_self_assign_refused_8616", refused)
    return changed


def lower_runtime_ss_segment_helper_to_stack_8616(
    node: object,
    *,
    codegen: _AngrCodegenBoundary8616,
    project: object,
) -> object | None:
    """Convert proven SS SEG_U* helper accesses back to stack variables."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    helper_name = _runtime_segment_helper_name_8616(node)
    width = _runtime_segment_helper_width_8616(helper_name)
    if width is None:
        return None
    args = _runtime_segment_helper_args_8616(node)
    if args is None:
        return None
    segment_expr, offset_expr = args
    segment_name = _segment_base_name_8616(segment_expr, project, codegen=codegen)
    if segment_name != "ss":
        return None
    displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    displacement = _canonical_stack_offset_8616(displacement)
    if not isinstance(displacement, int):
        return None
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    if (
        not _has_stack_alias_fact_for_displacement_8616(codegen, displacement, width)
        and displacement not in known_offsets
    ):
        return None
    access = RealModeLinearStackAccess8616(displacement=displacement, width=width)
    return stack_cvar_for_stable_ss_linear_access_8616(codegen, access)


def lower_runtime_ss_segment_helpers_to_stack_8616(
    codegen: object,
    *,
    project: object | None = None,
) -> bool:
    """Convert all proven SS runtime helpers in a function body to stack variables."""
    typed_codegen = cast(_AngrCodegenBoundary8616, codegen)
    if project is None:
        project = typed_codegen.project
    cfunc = typed_codegen.cfunc
    if project is None or cfunc is None:
        return False
    root = cfunc.statements
    if root is None:
        return False

    candidate_count = 0
    materialized_count = 0
    refused_count = 0
    changed = False

    def transform(node: object) -> object:
        nonlocal candidate_count, changed, materialized_count, refused_count
        if not isinstance(_strip_casts_8616(node), structured_c.CFunctionCall):
            return node
        if _runtime_segment_helper_width_8616(_runtime_segment_helper_name_8616(node)) is None:
            return node
        candidate_count += 1
        cvar = lower_runtime_ss_segment_helper_to_stack_8616(node, codegen=typed_codegen, project=project)
        if cvar is None:
            refused_count += 1
            return node
        changed = True
        materialized_count += 1
        return cvar

    new_root = transform(root)
    if new_root is not root:
        _replace_cfunc_statements_root_8616(cfunc, new_root)
        changed = True
    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_ss_helper_candidate_count_8616", candidate_count)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_ss_helper_materialized_count_8616", materialized_count)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_ss_helper_refused_count_8616", refused_count)
    return changed


def apply_runtime_segment_lowering_8616(
    codegen: object,
    *,
    target: str = "portable-flat",
) -> bool:
    """Apply all runtime segmented-memory lowering passes for one generated C function."""
    typed_codegen = cast(_AngrCodegenBoundary8616, codegen)
    cfunc = typed_codegen.cfunc
    project = typed_codegen.project
    if cfunc is None or project is None:
        return False
    root = cfunc.statements
    if root is None:
        return False

    # Offset resolution depends on mutable alias/prototype evidence. A cache
    # populated by an earlier Structuring replay cannot cross this pass boundary.
    typed_codegen._inertia_stack_offset_cache = {}
    active_function = _active_function_for_codegen_8616(typed_codegen)
    facts = _collect_near_pointer_argument_facts_8616(active_function)
    typed_codegen._inertia_near_pointer_argument_facts_8616 = facts
    typed_codegen._inertia_near_pointer_argument_classified_offsets_8616 = set()
    typed_codegen._inertia_near_pointer_argument_materialized_offsets_8616 = set()
    typed_codegen._inertia_near_pointer_argument_refusals_8616 = []
    changed = False

    def transform(node: object) -> object:
        nonlocal changed
        lowered_access = lower_runtime_segment_access_8616(node, target=target)
        if lowered_access is not None:
            changed = True
            return lowered_access
        lowered_addr = lower_runtime_segment_address_8616(node, target=target)
        if lowered_addr is not None:
            changed = True
            return lowered_addr
        return node

    new_root = transform(root)
    if new_root is not root:
        _replace_cfunc_statements_root_8616(cfunc, new_root)
        changed = True
    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True
    if _prune_runtime_segment_address_self_assignments_8616(typed_codegen):
        changed = True
    if materialize_runtime_helper_segment_carriers_8616(codegen, project=project):
        changed = True
    if _lower_binary_proven_pointer_argument_helpers_8616(typed_codegen):
        changed = True
    if lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project):
        changed = True
    classified_count = len(typed_codegen._inertia_near_pointer_argument_classified_offsets_8616)
    materialized_count = len(typed_codegen._inertia_near_pointer_argument_materialized_offsets_8616)
    typed_codegen._inertia_near_pointer_argument_stats_8616 = NearPointerArgumentStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(classified_count - materialized_count, 0),
        refusals=tuple(typed_codegen._inertia_near_pointer_argument_refusals_8616),
    )
    return changed


__all__ = [
    "SegmentedMemoryExpr",
    "apply_runtime_segment_lowering_8616",
    "lower_runtime_segment_access_8616",
    "lower_runtime_segment_address_8616",
    "lower_runtime_ss_segment_helper_to_stack_8616",
    "lower_runtime_ss_segment_helpers_to_stack_8616",
    "materialize_runtime_helper_segment_carriers_8616",
]
