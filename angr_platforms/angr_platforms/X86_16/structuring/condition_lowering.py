"""Lower typed condition/value IR into structured-codegen C AST nodes.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import (
    ConditionIR,
    condition_compare_symbol_8616,
    is_condition_compare_family_8616,
)
from ..ir.core import (
    SEGMENTED_LOAD_ADDRESS_TAG_8616,
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRCondition,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from ..lowering.condition_stack_operands import materialize_typed_condition_stack_operand_8616
from ..lowering.stack_variable_binding import StackVariableBinding, stable_stack_binding_tags_8616
from ..widening.segmented_load_identity import segmented_load_identity_8616
from .indexed_condition_values import materialize_indexed_segmented_condition_value_8616

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CConstant, CExpression

__all__ = [
    "lower_typed_condition_to_c_expr_8616",
    "lower_ir_value_to_c_expr_8616",
    "condition_op_to_structured_kind_8616",
    "condition_origin_tags_8616",
    "condition_segment_access_tags_8616",
    "attach_condition_segment_access_provenance_8616",
    "materialize_indexed_segmented_condition_value_8616",
    "materialize_typed_condition_stack_operand_8616",
    "stable_stack_condition_binding_tags_8616",
]

_SOURCE_INSTRUCTION_ADDRS_TAG_8616 = "inertia_source_instruction_addrs"


def _make_c_constant_8616(value: int, codegen: object, signed: bool = False) -> "CConstant":
    """Create a structured-codegen CConstant node."""
    from angr.analyses.decompiler.structured_codegen.c import CConstant
    from angr.sim_type import SimTypeShort

    return CConstant(int(value), SimTypeShort(signed), codegen=codegen)


def _register_offset_size_for_value_8616(value: IRValue, project: object) -> tuple[int, int]:
    """Read register metadata through the dynamic third-party angr project boundary."""
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", {}) if arch is not None else {}
    if isinstance(value.name, str) and value.name in registers:
        reg_offset, reg_size = registers[value.name]
        return int(reg_offset), int(value.size or reg_size or 2)
    return int(value.offset), int(value.size or 2)


def lower_ir_value_to_c_expr_8616(
    value: IRValue,
    project: object,
    codegen: object,
    *,
    resolve_register_name: bool = False,
) -> object | None:
    """Convert typed IR value evidence into a structured-codegen C expression."""
    return _ir_value_to_cvar_8616(value, project, codegen, resolve_register_name=resolve_register_name)


def stable_stack_condition_binding_tags_8616(
    bp_offset: int,
    size: int,
    *,
    name: str | None = None,
) -> dict[str, object]:
    """Return exact stack-slot tags for one proven ConditionIR operand."""
    binding = StackVariableBinding(bp_offset, size, var_name=name)
    return stable_stack_binding_tags_8616(binding)


def condition_origin_tags_8616(condition: ConditionIR | IRCondition) -> dict[str, object]:
    """Return C-AST provenance tags for a typed branch condition."""
    tags: dict[str, object] = {"typed_condition": True}
    if not isinstance(condition, ConditionIR):
        return tags
    src_insn = condition.src_insn
    block_addr = condition.block_addr
    producer_insn = condition.producer_insn
    if isinstance(src_insn, int) and isinstance(block_addr, int):
        tags["ins_addr"] = src_insn
        tags["vex_block_addr"] = block_addr
    if isinstance(producer_insn, int):
        tags["condition_producer_insn"] = producer_insn
    return tags


def condition_segment_access_tags_8616(
    operand: IRValue,
    helper: str,
) -> dict[str, object]:
    """Return typed tags for a segment access already proven by ConditionIR."""
    if operand.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}:
        raise ValueError("condition segment access requires a segmented IRValue")
    width = max(1, int(operand.memory_access_size or operand.size or 2))
    tags: dict[str, object] = {
        "inertia_x86_16_runtime_segment_helper": helper,
        SEGMENTED_LOAD_ADDRESS_TAG_8616: IRAddress(
            space=operand.space,
            offset=int(operand.offset) & 0xFFFF,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    }
    if isinstance(operand.memory_access_insn, int):
        tags[_SOURCE_INSTRUCTION_ADDRS_TAG_8616] = (operand.memory_access_insn,)
    return tags


def _condition_segment_accesses_8616(
    value: object,
) -> tuple[IRValue, ...]:
    """Return segmented leaves carrying exact access provenance."""
    if isinstance(value, IRBinaryValue):
        return (
            *_condition_segment_accesses_8616(value.lhs),
            *_condition_segment_accesses_8616(value.rhs),
        )
    if (
        isinstance(value, IRValue)
        and value.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        and isinstance(value.memory_access_insn, int)
    ):
        return (value,)
    return ()


def attach_condition_segment_access_provenance_8616(
    expression: "CExpression",
    condition: ConditionIR,
) -> int:
    """Carry exact operand access provenance onto matching segment helpers.

    The condition producer defines flags and is not necessarily a memory load.
    This boundary therefore matches typed operand addresses and refuses absent
    or ambiguous access evidence instead of borrowing CMP/JCC provenance.
    """
    from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

    sources_by_access: dict[tuple[MemSpace, int, int], set[int]] = {}
    for operand in (
        *_condition_segment_accesses_8616(condition.lhs),
        *_condition_segment_accesses_8616(condition.rhs),
    ):
        key = (
            operand.space,
            int(operand.offset) & 0xFFFF,
            max(1, int(operand.memory_access_size or operand.size or 2)),
        )
        sources_by_access.setdefault(key, set()).add(cast(int, operand.memory_access_insn))

    tagged_count = 0
    for candidate in _iter_c_nodes_deep_8616(expression):
        if not isinstance(candidate, CFunctionCall):
            continue
        boundary = cast(Any, candidate)  # mutable tags are an angr C-AST boundary
        tags = boundary.tags
        identity = segmented_load_identity_8616(candidate)
        if not isinstance(tags, dict) or identity is None:
            continue
        sources = sources_by_access.get(
            (identity.space, identity.offset, identity.width),
            set(),
        )
        if len(sources) != 1:
            continue
        exact_sources = tuple(sorted(sources))
        if tags.get(_SOURCE_INSTRUCTION_ADDRS_TAG_8616) == exact_sources:
            continue
        updated_tags = dict(tags)
        updated_tags[_SOURCE_INSTRUCTION_ADDRS_TAG_8616] = exact_sources
        boundary.tags = updated_tags
        tagged_count += 1
    return tagged_count


def _ir_value_to_cvar_8616(
    value: IRValue,
    project: object,
    codegen: object,
    *,
    resolve_register_name: bool = False,
) -> object:
    """Convert an IRValue to a CVariable node for structured codegen."""
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable, SimStackVariable

    if value.space == MemSpace.CONST:
        return _make_c_constant_8616(int(value.const or 0), codegen)

    if value.space == MemSpace.REG:
        if resolve_register_name:
            reg_offset, reg_size = _register_offset_size_for_value_8616(value, project)
            var = SimRegisterVariable(reg_offset, reg_size, name=value.name)
        else:
            reg_offset, reg_size = int(value.offset), int(value.size or 2)
            var = SimRegisterVariable(reg_offset, reg_size)
        return CVariable(variable=var, codegen=codegen)

    if value.space == MemSpace.SS:
        var = SimStackVariable(offset=value.offset, size=value.size or 2, base="bp")
        tags = stable_stack_condition_binding_tags_8616(int(value.offset), int(value.size or 2))
        return CVariable(variable=var, codegen=codegen, tags=tags)

    # Fallback: unnamed register variable
    var = SimRegisterVariable(0, value.size or 2)
    return CVariable(variable=var, codegen=codegen)


def lower_typed_condition_to_c_expr_8616(
    recovered: object,  # RecoveredCondition
    project: object,
    codegen: object,
) -> object | None:
    """Convert a RecoveredCondition into a structured-codegen C expression node.

    Returns a CBinaryOp (for comparisons) or CUnaryOp (for Not) node, or None.
    """
    from ..semantics.condition_recovery import RecoveredCondition

    if not isinstance(recovered, RecoveredCondition):
        return None

    condition = recovered.condition
    return _lower_condition_ir_to_c_expr_8616(condition, project, codegen)


def _lower_condition_ir_to_c_expr_8616(
    condition: IRCondition,
    project: object,
    codegen: object,
) -> object | None:
    def _impl() -> object | None:
        """Lower a typed IRCondition to a structured-codegen C expression."""
        from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CUnaryOp

        op = condition.op

        # Zero/nonzero tests
        if op == "zero":
            if not condition.args or not isinstance(condition.args[0], IRValue):
                return None
            lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
            zero = _make_c_constant_8616(0, codegen)
            return CBinaryOp("CmpEQ", lhs, zero, codegen=codegen, tags=condition_origin_tags_8616(condition))

        if op == "nonzero":
            if not condition.args or not isinstance(condition.args[0], IRValue):
                return None
            lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
            zero = _make_c_constant_8616(0, codegen)
            return CBinaryOp("CmpNE", lhs, zero, codegen=codegen, tags=condition_origin_tags_8616(condition))

        # Binary comparisons
        if (
            is_condition_compare_family_8616(op)
            and len(condition.args) >= 2
            and isinstance(condition.args[0], IRValue)
            and isinstance(condition.args[1], IRValue)
        ):
            sym = condition_compare_symbol_8616(op)
            if sym is None:
                return None
            lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
            rhs = _ir_value_to_cvar_8616(condition.args[1], project, codegen)
            # Map to angr structured-codegen CBinaryOp operator names
            angr_op = _condition_ir_op_to_angr_binary_op_8616(sym)
            if angr_op is None:
                return None
            return CBinaryOp(angr_op, lhs, rhs, codegen=codegen, tags=condition_origin_tags_8616(condition))

        # Not
        if op == "not" and len(condition.args) >= 1:
            inner = condition.args[0]
            if isinstance(inner, IRCondition):
                inner_expr = _lower_condition_ir_to_c_expr_8616(inner, project, codegen)
                if inner_expr is not None:
                    return CUnaryOp(
                        "Not",
                        cast("CExpression", inner_expr),
                        codegen=codegen,
                        tags=condition_origin_tags_8616(condition),
                    )
            return None

        # Compare (generic)
        if (
            op == "compare"
            and len(condition.args) >= 2
            and isinstance(condition.args[0], IRValue)
            and isinstance(condition.args[1], IRValue)
        ):
            lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
            rhs = _ir_value_to_cvar_8616(condition.args[1], project, codegen)
            return CBinaryOp("CmpNE", lhs, rhs, codegen=codegen, tags=condition_origin_tags_8616(condition))

        return None

    return _impl()


def condition_op_to_structured_kind_8616(op: str) -> str:
    """Map a ConditionOp to the kind string used in structured-codegen node kinds."""
    if op == "zero":
        return "CmpEQ"
    if op == "nonzero":
        return "CmpNE"
    if op in {"eq", "ne"}:
        return f"Cmp{op.upper()}"
    if op in {"slt", "ult"}:
        return "CmpLT"
    if op in {"sgt", "ugt"}:
        return "CmpGT"
    if op in {"sle", "ule"}:
        return "CmpLE"
    if op in {"sge", "uge"}:
        return "CmpGE"
    return "CmpNE"


_ANGr_BINARY_OP_MAP_8616: dict[str, str] = {
    "==": "CmpEQ",
    "!=": "CmpNE",
    "<": "CmpLT",
    ">": "CmpGT",
    "<=": "CmpLE",
    ">=": "CmpGE",
}


def _condition_ir_op_to_angr_binary_op_8616(symbol: str) -> str | None:
    """Map a condition op symbol ('==', '!=' etc.) to angr CBinaryOp operator name."""
    return _ANGr_BINARY_OP_MAP_8616.get(symbol)
