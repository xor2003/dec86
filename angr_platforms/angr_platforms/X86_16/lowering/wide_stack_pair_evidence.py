"""Prove that typed stack words belong to one widened stack object.

Layer: Types/Lowering.
Responsibility: connect adjacent ``IRValue`` stack slices to the active C stack
object only when alias adjacency or an existing four-byte stack owner proves
that they are one logical value.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not infer widths from names, rendered C, or compiler-specific
instruction shapes.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..ir.core import IRValue, MemSpace
from .real_mode_linear import proven_wide_stack_pair_low_offset_8616


def materialize_proven_wide_stack_pair_variable_8616(
    codegen: object,
    high_expression: object,
    low_expression: object,
    candidate_expression: object,
) -> CVariable | None:
    """Materialize a four-byte stack variable only from a widening proof."""
    low_offset = proven_wide_stack_pair_low_offset_8616(
        high_expression,
        low_expression,
    )
    if low_offset is None or not isinstance(candidate_expression, CVariable):
        return None
    candidate_variable = candidate_expression.variable
    if (
        not isinstance(candidate_variable, SimStackVariable)
        or candidate_variable.offset != low_offset
    ):
        return None
    if candidate_variable.size == 4:
        return candidate_expression
    if candidate_variable.size != 2:
        return None
    return CVariable(
        SimStackVariable(
            low_offset,
            4,
            base=candidate_variable.base,
            base_addr=candidate_variable.base_addr,
            ident=candidate_variable.ident,
            name=candidate_variable.name,
            region=candidate_variable.region,
            category=candidate_variable.category,
        ),
        codegen=codegen,
        tags=candidate_expression.tags,
    )


def _word_projection_source_8616(expression: object, shift: int) -> CVariable | None:
    """Recover one masked word projection of a proven wide stack C variable."""
    if not isinstance(expression, structured_c.CBinaryOp) or expression.op != "And":
        return None
    mask = expression.rhs
    if not isinstance(mask, structured_c.CConstant) or mask.value != 0xFFFF:
        return None
    source = expression.lhs
    if shift:
        if not isinstance(source, structured_c.CBinaryOp) or source.op != "Shr":
            return None
        shift_node = source.rhs
        if not isinstance(shift_node, structured_c.CConstant) or shift_node.value != shift:
            return None
        source = source.lhs
    return source if isinstance(source, CVariable) else None


def _proven_projected_wide_pair_8616(
    high_expression: object,
    low_expression: object,
    low_offset: int,
) -> bool:
    """Accept low/high projections that share one four-byte stack declaration."""
    high_source = _word_projection_source_8616(high_expression, 16)
    low_source = _word_projection_source_8616(low_expression, 0)
    if high_source is None or low_source is None:
        return False
    high_variable = high_source.variable
    low_variable = low_source.variable
    return (
        isinstance(high_variable, SimStackVariable)
        and isinstance(low_variable, SimStackVariable)
        and high_variable == low_variable
        and high_variable.size == 4
        and high_variable.offset == low_offset
    )


def proven_wide_stack_ir_pair_8616(
    high_value: IRValue,
    low_value: IRValue,
    high_expression: object,
    low_expression: object,
) -> bool:
    """Return whether typed IR slices and active stack objects prove a pair."""
    if (
        high_value.space is not MemSpace.SS
        or low_value.space is not MemSpace.SS
        or high_value.name != "bp"
        or low_value.name != "bp"
        or high_value.size != 2
        or low_value.size != 2
        or high_value.offset != low_value.offset + 2
    ):
        return False
    if proven_wide_stack_pair_low_offset_8616(high_expression, low_expression) == low_value.offset:
        return True
    if _proven_projected_wide_pair_8616(
        high_expression,
        low_expression,
        low_value.offset,
    ):
        return True
    if not isinstance(high_expression, CVariable) or not isinstance(low_expression, CVariable):
        return False
    high_variable = high_expression.variable
    low_variable = low_expression.variable
    return (
        isinstance(high_variable, SimStackVariable)
        and isinstance(low_variable, SimStackVariable)
        and high_variable.offset == high_value.offset
        and low_variable.offset == low_value.offset
        and isinstance(low_variable.size, int)
        and low_variable.size >= 4
    )
