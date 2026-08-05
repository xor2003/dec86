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

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..ir.core import IRValue, MemSpace
from .real_mode_linear import proven_wide_stack_pair_low_offset_8616


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
