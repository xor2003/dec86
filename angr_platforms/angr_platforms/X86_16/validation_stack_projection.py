"""Consume exact stack projection facts during final validation.

Layer: Tail validation.
Responsibility: validate the typed stack-owner/view contract published by
Types/Lowering and expose only contained BP-relative views to validation
consumers. This module does not infer projections from rendered expressions.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .lowering.condition_stack_projection_contracts import (
    ConditionStackProjectionFact8616,
    condition_stack_projection_fact_8616,
)


def validated_stack_projection_fact_8616(
    expression: object,
) -> ConditionStackProjectionFact8616 | None:
    """Return one internally consistent BP-relative projection fact."""
    if not isinstance(expression, structured_c.CExpression):
        return None
    fact = condition_stack_projection_fact_8616(expression)
    if (
        fact is None
        or fact.base != "bp"
        or fact.owner_size <= 0
        or fact.view_size <= 0
        or fact.view_offset < fact.owner_offset
        or fact.view_offset + fact.view_size > fact.owner_offset + fact.owner_size
    ):
        return None
    return fact


__all__ = ["validated_stack_projection_fact_8616"]
