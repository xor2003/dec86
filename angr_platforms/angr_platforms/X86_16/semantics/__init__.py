"""Semantics-layer package exports.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .call_output_contracts import (
    CallOutputFact8616,
    CallOutputFailure8616,
    CallOutputShape8616,
    CallOutputStats8616,
    CallOutputVerdict8616,
)
from .call_outputs import CallOutputArtifact8616, materialize_call_outputs_8616
from .call_stack_effect_contracts import (
    CallStackEffectFact8616,
    CallStackEffectFailure8616,
    CallStackEffectStats8616,
    CallStackEffectVerdict8616,
)
from .call_stack_effect_pipeline import (
    apply_x86_16_call_stack_effects_8616,
    build_semantic_function_ssa_8616,
)
from .call_stack_effects import (
    CallStackEffectArtifact8616,
    materialize_call_stack_effects_8616,
)
from .carry_borrow_contracts import (
    CarryBorrowEvidence8616,
    CarryBorrowFailure8616,
    CarryBorrowKind8616,
    CarryBorrowLink8616,
    CarryBorrowVerdict8616,
)
from .carry_borrow_links import analyze_carry_borrow_links_8616

__all__ = [
    "CallOutputArtifact8616",
    "CallOutputFact8616",
    "CallOutputFailure8616",
    "CallOutputShape8616",
    "CallOutputStats8616",
    "CallOutputVerdict8616",
    "CallStackEffectArtifact8616",
    "CallStackEffectFact8616",
    "CallStackEffectFailure8616",
    "CallStackEffectStats8616",
    "CallStackEffectVerdict8616",
    "CarryBorrowEvidence8616",
    "CarryBorrowFailure8616",
    "CarryBorrowKind8616",
    "CarryBorrowLink8616",
    "CarryBorrowVerdict8616",
    "apply_x86_16_call_stack_effects_8616",
    "analyze_carry_borrow_links_8616",
    "build_semantic_function_ssa_8616",
    "materialize_call_outputs_8616",
    "materialize_call_stack_effects_8616",
]
