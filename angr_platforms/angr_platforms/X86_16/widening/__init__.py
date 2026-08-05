"""Widening-layer exports.

Layer: Widening.
Responsibility: owns exports for alias-proven widening helpers.
Consumes alias-proven storage identity before joining values or propagating
widths.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from .register_widening import (
    RegisterWideningCandidate,
    can_join_adjacent_register_slices,
    join_adjacent_register_slices,
)
from .stack_subview_projection import (
    materialize_contained_stack_subviews_8616,
)
from .stack_widening import (
    WIDENING_PIPELINE,
    StorageJoinAnalysis,
    StorageSubviewProof,
    WideningCandidate,
    WideningPipelineSpec,
    WideningProof,
    analyze_adjacent_storage_slices,
    can_join_adjacent_storage_slices,
    collect_widening_candidates,
    describe_widening_candidates,
    describe_x86_16_widening_pipeline,
    merge_storage_slice_domains,
    prove_adjacent_storage_slices,
    prove_contained_stack_subview,
)
from .widening_rules import (
    collect_bp_stack_access_widths_from_instructions_8616,
    promote_stack_slots_from_instruction_widths_8616,
    run_typed_widening_pass_8616,
)
from .word_projection_recomposition import (
    WordProjectionRecompositionStats8616,
    materialize_word_projection_recompositions_8616,
)

__all__ = [
    "RegisterWideningCandidate",
    "StorageJoinAnalysis",
    "StorageSubviewProof",
    "WIDENING_PIPELINE",
    "WideningCandidate",
    "WideningPipelineSpec",
    "WideningProof",
    "WordProjectionRecompositionStats8616",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_register_slices",
    "can_join_adjacent_storage_slices",
    "collect_bp_stack_access_widths_from_instructions_8616",
    "collect_widening_candidates",
    "describe_widening_candidates",
    "describe_x86_16_widening_pipeline",
    "join_adjacent_register_slices",
    "merge_storage_slice_domains",
    "materialize_contained_stack_subviews_8616",
    "materialize_word_projection_recompositions_8616",
    "promote_stack_slots_from_instruction_widths_8616",
    "prove_adjacent_storage_slices",
    "prove_contained_stack_subview",
    "run_typed_widening_pass_8616",
]
