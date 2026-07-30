"""Materialize alias-proven redundant stack subview recompositions.

Layer: Widening.
Responsibility: remove byte recompositions only after Alias proves that the
wider stack operand already contains the projected byte view.
Consumes alias-proven storage identity before materializing contained views.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

This pass consumes structured C AST shape as a materialization target, not as
semantic evidence. It refuses unknown storage, cross-region views, wrong
projection offsets or scales, and assignment lvalues. Do not move this work to
postprocess or infer it from rendered C or assembly text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _clone_c_ast_tree_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError
from .stack_widening import prove_contained_stack_subview


@dataclass(slots=True)
class StackSubviewProjectionStats8616:
    """Closed evidence counters for contained stack-subview materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class _StackSubviewCandidate8616:
    """One syntax-normalized stack subview recomposition candidate."""

    container: structured_c.CVariable
    subview: structured_c.CVariable
    projection_bits: int | None


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read optional third-party codegen state at the dynamic AST boundary."""
    return getattr(obj, name, default)


def _unwrap_casts_8616(node: object) -> object:
    """Remove syntax-only C casts while matching a structured expression."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_int_8616(node: object) -> int | None:
    """Return an integer C constant value without parsing rendered text."""
    node = _unwrap_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _projection_candidate_8616(node: object) -> tuple[structured_c.CVariable, int | None] | None:
    """Match a byte projection multiplied or shifted into a wider value."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    if node.op == "Shl":
        subview = _unwrap_casts_8616(node.lhs)
        shift = _constant_int_8616(node.rhs)
        if isinstance(subview, structured_c.CVariable) and shift is not None:
            return subview, shift
        return None
    if node.op != "Mul":
        return None
    for subview_node, scale_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        subview = _unwrap_casts_8616(subview_node)
        scale = _constant_int_8616(scale_node)
        if not isinstance(subview, structured_c.CVariable) or scale is None:
            continue
        projection_bits = scale.bit_length() - 1 if scale > 0 and scale & (scale - 1) == 0 else None
        return subview, projection_bits
    return None


def _stack_subview_candidate_8616(node: object) -> _StackSubviewCandidate8616 | None:
    """Match an OR recomposition with one direct container and one projected view."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    for container_node, projection_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        container = _unwrap_casts_8616(container_node)
        projection = _projection_candidate_8616(projection_node)
        if isinstance(container, structured_c.CVariable) and projection is not None:
            subview, projection_bits = projection
            return _StackSubviewCandidate8616(container, subview, projection_bits)
    return None


def _increment_codegen_counter_8616(codegen: object, name: str, amount: int) -> None:
    """Accumulate evidence on the dynamic third-party codegen boundary."""
    current = _dynamic_attr_8616(codegen, name, 0)
    current_value = current if isinstance(current, int) else 0
    setattr(cast(Any, codegen), name, current_value + amount)


def materialize_contained_stack_subviews_8616(codegen: object) -> bool:
    """Fold redundant high-byte recomposition after a strict Alias proof."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    root = _dynamic_attr_8616(cfunc, "statements", None)
    if root is None:
        return False

    stats = StackSubviewProjectionStats8616()

    def transform(node: object) -> object:
        """Materialize one proven contained stack view."""
        candidate = _stack_subview_candidate_8616(node)
        if candidate is None:
            return node
        stats.raw_fact_count += 1
        if candidate.projection_bits != 8:
            stats.failure_count += 1
            return node
        stats.normalized_fact_count += 1
        proof = prove_contained_stack_subview(
            candidate.container,
            candidate.subview,
            expected_bit_offset=8,
        )
        if not proof.ok:
            stats.failure_count += 1
            return node
        stats.classified_fact_count += 1
        stats.materialized_count += 1
        return _clone_c_ast_tree_8616(candidate.container)

    def should_process_child(parent: object, attr: str) -> bool:
        """Keep assignment lvalues outside this rvalue materialization pass."""
        return not (isinstance(parent, structured_c.CAssignment) and attr == "lhs")

    changed = _replace_c_children_8616(root, transform, should_process_child=should_process_child)
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_raw_fact_count",
        stats.raw_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_normalized_fact_count",
        stats.normalized_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_classified_fact_count",
        stats.classified_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_materialized_count",
        stats.materialized_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_failure_count",
        stats.failure_count,
    )
    cast(Any, codegen)._inertia_stack_subview_last_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified contained stack subview was not materialized",
            layer="widening",
        )
    return bool(changed and stats.materialized_count > 0)


__all__ = [
    "StackSubviewProjectionStats8616",
    "materialize_contained_stack_subviews_8616",
]
