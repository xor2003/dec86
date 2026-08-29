"""Lower typed unobserved call-result carriers to standalone calls.

Layer: Types/Lowering.
Responsibility: consume exact callsite return-use evidence and remove only the
register assignment that stores a proven-clobbered call result while retaining
the call and all of its observable effects.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This owner does not infer liveness from rendered C, helper names, source/COD
metadata, or variable names. Unknown or used return classifications are kept.
Stack-probe helpers remain owned by ``fixed_stack_probe_frames`` because their
call itself may become redundant after fixed-frame recovery.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..caller_return_use_contracts import CallsiteReturnUseKind8616
from ..callsite_summary import CallsiteSummary8616
from ..pipeline.errors import PipelineHardError
from .physical_registers import physical_register_view_8616

__all__ = (
    "UnobservedCallResultLoweringStats8616",
    "lower_unobserved_call_result_assignments_8616",
)


class _UnobservedResultCFunction8616(Protocol):
    """Minimal third-party generated C function surface."""

    statements: object


class _UnobservedResultCodegen8616(Protocol):
    """Dynamic angr codegen fields consumed by this lowering owner."""

    cfunc: _UnobservedResultCFunction8616
    _inertia_callsite_summaries: object
    _inertia_unobserved_call_result_lowering_stats_8616: UnobservedCallResultLoweringStats8616


@dataclass(frozen=True, slots=True)
class UnobservedCallResultLoweringStats8616:
    """Closed evidence census for unobserved call-result lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def changed(self) -> bool:
        """Return whether at least one dead result assignment was lowered."""
        return self.materialized_count > 0

    @property
    def closed(self) -> bool:
        """Return whether every classified result was materialized or failed."""
        return bool(
            0 <= self.classified_fact_count <= self.normalized_fact_count <= self.raw_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
        )


def _typed_summary_map_8616(codegen: _UnobservedResultCodegen8616) -> dict[int, CallsiteSummary8616]:
    """Narrow dynamic codegen metadata to owned typed callsite summaries."""
    raw = codegen._inertia_callsite_summaries
    if not isinstance(raw, dict):
        return {}
    return {
        node_id: summary
        for node_id, summary in raw.items()
        if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
    }


def _is_proven_unobserved_ax_result_8616(
    assignment: CAssignment,
    summary: CallsiteSummary8616,
) -> bool:
    """Classify an exact AX-family result assignment from typed binary facts."""
    if summary.stack_probe_helper:
        return False
    if summary.return_used is not False or summary.return_use_kind not in {
        None,
        CallsiteReturnUseKind8616.CLOBBERED,
    }:
        return False
    if summary.return_register not in {None, "ax", "eax"}:
        return False
    view = physical_register_view_8616(assignment.lhs)
    return view is not None and view.reg_offset == 0 and view.width in {2, 4}


def lower_unobserved_call_result_assignments_8616(codegen: object) -> bool:
    """Replace only typed-clobbered AX call assignments with standalone calls."""
    boundary = cast(_UnobservedResultCodegen8616, codegen)
    try:
        root = boundary.cfunc.statements
        summaries = _typed_summary_map_8616(boundary)
    except AttributeError:
        return False

    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    seen_assignments: set[int] = set()
    for container in tuple(
        node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements)
    ):
        statements = list(container.statements or ())
        changed = False
        for index, statement in enumerate(statements):
            if not isinstance(statement, CAssignment) or not isinstance(statement.rhs, CFunctionCall):
                continue
            assignment_id = id(statement)
            if assignment_id in seen_assignments:
                continue
            seen_assignments.add(assignment_id)
            raw_fact_count += 1
            summary = summaries.get(id(statement.rhs))
            if summary is None:
                continue
            normalized_fact_count += 1
            if not _is_proven_unobserved_ax_result_8616(statement, summary):
                continue
            classified_fact_count += 1
            statements[index] = CExpressionStatement(statement.rhs, codegen=statement.codegen)
            materialized_count += 1
            changed = True
        if changed:
            cast(Any, container).statements = statements

    stats = UnobservedCallResultLoweringStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=classified_fact_count - materialized_count,
    )
    if not stats.closed:
        raise PipelineHardError("unobserved call-result lowering evidence accounting is not closed")
    boundary._inertia_unobserved_call_result_lowering_stats_8616 = stats
    return stats.changed
