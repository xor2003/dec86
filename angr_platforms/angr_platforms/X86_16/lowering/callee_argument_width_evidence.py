"""Aggregate exact incoming call widths for one callee interface.

Layer: Types/Lowering.
Responsibility: project complete binary caller PUSH summaries onto positive-BP
callee argument offsets and publish one closed width verdict.
Consumes alias, widening, and typed facts from complete callsite summaries.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..callsite_summary import CallsiteSummary8616, logical_argument_widths_from_callsite_8616
from .callee_argument_count_evidence import (
    CalleeArgumentCountVerdict8616,
    collect_callee_argument_count_evidence_8616,
)

__all__ = [
    "CalleeArgumentWidthEvidence8616",
    "CalleeArgumentWidthVerdict8616",
    "collect_callee_argument_width_evidence_8616",
]


class CalleeArgumentWidthVerdict8616(StrEnum):
    """Typed outcome of joining incoming logical argument widths."""

    UNKNOWN = "unknown"
    CONSISTENT = "consistent"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class CalleeArgumentWidthEvidence8616:
    """Closed incoming-width evidence mapped to architectural BP offsets."""

    target_addr: int
    verdict: CalleeArgumentWidthVerdict8616
    widths_by_offset: tuple[tuple[int, int], ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _widths_by_offset_8616(widths: tuple[int, ...]) -> tuple[tuple[int, int], ...]:
    """Map source-order near-call argument widths onto BP+4 storage."""
    offset = 4
    mapped: list[tuple[int, int]] = []
    for width in widths:
        mapped.append((offset, width))
        offset += width
    return tuple(mapped)


def _logical_widths_for_proven_count_8616(
    summary: CallsiteSummary8616,
    argument_count: int,
) -> tuple[int, ...] | None:
    """Project widths after arity proof without requiring value provenance."""
    widths: tuple[int, ...] | None = logical_argument_widths_from_callsite_8616(
        summary,
        expected_arg_count=argument_count,
    )
    if widths is not None:
        return widths
    physical_widths = summary.arg_widths
    if (
        len(physical_widths) != argument_count
        or summary.stack_cleanup != sum(physical_widths)
        or any(not isinstance(width, int) or width <= 0 for width in physical_widths)
    ):
        return None
    return tuple(reversed(physical_widths))


def collect_callee_argument_width_evidence_8616(
    project: object,
    target_addr: int,
) -> CalleeArgumentWidthEvidence8616:
    """Join exact logical widths from every completely classified caller."""
    count_evidence = collect_callee_argument_count_evidence_8616(project, target_addr)
    summaries = count_evidence.callsite_summaries
    raw_count = len(summaries)
    if (
        count_evidence.verdict is not CalleeArgumentCountVerdict8616.CONSISTENT
        or not isinstance(count_evidence.argument_count, int)
        or count_evidence.argument_count <= 0
    ):
        return CalleeArgumentWidthEvidence8616(
            target_addr=target_addr,
            verdict=CalleeArgumentWidthVerdict8616.UNKNOWN,
            raw_fact_count=raw_count,
            failure_count=raw_count,
        )
    classified_widths = tuple(
        widths
        for summary in summaries
        if (
            widths := _logical_widths_for_proven_count_8616(
                summary,
                count_evidence.argument_count,
            )
        )
        is not None
    )
    distinct_widths = set(classified_widths)
    failure_count = raw_count - len(classified_widths)
    if len(distinct_widths) == 1 and failure_count == 0:
        widths = next(iter(distinct_widths))
        verdict = CalleeArgumentWidthVerdict8616.CONSISTENT
        mapped_widths = _widths_by_offset_8616(widths)
        materialized_count = len(classified_widths)
    elif len(distinct_widths) > 1:
        verdict = CalleeArgumentWidthVerdict8616.CONFLICT
        mapped_widths = ()
        materialized_count = 0
        failure_count += 1
    else:
        verdict = CalleeArgumentWidthVerdict8616.UNKNOWN
        mapped_widths = ()
        materialized_count = 0
    return CalleeArgumentWidthEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        widths_by_offset=mapped_widths,
        raw_fact_count=raw_count,
        normalized_fact_count=len(classified_widths),
        classified_fact_count=len(classified_widths),
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
