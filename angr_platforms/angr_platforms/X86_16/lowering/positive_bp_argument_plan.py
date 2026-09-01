"""Plan positive-BP arguments without mutating the generated C interface.

Layer: Types/Lowering.
Responsibility: join a body-proven positive-BP argument prefix with one closed
caller-width census before codegen variables or prototypes are changed.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimType

from .callee_argument_width_evidence import CalleeArgumentWidthEvidence8616


class PositiveBpArgumentPlanDecision8616(StrEnum):
    """Typed outcome of joining body storage with incoming argument storage."""

    BODY_ONLY = "body_only"
    BODY_CALLER_PHYSICAL = "body_caller_physical"
    CALLER_COMPLETE = "caller_complete"
    REFUSE = "refuse"


@dataclass(frozen=True, slots=True)
class PositiveBpArgumentPlanEntry8616:
    """One proposed argument slot and its optional existing C variable."""

    bp_offset: int
    width: int
    name: str
    argument_type: SimType
    cvar: CVariable | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class PositiveBpArgumentPlan8616:
    """Mutation-free positive-BP interface decision with retained evidence."""

    decision: PositiveBpArgumentPlanDecision8616
    entries: tuple[PositiveBpArgumentPlanEntry8616, ...]
    evidence: CalleeArgumentWidthEvidence8616 = field(compare=False)


def complete_positive_bp_body_word_access_plan_8616(
    body_entries: tuple[PositiveBpArgumentPlanEntry8616, ...],
    word_access_offsets: Collection[int],
    *,
    default_argument_type: SimType,
) -> tuple[PositiveBpArgumentPlanEntry8616, ...]:
    """Complete one contiguous body plan from exact decoded word accesses.

    Existing typed entries remain authoritative. A missing slot is synthesized
    only when the binary contains an exact word access at the current ABI
    cursor; the first gap ends recovery.
    """
    entries_by_offset = {entry.bp_offset: entry for entry in body_entries}
    accesses = frozenset(offset for offset in word_access_offsets if offset >= 4)
    completed: list[PositiveBpArgumentPlanEntry8616] = []
    cursor = 4
    while cursor in entries_by_offset or cursor in accesses:
        entry = entries_by_offset.get(cursor)
        if entry is None:
            entry = PositiveBpArgumentPlanEntry8616(
                bp_offset=cursor,
                width=2,
                name=f"arg_{cursor:x}",
                argument_type=default_argument_type,
            )
        if entry.width < 2 or entry.width % 2:
            break
        completed.append(entry)
        cursor += entry.width
    return tuple(completed)


def _body_layout_matches_all_physical_calls_8616(
    body_entries: tuple[PositiveBpArgumentPlanEntry8616, ...],
    evidence: CalleeArgumentWidthEvidence8616,
) -> bool:
    """Accept an unknown logical grouping only when every footprint matches."""
    count_evidence = evidence.count_evidence
    if count_evidence is None or count_evidence.raw_fact_count <= 0:
        return False
    summaries = count_evidence.callsite_summaries
    if len(summaries) != count_evidence.raw_fact_count:
        return False
    widths = tuple(entry.width for entry in body_entries)
    return all(
        summary.arg_count == len(widths) and tuple(summary.arg_widths) == widths
        for summary in summaries
    )


def complete_positive_bp_argument_plan_8616(
    body_entries: tuple[PositiveBpArgumentPlanEntry8616, ...],
    evidence: CalleeArgumentWidthEvidence8616,
    *,
    default_argument_type: SimType,
) -> PositiveBpArgumentPlan8616:
    """Complete an exact body prefix from a closed caller-width census.

    No caller facts leaves body-owned recovery unchanged. Once caller facts
    exist, an incomplete or width-inconsistent census refuses the whole plan.
    Unused trailing arguments are materialized only from the exact remaining
    slots in a closed logical-width layout.
    """
    if not body_entries or evidence.raw_fact_count == 0:
        return PositiveBpArgumentPlan8616(
            PositiveBpArgumentPlanDecision8616.BODY_ONLY,
            body_entries,
            evidence,
        )
    if not evidence.closes_census:
        decision = (
            PositiveBpArgumentPlanDecision8616.BODY_CALLER_PHYSICAL
            if _body_layout_matches_all_physical_calls_8616(body_entries, evidence)
            else PositiveBpArgumentPlanDecision8616.REFUSE
        )
        return PositiveBpArgumentPlan8616(
            decision,
            body_entries,
            evidence,
        )

    evidence_layout = evidence.widths_by_offset
    body_layout = tuple((entry.bp_offset, entry.width) for entry in body_entries)
    if len(body_layout) > len(evidence_layout) or body_layout != evidence_layout[: len(body_layout)]:
        return PositiveBpArgumentPlan8616(
            PositiveBpArgumentPlanDecision8616.REFUSE,
            body_entries,
            evidence,
        )

    completed = list(body_entries)
    completed.extend(
        PositiveBpArgumentPlanEntry8616(
            bp_offset=offset,
            width=width,
            name=f"arg_{offset:x}",
            argument_type=default_argument_type,
        )
        for offset, width in evidence_layout[len(body_layout) :]
    )
    return PositiveBpArgumentPlan8616(
        PositiveBpArgumentPlanDecision8616.CALLER_COMPLETE,
        tuple(completed),
        evidence,
    )


__all__ = [
    "PositiveBpArgumentPlan8616",
    "PositiveBpArgumentPlanDecision8616",
    "PositiveBpArgumentPlanEntry8616",
    "complete_positive_bp_argument_plan_8616",
    "complete_positive_bp_body_word_access_plan_8616",
]
