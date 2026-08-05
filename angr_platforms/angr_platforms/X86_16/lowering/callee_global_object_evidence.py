"""Classify caller pointer sources against proven global object layouts.

Layer: Types/Lowering.
Responsibility: join structured direct-call argument sources with Widening-owned
global object layouts and publish a closed-census aggregate-pointee decision.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not mutate codegen state.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Sequence

from ..callsite_summary import CallsiteSummary8616
from ..widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)


class CalleeGlobalObjectInterfaceVerdict8616(StrEnum):
    """Typed completeness state for aggregate-pointee interface evidence."""

    UNKNOWN = "unknown"
    COMPLETE = "complete"
    ANCHORED_WITH_UNKNOWN_CALLERS = "anchored_with_unknown_callers"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class AffineGlobalPointerSource8616:
    """Normalized near-pointer source with its nonconstant index identity."""

    base_offset: int
    index_identity: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class CalleeGlobalObjectInterfaceEvidence8616:
    """Closed census for one aggregate-pointee callee interface decision."""

    target_addr: int
    verdict: CalleeGlobalObjectInterfaceVerdict8616
    family_base_offset: int | None
    pointer_argument_indices: tuple[int, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    callsite_addrs: tuple[int, ...]
    source_facts: tuple[CalleeGlobalObjectSourceFamilyFact8616, ...]


@dataclass(frozen=True, slots=True)
class CalleeGlobalObjectSourceFamilyFact8616:
    """One normalized call argument proven to belong to an object family."""

    target_addr: int
    callsite_addr: int
    argument_index: int
    base_offset: int
    canonical_base_offset: int
    index_identity: tuple[object, ...]
    family_base_offset: int
    element_width: int
    field_offsets: tuple[int, ...]


def _affine_global_pointer_source_8616(
    source: object,
) -> AffineGlobalPointerSource8616 | None:
    """Normalize one structured callsite push source without text parsing."""
    if not isinstance(source, tuple) or len(source) < 2:
        return None
    if source[0] == "imm" and len(source) == 2 and isinstance(source[1], int):
        return AffineGlobalPointerSource8616(source[1] & 0xFFFF, ("constant",))
    if source[0] != "expr" or len(source) != 3:
        return None
    origin = source[1]
    operations = source[2]
    if not isinstance(origin, tuple) or not isinstance(operations, tuple):
        return None
    additive = tuple(
        operation
        for operation in operations
        if isinstance(operation, tuple)
        and len(operation) == 2
        and operation[0] == "add"
        and isinstance(operation[1], int)
    )
    if len(additive) != 1:
        return None
    index_operations = tuple(
        operation for operation in operations if operation is not additive[0]
    )
    return AffineGlobalPointerSource8616(
        additive[0][1] & 0xFFFF,
        (origin, *index_operations),
    )


def _classify_summary_sources_8616(
    sources: tuple[AffineGlobalPointerSource8616 | None, ...],
    layouts_by_base: dict[int, GlobalObjectLayout8616],
) -> tuple[int | None, tuple[GlobalObjectLayout8616 | None, ...]]:
    """Classify exact or one-element-adjacent sources within one callsite."""
    source_layouts: list[GlobalObjectLayout8616 | None] = [
        None
        if source is None or source.base_offset not in layouts_by_base
        else layouts_by_base[source.base_offset]
        for source in sources
    ]
    changed = True
    while changed:
        changed = False
        for index, source in enumerate(sources):
            if source is None or source_layouts[index] is not None:
                continue
            for anchor_index, anchor in enumerate(sources):
                anchor_layout = source_layouts[anchor_index]
                if anchor is None or anchor_layout is None:
                    continue
                if (
                    source.index_identity == anchor.index_identity
                    and abs(source.base_offset - anchor.base_offset)
                    == anchor_layout.element_width
                ):
                    source_layouts[index] = anchor_layout
                    changed = True
                    break
    distinct = {
        layout.family_base_offset for layout in source_layouts if layout is not None
    }
    family = next(iter(distinct)) if len(distinct) == 1 else None
    return family, tuple(source_layouts)


def recover_callee_global_object_interface_evidence_8616(
    target_addr: int,
    summaries: Sequence[CallsiteSummary8616],
    layout_evidence: GlobalObjectLayoutEvidence8616,
    pointer_argument_indices: tuple[int, ...],
) -> CalleeGlobalObjectInterfaceEvidence8616:
    """Join all direct caller sources to one proven aggregate family."""
    raw_count = sum(len(summary.push_arg_sources) for summary in summaries)
    normalized_count = 0
    classified_source_count = 0
    families: set[int] = set()
    invalid_callsites = 0
    classified_summaries: list[
        tuple[
            CallsiteSummary8616,
            tuple[AffineGlobalPointerSource8616 | None, ...],
            tuple[GlobalObjectLayout8616 | None, ...],
        ]
    ] = []
    layouts_by_base = {
        layout.address.offset & 0xFFFF: layout for layout in layout_evidence.layouts
    }
    expected_arg_count = len(pointer_argument_indices)
    for summary in summaries:
        sources = tuple(
            _affine_global_pointer_source_8616(source)
            for source in summary.push_arg_sources
        )
        normalized_count += sum(source is not None for source in sources)
        family, source_layouts = _classify_summary_sources_8616(
            sources,
            layouts_by_base,
        )
        classified = sum(layout is not None for layout in source_layouts)
        classified_source_count += classified
        if (
            expected_arg_count == 0
            or len(sources) != expected_arg_count
            or family is None
            or classified != len(sources)
        ):
            invalid_callsites += 1
            continue
        families.add(family)
        classified_summaries.append((summary, sources, source_layouts))
    complete = (
        bool(summaries)
        and invalid_callsites == 0
        and normalized_count == raw_count
        and classified_source_count == raw_count
        and len(families) == 1
    )
    anchored = bool(classified_summaries) and len(families) == 1
    if len(families) > 1:
        verdict = CalleeGlobalObjectInterfaceVerdict8616.CONFLICT
    elif complete:
        verdict = CalleeGlobalObjectInterfaceVerdict8616.COMPLETE
    elif anchored:
        verdict = (
            CalleeGlobalObjectInterfaceVerdict8616.ANCHORED_WITH_UNKNOWN_CALLERS
        )
    else:
        verdict = CalleeGlobalObjectInterfaceVerdict8616.UNKNOWN
    family_base_offset = next(iter(families)) if anchored else None
    classified_count = expected_arg_count if anchored else 0
    source_facts = (
        tuple(
            CalleeGlobalObjectSourceFamilyFact8616(
                target_addr=target_addr,
                callsite_addr=summary.callsite_addr,
                argument_index=pointer_argument_indices[source_index],
                base_offset=source.base_offset,
                canonical_base_offset=layout.address.offset & 0xFFFF,
                index_identity=source.index_identity,
                family_base_offset=layout.family_base_offset,
                element_width=layout.element_width,
                field_offsets=layout.field_offsets,
            )
            for summary, sources, source_layouts in classified_summaries
            for source_index, (source, layout) in enumerate(
                zip(sources, source_layouts, strict=True)
            )
            if source is not None and layout is not None
        )
        if anchored
        else ()
    )
    return CalleeGlobalObjectInterfaceEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        family_base_offset=family_base_offset,
        pointer_argument_indices=pointer_argument_indices if anchored else (),
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=0,
        failure_count=(raw_count - classified_source_count)
        + invalid_callsites
        + int(len(families) > 1),
        callsite_addrs=tuple(sorted(summary.callsite_addr for summary in summaries)),
        source_facts=source_facts,
    )


__all__ = [
    "AffineGlobalPointerSource8616",
    "CalleeGlobalObjectInterfaceEvidence8616",
    "CalleeGlobalObjectInterfaceVerdict8616",
    "CalleeGlobalObjectSourceFamilyFact8616",
    "recover_callee_global_object_interface_evidence_8616",
]
