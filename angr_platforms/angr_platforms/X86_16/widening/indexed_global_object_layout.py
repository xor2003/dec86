"""Widen project object layouts from indexed-address Alias evidence.

Layer: Widening.
Responsibility: join exact global-indexed Alias byte/word views into bounded
element layouts and connect only those layouts related by an Alias-proven
whole-value copy. Every unused or upstream input remains a typed refusal.
Consumes alias-proven storage identity before joining values or propagating widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from ..alias.indexed_address_access_contracts import (
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRefusal8616,
    IndexedAliasAccessRole8616,
)
from ..alias.indexed_address_copy_contracts import (
    IndexedAliasCopyFact8616,
    IndexedAliasCopyRefusal8616,
)
from ..alias.indexed_address_program import IndexedAliasProgramEvidence8616
from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
    GlobalObjectLayoutFailureKind8616,
    GlobalObjectLayoutRefusal8616,
)


def recover_global_object_layout_evidence_8616(
    program: IndexedAliasProgramEvidence8616,
) -> GlobalObjectLayoutEvidence8616:
    """Join exact global-indexed Alias views and whole-value copy relations."""
    if not program.closed:
        raise ValueError("global-object Widening requires closed Alias program evidence")
    access_input_list: list[
        tuple[int, IndexedAliasAccessFact8616 | IndexedAliasAccessRefusal8616]
    ] = []
    copy_input_list: list[
        tuple[int, IndexedAliasCopyFact8616 | IndexedAliasCopyRefusal8616]
    ] = []
    for function in program.functions:
        access_input_list.extend(
            (function.function_addr, fact) for fact in function.accesses.facts
        )
        access_input_list.extend(
            (function.function_addr, refusal)
            for refusal in function.accesses.refusals
        )
        copy_input_list.extend(
            (function.function_addr, fact) for fact in function.copies.facts
        )
        copy_input_list.extend(
            (function.function_addr, refusal)
            for refusal in function.copies.refusals
        )
    access_inputs = tuple(access_input_list)
    copy_inputs = tuple(copy_input_list)
    global_accesses = tuple(
        (function_addr, fact)
        for function_addr, fact in access_inputs
        if isinstance(fact, IndexedAliasAccessFact8616)
        and fact.role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
    )
    word_bases = {
        fact.source.storage.base_offset
        for _function_addr, fact in global_accesses
        if fact.source.storage.space is MemSpace.DS
        and fact.source.storage.width == 2
        and fact.source.storage.index_shift == 1
    }
    byte_groups: dict[tuple[int, object, int], set[int]] = {}
    for function_addr, fact in global_accesses:
        storage = fact.source.storage
        if storage.space is not MemSpace.DS or storage.width != 1 or storage.index_shift != 1:
            continue
        key = (
            function_addr,
            storage.index_source_range.storage.identity,
            storage.index_shift,
        )
        byte_groups.setdefault(key, set()).add(storage.base_offset)
    candidate_bases = (
        {
            base
            for bases in byte_groups.values()
            for base in bases
            if base in word_bases and ((base + 1) & 0xFFFF) in bases
        }
        if not program.refusals
        else set()
    )
    accepted_copies = tuple(
        (function_addr, fact)
        for function_addr, fact in copy_inputs
        if isinstance(fact, IndexedAliasCopyFact8616)
        and fact.source.storage.space is MemSpace.DS
        and fact.destination.storage.space is MemSpace.DS
        and fact.source.storage.width == fact.destination.storage.width == 2
        and fact.source.storage.index_shift == fact.destination.storage.index_shift == 1
        and fact.source.storage.base_offset in candidate_bases
        and fact.destination.storage.base_offset in candidate_bases
    )
    copy_pairs = {
        tuple(
            sorted(
                (
                    fact.source.storage.base_offset,
                    fact.destination.storage.base_offset,
                )
            )
        )
        for _function_addr, fact in accepted_copies
    }
    families = {base: {base} for base in candidate_bases}
    for source_base, destination_base in sorted(copy_pairs):
        merged = families[source_base] | families[destination_base]
        for member in merged:
            families[member] = merged
    layouts = tuple(
        GlobalObjectLayout8616(
            address=IRAddress(
                space=MemSpace.DS,
                offset=base,
                size=2,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
            element_width=2,
            field_offsets=(0, 1),
            family_base_offset=min(families[base]),
        )
        for base in sorted(candidate_bases)
    )
    consumed_accesses = tuple(
        (function_addr, fact)
        for function_addr, fact in global_accesses
        if any(
            (
                fact.source.storage.width == 2
                and fact.source.storage.base_offset == base
            )
            or (
                fact.source.storage.width == 1
                and fact.source.storage.base_offset
                in {base, (base + 1) & 0xFFFF}
            )
            for base in candidate_bases
        )
    )
    incomplete = bool(program.refusals)
    refusals: list[GlobalObjectLayoutRefusal8616] = [
        GlobalObjectLayoutRefusal8616(
            refusal.function_addr,
            GlobalObjectLayoutFailureKind8616.UPSTREAM_FUNCTION_REFUSAL,
            "selected function has no complete Alias evidence",
            refusal,
        )
        for refusal in program.refusals
    ]
    for function_addr, source in access_inputs:
        if (function_addr, source) in consumed_accesses:
            continue
        if incomplete:
            failure = GlobalObjectLayoutFailureKind8616.PROGRAM_CENSUS_INCOMPLETE
        elif isinstance(source, IndexedAliasAccessRefusal8616):
            failure = GlobalObjectLayoutFailureKind8616.UPSTREAM_ACCESS_REFUSAL
        elif source.role is not IndexedAliasAccessRole8616.GLOBAL_INDEXED:
            failure = GlobalObjectLayoutFailureKind8616.NON_GLOBAL_ACCESS
        else:
            failure = GlobalObjectLayoutFailureKind8616.LAYOUT_NOT_PROVEN
        refusals.append(
            GlobalObjectLayoutRefusal8616(
                function_addr,
                failure,
                "Alias access does not participate in one proven object layout",
                source,
            )
        )
    for function_addr, copy_source in copy_inputs:
        if (function_addr, copy_source) in accepted_copies:
            continue
        if incomplete:
            failure = GlobalObjectLayoutFailureKind8616.PROGRAM_CENSUS_INCOMPLETE
        elif isinstance(copy_source, IndexedAliasCopyRefusal8616):
            failure = GlobalObjectLayoutFailureKind8616.UPSTREAM_COPY_REFUSAL
        else:
            failure = GlobalObjectLayoutFailureKind8616.COPY_ENDPOINT_NOT_LAYOUT
        refusals.append(
            GlobalObjectLayoutRefusal8616(
                function_addr,
                failure,
                "Alias copy does not join two proven object layouts",
                copy_source,
            )
        )
    materialized_count = len(consumed_accesses) + len(accepted_copies)
    result = GlobalObjectLayoutEvidence8616(
        layouts=layouts,
        raw_fact_count=len(program.refusals) + len(access_inputs) + len(copy_inputs),
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
        refusals=tuple(refusals),
    )
    if not result.closed:
        raise ValueError("global-object Widening evidence accounting did not close")
    return result


__all__ = ["recover_global_object_layout_evidence_8616"]
