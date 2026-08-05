"""Recover project-wide object layouts from typed segmented storage views.

Layer: Widening.
Responsibility: join exact segmented direct or indexed views into stable object
extents. C type materialization remains owned by Types/Lowering.
Consumes alias-proven storage identity and instruction-backed access widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin


@dataclass(frozen=True, slots=True)
class IndexedStorageView8616:
    """One binary-proven indexed storage view and its index identity."""

    function_addr: int
    address: IRAddress
    index_stack_offset: int
    index_shift: int


@dataclass(frozen=True, slots=True)
class IndexedStorageCopy8616:
    """One exact whole-element copy between indexed segmented storages."""

    function_addr: int
    source_address: IRAddress
    destination_address: IRAddress
    source_index_stack_offset: int
    destination_index_stack_offset: int
    source_index_shift: int
    destination_index_shift: int


@dataclass(frozen=True, slots=True)
class GlobalObjectLayout8616:
    """One stable segmented object extent with byte field boundaries."""

    address: IRAddress
    element_width: int
    field_offsets: tuple[int, ...]
    family_base_offset: int


@dataclass(frozen=True, slots=True)
class GlobalObjectLayoutEvidence8616:
    """Closed evidence census and materialized project-wide layouts."""

    layouts: tuple[GlobalObjectLayout8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class DirectGlobalStorageView8616:
    """One exact direct DS storage view observed in a recovered function."""

    function_addr: int
    address: IRAddress


@dataclass(frozen=True, slots=True)
class DirectGlobalObjectLayout8616:
    """One unambiguous direct global object extent proven across the program."""

    address: IRAddress
    proof_function_addrs: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DirectGlobalObjectLayoutEvidence8616:
    """Closed evidence census for project-wide direct global object extents."""

    layouts: tuple[DirectGlobalObjectLayout8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int = 0


def recover_direct_global_object_layout_evidence_8616(
    views: Sequence[DirectGlobalStorageView8616],
) -> DirectGlobalObjectLayoutEvidence8616:
    """Join exact wide DS views by base and refuse overlapping object bases."""
    normalized = tuple(dict.fromkeys(views))
    wide_views = tuple(
        view
        for view in normalized
        if view.address.space is MemSpace.DS
        and view.address.size >= 4
        and view.address.status is AddressStatus.STABLE
        and view.address.segment_origin is SegmentOrigin.PROVEN
    )
    widest_by_base: dict[int, int] = {}
    proof_functions_by_base: dict[int, set[int]] = {}
    for view in wide_views:
        base = view.address.offset & 0xFFFF
        widest_by_base[base] = max(widest_by_base.get(base, 0), view.address.size)
        proof_functions_by_base.setdefault(base, set()).add(view.function_addr)

    covered_offsets_by_base = {
        base: frozenset((base + delta) & 0xFFFF for delta in range(width))
        for base, width in widest_by_base.items()
    }
    ambiguous_bases = {
        left_base
        for left_base, left_offsets in covered_offsets_by_base.items()
        for right_base, right_offsets in covered_offsets_by_base.items()
        if left_base != right_base and not left_offsets.isdisjoint(right_offsets)
    }
    layouts = tuple(
        DirectGlobalObjectLayout8616(
            address=IRAddress(
                space=MemSpace.DS,
                offset=base,
                size=width,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
            proof_function_addrs=tuple(sorted(proof_functions_by_base[base])),
        )
        for base, width in sorted(widest_by_base.items())
        if base not in ambiguous_bases
    )
    invalid_fact_count = len(normalized) - len(wide_views)
    return DirectGlobalObjectLayoutEvidence8616(
        layouts=layouts,
        raw_fact_count=len(views),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(wide_views),
        materialized_count=len(layouts),
        failure_count=invalid_fact_count + len(ambiguous_bases),
    )


def recover_global_object_layout_evidence_8616(
    views: Sequence[IndexedStorageView8616],
    copies: Sequence[IndexedStorageCopy8616] = (),
) -> GlobalObjectLayoutEvidence8616:
    """Join exact DS byte pairs with matching word storage identities."""
    normalized = tuple(dict.fromkeys(views))
    normalized_copies = tuple(dict.fromkeys(copies))
    word_bases = {
        view.address.offset & 0xFFFF
        for view in normalized
        if view.address.space is MemSpace.DS and view.address.size == 2 and view.index_shift == 1
    }
    byte_groups: dict[tuple[int, int, int], set[int]] = {}
    for view in normalized:
        if view.address.space is not MemSpace.DS or view.address.size != 1 or view.index_shift != 1:
            continue
        key = (view.function_addr, view.index_stack_offset, view.index_shift)
        byte_groups.setdefault(key, set()).add(view.address.offset & 0xFFFF)

    candidate_bases = {
        base
        for bases in byte_groups.values()
        for base in bases
        if base in word_bases and ((base + 1) & 0xFFFF) in bases
    }
    copy_pairs = {
        tuple(sorted((copy.source_address.offset & 0xFFFF, copy.destination_address.offset & 0xFFFF)))
        for copy in normalized_copies
        if copy.source_address.space is MemSpace.DS
        and copy.destination_address.space is MemSpace.DS
        and copy.source_address.size == copy.destination_address.size == 2
        and copy.source_index_stack_offset == copy.destination_index_stack_offset
        and copy.source_index_shift == copy.destination_index_shift == 1
        and (copy.source_address.offset & 0xFFFF) in candidate_bases
        and (copy.destination_address.offset & 0xFFFF) in candidate_bases
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
    return GlobalObjectLayoutEvidence8616(
        layouts=layouts,
        raw_fact_count=len(views) + len(copies),
        normalized_fact_count=len(normalized) + len(normalized_copies),
        classified_fact_count=len(candidate_bases) + len(copy_pairs),
        materialized_count=len(layouts) + len(copy_pairs),
    )


__all__ = [
    "DirectGlobalObjectLayout8616",
    "DirectGlobalObjectLayoutEvidence8616",
    "DirectGlobalStorageView8616",
    "GlobalObjectLayout8616",
    "GlobalObjectLayoutEvidence8616",
    "IndexedStorageCopy8616",
    "IndexedStorageView8616",
    "recover_direct_global_object_layout_evidence_8616",
    "recover_global_object_layout_evidence_8616",
]
