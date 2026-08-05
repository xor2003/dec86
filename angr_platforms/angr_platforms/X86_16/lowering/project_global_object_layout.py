"""Collect project-wide storage evidence for object layout widening.

Layer: Types/Lowering orchestration.
Responsibility: collect exact instruction-backed direct and indexed DS views
across known function bounds and delegate object extent classification to
Widening. This module does not choose C types or mutate generated C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol, TypeAlias, cast, runtime_checkable

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..widening.global_object_layout import (
    DirectGlobalObjectLayoutEvidence8616,
    DirectGlobalStorageView8616,
    GlobalObjectLayoutEvidence8616,
    IndexedStorageCopy8616,
    IndexedStorageView8616,
    recover_direct_global_object_layout_evidence_8616,
    recover_global_object_layout_evidence_8616,
)


class DirectGlobalStorageEvidenceBoundary8616(Protocol):
    """Exact direct global storage fields exposed by a binary collector."""

    @property
    def offset(self) -> int:
        """Return the exact DS base displacement."""
        ...

    @property
    def width(self) -> int:
        """Return the proven object width in bytes."""
        ...


class IndexedStorageEvidenceBoundary8616(Protocol):
    """Shared exact fields exposed by indexed load and store evidence."""

    @property
    def base_offset(self) -> int:
        """Return the exact DS base displacement."""
        ...

    @property
    def width(self) -> int:
        """Return the accessed storage width in bytes."""
        ...

    @property
    def index_stack_offset(self) -> int:
        """Return the exact BP-relative identity of the index."""
        ...

    @property
    def index_shift(self) -> int:
        """Return the binary-proven index shift."""
        ...


@runtime_checkable
class IndexedStorageCopyEvidenceBoundary8616(IndexedStorageEvidenceBoundary8616, Protocol):
    """Optional whole-copy fields exposed by indexed store evidence."""

    @property
    def source_base_offset(self) -> int | None:
        """Return the source DS base when an exact indexed source exists."""
        ...

    @property
    def source_width(self) -> int | None:
        """Return the exact source width when known."""
        ...

    @property
    def source_index_stack_offset(self) -> int | None:
        """Return the source index storage identity when known."""
        ...

    @property
    def source_index_shift(self) -> int | None:
        """Return the source index shift when known."""
        ...


IndexedStorageEvidenceCollector8616: TypeAlias = Callable[
    [object, object], Iterable[IndexedStorageEvidenceBoundary8616]
]
DirectGlobalStorageEvidenceCollector8616: TypeAlias = Callable[
    [object, object], Iterable[DirectGlobalStorageEvidenceBoundary8616]
]


class _ProjectGlobalObjectLayoutSurface8616(Protocol):
    """Owned metadata attached to an angr project at the dynamic boundary."""

    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_original_project: object
    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_project_direct_global_object_layout_evidence_8616: DirectGlobalObjectLayoutEvidence8616


@dataclass(frozen=True, slots=True)
class FunctionRangeView8616:
    """Minimal function boundary consumed by linear instruction recovery."""

    addr: int
    size: int


def collect_project_global_object_layout_evidence_8616(
    project: object,
    collectors: tuple[IndexedStorageEvidenceCollector8616, ...],
) -> GlobalObjectLayoutEvidence8616:
    """Collect and cache exact indexed storage views across known functions."""
    surface = cast(_ProjectGlobalObjectLayoutSurface8616, project)
    try:
        cached = surface._inertia_project_global_object_layout_evidence_8616
    except AttributeError:
        cached = None
    if isinstance(cached, GlobalObjectLayoutEvidence8616):
        return cached

    try:
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        ranges = ()
    if not isinstance(ranges, tuple):
        raise TypeError("project function ranges must be a tuple of (start, end) pairs")

    try:
        evidence_project = surface._inertia_original_project
    except AttributeError:
        evidence_project = project

    views: list[IndexedStorageView8616] = []
    copies: list[IndexedStorageCopy8616] = []
    for bounds in ranges:
        if (
            not isinstance(bounds, tuple)
            or len(bounds) != 2
            or not isinstance(bounds[0], int)
            or not isinstance(bounds[1], int)
            or bounds[1] <= bounds[0]
        ):
            raise TypeError("project function ranges contain an invalid (start, end) pair")
        function = FunctionRangeView8616(addr=bounds[0], size=bounds[1] - bounds[0])
        for collector in collectors:
            for fact in collector(evidence_project, function):
                destination_address = IRAddress(
                    space=MemSpace.DS,
                    offset=fact.base_offset & 0xFFFF,
                    size=fact.width,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                )
                views.append(
                    IndexedStorageView8616(
                        function_addr=function.addr,
                        address=destination_address,
                        index_stack_offset=fact.index_stack_offset,
                        index_shift=fact.index_shift,
                    )
                )
                if not isinstance(fact, IndexedStorageCopyEvidenceBoundary8616):
                    continue
                if (
                    not isinstance(fact.source_base_offset, int)
                    or not isinstance(fact.source_width, int)
                    or not isinstance(fact.source_index_stack_offset, int)
                    or not isinstance(fact.source_index_shift, int)
                ):
                    continue
                copies.append(
                    IndexedStorageCopy8616(
                        function_addr=function.addr,
                        source_address=IRAddress(
                            space=MemSpace.DS,
                            offset=fact.source_base_offset & 0xFFFF,
                            size=fact.source_width,
                            status=AddressStatus.STABLE,
                            segment_origin=SegmentOrigin.PROVEN,
                        ),
                        destination_address=destination_address,
                        source_index_stack_offset=fact.source_index_stack_offset,
                        destination_index_stack_offset=fact.index_stack_offset,
                        source_index_shift=fact.source_index_shift,
                        destination_index_shift=fact.index_shift,
                    )
                )

    result = recover_global_object_layout_evidence_8616(views, copies)
    surface._inertia_project_global_object_layout_evidence_8616 = result
    return result


def collect_project_direct_global_object_layout_evidence_8616(
    project: object,
    collectors: tuple[DirectGlobalStorageEvidenceCollector8616, ...],
) -> DirectGlobalObjectLayoutEvidence8616:
    """Collect and cache exact wide direct DS views across known functions."""
    surface = cast(_ProjectGlobalObjectLayoutSurface8616, project)
    try:
        cached = surface._inertia_project_direct_global_object_layout_evidence_8616
    except AttributeError:
        cached = None
    if isinstance(cached, DirectGlobalObjectLayoutEvidence8616):
        return cached

    try:
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        ranges = ()
    if not isinstance(ranges, tuple):
        raise TypeError("project function ranges must be a tuple of (start, end) pairs")

    try:
        evidence_project = surface._inertia_original_project
    except AttributeError:
        evidence_project = project

    views: list[DirectGlobalStorageView8616] = []
    for bounds in ranges:
        if (
            not isinstance(bounds, tuple)
            or len(bounds) != 2
            or not isinstance(bounds[0], int)
            or not isinstance(bounds[1], int)
            or bounds[1] <= bounds[0]
        ):
            raise TypeError("project function ranges contain an invalid (start, end) pair")
        function = FunctionRangeView8616(addr=bounds[0], size=bounds[1] - bounds[0])
        for collector in collectors:
            for fact in collector(evidence_project, function):
                views.append(
                    DirectGlobalStorageView8616(
                        function_addr=function.addr,
                        address=IRAddress(
                            space=MemSpace.DS,
                            offset=fact.offset & 0xFFFF,
                            size=fact.width,
                            status=AddressStatus.STABLE,
                            segment_origin=SegmentOrigin.PROVEN,
                        ),
                    )
                )

    result = recover_direct_global_object_layout_evidence_8616(views)
    surface._inertia_project_direct_global_object_layout_evidence_8616 = result
    return result


__all__ = [
    "DirectGlobalStorageEvidenceBoundary8616",
    "DirectGlobalStorageEvidenceCollector8616",
    "FunctionRangeView8616",
    "IndexedStorageCopyEvidenceBoundary8616",
    "IndexedStorageEvidenceBoundary8616",
    "IndexedStorageEvidenceCollector8616",
    "collect_project_direct_global_object_layout_evidence_8616",
    "collect_project_global_object_layout_evidence_8616",
]
