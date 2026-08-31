"""Publish discovered function boundaries as Alias and Widening artifacts.

Layer: CLI/fallback/reporting orchestration.
Responsibility: transport a complete binary function catalog into the Alias
program builder once, invoke the Widening owner, then attach immutable results
for sliced workers. No semantic fact is classified in CLI; discovery supplies
boundaries and the owning X86_16 layers classify them.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

import angr
from angr_platforms.X86_16.alias.indexed_address_program import (
    IndexedAliasProgramEvidence8616,
    build_indexed_alias_program_evidence_8616,
)
from angr_platforms.X86_16.lowering.global_object_program_requirement import (
    GlobalObjectProgramRequirementEvidence8616,
    collect_global_object_program_requirement_8616,
)
from angr_platforms.X86_16.lowering.project_callee_callsite_collection import (
    collect_complete_project_callee_callsites_8616,
)
from angr_platforms.X86_16.lowering.project_global_object_source_collection import (
    collect_complete_project_global_object_sources_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
    recover_program_bounded_global_object_ranges_8616,
)

from . import indexed_alias_program_parallel as _alias_program_parallel
from .cache import _cache_key_lock
from .cli_function_discovery import (
    _recover_fast_exe_catalog,
    _source_region_catalog_evidence_8616,
)
from .discovery_evidence_project import isolated_discovery_evidence_project_8616
from .indexed_global_object_cache import (
    INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
    PersistedIndexedGlobalObjectEvidence8616,
    indexed_global_object_cache_key_8616,
    load_indexed_global_object_cache_8616,
    store_indexed_global_object_cache_8616,
)
from .program_callsite_cache import (
    attach_available_program_callsite_evidence_8616,
    attach_program_callsite_caller_ranges_8616,
    attach_program_callsite_evidence_8616,
    program_callsite_cache_key_8616,
    program_callsite_evidence_from_project_8616,
    store_program_callsite_cache_8616,
)
from .project_evidence_transport import (
    attach_project_bounded_global_object_ranges_8616,
    attach_project_global_object_layout_evidence_8616,
)

log: logging.Logger = logging.getLogger(__name__)

class IndexedAliasProgramContextStatus8616(StrEnum):
    """Typed result of preparing one direct-run Alias program context."""

    NOT_REQUIRED = "not_required"
    PUBLISHED = "published"
    REUSED_WIDENING = "reused_widening"
    REUSED_PERSISTED_WIDENING = "reused_persisted_widening"
    DISCOVERY_INCOMPLETE = "discovery_incomplete"


@dataclass(frozen=True, slots=True)
class IndexedAliasProgramContextResult8616:
    """One direct-run context status and its optional complete program."""

    status: IndexedAliasProgramContextStatus8616
    program: IndexedAliasProgramEvidence8616 | None
    requirement: GlobalObjectProgramRequirementEvidence8616


class _ProjectProgramSurface8616(Protocol):
    """Owned immutable Alias/Widening artifacts attached to a project."""

    _inertia_indexed_alias_program_evidence_8616: IndexedAliasProgramEvidence8616
    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_project_bounded_global_object_ranges_8616: ProjectBoundedGlobalObjectRangeEvidence8616
    _inertia_global_object_program_requirement_8616: GlobalObjectProgramRequirementEvidence8616


def publish_discovered_indexed_alias_program_8616(
    evidence_project: object,
    functions: Sequence[object],
    *,
    target_project: object | None = None,
) -> IndexedAliasProgramEvidence8616:
    """Build Alias once and attach its closed Widening projection."""
    program = _alias_program_parallel.build_discovered_indexed_alias_program_bounded_8616(
        evidence_project,
        functions,
    )
    destination = evidence_project if target_project is None else target_project
    layouts = recover_global_object_layout_evidence_8616(program)
    ranges = recover_program_bounded_global_object_ranges_8616(
        program,
        layouts,
    )
    evidence_surface = cast(_ProjectProgramSurface8616, evidence_project)
    evidence_surface._inertia_indexed_alias_program_evidence_8616 = program
    evidence_surface._inertia_project_global_object_layout_evidence_8616 = layouts
    evidence_surface._inertia_project_bounded_global_object_ranges_8616 = ranges
    if destination is not evidence_project:
        destination_surface = cast(_ProjectProgramSurface8616, destination)
        destination_surface._inertia_indexed_alias_program_evidence_8616 = program
        destination_surface._inertia_project_global_object_layout_evidence_8616 = layouts
        destination_surface._inertia_project_bounded_global_object_ranges_8616 = ranges
    if destination is evidence_project:
        collect_complete_project_callee_callsites_8616(
            evidence_project,
            functions,
        )
        collect_complete_project_global_object_sources_8616(
            evidence_project,
            functions,
            layouts,
        )
    return program


def _discover_direct_indexed_alias_program_context_8616(
    source_project: object,
    target_project: object,
    requirement: GlobalObjectProgramRequirementEvidence8616,
    *,
    timeout: int,
    window: int,
    cache_key: dict[str, object] | None,
    callsite_cache_key: dict[str, object] | None,
    program_callsites_ready: bool = False,
) -> IndexedAliasProgramContextResult8616:
    """Publish a complete census and optionally persist its closed projection."""
    evidence_project = isolated_discovery_evidence_project_8616(
        cast(angr.Project, source_project)
    )
    with contextlib.redirect_stdout(sys.stderr):
        recovered = _recover_fast_exe_catalog(
            evidence_project,
            timeout=max(1, timeout),
            window=max(1, window),
            low_memory=False,
            limit=None,
            seed_calling_conventions_enabled=False,
        )
    catalog = _source_region_catalog_evidence_8616(evidence_project)
    if catalog is None or not catalog.complete:
        log.warning(
            "indexed Alias program context refused: binary function census incomplete"
        )
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.DISCOVERY_INCOMPLETE,
            None,
            requirement,
        )
    program = publish_discovered_indexed_alias_program_8616(
        evidence_project,
        tuple(function_boundary for _cfg, function_boundary in recovered),
        target_project=target_project,
    )
    target_layout = cast(
        _ProjectProgramSurface8616,
        target_project,
    )._inertia_project_global_object_layout_evidence_8616
    target_ranges = cast(
        _ProjectProgramSurface8616,
        target_project,
    )._inertia_project_bounded_global_object_ranges_8616
    caller_ranges_ready = attach_program_callsite_caller_ranges_8616(
        evidence_project,
        target_project,
        source_project,
    )
    if not program_callsites_ready and caller_ranges_ready:
        collect_complete_project_callee_callsites_8616(
            evidence_project,
            tuple(function_boundary for _cfg, function_boundary in recovered),
        )
        callsite_evidence = program_callsite_evidence_from_project_8616(
            evidence_project
        )
        attach_program_callsite_evidence_8616(target_project, callsite_evidence)
        if callsite_cache_key is not None:
            store_program_callsite_cache_8616(
                callsite_cache_key,
                evidence_project,
                callsite_evidence,
            )
    elif not program_callsites_ready:
        log.warning(
            "program callsite cache refused: complete caller ranges unavailable"
        )
    if cache_key is not None:
        store_indexed_global_object_cache_8616(
            cache_key,
            PersistedIndexedGlobalObjectEvidence8616(target_layout, target_ranges),
        )
    return IndexedAliasProgramContextResult8616(
        IndexedAliasProgramContextStatus8616.PUBLISHED,
        program,
        requirement,
    )


def prepare_direct_indexed_alias_program_context_8616(
    source_project: object,
    target_project: object,
    function: object,
    *,
    timeout: int,
    window: int,
    binary_path: Path | None = None,
) -> IndexedAliasProgramContextResult8616:
    """Publish a full catalog only when the direct function needs one."""
    selection = _alias_program_parallel.indexed_alias_function_selection_8616(function)
    local_program = build_indexed_alias_program_evidence_8616(
        target_project,
        (selection,),
    )
    requirement = collect_global_object_program_requirement_8616(
        source_project,
        function,
        local_program,
    )
    target_surface = cast(_ProjectProgramSurface8616, target_project)
    target_surface._inertia_global_object_program_requirement_8616 = requirement
    if not requirement.requires_program:
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.NOT_REQUIRED,
            None,
            requirement,
        )
    program_callsites_required = bool(requirement.callsite_addrs)
    callsite_cache_key = program_callsite_cache_key_8616(
        source_project,
        binary_path,
    )
    try:
        transported_layout = target_surface._inertia_project_global_object_layout_evidence_8616
    except AttributeError:
        transported_layout = None
    try:
        transported_ranges = target_surface._inertia_project_bounded_global_object_ranges_8616
    except AttributeError:
        transported_ranges = None
    if (transported_layout is None) != (transported_ranges is None):
        raise ValueError("transported indexed-global Widening bundle is incomplete")
    if transported_layout is not None and transported_ranges is not None:
        if not isinstance(transported_layout, GlobalObjectLayoutEvidence8616):
            raise TypeError("transported indexed-global Widening artifact has a wrong type")
        if not isinstance(transported_ranges, ProjectBoundedGlobalObjectRangeEvidence8616):
            raise TypeError("transported bounded-global Widening artifact has a wrong type")
        if not transported_layout.closed:
            raise ValueError("transported indexed-global Widening artifact is open")
        if not transported_ranges.closed or transported_ranges.layouts != transported_layout:
            raise ValueError("transported indexed-global Widening bundle is incoherent")
        if not program_callsites_required or attach_available_program_callsite_evidence_8616(
            target_project, callsite_cache_key
        ):
            return IndexedAliasProgramContextResult8616(
                IndexedAliasProgramContextStatus8616.REUSED_WIDENING,
                None,
                requirement,
            )
    cache_key = indexed_global_object_cache_key_8616(source_project, binary_path)
    if cache_key is None:
        return _discover_direct_indexed_alias_program_context_8616(
            source_project,
            target_project,
            requirement,
            timeout=timeout,
            window=window,
            cache_key=None,
            callsite_cache_key=callsite_cache_key,
            program_callsites_ready=not program_callsites_required,
        )
    lock_timeout = max(600.0, float(max(1, timeout)) * 2.0)
    with _cache_key_lock(
        INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        cache_key,
        timeout_seconds=lock_timeout,
    ):
        program_callsites_ready = (
            not program_callsites_required
            or attach_available_program_callsite_evidence_8616(
                target_project,
                callsite_cache_key,
            )
        )
        persisted = load_indexed_global_object_cache_8616(cache_key)
        if persisted is not None and program_callsites_ready:
            attach_project_global_object_layout_evidence_8616(
                target_project,
                persisted.layouts,
            )
            attach_project_bounded_global_object_ranges_8616(
                target_project,
                persisted.ranges,
            )
            return IndexedAliasProgramContextResult8616(
                IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING,
                None,
                requirement,
            )
        return _discover_direct_indexed_alias_program_context_8616(
            source_project,
            target_project,
            requirement,
            timeout=timeout,
            window=window,
            cache_key=cache_key,
            callsite_cache_key=callsite_cache_key,
            program_callsites_ready=program_callsites_ready,
        )


__all__ = [
    "IndexedAliasProgramContextResult8616",
    "IndexedAliasProgramContextStatus8616",
    "prepare_direct_indexed_alias_program_context_8616",
    "publish_discovered_indexed_alias_program_8616",
]
