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
    IndexedAliasFunctionSelection8616,
    IndexedAliasProgramEvidence8616,
    build_indexed_alias_program_evidence_8616,
)
from angr_platforms.X86_16.lowering.global_object_program_requirement import (
    GlobalObjectProgramRequirementEvidence8616,
    collect_global_object_program_requirement_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from angr_platforms.X86_16.widening.global_object_layout_codec import (
    global_object_layout_evidence_from_record_8616,
    global_object_layout_evidence_record_8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)

from .cache import (
    _cache_key_lock,
    _load_cache_json,
    _recovery_cache_key,
    _store_cache_json,
)
from .cli_function_discovery import (
    _display_catalog_cache_policy_8616,
    _recover_fast_exe_catalog,
    _source_region_catalog_evidence_8616,
)
from .discovery_evidence_project import isolated_discovery_evidence_project_8616
from .project_evidence_transport import (
    attach_project_global_object_layout_evidence_8616,
)

log: logging.Logger = logging.getLogger(__name__)

_GLOBAL_OBJECT_LAYOUT_CACHE_NAMESPACE_8616 = "indexed_global_object_layout"
_GLOBAL_OBJECT_LAYOUT_CACHE_SCHEMA_8616 = 1


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


class _FunctionBoundary8616(Protocol):
    """Third-party recovered function surface used only for transport."""

    addr: object


class _ProjectProgramSurface8616(Protocol):
    """Owned immutable Alias/Widening artifacts attached to a project."""

    _inertia_indexed_alias_program_evidence_8616: IndexedAliasProgramEvidence8616
    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_global_object_program_requirement_8616: GlobalObjectProgramRequirementEvidence8616


def _global_object_layout_cache_key_8616(
    source_project: object,
    binary_path: Path | None,
) -> dict[str, object] | None:
    """Return semantic identity for one closed whole-program layout artifact."""
    policy = _display_catalog_cache_policy_8616(cast(angr.Project, source_project))
    return cast(
        dict[str, object] | None,
        _recovery_cache_key(
            binary_path=binary_path,
            kind=_GLOBAL_OBJECT_LAYOUT_CACHE_NAMESPACE_8616,
            extra={
                "artifact_schema": _GLOBAL_OBJECT_LAYOUT_CACHE_SCHEMA_8616,
                "ignore_local_sidecar_hints": policy.ignore_local_sidecar_hints,
                "include_library_functions": policy.include_library_functions,
                "function_discovery_backend": policy.function_discovery_backend,
                "pat_backend": policy.pat_backend,
                "auto_rizin_policy": policy.auto_rizin_policy,
                "signature_catalog_path": policy.signature_catalog_path,
                "signature_catalog_size": policy.signature_catalog_size,
                "signature_catalog_mtime_ns": policy.signature_catalog_mtime_ns,
            },
        ),
    )


def _load_global_object_layout_cache_8616(
    cache_key: dict[str, object],
) -> GlobalObjectLayoutEvidence8616 | None:
    """Restore one closed Widening artifact, refusing malformed cache data."""
    record = _load_cache_json(_GLOBAL_OBJECT_LAYOUT_CACHE_NAMESPACE_8616, cache_key)
    if record is None:
        return None
    try:
        return global_object_layout_evidence_from_record_8616(record)
    except ValueError as exc:
        log.warning("persisted indexed-global Widening artifact refused: %s", exc)
        return None


def _store_global_object_layout_cache_8616(
    cache_key: dict[str, object],
    evidence: GlobalObjectLayoutEvidence8616,
) -> None:
    """Persist one already-classified closed Widening artifact."""
    _store_cache_json(
        _GLOBAL_OBJECT_LAYOUT_CACHE_NAMESPACE_8616,
        cache_key,
        global_object_layout_evidence_record_8616(evidence),
    )


def publish_discovered_indexed_alias_program_8616(
    evidence_project: object,
    functions: Sequence[object],
    *,
    target_project: object | None = None,
) -> IndexedAliasProgramEvidence8616:
    """Build Alias once and attach its closed Widening projection."""
    selections: list[IndexedAliasFunctionSelection8616] = []
    for function in functions:
        try:
            function_addr = cast(_FunctionBoundary8616, function).addr
        except AttributeError as exc:
            raise TypeError("discovered function has no canonical address") from exc
        if not isinstance(function_addr, int) or function_addr < 0:
            raise TypeError("discovered function has an invalid canonical address")
        selections.append(IndexedAliasFunctionSelection8616(function_addr, function))
    program = build_indexed_alias_program_evidence_8616(
        evidence_project,
        selections,
    )
    destination = evidence_project if target_project is None else target_project
    surface = cast(_ProjectProgramSurface8616, destination)
    surface._inertia_indexed_alias_program_evidence_8616 = program
    surface._inertia_project_global_object_layout_evidence_8616 = (
        recover_global_object_layout_evidence_8616(program)
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
    if cache_key is not None:
        _store_global_object_layout_cache_8616(cache_key, target_layout)
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
    try:
        function_addr = cast(_FunctionBoundary8616, function).addr
    except AttributeError as exc:
        raise TypeError("direct function has no canonical address") from exc
    if not isinstance(function_addr, int) or function_addr < 0:
        raise TypeError("direct function has an invalid canonical address")
    local_program = build_indexed_alias_program_evidence_8616(
        target_project,
        (IndexedAliasFunctionSelection8616(function_addr, function),),
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
    try:
        transported_layout = (
            target_surface._inertia_project_global_object_layout_evidence_8616
        )
    except AttributeError:
        transported_layout = None
    if transported_layout is not None:
        if not isinstance(transported_layout, GlobalObjectLayoutEvidence8616):
            raise TypeError("transported indexed-global Widening artifact has a wrong type")
        if not transported_layout.closed:
            raise ValueError("transported indexed-global Widening artifact is open")
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.REUSED_WIDENING,
            None,
            requirement,
        )
    cache_key = _global_object_layout_cache_key_8616(source_project, binary_path)
    if cache_key is None:
        return _discover_direct_indexed_alias_program_context_8616(
            source_project,
            target_project,
            requirement,
            timeout=timeout,
            window=window,
            cache_key=None,
        )
    lock_timeout = max(600.0, float(max(1, timeout)) * 2.0)
    with _cache_key_lock(
        _GLOBAL_OBJECT_LAYOUT_CACHE_NAMESPACE_8616,
        cache_key,
        timeout_seconds=lock_timeout,
    ):
        persisted_layout = _load_global_object_layout_cache_8616(cache_key)
        if persisted_layout is not None:
            attach_project_global_object_layout_evidence_8616(
                target_project,
                persisted_layout,
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
        )


__all__ = [
    "IndexedAliasProgramContextResult8616",
    "IndexedAliasProgramContextStatus8616",
    "prepare_direct_indexed_alias_program_context_8616",
    "publish_discovered_indexed_alias_program_8616",
]
