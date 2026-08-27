"""Collect project-wide global object-family source facts.

Layer: Types/Lowering.
Responsibility: join complete callee source-family facts across binary-proven
pointer targets and refuse conflicting family identities for one storage base.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from ..widening.global_object_layout import GlobalObjectLayoutEvidence8616
from .callee_global_object_collection import (
    collect_callee_global_object_interface_evidence_8616,
)
from .callee_global_object_evidence import CalleeGlobalObjectSourceFamilyFact8616
from .callee_pointer_evidence import CalleePointerArgumentEvidence8616

_LOGGER = logging.getLogger(__name__)


class _ProjectSourceEvidenceSurface8616(Protocol):
    """Owned project caches used by project-wide source-family collection."""

    _inertia_callee_pointer_argument_evidence_8616: dict[int, object]
    _inertia_project_global_object_source_evidence_8616: GlobalObjectSourceEvidence8616


@dataclass(frozen=True, slots=True)
class GlobalObjectSourceEvidence8616:
    """Closed census of callee-proven global object sources in one scope."""

    scope_addr: int | None
    source_facts: tuple[CalleeGlobalObjectSourceFamilyFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    pointer_target_addrs: tuple[int, ...] = ()


def join_global_object_source_facts_8616(
    scope_addr: int | None,
    source_facts: Iterable[CalleeGlobalObjectSourceFamilyFact8616],
    pointer_target_addrs: tuple[int, ...] = (),
) -> GlobalObjectSourceEvidence8616:
    """Join source facts by storage base and refuse family conflicts."""
    normalized = tuple(source_facts)
    families_by_base: dict[int, set[int]] = {}
    for fact in normalized:
        families_by_base.setdefault(fact.base_offset & 0xFFFF, set()).add(
            fact.family_base_offset & 0xFFFF
        )
    conflicted_bases = {
        base_offset
        for base_offset, families in families_by_base.items()
        if len(families) != 1
    }
    classified = tuple(
        fact
        for fact in normalized
        if (fact.base_offset & 0xFFFF) not in conflicted_bases
    )
    return GlobalObjectSourceEvidence8616(
        scope_addr=scope_addr,
        source_facts=classified,
        raw_fact_count=len(normalized),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(classified),
        materialized_count=0,
        failure_count=len(normalized) - len(classified),
        pointer_target_addrs=pointer_target_addrs,
    )


def _proven_pointer_target_addresses_8616(project: object) -> tuple[int, ...]:
    """Return targets with a complete binary pointer-argument contract."""
    surface = cast(_ProjectSourceEvidenceSurface8616, project)
    try:
        registry = surface._inertia_callee_pointer_argument_evidence_8616
    except AttributeError:
        return ()
    if not isinstance(registry, dict):
        raise TypeError("callee pointer evidence registry must be a dict")
    return tuple(
        sorted(
            target_addr
            for target_addr, evidence in registry.items()
            if isinstance(target_addr, int)
            and isinstance(evidence, CalleePointerArgumentEvidence8616)
            and evidence.failure_count == 0
            and evidence.classified_fact_count > 0
            and evidence.materialized_count == evidence.classified_fact_count
        )
    )


def collect_project_global_object_source_evidence_8616(
    project: object,
    layout_evidence: GlobalObjectLayoutEvidence8616,
) -> GlobalObjectSourceEvidence8616:
    """Collect and cache source-family facts across proven pointer callees."""
    surface = cast(_ProjectSourceEvidenceSurface8616, project)
    try:
        cached = surface._inertia_project_global_object_source_evidence_8616
    except AttributeError:
        cached = None
    pointer_targets = _proven_pointer_target_addresses_8616(project)
    if (
        isinstance(cached, GlobalObjectSourceEvidence8616)
        and cached.pointer_target_addrs == pointer_targets
    ):
        return cached
    facts: list[CalleeGlobalObjectSourceFamilyFact8616] = []
    for target_addr in pointer_targets:
        evidence = collect_callee_global_object_interface_evidence_8616(
            project,
            target_addr,
            layout_evidence,
        )
        facts.extend(evidence.source_facts)
        if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
            _LOGGER.warning(
                "project global object source target=%#x callee_family=%s "
                "callee_callsites=%s source_facts=%s",
                target_addr,
                evidence.family_base_offset,
                evidence.callsite_addrs,
                evidence.source_facts,
            )
    joined = join_global_object_source_facts_8616(
        None,
        facts,
        pointer_targets,
    )
    surface._inertia_project_global_object_source_evidence_8616 = joined
    if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
        _LOGGER.warning("project global object source joined=%s", joined)
    return joined


__all__ = [
    "GlobalObjectSourceEvidence8616",
    "collect_project_global_object_source_evidence_8616",
    "join_global_object_source_facts_8616",
]
