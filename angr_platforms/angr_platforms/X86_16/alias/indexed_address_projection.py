"""Project indexed IR addresses into symbolic Alias storage identities.

Layer: Alias.
Responsibility: bind each indexed DS/ES IR fact to the exact stack Alias range
that supplies its dynamic term while preserving segment, displacement, width,
SSA identity, shift, proof path, and typed refusals. This module deliberately
does not infer bounds, arrays, fields, C types, or rendered expressions.
Owns storage identity and exact Alias-domain relationships.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Widening and Types/Lowering consume these facts only after Alias proof.
"""

from __future__ import annotations

from collections import Counter
from typing import Protocol, cast

from ..ir.indexed_address_contracts import IndexedAddressEvidence8616, IndexedAddressFact8616
from ..pipeline.errors import PipelineHardError
from .alias_model_impl import AliasFailure, AliasStorageFacts, alias_facts_for_ir_address_8616
from .indexed_address_access_classification import classify_indexed_alias_accesses_8616
from .indexed_address_access_contracts import IndexedAliasAccessEvidence8616
from .indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
    IndexedAddressAliasFailureKind8616,
    IndexedAddressAliasRefusal8616,
    IndexedAddressAliasStats8616,
    IndexedAliasStorage8616,
)
from .storage_fact_join import build_segmented_alias_range_8616


class _CodegenBoundary8616(Protocol):
    """Typed IR and Alias artifacts on the dynamic angr codegen boundary."""

    _inertia_vex_ir_function_ssa: object
    _inertia_indexed_address_evidence_8616: IndexedAddressEvidence8616
    _inertia_indexed_address_alias_evidence_8616: IndexedAddressAliasEvidence8616
    _inertia_indexed_address_alias_access_evidence_8616: IndexedAliasAccessEvidence8616


def _source_key_8616(fact: IndexedAddressFact8616) -> tuple[object, ...]:
    """Return the exact machine/SSA identity of one indexed access."""
    return (
        fact.function_addr,
        fact.block_addr,
        fact.instr_index,
        fact.instr_addr,
        fact.kind,
    )


def _project_fact_8616(
    fact: IndexedAddressFact8616,
) -> IndexedAddressAliasFact8616 | IndexedAddressAliasRefusal8616:
    """Project one complete indexed fact without widening its meaning."""
    if not fact.complete:
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INCOMPLETE_SOURCE_FACT,
            "indexed IR source fact is incomplete",
            source_fact=fact,
        )
    index_storage = alias_facts_for_ir_address_8616(fact.index_source)
    if isinstance(index_storage, AliasFailure):
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INDEX_SOURCE_ALIAS_FAILURE,
            index_storage.reason,
            source_fact=fact,
        )
    if not isinstance(index_storage, AliasStorageFacts):
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INDEX_SOURCE_UNCLASSIFIABLE,
            "canonical Alias model did not classify the stack index source",
            source_fact=fact,
        )
    source_range = build_segmented_alias_range_8616(
        (fact.index_source,),
        (index_storage,),
    )
    if source_range is None:
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INDEX_SOURCE_RANGE_REFUSED,
            "stack index source did not form one exact segmented Alias range",
            source_fact=fact,
        )
    storage = IndexedAliasStorage8616(
        fact.address.space,
        fact.address.offset & 0xFFFF,
        fact.address.size,
        fact.index_value,
        source_range,
        fact.index_shift,
    )
    projected = IndexedAddressAliasFact8616(fact, storage)
    if not projected.complete:
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INCOMPLETE_SOURCE_FACT,
            "indexed IR and symbolic Alias storage disagree",
            source_fact=fact,
        )
    return projected


def project_indexed_address_aliases_8616(
    evidence: IndexedAddressEvidence8616,
) -> IndexedAddressAliasEvidence8616:
    """Project every closed indexed IR outcome into Alias or a typed refusal."""
    if not evidence.closed:
        raise PipelineHardError(
            "indexed-address IR evidence is incomplete before Alias projection",
            layer="alias",
        )
    duplicate_keys = {
        key
        for key, count in Counter(_source_key_8616(fact) for fact in evidence.facts).items()
        if count > 1
    }
    facts: list[IndexedAddressAliasFact8616] = []
    refusals = [
        IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.UPSTREAM_REFUSAL,
            f"IR refused indexed address: {source.failure.value}",
            source_refusal=source,
        )
        for source in evidence.refusals
    ]
    for source in evidence.facts:
        if _source_key_8616(source) in duplicate_keys:
            refusals.append(
                IndexedAddressAliasRefusal8616(
                    IndexedAddressAliasFailureKind8616.DUPLICATE_ACCESS,
                    "duplicate indexed IR access identity",
                    source_fact=source,
                )
            )
            continue
        projected = _project_fact_8616(source)
        if isinstance(projected, IndexedAddressAliasRefusal8616):
            refusals.append(projected)
        else:
            facts.append(projected)
    materialized = len(facts)
    result = IndexedAddressAliasEvidence8616(
        evidence.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAddressAliasStats8616(
            raw_fact_count=evidence.stats.normalized_fact_count,
            normalized_fact_count=materialized,
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(refusals),
        ),
        evidence,
    )
    if not result.closed:
        raise PipelineHardError(
            "indexed-address Alias projection has incomplete accounting",
            layer="alias",
        )
    return result


def apply_x86_16_indexed_address_aliases_8616(
    project: object,  # noqa: ARG001
    codegen: object,
) -> bool:
    """Publish Alias projection and fail if the preceding IR owner is absent."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_indexed_address_evidence_8616
    except AttributeError as error:
        try:
            boundary._inertia_vex_ir_function_ssa
        except AttributeError:
            return False
        raise PipelineHardError(
            "indexed-address IR evidence is missing before Alias projection",
            layer="alias",
        ) from error
    if not isinstance(source, IndexedAddressEvidence8616):
        raise PipelineHardError(
            "indexed-address IR evidence has the wrong pipeline contract",
            layer="alias",
        )
    try:
        existing = boundary._inertia_indexed_address_alias_evidence_8616
    except AttributeError:
        existing = None
    if not (
        isinstance(existing, IndexedAddressAliasEvidence8616)
        and existing.source == source
    ):
        existing = project_indexed_address_aliases_8616(source)
        boundary._inertia_indexed_address_alias_evidence_8616 = existing
    try:
        access_evidence = boundary._inertia_indexed_address_alias_access_evidence_8616
    except AttributeError:
        access_evidence = None
    if not (
        isinstance(access_evidence, IndexedAliasAccessEvidence8616)
        and access_evidence.source == existing
    ):
        boundary._inertia_indexed_address_alias_access_evidence_8616 = (
            classify_indexed_alias_accesses_8616(existing)
        )
    return False


__all__ = [
    "apply_x86_16_indexed_address_aliases_8616",
    "project_indexed_address_aliases_8616",
]
