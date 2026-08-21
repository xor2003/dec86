"""Collect exact indexed LOAD-to-STORE value-copy evidence.

Layer: IR.
Responsibility: classify every proven indexed STORE through normalized member
ownership and exact byte-lane SSA paths, retaining all non-copy outcomes as
typed refusals. Alias identity, aggregate families, bounds, types, names, and
rendered expressions are out of scope.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .indexed_address_access_normalization import (
    NormalizedIndexedAddressAccess8616,
    normalize_indexed_address_accesses_8616,
)
from .indexed_address_contracts import (
    IndexedAddressAccessKind8616,
    IndexedAddressEvidence8616,
    IndexedAddressFact8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyEvidence8616,
    IndexedAddressCopyFact8616,
    IndexedAddressCopyFailureKind8616,
    IndexedAddressCopyLane8616,
    IndexedAddressCopyRefusal8616,
    IndexedAddressCopyStats8616,
    IndexedAddressCopyValuePath8616,
)
from .indexed_address_copy_trace import (
    IndexedAddressCopyPathRefusal8616,
    order_indexed_store_members_8616,
    trace_indexed_store_member_8616,
)
from .scalar_definitions import (
    ScalarDefinitionIndex8616,
    build_scalar_definition_index_8616,
)
from .ssa import SSABlock
from .ssa_function import SSAFunctionArtifact


def _source_fact_8616(
    evidence: IndexedAddressEvidence8616,
    path: IndexedAddressCopyValuePath8616,
) -> IndexedAddressFact8616 | IndexedAddressCopyFailureKind8616:
    """Resolve one path endpoint to exactly one indexed LOAD fact."""
    matches = tuple(
        fact
        for fact in evidence.facts
        if fact.kind is IndexedAddressAccessKind8616.LOAD
        and fact.block_addr == path.load_block_addr
        and fact.instr_index == path.load_instr_index
        and fact.instr_addr == path.load_instr_addr
    )
    if not matches:
        return IndexedAddressCopyFailureKind8616.SOURCE_LOAD_NOT_INDEXED
    if len(matches) != 1:
        return IndexedAddressCopyFailureKind8616.SOURCE_LOAD_CONFLICT
    return matches[0]


def _copy_or_refusal_8616(
    destination: IndexedAddressFact8616,
    access: NormalizedIndexedAddressAccess8616,
    block: SSABlock,
    definitions: ScalarDefinitionIndex8616,
    evidence: IndexedAddressEvidence8616,
) -> IndexedAddressCopyFact8616 | IndexedAddressCopyRefusal8616:
    """Classify one normalized indexed STORE without inferring Alias identity."""
    members = order_indexed_store_members_8616(block, access)
    if members is None or len(members) not in {1, 2}:
        return IndexedAddressCopyRefusal8616(
            destination,
            IndexedAddressCopyFailureKind8616.NORMALIZED_STORE_CONFLICT,
            "normalized STORE members are not one direct access or little-endian pair",
        )
    lanes = (
        (IndexedAddressCopyLane8616.DIRECT,)
        if len(members) == 1
        else (
            IndexedAddressCopyLane8616.LOW_BYTE,
            IndexedAddressCopyLane8616.HIGH_BYTE,
        )
    )
    paths: list[IndexedAddressCopyValuePath8616] = []
    for instr_index, lane in zip(members, lanes, strict=True):
        path = trace_indexed_store_member_8616(
            block,
            instr_index,
            lane,
            definitions,
        )
        if isinstance(path, IndexedAddressCopyPathRefusal8616):
            return IndexedAddressCopyRefusal8616(
                destination,
                path.failure,
                path.detail,
            )
        paths.append(path)
    load_sites = {
        (path.load_block_addr, path.load_instr_index, path.load_instr_addr)
        for path in paths
    }
    if len(load_sites) != 1:
        return IndexedAddressCopyRefusal8616(
            destination,
            IndexedAddressCopyFailureKind8616.SPLIT_LANE_CONFLICT,
            "normalized STORE lanes do not converge on one exact LOAD",
        )
    source = _source_fact_8616(evidence, paths[0])
    if isinstance(source, IndexedAddressCopyFailureKind8616):
        return IndexedAddressCopyRefusal8616(
            destination,
            source,
            "value-path endpoint does not identify one indexed LOAD fact",
        )
    if source.address.size != destination.address.size:
        return IndexedAddressCopyRefusal8616(
            destination,
            IndexedAddressCopyFailureKind8616.VALUE_WIDTH_CONFLICT,
            "indexed LOAD and STORE widths differ",
        )
    result = IndexedAddressCopyFact8616(source, destination, members, tuple(paths))
    if not result.complete:
        return IndexedAddressCopyRefusal8616(
            destination,
            IndexedAddressCopyFailureKind8616.SPLIT_LANE_CONFLICT,
            "indexed LOAD-to-STORE proof is internally inconsistent",
        )
    return result


def collect_indexed_address_copy_evidence_8616(
    artifact: SSAFunctionArtifact,
    evidence: IndexedAddressEvidence8616,
) -> IndexedAddressCopyEvidence8616:
    """Classify every proven indexed STORE as one exact copy or refusal."""
    if not evidence.closed or artifact.function_addr != evidence.function_addr:
        raise ValueError("indexed copy collection requires matching closed IR evidence")
    definitions = build_scalar_definition_index_8616(artifact)
    normalization = normalize_indexed_address_accesses_8616(artifact)
    blocks = {block.addr: block for block in artifact.blocks}
    normalized_stores: dict[
        tuple[int, int, int], list[NormalizedIndexedAddressAccess8616]
    ] = {}
    for access in normalization.accesses:
        if access.op != "STORE":
            continue
        key = (access.block_addr, access.instr_index, access.instr_addr)
        normalized_stores.setdefault(key, []).append(access)
    facts: list[IndexedAddressCopyFact8616] = []
    refusals: list[IndexedAddressCopyRefusal8616] = []
    destinations = tuple(
        fact
        for fact in evidence.facts
        if fact.kind is IndexedAddressAccessKind8616.STORE
    )
    for destination in destinations:
        key = (
            destination.block_addr,
            destination.instr_index,
            destination.instr_addr,
        )
        matches = tuple(normalized_stores.get(key, ()))
        block = blocks.get(destination.block_addr)
        if not matches or block is None:
            refusals.append(
                IndexedAddressCopyRefusal8616(
                    destination,
                    IndexedAddressCopyFailureKind8616.NORMALIZED_STORE_MISSING,
                    "indexed STORE has no exact normalized IR owner",
                )
            )
            continue
        if len(matches) != 1:
            refusals.append(
                IndexedAddressCopyRefusal8616(
                    destination,
                    IndexedAddressCopyFailureKind8616.NORMALIZED_STORE_CONFLICT,
                    "indexed STORE has multiple normalized IR owners",
                )
            )
            continue
        classified = _copy_or_refusal_8616(
            destination,
            matches[0],
            block,
            definitions,
            evidence,
        )
        if isinstance(classified, IndexedAddressCopyRefusal8616):
            refusals.append(classified)
        else:
            facts.append(classified)
    result = IndexedAddressCopyEvidence8616(
        evidence.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAddressCopyStats8616(
            raw_fact_count=len(destinations),
            normalized_fact_count=len(facts),
            classified_fact_count=len(facts),
            materialized_count=len(facts),
            failure_count=len(refusals),
        ),
        evidence,
    )
    if not result.closed:
        raise ValueError("indexed LOAD-to-STORE value-path accounting did not close")
    return result


__all__ = ["collect_indexed_address_copy_evidence_8616"]
