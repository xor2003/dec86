"""Trace returned pointer carriers through typed caller CFG and phi facts.

Layer: Types/Lowering.
Responsibility: converge block-local pointer carriers across complete in-function
CFG edges and exact all-predecessor register phi joins until a stable segmented
dereference proves pointer class.
Consumes alias, widening, and typed facts.
Consumes Alias-owned domains, typed SSA, and block-transfer facts. This module
does not repair CFG or SSA, infer arithmetic aliases, mutate codegen, or inspect
Structuring output.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..alias.domains import AX, DomainKey
from ..caller_return_use_contracts import CallerReturnUseFact8616
from ..ir.ssa_function import SSAFunctionArtifact, SSAPhiNode
from ..widening.stack_word_register_transfers import StackWordStorageVersion8616
from .interprocedural_storage_return_pointer_block import (
    PointerCarrier8616,
    append_unique_pointer_proofs_8616,
    full_word_pointer_domain_8616,
    pointer_witness_seed_values_8616,
    scan_pointer_carriers_in_block_8616,
)
from .interprocedural_storage_return_pointer_stack import (
    build_pointer_stack_transfer_context_8616,
    join_pointer_stack_carriers_8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnPointerAliasStep8616,
    ReturnPointerCfgEdge8616,
    ReturnPointerFlowScan8616,
    ReturnPointerPhiEvidence8616,
    ReturnPointerUseEvidence8616,
    ReturnStorageTypeFailure8616,
)

__all__ = ["scan_pointer_return_flow_8616"]


def _phi_for_domain_8616(
    artifact: SSAFunctionArtifact,
    block_addr: int,
    domain: DomainKey,
) -> tuple[SSAPhiNode, ...]:
    """Return exact register phi candidates for one join and Alias domain."""
    return tuple(
        phi
        for phi in artifact.phi_nodes
        if phi.block_addr == block_addr and full_word_pointer_domain_8616(phi.target) == domain
    )


def _join_carriers_8616(
    artifact: SSAFunctionArtifact,
    block_addr: int,
    predecessors: tuple[int, ...],
    outputs: dict[int, dict[DomainKey, PointerCarrier8616]],
) -> tuple[dict[DomainKey, PointerCarrier8616], bool, bool]:
    """Join only carriers proven on every predecessor and exact phi input."""
    if not predecessors or any(predecessor not in outputs for predecessor in predecessors):
        return {}, True, False
    domain_sets = tuple(set(outputs[predecessor]) for predecessor in predecessors)
    common = set.intersection(*domain_sets)
    join_conflict = bool(set.union(*domain_sets) - common)
    joined: dict[DomainKey, PointerCarrier8616] = {}
    phi_conflict = False
    for domain in sorted(common, key=lambda item: item.name):
        incoming_carriers = tuple(outputs[pred][domain] for pred in predecessors)
        phi_candidates = _phi_for_domain_8616(artifact, block_addr, domain)
        if len(phi_candidates) > 1:
            phi_conflict = True
            continue
        phi_evidence: ReturnPointerPhiEvidence8616 | None = None
        if phi_candidates:
            phi = phi_candidates[0]
            expected = tuple(
                (predecessor, carrier.value)
                for predecessor, carrier in zip(
                    predecessors,
                    incoming_carriers,
                    strict=True,
                )
            )
            actual = tuple((item.source_block_addr, item.value) for item in phi.incoming)
            phi_evidence = ReturnPointerPhiEvidence8616(
                block_addr=block_addr,
                carrier_register=phi.target.name or "",
                target=phi.target,
                incoming=phi.incoming,
            )
            if actual != expected or not phi_evidence.complete:
                phi_conflict = True
                continue
            value = phi.target
        else:
            value = incoming_carriers[0].value
            if any(carrier.value != value for carrier in incoming_carriers[1:]):
                phi_conflict = True
                continue
        aliases: tuple[ReturnPointerAliasStep8616, ...] = ()
        edges: tuple[ReturnPointerCfgEdge8616, ...] = ()
        phis: tuple[ReturnPointerPhiEvidence8616, ...] = ()
        for predecessor, carrier in zip(predecessors, incoming_carriers, strict=True):
            aliases = append_unique_pointer_proofs_8616(aliases, carrier.aliases)
            edges = append_unique_pointer_proofs_8616(edges, carrier.cfg_edges)
            edges = append_unique_pointer_proofs_8616(
                edges,
                (
                    ReturnPointerCfgEdge8616(
                        source_block_addr=predecessor,
                        target_block_addr=block_addr,
                        carrier_register=carrier.value.name or "",
                        value=carrier.value,
                    ),
                ),
            )
            phis = append_unique_pointer_proofs_8616(phis, carrier.phis)
        if phi_evidence is not None:
            phis = append_unique_pointer_proofs_8616(phis, (phi_evidence,))
        joined[domain] = PointerCarrier8616(
            value=value,
            aliases=aliases,
            cfg_edges=edges,
            phis=phis,
            stack_transfers=append_unique_pointer_proofs_8616(
                (),
                tuple(
                    transfer
                    for carrier in incoming_carriers
                    for transfer in carrier.stack_transfers
                ),
            ),
        )
    return joined, join_conflict, phi_conflict


def _successors_8616(artifact: SSAFunctionArtifact) -> dict[int, tuple[int, ...]]:
    """Invert the authoritative predecessor map deterministically."""
    successors: dict[int, list[int]] = {block.addr: [] for block in artifact.blocks}
    for target, predecessors in artifact.predecessor_map.items():
        for predecessor in predecessors:
            if predecessor in successors:
                successors[predecessor].append(target)
    return {addr: tuple(sorted(set(targets))) for addr, targets in successors.items()}


def _reachable_blocks_8616(
    start_addr: int,
    successors: dict[int, tuple[int, ...]],
) -> set[int]:
    """Return the deterministic in-function CFG reachability set."""
    reachable = {start_addr}
    frontier = [start_addr]
    while frontier:
        source = frontier.pop(0)
        for target in successors[source]:
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    return reachable


def _has_cycle_8616(
    reachable: set[int],
    successors: dict[int, tuple[int, ...]],
) -> bool:
    """Return whether the reachable CFG requires an unsupported fixed point."""
    remaining_predecessors = {
        block_addr: sum(source in reachable and block_addr in successors[source] for source in reachable)
        for block_addr in reachable
    }
    ready = sorted(block_addr for block_addr, count in remaining_predecessors.items() if count == 0)
    removed = 0
    while ready:
        source = ready.pop(0)
        removed += 1
        for target in successors[source]:
            if target not in remaining_predecessors:
                continue
            remaining_predecessors[target] -= 1
            if remaining_predecessors[target] == 0:
                ready.append(target)
                ready.sort()
    return removed != len(reachable)


def _failure_8616(
    *,
    ambiguous: bool,
    unknown: bool,
    phi: bool,
    join: bool,
    clobber: bool,
) -> ReturnStorageTypeFailure8616:
    """Select the most specific deterministic pointer-flow refusal."""
    if ambiguous:
        return ReturnStorageTypeFailure8616.POINTER_ADDRESS_AMBIGUOUS
    if unknown:
        return ReturnStorageTypeFailure8616.POINTER_ADDRESS_UNKNOWN
    if phi:
        return ReturnStorageTypeFailure8616.POINTER_PHI_CONFLICT
    if join:
        return ReturnStorageTypeFailure8616.POINTER_CFG_JOIN_CONFLICT
    if clobber:
        return ReturnStorageTypeFailure8616.POINTER_ALIAS_CLOBBERED
    return ReturnStorageTypeFailure8616.POINTER_DEREFERENCE_NOT_FOUND


def scan_pointer_return_flow_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
) -> ReturnPointerFlowScan8616:
    """Trace one exact returned pointer through acyclic CFG and phi evidence."""
    witness = fact.witness_instruction_addr
    candidates = tuple(
        block for block in artifact.blocks if witness is not None and pointer_witness_seed_values_8616(block, witness)
    )
    if not candidates:
        return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_WITNESS_NOT_FOUND)
    if len(candidates) != 1 or witness is None:
        return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_WITNESS_CONFLICT)
    block = candidates[0]
    seeds = pointer_witness_seed_values_8616(block, witness)
    if len(seeds) != 1:
        return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_WITNESS_CONFLICT)
    stack_context = build_pointer_stack_transfer_context_8616(artifact)
    start_indices = tuple(index for index, instruction in enumerate(block.instrs) if instruction.addr == witness)
    if not start_indices:
        return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_WITNESS_NOT_FOUND)
    start = scan_pointer_carriers_in_block_8616(
        block,
        fact,
        {AX: PointerCarrier8616(seeds[0])},
        {},
        stack_context.by_instruction_addr,
        start_indices[0],
        witness,
    )
    if start.evidence is not None:
        return ReturnPointerFlowScan8616(evidence=start.evidence)

    block_by_addr = {item.addr: item for item in artifact.blocks}
    block_addrs = set(block_by_addr)
    if set(artifact.predecessor_map) != block_addrs or any(
        predecessor not in block_addrs
        for predecessors in artifact.predecessor_map.values()
        for predecessor in predecessors
    ):
        return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_CFG_INCOMPLETE)
    successors = _successors_8616(artifact)
    reachable = _reachable_blocks_8616(block.addr, successors)
    if _has_cycle_8616(reachable, successors):
        return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_CFG_CYCLE)

    outputs = {block.addr: start.carriers}
    stack_outputs: dict[
        int,
        dict[StackWordStorageVersion8616, PointerCarrier8616],
    ] = {block.addr: start.stack_carriers}
    pending = reachable - {block.addr}
    evidence: list[ReturnPointerUseEvidence8616] = []
    ambiguous = start.saw_ambiguous_address
    unknown = start.saw_unknown_address
    clobber = start.saw_alias_clobber
    join_conflict = False
    phi_conflict = False
    while pending:
        progress = False
        for block_addr in sorted(pending):
            predecessors = artifact.predecessor_map[block_addr]
            if any(predecessor not in outputs for predecessor in predecessors):
                continue
            entry, joined_bad, phi_bad = _join_carriers_8616(
                artifact,
                block_addr,
                predecessors,
                outputs,
            )
            stack_entry, stack_join_bad = join_pointer_stack_carriers_8616(
                predecessors,
                stack_outputs,
            )
            scan = scan_pointer_carriers_in_block_8616(
                block_by_addr[block_addr],
                fact,
                entry,
                stack_entry,
                stack_context.by_instruction_addr,
                0,
                witness,
            )
            outputs[block_addr] = scan.carriers
            stack_outputs[block_addr] = scan.stack_carriers
            pending.remove(block_addr)
            progress = True
            join_conflict = join_conflict or joined_bad or stack_join_bad
            phi_conflict = phi_conflict or phi_bad
            ambiguous = ambiguous or scan.saw_ambiguous_address
            unknown = unknown or scan.saw_unknown_address
            clobber = clobber or scan.saw_alias_clobber
            if scan.evidence is not None:
                evidence.append(scan.evidence)
        if not progress:
            return ReturnPointerFlowScan8616(failure=ReturnStorageTypeFailure8616.POINTER_CFG_INCOMPLETE)
    if evidence:
        chosen = min(
            evidence,
            key=lambda item: (
                item.dereference_instruction_addr,
                item.carrier_register,
            ),
        )
        return ReturnPointerFlowScan8616(evidence=chosen)
    if not stack_context.complete:
        return ReturnPointerFlowScan8616(
            failure=ReturnStorageTypeFailure8616.POINTER_STACK_EVIDENCE_INCOMPLETE
        )
    return ReturnPointerFlowScan8616(
        failure=_failure_8616(
            ambiguous=ambiguous,
            unknown=unknown,
            phi=phi_conflict,
            join=join_conflict,
            clobber=clobber,
        )
    )
