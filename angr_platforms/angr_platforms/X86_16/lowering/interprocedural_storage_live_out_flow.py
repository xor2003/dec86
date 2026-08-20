"""Prove and materialize one direct segmented-memory live-out use.

Layer: Types/Lowering.
Responsibility: bind one Semantics output to CALL_OUTPUT, prove an unclobbered
caller CFG path, classify ConditionIR, and build one provisional LIVE_OUT trial.
Function censuses stay outside. Only ConditionIR-attributed access instructions
activate evidence; JCC replay loads and absent direct uses do not become facts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from enum import StrEnum
from operator import attrgetter
from typing import TypeAlias

from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace
from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputFact8616,
)
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_live_out_contracts import (
    MemoryLiveOutCandidateResult8616,
    MemoryLiveOutFailureKind8616,
    MemoryLiveOutUseDisposition8616,
    MemoryLiveOutUseFact8616,
)
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionResult8616,
    CallOutputDefinitionVerdict8616,
    resolve_storage_call_output_definitions_8616,
)


class _AccessRelation8616(StrEnum):
    """Relationship between one IR memory access and an exact output range."""

    DISJOINT = "disjoint"
    EXACT = "exact"
    OVERLAP = "overlap"
    UNKNOWN = "unknown"


_PathResult8616: TypeAlias = tuple[bool, frozenset[MemoryLiveOutFailureKind8616]]


def _access_relation_8616(instruction: IRInstr, storage: StorageIdentity8616) -> _AccessRelation8616:
    """Classify one LOAD/STORE against exact segmented storage."""
    address = instruction.args[0] if instruction.args else None
    target = storage.address
    if not isinstance(address, IRAddress) or target is None:
        return _AccessRelation8616.UNKNOWN
    if address.space is MemSpace.SS or (
        address.space in {MemSpace.DS, MemSpace.ES} and address.space is not target.space
    ):
        return _AccessRelation8616.DISJOINT
    if address.space is not target.space:
        return _AccessRelation8616.UNKNOWN
    if address.base or address.status is not AddressStatus.STABLE or address.size <= 0:
        return _AccessRelation8616.UNKNOWN
    overlaps = address.offset < target.offset + target.size and target.offset < address.offset + address.size
    if not overlaps:
        return _AccessRelation8616.DISJOINT
    if address.offset == target.offset and address.size == target.size and instruction.size == storage.width:
        return _AccessRelation8616.EXACT
    return _AccessRelation8616.OVERLAP


def _successors_8616(artifact: SSAFunctionArtifact) -> dict[int, tuple[int, ...]] | None:
    """Invert the authoritative predecessor map after exact census checks."""
    blocks = {block.addr for block in artifact.blocks}
    if set(artifact.predecessor_map) != blocks:
        return None
    successors: dict[int, set[int]] = {address: set() for address in blocks}
    for successor, predecessors in artifact.predecessor_map.items():
        if any(predecessor not in blocks for predecessor in predecessors):
            return None
        for predecessor in predecessors:
            successors[predecessor].add(successor)
    return {address: tuple(sorted(values)) for address, values in successors.items()}


def _related_loads_8616(
    artifact: SSAFunctionArtifact, storage: StorageIdentity8616, callsite_addr: int,
) -> tuple[tuple[StorageUseEvidence8616, ...], tuple[StorageUseEvidence8616, ...]]:
    """Return exact and overlapping direct LOAD candidates in caller SSA."""
    exact: list[StorageUseEvidence8616] = []
    overlap: list[StorageUseEvidence8616] = []
    for block in artifact.blocks:
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "LOAD" or instruction.addr is None:
                continue
            relation = _access_relation_8616(instruction, storage)
            use = StorageUseEvidence8616(block.addr, instr_index, instruction.addr, callsite_addr)
            if relation is _AccessRelation8616.EXACT:
                exact.append(use)
            elif relation is _AccessRelation8616.OVERLAP:
                overlap.append(use)
    order = attrgetter("block_addr", "instr_index", "instr_addr")
    return tuple(sorted(exact, key=order)), tuple(sorted(overlap, key=order))


def _clean_path_8616(
    artifact: SSAFunctionArtifact,
    successors: dict[int, tuple[int, ...]],
    definition: CallOutputDefinitionResult8616,
    storage: StorageIdentity8616,
    target: StorageUseEvidence8616,
) -> _PathResult8616:
    """Prove one path from CALL_OUTPUT to a load without intervening ambiguity."""
    producer = definition.definitions[0]
    blocks = {block.addr: block for block in artifact.blocks}
    target_site = (target.block_addr, target.instr_index)
    blockers: set[MemoryLiveOutFailureKind8616] = set()
    visiting: set[tuple[int, int]] = set()
    memo: dict[tuple[int, int], bool] = {}

    def _visit(state: tuple[int, int]) -> bool:
        if state in memo:
            return memo[state]
        if state in visiting:
            blockers.add(MemoryLiveOutFailureKind8616.CFG_CYCLE)
            return False
        block = blocks.get(state[0])
        if block is None or not 0 <= state[1] <= len(block.instrs):
            blockers.add(MemoryLiveOutFailureKind8616.CFG_INCOMPLETE)
            return False
        visiting.add(state)
        reached = blocked = False
        for index in range(state[1], len(block.instrs)):
            if (block.addr, index) == target_site:
                reached = True
                break
            instruction = block.instrs[index]
            if instruction.op == "CALL":
                blockers.add(MemoryLiveOutFailureKind8616.INTERVENING_CALL)
                blocked = True
                break
            if instruction.op not in {"LOAD", "STORE"}:
                continue
            relation = _access_relation_8616(instruction, storage)
            if relation is _AccessRelation8616.UNKNOWN:
                blockers.add(MemoryLiveOutFailureKind8616.INTERVENING_ALIAS)
                blocked = True
                break
            if instruction.op == "STORE" and relation in {
                _AccessRelation8616.EXACT,
                _AccessRelation8616.OVERLAP,
            }:
                blocked = True
                break
        if not reached and not blocked:
            reached = any(_visit((successor, 0)) for successor in successors[block.addr])
        visiting.remove(state)
        memo[state] = reached
        return reached

    start = (producer.block_addr, producer.instr_index + 1)
    return _visit(start), frozenset(blockers)


def _value_matches_8616(value: object, storage: StorageIdentity8616, use: StorageUseEvidence8616) -> bool:
    """Match one canonical condition operand to one exact direct LOAD."""
    address = storage.address
    return bool(
        isinstance(value, IRValue)
        and address is not None
        and value.space is address.space
        and value.offset == address.offset
        and value.size == storage.width
        and value.memory_access_insn == use.instr_addr
    )


def _condition_for_use_8616(
    conditions: tuple[ConditionIR, ...], storage: StorageIdentity8616, use: StorageUseEvidence8616,
) -> tuple[ConditionIR | None, StorageTrialSignedness8616 | None, MemoryLiveOutFailureKind8616 | None]:
    """Select one canonical direct-memory condition and its exact sign class."""
    matching: list[ConditionIR] = []
    for condition in conditions:
        operands = (condition.lhs,) if condition.is_zero_test else (condition.lhs, condition.rhs)
        if condition.width_bits == storage.width * 8 and sum(
            _value_matches_8616(operand, storage, use) for operand in operands
        ) == 1 and condition not in matching:
            matching.append(condition)
    if not matching:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_NOT_FOUND
    if len(matching) != 1:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_CONFLICT
    condition = matching[0]
    signedness = (
        StorageTrialSignedness8616.SIGNED
        if condition.is_signed
        else StorageTrialSignedness8616.UNSIGNED
        if condition.is_unsigned
        else StorageTrialSignedness8616.SIGN_INSENSITIVE
        if condition.op in {"eq", "ne", "zero", "nonzero"}
        else None
    )
    if signedness is None:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_UNSUPPORTED
    return condition, signedness, None


def materialize_memory_live_out_candidate_8616(
    artifact: SSAFunctionArtifact,
    output: TerminalMemoryOutputFact8616,
    caller_addr: int,
    callee_addr: int,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
    conditions: tuple[ConditionIR, ...],
) -> MemoryLiveOutCandidateResult8616:
    """Materialize one activated direct-memory output candidate or refuse."""
    storage = StorageIdentity8616(
        StorageIdentityKind8616.MEMORY, output.address.size, output.address
    )
    exact_loads, overlapping_loads = _related_loads_8616(artifact, storage, callsite_addr)
    condition_candidates: list[
        tuple[
            StorageUseEvidence8616,
            ConditionIR | None,
            StorageTrialSignedness8616 | None,
            MemoryLiveOutFailureKind8616 | None,
        ]
    ] = []
    for use in exact_loads:
        condition, signedness, failure = _condition_for_use_8616(conditions, storage, use)
        if failure is not MemoryLiveOutFailureKind8616.CONDITION_NOT_FOUND:
            condition_candidates.append((use, condition, signedness, failure))
    if not condition_candidates and not overlapping_loads:
        return MemoryLiveOutCandidateResult8616(False)
    if not storage.is_exact:
        raise RuntimeError("Semantics published an inexact direct-memory output")
    definitions = resolve_storage_call_output_definitions_8616(
        artifact,
        caller_addr,
        callsite_addr,
        callee_addr,
        accepted_target_addrs,
        (storage,),
    )
    if not definitions.complete:
        conflict = definitions.verdict is CallOutputDefinitionVerdict8616.CONFLICT
        return MemoryLiveOutCandidateResult8616(
            True,
            failure=(
                MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT
                if conflict
                else MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED
            ),
            definition_failure=definitions.failure,
        )
    successors = _successors_8616(artifact)
    if successors is None:
        return MemoryLiveOutCandidateResult8616(
            True, failure=MemoryLiveOutFailureKind8616.CFG_INCOMPLETE
        )
    if any(
        _clean_path_8616(artifact, successors, definitions, storage, use)[0]
        for use in overlapping_loads
    ):
        return MemoryLiveOutCandidateResult8616(
            True, failure=MemoryLiveOutFailureKind8616.USE_OVERLAP
        )
    paths = tuple(
        (candidate, _clean_path_8616(artifact, successors, definitions, storage, candidate[0]))
        for candidate in condition_candidates
    )
    clean_candidates = tuple(candidate for candidate, path in paths if path[0])
    if not clean_candidates:
        blockers = frozenset(blocker for _candidate, path in paths for blocker in path[1])
        failure = next(
            (
                kind
                for kind in (
                    MemoryLiveOutFailureKind8616.INTERVENING_ALIAS,
                    MemoryLiveOutFailureKind8616.INTERVENING_CALL,
                    MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
                    MemoryLiveOutFailureKind8616.CFG_CYCLE,
                )
                if kind in blockers
            ),
            None,
        )
        if failure is not None:
            return MemoryLiveOutCandidateResult8616(True, failure=failure)
        fact = MemoryLiveOutUseFact8616(storage, MemoryLiveOutUseDisposition8616.NOT_REACHED)
        return MemoryLiveOutCandidateResult8616(True, fact=fact)
    if output.disposition is TerminalMemoryOutputDisposition8616.CONDITIONAL:
        return MemoryLiveOutCandidateResult8616(
            True, failure=MemoryLiveOutFailureKind8616.CONDITIONAL_WRITE
        )
    typed: list[tuple[StorageUseEvidence8616, ConditionIR, StorageTrialSignedness8616]] = []
    for use, condition, signedness, failure in clean_candidates:
        if failure is not None or condition is None or signedness is None:
            return MemoryLiveOutCandidateResult8616(
                True,
                failure=failure or MemoryLiveOutFailureKind8616.CONDITION_UNSUPPORTED,
            )
        typed.append((use, condition, signedness))
    if len({item[2] for item in typed}) != 1:
        return MemoryLiveOutCandidateResult8616(
            True, failure=MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT
        )
    use, condition, signedness = typed[0]
    provenance = definitions.provenance
    if provenance is None:
        raise RuntimeError("complete CALL_OUTPUT lost provenance")
    fact = MemoryLiveOutUseFact8616(
        storage, MemoryLiveOutUseDisposition8616.USED, use, signedness, condition
    )
    trial = StorageTrial8616(
        callee_addr=callee_addr,
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        role=StorageTrialRole8616.LIVE_OUT,
        logical_index=0,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=definitions.definitions[0],
        use=use,
        signedness=signedness,
        value_class=StorageTrialValueClass8616.VALUE,
        provenance=provenance,
    )
    return MemoryLiveOutCandidateResult8616(True, fact=fact, trial=trial)
