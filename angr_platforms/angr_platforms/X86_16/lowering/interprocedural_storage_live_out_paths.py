"""Prove caller CFG paths from one call output to one memory use.

Layer: Types/Lowering.
Responsibility: classify exact segmented-memory access relationships and require
every caller path reaching one candidate LOAD to preserve the same CALL_OUTPUT.
This module consumes canonical function SSA and exact Alias/Types storage facts;
it does not infer storage, mutate prototypes, structure control flow, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir import AddressStatus, IRAddress, IRInstr, MemSpace
from ..ir.ssa import SSABlock
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import StorageIdentity8616, StorageUseEvidence8616
from .interprocedural_storage_live_out_contracts import MemoryLiveOutFailureKind8616
from .interprocedural_storage_return_defs import CallOutputDefinitionResult8616

__all__ = [
    "MemoryAccessRelation8616",
    "MemoryLiveOutPathResult8616",
    "MemoryLiveOutPathVerdict8616",
    "memory_access_relation_8616",
    "memory_live_out_path_failure_8616",
    "prove_memory_live_out_path_8616",
]


class MemoryAccessRelation8616(StrEnum):
    """Relationship between one IR memory access and an exact output range."""

    DISJOINT = "disjoint"
    EXACT = "exact"
    OVERLAP = "overlap"
    UNKNOWN = "unknown"


class MemoryLiveOutPathVerdict8616(StrEnum):
    """Universal result for paths that can reach one candidate memory use."""

    CLEAN = "clean"
    OVERWRITTEN = "overwritten"
    NOT_REACHED = "not_reached"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class MemoryLiveOutPathResult8616:
    """One closed universal path verdict or its stable refusal reason."""

    verdict: MemoryLiveOutPathVerdict8616
    failure: MemoryLiveOutFailureKind8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether the verdict and refusal fields agree."""
        return (self.verdict is MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE) == (
            self.failure is not None
        )


_FAILURE_PRIORITY_8616 = (
    MemoryLiveOutFailureKind8616.INTERVENING_ALIAS,
    MemoryLiveOutFailureKind8616.INTERVENING_CALL,
    MemoryLiveOutFailureKind8616.INTERVENING_WRITE,
    MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
    MemoryLiveOutFailureKind8616.CFG_CYCLE,
)


def memory_access_relation_8616(
    instruction: IRInstr,
    storage: StorageIdentity8616,
) -> MemoryAccessRelation8616:
    """Classify one LOAD/STORE against exact segmented storage."""
    address = instruction.args[0] if instruction.args else None
    target = storage.address
    if not isinstance(address, IRAddress) or target is None:
        return MemoryAccessRelation8616.UNKNOWN
    if address.space is MemSpace.SS or (
        address.space in {MemSpace.DS, MemSpace.ES} and address.space is not target.space
    ):
        return MemoryAccessRelation8616.DISJOINT
    if address.space is not target.space:
        return MemoryAccessRelation8616.UNKNOWN
    if address.base or address.status is not AddressStatus.STABLE or address.size <= 0:
        return MemoryAccessRelation8616.UNKNOWN
    overlaps = (
        address.offset < target.offset + target.size
        and target.offset < address.offset + address.size
    )
    if not overlaps:
        return MemoryAccessRelation8616.DISJOINT
    if (
        address.offset == target.offset
        and address.size == target.size
        and instruction.size == storage.width
    ):
        return MemoryAccessRelation8616.EXACT
    return MemoryAccessRelation8616.OVERLAP


def _validated_cfg_8616(
    artifact: SSAFunctionArtifact,
) -> tuple[dict[int, SSABlock], dict[int, tuple[int, ...]]] | None:
    """Return exact block and successor maps when the CFG census closes."""
    blocks = {block.addr: block for block in artifact.blocks}
    if len(blocks) != len(artifact.blocks) or set(artifact.predecessor_map) != set(blocks):
        return None
    successors: dict[int, set[int]] = {address: set() for address in blocks}
    for successor, predecessors in artifact.predecessor_map.items():
        if any(predecessor not in blocks for predecessor in predecessors):
            return None
        for predecessor in predecessors:
            successors[predecessor].add(successor)
    return blocks, {
        address: tuple(sorted(values)) for address, values in successors.items()
    }


def _target_reaching_blocks_8616(
    predecessor_map: dict[int, tuple[int, ...]],
    target_block_addr: int,
) -> frozenset[int]:
    """Return blocks on at least one reverse CFG path to the target block."""
    reaching = {target_block_addr}
    pending = [target_block_addr]
    while pending:
        block_addr = pending.pop()
        for predecessor in predecessor_map[block_addr]:
            if predecessor not in reaching:
                reaching.add(predecessor)
                pending.append(predecessor)
    return frozenset(reaching)


def memory_live_out_path_failure_8616(
    results: tuple[MemoryLiveOutPathResult8616, ...],
) -> MemoryLiveOutFailureKind8616 | None:
    """Select the deterministic highest-priority refusal from path results."""
    failures: set[MemoryLiveOutFailureKind8616] = {
        result.failure for result in results if result.failure is not None
    }
    prioritized = next(
        (failure for failure in _FAILURE_PRIORITY_8616 if failure in failures),
        None,
    )
    return prioritized or min(failures, key=lambda failure: failure.value, default=None)


def _aggregate_results_8616(
    results: tuple[MemoryLiveOutPathResult8616, ...],
) -> MemoryLiveOutPathResult8616:
    """Join all target-reaching successor results without short-circuiting."""
    failure = memory_live_out_path_failure_8616(results)
    if failure is not None:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            failure,
        )
    verdicts = {result.verdict for result in results}
    if {
        MemoryLiveOutPathVerdict8616.CLEAN,
        MemoryLiveOutPathVerdict8616.OVERWRITTEN,
    } <= verdicts:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.INTERVENING_WRITE,
        )
    if MemoryLiveOutPathVerdict8616.CLEAN in verdicts:
        return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.CLEAN)
    if MemoryLiveOutPathVerdict8616.OVERWRITTEN in verdicts:
        return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.OVERWRITTEN)
    return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.NOT_REACHED)


def prove_memory_live_out_path_8616(
    artifact: SSAFunctionArtifact,
    definition: CallOutputDefinitionResult8616,
    storage: StorageIdentity8616,
    target: StorageUseEvidence8616,
) -> MemoryLiveOutPathResult8616:
    """Require every CFG path reaching ``target`` to preserve CALL_OUTPUT."""
    if not definition.complete or len(definition.definitions) != 1 or not storage.is_exact:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED,
        )
    producer = definition.definitions[0]
    if producer.source_storage != storage or producer.instr_addr != target.callsite_addr:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED,
        )
    cfg = _validated_cfg_8616(artifact)
    if cfg is None:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
        )
    blocks, successors = cfg
    target_block = blocks.get(target.block_addr)
    target_instruction = (
        target_block.instrs[target.instr_index]
        if target_block is not None and 0 <= target.instr_index < len(target_block.instrs)
        else None
    )
    if (
        target_block is None
        or target_instruction is None
        or target_instruction.op != "LOAD"
        or target_instruction.addr != target.instr_addr
    ):
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
        )
    target_reaching = _target_reaching_blocks_8616(
        artifact.predecessor_map,
        target.block_addr,
    )
    if producer.block_addr not in target_reaching:
        return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.NOT_REACHED)
    target_site = (target.block_addr, target.instr_index)
    visiting: set[tuple[int, int]] = set()
    memo: dict[tuple[int, int], MemoryLiveOutPathResult8616] = {}

    def _visit(state: tuple[int, int]) -> MemoryLiveOutPathResult8616:
        cached = memo.get(state)
        if cached is not None:
            return cached
        if state in visiting:
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.CFG_CYCLE,
            )
        block = blocks.get(state[0])
        if block is None or not 0 <= state[1] <= len(block.instrs):
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
            )
        visiting.add(state)
        result: MemoryLiveOutPathResult8616 | None = None
        for index in range(state[1], len(block.instrs)):
            if (block.addr, index) == target_site:
                result = MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.CLEAN)
                break
            instruction = block.instrs[index]
            if instruction.op == "CALL":
                result = MemoryLiveOutPathResult8616(
                    MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                    MemoryLiveOutFailureKind8616.INTERVENING_CALL,
                )
                break
            if instruction.op not in {"LOAD", "STORE"}:
                continue
            relation = memory_access_relation_8616(instruction, storage)
            if relation is MemoryAccessRelation8616.UNKNOWN:
                result = MemoryLiveOutPathResult8616(
                    MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                    MemoryLiveOutFailureKind8616.INTERVENING_ALIAS,
                )
                break
            if instruction.op == "STORE" and relation is MemoryAccessRelation8616.OVERLAP:
                result = MemoryLiveOutPathResult8616(
                    MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                    MemoryLiveOutFailureKind8616.INTERVENING_WRITE,
                )
                break
            if instruction.op == "STORE" and relation is MemoryAccessRelation8616.EXACT:
                result = MemoryLiveOutPathResult8616(
                    MemoryLiveOutPathVerdict8616.OVERWRITTEN
                )
                break
        if result is None:
            next_results = tuple(
                _visit((successor, 0))
                for successor in successors[block.addr]
                if successor in target_reaching
            )
            result = _aggregate_results_8616(next_results)
        visiting.remove(state)
        memo[state] = result
        return result

    return _visit((producer.block_addr, producer.instr_index + 1))
