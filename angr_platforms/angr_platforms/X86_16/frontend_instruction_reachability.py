"""Collect instruction reachability from loaded x86-16 bytes.

Layer: Frontend.
Responsibility: decode bounded basic-block successors and publish a closed
binary reachability census without assigning higher-level semantics.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

__all__ = [
    "DecodedBlockRequest8616",
    "DecodedBlockStatus8616",
    "InstructionReachabilityEvidence8616",
    "collect_instruction_reachability_8616",
    "decoded_block_instructions_8616",
    "x86_16_block_successors_from_capstone_8616",
]


class _OperandBoundary8616(Protocol):
    """Capstone operand fields consumed at the third-party decode boundary."""

    type: int
    imm: object


class _DecodedInstructionBoundary8616(Protocol):
    """Capstone instruction fields consumed by bounded CFG traversal."""

    address: int
    mnemonic: str
    operands: Sequence[_OperandBoundary8616]


class _InstructionBoundary8616(Protocol):
    """angr wrapper fields for one decoded Capstone instruction."""

    address: int
    mnemonic: str
    insn: _DecodedInstructionBoundary8616


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction sequence exposed by an angr block."""

    insns: Sequence[_InstructionBoundary8616]


class _BlockBoundary8616(Protocol):
    """angr block fields consumed by the frontend traversal."""

    addr: int
    size: int
    capstone: _CapstoneBoundary8616


class _FactoryBoundary8616(Protocol):
    """Dynamic angr block factory boundary."""

    def block(
        self,
        addr: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> _BlockBoundary8616:
        """Decode one block at ``addr``."""


class _ProjectBoundary8616(Protocol):
    """Dynamic angr project boundary used by frontend traversal."""

    factory: _FactoryBoundary8616
    _inertia_decoded_block_inventories_8616: dict[
        DecodedBlockRequest8616,
        DecodedBlockEvidence8616,
    ]


@dataclass(frozen=True, slots=True)
class DecodedBlockRequest8616:
    """Exact request identity for one request-local frontend block decode."""

    address: int
    instruction_limit: int | None
    optimization_level: int


class DecodedBlockStatus8616(Enum):
    """Typed outcome of one immutable frontend block decode request."""

    DECODED = "decoded"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class DecodedBlockEvidence8616:
    """Cached instructions or a deterministic decode refusal."""

    request: DecodedBlockRequest8616
    status: DecodedBlockStatus8616
    instructions: tuple[Any, ...]
    failure_type: type[Exception] | None
    failure_message: str | None


def _raise_cached_decode_failure_8616(evidence: DecodedBlockEvidence8616) -> None:
    """Re-raise a cached refusal without retaining a traceback object."""
    failure_type = evidence.failure_type or RuntimeError
    message = evidence.failure_message or "cached x86-16 block decode refusal"
    try:
        failure = failure_type(message)
    except Exception:
        failure = RuntimeError(f"{failure_type.__name__}: {message}")
    raise failure


@dataclass(frozen=True, slots=True)
class InstructionReachabilityEvidence8616:
    """Closed census of bounded binary basic-block reachability."""

    reachable_instruction_addrs: tuple[int, ...]
    unresolved_block_addrs: tuple[int, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every visited block had a resolved successor class."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
            and self.failure_count == 0
            and not self.unresolved_block_addrs
        )


def decoded_block_instructions_8616(
    project: object,
    address: int,
    *,
    num_inst: int | None = None,
    opt_level: int = 0,
) -> tuple[Any, ...]:
    """Decode one exact block request once within an immutable project request.

    The cache retains only third-party Capstone instruction evidence. It does
    not store mutable C AST, semantic state, aliases, prototypes, or validation
    results. Failed decode requests are deliberately not cached.
    """
    boundary = cast(_ProjectBoundary8616, project)
    request = DecodedBlockRequest8616(int(address), num_inst, int(opt_level))
    try:
        inventories = boundary._inertia_decoded_block_inventories_8616
    except AttributeError:
        inventories = {}
        boundary._inertia_decoded_block_inventories_8616 = inventories
    cached = inventories.get(request)
    if cached is not None:
        if cached.status is DecodedBlockStatus8616.DECODED:
            return cached.instructions
        _raise_cached_decode_failure_8616(cached)
    try:
        if num_inst is None:
            block = boundary.factory.block(address, opt_level=opt_level)
        else:
            block = boundary.factory.block(address, num_inst=num_inst, opt_level=opt_level)
    except Exception as exc:
        inventories[request] = DecodedBlockEvidence8616(
            request=request,
            status=DecodedBlockStatus8616.REFUSED,
            instructions=(),
            failure_type=type(exc),
            failure_message=str(exc),
        )
        raise
    instructions = tuple(block.capstone.insns)
    evidence = DecodedBlockEvidence8616(
        request=request,
        status=DecodedBlockStatus8616.DECODED,
        instructions=cast(tuple[Any, ...], instructions),
        failure_type=None,
        failure_message=None,
    )
    inventories[request] = evidence
    return evidence.instructions


def _direct_target_8616(instruction: _InstructionBoundary8616) -> int | None:
    """Return one direct Capstone branch target, if present."""
    try:
        operands = tuple(instruction.insn.operands)
    except (AttributeError, TypeError):
        return None
    for operand in operands:
        if operand.type != 2:
            continue
        target = operand.imm
        if isinstance(target, int):
            return target
    return None


def x86_16_block_successors_from_capstone_8616(
    block: object,
    region_start: int,
    region_end: int,
) -> tuple[set[int], bool]:
    """Return bounded block successors and whether control flow is unresolved."""
    boundary = cast(_BlockBoundary8616, block)
    try:
        instructions = tuple(boundary.capstone.insns)
    except (AttributeError, TypeError):
        return set(), True
    if not instructions:
        return set(), True

    last = instructions[-1]
    mnemonic = last.mnemonic.lower()
    block_end = boundary.addr + boundary.size
    successors: set[int] = set()

    def add_target(target: int | None) -> None:
        if isinstance(target, int) and region_start <= target < region_end:
            successors.add(target)

    if mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
        return successors, False
    if mnemonic in {"call", "lcall", "callq"}:
        if block_end < region_end:
            successors.add(block_end)
        return successors, False
    if mnemonic in {"jmp", "ljmp"}:
        target = _direct_target_8616(last)
        add_target(target)
        return successors, target is None
    if mnemonic.startswith("j") or mnemonic in {"loop", "loope", "loopne", "loopnz", "loopz"}:
        target = _direct_target_8616(last)
        add_target(target)
        if block_end < region_end:
            successors.add(block_end)
        return successors, target is None
    if block_end < region_end:
        successors.add(block_end)
    return successors, False


def collect_instruction_reachability_8616(
    project: object,
    *,
    entry: int,
    region_start: int,
    region_end: int,
) -> InstructionReachabilityEvidence8616:
    """Traverse binary-proven successors inside one bounded loaded image."""
    if not (region_start <= entry < region_end):
        return InstructionReachabilityEvidence8616((), (), 0, 0, 0, 0, 0)

    boundary = cast(_ProjectBoundary8616, project)
    queue: deque[int] = deque((entry,))
    visited: set[int] = set()
    reachable_instructions: set[int] = set()
    unresolved: set[int] = set()
    while queue:
        block_addr = queue.popleft()
        if block_addr in visited or not (region_start <= block_addr < region_end):
            continue
        visited.add(block_addr)
        try:
            block = boundary.factory.block(block_addr, opt_level=0)
            instructions = tuple(block.capstone.insns)
        except (AttributeError, RuntimeError, TypeError, ValueError):
            unresolved.add(block_addr)
            continue
        if not instructions or block.size <= 0:
            unresolved.add(block_addr)
            continue
        reachable_instructions.update(
            instruction.address
            for instruction in instructions
            if region_start <= instruction.address < region_end
        )
        successors, successor_unresolved = x86_16_block_successors_from_capstone_8616(
            block,
            region_start,
            region_end,
        )
        if successor_unresolved:
            unresolved.add(block_addr)
        for successor in sorted(successors):
            if successor not in visited:
                queue.append(successor)

    failure_count = len(unresolved)
    classified_count = len(visited)
    return InstructionReachabilityEvidence8616(
        reachable_instruction_addrs=tuple(sorted(reachable_instructions)),
        unresolved_block_addrs=tuple(sorted(unresolved)),
        raw_fact_count=classified_count,
        normalized_fact_count=classified_count,
        classified_fact_count=classified_count,
        materialized_count=classified_count - failure_count,
        failure_count=failure_count,
    )
