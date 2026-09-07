"""Recover bounded binary evidence for direct-callee status-flag effects.

Layer: IR.
Responsibility: adapt loaded-image bounds, exact frontend-decoded blocks, and
binary-proven successors into a typed summary of incoming status bits that a
callee may read before overwriting. Proven prefixes are projected to the
Semantics CFG solver for definite overwrites; this adapter does not infer them.
This module owns no instruction semantics
and never changes Alias, Widening, Types, Structuring, Rewrite, or rendered C.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from ..frontend_instruction_reachability import (
    x86_16_block_successors_from_capstone_8616,
)
from ..semantics.status_flag_cfg_liveness import (
    StatusFlagCFGBlock8616,
    StatusFlagCFGInstruction8616,
    summarize_status_flag_cfg_effect_8616,
)
from ..semantics.status_flag_contracts import (
    STATUS_FLAGS_8616,
    StatusFlag8616,
    StatusFlagEffect8616,
)


class _InstructionBoundary8616(Protocol):
    """Exact address on a third-party Capstone instruction wrapper."""

    address: int


class _CapstoneBlockBoundary8616(Protocol):
    """Third-party angr disassembly collection."""

    insns: tuple[object, ...]


class _BlockBoundary8616(Protocol):
    """Third-party angr block fields consumed by bounded read recovery."""

    size: int
    capstone: _CapstoneBlockBoundary8616


class _FactoryBoundary8616(Protocol):
    """Third-party angr block factory used at exact binary addresses."""

    def block(self, address: int, *, opt_level: int = 0) -> _BlockBoundary8616:
        """Decode one exact basic block."""


class _MainObjectBoundary8616(Protocol):
    """Third-party loaded-object address range."""

    min_addr: int
    max_addr: int


class _LoaderBoundary8616(Protocol):
    """Third-party loader surface exposing the main binary image."""

    main_object: _MainObjectBoundary8616


class _ProjectBoundary8616(Protocol):
    """Third-party project fields required by binary read recovery."""

    factory: _FactoryBoundary8616
    loader: _LoaderBoundary8616


type InstructionEffectProjector8616 = Callable[[object], StatusFlagEffect8616 | None]


@dataclass(frozen=True, slots=True)
class BinaryStatusFlagReadSummary8616:
    """Incoming reads, proven overwrites, and bounded traversal accounting."""

    reads: StatusFlag8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    overwrites: StatusFlag8616 = StatusFlag8616.NONE

    @property
    def complete(self) -> bool:
        """Return whether every flag-relevant path had complete evidence."""
        return self.failure_count == 0


def _loaded_image_bounds_8616(project: object) -> tuple[int, int] | None:
    """Return the main object's inclusive/exclusive loaded address interval."""
    try:
        main_object = cast(_ProjectBoundary8616, project).loader.main_object
        start = int(main_object.min_addr)
        end = int(main_object.max_addr) + 1
    except (AttributeError, TypeError, ValueError):
        return None
    return (start, end) if 0 <= start < end else None


def summarize_binary_status_flag_entry_reads_8616(
    project: object,
    *,
    entry_address: int,
    instruction_effect: InstructionEffectProjector8616,
    max_blocks: int = 512,
    max_instructions: int = 4096,
) -> BinaryStatusFlagReadSummary8616:
    """Find incoming status bits observed before a binary callee kills them.

    The worklist carries only bits still derived from the caller's incoming
    FLAGS. Paths stop once that set is empty, so calls after a definite local
    overwrite are never recursively summarized. Unknown decode or control flow
    marks every still-carried bit as read, preserving the refuse-and-keep rule.
    The Semantics solver intersects overwrites across the decoded prefix CFG.
    A prefix ends at return or when no incoming bits remain, not at an arbitrary
    instruction budget. Any failed path refuses overwrite publication.
    """
    bounds = _loaded_image_bounds_8616(project)
    if (
        bounds is None or not (bounds[0] <= entry_address < bounds[1])
        or max_blocks <= 0 or max_instructions <= 0
    ):
        return BinaryStatusFlagReadSummary8616(STATUS_FLAGS_8616, 0, 0, 0, 0, 1)
    region_start, region_end = bounds
    boundary = cast(_ProjectBoundary8616, project)
    pending: dict[int, StatusFlag8616] = {entry_address: STATUS_FLAGS_8616}
    queue: deque[int] = deque((entry_address,))
    processed: dict[int, StatusFlag8616] = {}
    prefixes: dict[int, StatusFlagCFGBlock8616] = {}
    reads = StatusFlag8616.NONE
    visited: set[int] = set()
    failed: set[int] = set()
    instruction_count = 0

    while queue and len(visited) < max_blocks and instruction_count < max_instructions:
        address = queue.popleft()
        incoming = pending.pop(address, StatusFlag8616.NONE)
        new_incoming = incoming & ~processed.get(address, StatusFlag8616.NONE)
        if int(new_incoming) == 0:
            continue
        processed[address] = processed.get(address, StatusFlag8616.NONE) | new_incoming
        visited.add(address)
        try:
            block = boundary.factory.block(address, opt_level=0)
            wrapped_instructions = tuple(block.capstone.insns)
        except (AttributeError, RuntimeError, TypeError, ValueError):
            reads |= new_incoming
            failed.add(address)
            continue
        if not wrapped_instructions or int(block.size) <= 0:
            reads |= new_incoming
            failed.add(address)
            continue

        carried: StatusFlag8616 = new_incoming
        instructions: list[StatusFlagCFGInstruction8616] = []
        for wrapped in wrapped_instructions:
            if instruction_count >= max_instructions:
                reads |= carried
                carried = StatusFlag8616.NONE
                failed.add(address)
                break
            instruction_count += 1
            effect = instruction_effect(wrapped)
            instructions.append(StatusFlagCFGInstruction8616(
                address=int(cast(_InstructionBoundary8616, wrapped).address),
                effect=effect,
            ))
            if effect is None:
                reads |= carried
                carried = StatusFlag8616.NONE
                failed.add(address)
                break
            reads |= effect.reads & carried
            carried &= ~effect.overwrites
            if int(carried) == 0:
                break
        successors, successor_unresolved = (
            x86_16_block_successors_from_capstone_8616(block, region_start, region_end)
            if carried else (set(), False)
        )
        previous = prefixes.get(address)
        # A later visit may carry fewer bits and stop earlier at the same block.
        if previous is not None and len(instructions) == len(previous.instructions):
            successors.update(previous.successor_addresses)
            successor_unresolved |= not previous.successors_complete
        if previous is None or len(instructions) >= len(previous.instructions):
            prefixes[address] = StatusFlagCFGBlock8616(
                address=address,
                instructions=tuple(instructions),
                successor_addresses=tuple(sorted(successors)),
                successors_complete=not successor_unresolved,
            )
        if int(carried) == 0:
            continue
        if successor_unresolved:
            reads |= carried
            failed.add(address)
            continue
        for successor in sorted(successors):
            unseen = carried & ~processed.get(successor, StatusFlag8616.NONE)
            if int(unseen) == 0:
                continue
            pending[successor] = pending.get(successor, StatusFlag8616.NONE) | unseen
            if successor not in queue:
                queue.append(successor)

    if queue:
        for remaining in pending.values():
            reads |= remaining
        failed.add(min(visited) if visited else entry_address)
    classified_count = len(visited)
    failure_count = min(classified_count, len(failed))
    return BinaryStatusFlagReadSummary8616(
        reads=reads & STATUS_FLAGS_8616,
        raw_fact_count=classified_count,
        normalized_fact_count=classified_count,
        classified_fact_count=classified_count,
        materialized_count=classified_count - failure_count,
        failure_count=failure_count,
        overwrites=(
            summarize_status_flag_cfg_effect_8616(
                tuple(prefixes.values()), entry_address=entry_address,
            ).overwrites if not failed else StatusFlag8616.NONE
        ),
    )


__all__ = [
    "BinaryStatusFlagReadSummary8616",
    "InstructionEffectProjector8616",
    "summarize_binary_status_flag_entry_reads_8616",
]
