"""Function-level status-flag liveness over typed CFG evidence.

Layer: Semantics.
Responsibility: solve per-bit status-flag liveness across complete CFG edges and
materialize conservative suppression decisions before Lowering or Structuring.
Unknown instructions, missing successors, and incomplete call summaries keep
all status bits live. This module never mutates VEX, AIL, or rendered C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .status_flag_contracts import (
    STATUS_FLAGS_8616,
    StatusFlag8616,
    StatusFlagEffect8616,
    StatusFlagLivenessStats8616,
    StatusFlagLivenessVerdict8616,
)


@dataclass(frozen=True, slots=True)
class StatusFlagCFGInstruction8616:
    """One decoded instruction projected to a proven or unknown flag effect."""

    address: int
    effect: StatusFlagEffect8616 | None
    suppression_supported: bool = True


@dataclass(frozen=True, slots=True)
class StatusFlagCFGBlock8616:
    """One function-owned block with complete intraprocedural successors."""

    address: int
    instructions: tuple[StatusFlagCFGInstruction8616, ...]
    successor_addresses: tuple[int, ...] = ()
    successors_complete: bool = True


@dataclass(frozen=True, slots=True)
class StatusFlagCFGDecision8616:
    """Per-instruction dead-write decision from the converged CFG solution."""

    block_address: int
    instruction_index: int
    instruction_address: int
    written: StatusFlag8616
    live_after: StatusFlag8616
    dead_writes: StatusFlag8616
    verdict: StatusFlagLivenessVerdict8616
    suppression_supported: bool

    @property
    def suppresses_write(self) -> bool:
        """Return whether every status bit written by this instruction is dead."""
        return bool(
            self.verdict is StatusFlagLivenessVerdict8616.SUPPRESS_DEAD
            and self.suppression_supported
            and int(self.written) != 0
            and self.dead_writes == self.written
        )


@dataclass(frozen=True, slots=True)
class StatusFlagCFGLivenessArtifact8616:
    """Converged liveness maps, decisions, and closed evidence counters."""

    entry_address: int
    live_in_by_block: tuple[tuple[int, StatusFlag8616], ...]
    live_out_by_block: tuple[tuple[int, StatusFlag8616], ...]
    decisions: tuple[StatusFlagCFGDecision8616, ...]
    stats: StatusFlagLivenessStats8616

    def live_at_entry(self) -> StatusFlag8616:
        """Return status bits required at the selected function entry."""
        return dict(self.live_in_by_block).get(self.entry_address, STATUS_FLAGS_8616)

    def suppressed_instruction_addresses(self) -> frozenset[int]:
        """Return addresses whose complete status write is proven dead."""
        return frozenset(
            decision.instruction_address
            for decision in self.decisions
            if decision.suppresses_write
        )


def _transfer_effect_8616(
    effect: StatusFlagEffect8616 | None,
    live_after: StatusFlag8616,
) -> StatusFlag8616:
    """Transfer one instruction backward; unknown effects preserve everything."""
    if effect is None:
        return STATUS_FLAGS_8616
    return effect.reads | (live_after & ~effect.overwrites)


def _block_live_in_8616(
    block: StatusFlagCFGBlock8616,
    live_out: StatusFlag8616,
) -> StatusFlag8616:
    """Transfer one complete block backward from its live-out mask."""
    live = live_out
    for instruction in reversed(block.instructions):
        live = _transfer_effect_8616(instruction.effect, live)
    return live & STATUS_FLAGS_8616


def analyze_status_flag_cfg_liveness_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    *,
    entry_address: int,
    exit_live: StatusFlag8616 = STATUS_FLAGS_8616,
) -> StatusFlagCFGLivenessArtifact8616:
    """Solve per-bit liveness to a fixed point and materialize every decision.

    ``exit_live`` is an owned function-contract input. The conservative default
    preserves all architectural status bits. A caller may pass ``NONE`` only
    after a typed function-output contract proves flags are unobservable.
    """
    block_by_addr = {block.address: block for block in blocks}
    live_in = {block.address: StatusFlag8616.NONE for block in blocks}
    live_out = {block.address: StatusFlag8616.NONE for block in blocks}
    missing_successor_count = 0

    changed = True
    while changed:
        changed = False
        missing_successor_count = 0
        for block in reversed(blocks):
            if not block.successors_complete:
                block_live_out = STATUS_FLAGS_8616
                missing_successor_count += 1
            elif not block.successor_addresses:
                block_live_out = exit_live & STATUS_FLAGS_8616
            else:
                block_live_out = StatusFlag8616.NONE
                for successor in block.successor_addresses:
                    if successor not in block_by_addr:
                        block_live_out |= STATUS_FLAGS_8616
                        missing_successor_count += 1
                    else:
                        block_live_out |= live_in[successor]
            block_live_in = _block_live_in_8616(block, block_live_out)
            if live_out[block.address] != block_live_out:
                live_out[block.address] = block_live_out
                changed = True
            if live_in[block.address] != block_live_in:
                live_in[block.address] = block_live_in
                changed = True

    decisions: list[StatusFlagCFGDecision8616] = []
    unknown_count = 0
    instruction_count = 0
    for block in blocks:
        live = live_out[block.address]
        reversed_decisions: list[StatusFlagCFGDecision8616] = []
        for reverse_index, instruction in enumerate(reversed(block.instructions)):
            instruction_count += 1
            index = len(block.instructions) - reverse_index - 1
            effect = instruction.effect
            if effect is None:
                unknown_count += 1
                written = StatusFlag8616.NONE
                dead_writes = StatusFlag8616.NONE
                verdict = StatusFlagLivenessVerdict8616.KEEP_UNKNOWN
            else:
                written = effect.overwrites & STATUS_FLAGS_8616
                dead_writes = written & ~live
                verdict = (
                    StatusFlagLivenessVerdict8616.SUPPRESS_DEAD
                    if int(written) != 0 and dead_writes == written
                    else StatusFlagLivenessVerdict8616.KEEP_LIVE
                )
            reversed_decisions.append(
                StatusFlagCFGDecision8616(
                    block_address=block.address,
                    instruction_index=index,
                    instruction_address=instruction.address,
                    written=written,
                    live_after=live,
                    dead_writes=dead_writes,
                    verdict=verdict,
                    suppression_supported=instruction.suppression_supported,
                )
            )
            live = _transfer_effect_8616(effect, live)
        decisions.extend(reversed(reversed_decisions))

    failure_count = unknown_count + missing_successor_count
    stats = StatusFlagLivenessStats8616(
        raw_fact_count=instruction_count,
        normalized_fact_count=instruction_count,
        classified_fact_count=instruction_count,
        materialized_count=instruction_count,
        failure_count=failure_count,
    )
    if not stats.closed:
        raise RuntimeError("status-flag CFG liveness evidence did not close")
    return StatusFlagCFGLivenessArtifact8616(
        entry_address=entry_address,
        live_in_by_block=tuple(sorted(live_in.items())),
        live_out_by_block=tuple(sorted(live_out.items())),
        decisions=tuple(
            sorted(
                decisions,
                key=lambda decision: (decision.block_address, decision.instruction_index),
            )
        ),
        stats=stats,
    )


def _definitely_overwritten_on_all_exits_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    *,
    entry_address: int,
) -> StatusFlag8616:
    """Return bits overwritten on every complete path from entry to return."""
    block_by_addr = {block.address: block for block in blocks}
    if entry_address not in block_by_addr:
        return StatusFlag8616.NONE
    for block in blocks:
        if not block.successors_complete or any(
            successor not in block_by_addr for successor in block.successor_addresses
        ):
            return StatusFlag8616.NONE

    reachable = {entry_address}
    pending = [entry_address]
    while pending:
        current = pending.pop()
        for successor in block_by_addr[current].successor_addresses:
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    predecessors: dict[int, set[int]] = {address: set() for address in reachable}
    for address in reachable:
        for successor in block_by_addr[address].successor_addresses:
            if successor in reachable:
                predecessors[successor].add(address)

    must_in = {
        address: (
            StatusFlag8616.NONE if address == entry_address else STATUS_FLAGS_8616
        )
        for address in reachable
    }
    must_out = dict(must_in)
    changed = True
    while changed:
        changed = False
        for address in sorted(reachable):
            if address == entry_address:
                block_in = StatusFlag8616.NONE
            else:
                incoming = predecessors[address]
                block_in = STATUS_FLAGS_8616
                if not incoming:
                    block_in = StatusFlag8616.NONE
                else:
                    for predecessor in incoming:
                        block_in &= must_out[predecessor]
            block_out = block_in
            for instruction in block_by_addr[address].instructions:
                if instruction.effect is not None:
                    block_out |= instruction.effect.overwrites
            block_out &= STATUS_FLAGS_8616
            if must_in[address] != block_in:
                must_in[address] = block_in
                changed = True
            if must_out[address] != block_out:
                must_out[address] = block_out
                changed = True

    exits = tuple(
        address
        for address in reachable
        if not block_by_addr[address].successor_addresses
    )
    if not exits:
        return StatusFlag8616.NONE
    definitely_overwritten = STATUS_FLAGS_8616
    for address in exits:
        definitely_overwritten &= must_out[address]
    return definitely_overwritten


def summarize_status_flag_cfg_effect_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    *,
    entry_address: int,
) -> StatusFlagEffect8616:
    """Summarize callee entry reads and all-return definite overwrites."""
    reads_artifact = analyze_status_flag_cfg_liveness_8616(
        blocks,
        entry_address=entry_address,
        exit_live=StatusFlag8616.NONE,
    )
    return StatusFlagEffect8616(
        reads=reads_artifact.live_at_entry(),
        overwrites=_definitely_overwritten_on_all_exits_8616(
            blocks,
            entry_address=entry_address,
        ),
    )


__all__ = [
    "StatusFlagCFGBlock8616",
    "StatusFlagCFGDecision8616",
    "StatusFlagCFGInstruction8616",
    "StatusFlagCFGLivenessArtifact8616",
    "analyze_status_flag_cfg_liveness_8616",
    "summarize_status_flag_cfg_effect_8616",
]
