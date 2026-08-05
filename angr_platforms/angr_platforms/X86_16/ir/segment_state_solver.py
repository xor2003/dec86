"""Solve typed segment-register state across a function CFG.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and
lossless normalization. Iteratively consumes Alias-proved restore relations
without owning stack identity. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRFunctionArtifact
from .segment_state_transfer import (
    SEGMENT_REGISTERS,
    InstructionStateKey,
    SegmentRegisterState,
    SegmentRestoreSource,
    architectural_live_in_state,
    join_register_states,
    transfer_block_with_instruction_states,
    unknown_segment_state,
)
from .ssa_function import SSAFunctionArtifact, build_x86_16_ir_predecessor_map

__all__ = ["SegmentStateSolution8616", "solve_segment_state_8616"]


@dataclass(frozen=True, slots=True)
class SegmentStateSolution8616:
    """Raw block and instruction state maps from the IR fixed point."""

    entry_states: dict[int, dict[str, SegmentRegisterState]]
    exit_states: dict[int, dict[str, SegmentRegisterState]]
    instruction_entry_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]]
    instruction_exit_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]]


def _predecessor_register_states(
    predecessors: tuple[int, ...],
    exit_states: dict[int, dict[str, SegmentRegisterState]],
    register: str,
) -> tuple[SegmentRegisterState, ...]:
    """Return initialized predecessor facts, treating absent maps as dataflow bottom."""
    return tuple(
        state
        for predecessor in predecessors
        if (state := exit_states.get(predecessor, {}).get(register)) is not None
    )


def _join_entry_state(
    predecessor_map: dict[int, tuple[int, ...]],
    exit_states: dict[int, dict[str, SegmentRegisterState]],
    block_addr: int,
    function_addr: int,
) -> dict[str, SegmentRegisterState]:
    """Join predecessor segment identities as must-state."""
    predecessors = predecessor_map.get(block_addr, ())
    if not predecessors and block_addr != function_addr:
        return {register: unknown_segment_state(register) for register in SEGMENT_REGISTERS}
    result: dict[str, SegmentRegisterState] = {}
    for register in SEGMENT_REGISTERS:
        states = (
            ((architectural_live_in_state(register),) if block_addr == function_addr else ())
            + _predecessor_register_states(predecessors, exit_states, register)
        )
        if states:
            result[register] = join_register_states(states, register)
    return result


def _solve_once(
    artifact: IRFunctionArtifact,
    predecessor_map: dict[int, tuple[int, ...]],
    restore_sources: tuple[SegmentRestoreSource, ...],
    saved_instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]],
) -> SegmentStateSolution8616:
    """Solve one CFG fixed point using the prior restore-source state surface."""
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    entry_states: dict[int, dict[str, SegmentRegisterState]] = {addr: {} for addr in blocks_by_addr}
    exit_states: dict[int, dict[str, SegmentRegisterState]] = {addr: {} for addr in blocks_by_addr}
    changed = True
    while changed:
        changed = False
        for block_addr in sorted(blocks_by_addr):
            new_entry = _join_entry_state(
                predecessor_map,
                exit_states,
                block_addr,
                artifact.function_addr,
            )
            new_exit = transfer_block_with_instruction_states(
                blocks_by_addr[block_addr],
                new_entry,
                restore_sources,
                saved_instruction_entries,
            )[0]
            if new_entry != entry_states[block_addr]:
                entry_states[block_addr] = new_entry
                changed = True
            if new_exit != exit_states[block_addr]:
                exit_states[block_addr] = new_exit
                changed = True

    instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    instruction_exits: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    for block_addr, block in sorted(blocks_by_addr.items()):
        _, block_entries, block_exits = transfer_block_with_instruction_states(
            block,
            entry_states[block_addr],
            restore_sources,
            saved_instruction_entries,
        )
        instruction_entries.update(block_entries)
        instruction_exits.update(block_exits)
    return SegmentStateSolution8616(
        entry_states,
        exit_states,
        instruction_entries,
        instruction_exits,
    )


def solve_segment_state_8616(
    artifact: IRFunctionArtifact,
    function_ssa: SSAFunctionArtifact | None,
    restore_sources: tuple[SegmentRestoreSource, ...],
) -> SegmentStateSolution8616:
    """Solve local and cross-block restore chains to a deterministic fixed point."""
    predecessor_map = (
        dict(function_ssa.predecessor_map)
        if function_ssa is not None and function_ssa.predecessor_map
        else build_x86_16_ir_predecessor_map(artifact)
    )
    saved_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    solution = _solve_once(artifact, predecessor_map, restore_sources, saved_entries)
    for _ in range(len(restore_sources) + 2):
        if solution.instruction_entry_states == saved_entries:
            return solution
        saved_entries = solution.instruction_entry_states
        solution = _solve_once(artifact, predecessor_map, restore_sources, saved_entries)
    return solution
