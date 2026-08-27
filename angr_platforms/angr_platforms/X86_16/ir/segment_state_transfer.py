"""Transfer typed segment-register state through one IR block.

Layer: IR.
Responsibility: own the segment-state lattice and consume typed restore-source
relations already proved by Alias. Owns typed Value, Address, Condition,
instruction facts, and lossless normalization. Do not perform alias-state
ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here. Never infer stack identity here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRBlock, IRInstr, IRValue, MemSpace, SegmentOrigin

__all__ = [
    "SEGMENT_REGISTERS",
    "InstructionStateKey",
    "SegmentRegisterState",
    "SegmentRestoreSource",
    "SegmentValueKind8616",
    "architectural_live_in_state",
    "join_register_states",
    "transfer_block_with_instruction_states",
    "unknown_segment_state",
]

SEGMENT_REGISTERS: tuple[str, ...] = ("cs", "ds", "es", "ss", "fs", "gs")
type InstructionStateKey = int | tuple[int, int]


class SegmentValueKind8616(StrEnum):
    """Typed provenance class for one segment-register state."""

    UNKNOWN = "unknown"
    ARCHITECTURAL_LIVE_IN = "architectural_live_in"
    MERGED_PROVEN = "merged_proven"
    MERGED = "merged"
    STACK_RESTORE = "stack_restore"
    CONST_WRITE = "const_write"
    SEGMENT_COPY = "segment_copy"
    REGISTER_COPY = "register_copy"
    UNKNOWN_WRITE = "unknown_write"


@dataclass(frozen=True, slots=True)
class SegmentRegisterState:
    """Proven state for one segment register at a program point."""

    register: str
    value_kind: SegmentValueKind8616
    source: str | None
    origin: SegmentOrigin

    def __post_init__(self) -> None:
        """Normalize legacy construction sites to the typed state enum."""
        if not isinstance(self.value_kind, SegmentValueKind8616):
            object.__setattr__(self, "value_kind", SegmentValueKind8616(self.value_kind))

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "register": self.register,
            "value_kind": self.value_kind.value,
            "source": self.source,
            "origin": self.origin.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentRestoreSource:
    """Alias-proved relation from one segment write to an earlier segment read."""

    block_addr: int
    restore_instruction_addr: int
    restore_register: str
    saved_instruction_addr: int
    saved_register: str


def unknown_segment_state(register: str) -> SegmentRegisterState:
    """Return the lattice unknown state for one register."""
    return SegmentRegisterState(register, SegmentValueKind8616.UNKNOWN, None, SegmentOrigin.UNKNOWN)


def architectural_live_in_state(register: str) -> SegmentRegisterState:
    """Return a proven physical identity with an unknown runtime value."""
    return SegmentRegisterState(
        register,
        SegmentValueKind8616.ARCHITECTURAL_LIVE_IN,
        register,
        SegmentOrigin.PROVEN,
    )


def join_register_states(states: tuple[SegmentRegisterState, ...], register: str) -> SegmentRegisterState:
    """Join predecessor states as a must lattice."""
    if not states or any(state.origin is not SegmentOrigin.PROVEN or state.source is None for state in states):
        return unknown_segment_state(register)
    first = states[0]
    if all(state.source == first.source for state in states[1:]):
        if all(state.value_kind == first.value_kind for state in states[1:]):
            return first
        return SegmentRegisterState(register, SegmentValueKind8616.MERGED_PROVEN, first.source, SegmentOrigin.PROVEN)
    return SegmentRegisterState(register, SegmentValueKind8616.MERGED, None, SegmentOrigin.UNKNOWN)


def _visible_segment_states(state: dict[str, SegmentRegisterState]) -> dict[str, SegmentRegisterState]:
    """Keep general-register aliases internal to one block transfer."""
    return {register: state[register] for register in SEGMENT_REGISTERS if register in state}


def _restore_source_map(
    block_addr: int,
    restore_sources: tuple[SegmentRestoreSource, ...],
) -> dict[tuple[int, str], SegmentRestoreSource]:
    """Index proven restore relations for one block."""
    return {
        (source.restore_instruction_addr, source.restore_register): source
        for source in restore_sources
        if source.block_addr == block_addr
    }


def _restored_register_state(
    dst_name: str,
    instruction_addr: int | None,
    instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]],
    restore_map: dict[tuple[int, str], SegmentRestoreSource],
    saved_instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]],
) -> SegmentRegisterState | None:
    """Resolve an Alias-proved restoration to the saved pre-instruction state."""
    if instruction_addr is None:
        return None
    source = restore_map.get((instruction_addr, dst_name))
    if source is None:
        return None
    saved = instruction_entries.get(source.saved_instruction_addr, {}).get(source.saved_register)
    if saved is None:
        saved = saved_instruction_entries.get(source.saved_instruction_addr, {}).get(source.saved_register)
    if saved is None or saved.origin is not SegmentOrigin.PROVEN or saved.source is None:
        return unknown_segment_state(dst_name)
    return SegmentRegisterState(dst_name, SegmentValueKind8616.STACK_RESTORE, saved.source, SegmentOrigin.PROVEN)


def _written_register_state(
    dst_name: str,
    src: IRValue,
    state: dict[str, SegmentRegisterState],
    restored: SegmentRegisterState | None,
) -> SegmentRegisterState | None:
    """Propagate typed segment identities through proven register writes."""
    if restored is not None:
        return restored
    if dst_name in SEGMENT_REGISTERS and src.space is MemSpace.CONST and src.const is not None:
        return SegmentRegisterState(
            dst_name,
            SegmentValueKind8616.CONST_WRITE,
            hex(int(src.const)),
            SegmentOrigin.PROVEN,
        )
    if src.space is MemSpace.REG and src.name is not None:
        inherited = state.get(src.name)
        if inherited is not None and inherited.origin is SegmentOrigin.PROVEN and inherited.source is not None:
            value_kind = (
                SegmentValueKind8616.SEGMENT_COPY
                if dst_name in SEGMENT_REGISTERS
                else SegmentValueKind8616.REGISTER_COPY
            )
            return SegmentRegisterState(dst_name, value_kind, inherited.source, SegmentOrigin.PROVEN)
    if dst_name in SEGMENT_REGISTERS:
        return SegmentRegisterState(dst_name, SegmentValueKind8616.UNKNOWN_WRITE, None, SegmentOrigin.UNKNOWN)
    return None


def transfer_block_with_instruction_states(
    block: IRBlock,
    entry_state: dict[str, SegmentRegisterState],
    restore_sources: tuple[SegmentRestoreSource, ...] = (),
    saved_instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] | None = None,
) -> tuple[
    dict[str, SegmentRegisterState],
    dict[InstructionStateKey, dict[str, SegmentRegisterState]],
    dict[InstructionStateKey, dict[str, SegmentRegisterState]],
]:
    """Transfer one block and retain exact before/after instruction states."""
    state = dict(entry_state)
    instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    instruction_exits: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    restore_map = _restore_source_map(block.addr, restore_sources)
    saved_entries = saved_instruction_entries or {}
    for instruction_index, instr in enumerate(tuple(block.instrs or ())):
        instruction_key = instr.addr if isinstance(instr, IRInstr) and isinstance(instr.addr, int) else (block.addr, instruction_index)
        instruction_entries.setdefault(instruction_key, _visible_segment_states(state))
        if not isinstance(instr, IRInstr):
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        dst = instr.dst
        if not isinstance(dst, IRValue) or dst.space is not MemSpace.REG or dst.name is None:
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        src = instr.args[0] if instr.args else None
        if not isinstance(src, IRValue):
            if dst.name in SEGMENT_REGISTERS:
                state[dst.name] = unknown_segment_state(dst.name)
            else:
                state.pop(dst.name, None)
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        restored = _restored_register_state(
            dst.name,
            instr.addr,
            instruction_entries,
            restore_map,
            saved_entries,
        )
        written_state = _written_register_state(dst.name, src, state, restored)
        if written_state is None:
            state.pop(dst.name, None)
        else:
            state[dst.name] = written_state
        instruction_exits[instruction_key] = _visible_segment_states(state)
    return _visible_segment_states(state), instruction_entries, instruction_exits
