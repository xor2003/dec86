"""Track proven segment-register state across IR blocks.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

from .core import IRFunctionArtifact, IRValue, MemSpace, SegmentOrigin
from .segment_state_solver import solve_segment_state_8616
from .segment_state_transfer import (
    SEGMENT_REGISTERS,
    InstructionStateKey,
    SegmentRegisterState,
    SegmentRestoreSource,
    SegmentValueKind8616,
    join_register_states,
)
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "SegmentRegisterState",
    "SegmentRestoreSource",
    "SegmentValueKind8616",
    "SegmentStateArtifact",
    "apply_x86_16_segment_state_artifact",
    "build_x86_16_segment_state_artifact",
]

class _SegmentStateCodegenBoundary(Protocol):
    """Dynamic codegen attributes consumed and produced by this IR attachment."""

    _inertia_vex_ir_artifact: object
    _inertia_vex_ir_function_ssa: object
    _inertia_segment_stack_restore_artifact: object
    _inertia_segment_state_artifact: SegmentStateArtifact


class _SegmentRestoreEvidenceSurface(Protocol):
    """Alias-owned restore evidence consumed through a typed IR relation."""

    restore_sources: tuple[SegmentRestoreSource, ...]


@dataclass(frozen=True, slots=True)
class SegmentStateArtifact:
    """Entry/exit segment-register state for a function's IR blocks."""

    entry_states: dict[int, dict[str, SegmentRegisterState]]
    exit_states: dict[int, dict[str, SegmentRegisterState]]
    summary: dict[str, object]
    instruction_entry_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = field(default_factory=dict)
    instruction_exit_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = field(default_factory=dict)

    def state_for_register(self, register: str) -> SegmentRegisterState | None:
        """Return the one proven identity held throughout the function."""
        observed = tuple(
            state
            for state_map in (
                *self.entry_states.values(),
                *self.exit_states.values(),
                *self.instruction_entry_states.values(),
                *self.instruction_exit_states.values(),
            )
            if (state := state_map.get(register)) is not None
        )
        joined = join_register_states(observed, register)
        return joined if joined.origin is SegmentOrigin.PROVEN else None

    def state_at_block_entry(self, block_addr: int, register: str) -> SegmentRegisterState | None:
        """Return the exact state before one IR block when available."""
        return self.entry_states.get(block_addr, {}).get(register)

    def state_at_block_exit(self, block_addr: int, register: str) -> SegmentRegisterState | None:
        """Return the exact state after one IR block when available."""
        return self.exit_states.get(block_addr, {}).get(register)

    def state_before_instruction(
        self,
        instruction_addr: int,
        register: str,
    ) -> SegmentRegisterState | None:
        """Return the exact state immediately before one typed IR instruction."""
        return self.instruction_entry_states.get(instruction_addr, {}).get(register)

    def state_after_instruction(
        self,
        instruction_addr: int,
        register: str,
    ) -> SegmentRegisterState | None:
        """Return the exact state immediately after one typed IR instruction."""
        return self.instruction_exit_states.get(instruction_addr, {}).get(register)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "entry_states": {
                hex(addr): {name: state.to_dict() for name, state in sorted(states.items())}
                for addr, states in sorted(self.entry_states.items())
            },
            "exit_states": {
                hex(addr): {name: state.to_dict() for name, state in sorted(states.items())}
                for addr, states in sorted(self.exit_states.items())
            },
            "instruction_entry_states": {
                _instruction_state_key_text(key): {name: state.to_dict() for name, state in sorted(states.items())}
                for key, states in sorted(self.instruction_entry_states.items(), key=lambda item: str(item[0]))
            },
            "instruction_exit_states": {
                _instruction_state_key_text(key): {name: state.to_dict() for name, state in sorted(states.items())}
                for key, states in sorted(self.instruction_exit_states.items(), key=lambda item: str(item[0]))
            },
            "summary": dict(self.summary),
        }


def _instruction_state_key_text(key: InstructionStateKey) -> str:
    return hex(key) if isinstance(key, int) else f"{key[0]:#x}:{key[1]}"


def build_x86_16_segment_state_artifact(
    artifact: IRFunctionArtifact,
    function_ssa: SSAFunctionArtifact | None = None,
    restore_sources: tuple[SegmentRestoreSource, ...] = (),
) -> SegmentStateArtifact:
    """Build forward segment-register state from typed IR and SSA predecessors."""
    solution = solve_segment_state_8616(artifact, function_ssa, restore_sources)
    explicit_write_count = sum(
        1
        for block in artifact.blocks
        for instruction in block.instrs
        if isinstance(instruction.dst, IRValue)
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in SEGMENT_REGISTERS
    )
    classified_write_count = sum(
        1
        for block in artifact.blocks
        for instruction_index, instruction in enumerate(block.instrs)
        if isinstance(instruction.dst, IRValue)
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in SEGMENT_REGISTERS
        and solution.instruction_exit_states[
            instruction.addr if isinstance(instruction.addr, int) else (block.addr, instruction_index)
        ][instruction.dst.name].origin
        is SegmentOrigin.PROVEN
    )
    summary: dict[str, object] = {
        "block_count": len(artifact.blocks),
        "explicit_write_count": explicit_write_count,
        "raw_fact_count": explicit_write_count,
        "normalized_fact_count": explicit_write_count,
        "classified_fact_count": classified_write_count,
        "materialized_count": classified_write_count,
        "failure_count": explicit_write_count - classified_write_count,
        "architectural_live_in_count": sum(
            state.value_kind is SegmentValueKind8616.ARCHITECTURAL_LIVE_IN
            for state in solution.entry_states.get(artifact.function_addr, {}).values()
        ),
        "proven_register_count": sum(
            state.origin is SegmentOrigin.PROVEN
            for states in solution.exit_states.values()
            for state in states.values()
        ),
        "unknown_register_count": sum(
            state.origin is SegmentOrigin.UNKNOWN
            for states in solution.exit_states.values()
            for state in states.values()
        ),
    }
    return SegmentStateArtifact(
        entry_states=solution.entry_states,
        exit_states=solution.exit_states,
        summary=summary,
        instruction_entry_states=solution.instruction_entry_states,
        instruction_exit_states=solution.instruction_exit_states,
    )


def apply_x86_16_segment_state_artifact(project: object, codegen: object) -> bool:  # noqa: ARG001
    """Attach the segment-state artifact to codegen for later IR consumers."""
    boundary = cast(_SegmentStateCodegenBoundary, codegen)
    try:
        artifact = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, IRFunctionArtifact):
        return False
    try:
        candidate_function_ssa = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        candidate_function_ssa = None
    function_ssa = candidate_function_ssa if isinstance(candidate_function_ssa, SSAFunctionArtifact) else None
    try:
        restore_evidence = cast(
            _SegmentRestoreEvidenceSurface,
            boundary._inertia_segment_stack_restore_artifact,
        )
        restore_sources = restore_evidence.restore_sources
    except AttributeError:
        restore_sources = ()
    segment_artifact = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=function_ssa,
        restore_sources=restore_sources,
    )
    boundary._inertia_segment_state_artifact = segment_artifact
    return False
