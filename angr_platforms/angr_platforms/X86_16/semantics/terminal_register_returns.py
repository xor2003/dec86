"""Classify terminal AX byte-lane writes from bounded binary paths.

Layer: Semantics.
Responsibility: expose typed AL/AH/AX return-width evidence from binary
instructions without choosing a C type or mutating a function prototype.
Forbidden: source/COD/name evidence, C-AST rewriting, or prototype repair.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from typing import Any, Protocol, cast

from angr.errors import SimTranslationError

from .branch_target_return import TerminalAxReturnEffectKind8616, terminal_ax_return_effect_8616

__all__ = [
    "TerminalAxReturnEvidence8616",
    "TerminalAxReturnLane8616",
    "collect_terminal_ax_return_evidence_8616",
    "terminal_ax_return_lane_states_8616",
]

_CONDITIONAL_BRANCHES_8616 = frozenset(
    {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "jcxz",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
        "loop",
        "loope",
        "loopne",
        "loopnz",
        "loopz",
    }
)


class TerminalAxReturnLane8616(IntFlag):
    """AX byte lanes definitely written along one bounded terminal path."""

    NONE = 0
    LOW = 1
    HIGH = 2
    WORD = LOW | HIGH


@dataclass(frozen=True, slots=True)
class TerminalAxReturnEvidence8616:
    """Closed accounting for entry-reachable binary terminal AX paths."""

    states: frozenset[TerminalAxReturnLane8616]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every discovered terminal-path fact was classified."""
        return (
            self.raw_fact_count > 0
            and self.normalized_fact_count == self.raw_fact_count
            and self.classified_fact_count == self.raw_fact_count
            and self.materialized_count == self.classified_fact_count
            and self.failure_count == 0
        )

    @property
    def proves_missing_value_path(self) -> bool:
        """Return whether a complete census includes a path with no AX definition."""
        return self.complete and TerminalAxReturnLane8616.NONE in self.states


class _FunctionSurface8616(Protocol):
    """angr function fields consumed by terminal-path semantics."""

    addr: int
    block_addrs_set: set[int]


def _inner_instruction_8616(insn: object) -> object:
    """Return an angr wrapper's underlying capstone instruction."""
    # Dynamic angr/capstone compatibility boundary.
    return getattr(insn, "insn", insn)


def _register_name_8616(insn: object, reg_id: int) -> str:
    """Return a normalized capstone register name."""
    try:
        return str(cast(Any, _inner_instruction_8616(insn)).reg_name(reg_id)).lower()
    except Exception:
        return ""


def _written_lane_8616(insn: object, effect_dst: str | None) -> TerminalAxReturnLane8616:
    """Return a proven AX lane written by one instruction."""
    if effect_dst == "ax":
        return TerminalAxReturnLane8616.WORD
    if effect_dst == "al":
        return TerminalAxReturnLane8616.LOW
    if effect_dst == "ah":
        return TerminalAxReturnLane8616.HIGH
    # The typed effect vocabulary is intentionally incomplete. This fallback
    # accepts only instructions whose first register operand is a destination.
    inner = _inner_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    mnemonic = str(getattr(inner, "mnemonic", "") or "").lower()
    if mnemonic not in {
        "mov", "lea", "pop", "add", "adc", "sub", "sbb", "and", "or", "xor",
        "inc", "dec", "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr",
    }:
        return TerminalAxReturnLane8616.NONE
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if not operands:
        return TerminalAxReturnLane8616.NONE
    # Dynamic capstone compatibility boundary.
    if int(getattr(operands[0], "type", -1)) != 1:
        return TerminalAxReturnLane8616.NONE
    # Dynamic capstone compatibility boundary.
    reg_name = _register_name_8616(insn, int(getattr(operands[0], "reg", 0) or 0))
    return {
        "ax": TerminalAxReturnLane8616.WORD,
        "al": TerminalAxReturnLane8616.LOW,
        "ah": TerminalAxReturnLane8616.HIGH,
    }.get(reg_name, TerminalAxReturnLane8616.NONE)


def _direct_jump_target_8616(insn: object) -> int | None:
    """Return a direct immediate jump target, if present."""
    inner = _inner_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if len(operands) != 1:
        return None
    operand = operands[0]
    # Dynamic capstone compatibility boundary.
    if int(getattr(operand, "type", -1)) != 2:
        return None
    # Dynamic capstone compatibility boundary.
    target = getattr(operand, "imm", None)
    return target if isinstance(target, int) else None


def _instruction_fallthrough_8616(insn: object) -> int | None:
    """Return the next instruction address across the Capstone boundary."""
    inner = cast(Any, _inner_instruction_8616(insn))
    try:
        address = inner.address
        size = inner.size
    except AttributeError:
        return None
    if not isinstance(address, int) or not isinstance(size, int) or size <= 0:
        return None
    return address + size


def collect_terminal_ax_return_evidence_8616(
    project: object,
    function: object,
) -> TerminalAxReturnEvidence8616:
    """Collect closed AX lane evidence along bounded paths to binary returns."""
    function_surface = cast(_FunctionSurface8616, function)
    try:
        block_addrs = frozenset(int(addr) for addr in (function_surface.block_addrs_set or ()))
    except AttributeError:
        block_addrs = frozenset()
    try:
        entry_addr = function_surface.addr
    except AttributeError:
        entry_addr = None
    if not isinstance(entry_addr, int):
        entry_addr = min(block_addrs, default=None)
    if not isinstance(entry_addr, int) or entry_addr not in block_addrs:
        return TerminalAxReturnEvidence8616(frozenset(), 1, 0, 0, 0, 1)
    project_dynamic = cast(Any, project)
    terminal_states: set[TerminalAxReturnLane8616] = set()
    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    failure_count = 0

    def _record_terminal(lanes: TerminalAxReturnLane8616) -> None:
        """Materialize one classified terminal-path state into the evidence set."""
        nonlocal raw_fact_count, normalized_fact_count, classified_fact_count, materialized_count
        raw_fact_count += 1
        normalized_fact_count += 1
        classified_fact_count += 1
        materialized_count += 1
        terminal_states.add(lanes)

    def _record_failure() -> None:
        """Record one reachable control-flow fact that could not be classified."""
        nonlocal raw_fact_count, failure_count
        raw_fact_count += 1
        failure_count += 1

    def _scan(block_addr: int, lanes: TerminalAxReturnLane8616, path: frozenset[int]) -> None:
        """Follow one entry-reachable path without crossing cycles."""
        if block_addr in path:
            return
        try:
            block = project_dynamic.factory.block(block_addr, opt_level=0)
        except (KeyError, SimTranslationError, ValueError):
            _record_failure()
            return
        # Dynamic angr/capstone compatibility boundary.
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            _record_failure()
            return
        for insn in insns:
            effect = terminal_ax_return_effect_8616(insn)
            if effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER:
                lanes = TerminalAxReturnLane8616.NONE
            else:
                written = _written_lane_8616(insn, effect.dst_reg)
                lanes = written if written == TerminalAxReturnLane8616.WORD else lanes | written
            # Dynamic capstone compatibility boundary.
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            if mnemonic in {"ret", "retf", "iret"}:
                _record_terminal(lanes)
                return
            if mnemonic in {"jmp", "ljmp"}:
                target = _direct_jump_target_8616(insn)
                if isinstance(target, int) and target in block_addrs:
                    _scan(target, lanes, path | {block_addr})
                else:
                    _record_failure()
                return
            if mnemonic in _CONDITIONAL_BRANCHES_8616:
                target = _direct_jump_target_8616(insn)
                fallthrough = _instruction_fallthrough_8616(insn)
                successors = tuple(dict.fromkeys((target, fallthrough)))
                for successor in successors:
                    if isinstance(successor, int) and successor in block_addrs:
                        _scan(successor, lanes, path | {block_addr})
                    else:
                        _record_failure()
                return
        fallthrough = _instruction_fallthrough_8616(insns[-1])
        if isinstance(fallthrough, int) and fallthrough in block_addrs:
            _scan(fallthrough, lanes, path | {block_addr})
        else:
            _record_failure()

    _scan(entry_addr, TerminalAxReturnLane8616.NONE, frozenset())
    return TerminalAxReturnEvidence8616(
        states=frozenset(terminal_states),
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )


def terminal_ax_return_lane_states_8616(
    project: object,
    function: object,
) -> frozenset[TerminalAxReturnLane8616]:
    """Return the compatibility lane-state view of closed terminal evidence."""
    return collect_terminal_ax_return_evidence_8616(project, function).states
