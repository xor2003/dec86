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

from enum import IntFlag
from typing import Any, Protocol, cast

from angr.errors import SimTranslationError

from .branch_target_return import TerminalAxReturnEffectKind8616, terminal_ax_return_effect_8616

__all__ = ["TerminalAxReturnLane8616", "terminal_ax_return_lane_states_8616"]

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


def terminal_ax_return_lane_states_8616(
    project: object,
    function: object,
) -> frozenset[TerminalAxReturnLane8616]:
    """Collect AX lane states along bounded entry-reachable paths to returns."""
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
        return frozenset()
    project_dynamic = cast(Any, project)
    terminal_states: set[TerminalAxReturnLane8616] = set()

    def _scan(block_addr: int, lanes: TerminalAxReturnLane8616, path: frozenset[int]) -> None:
        """Follow one entry-reachable path without crossing cycles."""
        if block_addr in path:
            return
        try:
            block = project_dynamic.factory.block(block_addr, opt_level=0)
        except (KeyError, SimTranslationError, ValueError):
            return
        # Dynamic angr/capstone compatibility boundary.
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        for insn in insns:
            effect = terminal_ax_return_effect_8616(insn)
            if effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER:
                lanes = TerminalAxReturnLane8616.NONE
            else:
                written = _written_lane_8616(insn, effect.dst_reg)
                lanes = written if written is TerminalAxReturnLane8616.WORD else lanes | written
            # Dynamic capstone compatibility boundary.
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            if mnemonic in {"ret", "retf", "iret"}:
                terminal_states.add(lanes)
                return
            if mnemonic in {"jmp", "ljmp"}:
                target = _direct_jump_target_8616(insn)
                if isinstance(target, int) and target in block_addrs:
                    _scan(target, lanes, path | {block_addr})
                return
            if mnemonic in _CONDITIONAL_BRANCHES_8616:
                target = _direct_jump_target_8616(insn)
                fallthrough = _instruction_fallthrough_8616(insn)
                for successor in (target, fallthrough):
                    if isinstance(successor, int) and successor in block_addrs:
                        _scan(successor, lanes, path | {block_addr})
                return
        if insns:
            fallthrough = _instruction_fallthrough_8616(insns[-1])
            if isinstance(fallthrough, int) and fallthrough in block_addrs:
                _scan(fallthrough, lanes, path | {block_addr})

    _scan(entry_addr, TerminalAxReturnLane8616.NONE, frozenset())
    return frozenset(terminal_states)
