"""Classify exact paired callee-saved PUSH/POP instruction evidence.

Layer: Types/Lowering.
Responsibility: normalize decoded Capstone instruction facts into exact
callee-saved frame pairs consumed by structured stack-carrier lowering.
Forbidden: assembly-text matching, source/COD recovery, or cleanup guesses.
Consumes alias, widening, and typed facts from decoded instruction evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable, Set
from dataclasses import dataclass
from typing import Protocol, cast

from capstone.x86_const import X86_INS_POP, X86_INS_PUSH, X86_INS_RET, X86_OP_REG


class _CapstoneOperand8616(Protocol):
    """Capstone operand fields consumed by frame-pair classification."""

    type: int
    reg: int


class _CapstoneInstruction8616(Protocol):
    """Capstone instruction fields consumed by frame-pair classification."""

    address: int
    id: int
    operands: tuple[_CapstoneOperand8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return the architecture register name for one Capstone id."""
        ...


@dataclass(frozen=True)
class CalleeSavedFramePair8616:
    """Pair one exact frame PUSH with its epilogue POP."""

    register_name: str
    push_addr: int
    pop_addr: int

    @property
    def instruction_addresses(self) -> frozenset[int]:
        """Return both machine instruction addresses in the pair."""
        return frozenset((self.push_addr, self.pop_addr))


def _decoded_register_name_8616(instruction: object, instruction_id: int) -> str | None:
    """Return one decoded register operand at the Capstone boundary."""
    instruction_surface = cast(_CapstoneInstruction8616, instruction)
    try:
        if instruction_surface.id != instruction_id:
            return None
        operand = instruction_surface.operands[0]
        if operand.type != X86_OP_REG:
            return None
        register_name = instruction_surface.reg_name(operand.reg)
    except (AttributeError, IndexError, TypeError):
        return None
    return register_name.lower() if isinstance(register_name, str) else None


def callee_saved_frame_pairs_8616(
    instructions: Iterable[object],
    saved_registers: Set[str],
) -> tuple[CalleeSavedFramePair8616, ...]:
    """Return deterministic first-PUSH/epilogue-POP pairs for proven registers."""
    normalized_saved = frozenset(name.lower() for name in saved_registers)
    first_push: dict[str, int] = {}
    epilogue_pop: dict[str, int] = {}
    ordered: list[_CapstoneInstruction8616] = []
    seen_addresses: set[tuple[int, int]] = set()
    for instruction in instructions:
        instruction_surface = cast(_CapstoneInstruction8616, instruction)
        try:
            address = instruction_surface.address
            instruction_id = instruction_surface.id
        except AttributeError:
            continue
        if not isinstance(address, int) or not isinstance(instruction_id, int):
            continue
        key = (address, instruction_id)
        if key in seen_addresses:
            continue
        seen_addresses.add(key)
        ordered.append(instruction_surface)
        register_name = _decoded_register_name_8616(instruction_surface, X86_INS_PUSH)
        if register_name is not None and register_name in normalized_saved:
            first_push.setdefault(register_name, address)
        if instruction_id == X86_INS_RET:
            break

    for instruction in reversed(ordered):
        register_name = _decoded_register_name_8616(instruction, X86_INS_POP)
        if register_name is not None and register_name in normalized_saved:
            epilogue_pop.setdefault(register_name, instruction.address)

    return tuple(
        CalleeSavedFramePair8616(
            register_name=register_name,
            push_addr=first_push[register_name],
            pop_addr=epilogue_pop[register_name],
        )
        for register_name in sorted(normalized_saved)
        if register_name in first_push and register_name in epilogue_pop
    )


__all__ = ["CalleeSavedFramePair8616", "callee_saved_frame_pairs_8616"]
