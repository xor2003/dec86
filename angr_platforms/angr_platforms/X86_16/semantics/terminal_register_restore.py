"""Classify balanced entry-save and terminal-restore register sites.

Layer: Semantics.
Responsibility: identify exact POP instructions that restore entry-saved
registers without treating those restores as newly computed return values.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, cast

__all__ = ["terminal_register_restore_sites_8616"]


class _OperandBoundary8616(Protocol):
    """Capstone register operand fields consumed by restore classification."""

    type: int
    reg: int


class _InstructionBoundary8616(Protocol):
    """Capstone instruction fields consumed by restore classification."""

    address: int
    mnemonic: str
    operands: tuple[_OperandBoundary8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return an architecture register name."""


def _inner_instruction_8616(instruction: object) -> object:
    """Return an angr wrapper's underlying Capstone instruction."""
    try:
        return cast(object, instruction.insn)  # type: ignore[attr-defined]
    except AttributeError:
        return instruction


def _register_operand_name_8616(instruction: object) -> str | None:
    """Return one exact register operand name, or refuse the instruction."""
    inner = cast(_InstructionBoundary8616, _inner_instruction_8616(instruction))
    try:
        operands = tuple(inner.operands)
    except (AttributeError, TypeError):
        return None
    if len(operands) != 1 or operands[0].type != 1:
        return None
    try:
        return str(inner.reg_name(operands[0].reg)).lower()
    except (AttributeError, TypeError, ValueError):
        return None


def _instruction_mnemonic_8616(instruction: object) -> str:
    """Return a normalized Capstone mnemonic."""
    try:
        return str(cast(_InstructionBoundary8616, _inner_instruction_8616(instruction)).mnemonic).lower()
    except (AttributeError, TypeError, ValueError):
        return ""


def _instruction_address_8616(instruction: object) -> int | None:
    """Return an exact Capstone instruction address."""
    try:
        address = cast(_InstructionBoundary8616, _inner_instruction_8616(instruction)).address
    except AttributeError:
        return None
    return address if isinstance(address, int) else None


def terminal_register_restore_sites_8616(
    instructions_by_block: Mapping[int, tuple[object, ...]],
    entry_addr: int,
) -> frozenset[int]:
    """Return balanced restore sites using complete decoded block evidence.

    The current semantic contract intentionally preserves the legacy ordering:
    entry saves are the leading PUSH sequence and restores are the POP sequence
    immediately preceding the first address-ordered return. The Frontend owns
    byte decoding; this owner only classifies register-transfer meaning.
    """
    entry_instructions = instructions_by_block.get(entry_addr, ())
    entry_saves: list[str] = []
    for instruction in entry_instructions:
        if _instruction_mnemonic_8616(instruction) != "push":
            break
        register_name = _register_operand_name_8616(instruction)
        if register_name is None:
            break
        entry_saves.append(register_name)
    if not entry_saves:
        return frozenset()

    addressed: list[tuple[int, object]] = []
    for instructions in instructions_by_block.values():
        for instruction in instructions:
            instruction_addr = _instruction_address_8616(instruction)
            if instruction_addr is not None:
                addressed.append((instruction_addr, instruction))
    ordered = tuple(instruction for _address, instruction in sorted(addressed))
    terminal_index = next(
        (
            index
            for index, instruction in enumerate(ordered)
            if _instruction_mnemonic_8616(instruction) in {"ret", "retf", "iret"}
        ),
        None,
    )
    if terminal_index is None:
        return frozenset()

    restores: list[tuple[str, int]] = []
    for instruction in reversed(ordered[:terminal_index]):
        if _instruction_mnemonic_8616(instruction) != "pop":
            break
        register_name = _register_operand_name_8616(instruction)
        address = _instruction_address_8616(instruction)
        if register_name is None or address is None:
            break
        restores.append((register_name, address))
    if tuple(name for name, _address in restores) != tuple(entry_saves):
        return frozenset()
    return frozenset(address for _name, address in restores)
