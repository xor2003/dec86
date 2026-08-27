"""Prove decoded instructions preserve a register's exact value.

Layer: Semantics.
Responsibility: classify exact identity operations on decoded x86-16 register
values for downstream Alias and recovery-metadata consumers.
Forbidden: source/COD/rendered-C inference or call-argument materialization.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, cast

from capstone.x86_const import X86_OP_REG

__all__ = (
    "decoded_instruction_preserves_register_value_8616",
    "decoded_instruction_self_clears_register_8616",
    "register_value_family_8616",
)


class _Operand8616(Protocol):
    """Capstone operand fields needed for identity classification."""

    type: int
    reg: int


class _DecodedInstruction8616(Protocol):
    """Capstone instruction fields needed for identity classification."""

    operands: Sequence[_Operand8616]

    def reg_name(self, reg_id: int) -> str:
        """Return the backend register name for ``reg_id``."""


class _Instruction8616(Protocol):
    """Decoded instruction wrapper consumed at the frontend boundary."""

    mnemonic: str
    insn: _DecodedInstruction8616


_REGISTER_VALUE_FAMILIES_8616: dict[str, frozenset[str]] = {
    "ax": frozenset({"ax", "al", "ah"}),
    "bx": frozenset({"bx", "bl", "bh"}),
    "cx": frozenset({"cx", "cl", "ch"}),
    "dx": frozenset({"dx", "dl", "dh"}),
}


def register_value_family_8616(register: str) -> frozenset[str]:
    """Return all decoded register names sharing one 16-bit value."""
    normalized = register.lower()
    return _REGISTER_VALUE_FAMILIES_8616.get(normalized, frozenset({normalized}))


def _same_decoded_register_pair_8616(instruction: object) -> str | None:
    """Return the normalized register repeated by a two-register instruction."""
    decoded = cast(_Instruction8616, instruction)
    try:
        operands = tuple(decoded.insn.operands)
    except (AttributeError, TypeError):
        return None
    if len(operands) != 2 or any(operand.type != X86_OP_REG for operand in operands):
        return None
    try:
        lhs_name = decoded.insn.reg_name(operands[0].reg).lower()
        rhs_name = decoded.insn.reg_name(operands[1].reg).lower()
    except (AttributeError, TypeError):
        return None
    return lhs_name if lhs_name == rhs_name else None


def decoded_instruction_preserves_register_value_8616(
    instruction: object,
    register: str,
) -> bool:
    """Prove an exact same-register identity operation preserves ``register``.

    Flag effects are intentionally outside this value-only fact. Any dynamic
    boundary failure remains unknown and therefore refuses preservation.
    """
    decoded = cast(_Instruction8616, instruction)
    try:
        mnemonic = decoded.mnemonic.lower()
    except AttributeError:
        return False
    repeated = _same_decoded_register_pair_8616(decoded)
    return mnemonic in {"and", "mov", "or"} and repeated in register_value_family_8616(register)


def decoded_instruction_self_clears_register_8616(
    instruction: object,
    register: str,
) -> bool:
    """Prove that exact ``sub reg, reg`` or ``xor reg, reg`` clears a register."""
    decoded = cast(_Instruction8616, instruction)
    try:
        mnemonic = decoded.mnemonic.lower()
    except AttributeError:
        return False
    repeated = _same_decoded_register_pair_8616(decoded)
    return mnemonic in {"sub", "xor"} and repeated in register_value_family_8616(register)
