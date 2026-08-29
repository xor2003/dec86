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
from enum import StrEnum
from typing import Protocol, cast

from capstone.x86_const import X86_OP_REG

__all__ = (
    "AxValueView8616",
    "ByteReturnExtensionKind8616",
    "decoded_ax_read_view_8616",
    "decoded_byte_return_extension_8616",
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

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]:
        """Return exact registers read and written by this instruction."""


class _Instruction8616(Protocol):
    """Decoded instruction wrapper consumed at the frontend boundary."""

    mnemonic: str
    insn: _DecodedInstruction8616


class AxValueView8616(StrEnum):
    """Exact AX-family view read by one caller instruction."""

    AL = "al"
    AH = "ah"
    AX = "ax"


class ByteReturnExtensionKind8616(StrEnum):
    """Binary-proven promotion of a returned AL value to AX."""

    SIGN_EXTEND_AL_TO_AX = "sign_extend_al_to_ax"
    ZERO_EXTEND_AL_TO_AX = "zero_extend_al_to_ax"


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


def _decoded_instruction_surface_8616(
    instruction: object,
) -> _DecodedInstruction8616 | None:
    """Normalize wrapped test instructions and direct Capstone instructions."""
    wrapped = cast(_Instruction8616, instruction)
    candidates: tuple[_DecodedInstruction8616, ...]
    try:
        candidates = (wrapped.insn, cast(_DecodedInstruction8616, instruction))
    except AttributeError:
        candidates = (cast(_DecodedInstruction8616, instruction),)
    for decoded in candidates:
        try:
            tuple(decoded.operands)
            _ = decoded.reg_name
        except (AttributeError, TypeError):
            continue
        return decoded
    return None


def _same_decoded_register_pair_8616(instruction: object) -> str | None:
    """Return the normalized register repeated by a two-register instruction."""
    decoded = _decoded_instruction_surface_8616(instruction)
    if decoded is None:
        return None
    operands = tuple(decoded.operands)
    if len(operands) != 2 or any(operand.type != X86_OP_REG for operand in operands):
        return None
    try:
        lhs_name = decoded.reg_name(operands[0].reg).lower()
        rhs_name = decoded.reg_name(operands[1].reg).lower()
    except (AttributeError, TypeError):
        return None
    return lhs_name if lhs_name == rhs_name else None


def decoded_ax_read_view_8616(instruction: object) -> AxValueView8616 | None:
    """Return the exact AX-family view read by one decoded instruction."""
    decoded = _decoded_instruction_surface_8616(instruction)
    if decoded is None:
        return None
    try:
        read_ids, _written_ids = decoded.regs_access()
        names = {decoded.reg_name(reg_id).lower() for reg_id in read_ids}
    except (AttributeError, TypeError):
        names = {
            decoded.reg_name(operand.reg).lower()
            for operand in decoded.operands
            if operand.type == X86_OP_REG
        }
    if "ax" in names or {"al", "ah"}.issubset(names):
        return AxValueView8616.AX
    if "al" in names:
        return AxValueView8616.AL
    if "ah" in names:
        return AxValueView8616.AH
    return None


def decoded_byte_return_extension_8616(
    instruction: object,
) -> ByteReturnExtensionKind8616 | None:
    """Classify an exact caller-side AL-to-AX promotion instruction."""
    decoded = cast(_Instruction8616, instruction)
    try:
        mnemonic = decoded.mnemonic.lower()
    except AttributeError:
        return None
    if mnemonic == "cbw":
        return ByteReturnExtensionKind8616.SIGN_EXTEND_AL_TO_AX
    if decoded_instruction_self_clears_register_8616(instruction, "ah"):
        return ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX
    return None


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
