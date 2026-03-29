from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pyvex.lifting.util.vex_helper import Type

from .regs import sgreg_t


def operand_width_bits(mode32: bool, chsz_op: bool = False) -> int:
    return 32 if mode32 ^ bool(chsz_op) else 16


def address_width_bits(mode32: bool, chsz_ad: bool = False) -> int:
    return 32 if mode32 ^ bool(chsz_ad) else 16


@dataclass(frozen=True)
class WidthProfile:
    operand_bits: int
    address_bits: int

    @property
    def operand_bytes(self) -> int:
        return self.operand_bits // 8

    @property
    def address_bytes(self) -> int:
        return self.address_bits // 8


def decode_width_profile(mode32: bool, chsz_op: bool = False, chsz_ad: bool = False) -> WidthProfile:
    return WidthProfile(
        operand_bits=operand_width_bits(mode32, chsz_op),
        address_bits=address_width_bits(mode32, chsz_ad),
    )


def displacement_width_bits(mod: int, rm: int, address_bits: int) -> int | None:
    if address_bits == 16:
        if mod == 0 and rm == 6:
            return 16
        if mod == 1:
            return 8
        if mod == 2:
            return 16
        return None
    if mod == 0 and rm == 5:
        return 32
    if mod == 1:
        return 8
    if mod == 2:
        return 32
    return None


def signed_displacement(value: int, width_bits: int) -> int:
    mask = (1 << width_bits) - 1
    value &= mask
    sign_bit = 1 << (width_bits - 1)
    if value & sign_bit:
        return value - (1 << width_bits)
    return value


def type_for_bits(width_bits: int):
    if width_bits == 8:
        return Type.int_8
    if width_bits == 16:
        return Type.int_16
    if width_bits == 32:
        return Type.int_32
    raise ValueError(f"unsupported width: {width_bits}")


def address_step(emu, step_bytes: int, address_bits: int = 16):
    return emu.constant(step_bytes, type_for_bits(address_bits))


@dataclass(frozen=True)
class ResolvedMemoryOperand:
    segment: sgreg_t
    offset: Any
    linear: Any
    width_bits: int
    address_bits: int


def default_segment_for_modrm16(mod: int, rm: int) -> sgreg_t:
    if rm in (2, 3):
        return sgreg_t.SS
    if rm == 6 and mod != 0:
        return sgreg_t.SS
    return sgreg_t.DS


def default_segment_for_modrm32(mod: int, rm: int, sib_base: int | None = None) -> sgreg_t:
    if rm == 4 and sib_base is not None:
        if sib_base in (4, 5):
            return sgreg_t.SS
        return sgreg_t.DS
    if rm == 5 and mod != 0:
        return sgreg_t.SS
    return sgreg_t.DS


def resolve_linear_operand(emu, segment: sgreg_t, offset, width_bits: int, address_bits: int) -> ResolvedMemoryOperand:
    return ResolvedMemoryOperand(segment, offset, emu.v2p(segment, offset), width_bits, address_bits)


def load_resolved_operand(emu, operand: ResolvedMemoryOperand):
    if operand.width_bits == 8:
        return emu.get_data8(operand.segment, operand.offset)
    if operand.width_bits == 16:
        return emu.get_data16(operand.segment, operand.offset)
    if operand.width_bits == 32:
        return emu.get_data32(operand.segment, operand.offset)
    raise ValueError(f"unsupported resolved operand width: {operand.width_bits}")


def store_resolved_operand(emu, operand: ResolvedMemoryOperand, value) -> None:
    if operand.width_bits == 8:
        emu.put_data8(operand.segment, operand.offset, value)
        return
    if operand.width_bits == 16:
        emu.put_data16(operand.segment, operand.offset, value)
        return
    if operand.width_bits == 32:
        emu.put_data32(operand.segment, operand.offset, value)
        return
    raise ValueError(f"unsupported resolved operand width: {operand.width_bits}")


def load_word_pair16(emu, segment: sgreg_t, offset, address_bits: int = 16):
    if isinstance(offset, int):
        offset = emu.constant(offset, type_for_bits(address_bits))
    step = address_step(emu, 2, address_bits)
    first = emu.get_data16(segment, offset)
    second = emu.get_data16(segment, offset + step)
    return first, second


def load_far_pointer(emu, segment: sgreg_t, offset, operand_bits: int, address_bits: int = 16):
    if isinstance(offset, int):
        offset = emu.constant(offset, type_for_bits(address_bits))
    step = address_step(emu, operand_bits // 8, address_bits)
    if operand_bits == 16:
        far_offset = emu.get_data16(segment, offset)
    elif operand_bits == 32:
        far_offset = emu.get_data32(segment, offset)
    else:
        raise ValueError(f"unsupported far pointer operand width: {operand_bits}")
    far_segment = emu.get_data16(segment, offset + step)
    return far_offset, far_segment


def load_far_pointer16(emu, segment: sgreg_t, offset, address_bits: int = 16):
    return load_word_pair16(emu, segment, offset, address_bits=address_bits)
