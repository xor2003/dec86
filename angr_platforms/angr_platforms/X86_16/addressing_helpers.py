from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pyvex.lifting.util.vex_helper import Type

from .regs import reg16_t, reg32_t, sgreg_t


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


@dataclass(frozen=True)
class DecodeWidthMatrixCase:
    name: str
    mode32: bool
    chsz_op: bool
    chsz_ad: bool
    profile: WidthProfile


DECODE_WIDTH_MATRIX: tuple[DecodeWidthMatrixCase, ...] = (
    DecodeWidthMatrixCase("16/16", False, False, False, decode_width_profile(False, False, False)),
    DecodeWidthMatrixCase("32/16", False, True, False, decode_width_profile(False, True, False)),
    DecodeWidthMatrixCase("16/32", False, False, True, decode_width_profile(False, False, True)),
    DecodeWidthMatrixCase("32/32", True, False, False, decode_width_profile(True, False, False)),
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


def describe_x86_16_decode_width_matrix() -> tuple[tuple[str, int, int], ...]:
    return tuple((case.name, case.profile.operand_bits, case.profile.address_bits) for case in DECODE_WIDTH_MATRIX)


def describe_x86_16_mixed_width_extension_surface() -> dict[str, object]:
    return {
        "matrix": tuple(
            {
                "name": case.name,
                "operand_bits": case.profile.operand_bits,
                "address_bits": case.profile.address_bits,
                "mode32": case.mode32,
                "chsz_op": case.chsz_op,
                "chsz_ad": case.chsz_ad,
            }
            for case in DECODE_WIDTH_MATRIX
        ),
        "supported_pairs": tuple((case.profile.operand_bits, case.profile.address_bits) for case in DECODE_WIDTH_MATRIX),
        "address_widths": tuple(sorted({case.profile.address_bits for case in DECODE_WIDTH_MATRIX})),
        "operand_widths": tuple(sorted({case.profile.operand_bits for case in DECODE_WIDTH_MATRIX})),
    }


def linear_address(emu, segment, offset):
    return emu.v2p(segment, offset)


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


def modrm16_effective_offset(emu, modrm, disp8: int, disp16: int):
    addr = emu.constant(0, Type.int_16)

    if modrm.mod == 1:
        addr = addr + emu.constant(signed_displacement(disp8, 8) & 0xFFFF, Type.int_16)
    elif modrm.mod == 2:
        addr = addr + emu.constant(disp16, Type.int_16)

    rm = modrm.rm
    if rm in (0, 1, 7):
        addr = addr + emu.get_gpreg(reg16_t.BX)
    elif rm in (2, 3, 6):
        if modrm.mod == 0 and rm == 6:
            addr = addr + emu.constant(disp16, Type.int_16)
        else:
            addr = addr + emu.get_gpreg(reg16_t.BP)

    if rm < 6:
        if rm % 2:
            addr = addr + emu.get_gpreg(reg16_t.DI)
        else:
            addr = addr + emu.get_gpreg(reg16_t.SI)

    return addr


def modrm32_effective_offset(emu, modrm, sib, disp8: int, disp32: int):
    addr = emu.constant(0, Type.int_32)

    if modrm.mod == 1:
        addr = addr + emu.constant(signed_displacement(disp8, 8) & 0xFFFFFFFF, Type.int_32)
    elif modrm.mod == 2:
        addr = addr + emu.constant(disp32, Type.int_32)

    rm = modrm.rm
    if rm == 4:
        if sib.base == 5 and modrm.mod == 0:
            base = emu.constant(disp32, Type.int_32)
        elif sib.base == 4:
            base = emu.get_gpreg(reg32_t.ESP)
        else:
            base = emu.get_gpreg(reg32_t(sib.base))
        if sib.index == 4:
            index = emu.constant(0, Type.int_32)
        else:
            index = emu.get_gpreg(reg32_t(sib.index))
        addr = addr + base + index * (1 << sib.scale)
        return addr

    if rm == 5 and modrm.mod == 0:
        return addr + emu.constant(disp32, Type.int_32)
    return addr + emu.get_gpreg(reg32_t(rm))


def resolve_modrm16_address(emu, modrm, disp8: int, disp16: int) -> tuple[sgreg_t, Any]:
    segment = default_segment_for_modrm16(modrm.mod, modrm.rm)
    return segment, modrm16_effective_offset(emu, modrm, disp8, disp16)


def resolve_modrm32_address(emu, modrm, sib, disp8: int, disp32: int) -> tuple[sgreg_t, Any]:
    segment = default_segment_for_modrm32(modrm.mod, modrm.rm, sib.base if modrm.rm == 4 else None)
    return segment, modrm32_effective_offset(emu, modrm, sib, disp8, disp32)


def resolve_linear_operand(emu, segment: sgreg_t, offset, width_bits: int, address_bits: int) -> ResolvedMemoryOperand:
    return ResolvedMemoryOperand(segment, offset, linear_address(emu, segment, offset), width_bits, address_bits)


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


def advance_ip16(emu, byte_count: int):
    return emu.get_gpreg(reg16_t.IP) + emu.constant(byte_count, Type.int_16)


def advance_eip32(emu, byte_count: int):
    return emu.get_gpreg(reg32_t.EIP) + emu.constant(byte_count, Type.int_32)
