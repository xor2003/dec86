from __future__ import annotations

from dataclasses import dataclass

from pyvex.lifting.util.vex_helper import Type


def operand_width_bits(mode32: bool, chsz_op: bool = False) -> int:
    return 32 if mode32 ^ bool(chsz_op) else 16


def address_width_bits(mode32: bool, chsz_ad: bool = False) -> int:
    return 32 if mode32 ^ bool(chsz_ad) else 16


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
class WidthProfile:
    operand_bits: int
    address_bits: int

    @property
    def operand_bytes(self) -> int:
        return self.operand_bits // 8

    @property
    def address_bytes(self) -> int:
        return self.address_bits // 8
