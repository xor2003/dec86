from angr_platforms.X86_16.addressing_helpers import (
    WidthProfile,
    address_width_bits,
    address_step,
    displacement_width_bits,
    operand_width_bits,
    signed_displacement,
)
from pyvex.lifting.util.vex_helper import Type


class _FakeEmu:
    def __init__(self):
        self.calls = []

    def constant(self, value, ty):
        self.calls.append((value, ty))
        return (value, ty)


def test_width_helpers_cover_real_mode_and_386_extension_paths():
    assert operand_width_bits(False, False) == 16
    assert operand_width_bits(False, True) == 32
    assert operand_width_bits(True, False) == 32
    assert operand_width_bits(True, True) == 16

    assert address_width_bits(False, False) == 16
    assert address_width_bits(False, True) == 32
    assert address_width_bits(True, False) == 32
    assert address_width_bits(True, True) == 16


def test_displacement_helpers_normalize_signed_values_and_widths():
    assert signed_displacement(0x7F, 8) == 127
    assert signed_displacement(0x80, 8) == -128
    assert signed_displacement(0xFF, 8) == -1

    assert displacement_width_bits(0, 6, 16) == 16
    assert displacement_width_bits(1, 0, 16) == 8
    assert displacement_width_bits(2, 7, 16) == 16
    assert displacement_width_bits(0, 5, 32) == 32
    assert displacement_width_bits(1, 2, 32) == 8
    assert displacement_width_bits(2, 2, 32) == 32


def test_address_step_uses_bit_width_specific_constants():
    emu = _FakeEmu()

    sixteen = address_step(emu, 2, 16)
    thirty_two = address_step(emu, 4, 32)

    assert emu.calls[0][0] == 2
    assert emu.calls[1][0] == 4
    assert emu.calls[0][1] == Type.int_16
    assert emu.calls[1][1] == Type.int_32
    assert sixteen == (2, emu.calls[0][1])
    assert thirty_two == (4, emu.calls[1][1])


def test_width_profile_exposes_byte_counts():
    profile = WidthProfile(operand_bits=32, address_bits=16)

    assert profile.operand_bytes == 4
    assert profile.address_bytes == 2
