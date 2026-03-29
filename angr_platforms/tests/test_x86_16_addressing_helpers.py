from angr_platforms.X86_16.addressing_helpers import (
    ResolvedMemoryOperand,
    WidthProfile,
    address_width_bits,
    address_step,
    decode_width_profile,
    default_segment_for_modrm16,
    default_segment_for_modrm32,
    displacement_width_bits,
    load_far_pointer,
    load_far_pointer16,
    load_resolved_operand,
    load_word_pair16,
    resolve_linear_operand,
    operand_width_bits,
    signed_displacement,
    store_resolved_operand,
)
from pyvex.lifting.util.vex_helper import Type
from angr_platforms.X86_16.regs import sgreg_t


class _FakeEmu:
    def __init__(self):
        self.calls = []
        self.loads = []
        self.stores = []

    def constant(self, value, ty):
        self.calls.append((value, ty))
        return (value, ty)

    def v2p(self, segment, offset):
        return (segment, offset)

    def get_data8(self, segment, offset):
        self.loads.append((segment, offset))
        return ("byte", segment, offset)

    def get_data16(self, segment, offset):
        self.loads.append((segment, offset))
        return ("word", segment, offset)

    def get_data32(self, segment, offset):
        self.loads.append((segment, offset))
        return ("dword", segment, offset)

    def put_data8(self, segment, offset, value):
        self.stores.append((8, segment, offset, value))

    def put_data16(self, segment, offset, value):
        self.stores.append((16, segment, offset, value))

    def put_data32(self, segment, offset, value):
        self.stores.append((32, segment, offset, value))


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


def test_default_segment_helpers_match_x86_16_addressing_rules():
    assert default_segment_for_modrm16(0, 0) == sgreg_t.DS
    assert default_segment_for_modrm16(0, 6) == sgreg_t.DS
    assert default_segment_for_modrm16(1, 2) == sgreg_t.SS
    assert default_segment_for_modrm16(2, 3) == sgreg_t.SS

    assert default_segment_for_modrm32(0, 0) == sgreg_t.DS
    assert default_segment_for_modrm32(0, 4, 4) == sgreg_t.SS
    assert default_segment_for_modrm32(0, 4, 5) == sgreg_t.SS
    assert default_segment_for_modrm32(0, 4, 0) == sgreg_t.DS
    assert default_segment_for_modrm32(1, 5) == sgreg_t.SS


def test_resolved_memory_operand_tracks_segment_offset_and_linear_form():
    emu = _FakeEmu()

    resolved = resolve_linear_operand(emu, sgreg_t.DS, 0x1234, 16, 16)

    assert isinstance(resolved, ResolvedMemoryOperand)
    assert resolved.segment == sgreg_t.DS
    assert resolved.offset == 0x1234
    assert resolved.linear == (sgreg_t.DS, 0x1234)
    assert resolved.width_bits == 16
    assert resolved.address_bits == 16


def test_width_profile_exposes_byte_counts():
    profile = WidthProfile(operand_bits=32, address_bits=16)

    assert profile.operand_bytes == 4
    assert profile.address_bytes == 2


def test_decode_width_profile_covers_explicit_mixed_width_matrix():
    assert decode_width_profile(False, False, False) == WidthProfile(operand_bits=16, address_bits=16)
    assert decode_width_profile(False, True, False) == WidthProfile(operand_bits=32, address_bits=16)
    assert decode_width_profile(False, False, True) == WidthProfile(operand_bits=16, address_bits=32)
    assert decode_width_profile(True, False, False) == WidthProfile(operand_bits=32, address_bits=32)


def test_load_far_pointer16_uses_address_width_specific_step():
    emu = _FakeEmu()

    offset, segment = load_far_pointer16(emu, sgreg_t.DS, 0x1234, address_bits=16)

    assert emu.calls == [(0x1234, Type.int_16), (2, Type.int_16)]
    typed_offset = (0x1234, Type.int_16)
    assert emu.loads[0] == (sgreg_t.DS, typed_offset)
    assert emu.loads[1] == (sgreg_t.DS, typed_offset + emu.calls[1])
    assert offset == ("word", sgreg_t.DS, typed_offset)
    assert segment == ("word", sgreg_t.DS, typed_offset + emu.calls[1])


def test_load_word_pair16_uses_address_width_specific_step():
    emu = _FakeEmu()

    first, second = load_word_pair16(emu, sgreg_t.DS, 0x1234, address_bits=16)

    assert emu.calls == [(0x1234, Type.int_16), (2, Type.int_16)]
    typed_offset = (0x1234, Type.int_16)
    assert emu.loads[0] == (sgreg_t.DS, typed_offset)
    assert emu.loads[1] == (sgreg_t.DS, typed_offset + emu.calls[1])
    assert first == ("word", sgreg_t.DS, typed_offset)
    assert second == ("word", sgreg_t.DS, typed_offset + emu.calls[1])


def test_load_far_pointer_supports_future_32_bit_operand_widths():
    emu = _FakeEmu()

    offset, segment = load_far_pointer(emu, sgreg_t.DS, 0x1234, 32, address_bits=16)

    assert emu.calls == [(0x1234, Type.int_16), (4, Type.int_16)]
    typed_offset = (0x1234, Type.int_16)
    assert emu.loads[0] == (sgreg_t.DS, typed_offset)
    assert emu.loads[1] == (sgreg_t.DS, typed_offset + emu.calls[1])
    assert offset == ("dword", sgreg_t.DS, typed_offset)
    assert segment == ("word", sgreg_t.DS, typed_offset + emu.calls[1])


def test_resolved_memory_helpers_dispatch_by_operand_width():
    emu = _FakeEmu()

    byte_operand = resolve_linear_operand(emu, sgreg_t.DS, 0x10, 8, 16)
    word_operand = resolve_linear_operand(emu, sgreg_t.DS, 0x20, 16, 16)
    dword_operand = resolve_linear_operand(emu, sgreg_t.DS, 0x30, 32, 16)

    assert load_resolved_operand(emu, byte_operand)[0] == "byte"
    assert load_resolved_operand(emu, word_operand)[0] == "word"
    assert load_resolved_operand(emu, dword_operand)[0] == "dword"

    store_resolved_operand(emu, byte_operand, 0x11)
    store_resolved_operand(emu, word_operand, 0x2222)
    store_resolved_operand(emu, dword_operand, 0x33333333)

    assert emu.stores == [
        (8, sgreg_t.DS, 0x10, 0x11),
        (16, sgreg_t.DS, 0x20, 0x2222),
        (32, sgreg_t.DS, 0x30, 0x33333333),
    ]
