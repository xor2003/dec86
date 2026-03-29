from angr_platforms.X86_16.instruction import NONE, REPZ
from angr_platforms.X86_16.regs import reg16_t, sgreg_t
from angr_platforms.X86_16.string_helpers import (
    repeat_prefix_cond,
    repeat_jump,
    string_source_segment,
)


class _JumpRecorder:
    def __init__(self):
        self.calls = []

    def jump(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class _StringEmu:
    def __init__(self, *, cx: int = 3, zf: bool = True):
        self.gpregs = {reg16_t.CX: cx, reg16_t.IP: 0x0100}
        self.zf = zf
        self.lifter_instruction = _JumpRecorder()

    def get_gpreg(self, reg):
        return self.gpregs[reg]

    def set_gpreg(self, reg, value):
        self.gpregs[reg] = value

    def constant(self, value, _ty):
        return value

    def is_zero(self):
        return self.zf


class _Cond:
    def __init__(self, value: bool):
        self.value = value

    def cast_to(self, _ty):
        return self

    def __and__(self, other):
        return self.value and other


class _Instr:
    def __init__(self, pre_segment=None, pre_repeat=NONE):
        self.pre_segment = pre_segment
        self.pre_repeat = pre_repeat


def test_string_source_segment_defaults_to_ds_and_honors_overrides():
    assert string_source_segment(_Instr()) == sgreg_t.DS
    assert string_source_segment(_Instr(pre_segment=sgreg_t.CS.value)) == sgreg_t.CS


def test_repeat_prefix_cond_consumes_cx_for_repeated_string_ops():
    emu = _StringEmu(cx=4)
    instr = _Instr(pre_repeat=REPZ)

    cond = repeat_prefix_cond(emu, instr)

    assert emu.get_gpreg(reg16_t.CX) == 3
    assert cond is True


def test_repeat_jump_uses_repz_and_current_zero_flag():
    emu = _StringEmu(cx=4, zf=True)
    instr = _Instr(pre_repeat=REPZ)

    repeat_jump(emu, instr, _Cond(True))

    assert emu.lifter_instruction.calls
