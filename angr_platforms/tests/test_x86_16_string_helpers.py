from angr_platforms.X86_16.instruction import NONE, REPZ
from angr_platforms.X86_16.regs import reg16_t, sgreg_t
from angr_platforms.X86_16.string_helpers import (
    repeat_prefix_cond,
    repeat_jump,
    string_advance_indices,
    string_compare_values,
    string_source_segment,
)


class _JumpRecorder:
    def __init__(self):
        self.calls = []
        self.irsb = type("_IRSB", (), {"next": None, "jumpkind": None})()

    def jump(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class _IrsbC:
    def ite(self, cond, when_true, when_false):
        return when_true if cond else when_false


class _BoolExpr:
    def __init__(self, value: bool):
        self.rdt = value

    def cast_to(self, _ty):
        return self


class _Const:
    def __init__(self, value):
        self.rdt = value

    def _coerce(self, other):
        return other.rdt if hasattr(other, "rdt") else other

    def __add__(self, other):
        return _Const(self.rdt + self._coerce(other))

    def __radd__(self, other):
        return _Const(self._coerce(other) + self.rdt)

    def __sub__(self, other):
        return _Const(self.rdt - self._coerce(other))

    def __rsub__(self, other):
        return _Const(self._coerce(other) - self.rdt)

    def __eq__(self, other):
        return self.rdt == self._coerce(other)

    def __and__(self, other):
        return self.rdt and self._coerce(other)


class _StringEmu:
    def __init__(self, *, cx: int = 3, zf: bool = True, direction: bool = False):
        self.gpregs = {reg16_t.CX: cx, reg16_t.IP: 0x0100, reg16_t.SI: 0x0200, reg16_t.DI: 0x0300}
        self.zf = zf
        self.direction = direction
        self.lifter_instruction = _JumpRecorder()
        self.lifter_instruction.irsb_c = _IrsbC()
        self.irsb = self.lifter_instruction.irsb

    def get_gpreg(self, reg):
        return self.gpregs[reg]

    def set_gpreg(self, reg, value):
        self.gpregs[reg] = value

    def constant(self, value, _ty):
        return _Const(value)

    def is_zero(self):
        return self.zf

    def is_direction(self):
        return _BoolExpr(self.direction)

    def _vv(self, expr):
        return _Const(expr)


class _Cond:
    def __init__(self, value: bool):
        self.value = value
        self.rdt = value

    def cast_to(self, _ty):
        return self

    def __and__(self, other):
        return self.value and other


class _Instr:
    def __init__(self, pre_segment=None, pre_repeat=NONE, size=2, mode32=False):
        self.pre_segment = pre_segment
        self.pre_repeat = pre_repeat
        self.size = size
        self.mode32 = mode32


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
    emu.gpregs[reg16_t.IP] = 0x0102
    instr = _Instr(pre_repeat=REPZ)

    repeat_jump(emu, instr, _Cond(True))

    assert emu.lifter_instruction.calls
    args, _kwargs = emu.lifter_instruction.calls[0]
    assert args[1] == 0x0100


def test_string_advance_indices_applies_directional_delta_to_all_indices():
    emu = _StringEmu(direction=False)

    delta = string_advance_indices(emu, 2, reg16_t.SI, reg16_t.DI)

    assert delta == 2
    assert emu.get_gpreg(reg16_t.SI) == 0x0202
    assert emu.get_gpreg(reg16_t.DI) == 0x0302


def test_string_compare_values_delegates_to_flags_update():
    state = {}

    string_compare_values(0x12, 0x34, lambda lhs, rhs: state.update({"flags": (lhs, rhs)}))

    assert state["flags"] == (0x12, 0x34)
