from angr_platforms.X86_16.alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    build_compare_condition_8616,
    compare_operation,
    masked_shift_count,
    rotate_count,
    rotate_left_operation,
    rotate_right_operation,
    shift_left_operation,
    shift_right_arithmetic_operation,
    shift_right_operation,
)
from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace


class _AluEmu:
    def __init__(self, carry=False):
        self.carry = carry
        self.last_condition = None

    def constant(self, value, _ty):
        return value

    def is_carry(self):
        return self.carry

    def update_eflags_sub(self, lhs, rhs):
        self.last_flags = ("sub", lhs, rhs)

    def update_eflags_and(self, lhs, rhs):
        self.last_flags = ("and", lhs, rhs)

    def set_last_condition(self, condition):
        self.last_condition = condition


def test_binary_operation_updates_result_and_flags():
    emu = _AluEmu()
    state = {}

    binary_operation(
        emu,
        lambda: 2,
        lambda: 3,
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs: state.update({"flags": (lhs, rhs)}),
        lambda lhs, rhs: lhs + rhs,
    )

    assert state["result"] == 5
    assert state["flags"] == (2, 3)


def test_binary_operation_with_carry_threads_the_carry_value():
    emu = _AluEmu(carry=True)
    state = {}

    binary_operation_with_carry(
        emu,
        lambda: 2,
        lambda: 3,
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs, carry: state.update({"flags": (lhs, rhs, carry)}),
        lambda lhs, rhs, carry: lhs + rhs + carry,
        width_bits=16,
    )

    assert state["result"] == 6
    assert state["flags"] == (2, 3, True)


def test_binary_operation_with_carry_accepts_plain_booleans():
    emu = _AluEmu(carry=False)
    state = {}

    binary_operation_with_carry(
        emu,
        lambda: 2,
        lambda: 3,
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs, carry: state.update({"flags": (lhs, rhs, carry)}),
        lambda lhs, rhs, carry: lhs + rhs + carry,
        width_bits=16,
    )

    assert state["result"] == 5
    assert state["flags"] == (2, 3, 0)


def test_compare_operation_only_updates_flags():
    state = {}

    compare_operation(lambda: 4, lambda: 2, lambda lhs, rhs: state.update({"flags": (lhs, rhs)}))

    assert state["flags"] == (4, 2)


def test_build_compare_condition_recovers_compare_family():
    condition = build_compare_condition_8616(4, 2, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=2, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_compare_operation_sets_last_condition_on_emulator():
    emu = _AluEmu()

    compare_operation(lambda: 4, lambda: 2, emu.update_eflags_sub)

    assert emu.last_flags == ("sub", 4, 2)
    assert emu.last_condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=2, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_compare_operation_captures_masked_nonzero_test_condition():
    emu = _AluEmu()

    compare_operation(lambda: 0x80, lambda: 0x08, emu.update_eflags_and)

    assert emu.last_flags == ("and", 0x80, 0x08)
    assert emu.last_condition == IRCondition(
        op="masked_nonzero",
        args=(
            IRValue(MemSpace.CONST, const=0x80, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=0x08, size=1, expr=("int",)),
        ),
        expr=("update_eflags_and",),
    )


def test_shift_helpers_mask_and_rotate_counts():
    emu = _AluEmu()

    assert masked_shift_count(emu, 0x23, 8) == 3
    assert rotate_count(emu, 0x23, 8, 8) == 3


def test_shift_and_rotate_helpers_apply_value_transformations():
    emu = _AluEmu()
    state = {}

    shift_left_operation(emu, lambda: 0x12, lambda value: state.setdefault("shl", value), lambda lhs, rhs: state.update({"shl_flags": (lhs, rhs)}), 1, 8)
    shift_right_operation(emu, lambda: 0x12, lambda value: state.setdefault("shr", value), lambda lhs, rhs: state.update({"shr_flags": (lhs, rhs)}), 1, 8)
    rotate_left_operation(emu, lambda: 0x81, lambda value: state.setdefault("rol", value), lambda lhs, rhs: state.update({"rol_flags": (lhs, rhs)}), 1, 8)
    rotate_right_operation(emu, lambda: 0x81, lambda value: state.setdefault("ror", value), lambda lhs, rhs: state.update({"ror_flags": (lhs, rhs)}), 1, 8)

    assert state["shl"] == 0x24
    assert state["shl_flags"] == (0x12, 1)
    assert state["shr"] == 0x09
    assert state["shr_flags"] == (0x12, 1)
    assert state["rol"] == 0x03
    assert state["rol_flags"] == (0x81, 1)
    assert state["ror"] == 0xC0
    assert state["ror_flags"] == (0x81, 1)


def test_shift_right_arithmetic_helper_uses_sar_on_the_value():
    emu = _AluEmu()

    class _SignedValue(int):
        def sar(self, count):
            return _SignedValue(self >> count)

    state = {}
    shift_right_arithmetic_operation(
        emu,
        lambda: _SignedValue(0xF0),
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs: state.update({"flags": (lhs, rhs)}),
        1,
        8,
    )

    assert state["result"] == 0x78
    assert state["flags"] == (_SignedValue(0xF0), 1)
