from angr_platforms.X86_16.alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    masked_shift_count,
    rotate_count,
)


class _AluEmu:
    def __init__(self, carry=False):
        self.carry = carry

    def constant(self, value, _ty):
        return value

    def is_carry(self):
        return self.carry


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


def test_shift_helpers_mask_and_rotate_counts():
    emu = _AluEmu()

    assert masked_shift_count(emu, 0x23, 8) == 3
    assert rotate_count(emu, 0x23, 8, 8) == 3
