from __future__ import annotations

from typing import Any, Callable

from .addressing_helpers import type_for_bits


def binary_operation(emu, get_lhs, get_rhs, set_result, update_flags, operator):
    lhs = get_lhs()
    rhs = get_rhs()
    set_result(operator(lhs, rhs))
    update_flags(lhs, rhs)


def binary_operation_with_carry(
    emu,
    get_lhs,
    get_rhs,
    set_result,
    update_flags,
    operator,
    width_bits: int,
):
    lhs = get_lhs()
    rhs = get_rhs()
    carry = emu.is_carry()
    if hasattr(carry, "cast_to"):
        carry = carry.cast_to(type_for_bits(width_bits))
    else:
        carry = emu.constant(int(bool(carry)), type_for_bits(width_bits))
    set_result(operator(lhs, rhs, carry))
    update_flags(lhs, rhs, carry)


def compare_operation(get_lhs, get_rhs, update_flags):
    update_flags(get_lhs(), get_rhs())


def unary_operation(get_value, set_result, update_flags, operator):
    value = get_value()
    set_result(operator(value))
    if update_flags is not None:
        update_flags(value)


def masked_shift_count(emu, count, width_bits: int, mask: int = 0x1F):
    count_v = emu.constant(count, type_for_bits(width_bits)) if isinstance(count, int) else count.cast_to(type_for_bits(width_bits))
    return count_v & emu.constant(mask, type_for_bits(width_bits))


def rotate_count(emu, count, modulo: int, width_bits: int, mask: int = 0x1F):
    return masked_shift_count(emu, count, width_bits, mask) % emu.constant(modulo, type_for_bits(width_bits))


def shift_left_operation(emu, get_value, set_result, update_flags, count, width_bits: int):
    value = get_value()
    shift = masked_shift_count(emu, count, width_bits)
    set_result(value << shift)
    update_flags(value, shift)


def shift_right_operation(emu, get_value, set_result, update_flags, count, width_bits: int):
    value = get_value()
    shift = masked_shift_count(emu, count, width_bits)
    set_result(value >> shift)
    update_flags(value, shift)


def shift_right_arithmetic_operation(emu, get_value, set_result, update_flags, count, width_bits: int):
    value = get_value()
    shift = masked_shift_count(emu, count, width_bits)
    set_result(value.sar(shift))
    update_flags(value, shift)


def rotate_left_operation(emu, get_value, set_result, update_flags, count, width_bits: int):
    value = get_value()
    shift = rotate_count(emu, count, width_bits, width_bits)
    width = emu.constant(width_bits, type_for_bits(width_bits))
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    set_result(((value << shift) | (value >> (width - shift))) & mask)
    update_flags(value, shift)


def rotate_right_operation(emu, get_value, set_result, update_flags, count, width_bits: int):
    value = get_value()
    shift = rotate_count(emu, count, width_bits, width_bits)
    width = emu.constant(width_bits, type_for_bits(width_bits))
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    set_result(((value >> shift) | (value << (width - shift))) & mask)
    update_flags(value, shift)
