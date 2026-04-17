from __future__ import annotations

from pyvex.lifting.util.vex_helper import Type

from .ir.core import IRCondition, IRValue, MemSpace
from .addressing_helpers import type_for_bits


def _size_bytes_from_operand(value) -> int:
    width = getattr(value, "width", None)
    if isinstance(width, int) and width > 0:
        return max(1, (width + 7) // 8)
    ty = getattr(value, "ty", None)
    ty_name = getattr(ty, "name", str(ty or ""))
    if ty_name.startswith("Ity_I"):
        try:
            bits = int(ty_name[5:])
        except ValueError:
            bits = 0
        if bits > 0:
            return max(1, bits // 8)
    return 0


def _condition_value_from_operand(value) -> IRValue:
    if isinstance(value, bool):
        return IRValue(MemSpace.CONST, const=int(value), size=1, expr=("bool",))
    if isinstance(value, int):
        size = 1
        if not -(1 << 7) <= value < (1 << 8):
            size = 2
        if not -(1 << 15) <= value < (1 << 16):
            size = 4
        return IRValue(MemSpace.CONST, const=value, size=size, expr=("int",))
    value_const = getattr(value, "value", None)
    if isinstance(value_const, int):
        return IRValue(MemSpace.CONST, const=value_const, size=_size_bytes_from_operand(value), expr=("vex_const",))
    return IRValue(
        MemSpace.TMP,
        name=type(value).__name__,
        size=_size_bytes_from_operand(value),
        expr=(str(getattr(getattr(value, "ty", None), "name", getattr(value, "ty", None) or type(value).__name__)),),
    )


def build_compare_condition_8616(lhs, rhs, update_flags) -> IRCondition | None:
    name = getattr(update_flags, "__name__", "")
    if name == "update_eflags_sub":
        return IRCondition(
            op="compare",
            args=(_condition_value_from_operand(lhs), _condition_value_from_operand(rhs)),
            expr=(name,),
        )
    if name == "update_eflags_and":
        return IRCondition(
            op="masked_nonzero",
            args=(_condition_value_from_operand(lhs), _condition_value_from_operand(rhs)),
            expr=(name,),
        )
    return None


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
    lhs = get_lhs()
    rhs = get_rhs()
    update_flags(lhs, rhs)
    owner = getattr(update_flags, "__self__", None)
    if owner is None or not hasattr(owner, "set_last_condition"):
        return
    condition = build_compare_condition_8616(lhs, rhs, update_flags)
    owner.set_last_condition(condition)


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


def rotate_through_carry_count(emu, count, width_bits: int, mask: int = 0x1F):
    return masked_shift_count(emu, count, width_bits, mask) % emu.constant(width_bits + 1, type_for_bits(width_bits))


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


def rotate_through_carry_left_state(emu, value, count, width_bits: int, ite_value):
    shift = rotate_through_carry_count(emu, count, width_bits)
    shift_value = emu._const_u8_value(shift)
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    one = emu.constant(1, Type.int_8)
    carry_in = emu.get_carry().cast_to(Type.int_1)

    if shift_value == 0:
        return value, None, None
    if shift_value == 1:
        result = ((value << one) | carry_in.cast_to(type_for_bits(width_bits))) & mask
        carry_out = value[width_bits - 1].cast_to(Type.int_1)
        overflow = result[width_bits - 1].cast_to(Type.int_1) ^ carry_out
        return result, carry_out, overflow

    result = value
    carry = carry_in
    selected_result = value
    selected_carry = carry_in.cast_to(type_for_bits(width_bits))
    for step in range(1, width_bits + 1):
        shifted_out = result[width_bits - 1].cast_to(Type.int_1)
        result = ((result << one) | carry.cast_to(type_for_bits(width_bits))) & mask
        carry = shifted_out
        cond = shift == emu.constant(step, type_for_bits(width_bits))
        selected_result = ite_value(cond, result, selected_result)
        selected_carry = ite_value(cond, carry.cast_to(type_for_bits(width_bits)), selected_carry)
    overflow = selected_result[width_bits - 1].cast_to(Type.int_1) ^ selected_carry.cast_to(Type.int_1)
    return selected_result, selected_carry.cast_to(Type.int_1), overflow


def rotate_through_carry_right_state(emu, value, count, width_bits: int, ite_value):
    shift = rotate_through_carry_count(emu, count, width_bits)
    shift_value = emu._const_u8_value(shift)
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    one = emu.constant(1, Type.int_8)
    carry_in = emu.get_carry().cast_to(Type.int_1)

    if shift_value == 0:
        return value, None, None
    if shift_value == 1:
        result = (value >> one) | (carry_in.cast_to(type_for_bits(width_bits)) << (width_bits - 1))
        carry_out = value[0].cast_to(Type.int_1)
        overflow = result[width_bits - 1].cast_to(Type.int_1) ^ result[width_bits - 2].cast_to(Type.int_1)
        return result & mask, carry_out, overflow

    result = value
    carry = carry_in
    selected_result = value
    selected_carry = carry_in.cast_to(type_for_bits(width_bits))
    for step in range(1, width_bits + 1):
        shifted_out = result[0].cast_to(Type.int_1)
        result = (result >> one) | (carry.cast_to(type_for_bits(width_bits)) << (width_bits - 1))
        carry = shifted_out
        cond = shift == emu.constant(step, type_for_bits(width_bits))
        selected_result = ite_value(cond, result & mask, selected_result)
        selected_carry = ite_value(cond, carry.cast_to(type_for_bits(width_bits)), selected_carry)
    overflow = selected_result[width_bits - 1].cast_to(Type.int_1) ^ selected_result[width_bits - 2].cast_to(Type.int_1)
    return selected_result & mask, selected_carry.cast_to(Type.int_1), overflow
