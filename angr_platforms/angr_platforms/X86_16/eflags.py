"""Layer: Frontend/runtime.

Responsibility: expose flag register accessors for lifter and emulator instruction behavior.
Forbidden: postprocess flag cleanup, condition recovery, or validation acceptance.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from pyvex.lifting.util.vex_helper import Type

from .regs import reg16_t, reg32_t

# pyvex's VexValue operator stubs expose raw RdTmp/list results even though the
# runtime syntax wrapper returns another value wrapper. Keep that third-party
# mismatch isolated behind one explicit frontend boundary type.
type VexExpr = Any
type FlagValue = int | VexExpr


class Eflags:
    """Flag-operation mixin backed by an instruction/emulator value host.

    The declared callables are supplied by the concrete emulator host. Their
    values remain dynamic because pyvex expression types are not a stable owned
    Inertia contract.
    """

    get_gpreg: Callable[[object], FlagValue]
    set_gpreg: Callable[[object, FlagValue], None]
    constant: Callable[..., VexExpr]
    _vv: Callable[[object], VexExpr]
    lifter_instruction: Any

    def __init__(self) -> None:
        """Initialize the stateless flag-operation mixin."""
        # self.eflags = 0

    def get_eflags(self) -> FlagValue:
        """Return the host's 32-bit EFLAGS value."""
        return self.get_gpreg(reg32_t.EFLAGS)

    def set_eflags(self, v: FlagValue) -> None:
        """Store a 32-bit EFLAGS value on the host."""
        self.set_gpreg(reg32_t.EFLAGS, v)

    def get_flags(self) -> FlagValue:
        """Return the host's 16-bit FLAGS value."""
        return self.get_gpreg(reg16_t.FLAGS)

    def set_flags(self, v: FlagValue) -> None:
        """Store a 16-bit FLAGS value on the host."""
        self.set_gpreg(reg16_t.FLAGS, v)

    def get_flag(self, idx: int) -> VexExpr:
        """Return one FLAGS bit as a one-bit pyvex value."""
        flags = cast(VexExpr, self.get_gpreg(reg16_t.FLAGS))
        return flags[idx].cast_to(Type.int_1)

    def is_carry(self) -> VexExpr:
        """Return the carry flag value."""
        return self.get_flag(0)

    def is_parity(self) -> VexExpr:
        """Return the parity flag value."""
        return self.get_flag(2)

    def is_zero(self) -> VexExpr:
        """Return the zero flag value."""
        return self.get_flag(6)

    def is_sign(self) -> VexExpr:
        """Return the sign flag value."""
        return self.get_flag(7)

    def is_overflow(self) -> VexExpr:
        """Return the overflow flag value."""
        return self.get_flag(11)

    def is_interrupt(self) -> VexExpr:
        """Return the interrupt-enable flag value."""
        return self.get_flag(9)

    def is_direction(self) -> VexExpr:
        """Return the direction flag value."""
        return self.get_flag(10)

    def set_flag(self, flags: FlagValue, idx: int, value: FlagValue) -> VexExpr:
        """Return FLAGS with one indexed bit replaced."""
        flags16 = self.constant(flags, Type.int_16) if isinstance(flags, int) else flags.cast_to(Type.int_16)
        value16 = self.constant(value, Type.int_1) if isinstance(value, int) else value.cast_to(Type.int_1)
        clear_mask = self.constant((~(1 << idx)) & 0xFFFF, Type.int_16)
        bit_mask = self.constant((1 << idx) & 0xFFFF, Type.int_16)
        return (flags16 & clear_mask) | ((value16.cast_to(Type.int_16) << idx) & bit_mask)

    def set_carry(self, flags: FlagValue, carry: FlagValue) -> VexExpr:
        """Return FLAGS with the carry bit replaced."""
        return self.set_flag(flags, 0, carry)

    def set_parity(self, flags: FlagValue, parity: FlagValue) -> VexExpr:
        """Return FLAGS with the parity bit replaced."""
        return self.set_flag(flags, 2, parity)

    def set_zero(self, flags: FlagValue, zero: FlagValue) -> VexExpr:
        """Return FLAGS with the zero bit replaced."""
        return self.set_flag(flags, 6, zero)

    def set_sign(self, flags: FlagValue, sign: FlagValue) -> VexExpr:
        """Return FLAGS with the sign bit replaced."""
        return self.set_flag(flags, 7, sign)

    def set_overflow(self, flags: FlagValue, over: FlagValue) -> VexExpr:
        """Return FLAGS with the overflow bit replaced."""
        return self.set_flag(flags, 11, over)

    def set_interrupt(self, interrupt: FlagValue) -> None:
        """Store the interrupt-enable flag on the host."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        interrupt = self.constant(interrupt, Type.int_1)
        flags = self.set_flag(flags, 9, interrupt)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def set_direction(self, direction: FlagValue) -> None:
        """Store the direction flag on the host."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        direction = self.constant(direction, Type.int_1)
        flags = self.set_flag(flags, 10, direction)
        self.set_gpreg(reg16_t.FLAGS, flags)

    @staticmethod
    def _wider_type(ty: object) -> object:
        if ty == Type.int_8:
            return Type.int_16
        if ty == Type.int_16:
            return Type.int_32
        if ty == Type.int_32:
            return Type.int_64
        raise ValueError(f"unsupported arithmetic width: {ty!r}")

    def _count8(self, count: FlagValue) -> VexExpr:
        return self.constant(count, Type.int_8) if isinstance(count, int) else count.cast_to(Type.int_8)

    def _mask_shift_count(self, count: FlagValue) -> VexExpr:
        return self._count8(count) & self.constant(0x1F, Type.int_8)

    @staticmethod
    def _const_u8_value(v: FlagValue) -> int | None:
        if isinstance(v, int):
            return v & 0xFF
        try:
            return cast(int, v.value & 0xFF)
        except (AttributeError, ValueError):
            return None

    def _ite(self, cond: FlagValue, when_true: VexExpr, when_false: VexExpr) -> VexExpr:
        cond_expr = cast(VexExpr, self.constant(cond, Type.int_1) if isinstance(cond, int) else cond.cast_to(Type.int_1))
        expr = self.lifter_instruction.irsb_c.ite(
            cond_expr.rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self._vv(expr)

    def _adjust_flag(self, v1: VexExpr, v2: VexExpr, result: VexExpr) -> VexExpr:
        one = self.constant(1, result.ty)
        return (((v1 ^ v2) ^ result) >> 4 & one).cast_to(Type.int_1)

    def update_eflags_inc(self, v1: VexExpr) -> None:
        """Update arithmetic flags for an increment result."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + self.constant(1, v1.ty)

        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, self.constant(1, v1.ty), result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v1 == self.constant((1 << (size - 1)) - 1, v1.ty))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_add(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for an addition result."""
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2_expr
        wide = self._wider_type(v1.ty)
        carry = ((v1.cast_to(wide) + v2_expr.cast_to(wide)) >> size & self.constant(1, wide)).cast_to(Type.int_1)

        flags = self.set_carry(flags, carry)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2_expr, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(
            flags,
            (((~(v1 ^ v2_expr)) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)).cast_to(Type.int_1),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_adc(self, v1: VexExpr, v2: FlagValue, carry: FlagValue) -> None:
        """Update arithmetic flags for addition with carry."""
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        carry_expr = cast(
            VexExpr,
            self.constant(carry, v1.ty) if isinstance(carry, int) else carry.cast_to(v1.ty),
        )
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2_expr + carry_expr
        wide = self._wider_type(v1.ty)
        carry_out = (
            (v1.cast_to(wide) + v2_expr.cast_to(wide) + carry_expr.cast_to(wide))
            >> size
            & self.constant(1, wide)
        ).cast_to(Type.int_1)

        flags = self.set_carry(flags, carry_out)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2_expr, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(
            flags,
            (((~(v1 ^ v2_expr)) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)).cast_to(Type.int_1),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_or(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a bitwise OR result."""
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 | v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_and(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a bitwise AND result."""
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 & v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sub(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a subtraction result."""
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        flags = self.set_carry(flags, (v1 < v2).cast_to(Type.int_1))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(
            flags, ((((v1 ^ v2) & (v1 ^ result)) >> (size - 1)) & self.constant(1, v1.ty)).cast_to(Type.int_1)
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sbb(self, v1: VexExpr, v2: FlagValue, c: FlagValue) -> None:
        """Update arithmetic flags for subtraction with borrow."""
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        c_expr = cast(VexExpr, self.constant(c, v1.ty) if isinstance(c, int) else c.cast_to(v1.ty))
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2_expr - c_expr
        size = v1.width
        borrow = (
            v1.cast_to(self._wider_type(v1.ty))
            < (v2_expr.cast_to(self._wider_type(v1.ty)) + c_expr.cast_to(self._wider_type(v1.ty)))
        ).cast_to(Type.int_1)

        flags = self.set_carry(flags, borrow)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2_expr, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(
            flags,
            ((((v1 ^ v2_expr) & (v1 ^ result)) >> (size - 1)) & self.constant(1, v1.ty)).cast_to(Type.int_1),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_xor(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a bitwise XOR result."""
        v2 = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 ^ v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_neg(self, v2: VexExpr) -> None:
        """Update arithmetic flags for a negation result."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v2.width
        zero = self.constant(0, v2.ty)
        result = (zero - v2).cast_to(v2.ty)

        flags = self.set_carry(flags, v2 != 0)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(zero, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v2 == self.constant(1 << (size - 1), v2.ty))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_dec(self, v1: VexExpr) -> None:
        """Update arithmetic flags for a decrement result."""
        v2 = self.constant(1, v1.ty)
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v1 == (self.constant(1 << (size - 1), v1.ty)))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_mul(self, v1: VexExpr, v2: VexExpr) -> None:
        """Update arithmetic flags for an unsigned multiply result."""
        type1 = v1.ty
        flags = self.get_gpreg(reg16_t.FLAGS)
        wide_type = self._wider_type(type1)
        result = v1.cast_to(wide_type) * v2.cast_to(wide_type)
        size = v1.width
        high_nonzero = ((result >> size) != self.constant(0, wide_type)).cast_to(Type.int_1)

        flags = self.set_carry(flags, high_nonzero)
        flags = self.set_zero(flags, result.cast_to(type1) == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, high_nonzero)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_imul(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a signed multiply result."""
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        type1 = v1.ty
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        wide_type = Type.int_64 if size == 32 else Type.int_32
        result = v1.widen_signed(wide_type) * v2_expr.widen_signed(wide_type)

        low = result.cast_to(type1)
        high = (result >> self.constant(size, Type.int_8)).cast_to(type1)
        sign_ext = self._ite(
            low[size - 1].cast_to(Type.int_1),
            self.constant((1 << size) - 1, type1),
            self.constant(0, type1),
        ).cast_to(type1)
        sign_ext_ok = (high == sign_ext).cast_to(Type.int_1)
        cfof = (sign_ext_ok == self.constant(0, Type.int_1)).cast_to(Type.int_1)
        flags = self.set_carry(flags, cfof)
        flags = self.set_overflow(flags, cfof)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shl(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a logical left shift."""
        const_count = self._const_u8_value(c)
        masked_const_count = None if const_count is None else const_count & 0x1F
        if masked_const_count and masked_const_count <= v.width:
            flags = self.get_gpreg(reg16_t.FLAGS)
            count = self.constant(masked_const_count, Type.int_8)
            result = v << count
            cf = (v >> self.constant(v.width - masked_const_count, Type.int_8))[0].cast_to(Type.int_1)
            flags = self.set_carry(flags, cf)
            flags = self.set_parity(flags, self.chk_parity(result))
            flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
            flags = self.set_zero(flags, (result == 0).cast_to(Type.int_1))
            flags = self.set_sign(flags, result[v.width - 1].cast_to(Type.int_1))
            if masked_const_count == 1:
                flags = self.set_overflow(
                    flags,
                    (result[v.width - 1].cast_to(Type.int_1) ^ cf).cast_to(Type.int_1),
                )
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        unchanged = c == self.constant(0, Type.int_8)
        one = c == self.constant(1, Type.int_8)
        result = v << c
        inverse = self.constant(size, Type.int_8) - c
        cf = (v >> inverse)[0].cast_to(Type.int_1)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), cf))
        flags = self.set_parity(flags, self._ite(unchanged, self.get_flag(2), self.chk_parity(result)))
        flags = self.set_flag(flags, 4, self._ite(unchanged, self.get_flag(4), self.constant(0, Type.int_1)))
        flags = self.set_zero(flags, self._ite(unchanged, self.get_flag(6), (result == 0).cast_to(Type.int_1)))
        flags = self.set_sign(flags, self._ite(unchanged, self.get_flag(7), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(
                unchanged,
                self.get_flag(11),
                self._ite(
                    one,
                    (result[size - 1].cast_to(Type.int_1) ^ cf).cast_to(Type.int_1),
                    self.get_flag(11),
                ),
            ),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_double_shift(self, v: VexExpr, result: VexExpr, c: FlagValue, *, left: bool) -> None:
        """Update defined SHLD/SHRD flags from the combined double-shift result."""
        count = self._mask_shift_count(c)
        width = v.width
        defined = count <= self.constant(width, Type.int_8)
        active = defined & (count != self.constant(0, Type.int_8))
        one = count == self.constant(1, Type.int_8)
        if left:
            carry = (v >> (self.constant(width, Type.int_8) - count))[0].cast_to(Type.int_1)
            overflow = (result[width - 1].cast_to(Type.int_1) ^ carry).cast_to(Type.int_1)
        else:
            carry = (v >> (count - self.constant(1, Type.int_8)))[0].cast_to(Type.int_1)
            overflow = (v[width - 1].cast_to(Type.int_1) ^ result[width - 1].cast_to(Type.int_1)).cast_to(
                Type.int_1
            )
        flags = self.get_gpreg(reg16_t.FLAGS)
        flags = self.set_carry(flags, self._ite(active, carry, self.get_flag(0)))
        flags = self.set_parity(flags, self._ite(active, self.chk_parity(result), self.get_flag(2)))
        flags = self.set_zero(flags, self._ite(active, (result == 0).cast_to(Type.int_1), self.get_flag(6)))
        flags = self.set_sign(flags, self._ite(active, result[width - 1].cast_to(Type.int_1), self.get_flag(7)))
        flags = self.set_overflow(flags, self._ite(one, overflow, self.get_flag(11)))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_rol(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a left rotate."""
        size = v.width
        masked = self._mask_shift_count(c)
        c = masked % self.constant(size, Type.int_8)
        result = (v << c) | (v >> (self.constant(size, Type.int_8) - c))
        flags = self.get_gpreg(reg16_t.FLAGS)
        unchanged = masked == self.constant(0, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), result[0].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(unchanged, self.get_flag(11), (result[size - 1] ^ result[0]).cast_to(Type.int_1)),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_ror(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a right rotate."""
        size = v.width
        masked = self._mask_shift_count(c)
        c = masked % self.constant(size, Type.int_8)
        result = (v >> c) | (v << (self.constant(size, Type.int_8) - c))
        flags = self.get_gpreg(reg16_t.FLAGS)
        unchanged = masked == self.constant(0, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(unchanged, self.get_flag(11), (result[size - 1] ^ result[size - 2]).cast_to(Type.int_1)),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shr(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a logical right shift."""
        const_count = self._const_u8_value(c)
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v >> self.constant(1, Type.int_8)
            flags = self.set_carry(flags, v[0].cast_to(Type.int_1))
            flags = self.set_parity(flags, self.chk_parity(result))
            flags = self.set_flag(flags, 4, self.constant(1, Type.int_1))
            flags = self.set_zero(flags, (result == 0).cast_to(Type.int_1))
            flags = self.set_sign(flags, result[v.width - 1].cast_to(Type.int_1))
            flags = self.set_overflow(flags, v[v.width - 1].cast_to(Type.int_1))
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        unchanged = c == self.constant(0, Type.int_8)
        one = c == self.constant(1, Type.int_8)
        result = v >> c
        previous = v >> (c - self.constant(1, Type.int_8))
        cf = previous[0].cast_to(Type.int_1)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), cf))
        flags = self.set_parity(flags, self._ite(unchanged, self.get_flag(2), self.chk_parity(result)))
        flags = self.set_flag(flags, 4, self._ite(unchanged, self.get_flag(4), self.constant(1, Type.int_1)))
        flags = self.set_zero(flags, self._ite(unchanged, self.get_flag(6), (result == 0).cast_to(Type.int_1)))
        flags = self.set_sign(flags, self._ite(unchanged, self.get_flag(7), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(
                unchanged,
                self.get_flag(11),
                self._ite(one, v[size - 1].cast_to(Type.int_1), self.get_flag(11)),
            ),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sar(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for an arithmetic right shift."""
        const_count = self._const_u8_value(c)
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v.sar(self.constant(1, Type.int_8))
            flags = self.set_carry(flags, v[0].cast_to(Type.int_1))
            flags = self.set_parity(flags, self.chk_parity(result))
            flags = self.set_flag(flags, 4, self.constant(1, Type.int_1))
            flags = self.set_zero(flags, (result == 0).cast_to(Type.int_1))
            flags = self.set_sign(flags, result[v.width - 1].cast_to(Type.int_1))
            flags = self.set_overflow(flags, self.constant(0, Type.int_1))
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        unchanged = c == self.constant(0, Type.int_8)
        result = v.sar(c)
        previous = v.sar(c - self.constant(1, Type.int_8))
        cf = previous[0].cast_to(Type.int_1)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), cf))
        flags = self.set_parity(flags, self._ite(unchanged, self.get_flag(2), self.chk_parity(result)))
        flags = self.set_flag(flags, 4, self._ite(unchanged, self.get_flag(4), self.constant(1, Type.int_1)))
        flags = self.set_zero(flags, self._ite(unchanged, self.get_flag(6), (result == 0).cast_to(Type.int_1)))
        flags = self.set_sign(flags, self._ite(unchanged, self.get_flag(7), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(flags, self._ite(unchanged, self.get_flag(11), self.constant(0, Type.int_1)))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def chk_parity(self, v: FlagValue) -> VexExpr:
        """Return one when the low byte has even parity."""
        v = self.constant(v, Type.int_8) if isinstance(v, int) else v.cast_to(Type.int_8)
        parity = v ^ (v >> self.constant(4, Type.int_8))
        parity = parity ^ (parity >> self.constant(2, Type.int_8))
        parity = parity ^ (parity >> self.constant(1, Type.int_8))
        return ((~parity) & self.constant(1, Type.int_8)).cast_to(Type.int_1)
