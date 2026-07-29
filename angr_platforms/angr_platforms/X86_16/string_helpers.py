"""Layer: Helper boundary.

Responsibility: execute string-instruction repeat, segment, direction, and branch helper effects.
Forbidden: replacing string-instruction semantics with source-backed or rendered-C rewrites.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeGuard, cast, runtime_checkable

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .alu_helpers import compare_operation
from .instruction import REPNZ, REPZ
from .regs import reg16_t, reg32_t, sgreg_t


@runtime_checkable
class _RdtCarrier(Protocol):
    rdt: object


class _CastableToRdt(Protocol):
    rdt: object

    def cast_to(self, ty: object) -> object:
        """Return this expression cast to the requested VEX helper type."""
        ...


class _AddSubValue(Protocol):
    def __add__(self, other: object) -> object:
        """Return this VEX value plus another helper value."""
        ...

    def __sub__(self, other: object) -> object:
        """Return this VEX value minus another helper value."""
        ...


class _AndValue(Protocol):
    def __and__(self, other: object) -> object:
        """Return this VEX condition conjoined with another helper value."""
        ...


class _StringIrsbCustomizer(Protocol):
    def ite(self, _condition: object, _when_true: object, _when_false: object) -> object:
        """Return a VEX if-then-else expression."""
        ...


class StringInstruction(Protocol):
    """Decoded string-instruction metadata consumed by shared helpers."""

    @property
    def pre_segment(self) -> sgreg_t | None:
        """Return the optional decoded segment override."""
        ...

    @property
    def pre_repeat(self) -> int:
        """Return the decoded repeat-prefix value."""
        ...

    @property
    def repeat_class(self) -> str:
        """Return the normalized repeat-prefix class."""
        ...

    @property
    def mode32(self) -> bool:
        """Return whether string indices use 32-bit registers."""
        ...


class _StringLifterInstruction(Protocol):
    irsb_c: _StringIrsbCustomizer

    def jump(self, _condition: object, _target: object, _jumpkind: object) -> None:
        """Emit a VEX jump for the active string instruction."""
        ...


class StringEmulator(Protocol):
    """Active VEX emulator surface required by string-instruction helpers."""

    lifter_instruction: _StringLifterInstruction

    def is_direction(self) -> _CastableToRdt:
        """Return the current direction-flag expression."""
        ...

    def constant(self, value: int, ty: object) -> object:
        """Return a VEX constant wrapper for the requested helper type."""
        ...

    def _vv(self, expr: object) -> object:
        """Wrap a raw VEX expression in the emulator's value carrier."""
        ...

    def get_gpreg(self, reg: object) -> object:
        """Read a general-purpose register from emulator state."""
        ...

    def set_gpreg(self, reg: object, value: object) -> None:
        """Write a general-purpose register in emulator state."""
        ...

    def is_zero(self) -> object:
        """Return the current zero-flag expression."""
        ...

    def get_data8(self, segment: sgreg_t, offset: object) -> object:
        """Read an 8-bit segmented value."""
        ...

    def get_data16(self, segment: sgreg_t, offset: object) -> object:
        """Read a 16-bit segmented value."""
        ...

    def get_data32(self, segment: sgreg_t, offset: object) -> object:
        """Read a 32-bit segmented value."""
        ...

    def put_data8(self, segment: sgreg_t, offset: object, value: object) -> None:
        """Store an 8-bit segmented value."""
        ...

    def put_data16(self, segment: sgreg_t, offset: object, value: object) -> None:
        """Store a 16-bit segmented value."""
        ...

    def put_data32(self, segment: sgreg_t, offset: object, value: object) -> None:
        """Store a 32-bit segmented value."""
        ...


def _has_rdt(value: object) -> TypeGuard[_RdtCarrier]:
    return isinstance(value, _RdtCarrier)


def _rdt_or_self(value: object) -> object:
    return value.rdt if _has_rdt(value) else value


def string_delta(emu: StringEmulator, width: int) -> object:
    """Return the signed index delta implied by direction flag and element width."""
    df = emu.is_direction()
    neg = cast(_RdtCarrier, emu.constant((-width) & 0xFFFF, Type.int_16))
    pos = cast(_RdtCarrier, emu.constant(width, Type.int_16))
    expr = emu.lifter_instruction.irsb_c.ite(cast(_RdtCarrier, df.cast_to(Type.int_1)).rdt, neg.rdt, pos.rdt)
    return emu._vv(expr)


def string_source_segment(instr: StringInstruction) -> sgreg_t:
    """Return the source segment for a string instruction."""
    if instr.pre_segment is not None:
        return sgreg_t(instr.pre_segment)
    return sgreg_t.DS


def repeat_kind(instr: StringInstruction) -> str:
    """Return the normalized repeat prefix class for a string instruction."""
    normalized = instr.repeat_class
    if normalized not in (None, ""):
        return normalized
    if instr.pre_repeat == REPZ:
        return "repz"
    if instr.pre_repeat == REPNZ:
        return "repnz"
    return "none"


def repeat_prefix_cond(emu: StringEmulator, instr: StringInstruction) -> _CastableToRdt | bool | None:
    """Consume CX and return whether a repeated string operation should continue."""
    if repeat_kind(instr) == "none":
        return None

    cx = cast(_AddSubValue, emu.get_gpreg(reg16_t.CX))
    remaining = cx - emu.constant(1, Type.int_16)
    emu.set_gpreg(reg16_t.CX, remaining)
    return cast(_CastableToRdt | bool, remaining != emu.constant(0, Type.int_16))


def repeat_jump(
    emu: StringEmulator,
    instr: StringInstruction,
    repeat_cond: _CastableToRdt | bool | None,
    zf_sensitive: bool = False,
) -> None:
    """Emit the repeat backedge for a string instruction when its condition holds."""
    if repeat_cond is None:
        return

    cond: object = repeat_cond if isinstance(repeat_cond, bool) else repeat_cond.cast_to(Type.int_1)
    if zf_sensitive:
        kind = repeat_kind(instr)
        if kind == "repz":
            cond = cast(_AndValue, cond) & emu.is_zero()
        elif kind == "repnz":
            cond = cast(_AndValue, cond) & (emu.is_zero() == emu.constant(0, Type.int_1))
    if isinstance(cond, bool):
        if not cond:
            return
        ip_reg = reg32_t.EIP if instr.mode32 else reg16_t.IP
        repeat_target = emu.get_gpreg(ip_reg)
        emu.lifter_instruction.jump(None, _rdt_or_self(repeat_target), JumpKind.Boring)
        emu.set_gpreg(ip_reg, repeat_target)
        return
    cond_value = cond.rdt if _has_rdt(cond) else None
    ip_reg = reg32_t.EIP if instr.mode32 else reg16_t.IP
    repeat_target = emu.get_gpreg(ip_reg)
    repeat_target_expr = _rdt_or_self(repeat_target)

    if isinstance(cond_value, bool):
        if not cond_value:
            return
        emu.lifter_instruction.jump(None, repeat_target_expr, JumpKind.Boring)
        emu.set_gpreg(ip_reg, repeat_target)
        return

    emu.lifter_instruction.jump(cond, repeat_target_expr, JumpKind.Boring)
    emu.set_gpreg(ip_reg, repeat_target)


def string_advance_indices(emu: StringEmulator, width: int, *regs: object) -> object:
    """Advance each string index register according to direction flag and width."""
    delta = string_delta(emu, width)
    for reg in regs:
        emu.set_gpreg(reg, cast(_AddSubValue, emu.get_gpreg(reg)) + delta)
    return delta


def string_compare_values(lhs: object, rhs: object, update_flags: Callable[[object, object], object]) -> None:
    """Compare two string operands through the caller-provided flag updater."""
    compare_operation(lambda: lhs, lambda: rhs, update_flags)


def string_load(emu: StringEmulator, segment: sgreg_t, offset: object, width: int) -> object:
    """Load a segmented string operand with the requested width."""
    if width == 1:
        return emu.get_data8(segment, offset)
    if width == 2:
        return emu.get_data16(segment, offset)
    if width == 4:
        return emu.get_data32(segment, offset)
    raise ValueError(f"unsupported string width: {width}")


def string_store(emu: StringEmulator, segment: sgreg_t, offset: object, value: object, width: int) -> None:
    """Store a segmented string operand with the requested width."""
    if width == 1:
        emu.put_data8(segment, offset, value)
        return
    if width == 2:
        emu.put_data16(segment, offset, value)
        return
    if width == 4:
        emu.put_data32(segment, offset, value)
        return
    raise ValueError(f"unsupported string width: {width}")
