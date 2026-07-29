"""Layer: Helper boundary.

Responsibility: materialize explicit JCC branch conditions from typed IR condition facts.
Forbidden: recovering branch meaning from rendered assembly or postprocess text patterns.
"""

from __future__ import annotations

import contextlib
from typing import Protocol, runtime_checkable

from pyvex.lifting.util.vex_helper import Type

from .ir.condition_ir import (
    _JCC_COMPARISON_MNEMONICS_8616,
    JCC_EQ_MNEMONICS_8616,
    JCC_NE_MNEMONICS_8616,
    JCC_SGE_MNEMONICS_8616,
    JCC_SGT_MNEMONICS_8616,
    JCC_SLE_MNEMONICS_8616,
    JCC_SLT_MNEMONICS_8616,
    JCC_UGE_MNEMONICS_8616,
    JCC_UGT_MNEMONICS_8616,
    JCC_ULE_MNEMONICS_8616,
    JCC_ULT_MNEMONICS_8616,
)
from .ir.core import IRCondition, IRValue, MemSpace

__all__ = [
    "_condition_value_from_ir_value_8616",
    "_consume_last_condition_branch_8616",
    "_direct_jcc_condition_from_last_condition_8616",
]


class _ConditionExpr(Protocol):
    @property
    def signed(self) -> "_ConditionExpr":
        """Return the signed comparison view for a pyvex-like expression."""
        ...

    def __and__(self, _other: object) -> "_ConditionExpr":
        """Return a bitwise conjunction expression."""
        ...

    def __eq__(self, _other: object) -> object:
        """Return an equality comparison expression."""
        ...

    def __ne__(self, _other: object) -> object:
        """Return an inequality comparison expression."""
        ...

    def __lt__(self, _other: object) -> object:
        """Return an unsigned less-than comparison expression."""
        ...

    def __le__(self, _other: object) -> object:
        """Return an unsigned less-or-equal comparison expression."""
        ...

    def __gt__(self, _other: object) -> object:
        """Return an unsigned greater-than comparison expression."""
        ...

    def __ge__(self, _other: object) -> object:
        """Return an unsigned greater-or-equal comparison expression."""
        ...


class _ConditionInstruction(Protocol):
    def constant(self, value: int, ty: object) -> _ConditionExpr:
        """Return a pyvex-like constant expression."""
        ...

    def get(self, name: str, ty: object) -> _ConditionExpr:
        """Return a pyvex-like register or temporary expression."""
        ...


@runtime_checkable
class _ConditionState(Protocol):
    def get_last_condition(self) -> object | None:
        """Return the last typed condition captured by the lifting emulator."""
        ...

    def clear_last_condition(self) -> None:
        """Clear the consumed typed condition from the lifting emulator."""
        ...


def _condition_value_from_ir_value_8616(instruction: _ConditionInstruction, value: IRValue) -> _ConditionExpr | None:
    """Convert a typed IR value into a pyvex condition value when possible."""

    def _impl() -> _ConditionExpr | None:
        if value.space == MemSpace.CONST:
            bits = max(1, int(value.size or 0) * 8 or 16)
            if bits <= 8:
                ty = Type.int_8
            elif bits <= 16:
                ty = Type.int_16
            else:
                ty = Type.int_32
            return instruction.constant(0 if value.const is None else int(value.const), ty)
        if value.space == MemSpace.REG and isinstance(value.name, str) and value.name:
            reg_name = value.name.lower()
            bits = int(value.size or 0) * 8
            if bits <= 8:
                return instruction.get(reg_name, Type.int_8)
            if bits <= 16:
                return instruction.get(reg_name, Type.int_16)
            return instruction.get(reg_name, Type.int_32)
        if value.space == MemSpace.TMP and isinstance(value.name, str) and value.name:
            if value.name == "VexValue":
                return None
            bits = int(value.size or 0) * 8
            if bits <= 8:
                ty = Type.int_8
            elif bits <= 16:
                ty = Type.int_16
            else:
                ty = Type.int_32
            with contextlib.suppress(Exception):
                return instruction.get(value.name, ty)
            return None
        return None

    return _impl()


def _direct_jcc_condition_from_last_condition_8616(
    instruction: _ConditionInstruction,
    kind: str,
    condition: IRCondition,
) -> object | None:
    """Build a pyvex branch condition from the previously recorded typed IR condition."""

    def _impl() -> object | None:
        def _masked_zero_result(args_local: tuple[IRValue, ...]) -> object | None:
            lhs = _condition_value_from_ir_value_8616(instruction, args_local[0])
            rhs = _condition_value_from_ir_value_8616(instruction, args_local[1]) if len(args_local) == 2 else None
            if lhs is None:
                return None
            masked = lhs if rhs is None else lhs & rhs
            if kind in JCC_EQ_MNEMONICS_8616:
                return masked == instruction.constant(0, Type.int_16)
            if kind in JCC_NE_MNEMONICS_8616:
                return masked != instruction.constant(0, Type.int_16)
            return None

        def _binary_compare_result(args_local: tuple[IRValue, ...]) -> object | None:
            lhs = _condition_value_from_ir_value_8616(instruction, args_local[0])
            rhs = _condition_value_from_ir_value_8616(instruction, args_local[1])
            if lhs is None or rhs is None:
                return None
            if kind in JCC_EQ_MNEMONICS_8616:
                return lhs == rhs
            if kind in JCC_NE_MNEMONICS_8616:
                return lhs != rhs
            if kind in JCC_SLE_MNEMONICS_8616:
                return lhs.signed <= rhs.signed
            if kind in JCC_SGT_MNEMONICS_8616:
                return lhs.signed > rhs.signed
            if kind in JCC_SLT_MNEMONICS_8616:
                return lhs.signed < rhs.signed
            if kind in JCC_SGE_MNEMONICS_8616:
                return lhs.signed >= rhs.signed
            if kind in JCC_ULT_MNEMONICS_8616:
                return lhs < rhs
            if kind in JCC_UGE_MNEMONICS_8616:
                return lhs >= rhs
            if kind in JCC_ULE_MNEMONICS_8616:
                return lhs <= rhs
            if kind in JCC_UGT_MNEMONICS_8616:
                return lhs > rhs
            if kind in _JCC_COMPARISON_MNEMONICS_8616:
                return None
            return None

        args = tuple(arg for arg in condition.args if isinstance(arg, IRValue))
        if len(args) != len(condition.args):
            return None
        op = str(condition.op)
        if op in {
            "compare",
            "eq",
            "ne",
            "slt",
            "sle",
            "sgt",
            "sge",
            "ult",
            "ule",
            "ugt",
            "uge",
            "masked_zero",
            "zero",
            "masked_nonzero",
            "nonzero",
        }:
            if len(args) not in {1, 2}:
                return None
            if op in {"masked_zero", "zero"}:
                return _masked_zero_result(args)
            if op in {"masked_nonzero", "nonzero"}:
                return _masked_zero_result(args)
            return _binary_compare_result(args)

        if op in {"zero", "nonzero"} and len(args) == 1:
            value = _condition_value_from_ir_value_8616(instruction, args[0])
            if value is None:
                return None
            zero = instruction.constant(0, Type.int_16)
            if op == "zero":
                return (
                    value == zero
                    if kind in JCC_EQ_MNEMONICS_8616
                    else value != zero
                    if kind in JCC_NE_MNEMONICS_8616
                    else None
                )
            return (
                value != zero
                if kind in JCC_EQ_MNEMONICS_8616
                else value == zero
                if kind in JCC_NE_MNEMONICS_8616
                else None
            )

        return None

    return _impl()


def _consume_last_condition_branch_8616(instruction: _ConditionInstruction, emu: object, kind: str) -> object | None:
    """Consume the emulator's last typed condition and clear it after use.

    Dynamic boundary: the emulator is supplied by the pyvex/angr lifting
    framework, so this helper accepts any object that structurally provides the
    typed-condition state methods.
    """
    if not isinstance(emu, _ConditionState):
        return None
    last_condition = emu.get_last_condition()
    if not isinstance(last_condition, IRCondition):
        return None
    branch_cond = _direct_jcc_condition_from_last_condition_8616(instruction, kind, last_condition)
    with contextlib.suppress(Exception):
        emu.clear_last_condition()
    return branch_cond
