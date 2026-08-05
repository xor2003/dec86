"""Tests for typed multi-register return value construction."""

from __future__ import annotations

from angr import ailment
from angr_platforms.X86_16.structuring.wide_return_values import combine_word_return_sources_8616


def test_combines_constant_dx_ax_words_before_codegen() -> None:
    atoms = iter(range(10, 20))
    high = ailment.Expr.Const(1, None, 0x1234, 16)
    low = ailment.Expr.Const(2, None, 0x5678, 16)

    result = combine_word_return_sources_8616(high, low, next_atom=lambda: next(atoms), ins_addr=0x1004)

    assert isinstance(result, ailment.Expr.Const)
    assert result.bits == 32
    assert result.value == 0x12345678


def test_preserves_nonconstant_dx_ax_as_concat() -> None:
    high = ailment.Expr.Register(1, None, 6, 16, reg_name="dx")
    low = ailment.Expr.Register(2, None, 0, 16, reg_name="ax")

    result = combine_word_return_sources_8616(high, low, next_atom=lambda: 3, ins_addr=0x1004)

    assert isinstance(result, ailment.Expr.BinaryOp)
    assert result.op == "Concat"
    assert tuple(result.operands) == (high, low)
