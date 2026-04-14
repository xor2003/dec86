from __future__ import annotations

from dataclasses import dataclass

from angr.ailment.expression import BasePointerOffset

from inertia_decompiler.runtime_support import (
    install_angr_peephole_expr_bitwidth_guard,
    install_angr_variable_recovery_binop_sub_size_guard,
)


@dataclass
class _Expr:
    bits: int
    text: str

    def __str__(self) -> str:
        return self.text


@dataclass
class _Block:
    addr: int


class _IdentityHandleExpr:
    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):  # noqa: ANN001
        return expr


class _ExprOpt:
    expr_classes = (_Expr,)

    def optimize(self, expr, stmt_idx=None, block=None):  # noqa: ANN001
        return BasePointerOffset(None, 32, "stack_base", 0)


class _Walker(_IdentityHandleExpr):
    def __init__(self) -> None:
        self.expr_opts = [_ExprOpt()]
        self.any_update = False

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):  # noqa: ANN001
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def test_peephole_bitwidth_guard_logs_mismatch(capsys) -> None:
    original = install_angr_peephole_expr_bitwidth_guard(_Walker)
    try:
        walker = _Walker()
        expr = _Expr(bits=16, text="(stack_base-2 + 0x2<16>)")
        result = walker._handle_expr(1, expr, 0, "t0 = ...", _Block(addr=0x11732))
    finally:
        _Walker._handle_expr = original

    captured = capsys.readouterr()
    assert isinstance(result, BasePointerOffset)
    assert result.bits == 16
    assert result.offset == 0
    assert "clinic:peephole-bits-mismatch" not in captured.err


class _GenericExprOpt:
    expr_classes = (_Expr,)

    def optimize(self, expr, stmt_idx=None, block=None):  # noqa: ANN001
        return _Expr(bits=32, text="wide_tmp")


class _GenericWalker(_IdentityHandleExpr):
    def __init__(self) -> None:
        self.expr_opts = [_GenericExprOpt()]
        self.any_update = False

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):  # noqa: ANN001
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def test_peephole_bitwidth_guard_keeps_generic_mismatch_as_log_only(capsys) -> None:
    original = install_angr_peephole_expr_bitwidth_guard(_GenericWalker)
    try:
        walker = _GenericWalker()
        expr = _Expr(bits=16, text="(stack_base-2 + 0x2<16>)")
        result = walker._handle_expr(1, expr, 0, "t0 = ...", _Block(addr=0x11732))
    finally:
        _GenericWalker._handle_expr = original

    captured = capsys.readouterr()
    assert result is expr
    assert "clinic:peephole-bits-mismatch" in captured.err
    assert "opt=_GenericExprOpt" in captured.err


class _FakeBV:
    def __init__(self, bits: int) -> None:
        self._bits = bits

    def size(self) -> int:
        return self._bits

    def zero_extend(self, nbits: int) -> _FakeBV:
        return _FakeBV(self._bits + nbits)

    def __getitem__(self, item) -> _FakeBV:  # noqa: ANN001
        hi, lo = item.start, item.stop
        return _FakeBV(hi - lo + 1)

    def __sub__(self, other: _FakeBV) -> _FakeBV:
        return _FakeBV(max(self._bits, other._bits))


class _FakeRichR:
    def __init__(self, data, typevar=None, type_constraints=None):  # noqa: ANN001
        self.data = data
        self.typevar = typevar
        self.type_constraints = type_constraints or set()


class _FakeState:
    def top(self, bits: int) -> _FakeBV:
        return _FakeBV(bits)


class _FakeTypevars:
    class TypeVariable:
        pass

    @staticmethod
    def new_dtv(typevar, label=None):  # noqa: ANN001
        return ("dtv", typevar, label)

    @staticmethod
    def SubN(value):  # noqa: ANN001
        return ("SubN", value)

    @staticmethod
    def Sub(lhs, rhs, out):  # noqa: ANN001
        return ("Sub", lhs, rhs, out)


class _FakeExpr:
    bits = 16
    operands = ("lhs", "rhs")


class _Engine:
    def __init__(self) -> None:
        self.state = _FakeState()

    def _expr_pair(self, arg0, arg1):  # noqa: ANN001
        lhs = _FakeRichR(_FakeBV(16), typevar=None)
        rhs = _FakeRichR(_FakeBV(32), typevar=None)
        return lhs, rhs

    def _handle_binop_Sub(self, expr):  # noqa: ANN001
        raise AssertionError("guard not installed")


def test_variable_recovery_guard_logs_size_mismatch(capsys) -> None:
    original = install_angr_variable_recovery_binop_sub_size_guard(
        _Engine,
        richr_cls=_FakeRichR,
        typevars_module=_FakeTypevars,
    )
    try:
        engine = _Engine()
        result = engine._handle_binop_Sub(_FakeExpr())
    finally:
        _Engine._handle_binop_Sub = original

    captured = capsys.readouterr()
    assert isinstance(result, _FakeRichR)
    assert result.data.size() == 16
    assert "clinic:variable-recovery-size-mismatch" in captured.err
    assert "lhs_bits=16 rhs_bits=32 expr_bits=16" in captured.err
