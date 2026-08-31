from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir import vex_import
from angr_platforms.X86_16.ir.core import IRInstr
from pytest import MonkeyPatch


def test_binary_temporary_normalizes_each_operand_once(monkeypatch: MonkeyPatch) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=3))
    binary = SimpleNamespace(
        tag="Iex_Binop",
        op="Iop_Add16",
        args=(left, right),
    )
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=0, data=binary)
    converted: list[object] = []
    original = vex_import._expr_to_value

    def tracked(expr: object, *args: object, **kwargs: object):
        converted.append(expr)
        return original(expr, *args, **kwargs)

    monkeypatch.setattr(vex_import, "_expr_to_value", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
    )

    assert isinstance(instruction, IRInstr)
    assert instruction.op == "Iop_Add16"
    assert converted == [left, right]
