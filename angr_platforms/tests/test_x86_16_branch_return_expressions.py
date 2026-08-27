from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CReturn, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.structuring import branch_return_expressions
from angr_platforms.X86_16.structuring.branch_return_expressions import (
    recover_branch_target_return_expression_8616,
    sole_return_expression_8616,
)
from archinfo import ArchX86


@dataclass
class _Operand:
    type: int
    reg: int = 0
    imm: int = 0
    size: int = 2
    mem: object | None = None


class _Insn:
    def __init__(self, mnemonic: str, operands: tuple[_Operand, ...]) -> None:
        self.mnemonic = mnemonic
        self.operands = operands

    def reg_name(self, reg_id: int) -> str:
        return {1: "ax", 2: "dx", 3: "bp"}.get(reg_id, "")


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Factory:
    def __init__(self, insns: tuple[_Insn, ...]) -> None:
        self._block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def block(self, _addr: int, *, opt_level: int = 0) -> object:
        del opt_level
        return self._block


def _project(*insns: _Insn) -> object:
    return SimpleNamespace(factory=_Factory(insns))


def test_sole_return_expression_accepts_one_wrapped_return() -> None:
    codegen = _Codegen()
    expression = CConstant(7, SimTypeShort(False), codegen=codegen)
    body = CStatements([CReturn(expression, codegen=codegen)], codegen=codegen)

    assert sole_return_expression_8616(body) is expression


def test_branch_target_return_expression_recovers_signed_ax_immediate() -> None:
    codegen = _Codegen()
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=0xFFFF))),
    )

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CConstant)
    assert expression.value == -1
    assert expression.type.signed is True


def test_branch_target_return_expression_refuses_value_before_conditional_branch() -> None:
    codegen = _Codegen()
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=7))),
        _Insn("jge", (_Operand(2, imm=0x1100),)),
    )

    assert recover_branch_target_return_expression_8616(project, codegen, 0x1000) is None


def test_branch_target_return_expression_combines_adjacent_dx_ax_stack_slices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lowered_values: list[object] = []

    def _lower(value: object, _project: object, _codegen: object) -> CConstant:
        lowered_values.append(value)
        return CConstant(77, SimTypeShort(False), codegen=_codegen)

    monkeypatch.setattr(branch_return_expressions, "lower_ir_value_to_c_expr_8616", _lower)
    codegen = _Codegen()
    ax_mem = SimpleNamespace(base=3, index=0, disp=4)
    dx_mem = SimpleNamespace(base=3, index=0, disp=6)
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=ax_mem))),
        _Insn("mov", (_Operand(1, reg=2), _Operand(3, mem=dx_mem))),
    )

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CConstant)
    assert expression.value == 77
    assert len(lowered_values) == 1
    assert lowered_values[0].offset == 4
    assert lowered_values[0].size == 4
