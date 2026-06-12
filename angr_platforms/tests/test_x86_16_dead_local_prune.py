from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616

import decompile


class _FakeCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._idx += 1
        return self._idx


def test_prune_dead_local_assignments_keeps_side_effecting_rhs() -> None:
    codegen = _FakeCodegen()
    local_var = SimStackVariable(-2, 2, base="bp", name="local", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    call_expr = structured_c.CFunctionCall(
        "helper",
        SimTypeInt(False),
        args=(),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CAssignment(local_cvar, call_expr, codegen=codegen)],
            codegen=codegen,
        ),
        variables_in_use={local_var: local_cvar},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 1


def test_prune_dead_local_assignments_drops_duplicate_call_before_return() -> None:
    codegen = _FakeCodegen()
    arg_var = SimRegisterVariable(0, 2, name="arg")
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    call_expr = structured_c.CFunctionCall(
        "helper",
        SimTypeInt(False),
        args=(arg_cvar,),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                call_expr,
                structured_c.CReturn(
                    structured_c.CFunctionCall(
                        "helper",
                        SimTypeInt(False),
                        args=(structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen),),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        variables_in_use={arg_var: arg_cvar},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CReturn)


def test_prune_dead_local_assignments_keeps_loop_carried_write_before_continue() -> None:
    codegen = _FakeCodegen()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    x_var = SimStackVariable(4, 2, base="bp", name="x", region=0x1000)

    def total():
        return structured_c.CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)

    def x():
        return structured_c.CVariable(x_var, variable_type=SimTypeShort(False), codegen=codegen)

    statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                total(),
                structured_c.CBinaryOp("Add", total(), x(), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CIfElse(
                [
                    (
                        structured_c.CBinaryOp(
                            "CmpNE",
                            structured_c.CBinaryOp(
                                "And",
                                x(),
                                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                                codegen=codegen,
                            ),
                            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                            codegen=codegen,
                        ),
                        structured_c.CStatements([structured_c.CContinue(codegen=codegen)], codegen=codegen),
                    )
                ],
                codegen=codegen,
            ),
            structured_c.CAssignment(
                total(),
                structured_c.CBinaryOp(
                    "Add",
                    total(),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CReturn(total(), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=statements, variables_in_use={total_var: total(), x_var: x()})

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 4


def test_dce_prunes_unread_pure_stack_base_dirty_carrier() -> None:
    codegen = _FakeCodegen()
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(idx=23, name="vvar_23", reg_offset=8, bits=16),
        codegen=codegen,
    )
    rhs = structured_c.CBinaryOp(
        "Add",
        structured_c.CFakeVariable("stack_base", SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(-6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CAssignment(dirty, rhs, codegen=codegen)],
            codegen=codegen,
        ),
        variables_in_use={},
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    assert codegen.dce_deleted == 1


def test_dce_keeps_read_stack_base_dirty_carrier() -> None:
    codegen = _FakeCodegen()
    dirty_info = SimpleNamespace(idx=23, name="vvar_23", reg_offset=8, bits=16)
    dirty_lhs = structured_c.CDirtyExpression(dirty_info, codegen=codegen)
    dirty_read = structured_c.CDirtyExpression(dirty_info, codegen=codegen)
    rhs = structured_c.CBinaryOp(
        "Add",
        structured_c.CFakeVariable("stack_base", SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(-6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    local_var = SimStackVariable(-2, 2, base="bp", name="local", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(dirty_lhs, rhs, codegen=codegen),
                structured_c.CAssignment(local_cvar, dirty_read, codegen=codegen),
            ],
            codegen=codegen,
        ),
        variables_in_use={local_var: local_cvar},
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 2
