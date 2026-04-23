from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler import structured_codegen as _scg
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CExpressionStatement, CFunctionCall, CStatements
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import _materialize_callsite_stack_arguments_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _empty_codegen(project):
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def test_stack_probe_typed_return_state_refuses_partial_recovery_when_summary_arg_count_is_oversized():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    arg_slot = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    draw_bar = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(draw_bar, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(draw_bar): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 3
    final_stmt = codegen.cfunc.statements.statements[2]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == []
    assert codegen._inertia_callsite_summaries[id(draw_bar)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(draw_bar)].arg_widths == (2, 2)
