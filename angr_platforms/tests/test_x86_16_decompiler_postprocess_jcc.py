from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CIfElse, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_jcc import _DecodedCmpGuard8616, _rewrite_decoded_jcc_conditions_8616


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements):
    codegen = _DummyCodegen()
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


def test_rewrite_decoded_jcc_conditions_refuses_self_compare(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    same_expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=same_expr,
            rhs=same_expr,
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_refuses_fingerprint_equal_compare(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    lhs = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    rhs = CBinaryOp("Add", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=lhs,
            rhs=rhs,
            op="CmpGT",
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._expr_fingerprint",
        lambda _expr, _project: "same",
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond
