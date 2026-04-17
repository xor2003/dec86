from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_flags import (
    _c_expr_uses_var_8616,
    _fix_interval_guard_conditions_8616,
    _rewrite_flag_condition_pairs_8616,
)
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = _project()

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


def _empty_body(codegen):
    return CStatements([], codegen=codegen)


def test_rewrite_flag_condition_pairs_recovers_zero_flag_guard_without_tail_delta():
    project = _project()
    before_codegen = _codegen([])
    before_flags = _reg(project, "flags", before_codegen, var_name="flags_tmp")
    before_predicate = CBinaryOp(
        "CmpEQ",
        CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen),
        _const(0, before_codegen),
        codegen=before_codegen,
    )
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                before_flags,
                CBinaryOp("Mul", before_predicate, _const(0x40, before_codegen), codegen=before_codegen),
                codegen=before_codegen,
            ),
            CIfElse(
                [(
                    CUnaryOp(
                        "Not",
                        CBinaryOp(
                            "CmpEQ",
                            CBinaryOp("And", before_flags, _const(0x40, before_codegen), codegen=before_codegen),
                            _const(0, before_codegen),
                            codegen=before_codegen,
                        ),
                        codegen=before_codegen,
                    ),
                    _empty_body(before_codegen),
                )],
                codegen=before_codegen,
            ),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = _rewrite_flag_condition_pairs_8616(after_codegen)

    assert changed is True
    assert len(after_codegen.cfunc.statements.statements) == 1
    after_if = after_codegen.cfunc.statements.statements[0]
    after_condition = after_if.condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpEQ"
    assert _c_expr_uses_var_8616(after_condition, before_flags) is False

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen)
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen)
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_rewrite_flag_condition_pairs_recovers_signed_mask_compare_without_raw_flags():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    of_predicate = CBinaryOp("CmpLT", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    flags_value = CBinaryOp(
        "Or",
        CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
        CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(flags_var, flags_value, codegen=codegen),
            CIfElse([(condition, _empty_body(codegen))], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpNE"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False
    assert isinstance(after_condition.lhs, CBinaryOp)
    assert isinstance(after_condition.rhs, CBinaryOp)


def test_rewrite_flag_condition_pairs_refuses_incomplete_signed_mask_recovery():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp(
                        "CmpNE",
                        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is False
    after_condition = codegen.cfunc.statements.statements[1].condition_and_nodes[0][0]
    assert _c_expr_uses_var_8616(after_condition, flags_var) is True


def test_rewrite_flag_condition_pairs_recovers_nested_flag_mask_inside_logical_and():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    of_predicate = CBinaryOp("CmpLT", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    other_guard = CUnaryOp(
        "Not",
        CBinaryOp("CmpLE", _reg(project, "si", codegen), _reg(project, "di", codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp(
                    "Or",
                    CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                    CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp(
                        "LogicalAnd",
                        CBinaryOp(
                            "CmpEQ",
                            CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                            CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                            codegen=codegen,
                        ),
                        other_guard,
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "LogicalAnd"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False
    assert isinstance(after_condition.lhs, CUnaryOp)
    assert after_condition.lhs.op == "Not"
    assert isinstance(after_condition.rhs, CUnaryOp)
    assert after_condition.rhs.op == "Not"


def test_fix_interval_guard_conditions_rewrites_impossible_bool_cite_interval():
    codegen = _codegen([])
    project = _project()
    guard_value = CBinaryOp("Sub", _reg(project, "ax", codegen), _const(3, codegen), codegen=codegen)
    limit = _const(10, codegen)
    low = CBinaryOp("CmpGT", guard_value, limit, codegen=codegen)
    high = CBinaryOp("CmpLT", guard_value, limit, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CIfElse(
                [(
                    CBinaryOp(
                        "LogicalAnd",
                        CITE(low, _const(1, codegen), _const(0, codegen), codegen=codegen),
                        CITE(high, _const(1, codegen), _const(0, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _fix_interval_guard_conditions_8616(codegen)

    assert changed is True
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "LogicalAnd"
