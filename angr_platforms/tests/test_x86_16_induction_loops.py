from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia_decompiler.cli_access_profiles import (
    AccessTraitEvidenceProfile,
    AccessTraitStrideEvidence,
    infer_induction_variable,
)

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from angr_platforms.X86_16.type_array_matching import apply_x86_16_array_expression_matching


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project(traits=None):
    return SimpleNamespace(arch=Arch86_16(), _inertia_access_traits=traits or {})


def _codegen(project, statements):
    codegen = _DummyCodegen(project)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _break_if(cond, codegen):
    return CIfElse(
        [(cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )


def _induction_traits(reg_offset: int, stride: int, *, conflicting_stride: int | None = None):
    base = {
        ("induction_like", "ss", ("stack", "bp", -4), ("reg", reg_offset), stride, 0, 2): AccessTraitStrideEvidence(
            segment="ss",
            base_key=("stack", "bp", -4),
            index_key=("reg", reg_offset),
            stride=stride,
            offset=0,
            width=2,
            count=3,
            kind="induction_like",
        )
    }
    if conflicting_stride is not None:
        base[("induction_like", "ss", ("stack", "bp", -4), ("reg", reg_offset), conflicting_stride, 0, 2)] = AccessTraitStrideEvidence(
            segment="ss",
            base_key=("stack", "bp", -4),
            index_key=("reg", reg_offset),
            stride=conflicting_stride,
            offset=0,
            width=2,
            count=2,
            kind="induction_like",
        )
    return {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": base,
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }


def test_infer_induction_variable_accepts_stable_stride_profile():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=2,
                offset=0,
                width=2,
                count=3,
                kind="induction_like",
            ),
        ),
    )

    inferred = infer_induction_variable(profile)

    assert inferred is not None
    assert inferred.index_key == ("reg", 30)
    assert inferred.stride == 2


def test_infer_induction_variable_refuses_mixed_stride_profile():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=2,
                offset=0,
                width=2,
                count=3,
                kind="induction_like",
            ),
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=4,
                offset=0,
                width=2,
                count=2,
                kind="induction_like",
            ),
        ),
    )

    assert infer_induction_variable(profile) is None


def test_array_matching_rewrites_simple_increment_loop_without_tail_delta():
    project = _project()
    before_codegen = _codegen(project, [])
    i = _reg(project, "si", before_codegen)
    before_codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, before_codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpGE", i, _const(10, before_codegen), codegen=before_codegen), before_codegen),
                        CAssignment(i, CBinaryOp("Add", i, _const(1, before_codegen), codegen=before_codegen), codegen=before_codegen),
                    ],
                    codegen=before_codegen,
                ),
                codegen=before_codegen,
            ),
            CReturn(i, codegen=before_codegen),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = apply_x86_16_array_expression_matching(after_codegen)

    assert changed is True
    loop = after_codegen.cfunc.statements.statements[0]
    assert isinstance(loop, CWhileLoop)
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"
    assert len(loop.body.statements) == 1

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen)
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen)
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_array_matching_rewrites_decrement_loop():
    project = _project()
    codegen = _codegen(project, [])
    i = _reg(project, "cx", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpLE", i, _const(0, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Sub", i, _const(2, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_array_expression_matching(codegen)

    assert changed is True
    loop = codegen.cfunc.statements.statements[0]
    assert loop.condition.op == "CmpGT"
    update = loop.body.statements[0]
    assert isinstance(update, CAssignment)


def test_array_matching_rewrites_stride_non_unit_loop():
    project = _project()
    codegen = _codegen(project, [])
    i = _reg(project, "di", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpGE", i, _const(16, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Add", i, _const(4, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_array_expression_matching(codegen)

    assert changed is True
    loop = codegen.cfunc.statements.statements[0]
    assert loop.condition.op == "CmpLT"
    update = loop.body.statements[0]
    assert update.rhs.rhs.value == 4


def test_array_matching_refuses_loop_with_conflicting_induction_evidence():
    dummy = _DummyCodegen(_project())
    reg_offset = dummy.project.arch.registers["si"][0]
    project = _project({0x4010: _induction_traits(reg_offset, 2, conflicting_stride=4)})
    codegen = _codegen(project, [])
    i = _reg(project, "si", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpGE", i, _const(10, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Add", i, _const(1, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_array_expression_matching(codegen)

    assert changed is False
    loop = codegen.cfunc.statements.statements[0]
    assert isinstance(loop.condition, CConstant)
