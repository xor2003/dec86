from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.assignment_lvalue_casts import (
    AssignmentLvalueCastStats8616,
    normalize_scalar_assignment_lvalues_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc: object | None = None

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _assignment_codegen(*, cast_type: object) -> tuple[_Codegen, structured_c.CVariable]:
    codegen = _Codegen()
    storage_type = SimTypeShort(False).with_arch(codegen.project.arch)
    variable = structured_c.CVariable(
        SimStackVariable(-4, 1, base="bp", name="local_4"),
        variable_type=storage_type,
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        structured_c.CTypeCast(
            storage_type,
            cast_type,
            variable,
            codegen=codegen,
        ),
        structured_c.CConstant(0xFF, storage_type, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([assignment], codegen=codegen)
    )
    return codegen, variable


def test_equal_width_scalar_assignment_cast_becomes_direct_lvalue() -> None:
    codegen, variable = _assignment_codegen(
        cast_type=SimTypeChar(True).with_arch(Arch86_16())
    )

    assert normalize_scalar_assignment_lvalues_8616(codegen) is True
    assignment = codegen.cfunc.statements.statements[0]
    assert assignment.lhs is variable
    assert codegen._inertia_assignment_lvalue_cast_stats_8616 == AssignmentLvalueCastStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_width_mismatched_assignment_cast_is_refused() -> None:
    codegen, _variable = _assignment_codegen(
        cast_type=SimTypeShort(False).with_arch(Arch86_16())
    )

    assert normalize_scalar_assignment_lvalues_8616(codegen) is False
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment.lhs, structured_c.CTypeCast)
    assert codegen._inertia_assignment_lvalue_cast_stats_8616.failure_count == 1
