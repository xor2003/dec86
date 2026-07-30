"""Regressions for binary-proven direct stack-update multiplicity."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackUpdateFact8616,
    _has_existing_stack_update_assignment_8616,
)


class _DummyCodegen:
    def __init__(self, project: SimpleNamespace) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _stack_increment_fixture(
    *,
    count: int,
    tagged_addr: int | None = None,
) -> tuple[SimpleNamespace, CStatements, DirectStackUpdateFact8616, CVariable, CConstant]:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    stack_var = SimStackVariable(-6, 2, base="bp", name="j", region=0x1000)
    cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    statements = []
    for index in range(count):
        tags = {"ins_addr": tagged_addr} if index == 0 and tagged_addr is not None else {}
        statements.append(
            CAssignment(
                cvar,
                CBinaryOp("Add", cvar, one, codegen=codegen),
                codegen=codegen,
                tags=tags,
            )
        )
    fact = DirectStackUpdateFact8616(offset=-6, width=2, delta=1, ins_addr=0x1030)
    return project, CStatements(statements, codegen=codegen), fact, cvar, one


def test_existing_stack_update_group_accepts_exact_binary_multiplicity() -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=2)

    assert _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=2,
    )


def test_existing_stack_update_group_refuses_incomplete_multiplicity() -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=1)

    assert not _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=2,
    )


def test_existing_stack_update_group_accepts_exact_instruction_tag() -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=1, tagged_addr=0x1030)

    assert _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=2,
    )
