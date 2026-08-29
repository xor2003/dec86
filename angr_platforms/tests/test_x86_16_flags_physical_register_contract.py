"""Regressions for physical-register identity consumed by flag cleanup."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CIfElse,
    CStatements,
    CSwitchCase,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_flags import (
    _prune_overwritten_flag_assignments_8616,
    _prune_unused_flag_assignments_8616,
)


class _Codegen:
    """Provide the small structured-codegen contract needed by C AST nodes."""

    def __init__(self, project: SimpleNamespace) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = project
        root = CStatements([], addr=0x4010, codegen=self)
        self.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    def next_idx(self, _name: str) -> int:
        """Return one deterministic C AST index."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Return one deterministic C AST node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Keep deterministic identifiers in focused tests."""
        return name


def _project() -> SimpleNamespace:
    """Build the owned project boundary needed by flag cleanup."""
    return SimpleNamespace(arch=Arch86_16())


def _register_vvar(
    project: SimpleNamespace,
    codegen: _Codegen,
    name: str,
    varid: int,
) -> CDirtyExpression:
    """Build a current-angr virtual variable with exact register identity."""
    reg_offset, reg_size = project.arch.registers[name]
    virtual = VirtualVariable(
        codegen.next_idx("ail_vvar"),
        varid,
        reg_size * 8,
        VirtualVariableCategory.REGISTER,
        oident=reg_offset,
    )
    return CDirtyExpression(virtual, codegen=codegen)


def _constant(codegen: _Codegen, value: int) -> CConstant:
    """Build one unsigned 16-bit C constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _install_statements(codegen: _Codegen, statements: list[object]) -> CStatements:
    """Install one focused function body on the test codegen."""
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    return root


def test_unused_flag_pruning_recognizes_virtual_register_oident() -> None:
    """An unread flags vvar must not survive because its identity is in oident."""
    project = _project()
    codegen = _Codegen(project)
    statement = CAssignment(
        _register_vvar(project, codegen, "flags", 12),
        _constant(codegen, 0x40),
        codegen=codegen,
    )
    root = _install_statements(codegen, [statement])

    changed = _prune_unused_flag_assignments_8616(project, codegen)

    assert changed is True
    assert root.statements == []


def test_unused_flag_pruning_keeps_read_virtual_register_oident() -> None:
    """A condition read through the same physical flags register stays live."""
    project = _project()
    codegen = _Codegen(project)
    write = CAssignment(
        _register_vvar(project, codegen, "flags", 12),
        _constant(codegen, 0x40),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "And",
        _register_vvar(project, codegen, "flags", 13),
        _constant(codegen, 0x40),
        codegen=codegen,
    )
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)
    root = _install_statements(codegen, [write, branch])

    changed = _prune_unused_flag_assignments_8616(project, codegen)

    assert changed is False
    assert root.statements == [write, branch]


def test_overwritten_flag_pruning_recognizes_virtual_register_oident() -> None:
    """Dead overwritten flag chains reach a fixed point for real angr vvars."""
    project = _project()
    codegen = _Codegen(project)
    first_flags = _register_vvar(project, codegen, "flags", 12)
    second_flags = _register_vvar(project, codegen, "flags", 13)
    first = CAssignment(first_flags, _constant(codegen, 1), codegen=codegen)
    second = CAssignment(
        second_flags,
        CBinaryOp("Or", first_flags, _constant(codegen, 2), codegen=codegen),
        codegen=codegen,
    )
    root = _install_statements(codegen, [first, second])

    changed = _prune_overwritten_flag_assignments_8616(project, codegen)

    assert changed is True
    assert root.statements == []


def test_overwritten_flag_pruning_descends_into_switch_case() -> None:
    """A dead flags chain inside a switch arm must reach cleanup and vanish."""
    project = _project()
    codegen = _Codegen(project)
    first_flags = _register_vvar(project, codegen, "flags", 12)
    second_flags = _register_vvar(project, codegen, "flags", 13)
    first = CAssignment(first_flags, _constant(codegen, 1), codegen=codegen)
    second = CAssignment(
        second_flags,
        CBinaryOp("Or", first_flags, _constant(codegen, 2), codegen=codegen),
        codegen=codegen,
    )
    case_body = CStatements([first, second], codegen=codegen)
    switch = CSwitchCase(_constant(codegen, 84), [(84, case_body)], None, codegen=codegen)
    _install_statements(codegen, [switch])

    changed = _prune_overwritten_flag_assignments_8616(project, codegen)

    assert changed is True
    assert case_body.statements == []
