"""Regression coverage for tail-validation copy-alias cycle termination."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


class _DummyCodegen:
    """Provide the small structured-codegen boundary needed by C AST nodes."""

    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: object | None = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Allocate a deterministic C AST node identifier."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Allocate a deterministic C AST node identifier."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Keep test variable names stable."""
        return name


def _constant(value: int, codegen: _DummyCodegen) -> CConstant:
    """Build one unsigned 16-bit constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _register(name: str, codegen: _DummyCodegen) -> CVariable:
    """Build one 16-bit physical-register variable."""
    offset, size = codegen.project.arch.registers[name]
    return CVariable(SimRegisterVariable(offset, size, name=name), codegen=codegen)


def test_expr_fingerprint_terminates_two_register_copy_alias_cycle() -> None:
    """A proven copy-alias cycle must fall back to physical storage identity."""
    codegen = _DummyCodegen()
    ax = _register("ax", codegen)
    bx = _register("bx", codegen)
    ax_rhs = CBinaryOp("Add", bx, _constant(1, codegen), codegen=codegen)
    bx_rhs = CBinaryOp("Add", ax, _constant(2, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(ax, ax_rhs, codegen=codegen),
                CAssignment(bx, bx_rhs, codegen=codegen),
            ],
            codegen=codegen,
        ),
        variables_in_use={ax.variable: ax, bx.variable: bx},
    )

    fingerprint = _expr_fingerprint(ax, codegen.project)
    register_name = codegen.project.arch.translate_register_name(ax.variable.reg, ax.variable.size)

    assert f"reg:{register_name}" in fingerprint
    assert "cycle" not in fingerprint
    assert fingerprint == _expr_fingerprint(ax, codegen.project)
