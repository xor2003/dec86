from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616


class _Codegen(SimpleNamespace):
    """Minimal dynamic angr codegen boundary for focused DCE tests."""

    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        """Return one stable synthetic node index."""
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        """Return one stable synthetic AST node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep requested identifiers stable in the synthetic AST."""
        return name


def _variable(codegen: _Codegen, name: str, reg: int) -> structured_c.CVariable:
    """Build one local register carrier at the dynamic angr boundary."""
    return structured_c.CVariable(
        SimRegisterVariable(reg, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


@pytest.mark.parametrize("unary_op", ("LogicalNot", "BitwiseNegate"))
def test_dce_deletes_unread_pure_angr_unary_carrier(unary_op: str) -> None:
    codegen = _Codegen()
    source = _variable(codegen, "flags_in", 36)
    result = _variable(codegen, "ir_flags_out", 38)
    rhs = structured_c.CUnaryOp(unary_op, source, codegen=codegen)
    assignment = structured_c.CAssignment(result, rhs, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([assignment], codegen=codegen),
    )

    assert _dead_code_elimination_8616(codegen) is True
    assert codegen.cfunc.statements.statements == []
    assert codegen.dce_deleted == 1
