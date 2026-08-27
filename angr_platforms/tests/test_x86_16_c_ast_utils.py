from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import (
    _c_ast_cycle_path_8616,
    _clone_c_ast_tree_8616,
    _iter_c_nodes_deep_8616,
    _iter_c_statement_nodes_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._index += 1
        return self._index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_c_ast_cycle_path_reports_active_path_cycle() -> None:
    codegen = _DummyCodegen()
    constant = CConstant(1, SimTypeShort(False), codegen=codegen)
    outer = CBinaryOp("Or", constant, constant, codegen=codegen)
    inner = CBinaryOp("Or", outer, constant, codegen=codegen)
    outer.lhs = inner
    root = CStatements([outer], codegen=codegen)

    cycle = _c_ast_cycle_path_8616(root)

    assert cycle
    assert cycle[-1].endswith("(cycle-to=1)")


def test_clone_c_ast_tree_preserves_boundary_objects_without_sharing_nodes() -> None:
    codegen = _DummyCodegen()
    variable = SimRegisterVariable(0, 2, name="ax")
    source = CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp(
        "Or",
        source,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    cloned = _clone_c_ast_tree_8616(expression)

    assert isinstance(cloned, CBinaryOp)
    assert cloned is not expression
    assert cloned.lhs is not expression.lhs
    assert cloned.lhs.variable is variable
    assert cloned.codegen is codegen
    assert _c_ast_cycle_path_8616(cloned) == ()


def test_statement_walk_does_not_descend_into_expression_trees() -> None:
    codegen = _DummyCodegen()
    constant = CConstant(1, SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp("Or", constant, constant, codegen=codegen)
    statement = CExpressionStatement(expression, codegen=codegen)
    root = CStatements([statement], codegen=codegen)

    nodes = tuple(_iter_c_statement_nodes_8616(root))

    assert nodes == (root, statement)
    assert expression not in nodes


def test_deep_walk_visits_shared_nodes_once_and_refuses_cycles() -> None:
    codegen = _DummyCodegen()
    constant = CConstant(1, SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp("Or", constant, constant, codegen=codegen)
    expression.lhs = expression
    root = CStatements([expression, expression], codegen=codegen)

    nodes = tuple(_iter_c_nodes_deep_8616(root))

    assert nodes == (root, expression, constant)
