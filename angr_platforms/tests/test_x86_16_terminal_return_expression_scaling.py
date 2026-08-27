from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import terminal_return_expressions


class _Codegen:
    def __init__(self) -> None:
        self.index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self.index += 1
        return self.index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_deep_terminal_expression_uses_one_structural_clone(monkeypatch) -> None:
    """Keep terminal expression resolution linear in AST depth."""
    codegen = _Codegen()
    short_type = SimTypeShort(signed=False)
    expression: object = structured_c.CConstant(1, short_type, codegen=codegen)
    for value in range(2, 34):
        expression = structured_c.CBinaryOp(
            "Add",
            expression,
            structured_c.CConstant(value, short_type, codegen=codegen),
            codegen=codegen,
        )

    clone_count = 0
    original_clone = terminal_return_expressions._clone_c_ast_tree_8616

    def counted_clone(node: object) -> object:
        nonlocal clone_count
        clone_count += 1
        return original_clone(node)

    monkeypatch.setattr(terminal_return_expressions, "_clone_c_ast_tree_8616", counted_clone)

    resolved = terminal_return_expressions.resolve_linear_virtual_return_expression_8616((), expression)

    assert isinstance(resolved, structured_c.CBinaryOp)
    assert clone_count == 1


def test_safe_terminal_expression_clears_codegen_depth_collapse() -> None:
    """Render a proven scalar return even when angr hid it by depth."""
    codegen = _Codegen()
    short_type = SimTypeShort(signed=True)
    lhs = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(1, short_type, codegen=codegen),
        structured_c.CConstant(2, short_type, codegen=codegen),
        codegen=codegen,
        collapsed=True,
    )
    expression = structured_c.CBinaryOp(
        "Add",
        lhs,
        structured_c.CConstant(3, short_type, codegen=codegen),
        codegen=codegen,
        collapsed=True,
    )

    changed = terminal_return_expressions.uncollapse_safe_scalar_expression_8616(expression)

    assert changed is True
    assert expression.collapsed is False
    assert lhs.collapsed is False


def test_unresolved_terminal_expression_keeps_codegen_depth_collapse() -> None:
    """Do not expose a hidden return while its value remains unresolved."""
    codegen = _Codegen()
    expression = structured_c.CDirtyExpression(SimpleNamespace(varid=7), codegen=codegen)
    expression.collapsed = True

    changed = terminal_return_expressions.uncollapse_safe_scalar_expression_8616(expression)

    assert changed is False
    assert expression.collapsed is True
