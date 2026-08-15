"""Tests for typed condition views over x86-16 stack storage."""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.condition_stack_operands import (
    materialize_typed_condition_stack_operand_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616


class _FakeCodegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cfunc = SimpleNamespace(addr=0x108D0, variables_in_use={}, unified_local_vars={})
        self.display_vvar_ids = False
        self._next_idx = 0

    def next_idx(self, _kind: str) -> int:
        self._next_idx += 1
        return self._next_idx


def _declare_unsigned_local(codegen: _FakeCodegen) -> tuple[SimStackVariable, structured_c.CVariable]:
    variable = SimStackVariable(-4, 2, base="bp", ident="limit", name="local_4", region=0x108D0)
    cvar = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {(cvar, cvar.variable_type)}
    return variable, cvar


def test_signed_condition_reuses_stack_storage_with_cast_view() -> None:
    codegen = _FakeCodegen()
    variable, declaration = _declare_unsigned_local(codegen)

    expr = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=2,
        name="local_4",
        signed=True,
    )

    assert isinstance(expr, CSemanticCast8616)
    assert isinstance(expr.expr, structured_c.CVariable)
    assert expr.expr.variable is variable
    assert "".join(text for text, _node in expr.c_repr_chunks()) == "(short)local_4"
    assert tuple(codegen.cfunc.variables_in_use.values()) == (declaration,)
    assert tuple(codegen.cfunc.unified_local_vars) == (variable,)


def test_matching_condition_type_reuses_stack_storage_without_cast() -> None:
    codegen = _FakeCodegen()
    variable, declaration = _declare_unsigned_local(codegen)

    expr = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=2,
        name="local_4",
        signed=False,
    )

    assert isinstance(expr, structured_c.CVariable)
    assert expr.variable is variable
    assert tuple(codegen.cfunc.variables_in_use.values()) == (declaration,)


def test_missing_stack_storage_is_materialized_in_function_region() -> None:
    codegen = _FakeCodegen()

    expr = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-6,
        size=2,
        name="local_6",
        signed=True,
    )

    assert isinstance(expr, structured_c.CVariable)
    assert expr.variable.region == 0x108D0
    assert tuple(codegen.cfunc.variables_in_use) == (expr.variable,)
    assert tuple(codegen.cfunc.unified_local_vars) == (expr.variable,)
