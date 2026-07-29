from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.dead_register_carriers import (
    prune_unread_stack_lowered_register_carriers_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _stack_local(codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimStackVariable(-4, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _register_carrier(codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimRegisterVariable(6, 2, ident="ir_3", name="bx", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _unstructured_register_carrier(codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _install_root(codegen: _DummyCodegen, statements: list[object]) -> CStatements:
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return root


def test_stack_lowered_carrier_prunes_unread_pure_register_assignment() -> None:
    codegen = _DummyCodegen()
    assignment = CAssignment(
        _register_carrier(codegen),
        CBinaryOp(
            "Shl",
            _stack_local(codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = _install_root(codegen, [CStatements([assignment], codegen=codegen)])

    changed = prune_unread_stack_lowered_register_carriers_8616(codegen)

    assert changed is True
    assert root.statements[0].statements == []
    stats = codegen._inertia_lowered_register_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_stack_lowered_carrier_refuses_register_with_live_read() -> None:
    codegen = _DummyCodegen()
    definition = _register_carrier(codegen)
    read = _register_carrier(codegen)
    assignment = CAssignment(definition, _stack_local(codegen), codegen=codegen)
    use = CAssignment(
        _stack_local(codegen),
        CBinaryOp(
            "Add",
            read,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = _install_root(codegen, [assignment, use])

    changed = prune_unread_stack_lowered_register_carriers_8616(codegen)

    assert changed is False
    assert root.statements == [assignment, use]
    stats = codegen._inertia_lowered_register_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.live_use_refused_count == 1


def test_stack_lowered_carrier_refuses_effectful_rhs() -> None:
    codegen = _DummyCodegen()
    call = CFunctionCall(
        "consume",
        None,
        [_stack_local(codegen)],
        codegen=codegen,
    )
    assignment = CAssignment(_register_carrier(codegen), call, codegen=codegen)
    root = _install_root(codegen, [assignment])

    changed = prune_unread_stack_lowered_register_carriers_8616(codegen)

    assert changed is False
    assert root.statements == [assignment]
    stats = codegen._inertia_lowered_register_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.rhs_refused_count == 1


def test_stack_lowered_carrier_refuses_pure_non_stack_rhs() -> None:
    codegen = _DummyCodegen()
    assignment = CAssignment(
        _register_carrier(codegen),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = _install_root(codegen, [assignment])

    changed = prune_unread_stack_lowered_register_carriers_8616(codegen)

    assert changed is False
    assert root.statements == [assignment]
    stats = codegen._inertia_lowered_register_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.no_stack_source_refused_count == 1


def test_stack_lowered_carrier_prunes_unstructured_register_before_physical_overwrite() -> None:
    codegen = _DummyCodegen()
    dead = CAssignment(
        _unstructured_register_carrier(codegen),
        _stack_local(codegen),
        codegen=codegen,
    )
    overwrite = CAssignment(
        _unstructured_register_carrier(codegen),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    observable_use = CAssignment(
        _stack_local(codegen),
        _unstructured_register_carrier(codegen),
        codegen=codegen,
    )
    root = _install_root(codegen, [dead, overwrite, observable_use])

    changed = prune_unread_stack_lowered_register_carriers_8616(codegen)

    assert changed is True
    assert root.statements == [overwrite, observable_use]
    stats = codegen._inertia_lowered_register_carrier_prune_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_stack_lowered_carrier_refuses_unstructured_register_read_before_overwrite() -> None:
    codegen = _DummyCodegen()
    definition = CAssignment(
        _unstructured_register_carrier(codegen),
        _stack_local(codegen),
        codegen=codegen,
    )
    observable_use = CAssignment(
        _stack_local(codegen),
        _unstructured_register_carrier(codegen),
        codegen=codegen,
    )
    overwrite = CAssignment(
        _unstructured_register_carrier(codegen),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = _install_root(codegen, [definition, observable_use, overwrite])

    changed = prune_unread_stack_lowered_register_carriers_8616(codegen)

    assert changed is False
    assert root.statements == [definition, observable_use, overwrite]
