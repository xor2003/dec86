from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.call_return_selectors import (
    bind_call_return_switch_selectors_8616,
)
from angr_platforms.X86_16.validation_dataflow import validate_structured_def_use_8616


def _codegen() -> SimpleNamespace:
    project = SimpleNamespace(arch=SimpleNamespace(bits=16, byte_width=8))
    indices: dict[str, int] = {}

    def next_idx(kind: str) -> int:
        index = indices.get(kind, 0)
        indices[kind] = index + 1
        return index

    return SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x4010, statements=None),
        next_idx=next_idx,
    )


def _ax(codegen: SimpleNamespace) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _call(codegen: SimpleNamespace) -> structured_c.CFunctionCall:
    return structured_c.CFunctionCall(
        "toupper",
        SimpleNamespace(addr=0x2048, name="toupper", block_addrs_set={0x2048}),
        [],
        codegen=codegen,
    )


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1048,
        target_addr=0x2048,
        return_addr=0x104B,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        return_shape="ax",
    )


def test_call_return_selector_binding_materializes_one_structured_identity() -> None:
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen), call, codegen=codegen)
    intermediate = structured_c.CAssignment(
        structured_c.CVariable(
            SimRegisterVariable(18, 2, name="flags"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    switch = structured_c.CSwitchCase(_ax(codegen), [], None, codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CStatements([assignment], codegen=codegen),
            intermediate,
            switch,
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = root
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assignment_variable = assignment.lhs.variable
    selector_variable = switch.switch.variable
    assert assignment_variable is selector_variable
    assert assignment_variable.ident == "call-return-1048"
    assert assignment_variable.region == 0x4010
    assert validate_structured_def_use_8616(root).passed


def test_call_return_selector_binding_refuses_intervening_ax_clobber() -> None:
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen), call, codegen=codegen)
    clobber = structured_c.CAssignment(
        _ax(codegen),
        structured_c.CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    switch = structured_c.CSwitchCase(_ax(codegen), [], None, codegen=codegen)
    root = structured_c.CStatements([assignment, clobber, switch], codegen=codegen)
    codegen.cfunc.statements = root
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 0
    assert result.materialized_count == 0
    assert result.failure_count == 1
    assert assignment.lhs.variable.ident is None
    assert switch.switch.variable.ident is None


def test_call_return_selector_binding_refuses_unproven_return_shape() -> None:
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen), call, codegen=codegen)
    switch = structured_c.CSwitchCase(_ax(codegen), [], None, codegen=codegen)
    root = structured_c.CStatements([assignment, switch], codegen=codegen)
    codegen.cfunc.statements = root
    summary = _summary()
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=summary.callsite_addr,
            target_addr=summary.target_addr,
            return_addr=summary.return_addr,
            kind=summary.kind,
            arg_count=summary.arg_count,
            arg_widths=summary.arg_widths,
            stack_cleanup=summary.stack_cleanup,
            return_register=summary.return_register,
            return_used=summary.return_used,
            return_shape=None,
        )
    }

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 0
    assert result.materialized_count == 0
    assert assignment.lhs.variable.ident is None
    assert switch.switch.variable.ident is None
