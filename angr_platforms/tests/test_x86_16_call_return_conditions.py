"""Tests for typed call-return condition materialization."""

from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    structured_callsite_addr_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_calls import _callsite_materialization_signature_8616
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring.call_return_conditions import (
    materialize_call_return_conditions_8616,
)
from angr_platforms.X86_16.tail_validation_condition_context import (
    _owned_materialized_condition_fingerprint_8616,
)
from archinfo import ArchX86


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x100A3,
        target_addr=0x10010,
        return_addr=0x100A6,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )


def _condition() -> ConditionIR:
    return ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="ax", offset=8, size=2),
        rhs=IRValue(MemSpace.CONST, name="const", const=0, size=2),
        src_insn=0x100AC,
        block_addr=0x100A6,
    )


def _surface() -> tuple[SimpleNamespace, SimpleNamespace, CIfElse]:
    callee = SimpleNamespace(addr=0x10010, name="sub_10010")
    functions = SimpleNamespace(function=lambda *, addr, create: callee if addr == 0x10010 and not create else None)
    project = SimpleNamespace(arch=ArchX86(), kb=SimpleNamespace(functions=functions))
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False)
    condition = CBinaryOp(
        "CmpNE",
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100AC, "vex_block_addr": 0x100A6},
    )
    branch = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([branch], codegen=codegen))
    codegen._inertia_typed_conditions = (_condition(),)
    codegen._inertia_callsite_summary_inventory_8616 = {0x100A3: _summary()}
    codegen._inertia_callsite_summaries = {}
    return project, codegen, branch


def _stored_surface() -> tuple[SimpleNamespace, SimpleNamespace, CAssignment, CIfElse, CReturn]:
    """Build a value-return store followed by an AX zero condition."""
    project, codegen, branch = _surface()
    summary = replace(
        _summary(),
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
        return_store_destination=("bp", -2),
        return_store_width=2,
    )
    callee = project.kb.functions.function(addr=0x10010, create=False)
    call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    return_variable = SimRegisterVariable(8, 2, name="ax")
    assignment = CAssignment(
        CVariable(return_variable, variable_type=SimTypeShort(False), codegen=codegen),
        call,
        codegen=codegen,
    )
    returned = CReturn(
        CVariable(return_variable, variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x10000,
        statements=CStatements([assignment, branch, returned], codegen=codegen),
        variables_in_use={},
        unified_local_vars={},
        sort_local_vars=lambda: None,
    )
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    return project, codegen, assignment, branch, returned


def test_materializes_exact_call_return_condition() -> None:
    project, codegen, branch = _surface()

    assert materialize_call_return_conditions_8616(project, codegen)

    expression = branch.condition_and_nodes[0][0]
    assert isinstance(expression, CBinaryOp)
    assert isinstance(expression.lhs, CFunctionCall)
    assert expression.lhs.callee_target == "sub_10010"
    assert structured_callsite_addr_8616(expression.lhs) == 0x100A3
    assert codegen._inertia_callsite_summaries[id(expression.lhs)].target_addr == 0x10010
    assert codegen._inertia_call_return_condition_stats_8616.materialized_count == 1


def test_materializes_value_return_store_before_exact_condition() -> None:
    """Bind the call assignment, condition, and return to the proven BP local."""
    project, codegen, assignment, branch, returned = _stored_surface()

    assert materialize_call_return_conditions_8616(project, codegen)

    condition = branch.condition_and_nodes[0][0]
    assert isinstance(assignment.lhs, CVariable)
    assert isinstance(assignment.lhs.variable, SimStackVariable)
    assert assignment.lhs.variable.offset == -2
    assert condition.lhs is assignment.lhs
    assert returned.retval is assignment.lhs
    call = assignment.rhs
    assert structured_callsite_addr_8616(call) == 0x100A3
    assert codegen._inertia_callsite_summaries[id(call)].return_store_destination == ("bp", -2)


def test_value_return_store_materialization_is_idempotent() -> None:
    """Keep an already-bound stack condition stable on replay."""
    project, codegen, assignment, branch, returned = _stored_surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    destination = assignment.lhs

    assert not materialize_call_return_conditions_8616(project, codegen)
    assert assignment.lhs is destination
    assert branch.condition_and_nodes[0][0].lhs is destination
    assert returned.retval is destination


def test_materializes_when_ast_summary_carrier_is_not_initialized() -> None:
    project, codegen, branch = _surface()
    del codegen._inertia_callsite_summaries

    assert materialize_call_return_conditions_8616(project, codegen)

    call = branch.condition_and_nodes[0][0].lhs
    assert codegen._inertia_callsite_summaries[id(call)] == _summary()


def test_materialization_is_idempotent() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    first = branch.condition_and_nodes[0][0].lhs

    assert not materialize_call_return_conditions_8616(project, codegen)
    assert branch.condition_and_nodes[0][0].lhs is first
    assert codegen._inertia_call_return_condition_stats_8616.materialized_count == 1


def test_refuses_condition_without_exact_return_register() -> None:
    project, codegen, branch = _surface()
    branch.condition_and_nodes[0][0].lhs = CVariable(SimRegisterVariable(2, 2), codegen=codegen)

    assert not materialize_call_return_conditions_8616(project, codegen)
    assert codegen._inertia_call_return_condition_stats_8616.failure_count == 1
    assert not codegen._inertia_callsite_summaries


def test_rebinds_unique_regenerated_target_call() -> None:
    project, codegen, branch = _surface()
    condition = branch.condition_and_nodes[0][0]
    condition.lhs = CFunctionCall("sub_10010", project.kb.functions.function(addr=0x10010, create=False), [], codegen=codegen)

    assert materialize_call_return_conditions_8616(project, codegen)

    call = condition.lhs
    assert structured_callsite_addr_8616(call) == 0x100A3
    assert codegen._inertia_callsite_summaries[id(call)].callsite_addr == 0x100A3


def test_replaces_repeated_callee_clone_without_inheriting_other_callsite_arguments() -> None:
    project, codegen, branch = _surface()
    condition = branch.condition_and_nodes[0][0]
    stale_call = CFunctionCall(
        "sub_10010",
        project.kb.functions.function(addr=0x10010, create=False),
        [CConstant(9, SimTypeShort(False), codegen=codegen)],
        tags={"ins_addr": 0x100B3},
        codegen=codegen,
    )
    condition.lhs = stale_call
    stale_summary = replace(_summary(), callsite_addr=0x100B3, return_addr=0x100B6)
    codegen._inertia_callsite_summary_inventory_8616[stale_summary.callsite_addr] = stale_summary

    assert materialize_call_return_conditions_8616(project, codegen)

    call = condition.lhs
    assert call is not stale_call
    assert call.args == []
    assert structured_callsite_addr_8616(call) == 0x100A3


def test_materializes_original_target_against_rebased_project_callee() -> None:
    project, codegen, branch = _surface()
    original_target = 0x1016E
    local_target = 0x0FC7
    delta = original_target - local_target
    callee = SimpleNamespace(addr=local_target, name="sub_fc7")
    project.kb.functions.function = (
        lambda *, addr, create: callee if addr == local_target and not create else None
    )
    project.loader = SimpleNamespace(
        main_object=SimpleNamespace(linked_base=0, max_addr=0x1FFF)
    )
    project._inertia_original_project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x1FFF)
        )
    )
    project._inertia_original_linear_delta = delta
    summary = replace(_summary(), target_addr=original_target)
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    assert materialize_call_return_conditions_8616(project, codegen)

    call = branch.condition_and_nodes[0][0].lhs
    assert call.callee_func is callee
    assert structured_callsite_addr_8616(call) == summary.callsite_addr


def test_callsite_cache_signature_detects_lost_arguments() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    call = branch.condition_and_nodes[0][0].lhs
    call.args = [CConstant(104, SimTypeShort(False), codegen=codegen)]
    materialized_signature = _callsite_materialization_signature_8616(codegen)

    call.args = []

    assert _callsite_materialization_signature_8616(codegen) != materialized_signature


def test_validation_keeps_materialized_call_with_register_backed_argument() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    condition = branch.condition_and_nodes[0][0]
    condition.tags["inertia_structuring_condition_cfg_materialized_8616"] = True
    ds_offset, ds_size = project.arch.registers["ds"]
    condition.lhs.args = [
        CVariable(SimRegisterVariable(ds_offset, ds_size), codegen=codegen)
    ]

    fingerprint = _owned_materialized_condition_fingerprint_8616(condition, project)

    assert isinstance(fingerprint, str)
    assert "call:" in fingerprint
    assert "reg:ds" in fingerprint
