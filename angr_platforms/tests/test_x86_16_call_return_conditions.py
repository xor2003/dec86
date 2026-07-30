"""Tests for typed call-return condition materialization."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
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
