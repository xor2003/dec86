from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import CallsiteReturnUseKind8616
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.unobserved_call_results import (
    lower_unobserved_call_result_assignments_8616,
)


def _call_result_codegen(
    *,
    return_used: bool,
    return_use_kind: CallsiteReturnUseKind8616 | None,
    return_register: str | None = "ax",
):
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 0,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
    )
    call = CFunctionCall(
        "callee",
        SimpleNamespace(addr=0x12000),
        [],
        tags={"ins_addr": 0x10100},
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(0, 4, name="eax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(carrier, call, codegen=codegen)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x10100,
            target_addr=0x12000,
            return_addr=0x10103,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=return_register,
            return_used=return_used,
            return_use_kind=return_use_kind,
        )
    }
    return codegen, root, call, assignment


def test_lowers_typed_clobbered_ax_result_to_standalone_call() -> None:
    codegen, root, call, assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=CallsiteReturnUseKind8616.CLOBBERED,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True

    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call
    assert statement is not assignment
    stats = codegen._inertia_unobserved_call_result_lowering_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.closed is True


def test_refuses_call_result_without_clobbered_return_evidence() -> None:
    codegen, root, _call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is False
    assert root.statements == [assignment]
    stats = codegen._inertia_unobserved_call_result_lowering_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_lowers_typed_unused_ax_assignment_at_void_exit() -> None:
    codegen, root, call, _assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=None,
        return_register=None,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call
