from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.structuring.stored_call_result_assignments import (
    StoredCallResultAssignmentRefusalReason8616,
    StoredCallResultAssignmentVerdict8616,
    materialize_stored_call_result_assignments_8616,
)


class _AstCodegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _summary(callsite_addr: int, store_addr: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=None,
        return_addr=callsite_addr + 3,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        return_store_destination=("bp", 6),
        return_store_width=2,
        return_store_instruction_addr=store_addr,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )


def _stack_value(codegen: _AstCodegen) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="value"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _indirect_call(
    codegen: _AstCodegen,
    value: structured_c.CVariable,
    callsite_addr: int,
) -> structured_c.CFunctionCall:
    return structured_c.CFunctionCall(
        "fn",
        SimpleNamespace(addr=None, name="fn"),
        [value],
        tags={"ins_addr": callsite_addr},
        codegen=codegen,
    )


def test_materializes_indirect_call_results_into_exact_stack_argument() -> None:
    codegen = _AstCodegen()
    value = _stack_value(codegen)
    first_call = _indirect_call(codegen, value, 0x100E)
    second_call = _indirect_call(codegen, value, 0x101A)
    eax = structured_c.CVariable(
        SimRegisterVariable(codegen.project.arch.get_register_offset("eax"), 4, name="eax"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    first_assignment = structured_c.CAssignment(eax, first_call, codegen=codegen)
    wrong_destination = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="fn"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first_store_artifact = structured_c.CAssignment(
        wrong_destination,
        eax,
        tags={"ins_addr": 0x1014},
        codegen=codegen,
    )
    second_statement = structured_c.CExpressionStatement(second_call, codegen=codegen)
    second_store_artifact = structured_c.CAssignment(
        wrong_destination,
        eax,
        tags={"ins_addr": 0x1020},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [first_assignment, first_store_artifact, second_statement, second_store_artifact],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {
        id(first_call): _summary(0x100E, 0x1014),
        id(second_call): _summary(0x101A, 0x1020),
    }

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.MATERIALIZED
    assert result.changed
    assert isinstance(first_assignment.lhs.variable, SimStackVariable)
    assert first_assignment.lhs.variable.offset == 6
    assert len(root.statements) == 2
    second_assignment = root.statements[1]
    assert isinstance(second_assignment, structured_c.CAssignment)
    assert isinstance(second_assignment.lhs.variable, SimStackVariable)
    assert second_assignment.rhs is second_call
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_refuses_when_exact_stack_destination_has_no_owned_variable() -> None:
    codegen = _AstCodegen()
    call = structured_c.CFunctionCall(
        "fn",
        SimpleNamespace(addr=None, name="fn"),
        [structured_c.CConstant(5, SimTypeShort(False), codegen=codegen)],
        tags={"ins_addr": 0x100E},
        codegen=codegen,
    )
    statement = structured_c.CExpressionStatement(call, codegen=codegen)
    root = structured_c.CStatements([statement], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x100E, 0x1014)}

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.UNKNOWN_REFUSE
    assert not result.changed
    assert root.statements == [statement]
    assert result.refusals[0].reason is (
        StoredCallResultAssignmentRefusalReason8616.DESTINATION_VARIABLE_MISSING
    )
