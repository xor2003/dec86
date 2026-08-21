"""Types/Lowering regressions for exact wide call-output C assignments."""

from __future__ import annotations

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentFailure8616,
)
from angr_platforms.X86_16.lowering.wide_call_output_assignments import (
    lower_wide_call_output_stack_assignments_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from x86_16_carry_borrow_call_output_support import wide_assignment_fixture


def test_lowering_materializes_wide_call_output_assignment_once() -> None:
    codegen, root, call, source = wide_assignment_fixture()

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs is call
    assert assignment.rhs.rhs is source

    replayed = lower_wide_call_output_stack_assignments_8616(codegen)
    assert replayed is not None and replayed.complete
    assert replayed.stats.changed_count == 0
    assert replayed.stats.already_materialized_count == 1
    assert root.statements == [assignment]


def test_lowering_materializes_exact_adjacent_nested_carrier_group() -> None:
    codegen, root, call, source = wide_assignment_fixture(nested_carrier_group=True)
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    assert root.statements == [call_group, carrier_group]
    assert len(call_group.statements) == 1
    assignment = call_group.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.lhs is call
    assert assignment.rhs.rhs is source
    assert carrier_group.statements == []

    replayed = lower_wide_call_output_stack_assignments_8616(codegen)
    assert replayed is not None and replayed.complete
    assert replayed.stats.already_materialized_count == 1
    assert root.statements == [call_group, carrier_group]


def test_lowering_refuses_unjoined_callsite_without_mutation() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(callsite_tag=0xFE0)
    original = tuple(root.statements)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.normalized_fact_count == artifact.stats.failure_count == 1
    assert artifact.stats.classified_fact_count == artifact.stats.materialized_count == 0
    assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.CALLSITE_MISSING
    assert tuple(root.statements) == original


def test_lowering_materializes_missing_exact_source_object_from_fact() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(include_source=False)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.materialized_count == artifact.stats.changed_count == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    source = assignment.rhs.rhs
    assert isinstance(source, CVariable)
    assert isinstance(source.variable, SimStackVariable)
    assert (source.variable.base, source.variable.offset, source.variable.size) == (
        "bp",
        4,
        4,
    )


def test_lowering_hard_fails_classified_mixed_carrier_ownership() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(mixed_carrier=True)
    original = tuple(root.statements)

    with pytest.raises(PipelineHardError, match="accounting is incomplete"):
        lower_wide_call_output_stack_assignments_8616(codegen)

    artifact = codegen._inertia_wide_call_output_assignment_artifact_8616
    assert artifact.stats.classified_fact_count == artifact.stats.failure_count == 1
    assert artifact.stats.materialized_count == 0
    assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
    assert tuple(root.statements) == original


@pytest.mark.parametrize(
    "fixture_kwargs",
    (
        {"unrelated_nested_statement": True},
        {"mixed_carrier": True},
    ),
)
def test_lowering_refuses_noncarrier_effects_in_nested_group(
    fixture_kwargs: dict[str, bool],
) -> None:
    codegen, root, _call, _source = wide_assignment_fixture(
        nested_carrier_group=True,
        **fixture_kwargs,
    )
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)
    original_call = tuple(call_group.statements)
    original_carriers = tuple(carrier_group.statements)

    with pytest.raises(PipelineHardError, match="accounting is incomplete"):
        lower_wide_call_output_stack_assignments_8616(codegen)

    artifact = codegen._inertia_wide_call_output_assignment_artifact_8616
    assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
    assert tuple(call_group.statements) == original_call
    assert tuple(carrier_group.statements) == original_carriers


def test_lowering_refuses_ambiguous_nested_carrier_parent() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(nested_carrier_group=True)
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)
    duplicate_parent = CStatements([call_group, CStatements([], codegen=codegen)], codegen=codegen)
    root.statements.append(duplicate_parent)

    with pytest.raises(PipelineHardError, match="accounting is incomplete"):
        lower_wide_call_output_stack_assignments_8616(codegen)

    artifact = codegen._inertia_wide_call_output_assignment_artifact_8616
    assert (
        artifact.resolutions[0].failure
        is WideCallOutputAssignmentFailure8616.CARRIER_PLACEMENT_AMBIGUOUS
    )
    assert len(call_group.statements) == 1
    assert len(carrier_group.statements) == 4
