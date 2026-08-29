"""Production input storage-trial collection over real lifted IR and SSA."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsiteArgumentClass8616,
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.ir import IRValue, MemSpace
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering import interprocedural_storage_trial_collection as storage_trial_collection
from angr_platforms.X86_16.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from angr_platforms.X86_16.lowering.callee_callsite_census import (
    CalleeCallsiteFact8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_collection_contracts import (
    StorageTrialCollectionFailureKind8616,
    StorageTrialCollectionVerdict8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_trial_collection import (
    collect_function_input_storage_trials_8616,
)


class _Functions8616:
    """Exact fake function manager over real angr block lifting."""

    def __init__(self, functions: tuple[object, ...]) -> None:
        self._functions = functions

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return the unique exact function address, if present."""
        return next(
            (
                function
                for function in self._functions
                if isinstance(function, SimpleNamespace) and function.addr == addr
            ),
            None,
        )


def _summary(
    *,
    callsite_addr: int,
    target_addr: int,
    push_addr: int,
    source: tuple[object, ...],
    logical_class: CallsiteArgumentClass8616 | None = None,
) -> CallsiteSummary8616:
    """Build one exact single-word physical call summary."""
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=target_addr,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=None,
        push_arg_sources=(source,),
        push_arg_instruction_addrs=(push_addr,),
        logical_arg_classes=() if logical_class is None else (logical_class,),
    )


def _project_with_census(
    code: bytes,
    summary: CallsiteSummary8616,
    *,
    caller_addr: int = 0x1000,
    duplicate_callsite: bool = False,
) -> SimpleNamespace:
    """Build a real-lifter project surface with one retained typed caller census."""
    lifted = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    caller = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        info={},
    )
    project = SimpleNamespace(
        factory=lifted.factory,
        kb=SimpleNamespace(functions=_Functions8616((caller,))),
    )
    fact = CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=caller,
        evidence_target_addr=summary.target_addr or 0,
        caller_addr=caller_addr,
        callsite_addr=summary.callsite_addr,
        summary=summary,
    )
    facts = (fact, fact) if duplicate_callsite else (fact,)
    raw_count = len(facts)
    logical_argument_count = (
        len(summary.logical_arg_widths)
        if summary.logical_arg_widths
        else summary.arg_count
    )
    count_evidence = CalleeArgumentCountEvidence8616(
        target_addr=summary.target_addr or 0,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=logical_argument_count,
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=raw_count,
        materialized_count=raw_count,
        callsite_addrs=tuple(item.callsite_addr for item in facts),
        callsite_summaries=tuple(summary for _item in facts),
        callsite_facts=facts,
    )
    project._inertia_callee_argument_count_evidence_8616 = {
        count_evidence.target_addr: count_evidence,
    }
    return project


def _signed_codegen(width: int = 2) -> SimpleNamespace:
    """Return one exact signed condition fact over the first stack argument."""
    return SimpleNamespace(
        _inertia_typed_conditions=(
            ConditionIR(
                "slt",
                IRValue(MemSpace.SS, name="bp", offset=4, size=width),
                IRValue(MemSpace.CONST, const=0, size=width),
                src_insn=0x1010,
                block_addr=0x1010,
            ),
        ),
    )


def _empty_codegen() -> SimpleNamespace:
    """Return codegen without signedness evidence."""
    return SimpleNamespace(_inertia_typed_conditions=())


def test_collects_signed_immediate_trial_and_feeds_scc_solver() -> None:
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, -1),
    )
    project = _project_with_census(bytes.fromhex("6affe80000"), summary)

    result = collect_function_input_storage_trials_8616(project, _signed_codegen(), 0x1005)

    assert result.complete
    assert result.stats.complete
    trials = result.trials.callsites[0].arguments
    assert len(trials) == 2
    assert {trial.logical_index for trial in trials} == {0}
    assert all(trial.piece_count == 2 for trial in trials)
    assert trials[0].reaching_definition.value.const == 0xFFFF
    assert all(trial.signedness is StorageTrialSignedness8616.SIGNED for trial in trials)
    assert all(trial.value_class is StorageTrialValueClass8616.VALUE for trial in trials)
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(0x1005)
    assert contract is not None
    assert len(contract.inputs) == 1
    assert contract.inputs[0].width == 2


def test_wide_logical_input_keeps_four_pieces_in_one_solver_slot() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=0x1007,
        return_addr=0x1007,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=None,
        push_arg_sources=(
            (CallsitePushSourceKind8616.IMMEDIATE.value, 2),
            (CallsitePushSourceKind8616.IMMEDIATE.value, 1),
        ),
        push_arg_instruction_addrs=(0x1000, 0x1002),
        logical_arg_widths=(4,),
    )
    project = _project_with_census(bytes.fromhex("6a026a01e80000"), summary)

    result = collect_function_input_storage_trials_8616(
        project,
        _signed_codegen(4),
        0x1007,
    )

    assert result.complete
    trials = result.trials.callsites[0].arguments
    assert len(trials) == 4
    assert {trial.logical_index for trial in trials} == {0}
    assert all(trial.piece_count == 4 for trial in trials)
    assert tuple(trial.storage.address.offset for trial in trials if trial.storage.address) == (4, 5, 6, 7)
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(0x1007)
    assert contract is not None
    assert len(contract.inputs) == 1
    assert contract.inputs[0].width == 4


def test_zero_argument_call_does_not_materialize_return_address_bytes() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1000,
        target_addr=0x1003,
        return_addr=0x1003,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=None,
        push_arg_sources=(),
        push_arg_instruction_addrs=(),
    )
    project = _project_with_census(bytes.fromhex("e80000"), summary)

    result = collect_function_input_storage_trials_8616(
        project,
        _empty_codegen(),
        0x1003,
    )

    assert result.complete
    assert result.trials.callsites[0].arguments == ()
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(0x1003)
    assert contract is not None
    assert contract.inputs == ()


def test_collects_bp_address_as_pointer_without_scalar_signedness() -> None:
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1003,
        source=(CallsitePushSourceKind8616.BP_ADDRESS.value, -4),
    )
    project = _project_with_census(bytes.fromhex("8d46fc50e80000"), summary)

    result = collect_function_input_storage_trials_8616(project, _empty_codegen(), 0x1007)

    assert result.complete
    trials = result.trials.callsites[0].arguments
    assert {trial.logical_index for trial in trials} == {0}
    assert all(trial.value_class is StorageTrialValueClass8616.POINTER for trial in trials)
    assert all(trial.signedness is StorageTrialSignedness8616.NOT_APPLICABLE for trial in trials)
    assert tuple(
        trial.reaching_definition.source_storage.address.offset
        for trial in trials
        if trial.reaching_definition.source_storage is not None
        and trial.reaching_definition.source_storage.address is not None
    ) == (-4, -3)


def test_split_global_word_retains_two_source_and_callee_pieces() -> None:
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.GLOBAL_VALUE.value, 0x1200, 2),
    )
    project = _project_with_census(bytes.fromhex("ff360012e80000"), summary)

    result = collect_function_input_storage_trials_8616(project, _signed_codegen(), 0x1007)

    assert result.complete
    trials = result.trials.callsites[0].arguments
    assert tuple(trial.piece_index for trial in trials) == (0, 1)
    assert all(trial.piece_count == 2 for trial in trials)
    assert tuple(trial.storage.width for trial in trials) == (1, 1)
    assert tuple(trial.storage.address.offset for trial in trials if trial.storage.address) == (4, 5)
    assert tuple(
        trial.reaching_definition.source_storage.address.offset
        for trial in trials
        if trial.reaching_definition.source_storage is not None
        and trial.reaching_definition.source_storage.address is not None
    ) == (0x1200, 0x1201)


def test_unknown_signedness_refuses_before_caller_ssa(monkeypatch) -> None:
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )
    project = _project_with_census(bytes.fromhex("6a05e80000"), summary)
    monkeypatch.setattr(
        storage_trial_collection,
        "semantic_function_ssa_artifact_at_address_8616",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("caller SSA must not run")),
    )

    result = collect_function_input_storage_trials_8616(project, _empty_codegen(), 0x1005)

    assert result.verdict is StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
    assert result.trials.callsites == ()
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
    assert result.failures[0].kind is StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN


def test_mismatched_caller_boundary_retains_typed_registry_failure() -> None:
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )
    project = _project_with_census(
        bytes.fromhex("6a05e80000"),
        summary,
        caller_addr=0x1200,
    )

    result = collect_function_input_storage_trials_8616(project, _signed_codegen(), 0x1005)

    assert result.verdict is StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
    assert result.failures[0].kind is StorageTrialCollectionFailureKind8616.CALLER_SSA_UNAVAILABLE
    assert (
        result.failures[0].ssa_failure
        is FunctionSSAArtifactFailure8616.FUNCTION_BOUNDARY_CONFLICT
    )


def test_duplicate_machine_callsite_identity_is_a_conflict() -> None:
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )
    project = _project_with_census(
        bytes.fromhex("6a05e80000"),
        summary,
        duplicate_callsite=True,
    )

    result = collect_function_input_storage_trials_8616(project, _signed_codegen(), 0x1005)

    assert result.verdict is StorageTrialCollectionVerdict8616.CONFLICT
    assert result.failures[0].kind is StorageTrialCollectionFailureKind8616.CALLSITE_IDENTITY_CONFLICT
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_binary_pointer_source_conflicts_with_explicit_value_class() -> None:
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1003,
        source=(CallsitePushSourceKind8616.BP_ADDRESS.value, -4),
        logical_class=CallsiteArgumentClass8616.VALUE,
    )
    project = _project_with_census(bytes.fromhex("8d46fc50e80000"), summary)

    result = collect_function_input_storage_trials_8616(project, _empty_codegen(), 0x1007)

    assert result.verdict is StorageTrialCollectionVerdict8616.CONFLICT
    assert result.failures[0].kind is StorageTrialCollectionFailureKind8616.VALUE_CLASS_CONFLICT
