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

    def function(self, *, addr: int, create: bool = False) -> object | None:  # noqa: ARG002
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
        evidence_target_addr=summary.target_addr or 0,
        caller_addr=caller_addr,
        callsite_addr=summary.callsite_addr,
        summary=summary,
    )
    facts = (fact, fact) if duplicate_callsite else (fact,)
    raw_count = len(facts)
    count_evidence = CalleeArgumentCountEvidence8616(
        target_addr=summary.target_addr or 0,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=1,
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


def _signed_codegen() -> SimpleNamespace:
    """Return one exact signed condition fact over the first stack argument."""
    return SimpleNamespace(
        _inertia_typed_conditions=(
            ConditionIR(
                "slt",
                IRValue(MemSpace.SS, name="bp", offset=4, size=2),
                IRValue(MemSpace.CONST, const=0, size=2),
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
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )
    project = _project_with_census(bytes.fromhex("6a05e80000"), summary)

    result = collect_function_input_storage_trials_8616(project, _signed_codegen(), 0x1005)

    assert result.complete
    assert result.stats.complete
    trial = result.trials.callsites[0].arguments[0]
    assert trial.reaching_definition.value.const == 5
    assert trial.signedness is StorageTrialSignedness8616.SIGNED
    assert trial.value_class is StorageTrialValueClass8616.VALUE
    assert trial.storage.address is not None
    assert trial.storage.address.offset == 4
    assert resolve_program_storage_trials_8616((result.trials,)).contract_for(0x1005) is not None


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
    trial = result.trials.callsites[0].arguments[0]
    assert trial.value_class is StorageTrialValueClass8616.POINTER
    assert trial.signedness is StorageTrialSignedness8616.NOT_APPLICABLE
    source = trial.reaching_definition.source_storage
    assert source is not None and source.address is not None
    assert source.address.offset == -4


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


def test_unknown_signedness_refuses_without_classified_unmaterialized_gap() -> None:
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )
    project = _project_with_census(bytes.fromhex("6a05e80000"), summary)

    result = collect_function_input_storage_trials_8616(project, _empty_codegen(), 0x1005)

    assert result.verdict is StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
    assert result.trials.callsites == ()
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
    assert result.failures[0].kind is StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN


def test_missing_caller_ssa_retains_typed_registry_failure() -> None:
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
    assert result.failures[0].ssa_failure is FunctionSSAArtifactFailure8616.FUNCTION_NOT_FOUND


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
