from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir import AddressStatus, IRAddress, IRValue, MemSpace
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
    StorageTrialVerdict8616,
    StorageUseEvidence8616,
    ValueProvenance8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_transaction import (
    accepted_callsite_storage_binding_8616,
    accepted_function_storage_contract_8616,
    apply_program_storage_resolution_8616,
)

CALLEE = 0x2000


def _memory(
    offset: int,
    width: int = 1,
    *,
    space: MemSpace = MemSpace.DS,
) -> StorageIdentity8616:
    return StorageIdentity8616(
        StorageIdentityKind8616.MEMORY,
        width,
        IRAddress(
            space,
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
        ),
    )


def _live_out(
    caller: int,
    callsite: int,
    offset: int,
    *,
    logical_index: int = 0,
    role: StorageTrialRole8616 = StorageTrialRole8616.LIVE_OUT,
    signedness: StorageTrialSignedness8616 = StorageTrialSignedness8616.SIGNED,
    value_class: StorageTrialValueClass8616 = StorageTrialValueClass8616.VALUE,
    space: MemSpace = MemSpace.DS,
) -> StorageTrial8616:
    storage = _memory(offset, space=space)
    return StorageTrial8616(
        callee_addr=CALLEE,
        caller_addr=caller,
        callsite_addr=callsite,
        role=role,
        logical_index=logical_index,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=StorageReachingDefinition8616(
            value=IRValue(space, offset=offset, size=1),
            block_addr=caller,
            instr_index=0,
            instr_addr=callsite,
            source_storage=storage,
            definition_kind=StorageDefinitionKind8616.CALL_OUTPUT,
        ),
        use=StorageUseEvidence8616(caller, 1, callsite + 3, callsite),
        signedness=signedness,
        value_class=value_class,
        provenance=ValueProvenance8616(CALLEE, callsite, offset),
    )


def _callsite(
    caller: int,
    callsite: int,
    *live_outs: StorageTrial8616,
) -> CallsiteStorageTrials8616:
    return CallsiteStorageTrials8616(
        caller_addr=caller,
        callee_addr=CALLEE,
        callsite_addr=callsite,
        live_outs=live_outs,
        stack_delta=0,
    )


def _function(
    *callsites: CallsiteStorageTrials8616,
    complete: bool = True,
    expected: tuple[int, ...] | None = None,
) -> FunctionStorageTrials8616:
    return FunctionStorageTrials8616(
        function_addr=CALLEE,
        caller_census_complete=complete,
        expected_callsite_addrs=(
            expected
            if expected is not None
            else tuple(sorted(callsite.callsite_addr for callsite in callsites))
        ),
        callsites=callsites,
    )


def test_disjoint_caller_live_out_subsets_form_one_function_contract() -> None:
    first = _callsite(0x3000, 0x3010, _live_out(0x3000, 0x3010, 0x1200))
    second = _callsite(
        0x4000,
        0x4010,
        _live_out(
            0x4000,
            0x4010,
            0x1300,
            signedness=StorageTrialSignedness8616.UNSIGNED,
        ),
    )

    resolution = resolve_program_storage_trials_8616((_function(second, first),))
    contract = resolution.contract_for(CALLEE)

    assert resolution.stats.complete is True
    assert contract is not None
    assert tuple(slot.logical_index for slot in contract.outputs) == (0, 1)
    assert tuple(slot.pieces[0].address.offset for slot in contract.outputs) == (
        0x1200,
        0x1300,
    )
    assert tuple(binding.callsite_addr for binding in contract.callsites) == (0x3010, 0x4010)
    assert tuple(
        trial.storage.address.offset
        for binding in contract.callsites
        for trial in binding.live_outs
    ) == (0x1200, 0x1300)

    project = SimpleNamespace()
    assert apply_program_storage_resolution_8616(project, resolution) is True
    assert accepted_function_storage_contract_8616(project, CALLEE) == contract
    assert accepted_callsite_storage_binding_8616(project, CALLEE, 0x3010) == contract.callsites[0]


def test_multiple_live_outs_at_one_callsite_keep_exact_storage_order() -> None:
    callsite = _callsite(
        0x3000,
        0x3010,
        _live_out(0x3000, 0x3010, 0x1300, logical_index=0),
        _live_out(0x3000, 0x3010, 0x1200, logical_index=1),
    )

    contract = resolve_program_storage_trials_8616((_function(callsite),)).contract_for(CALLEE)

    assert contract is not None
    assert tuple(slot.pieces[0].address.offset for slot in contract.outputs) == (
        0x1200,
        0x1300,
    )
    assert tuple(slot.logical_index for slot in contract.outputs) == (0, 1)
    assert tuple(trial.logical_index for trial in contract.callsites[0].live_outs) == (0, 1)


def test_ds_and_es_live_outs_have_total_deterministic_storage_order() -> None:
    callsite = _callsite(
        0x3000,
        0x3010,
        _live_out(0x3000, 0x3010, 0x1200, logical_index=0, space=MemSpace.ES),
        _live_out(0x3000, 0x3010, 0x1200, logical_index=1, space=MemSpace.DS),
    )

    contract = resolve_program_storage_trials_8616((_function(callsite),)).contract_for(CALLEE)

    assert contract is not None
    assert tuple(slot.pieces[0].address.space for slot in contract.outputs) == (
        MemSpace.DS,
        MemSpace.ES,
    )


def test_same_live_out_storage_with_conflicting_type_evidence_refuses() -> None:
    first = _callsite(0x3000, 0x3010, _live_out(0x3000, 0x3010, 0x1200))
    second = _callsite(
        0x4000,
        0x4010,
        _live_out(
            0x4000,
            0x4010,
            0x1200,
            signedness=StorageTrialSignedness8616.UNSIGNED,
        ),
    )

    result = resolve_program_storage_trials_8616((_function(first, second),)).resolutions[0]

    assert result.verdict is StorageTrialVerdict8616.CONFLICT
    assert result.contract is None
    assert result.failures == (StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT,)


def test_duplicate_live_out_storage_at_one_callsite_refuses() -> None:
    callsite = _callsite(
        0x3000,
        0x3010,
        _live_out(0x3000, 0x3010, 0x1200, logical_index=0),
        _live_out(0x3000, 0x3010, 0x1200, logical_index=1),
    )

    result = resolve_program_storage_trials_8616((_function(callsite),)).resolutions[0]

    assert result.verdict is StorageTrialVerdict8616.CONFLICT
    assert result.failures == (StorageTrialFailureKind8616.STORAGE_CONFLICT,)


def test_trial_with_wrong_role_cannot_enter_live_out_contract() -> None:
    wrong_role = _live_out(
        0x3000,
        0x3010,
        0x1200,
        role=StorageTrialRole8616.RETURN,
    )
    callsite = _callsite(0x3000, 0x3010, wrong_role)

    result = resolve_program_storage_trials_8616((_function(callsite),)).resolutions[0]

    assert result.verdict is StorageTrialVerdict8616.UNKNOWN_REFUSE
    assert result.failures == (StorageTrialFailureKind8616.INCOMPLETE_TRIAL,)


def test_incomplete_census_cannot_publish_partial_live_out_union() -> None:
    callsite = _callsite(0x3000, 0x3010, _live_out(0x3000, 0x3010, 0x1200))
    trials = _function(
        callsite,
        complete=False,
        expected=(0x3010, 0x4010),
    )

    result = resolve_program_storage_trials_8616((trials,)).resolutions[0]

    assert result.verdict is StorageTrialVerdict8616.CONFLICT
    assert result.contract is None
    assert result.failures == (
        StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT,
        StorageTrialFailureKind8616.INCOMPLETE_CALLER_CENSUS,
    )
