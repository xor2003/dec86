"""Join and resolve one function's interprocedural storage trials.

Layer: Types/Lowering.
Responsibility: validate one complete caller census, derive exact direct input
and output slots, and finalize a function contract only after the SCC owner has
resolved every deferred recursive return pass-through. This module does not
infer signatures, mutate codegen, or synthesize missing SSA uses.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..pipeline.errors import PipelineHardError
from .interprocedural_storage_contracts import (
    CallsiteStorageBinding8616,
    CallsiteStorageTrials8616,
    FunctionStorageContract8616,
    FunctionStorageResolution8616,
    FunctionStorageTrials8616,
    StorageSlotContract8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialStats8616,
    StorageTrialVerdict8616,
)
from .interprocedural_storage_return_passthrough_contracts import ReturnPassThroughTrial8616

__all__ = [
    "FunctionStorageTrialJoin8616", "join_function_storage_trials_8616",
    "resolve_joined_function_storage_trials_8616",
]


@dataclass(frozen=True, slots=True)
class FunctionStorageTrialJoin8616:
    """Validated direct slots and deferred facts for one function census."""

    trials: FunctionStorageTrials8616
    all_trials: tuple[StorageTrial8616, ...]
    passthroughs: tuple[ReturnPassThroughTrial8616, ...]
    inputs: tuple[StorageSlotContract8616, ...] | None
    direct_outputs: tuple[StorageSlotContract8616, ...] | None
    live_outs: tuple[StorageSlotContract8616, ...] | None
    stack_delta: int | None
    failures: tuple[StorageTrialFailureKind8616, ...]
    raw_count: int
    normalized_count: int

    @property
    def function_addr(self) -> int:
        """Return the exact function address owning this joined census."""
        return self.trials.function_addr

    @property
    def direct_output_seed(self) -> tuple[StorageSlotContract8616, ...] | None:
        """Return a non-empty output seed only from an otherwise valid join."""
        if self.failures or not self.direct_outputs:
            return None
        return self.direct_outputs


def _ordered_trials_8616(
    callsite: CallsiteStorageTrials8616,
    role: StorageTrialRole8616,
) -> tuple[StorageTrial8616, ...]:
    """Return one role's trials in deterministic logical-piece order."""
    trials = callsite.arguments
    if role is StorageTrialRole8616.LIVE_OUT:
        trials = callsite.live_outs
    elif role is StorageTrialRole8616.RETURN:
        trials = callsite.returns
    return tuple(sorted(trials, key=lambda item: (item.logical_index, item.piece_index)))


def _trial_groups_8616(
    trials: tuple[StorageTrial8616, ...],
) -> tuple[tuple[StorageTrial8616, ...], ...] | None:
    """Group contiguous logical slots and reject missing or duplicate pieces."""
    if not trials:
        return ()
    grouped: dict[int, list[StorageTrial8616]] = {}
    for trial in trials:
        grouped.setdefault(trial.logical_index, []).append(trial)
    if tuple(sorted(grouped)) != tuple(range(len(grouped))):
        return None
    result: list[tuple[StorageTrial8616, ...]] = []
    for logical_index in sorted(grouped):
        pieces = tuple(sorted(grouped[logical_index], key=lambda item: item.piece_index))
        if (
            not pieces
            or any(item.piece_count != len(pieces) for item in pieces)
            or tuple(item.piece_index for item in pieces) != tuple(range(len(pieces)))
        ):
            return None
        result.append(pieces)
    return tuple(result)


def _slot_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
    role: StorageTrialRole8616,
) -> tuple[tuple[StorageSlotContract8616, ...] | None, StorageTrialFailureKind8616 | None]:
    """Join exact slot shape, signedness, and value class across callsites."""
    relevant = callsites
    if not relevant:
        return (), None
    if role is not StorageTrialRole8616.INPUT:
        relevant = tuple(callsite for callsite in callsites if _ordered_trials_8616(callsite, role))
        if not relevant:
            return (), None
    site_contracts: list[tuple[StorageSlotContract8616, ...]] = []
    for callsite in relevant:
        groups = _trial_groups_8616(_ordered_trials_8616(callsite, role))
        if groups is None:
            return None, StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT
        slots: list[StorageSlotContract8616] = []
        for pieces in groups:
            if role is not StorageTrialRole8616.INPUT and len(pieces) > 1:
                provenances = {item.provenance for item in pieces}
                if len(provenances) != 1 or None in provenances:
                    return None, StorageTrialFailureKind8616.SPLIT_PROVENANCE_CONFLICT
            signedness = {item.signedness for item in pieces}
            if len(signedness) != 1:
                return None, StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
            value_classes = {item.value_class for item in pieces}
            if len(value_classes) != 1:
                return None, StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
            slots.append(
                StorageSlotContract8616(
                    role=role,
                    logical_index=pieces[0].logical_index,
                    pieces=tuple(item.storage for item in pieces),
                    signedness=pieces[0].signedness,
                    value_class=pieces[0].value_class,
                )
            )
        site_contracts.append(tuple(slots))
    reference = site_contracts[0]
    for current in site_contracts[1:]:
        if len(current) != len(reference):
            return None, StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT
        for left, right in zip(reference, current, strict=True):
            if tuple(piece.key for piece in left.pieces) != tuple(
                piece.key for piece in right.pieces
            ):
                return None, StorageTrialFailureKind8616.STORAGE_CONFLICT
            if left.signedness is not right.signedness:
                return None, StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
            if left.value_class is not right.value_class:
                return None, StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
    return reference, None


def _trial_matches_callsite_8616(
    trial: StorageTrial8616,
    callsite: CallsiteStorageTrials8616,
) -> bool:
    """Return whether one complete trial belongs to its containing callsite."""
    return bool(
        trial.is_complete
        and trial.callee_addr == callsite.callee_addr
        and trial.caller_addr == callsite.caller_addr
        and trial.callsite_addr == callsite.callsite_addr
    )


def _ordered_failures_8616(
    failures: Iterable[StorageTrialFailureKind8616],
) -> tuple[StorageTrialFailureKind8616, ...]:
    """Return unique failure kinds in stable contract order."""
    return tuple(sorted(set(failures), key=lambda item: item.value))


def join_function_storage_trials_8616(
    trials: FunctionStorageTrials8616,
) -> FunctionStorageTrialJoin8616:
    """Validate one caller census and derive only directly proven slot shapes."""
    all_trials = tuple(
        trial
        for callsite in trials.callsites
        for trial in (*callsite.arguments, *callsite.returns, *callsite.live_outs)
    )
    passthroughs = tuple(
        trial for callsite in trials.callsites for trial in callsite.return_passthroughs
    )
    raw_count = len(all_trials) + len(passthroughs)
    normalized_count = sum(item.is_complete for item in all_trials) + sum(
        item.is_complete for item in passthroughs
    )
    failures: list[StorageTrialFailureKind8616] = []
    expected = tuple(sorted(set(trials.expected_callsite_addrs)))
    observed = tuple(sorted(callsite.callsite_addr for callsite in trials.callsites))
    if not trials.caller_census_complete:
        failures.append(StorageTrialFailureKind8616.INCOMPLETE_CALLER_CENSUS)
    if len(expected) != len(trials.expected_callsite_addrs) or observed != expected:
        failures.append(StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT)
    if any(
        not _trial_matches_callsite_8616(trial, callsite)
        for callsite in trials.callsites
        for trial in (*callsite.arguments, *callsite.returns, *callsite.live_outs)
    ):
        failures.append(StorageTrialFailureKind8616.INCOMPLETE_TRIAL)
    if any(
        not trial.belongs_to(callsite.callee_addr, callsite.caller_addr, callsite.callsite_addr)
        for callsite in trials.callsites
        for trial in callsite.return_passthroughs
    ):
        failures.append(StorageTrialFailureKind8616.INCOMPLETE_TRIAL)
    if any(
        len(callsite.return_passthroughs) > 1
        or bool(callsite.return_passthroughs and callsite.returns)
        for callsite in trials.callsites
    ):
        failures.append(StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT)
    stack_deltas = {callsite.stack_delta for callsite in trials.callsites}
    if not trials.callsites or None in stack_deltas or len(stack_deltas) != 1:
        failures.append(StorageTrialFailureKind8616.STACK_DELTA_CONFLICT)
    inputs, input_failure = _slot_contracts_8616(
        trials.callsites,
        StorageTrialRole8616.INPUT,
    )
    direct_outputs, output_failure = _slot_contracts_8616(
        trials.callsites,
        StorageTrialRole8616.RETURN,
    )
    live_outs, live_out_failure = _slot_contracts_8616(
        trials.callsites,
        StorageTrialRole8616.LIVE_OUT,
    )
    failures.extend(item for item in (input_failure, output_failure, live_out_failure) if item is not None)
    stack_delta = next(iter(stack_deltas)) if len(stack_deltas) == 1 else None
    if not isinstance(stack_delta, int):
        stack_delta = None
    return FunctionStorageTrialJoin8616(
        trials=trials,
        all_trials=all_trials,
        passthroughs=passthroughs,
        inputs=inputs,
        direct_outputs=direct_outputs,
        live_outs=live_outs,
        stack_delta=stack_delta,
        failures=_ordered_failures_8616(failures),
        raw_count=raw_count,
        normalized_count=normalized_count,
    )


def _refused_resolution_8616(
    joined: FunctionStorageTrialJoin8616,
    failures: Iterable[StorageTrialFailureKind8616],
) -> FunctionStorageResolution8616:
    """Build one deterministic refusal without classifying guessed facts."""
    ordered_failures = _ordered_failures_8616(failures)
    conflict_kinds = {
        StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT,
        StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT,
        StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT,
        StorageTrialFailureKind8616.SPLIT_PROVENANCE_CONFLICT,
        StorageTrialFailureKind8616.STACK_DELTA_CONFLICT,
        StorageTrialFailureKind8616.STORAGE_CONFLICT,
        StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT,
    }
    verdict = (
        StorageTrialVerdict8616.CONFLICT
        if any(item in conflict_kinds for item in ordered_failures)
        else StorageTrialVerdict8616.UNKNOWN_REFUSE
    )
    return FunctionStorageResolution8616(
        function_addr=joined.function_addr,
        verdict=verdict,
        contract=None,
        failures=ordered_failures,
        stats=StorageTrialStats8616(
            raw_fact_count=joined.raw_count,
            normalized_fact_count=joined.normalized_count,
            failure_count=max(
                1,
                joined.raw_count - joined.normalized_count,
                len(ordered_failures),
            ),
        ),
    )


def resolve_joined_function_storage_trials_8616(
    joined: FunctionStorageTrialJoin8616,
    passthrough_outputs: tuple[StorageSlotContract8616, ...] | None,
) -> FunctionStorageResolution8616:
    """Finalize one join after the SCC fixed point resolves pass-throughs."""
    failures = list(joined.failures)
    outputs = joined.direct_outputs
    if joined.passthroughs and not failures:
        if not passthrough_outputs:
            failures.append(StorageTrialFailureKind8616.PASSTHROUGH_OUTPUT_UNRESOLVED)
        elif outputs and outputs != passthrough_outputs:
            failures.append(StorageTrialFailureKind8616.STORAGE_CONFLICT)
        else:
            outputs = passthrough_outputs
    if outputs is not None and joined.live_outs is not None:
        outputs = (*outputs, *joined.live_outs)
    if (
        failures
        or joined.inputs is None
        or outputs is None
        or joined.stack_delta is None
    ):
        return _refused_resolution_8616(joined, failures)
    bindings = tuple(
        CallsiteStorageBinding8616(
            caller_addr=callsite.caller_addr,
            callsite_addr=callsite.callsite_addr,
            arguments=_ordered_trials_8616(callsite, StorageTrialRole8616.INPUT),
            returns=_ordered_trials_8616(callsite, StorageTrialRole8616.RETURN),
            stack_delta=joined.stack_delta,
            live_outs=_ordered_trials_8616(callsite, StorageTrialRole8616.LIVE_OUT),
            return_passthroughs=callsite.return_passthroughs,
        )
        for callsite in sorted(joined.trials.callsites, key=lambda item: item.callsite_addr)
    )
    contract = FunctionStorageContract8616(
        function_addr=joined.function_addr,
        inputs=joined.inputs,
        outputs=outputs,
        stack_delta=joined.stack_delta,
        callsites=bindings,
    )
    stats = StorageTrialStats8616(
        raw_fact_count=joined.raw_count,
        normalized_fact_count=joined.raw_count,
        classified_fact_count=joined.raw_count,
        materialized_count=joined.raw_count,
    )
    if not stats.complete:
        raise PipelineHardError(
            "accepted storage trials did not close their evidence counters",
            layer="types/lowering",
            function_addr=joined.function_addr,
        )
    return FunctionStorageResolution8616(
        function_addr=joined.function_addr,
        verdict=StorageTrialVerdict8616.ACCEPTED,
        contract=contract,
        failures=(),
        stats=stats,
    )
