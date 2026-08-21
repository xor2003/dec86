"""Join exact interprocedural storage slots across a complete caller census.

Layer: Types/Lowering.
Responsibility: normalize proof-bearing input, return, and memory live-out
trials into deterministic function-level storage slots. Input and scalar-return
shapes must agree at every relevant callsite. Memory live-outs are a union of
exact storage observed across the complete census because different callers
may consume different outputs of the same callee. This module does not collect
trials, infer storage, mutate codegen, or synthesize missing uses.
Consumes alias, widening, and typed facts. Storage-trial facts remain the
authoritative proof payload.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageIdentity8616,
    StorageSlotContract8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
)

__all__ = ["join_storage_slot_contracts_8616", "ordered_storage_trials_8616"]

_SlotJoinResult8616 = tuple[
    tuple[StorageSlotContract8616, ...] | None,
    StorageTrialFailureKind8616 | None,
]
_StoragePiecesKey8616 = tuple[tuple[object, ...], ...]
_StoragePieceOrderKey8616 = tuple[
    str,
    int,
    bool,
    str,
    tuple[str, ...],
    int,
    int,
    bool,
    int,
    str,
]
_StoragePiecesOrderKey8616 = tuple[_StoragePieceOrderKey8616, ...]


def ordered_storage_trials_8616(
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


def _slot_from_pieces_8616(
    role: StorageTrialRole8616,
    pieces: tuple[StorageTrial8616, ...],
) -> tuple[StorageSlotContract8616 | None, StorageTrialFailureKind8616 | None]:
    """Build one slot only when all physical pieces agree on typed meaning."""
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
    return (
        StorageSlotContract8616(
            role=role,
            logical_index=pieces[0].logical_index,
            pieces=tuple(item.storage for item in pieces),
            signedness=pieces[0].signedness,
            value_class=pieces[0].value_class,
        ),
        None,
    )


def _site_slots_8616(
    callsite: CallsiteStorageTrials8616,
    role: StorageTrialRole8616,
) -> _SlotJoinResult8616:
    """Normalize one callsite's complete trial groups into exact slots."""
    trials = ordered_storage_trials_8616(callsite, role)
    if any(trial.role is not role for trial in trials):
        return None, StorageTrialFailureKind8616.INCOMPLETE_TRIAL
    groups = _trial_groups_8616(trials)
    if groups is None:
        return None, StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT
    slots: list[StorageSlotContract8616] = []
    for pieces in groups:
        slot, failure = _slot_from_pieces_8616(role, pieces)
        if slot is None:
            return None, failure
        slots.append(slot)
    return tuple(slots), None


def _pieces_key_8616(slot: StorageSlotContract8616) -> _StoragePiecesKey8616:
    """Return one exact physical-storage key independent of local slot order."""
    return tuple(piece.key for piece in slot.pieces)


def _piece_order_key_8616(piece: StorageIdentity8616) -> _StoragePieceOrderKey8616:
    """Project exact storage to primitive fields with a total ordering."""
    address = piece.address
    if address is None:
        return (
            piece.kind.value,
            piece.width,
            False,
            "",
            (),
            0,
            0,
            False,
            0,
            piece.register or "",
        )
    return (
        piece.kind.value,
        piece.width,
        True,
        address.space.value,
        address.base,
        address.offset,
        address.size,
        address.version is not None,
        address.version if address.version is not None else 0,
        "",
    )


def _pieces_order_key_8616(slot: StorageSlotContract8616) -> _StoragePiecesOrderKey8616:
    """Return a deterministic total-order key for one logical slot."""
    return tuple(_piece_order_key_8616(piece) for piece in slot.pieces)


def _uniform_slot_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
    role: StorageTrialRole8616,
) -> _SlotJoinResult8616:
    """Require one identical input or scalar-return shape across callsites."""
    relevant = callsites
    if role is StorageTrialRole8616.RETURN:
        relevant = tuple(
            callsite
            for callsite in callsites
            if ordered_storage_trials_8616(callsite, role)
        )
    if not relevant:
        return (), None
    site_contracts: list[tuple[StorageSlotContract8616, ...]] = []
    for callsite in relevant:
        slots, failure = _site_slots_8616(callsite, role)
        if slots is None:
            return None, failure
        site_contracts.append(slots)
    reference = site_contracts[0]
    for current in site_contracts[1:]:
        if len(current) != len(reference):
            return None, StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT
        for left, right in zip(reference, current, strict=True):
            if _pieces_key_8616(left) != _pieces_key_8616(right):
                return None, StorageTrialFailureKind8616.STORAGE_CONFLICT
            if left.signedness is not right.signedness:
                return None, StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
            if left.value_class is not right.value_class:
                return None, StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
    return reference, None


def _live_out_slot_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
) -> _SlotJoinResult8616:
    """Union exact live-outs while rejecting conflicts for the same storage."""
    slots_by_storage: dict[_StoragePiecesKey8616, StorageSlotContract8616] = {}
    for callsite in callsites:
        slots, failure = _site_slots_8616(callsite, StorageTrialRole8616.LIVE_OUT)
        if slots is None:
            return None, failure
        seen_at_callsite: set[_StoragePiecesKey8616] = set()
        for slot in slots:
            storage_key = _pieces_key_8616(slot)
            if storage_key in seen_at_callsite:
                return None, StorageTrialFailureKind8616.STORAGE_CONFLICT
            seen_at_callsite.add(storage_key)
            previous = slots_by_storage.get(storage_key)
            if previous is None:
                slots_by_storage[storage_key] = slot
                continue
            if previous.signedness is not slot.signedness:
                return None, StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
            if previous.value_class is not slot.value_class:
                return None, StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
    ordered = tuple(sorted(slots_by_storage.values(), key=_pieces_order_key_8616))
    return (
        tuple(
            StorageSlotContract8616(
                role=slot.role,
                logical_index=index,
                pieces=slot.pieces,
                signedness=slot.signedness,
                value_class=slot.value_class,
            )
            for index, slot in enumerate(ordered)
        ),
        None,
    )


def join_storage_slot_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
    role: StorageTrialRole8616,
) -> _SlotJoinResult8616:
    """Join one role's exact slots over a complete caller census."""
    if role is StorageTrialRole8616.LIVE_OUT:
        return _live_out_slot_contracts_8616(callsites)
    return _uniform_slot_contracts_8616(callsites, role)
