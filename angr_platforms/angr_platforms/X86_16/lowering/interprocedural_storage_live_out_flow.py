"""Prove and materialize one direct segmented-memory live-out use.

Layer: Types/Lowering.
Responsibility: bind one Widening-proven output view to CALL_OUTPUT, prove an
unclobbered caller CFG path, classify ConditionIR, and build one provisional
LIVE_OUT trial.
Function censuses stay outside. Only ConditionIR-attributed access instructions
activate evidence; JCC replay loads and absent direct uses do not become facts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..ir import IRValue
from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.terminal_memory_output_contracts import TerminalMemoryOutputDisposition8616
from ..widening.terminal_memory_output_views import TerminalMemoryOutputViewFact8616
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_live_out_contracts import (
    MemoryLiveOutCandidateResult8616,
    MemoryLiveOutFailureKind8616,
    MemoryLiveOutUseDisposition8616,
    MemoryLiveOutUseFact8616,
)
from .interprocedural_storage_live_out_paths import (
    MemoryLiveOutPathVerdict8616,
    memory_live_out_path_failure_8616,
    prove_memory_live_out_path_8616,
)
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionVerdict8616,
    resolve_storage_call_output_definitions_8616,
)


def _value_matches_8616(value: object, storage: StorageIdentity8616, use: StorageUseEvidence8616) -> bool:
    """Match one canonical condition operand to one exact direct LOAD."""
    address = storage.address
    return bool(
        isinstance(value, IRValue)
        and address is not None
        and value.space is address.space
        and value.offset == address.offset
        and value.size == storage.width
        and value.memory_access_insn == use.instr_addr
    )


def _condition_for_use_8616(
    conditions: tuple[ConditionIR, ...], storage: StorageIdentity8616, use: StorageUseEvidence8616,
) -> tuple[ConditionIR | None, StorageTrialSignedness8616 | None, MemoryLiveOutFailureKind8616 | None]:
    """Select one canonical direct-memory condition and its exact sign class."""
    matching: list[ConditionIR] = []
    for condition in conditions:
        operands = (condition.lhs,) if condition.is_zero_test else (condition.lhs, condition.rhs)
        if condition.width_bits == storage.width * 8 and sum(
            _value_matches_8616(operand, storage, use) for operand in operands
        ) == 1 and condition not in matching:
            matching.append(condition)
    if not matching:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_NOT_FOUND
    if len(matching) != 1:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_CONFLICT
    condition = matching[0]
    signedness = (
        StorageTrialSignedness8616.SIGNED
        if condition.is_signed
        else StorageTrialSignedness8616.UNSIGNED
        if condition.is_unsigned
        else StorageTrialSignedness8616.SIGN_INSENSITIVE
        if condition.op in {"eq", "ne", "zero", "nonzero"}
        else None
    )
    if signedness is None:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_UNSUPPORTED
    return condition, signedness, None


def materialize_memory_live_out_candidate_8616(
    artifact: SSAFunctionArtifact,
    output_view: TerminalMemoryOutputViewFact8616,
    caller_addr: int,
    callee_addr: int,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
    conditions: tuple[ConditionIR, ...],
) -> MemoryLiveOutCandidateResult8616:
    """Materialize one activated direct-memory output candidate or refuse."""
    alias_output = output_view.alias_output
    output = alias_output.terminal_output
    if not output_view.complete:
        raise RuntimeError("Types/Lowering received an incomplete Widening output view")
    storage = StorageIdentity8616(
        StorageIdentityKind8616.MEMORY, output_view.width, output_view.address
    )
    uses = tuple(
        StorageUseEvidence8616(
            access.block_addr,
            access.instr_index,
            access.instr_addr,
            callsite_addr,
        )
        for access in output_view.accesses
    )
    condition_candidates: list[
        tuple[
            StorageUseEvidence8616,
            ConditionIR | None,
            StorageTrialSignedness8616 | None,
            MemoryLiveOutFailureKind8616 | None,
        ]
    ] = []
    for use in uses:
        condition, signedness, failure = _condition_for_use_8616(conditions, storage, use)
        if failure is not MemoryLiveOutFailureKind8616.CONDITION_NOT_FOUND:
            condition_candidates.append((use, condition, signedness, failure))
    if not condition_candidates:
        return MemoryLiveOutCandidateResult8616(False)
    if not storage.is_exact:
        raise RuntimeError("Widening published an inexact direct-memory view")
    definitions = resolve_storage_call_output_definitions_8616(
        artifact,
        caller_addr,
        callsite_addr,
        callee_addr,
        accepted_target_addrs,
        (storage,),
    )
    if not definitions.complete:
        conflict = definitions.verdict is CallOutputDefinitionVerdict8616.CONFLICT
        return MemoryLiveOutCandidateResult8616(
            True,
            failure=(
                MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT
                if conflict
                else MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED
            ),
            definition_failure=definitions.failure,
        )
    paths = tuple(
        (
            candidate,
            prove_memory_live_out_path_8616(
                artifact,
                definitions,
                storage,
                candidate[0],
            ),
        )
        for candidate in condition_candidates
    )
    path_failure = memory_live_out_path_failure_8616(
        tuple(path for _candidate, path in paths)
    )
    if path_failure is not None:
        return MemoryLiveOutCandidateResult8616(True, failure=path_failure)
    clean_candidates = tuple(
        candidate
        for candidate, path in paths
        if path.verdict is MemoryLiveOutPathVerdict8616.CLEAN
    )
    if not clean_candidates:
        fact = MemoryLiveOutUseFact8616(
            storage,
            output_view,
            MemoryLiveOutUseDisposition8616.NOT_REACHED,
        )
        return MemoryLiveOutCandidateResult8616(True, fact=fact)
    typed: list[tuple[StorageUseEvidence8616, ConditionIR, StorageTrialSignedness8616]] = []
    for use, condition, signedness, failure in clean_candidates:
        if failure is not None or condition is None or signedness is None:
            return MemoryLiveOutCandidateResult8616(
                True,
                failure=failure or MemoryLiveOutFailureKind8616.CONDITION_UNSUPPORTED,
            )
        typed.append((use, condition, signedness))
    if len({item[2] for item in typed}) != 1:
        return MemoryLiveOutCandidateResult8616(
            True, failure=MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT
        )
    use, condition, signedness = typed[0]
    fact = MemoryLiveOutUseFact8616(
        storage,
        output_view,
        MemoryLiveOutUseDisposition8616.USED,
        use,
        signedness,
        condition,
    )
    if output.disposition is TerminalMemoryOutputDisposition8616.CONDITIONAL:
        return MemoryLiveOutCandidateResult8616(True, fact=fact)
    provenance = definitions.provenance
    if provenance is None:
        raise RuntimeError("complete CALL_OUTPUT lost provenance")
    trial = StorageTrial8616(
        callee_addr=callee_addr,
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        role=StorageTrialRole8616.LIVE_OUT,
        logical_index=0,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=definitions.definitions[0],
        use=use,
        signedness=signedness,
        value_class=StorageTrialValueClass8616.VALUE,
        provenance=provenance,
    )
    return MemoryLiveOutCandidateResult8616(True, fact=fact, trial=trial)
