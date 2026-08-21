"""Collect function-wide direct segmented-memory live-out trials.

Layer: Types/Lowering.
Responsibility: join callee terminal-memory facts with every caller SSA census,
delegate candidate proof/materialization, and close function-wide evidence stats.
This module does not traverse CFGs, infer aliases, project C, or publish contracts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace

from ..ir.condition_ir import ConditionIR
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.terminal_memory_outputs import collect_terminal_memory_output_evidence_8616
from .condition_transfer import collect_typed_condition_artifacts_8616
from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageTrial8616,
    StorageTrialStats8616,
)
from .interprocedural_storage_live_out_contracts import (
    CallsiteMemoryLiveOutEvidence8616,
    FunctionMemoryLiveOutCollection8616,
    MemoryLiveOutCollectionVerdict8616,
    MemoryLiveOutFailure8616,
    MemoryLiveOutFailureKind8616,
    MemoryLiveOutUseFact8616,
)
from .interprocedural_storage_live_out_flow import materialize_memory_live_out_candidate_8616


def _failed_8616(
    failure: MemoryLiveOutFailure8616,
    raw: int,
    normalized: int,
) -> FunctionMemoryLiveOutCollection8616:
    """Build one atomic refusal without publishing partial live-out trials."""
    conflict = failure.kind in {
        MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT,
        MemoryLiveOutFailureKind8616.CONDITION_CONFLICT,
        MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT,
        MemoryLiveOutFailureKind8616.USE_OVERLAP,
    }
    verdict = (
        MemoryLiveOutCollectionVerdict8616.CONFLICT
        if conflict
        else MemoryLiveOutCollectionVerdict8616.UNKNOWN_REFUSE
    )
    return FunctionMemoryLiveOutCollection8616(
        verdict,
        (),
        (failure,),
        StorageTrialStats8616(
            raw_fact_count=raw,
            normalized_fact_count=normalized,
            failure_count=max(1, raw - normalized),
        ),
    )


def collect_function_memory_live_out_trials_8616(
    project: object,
    callee_addr: int,
    callsites: tuple[CallsiteStorageTrials8616, ...],
    accepted_target_addrs: tuple[int, ...],
) -> FunctionMemoryLiveOutCollection8616:
    """Collect bounded exact direct-memory LIVE_OUT trials for one callee."""
    callee_ssa = semantic_function_ssa_artifact_at_address_8616(project, callee_addr)
    if callee_ssa.artifact is None:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.CALLEE_SSA_UNAVAILABLE,
                callee_addr,
                ssa_failure=callee_ssa.failure,
            ),
            1,
            0,
        )
    terminal = collect_terminal_memory_output_evidence_8616(project, callee_ssa.artifact)
    if not terminal.complete:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.TERMINAL_EVIDENCE_REFUSED,
                callee_addr,
                terminal_failure=terminal.failure,
            ),
            max(1, terminal.stats.raw_fact_count),
            terminal.stats.normalized_fact_count,
        )
    if not terminal.facts:
        empty = tuple(
            CallsiteMemoryLiveOutEvidence8616(site.caller_addr, callee_addr, site.callsite_addr)
            for site in callsites
        )
        return FunctionMemoryLiveOutCollection8616(
            MemoryLiveOutCollectionVerdict8616.PROVEN,
            empty,
            (),
            StorageTrialStats8616(),
        )

    targets = tuple(dict.fromkeys((callee_addr, *accepted_target_addrs)))
    conditions_by_caller: dict[int, tuple[ConditionIR, ...]] = {}
    collected_sites: list[CallsiteMemoryLiveOutEvidence8616] = []
    raw = normalized = materialized = 0
    for site in sorted(callsites, key=lambda item: (item.callsite_addr, item.caller_addr)):
        caller_ssa = semantic_function_ssa_artifact_at_address_8616(
            project,
            site.caller_addr,
        )
        artifact = caller_ssa.artifact
        if artifact is None:
            return _failed_8616(
                MemoryLiveOutFailure8616(
                    MemoryLiveOutFailureKind8616.CALLER_SSA_UNAVAILABLE,
                    callee_addr,
                    site.caller_addr,
                    site.callsite_addr,
                    ssa_failure=caller_ssa.failure,
                ),
                max(1, raw),
                normalized,
            )
        conditions = conditions_by_caller.get(site.caller_addr)
        if conditions is None:
            condition_items, _edge_evidence = collect_typed_condition_artifacts_8616(
                project, site.caller_addr
            )
            conditions = tuple(condition_items)
            conditions_by_caller[site.caller_addr] = conditions
        facts: list[MemoryLiveOutUseFact8616] = []
        trials: list[StorageTrial8616] = []
        for output in sorted(
            terminal.facts,
            key=lambda fact: (fact.key[0].value, fact.key[1], fact.key[2]),
        ):
            candidate = materialize_memory_live_out_candidate_8616(
                artifact,
                output,
                site.caller_addr,
                callee_addr,
                site.callsite_addr,
                targets,
                conditions,
            )
            if not candidate.activated:
                continue
            raw += 1
            normalized += 1
            if candidate.failure is not None:
                return _failed_8616(
                    MemoryLiveOutFailure8616(
                        candidate.failure,
                        callee_addr,
                        site.caller_addr,
                        site.callsite_addr,
                        output.key,
                        definition_failure=candidate.definition_failure,
                    ),
                    raw,
                    normalized,
                )
            if not candidate.complete or candidate.fact is None:
                raise RuntimeError("complete memory live-out candidate lost its typed outcome")
            facts.append(candidate.fact)
            if candidate.trial is not None:
                trials.append(replace(candidate.trial, logical_index=len(trials)))
            materialized += 1
        collected_sites.append(
            CallsiteMemoryLiveOutEvidence8616(
                site.caller_addr,
                callee_addr,
                site.callsite_addr,
                tuple(facts),
                tuple(trials),
            )
        )
    stats = StorageTrialStats8616(raw, normalized, materialized, materialized)
    return FunctionMemoryLiveOutCollection8616(
        MemoryLiveOutCollectionVerdict8616.PROVEN,
        tuple(collected_sites),
        (),
        stats,
    )


__all__ = ["collect_function_memory_live_out_trials_8616"]
