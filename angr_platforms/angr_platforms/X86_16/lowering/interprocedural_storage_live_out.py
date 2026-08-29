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

from ..alias.terminal_memory_outputs import classify_terminal_memory_output_aliases_8616
from ..ir.condition_ir import ConditionIR
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.terminal_memory_outputs import collect_terminal_memory_output_evidence_8616
from ..widening.terminal_memory_output_views import collect_terminal_memory_output_views_8616
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
from .pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTarget8616,
    PointerParameterCallerTargetEvidence8616,
)


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
        MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
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


def attach_callsite_memory_live_out_evidence_8616(
    callsite: CallsiteStorageTrials8616,
    evidence: tuple[CallsiteMemoryLiveOutEvidence8616, ...],
) -> CallsiteStorageTrials8616:
    """Attach the unique exact live-out projection to one callsite contract."""
    matches = tuple(item for item in evidence if item.callsite_addr == callsite.callsite_addr)
    if len(matches) != 1:
        raise RuntimeError("complete memory live-out collection lost exact callsite evidence")
    match = matches[0]
    if match.caller_addr != callsite.caller_addr or match.callee_addr != callsite.callee_addr:
        raise RuntimeError("memory live-out callsite identity changed during projection")
    return replace(
        callsite,
        live_outs=match.trials,
        memory_effects=match.facts,
        pointer_effects=match.pointer_effects,
    )


def _pointer_effects_by_callsite_8616(
    callee_addr: int,
    callsites: tuple[CallsiteStorageTrials8616, ...],
    evidence: PointerParameterCallerTargetEvidence8616 | None,
) -> tuple[
    dict[int, tuple[PointerParameterCallerTarget8616, ...]] | None,
    MemoryLiveOutFailure8616 | None,
]:
    """Validate and partition exact dynamic effects by known callsite."""
    expected = {item.callsite_addr: item for item in callsites}
    if len(expected) != len(callsites):
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
            callee_addr,
        )
    empty: dict[int, tuple[PointerParameterCallerTarget8616, ...]] = dict.fromkeys(expected, ())
    if evidence is None:
        return empty, None
    if not evidence.complete:
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_REFUSED,
            callee_addr,
            pointer_failure=evidence.failure,
        )
    if evidence.callee_addr != callee_addr:
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
            callee_addr,
        )
    grouped: dict[int, list[PointerParameterCallerTarget8616]] = {
        callsite_addr: [] for callsite_addr in expected
    }
    for effect in evidence.facts:
        callsite = expected.get(effect.callsite_addr)
        if (
            callsite is None
            or not effect.complete
            or effect.callee_addr != callee_addr
            or effect.caller_addr != callsite.caller_addr
        ):
            return None, MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
                callee_addr,
                effect.caller_addr,
                effect.callsite_addr,
            )
        if any(item.logical_index == effect.logical_index for item in grouped[effect.callsite_addr]):
            return None, MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
                callee_addr,
                effect.caller_addr,
                effect.callsite_addr,
            )
        grouped[effect.callsite_addr].append(effect)
    if evidence.facts and any(not grouped[callsite_addr] for callsite_addr in expected):
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
            callee_addr,
        )
    return {
        callsite_addr: tuple(sorted(items, key=lambda item: item.logical_index))
        for callsite_addr, items in grouped.items()
    }, None


def collect_function_memory_live_out_trials_8616(
    project: object,
    callee_addr: int,
    callsites: tuple[CallsiteStorageTrials8616, ...],
    accepted_target_addrs: tuple[int, ...],
    *,
    pointer_targets: PointerParameterCallerTargetEvidence8616 | None = None,
) -> FunctionMemoryLiveOutCollection8616:
    """Collect exact direct and dynamic memory effects for one callee."""
    pointer_by_callsite, pointer_failure = _pointer_effects_by_callsite_8616(
        callee_addr,
        callsites,
        pointer_targets,
    )
    pointer_count = 0 if pointer_targets is None else len(pointer_targets.facts)
    if pointer_failure is not None or pointer_by_callsite is None:
        return _failed_8616(
            pointer_failure
            or MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.POINTER_TARGET_REFUSED,
                callee_addr,
            ),
            max(1, pointer_count),
            0,
        )
    callee_ssa = semantic_function_ssa_artifact_at_address_8616(project, callee_addr)
    if callee_ssa.artifact is None:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.CALLEE_SSA_UNAVAILABLE,
                callee_addr,
                ssa_failure=callee_ssa.failure,
            ),
            max(1, pointer_count),
            pointer_count,
        )
    terminal = collect_terminal_memory_output_evidence_8616(project, callee_ssa.artifact)
    if not terminal.complete:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.TERMINAL_EVIDENCE_REFUSED,
                callee_addr,
                terminal_failure=terminal.failure,
            ),
            max(1, pointer_count + terminal.stats.raw_fact_count),
            pointer_count + terminal.stats.normalized_fact_count,
        )
    aliases = classify_terminal_memory_output_aliases_8616(terminal)
    if not aliases.complete:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.ALIAS_EVIDENCE_REFUSED,
                callee_addr,
                alias_failure=aliases.failure,
            ),
            max(1, pointer_count + aliases.stats.raw_fact_count),
            pointer_count + aliases.stats.normalized_fact_count,
        )
    if not aliases.facts:
        empty = tuple(
            CallsiteMemoryLiveOutEvidence8616(
                site.caller_addr,
                callee_addr,
                site.callsite_addr,
                pointer_effects=pointer_by_callsite[site.callsite_addr],
            )
            for site in callsites
        )
        return FunctionMemoryLiveOutCollection8616(
            MemoryLiveOutCollectionVerdict8616.PROVEN,
            empty,
            (),
            StorageTrialStats8616(
                pointer_count,
                pointer_count,
                pointer_count,
                pointer_count,
            ),
        )

    targets = tuple(dict.fromkeys((callee_addr, *accepted_target_addrs)))
    conditions_by_caller: dict[int, tuple[ConditionIR, ...]] = {}
    collected_sites: list[CallsiteMemoryLiveOutEvidence8616] = []
    raw = normalized = materialized = pointer_count
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
        for alias_output in aliases.canonical_facts:
            output = alias_output.terminal_output
            views = collect_terminal_memory_output_views_8616(alias_output, artifact)
            if not views.complete:
                return _failed_8616(
                    MemoryLiveOutFailure8616(
                        MemoryLiveOutFailureKind8616.WIDENING_EVIDENCE_REFUSED,
                        callee_addr,
                        site.caller_addr,
                        site.callsite_addr,
                        output.key,
                        view_failure=views.failure,
                    ),
                    max(1, raw + views.stats.raw_fact_count),
                    normalized + views.stats.normalized_fact_count,
                )
            for output_view in views.facts:
                candidate = materialize_memory_live_out_candidate_8616(
                    artifact,
                    output_view,
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
                    raise RuntimeError(
                        "complete memory live-out candidate lost its typed outcome"
                    )
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
                pointer_by_callsite[site.callsite_addr],
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
