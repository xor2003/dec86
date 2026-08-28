"""Tests for typed guarded postprocess transaction policy."""

from __future__ import annotations

from angr_platforms.X86_16.postprocess.pass_transaction import (
    PostprocessMutationGeneration8616,
    PostprocessPassPreflightAction8616,
    PostprocessPassPreflightInput8616,
    PostprocessPassTransactionState8616,
    decide_postprocess_pass_preflight_8616,
)


def _request(
    pass_name: str,
    *,
    validation_enabled: bool = True,
    per_pass_validation_enabled: bool = False,
    large_function_skip: bool = False,
    force_per_pass_requested: bool = False,
    optional_reject_budget: int = 0,
    optional_reject_count: int = 0,
    local_evidence_present: bool | None = None,
) -> PostprocessPassPreflightInput8616:
    return PostprocessPassPreflightInput8616(
        pass_name=pass_name,
        validation_enabled=validation_enabled,
        per_pass_validation_enabled=per_pass_validation_enabled,
        large_function_skip=large_function_skip,
        force_per_pass_requested=force_per_pass_requested,
        optional_reject_budget=optional_reject_budget,
        optional_reject_count=optional_reject_count,
        local_evidence_present=local_evidence_present,
    )


def test_ordinary_pass_executes_without_snapshot_or_validation() -> None:
    decision = decide_postprocess_pass_preflight_8616(_request("ordinary_cleanup"))

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.requires_snapshot is False
    assert decision.enforce_pass_validation is False


def test_mandatory_pass_enforces_validation_on_bounded_function() -> None:
    decision = decide_postprocess_pass_preflight_8616(
        _request("_apply_annotations_8616", local_evidence_present=True)
    )

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.force_pass_validation is True
    assert decision.requires_snapshot is True
    assert decision.enforce_pass_validation is True


def test_force_request_enforces_mandatory_validation_on_large_function() -> None:
    decision = decide_postprocess_pass_preflight_8616(
        _request(
            "_apply_annotations_8616",
            large_function_skip=True,
            force_per_pass_requested=True,
        )
    )

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.force_pass_validation is True
    assert decision.requires_snapshot is True
    assert decision.enforce_pass_validation is True


def test_large_function_local_proof_is_probed_then_refused() -> None:
    request = _request(
        "_apply_word_global_types_8616",
        large_function_skip=True,
    )

    probe = decide_postprocess_pass_preflight_8616(request)
    refused = decide_postprocess_pass_preflight_8616(
        request.with_local_evidence(False)
    )
    allowed = decide_postprocess_pass_preflight_8616(
        request.with_local_evidence(True)
    )

    assert probe.action is PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE
    assert refused.action is PostprocessPassPreflightAction8616.REFUSE_LOCAL_PROOF
    assert allowed.action is PostprocessPassPreflightAction8616.EXECUTE


def test_optional_reject_budget_is_probed_then_skipped() -> None:
    request = _request(
        "_apply_annotations_8616",
        optional_reject_budget=2,
        optional_reject_count=2,
    )

    probe = decide_postprocess_pass_preflight_8616(request)
    skipped = decide_postprocess_pass_preflight_8616(
        request.with_local_evidence(False)
    )

    assert probe.action is PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE
    assert skipped.action is PostprocessPassPreflightAction8616.SKIP_REJECT_BUDGET


def test_optimization_pass_always_keeps_snapshot_and_validation() -> None:
    decision = decide_postprocess_pass_preflight_8616(
        _request("optimization:adjacent_temporary_copy_prune", large_function_skip=True)
    )

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.is_optimization_pass is True
    assert decision.requires_snapshot is True
    assert decision.enforce_pass_validation is True


def test_transaction_state_owns_baseline_cycle_and_accepted_change() -> None:
    state = PostprocessPassTransactionState8616(
        baseline_summary="before",
        known_cycle_path=None,
    )

    state.replace_baseline("after")
    state.record_cycle_path(("root", "child"))
    state.accept_change("cleanup")

    assert state.baseline_summary == "after"
    assert state.known_cycle_path == ("root", "child")
    assert state.accepted_changed is True
    assert state.last_changed_pass == "cleanup"
    assert state.mutation_generation() == PostprocessMutationGeneration8616(
        value=1,
        last_changed_pass="cleanup",
    )



def test_rejected_or_restored_state_does_not_advance_generation() -> None:
    """Keep rollback bookkeeping outside the accepted mutation generation."""
    state = PostprocessPassTransactionState8616(
        baseline_summary="before",
        known_cycle_path=None,
    )

    state.record_cycle_path(("root", "changed"))
    state.replace_baseline("restored")
    state.record_cycle_path(("root", "restored"))

    assert state.mutation_generation() == PostprocessMutationGeneration8616(0, None)
