"""Tests for typed postprocess runtime policy."""

from angr_platforms.X86_16.postprocess.pass_runtime import (
    build_postprocess_runtime_config_8616,
    postprocess_optional_reject_budget_8616,
)


def test_large_function_disables_requested_per_pass_validation() -> None:
    config = build_postprocess_runtime_config_8616(
        validation_enabled=True,
        per_pass_validation_requested=True,
        large_function_for_per_pass_validation=True,
        fact_backed_stack_normalize_enabled=True,
        baseline_summary=None,
        env={},
    )

    assert config.per_pass_validation_enabled is False
    assert config.pass_timeout_seconds == 2


def test_force_validation_overrides_large_function_policy() -> None:
    config = build_postprocess_runtime_config_8616(
        validation_enabled=True,
        per_pass_validation_requested=False,
        large_function_for_per_pass_validation=True,
        fact_backed_stack_normalize_enabled=True,
        baseline_summary=None,
        env={"INERTIA_FORCE_PER_PASS_TV": "1"},
    )

    assert config.per_pass_validation_enabled is True


def test_skip_policy_preserves_required_stack_normalization_refusal() -> None:
    config = build_postprocess_runtime_config_8616(
        validation_enabled=False,
        per_pass_validation_requested=False,
        large_function_for_per_pass_validation=False,
        fact_backed_stack_normalize_enabled=False,
        baseline_summary=None,
        env={"INERTIA_SKIP_POSTPROCESS_PASSES": " first,second "},
    )

    assert config.skip_names == {
        "first",
        "second",
        "_normalize_fact_backed_stack_accesses_8616",
    }


def test_invalid_reject_budget_uses_owned_default() -> None:
    assert postprocess_optional_reject_budget_8616(
        {"INERTIA_POSTPROCESS_OPTIONAL_REJECT_BUDGET": "invalid"}
    ) == postprocess_optional_reject_budget_8616({})
