from __future__ import annotations

from inertia_decompiler.function_worker_policy import (
    CleanProcessOverride8616,
    FunctionWorkerMode8616,
    clean_process_override_8616,
    select_function_worker_policy_8616,
)


def _policy(**overrides: object):
    inputs: dict[str, object] = {
        "isolation_required": True,
        "sidecar_available": False,
        "full_sweep": True,
        "include_library_functions": False,
        "posix_available": True,
        "function_count": 20,
        "shared_worker_count": 7,
        "clean_process_override": CleanProcessOverride8616.DEFAULT,
    }
    inputs.update(overrides)
    return select_function_worker_policy_8616(**inputs)  # type: ignore[arg-type]


def test_pure_binary_whole_file_uses_bounded_clean_processes_by_default() -> None:
    policy = _policy()

    assert policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    assert policy.workers == 7


def test_sidecar_whole_file_uses_clean_processes_to_bound_native_state() -> None:
    policy = _policy(sidecar_available=True)

    assert policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    assert policy.workers == 7


def test_explicit_clean_process_override_supports_sidecar_runs() -> None:
    policy = _policy(
        sidecar_available=True,
        clean_process_override=CleanProcessOverride8616.ENABLED,
    )

    assert policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    assert policy.workers == 7


def test_explicit_disable_preserves_single_shared_worker() -> None:
    policy = _policy(clean_process_override=CleanProcessOverride8616.DISABLED)

    assert policy.mode is FunctionWorkerMode8616.SHARED
    assert policy.workers == 1


def test_clean_process_mode_is_bounded_by_functions_and_cpu_budget() -> None:
    assert _policy(function_count=2).workers == 2
    assert _policy(function_count=200).workers == 7


def test_non_x86_policy_preserves_shared_worker_selection() -> None:
    policy = _policy(isolation_required=False, function_count=3, shared_worker_count=7)

    assert policy.mode is FunctionWorkerMode8616.SHARED
    assert policy.workers == 3


def test_clean_process_override_parser_returns_typed_states() -> None:
    assert clean_process_override_8616(None) is CleanProcessOverride8616.DEFAULT
    assert clean_process_override_8616("yes") is CleanProcessOverride8616.ENABLED
    assert clean_process_override_8616("0") is CleanProcessOverride8616.DISABLED
    assert clean_process_override_8616("unexpected") is CleanProcessOverride8616.DEFAULT
