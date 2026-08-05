"""Function-worker selection policy for CLI orchestration.

Layer: CLI/fallback/reporting.
Responsibility: identify whole-file jobs that require bounded-memory serial
execution without owning decompiler semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CleanProcessOverride8616(str, Enum):
    """Typed interpretation of the legacy clean-worker environment switch."""

    DEFAULT = "default"
    ENABLED = "enabled"
    DISABLED = "disabled"


class FunctionWorkerMode8616(str, Enum):
    """Execution isolation selected for one CLI function batch."""

    SHARED = "shared"
    CLEAN_PROCESS = "clean_process"


@dataclass(frozen=True, slots=True)
class FunctionWorkerPolicy8616:
    """Typed worker mode and bounded concurrency for one function batch."""

    mode: FunctionWorkerMode8616
    workers: int


def requires_serial_function_decompilation(
    *,
    architecture: str,
    binary_suffix: str,
    address_requested: bool,
) -> bool:
    """Return whether a whole-file x86-16 executable must use serial workers."""
    return not address_requested and binary_suffix.lower() == ".exe" and architecture == "86_16"


def clean_process_override_8616(value: str | None) -> CleanProcessOverride8616:
    """Parse the legacy clean-worker switch without leaking string states."""
    if value is None or not value.strip():
        return CleanProcessOverride8616.DEFAULT
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return CleanProcessOverride8616.ENABLED
    if normalized in {"0", "false", "no", "off"}:
        return CleanProcessOverride8616.DISABLED
    return CleanProcessOverride8616.DEFAULT


def select_function_worker_policy_8616(
    *,
    serial_required: bool,
    sidecar_available: bool,
    full_sweep: bool,
    include_library_functions: bool,
    posix_available: bool,
    function_count: int,
    shared_worker_count: int,
    clean_process_override: CleanProcessOverride8616,
) -> FunctionWorkerPolicy8616:
    """Select clean serial interpreters where shared state is unsafe."""
    if not serial_required:
        return FunctionWorkerPolicy8616(
            FunctionWorkerMode8616.SHARED,
            max(1, min(function_count or 1, shared_worker_count)),
        )

    clean_process_eligible = full_sweep and not include_library_functions and posix_available
    clean_process_selected = clean_process_eligible and (
        clean_process_override is CleanProcessOverride8616.ENABLED
        or (clean_process_override is CleanProcessOverride8616.DEFAULT and not sidecar_available)
    )
    if not clean_process_selected:
        return FunctionWorkerPolicy8616(FunctionWorkerMode8616.SHARED, 1)
    return FunctionWorkerPolicy8616(FunctionWorkerMode8616.CLEAN_PROCESS, 1)
