"""Function-worker selection policy for CLI orchestration.

Layer: CLI/fallback/reporting.
Responsibility: identify whole-file jobs that require bounded-memory serial
execution without owning decompiler semantics.
"""

from __future__ import annotations


def requires_serial_function_decompilation(
    *,
    architecture: str,
    binary_suffix: str,
    address_requested: bool,
) -> bool:
    """Return whether a whole-file x86-16 executable must use serial workers."""
    return not address_requested and binary_suffix.lower() == ".exe" and architecture == "86_16"
