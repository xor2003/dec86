"""Runtime startup guard for decompiler architecture constraints.

Layer: CLI/fallback/reporting.
Responsibility: owns startup enforcement of architecture guard checks.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from scripts import check_decompiler_architecture as architecture_check
from scripts.check_decompiler_architecture import ArchitectureViolation

__all__ = [
    "DecompilerArchitectureGuardError",
    "assert_decompiler_architecture_clean",
    "format_decompiler_architecture_guard_error",
]


class DecompilerArchitectureGuardError(RuntimeError):
    """Raised when the runtime decompiler architecture guard fails."""


def format_decompiler_architecture_guard_error(violations: Iterable[ArchitectureViolation]) -> str:
    """Format a clear startup error for wrong-layer decompiler changes."""
    lines = [
        "Decompiler architecture guard failed.",
        "Wrong-layer imports, missing guard documentation, or unsafe agent project guide settings were detected before decompiler startup.",
        "Move the work to the owning layer, or update the architecture allowlist with a documented migration reason.",
        "Run: make architecture-check PYTHON=./.venv/bin/python",
        "",
        "Violations:",
    ]
    lines.extend(f"- {violation.format()}" for violation in violations)
    return "\n".join(lines)


def assert_decompiler_architecture_clean() -> None:
    """Stop decompiler startup if static layer guardrails are violated."""
    root = os.environ.get("INERTIA_ARCH_GUARD_X86_16_ROOT")
    cli = os.environ.get("INERTIA_ARCH_GUARD_CLI")
    repo_root = os.environ.get("INERTIA_ARCH_GUARD_REPO_ROOT")
    if root or cli or repo_root:
        violations = architecture_check.check_decompiler_startup_architecture(
            Path(root) if root else architecture_check.X86_16_ROOT,
            Path(cli) if cli else architecture_check.CLI_DECOMPILATION,
            Path(repo_root) if repo_root else architecture_check.REPO_ROOT,
        )
    else:
        violations = architecture_check.check_decompiler_startup_architecture()
    if violations:
        raise DecompilerArchitectureGuardError(format_decompiler_architecture_guard_error(violations))
