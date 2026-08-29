"""Runtime startup guard for decompiler architecture constraints.

Layer: CLI/fallback/reporting.
Responsibility: owns startup enforcement of architecture guard checks.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path

from inertia_decompiler import architecture_import_attestation
from scripts import check_decompiler_architecture as architecture_check
from scripts.check_decompiler_architecture import ArchitectureViolation

__all__ = [
    "ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV",
    "DecompilerArchitectureGuardError",
    "assert_decompiler_architecture_clean",
    "format_decompiler_architecture_guard_error",
]

ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV: str = "INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID"
_ARCHITECTURE_GUARD_CACHE_PATH: Path = (
    architecture_check.REPO_ROOT
    / ".inertia_decomp_cache"
    / "architecture_import_guard.json"
)
_ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID: int | None = None


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


def _runtime_import_violations(
    root: Path,
    cli_path: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Run only import ownership checks required on every CLI startup."""
    return (
        *architecture_check._check_postprocess_imports(root),
        *architecture_check._check_semantic_layers_do_not_import_postprocess(root),
        *architecture_check._check_cli_imports(cli_path),
    )


_RUNTIME_IMPORT_VIOLATIONS_IMPL = _runtime_import_violations


def _architecture_guard_source_fingerprint(
    root: Path,
    cli_path: Path,
) -> str:
    """Hash every source that can change runtime import-guard conclusions."""
    paths = {
        *root.rglob("*.py"),
        cli_path,
        Path(architecture_check.__file__).resolve(),
        Path(architecture_import_attestation.__file__).resolve(),
        Path(__file__).resolve(),
    }
    digest = hashlib.sha256()
    for path in sorted(paths):
        try:
            data = path.read_bytes()
        except OSError:
            data = b"<missing>"
        digest.update(str(path.resolve()).encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _architecture_guard_cache_is_clean(fingerprint: str) -> bool:
    """Return whether the persistent attestation matches current source bytes."""
    return architecture_import_attestation.architecture_guard_cache_is_clean(
        _ARCHITECTURE_GUARD_CACHE_PATH,
        fingerprint,
    )


def _architecture_guard_checker_fingerprint() -> str:
    """Hash rule and cache implementations that determine stored verdicts."""
    return architecture_import_attestation.architecture_guard_checker_fingerprint(
        Path(__file__),
    )


def assert_decompiler_architecture_clean() -> None:
    """Stop decompiler startup if runtime import-layer guardrails are violated."""
    global _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID
    root = os.environ.get("INERTIA_ARCH_GUARD_X86_16_ROOT")
    cli = os.environ.get("INERTIA_ARCH_GUARD_CLI")
    repo_root = os.environ.get("INERTIA_ARCH_GUARD_REPO_ROOT")
    verified_parent_pid = os.environ.get(ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV)
    if not (root or cli or repo_root) and verified_parent_pid is not None:
        try:
            if int(verified_parent_pid) == os.getppid():
                return
        except ValueError:
            pass
    root_path = Path(root) if root else architecture_check.X86_16_ROOT
    cli_path = Path(cli) if cli else architecture_check.CLI_DECOMPILATION
    cache_allowed = (
        not (root or cli or repo_root)
        and _runtime_import_violations is _RUNTIME_IMPORT_VIOLATIONS_IMPL
    )
    process_pid = os.getpid()
    if cache_allowed and process_pid == _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID:
        return
    fingerprint = (
        _architecture_guard_source_fingerprint(root_path, cli_path)
        if cache_allowed
        else None
    )
    if fingerprint is not None and _architecture_guard_cache_is_clean(fingerprint):
        _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID = process_pid
        return
    checker_fingerprint = (
        _architecture_guard_checker_fingerprint()
        if cache_allowed
        else None
    )
    evaluation = (
        architecture_import_attestation.evaluate_runtime_import_snapshot(
            _ARCHITECTURE_GUARD_CACHE_PATH,
            root_path,
            cli_path,
            checker_fingerprint,
        )
        if checker_fingerprint is not None
        else None
    )
    violations = (
        evaluation.violations
        if evaluation is not None
        else _runtime_import_violations(root_path, cli_path)
    )
    if fingerprint is not None:
        final_fingerprint = _architecture_guard_source_fingerprint(root_path, cli_path)
        if final_fingerprint != fingerprint:
            raise DecompilerArchitectureGuardError(
                "Decompiler source changed while the runtime import guard was running; retry startup."
            )
        if checker_fingerprint is None or evaluation is None:
            raise DecompilerArchitectureGuardError(
                "Decompiler architecture guard cache evaluation was not completed."
            )
        architecture_import_attestation.store_architecture_guard_cache(
            _ARCHITECTURE_GUARD_CACHE_PATH,
            fingerprint,
            checker_fingerprint,
            root_path,
            cli_path,
            evaluation,
        )
    if violations:
        raise DecompilerArchitectureGuardError(format_decompiler_architecture_guard_error(violations))
    if fingerprint is not None:
        _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID = process_pid
