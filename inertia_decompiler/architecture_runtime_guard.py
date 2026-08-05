"""Runtime startup guard for decompiler architecture constraints.

Layer: CLI/fallback/reporting.
Responsibility: owns startup enforcement of architecture guard checks.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path

from scripts import check_decompiler_architecture as architecture_check
from scripts.check_decompiler_architecture import ArchitectureViolation

__all__ = [
    "ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV",
    "DecompilerArchitectureGuardError",
    "assert_decompiler_architecture_clean",
    "format_decompiler_architecture_guard_error",
]

ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV: str = "INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID"
_ARCHITECTURE_GUARD_CACHE_SCHEMA: int = 1
_ARCHITECTURE_GUARD_CACHE_PATH: Path = (
    architecture_check.REPO_ROOT
    / ".inertia_decomp_cache"
    / "architecture_import_guard.json"
)


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
    try:
        payload = json.loads(_ARCHITECTURE_GUARD_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema") == _ARCHITECTURE_GUARD_CACHE_SCHEMA
        and payload.get("fingerprint") == fingerprint
        and payload.get("clean") is True
    )


def _store_clean_architecture_guard_cache(fingerprint: str) -> None:
    """Atomically persist one content-addressed clean import attestation."""
    path = _ARCHITECTURE_GUARD_CACHE_PATH
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(
                {
                    "schema": _ARCHITECTURE_GUARD_CACHE_SCHEMA,
                    "fingerprint": fingerprint,
                    "clean": True,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)


def assert_decompiler_architecture_clean() -> None:
    """Stop decompiler startup if runtime import-layer guardrails are violated."""
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
    fingerprint = (
        _architecture_guard_source_fingerprint(root_path, cli_path)
        if cache_allowed
        else None
    )
    if fingerprint is not None and _architecture_guard_cache_is_clean(fingerprint):
        return
    violations = _runtime_import_violations(root_path, cli_path)
    if violations:
        raise DecompilerArchitectureGuardError(format_decompiler_architecture_guard_error(violations))
    if fingerprint is not None:
        final_fingerprint = _architecture_guard_source_fingerprint(root_path, cli_path)
        if final_fingerprint != fingerprint:
            raise DecompilerArchitectureGuardError(
                "Decompiler source changed while the runtime import guard was running; retry startup."
            )
        _store_clean_architecture_guard_cache(fingerprint)
