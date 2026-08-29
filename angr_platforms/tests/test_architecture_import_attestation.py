"""Regression tests for incremental runtime import-guard attestations."""

from __future__ import annotations

from pathlib import Path

import pytest

from inertia_decompiler import architecture_import_attestation as attestation


def _write_guard_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Create two semantic files and one valid CLI orchestration module."""

    root = tmp_path / "X86_16"
    ir_root = root / "ir"
    ir_root.mkdir(parents=True)
    first = ir_root / "first.py"
    second = ir_root / "second.py"
    first.write_text("from __future__ import annotations\n", encoding="utf-8")
    second.write_text("from __future__ import annotations\n", encoding="utf-8")
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        '"""CLI orchestration that must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )
    return root, cli, first, second


def test_incremental_attestation_rechecks_only_changed_guarded_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changed source invalidates its own verdict without replaying siblings."""

    root, cli, first, _second = _write_guard_tree(tmp_path)
    cache = tmp_path / "guard.json"
    checked: list[Path] = []
    original = attestation._evaluate_runtime_import_path

    def recording_evaluator(
        scan_root: Path,
        path: Path,
        rules: tuple[attestation._RuntimeImportGuardRule, ...],
    ) -> tuple[attestation.ArchitectureViolation, ...]:
        checked.append(path)
        return original(scan_root, path, rules)

    monkeypatch.setattr(attestation, "_evaluate_runtime_import_path", recording_evaluator)
    initial = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")
    assert not initial.violations
    assert len(checked) == 3
    attestation.store_architecture_guard_cache(
        cache,
        "source-v1",
        "checker-v1",
        root,
        cli,
        initial,
    )

    checked.clear()
    first.write_text(
        "from __future__ import annotations\nVALUE = 1\n",
        encoding="utf-8",
    )
    updated = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")

    assert not updated.violations
    assert checked == [first]


def test_incremental_attestation_retains_cached_violation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cached wrong-layer verdict still blocks and does not become clean."""

    root, cli, first, _second = _write_guard_tree(tmp_path)
    first.write_text(
        "from ..postprocess.flags_cleanup import cleanup\n",
        encoding="utf-8",
    )
    cache = tmp_path / "guard.json"
    initial = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")
    assert any(
        violation.rule == "semantic-layer-postprocess-import"
        for violation in initial.violations
    )
    attestation.store_architecture_guard_cache(
        cache,
        "source-v1",
        "checker-v1",
        root,
        cli,
        initial,
    )
    assert not attestation.architecture_guard_cache_is_clean(cache, "source-v1")

    def fail_if_rechecked(
        _root: Path,
        _path: Path,
        _rules: tuple[attestation._RuntimeImportGuardRule, ...],
    ) -> tuple[attestation.ArchitectureViolation, ...]:
        raise AssertionError("unchanged violating source must reuse its exact verdict")

    monkeypatch.setattr(attestation, "_evaluate_runtime_import_path", fail_if_rechecked)
    repeated = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")

    assert repeated.violations == initial.violations


def test_checker_change_invalidates_every_cached_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule implementation changes invalidate all prior per-file verdicts."""

    root, cli, _first, _second = _write_guard_tree(tmp_path)
    cache = tmp_path / "guard.json"
    initial = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")
    attestation.store_architecture_guard_cache(
        cache,
        "source-v1",
        "checker-v1",
        root,
        cli,
        initial,
    )
    checked: list[Path] = []
    original = attestation._evaluate_runtime_import_path

    def recording_evaluator(
        scan_root: Path,
        path: Path,
        rules: tuple[attestation._RuntimeImportGuardRule, ...],
    ) -> tuple[attestation.ArchitectureViolation, ...]:
        checked.append(path)
        return original(scan_root, path, rules)

    monkeypatch.setattr(attestation, "_evaluate_runtime_import_path", recording_evaluator)
    changed_checker = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v2")

    assert not changed_checker.violations
    assert len(checked) == 3
