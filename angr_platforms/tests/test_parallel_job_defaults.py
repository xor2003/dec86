"""Regression tests for bounded N-1 development-tool parallelism."""

from __future__ import annotations

import os
import subprocess
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

from pytest import MonkeyPatch

from scripts import build_mypyc

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_build_mypyc_defaults_to_cpu_count_minus_one(monkeypatch: MonkeyPatch) -> None:
    """Keep one CPU free when mypyc chooses its native build job count."""
    monkeypatch.setattr(build_mypyc.os, "cpu_count", lambda: 8)

    parsed = build_mypyc._setup_parser().parse_args([])

    assert parsed.jobs == 7


def test_build_mypyc_uses_public_angr_platform_module_identity() -> None:
    """Compile the runtime package name while resolving its nested source tree."""
    assert not any(module.startswith("angr_platforms.angr_platforms.") for module in build_mypyc.TARGET_MODULES)
    assert build_mypyc._module_to_path("angr_platforms.X86_16.validation_calls") == (
        "angr_platforms/angr_platforms/X86_16/validation_calls.py"
    )


def test_build_mypyc_rejects_nested_alias_target() -> None:
    """Refuse native modules that would duplicate public runtime type identity."""
    try:
        build_mypyc._module_to_path("angr_platforms.angr_platforms.X86_16.validation_calls")
    except ValueError as exc:
        assert "split runtime type identity" in str(exc)
    else:
        raise AssertionError("nested mypyc target unexpectedly accepted")


def test_build_mypyc_requires_main_and_native_helper_artifacts(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Treat a half-written separate mypyc extension pair as stale."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-lib"))
    source_path = tmp_path / "inertia_decompiler" / "sample.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("value = 1\n", encoding="utf-8")
    state = build_mypyc.ModuleState(
        module="inertia_decompiler.sample",
        source_path=source_path,
        marker_path=tmp_path / "sample.stamp",
    )
    target_dir = tmp_path / "native-lib" / "inertia_decompiler"
    target_dir.mkdir(parents=True)
    suffix = EXTENSION_SUFFIXES[0]
    (target_dir / f"sample{suffix}").write_bytes(b"main")

    assert len(build_mypyc._module_artifact_candidates(state)) == 1
    assert build_mypyc._build_stale([state]) == [state]

    (target_dir / f"sample__mypyc{suffix}").write_bytes(b"native")
    state.marker_path.write_text("ready\n", encoding="utf-8")
    newest = max(path.stat().st_mtime for path in build_mypyc._module_artifact_candidates(state))
    os.utime(state.marker_path, (newest + 1, newest + 1))
    assert build_mypyc._build_stale([state]) == []


def test_build_mypyc_reconciles_only_changed_module_artifacts(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Preserve unchanged artifacts while removing a retired module exactly."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-cache/lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))

    build_mypyc._ensure_build_layout(["example.alpha"])
    sentinel = tmp_path / "native-cache" / "old-extension.so"
    sentinel.write_bytes(b"native")
    artifact_dir = tmp_path / "native-cache" / "lib" / "example"
    artifact_dir.mkdir(parents=True)
    suffix = EXTENSION_SUFFIXES[0]
    alpha_main = artifact_dir / f"alpha{suffix}"
    alpha_native = artifact_dir / f"alpha__mypyc{suffix}"
    alpha_main.write_bytes(b"main")
    alpha_native.write_bytes(b"native")
    build_mypyc._ensure_build_layout(["example.alpha"])
    assert sentinel.is_file()
    assert alpha_main.is_file()
    assert alpha_native.is_file()

    build_mypyc._ensure_build_layout(["example.beta"])
    assert sentinel.is_file()
    assert not alpha_main.exists()
    assert not alpha_native.exists()
    assert (tmp_path / "native-cache" / "build-schema.txt").read_text(encoding="utf-8") == (
        f"{build_mypyc.MYPYC_BUILD_SCHEMA}\n"
    )
    assert (tmp_path / "native-cache" / "module-cohort.txt").read_text(encoding="utf-8") == (
        "example.beta\n"
    )


def test_build_mypyc_schema_change_resets_complete_cache(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Discard every old artifact when native compatibility schema changes."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-cache/lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))
    build_mypyc._ensure_build_layout(["example.alpha"])
    sentinel = tmp_path / "native-cache" / "old-extension.so"
    sentinel.write_bytes(b"native")

    monkeypatch.setattr(build_mypyc, "MYPYC_BUILD_SCHEMA", "next-schema")
    build_mypyc._ensure_build_layout(["example.alpha"])

    assert not sentinel.exists()
    assert (tmp_path / "native-cache" / "build-schema.txt").read_text(encoding="utf-8") == (
        "next-schema\n"
    )


def test_build_mypyc_refuses_artifact_directory_outside_cache(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Fail closed before cache reconciliation can target an external path."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("outside-native-lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))

    try:
        build_mypyc._ensure_build_layout(["example.alpha"])
    except ValueError as exc:
        assert "escapes cache root" in str(exc)
    else:
        raise AssertionError("external mypyc artifact directory unexpectedly accepted")


def test_build_mypyc_refuses_nested_artifact_symlink_outside_cache(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Do not follow a nested package symlink while retiring one module."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-cache/lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))
    build_mypyc._ensure_build_layout(["example.alpha"])
    package_parent = tmp_path / "native-cache" / "lib"
    package_parent.mkdir(parents=True)
    external_package = tmp_path / "external-package"
    external_package.mkdir()
    external_artifact = external_package / f"alpha{EXTENSION_SUFFIXES[0]}"
    external_artifact.write_bytes(b"external")
    (package_parent / "example").symlink_to(external_package, target_is_directory=True)

    try:
        build_mypyc._ensure_build_layout([])
    except ValueError as exc:
        assert "escapes cache root" in str(exc)
    else:
        raise AssertionError("nested external artifact symlink unexpectedly followed")
    assert external_artifact.read_bytes() == b"external"


def test_make_parallel_defaults_share_cpu_budget() -> None:
    """Keep tools on N-1 CPUs while bounding memory-heavy pytest workers."""
    make_fragment = """print-parallel:
	@printf '%s\\n' '$(PARALLEL_JOBS)' '$(PYTEST_ARGS)' '$(PYTEST_ALL_WORKERS)' '$(PYTEST_ALL_HEAVY_WORKERS)' '$(PYTEST_ALL_HEAVY_SHARDS)' '$(LINT_JOBS)' '$(MYPYC_JOBS)' '$(PIPELINE_WORKERS)'
"""
    env = {**os.environ, "PYTEST_ADDOPTS": ""}
    for inherited_make_variable in (
        "MAKEFLAGS",
        "MFLAGS",
        "MAKELEVEL",
        "LINT_JOBS",
        "MYPYC_JOBS",
        "PARALLEL_JOBS",
        "PIPELINE_WORKERS",
        "PYTEST_ALL_HEAVY_SHARDS",
        "PYTEST_ALL_HEAVY_WORKERS",
        "PYTEST_ALL_WORKERS",
        "PYTEST_ARGS",
    ):
        env.pop(inherited_make_variable, None)
    result = subprocess.run(
        [
            "make",
            "-s",
            "--no-print-directory",
            "--eval",
            make_fragment,
            "CPU_COUNT=8",
            "print-parallel",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.stdout.splitlines() == [
        "7",
        "--tb=short --no-header -n 7 --dist loadgroup --durations=5",
        "7",
        "2",
        "16",
        "7",
        "7",
        "7",
    ]
