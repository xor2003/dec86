"""Regression tests for bounded N-1 development-tool parallelism."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from scripts import build_mypyc

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_build_mypyc_defaults_to_cpu_count_minus_one(monkeypatch: MonkeyPatch) -> None:
    """Keep one CPU free when mypyc chooses its native build job count."""
    monkeypatch.setattr(build_mypyc.os, "cpu_count", lambda: 8)

    parsed = build_mypyc._setup_parser().parse_args([])

    assert parsed.jobs == 7


def test_make_parallel_defaults_share_cpu_count_minus_one() -> None:
    """Keep pytest, linters, pipelines, and mypyc on one shared default."""
    make_fragment = """print-parallel:
	@printf '%s\\n' '$(PARALLEL_JOBS)' '$(PYTEST_ARGS)' '$(LINT_JOBS)' '$(MYPYC_JOBS)' '$(PIPELINE_WORKERS)'
"""
    env = {**os.environ, "PYTEST_ADDOPTS": ""}
    for inherited_make_variable in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "PYTEST_ARGS"):
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
        "-n 7 --dist loadgroup --durations=5",
        "7",
        "7",
        "7",
    ]
