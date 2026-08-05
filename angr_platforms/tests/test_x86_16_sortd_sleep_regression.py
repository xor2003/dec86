"""Executable-only regression for the SORTD Sleep function."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def test_sortd_sleep_preserves_both_wide_clock_calls_sidecar_free(
    tmp_path: Path,
) -> None:
    """Require canonical calls, typed wide comparison, validation, and C."""
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    env = dict(os.environ)
    env.update(INERTIA_DISABLE_TIMING="1", INERTIA_ENABLE_TAIL_VALIDATION="1")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            "0x10f38",
            "--timeout",
            "120",
            "--ignore-local-sidecar-hints",
            "--no-alternate-source-c",
            "--window",
            "0x80",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=240,
        check=False,
    )

    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    body = result.stdout[result.stdout.rfind("unsigned short sub_10f38(") :]
    assert body.count("sub_1137e()") == 2
    assert "local_4 = sub_1137e() +" in body
    assert "if ((long)sub_1137e() > local_4)" in body
    assert "sub_137e" not in combined
    assert "vvar_" not in body
    assert "stack_base" not in body
    assert "flags" not in body
