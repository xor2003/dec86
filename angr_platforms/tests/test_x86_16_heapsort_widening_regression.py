from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _scaled_timeout(timeout: int) -> int:
    raw_scale = os.environ.get("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", "").strip()
    if not raw_scale:
        return timeout
    try:
        scale = float(raw_scale)
    except ValueError:
        return timeout
    if scale <= 1.0:
        return timeout
    return max(timeout, int(round(timeout * scale)))


def _run_decompile_addr(
    path: Path,
    addr: int,
    *,
    analysis_timeout: int = 12,
    subprocess_timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    scaled_analysis_timeout = _scaled_timeout(analysis_timeout)
    scaled_subprocess_timeout = _scaled_timeout(subprocess_timeout)
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--addr",
            hex(addr),
            "--timeout",
            str(scaled_analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=scaled_subprocess_timeout,
        check=False,
    )


def test_sortdemo_heapsort_uses_widened_word_access_for_crow_anchor():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10970, analysis_timeout=30, subprocess_timeout=120)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "whole-tail validation clean" in f"{result.stderr}{result.stdout}"
    assert "| ir_" not in result.stdout
    assert "cRow > local_2" in result.stdout or "cRow > i" in result.stdout
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in result.stdout or "Swaps(&abarWork[0], &abarWork[i]);" in result.stdout
    assert "SEG_PTR(ds" not in result.stdout
