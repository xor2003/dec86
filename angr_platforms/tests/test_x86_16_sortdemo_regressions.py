from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _run_decompile_addr(
    path: Path,
    addr: int,
    *,
    analysis_timeout: int = 6,
    subprocess_timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--addr",
            hex(addr),
            "--timeout",
            str(analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=subprocess_timeout,
        check=False,
    )


def test_sortdemo_sleep_anchor_keeps_bad_flag_guard_and_stack_linearization_visible():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10F28)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10f18 Sleep" in result.stdout
    assert "void Sleep(clock_t wait)" in result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" in result.stdout
    assert "ss << 4" in result.stdout
    assert "tail-validation" not in result.stdout.lower() or "uncollected" in result.stdout.lower()


def test_sortdemo_heapsort_anchor_keeps_stack_linearization_and_weak_call_surface_visible():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109D8)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "short HeapSort(void)" in result.stdout
    assert "ss << 4" in result.stdout
    assert "sub_1078();" in result.stdout
