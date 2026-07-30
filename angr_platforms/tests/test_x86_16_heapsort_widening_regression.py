from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from scripts.check_sortd_sidecar_free import mz_executable_image

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
    extra_args: tuple[str, ...] = (),
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
            *extra_args,
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


def test_sortd_heapsort_sidecar_free_accepts_typed_segment_live_in(tmp_path: Path) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10970,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=("--ignore-local-sidecar-hints", "--c-target", "portable-flat"),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 sub_10970" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "uninitialized-read:segment-carrier" not in combined
    assert result.stdout.count("SEG_U16(inertia_ds, 2978)") >= 2
    assert "sub_109e8(local_2);" in result.stdout
    assert "sub_10794(2892, (local_2 << 1) + 2892);" in result.stdout
    assert "sub_10768(0, local_2);" in result.stdout
    assert re.search(r"^\s+sub_1075b\(", result.stdout, re.MULTILINE) is None
    assert "sub_10a61(local_2 - 1);" in result.stdout


def test_sortd_shellsort_sidecar_free_accepts_typed_segment_live_in(tmp_path: Path) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10C18,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=("--ignore-local-sidecar-hints", "--c-target", "portable-flat"),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10c18 sub_10c18" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "uninitialized-read:segment-carrier" not in combined
    assert "for (local_2 = SEG_U16(inertia_ds, 2978) / 2; local_2; )" in result.stdout
    assert "sub_10794((local_4 << 1) + 2892, (local_4 + local_2 << 1) + 2892);" in result.stdout
    assert "sub_10768(local_4, local_4 + local_2);" in result.stdout
