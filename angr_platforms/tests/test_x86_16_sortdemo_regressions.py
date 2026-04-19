from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path

from inertia_decompiler.acceptance_scorecard import build_acceptance_scorecard
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function

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
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
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
        env=env,
        timeout=subprocess_timeout,
        check=False,
    )


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stderr}{result.stdout}"


def test_sortdemo_sleep_anchor_eliminates_raw_flag_guard_and_keeps_validation_clean():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10F28)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10f18 Sleep" in result.stdout
    assert "void Sleep(clock_t wait)" in result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in result.stdout
    assert "else if (t >" in result.stdout
    assert "ss << 4" not in result.stdout
    assert "whole-tail validation clean" in _combined_output(result)


def test_sortdemo_heapsort_anchor_no_longer_prunes_local_lane_after_repeated_empty_results():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109D8)

    assert result.returncode in {0, 4}, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "pruned local lane" not in result.stdout
    scorecard = build_acceptance_scorecard(
        "HeapSort",
        result.stdout,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "HeapSort"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode in {"asm_fallback", "decompiled"}
    if scorecard.recovery_mode == "decompiled":
        assert "sub_1078();" in result.stdout
        assert "ss << 4" in result.stdout
        assert "ds << 4" in result.stdout
    else:
        assert "shared-project slice full-with-refs: empty" in result.stdout
        assert "/* == asm fallback == */" in result.stdout


def test_sortdemo_percolateup_anchor_no_longer_crashes_on_vexvalue_register_resolution():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109E8)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "Function recovery failed" not in result.stdout
    assert "function: 0x109e8 PercolateUp" in result.stdout
    assert "short PercolateUp(int iMaxLevel)" in result.stdout


def test_sortdemo_acceptance_scorecards_capture_main_sleep_and_percolateup_state():
    main_result = _run_decompile_addr(SORTDEMO_EXE, 0x10010)
    sleep_result = _run_decompile_addr(SORTDEMO_EXE, 0x10F28)
    percolate_result = _run_decompile_addr(SORTDEMO_EXE, 0x109E8)

    assert main_result.returncode == 0, main_result.stderr + main_result.stdout
    assert sleep_result.returncode == 0, sleep_result.stderr + sleep_result.stdout
    assert percolate_result.returncode == 0, percolate_result.stderr + percolate_result.stdout
    assert "InitMenu();" in main_result.stdout

    main_scorecard = build_acceptance_scorecard(
        "main",
        _combined_output(main_result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "main"),
    )
    sleep_scorecard = build_acceptance_scorecard(
        "Sleep",
        _combined_output(sleep_result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Sleep"),
    )
    percolate_scorecard = build_acceptance_scorecard(
        "PercolateUp",
        _combined_output(percolate_result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "PercolateUp"),
    )

    assert main_scorecard.source_present is True
    assert main_scorecard.raw_ss_linear_count == 0
    assert main_scorecard.anonymous_sub_count == 0
    assert main_scorecard.validation_verdict == "stable"
    assert sleep_scorecard.source_present is True
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in sleep_result.stdout
    assert sleep_scorecard.raw_ss_linear_count == 0
    assert sleep_scorecard.validation_verdict == "stable"
    assert percolate_scorecard.source_present is True
    assert percolate_scorecard.raw_ds_linear_count >= 1
    assert percolate_scorecard.raw_ss_linear_count >= 1
    assert percolate_scorecard.validation_verdict in {"changed", "stable", "unknown", "uncollected"}


def test_sortdemo_acceptance_scorecards_capture_heapsort_quicksort_runmenu_and_beep_state():
    function_specs = {
        "HeapSort": (0x109D8, 30),
        "QuickSort": (0x10CE0, 60),
        "RunMenu": (0x102E0, 60),
        "Beep": (0x10E70, 30),
    }
    scorecards = {}
    for function_name, (addr, subprocess_timeout) in function_specs.items():
        result = _run_decompile_addr(SORTDEMO_EXE, addr, subprocess_timeout=subprocess_timeout)
        assert result.returncode in {0, 4}, result.stderr + result.stdout
        scorecards[function_name] = build_acceptance_scorecard(
            function_name,
            _combined_output(result),
            source_text=render_local_source_sidecar_function(SORTDEMO_EXE, function_name),
        )

    assert scorecards["HeapSort"].source_present is True
    assert scorecards["HeapSort"].recovery_mode in {"asm_fallback", "decompiled"}
    assert scorecards["HeapSort"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["HeapSort"].recovery_mode == "decompiled":
        assert scorecards["HeapSort"].raw_ss_linear_count >= 1
        assert scorecards["HeapSort"].raw_ds_linear_count >= 1
        assert scorecards["HeapSort"].anonymous_sub_count == 0
    assert scorecards["QuickSort"].source_present is True
    assert scorecards["QuickSort"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["QuickSort"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["QuickSort"].recovery_mode == "decompiled":
        assert scorecards["QuickSort"].raw_flags_count >= 1
    assert scorecards["RunMenu"].source_present is True
    assert scorecards["RunMenu"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["RunMenu"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["RunMenu"].recovery_mode == "decompiled":
        assert scorecards["RunMenu"].raw_ss_linear_count >= 1
    assert scorecards["Beep"].source_present is True
    assert scorecards["Beep"].raw_ss_linear_count >= 1
    assert scorecards["Beep"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}


def test_sortdemo_acceptance_scorecards_capture_swaps_swapbars_and_reinitbars_state():
    function_specs = {
        "Swaps": (0x107B8, 30),
        "SwapBars": (0x10768, 30),
        "ReInitBars": (0x10678, 30),
    }
    scorecards = {}
    for function_name, (addr, subprocess_timeout) in function_specs.items():
        result = _run_decompile_addr(SORTDEMO_EXE, addr, subprocess_timeout=subprocess_timeout)
        assert result.returncode in {0, 4}, result.stderr + result.stdout
        scorecards[function_name] = build_acceptance_scorecard(
            function_name,
            _combined_output(result),
            source_text=render_local_source_sidecar_function(SORTDEMO_EXE, function_name),
        )

    assert scorecards["Swaps"].source_present is True
    assert scorecards["Swaps"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["Swaps"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["Swaps"].recovery_mode == "decompiled":
        assert scorecards["Swaps"].raw_ds_linear_count >= 1
    assert scorecards["SwapBars"].source_present is True
    assert scorecards["SwapBars"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["SwapBars"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["SwapBars"].recovery_mode == "decompiled":
        assert scorecards["SwapBars"].raw_ss_linear_count >= 1 or scorecards["SwapBars"].raw_ds_linear_count >= 1
    assert scorecards["ReInitBars"].source_present is True
    assert scorecards["ReInitBars"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["ReInitBars"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["ReInitBars"].recovery_mode == "decompiled":
        assert scorecards["ReInitBars"].raw_ds_linear_count >= 1
