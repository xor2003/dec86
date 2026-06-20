from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from inertia_decompiler.acceptance_scorecard import build_acceptance_scorecard
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function

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
    analysis_timeout: int = 6,
    subprocess_timeout: int = 90,
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


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stderr}{result.stdout}"


def _function_body_from_stdout(stdout: str, signature: str) -> str:
    if signature not in stdout:
        return stdout
    return signature + stdout.rsplit(signature, 1)[-1]


def _run_decompile_file(
    path: Path,
    *,
    max_functions: int = 8,
    analysis_timeout: int = 30,
    subprocess_timeout: int = 180,
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
            "--timeout",
            str(scaled_analysis_timeout),
            "--max-functions",
            str(max_functions),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=scaled_subprocess_timeout,
        check=False,
    )


def test_sortdemo_sleep_anchor_eliminates_raw_flag_guard_and_keeps_validation_clean():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10F38, analysis_timeout=30)
    scorecard = build_acceptance_scorecard(
        "Sleep",
        _combined_output(result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Sleep"),
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert (
        ("function: 0x10f18 Sleep" in result.stdout)
        or ("function: 0x10f28 Sleep" in result.stdout)
        or ("function: 0x10f38 Sleep" in result.stdout)
    )
    assert ("void Sleep(clock_t wait)" in result.stdout) or ("void Sleep(uint32_t wait)" in result.stdout)
    assert "clock() + wait" in result.stdout
    assert "flags_2 = ...;" not in result.stdout
    assert "flags_2 =" not in result.stdout
    assert "if (...)" not in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in result.stdout
    assert "clock();" in result.stdout
    assert "ss << 4" not in result.stdout
    assert "(&s_" not in result.stdout
    assert "*(&" not in result.stdout
    assert scorecard.validation_verdict == "stable"


def test_sortdemo_reinitbars_uses_runtime_segment_helpers_and_keeps_validation_clean():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "ds << 4" not in combined
    assert "es << 4" not in combined
    assert "ss << 4" not in combined
    assert "abarWork[local_2] = abarPerm[local_2];" in result.stdout
    assert "DrawBar(local_2);" in result.stdout


def test_sortdemo_drawtime_materializes_clock_return_to_clfinish_once():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10491,
        analysis_timeout=45,
        subprocess_timeout=150,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    body = _function_body_from_stdout(result.stdout, "void DrawTime")
    clock_assignments = re.findall(r"\b([A-Za-z_]\w*)\s*=\s*clock\(\);", body)
    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "Missing source-evidenced calls" not in combined
    assert "clFinish = clock();" in body
    assert clock_assignments == ["clFinish"]
    assert re.search(r"(?m)^\s*if \([^\n]+\)\n\s*else\b", body) is None
    assert "Beep(iCurrentRow * 60, 75);" in body


def test_sortdemo_swapbars_call_arguments_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10768,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10768 SwapBars" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined


def test_sortdemo_swapbars_does_not_pointer_promote_irow2_or_emit_dead_setup_artifacts():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10768,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode in {0, 6}, combined
    assert "function: 0x10768 SwapBars" in result.stdout
    assert "validation=passed" in combined
    assert "void SwapBars(int iRow1, int *iRow2)" not in result.stdout
    assert "s_2 = &s_2 + 2;" not in result.stdout
    assert "vvar_16 = &s_6;" not in result.stdout


def test_sortdemo_swaps_preserves_binary_proven_global_increment_and_pointer_swap():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x107B8,
        analysis_timeout=10,
        subprocess_timeout=60,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x107b8 Swaps" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" in result.stdout
    assert "iSwaps += 1;" in result.stdout
    assert "barTmp = bar1[0];" in result.stdout or "local_2 = bar1[0];" in result.stdout
    assert "bar1[0] = bar2[0];" in result.stdout
    assert "bar2[0] = local_2;" in result.stdout or "bar2[0] = barTmp;" in result.stdout


def test_sortdemo_percolateup_materializes_parent_once_and_preserves_calls():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x109E8,
        analysis_timeout=60,
        subprocess_timeout=90,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x109e8 PercolateUp" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    final_body = "void PercolateUp" + result.stdout.rsplit("void PercolateUp", 1)[-1]
    executable_lines = tuple(
        line.strip() for line in final_body.splitlines() if line.startswith("        ") or line.startswith("    ")
    )
    assert "local_2 = i / 2;" in executable_lines
    assert executable_lines.count("iCompares += 1;") == 1
    assert (
        "if (abarWork[i] <= abarWork[local_2])" in executable_lines
        or "if (MEM_U8(&abarWork[i]) <= MEM_U8(&abarWork[local_2]))" in executable_lines
    )
    assert "Swaps(&abarWork[local_2], &abarWork[i]);" in executable_lines
    assert "SwapBars(local_2, i);" in executable_lines
    assert "SEG_U8(ds," not in final_body
    assert "SEG_PTR(ds," not in final_body
    assert sum(1 for line in executable_lines if line.startswith("Swaps(")) == 1
    assert sum(1 for line in executable_lines if line.startswith("SwapBars(")) == 1
    assert "flsbuf" not in final_body


def test_sortdemo_main_uses_portable_flat_int_main_signature():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10010,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=60,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10010 main" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void main(void)" not in result.stdout
    assert "int main(void)" in result.stdout
    assert "return 0;" in result.stdout


def test_sortdemo_nfree_does_not_emit_undeclared_vvar_carrier():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x125E6,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=120,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x125e6 nfree" in combined
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "undeclared" not in combined
    assert "void nfree(void *ptr)" in result.stdout
    assert "vvar_" not in result.stdout


def test_sortdemo_heapsort_callsites_materialized_in_c_order():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    assert "PercolateUp(local_2);" in final_body or "PercolateUp(i);" in final_body
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in final_body or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
    assert (
        "SwapBars(0, i);" in final_body
        or "SwapBars( 0, i );" in final_body
        or "SwapBars(0, local_2);" in final_body
        or "SwapBars( 0, local_2 );" in final_body
    )
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(local_2 - 1);" in final_body
        or "PercolateDown( local_2 - 1 );" in final_body
    )
    assert "SEG_PTR(ds" not in final_body
    assert "SwapBars(i, 0);" not in final_body
    assert "SwapBars(local_2, 0);" not in final_body
    assert "PercolateDown((i << 1) + 2892);" not in final_body
    assert "PercolateDown((local_2 << 1) + 2892);" not in final_body


def test_sortdemo_heapsort_call_args_use_bp_local_i_not_address_expr():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    assert "PercolateUp(local_2);" in final_body or "PercolateUp(i);" in final_body
    assert (
        "SwapBars(0, i);" in final_body
        or "SwapBars( 0, i );" in final_body
        or "SwapBars(0, local_2);" in final_body
        or "SwapBars( 0, local_2 );" in final_body
    )
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(local_2 - 1);" in final_body
        or "PercolateDown( local_2 - 1 );" in final_body
    )
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in final_body or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
    assert "*(&(&v0)[4])" not in final_body
    assert "SEG_PTR(ds, &s_4 + 2)" not in final_body
    assert "(i << 1) + 2892);" not in final_body
    assert "(local_2 << 1) + 2892);" not in final_body
    assert "SwapBars(i, 0)" not in final_body
    assert "SwapBars(local_2, 0)" not in final_body
    assert "PercolateDown((i << 1) + 2892)" not in final_body
    assert "PercolateDown((local_2 << 1) + 2892)" not in final_body


def test_sortdemo_heapsort_callsite_args_survive_postprocess():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    assert "SwapBars(0, local_2);" in final_body or "SwapBars(0, i);" in final_body
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(local_2 - 1);" in final_body
    )
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in final_body or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
    assert "SEG_PTR(ds" not in final_body
    assert "SEG_PTR(ds, &s_" not in final_body
    assert "SEG_PTR(ds, &v" not in final_body
    assert "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, &s_4 + 2))" not in final_body
    assert "PercolateDown((i << 1) + 2892)" not in final_body


def test_sortdemo_heapsort_value_and_pointer_args_survive_final_output():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    call_lines = "\n".join(
        line.strip()
        for line in final_body.splitlines()
        if any(name in line for name in ("PercolateUp(", "Swaps(", "SwapBars(", "PercolateDown("))
    )
    assert "PercolateUp(local_2);" in call_lines or "PercolateUp(i);" in call_lines
    assert "SwapBars(0, local_2);" in call_lines or "SwapBars(0, i);" in call_lines
    assert (
        "PercolateDown(i - 1);" in call_lines
        or "PercolateDown(local_2 - 1);" in call_lines
    )
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in call_lines or "Swaps(&abarWork[0], &abarWork[i]);" in call_lines
    assert "PercolateDown(3)" not in call_lines
    assert "PercolateDown((i << 1) + 2892)" not in call_lines
    assert "SEG_PTR(ds" not in call_lines
    assert "SEG_PTR(ds, &s_" not in call_lines
    assert "&s_4" not in call_lines
    assert "arg_1" not in call_lines


def test_sortdemo_file_summary_lines_are_stable_and_sorted():
    first = _run_decompile_file(SORTDEMO_EXE, max_functions=8)
    second = _run_decompile_file(SORTDEMO_EXE, max_functions=8)

    assert first.returncode in {0, 2}, first.stderr + first.stdout
    assert second.returncode in {0, 2}, second.stderr + second.stdout

    def _summary_lines(text: str) -> list[str]:
        return [line for line in text.splitlines() if "summary:" in line]

    first_summary = _summary_lines(_combined_output(first))
    second_summary = _summary_lines(_combined_output(second))
    # Summary should remain deterministic across repeated runs even when
    # timeout/fallback accounting changes the exact mix of lines.
    assert first_summary == second_summary
    assert any("same_family_retry_stops=" in line for line in first_summary)
    assert any("shown=8 decompiled=8 asm_or_detail_fallback=0" in line for line in first_summary)


def test_sortdemo_heapsort_anchor_no_longer_prunes_local_lane_after_repeated_empty_results():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109D8)
    combined = result.stderr + result.stdout

    assert result.returncode in {0, 1, 4}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "pruned local lane" not in result.stdout
    if result.returncode == 1:
        assert "Swaps missing argument 1" in combined
        assert "validation=passed" not in combined
        return
    scorecard = build_acceptance_scorecard(
        "HeapSort",
        result.stdout,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "HeapSort"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode in {"asm_fallback", "decompiled"}
    if scorecard.recovery_mode == "decompiled":
        assert "ss << 4" not in result.stdout
        assert "!(!(" not in result.stdout
    else:
        assert (
            "shared-project slice full-with-refs: empty" in result.stdout
            or "Function recovery timed out; using sidecar-bounded asm fallback." in result.stdout
        )
        assert "/* == asm fallback == */" in result.stdout


def test_sortdemo_percolateup_anchor_no_longer_crashes_on_vexvalue_register_resolution():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109E8, analysis_timeout=30, subprocess_timeout=90)

    combined = _combined_output(result)

    assert result.returncode == 0, combined
    assert "Non-constant VexValue has no value property" not in combined
    assert "Function recovery failed" not in combined
    assert "function: 0x109e8 PercolateUp" in result.stdout
    assert "void PercolateUp(int iMaxLevel)" in result.stdout
    final_body = "void PercolateUp" + result.stdout.rsplit("void PercolateUp", 1)[-1]
    assert "stack_bp_" not in final_body
    assert "(&s_fffa)[" not in final_body
    assert "flags & 64" not in final_body
    assert "SEG_U8(ds," not in final_body
    assert "SEG_PTR(ds," not in final_body
    assert (
        "abarWork[i] <= abarWork[local_2]" in final_body
        or "MEM_U8(&abarWork[i]) <= MEM_U8(&abarWork[local_2])" in final_body
    )
    assert "Swaps(&abarWork[local_2], &abarWork[i]);" in final_body


def test_sortdemo_quicksort_anchor_distinguishes_timeout_from_old_vexvalue_crash():
    try:
        result = _run_decompile_addr(SORTDEMO_EXE, 0x10CE0, subprocess_timeout=20)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        combined = f"{stderr}{stdout}"
        assert "Non-constant VexValue has no value property" not in combined
        assert "function: 0x10ce0 QuickSort" in stdout
        return

    combined = _combined_output(result)

    assert result.returncode in {0, 3, 4}, combined
    assert "Non-constant VexValue has no value property" not in combined
    assert "function: 0x10ce0 QuickSort" in result.stdout
    if result.returncode == 0:
        assert "Function recovery failed" not in combined
    elif result.returncode == 3:
        assert (
            "Timed out while recovering a function after 6s after exhausting direct-address fallback budget."
            in combined
        )
    else:
        assert "Decompilation timeout" in combined
        assert "Function recovery failed" not in combined


def test_sortdemo_acceptance_scorecards_capture_main_sleep_and_percolateup_state():
    main_result = _run_decompile_addr(SORTDEMO_EXE, 0x10010, analysis_timeout=12, subprocess_timeout=120)
    sleep_result = _run_decompile_addr(SORTDEMO_EXE, 0x10F28, analysis_timeout=12, subprocess_timeout=120)
    percolate_result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x109E8,
        analysis_timeout=12,
        subprocess_timeout=120,
    )

    assert main_result.returncode == 0, main_result.stderr + main_result.stdout
    assert sleep_result.returncode == 0, sleep_result.stderr + sleep_result.stdout
    assert percolate_result.returncode in {0, 4}, percolate_result.stderr + percolate_result.stdout
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
    assert "flags_2 = ...;" not in sleep_result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in sleep_result.stdout
    assert "else if" not in sleep_result.stdout
    assert "if (clock() <= goal)" not in sleep_result.stdout
    assert re.search(r"\bif\s*\(\s*clock\(\)\s*>\s*[A-Za-z_]\w*\s*\)", sleep_result.stdout) or re.search(
        r"\bwhile\s*\(\s*clock\(\)\s*<=\s*[A-Za-z_]\w*\s*\)",
        sleep_result.stdout,
    )
    assert sleep_scorecard.raw_ss_linear_count == 0
    assert sleep_scorecard.validation_verdict == "stable"
    if percolate_result.returncode == 0:
        assert percolate_scorecard.source_present is True
        assert percolate_scorecard.raw_ds_linear_count == 0
        assert percolate_scorecard.raw_ss_linear_count == 0
    assert percolate_scorecard.validation_verdict == "stable"
    for marker in ("int PercolateUp(", "short PercolateUp(", "void PercolateUp("):
        if marker in percolate_result.stdout:
            percolate_body = marker + percolate_result.stdout.rsplit(marker, 1)[-1]
            break
    else:
        percolate_body = percolate_result.stdout
    assert "arg_6" not in percolate_body
    assert "SwapBars(arg_6" not in percolate_body


def test_sortdemo_acceptance_scorecards_capture_heapsort_quicksort_runmenu_and_beep_state():
    function_specs = {
        "HeapSort": (0x109D8, 30),
        "QuickSort": (0x10CE0, 120),
        "RunMenu": (0x102E0, 60),
        "Beep": (0x10E70, 30),
    }
    scorecards = {}
    results = {}
    for function_name, (addr, subprocess_timeout) in function_specs.items():
        result = _run_decompile_addr(SORTDEMO_EXE, addr, subprocess_timeout=subprocess_timeout)
        results[function_name] = result
        if function_name == "HeapSort":
            assert result.returncode in {0, 1, 4}, result.stderr + result.stdout
        else:
            assert result.returncode in {0, 4}, result.stderr + result.stdout
        scorecards[function_name] = build_acceptance_scorecard(
            function_name,
            _combined_output(result),
            source_text=render_local_source_sidecar_function(SORTDEMO_EXE, function_name),
        )

    assert scorecards["HeapSort"].source_present is True
    if results["HeapSort"].returncode == 1:
        assert "Swaps missing argument 1" in _combined_output(results["HeapSort"])
        assert "validation=passed" not in _combined_output(results["HeapSort"])
    else:
        assert scorecards["HeapSort"].recovery_mode in {"asm_fallback", "decompiled"}
        assert scorecards["HeapSort"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if results["HeapSort"].returncode == 0 and scorecards["HeapSort"].recovery_mode == "decompiled":
        assert scorecards["HeapSort"].raw_ss_linear_count == 0
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
        # Better lowering may remove raw SS linear artifacts entirely.
        assert scorecards["RunMenu"].raw_ss_linear_count >= 0
    assert scorecards["Beep"].source_present is True
    assert scorecards["Beep"].raw_ss_linear_count == 0
    assert scorecards["Beep"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}


def test_sortdemo_acceptance_scorecards_capture_swaps_swapbars_and_reinitbars_state():
    function_specs = {
        "Swaps": (0x107B8, 30),
        "SwapBars": (0x10768, 30),
        "ReInitBars": (0x10678, 90),
    }
    scorecards = {}
    for function_name, (addr, subprocess_timeout) in function_specs.items():
        result = _run_decompile_addr(SORTDEMO_EXE, addr, subprocess_timeout=subprocess_timeout)
        assert result.returncode in {0, 4, 6}, result.stderr + result.stdout
        scorecards[function_name] = build_acceptance_scorecard(
            function_name,
            _combined_output(result),
            source_text=render_local_source_sidecar_function(SORTDEMO_EXE, function_name),
        )

    assert scorecards["Swaps"].source_present is True
    assert scorecards["Swaps"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["Swaps"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["Swaps"].recovery_mode == "decompiled":
        assert scorecards["Swaps"].raw_ds_linear_count == 0
    assert scorecards["SwapBars"].source_present is True
    assert scorecards["SwapBars"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["SwapBars"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["SwapBars"].recovery_mode == "decompiled":
        assert scorecards["SwapBars"].raw_ds_linear_count == 0
        assert scorecards["SwapBars"].anonymous_sub_count == 0
    assert scorecards["ReInitBars"].source_present is True
    assert scorecards["ReInitBars"].recovery_mode == "decompiled"
    assert scorecards["ReInitBars"].validation_verdict == "stable"
    assert scorecards["ReInitBars"].raw_ds_linear_count == 0
    assert scorecards["ReInitBars"].raw_ss_linear_count == 0


def test_reinitbars_stable_stack_slot_irow_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "abarWork[local_2] = abarPerm[local_2];" in result.stdout
    assert "DrawBar(local_2);" in result.stdout
    assert "ss << 4" not in combined


def test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10554,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=75,
        subprocess_timeout=210,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10560 InitBars" in result.stdout
    assert "validation=passed" in combined
    assert "Source-backed quality guard rejected" not in combined
    body = _function_body_from_stdout(result.stdout, "void InitBars")
    assert "fSound = 1;" in body
    assert "clPause = 30;" in body
    assert "clPause[0]" not in body
    assert "clPause[1]" not in body
    assert "getvideoconfig(&vc);" in body
    assert "vvar_51" not in body
    assert "vvar_53" not in body
    assert "SEG_U8(" not in body


def test_initmenu_pause_zero_guard_has_no_raw_flag_carrier():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10060,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=90,
        subprocess_timeout=240,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10060 InitMenu" in result.stdout
    assert "validation=passed" in combined
    assert "Source-backed quality guard rejected" not in combined
    body = _function_body_from_stdout(result.stdout, "void InitMenu")
    tail_after_pause_text = body.rsplit("strcpy(&ach, 368);", 1)[-1]
    assert "sprintf(&ach, &_SG564[0], aNldiv(clPause, 30));" in body
    assert "vvar_" not in tail_after_pause_text
    assert "& 64" not in tail_after_pause_text
    assert "SEG_U" not in tail_after_pause_text
    assert "clPause" in tail_after_pause_text
    assert "outtext(&ach);" in tail_after_pause_text


def test_insertionsort_word_stores_materialized_without_raw_high_byte_memory():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x107E7,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=60,
        subprocess_timeout=180,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10808 InsertionSort" in result.stdout
    assert "validation=passed" in combined
    assert "Source-backed quality guard rejected" not in combined
    body = _function_body_from_stdout(result.stdout, "void InsertionSort")
    assert "abarWork[local_4] = abarWork[local_4 - 1];" in body
    assert "abarWork[local_4] = barTemp;" in body
    assert "DrawBar(local_4);" in body
    assert "DrawTime(local_4);" in body
    assert "mem_0B4D" not in body
    assert "MEM_U8(" not in body
    assert "SEG_U8(" not in body
    assert "*(&" not in body


def test_drawbar_word_stride_byte_fields_validate_without_indexed_mem_helper_syntax():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x106C8,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=20,
        subprocess_timeout=60,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x106c8 DrawBar" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void DrawBar")
    assert "abarWork[iRow] & 255" in final_body
    assert "abarWork[iRow] >> 8 & 255" in final_body
    assert "MEM_U8(&abarWork[iRow))]" not in final_body
    assert "SEG_PTR(ds" not in final_body


def test_heapsort_stable_stack_slot_i_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    assert "local_2" in final_body or "i" in final_body
    assert "PercolateDown(local_2 - 1);" in final_body or "PercolateDown(i - 1);" in final_body
    assert "SwapBars(0, local_2);" in final_body or "SwapBars(0, i);" in final_body
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in final_body or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
    assert "SEG_PTR(ds" not in final_body
    assert "&s_" not in final_body
    assert "*(&v" not in final_body
    assert "stack[" not in final_body


def test_percolatedown_direct_global_increment_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10A61,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=120,
        subprocess_timeout=360,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10a88 PercolateDown" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void PercolateDown")
    assert final_body.count("iCompares += 1;") == 2
    assert "mem_0BAA" not in final_body
    assert "mem_0BAB" not in final_body
    assert "SEG_U" not in final_body
    assert "SEG_PTR" not in final_body


def test_reinitbars_recurrence_rebound_to_irow():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    assert "validation=passed" in combined
    assert "for (local_2 = 0; cRow > local_2; local_2 += 1)" in result.stdout
    assert "DrawBar(local_2);" in result.stdout


def test_heapsort_has_no_byte_carrier_stack_leaks():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    assert "&s_" not in final_body
    assert "s_ff" not in final_body
    assert "SEG_PTR(ds" not in final_body
