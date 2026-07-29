from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CMP16_EXE = REPO_ROOT / "examples" / "build_msc6" / "CMP16.EXE"
CMP32_EXE = REPO_ROOT / "examples" / "build_msc6" / "COMP32.EXE"
FPTR_EXE = REPO_ROOT / "examples" / "build_msc6" / "FPTR.EXE"
SIMPLE_EXE = REPO_ROOT / "examples" / "build_msc6" / "SIMPLE.EXE"
LOOPS_EXE = REPO_ROOT / "examples" / "build_msc6" / "LOOPS.EXE"
POINT_EXE = REPO_ROOT / "examples" / "build_msc6" / "POINT.EXE"
TYPES_EXE = REPO_ROOT / "examples" / "build_msc6" / "TYPES.EXE"
CLI_PATH = REPO_ROOT / "decompile.py"
RUNTIME_GATE_PATH = REPO_ROOT / "scripts" / "verify_msc_example_runtime_gate.py"
KVIKDOS_PATH = Path("/home/xor/kvikdos/kvikdos")
MSC6_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")


def _run_decompile_proc(
    function_name: str,
    *,
    proc_kind: str = "NEAR",
    exe_path: Path = CMP16_EXE,
    timeout: int = 90,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--alternate-source-c",
            "--proc",
            function_name,
            "--proc-kind",
            proc_kind,
            "--timeout",
            "60",
            str(exe_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def _run_decompile_addr(
    addr: str,
    *,
    timeout: int = 90,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_ENABLE_REBASED_EXACT_SLICE", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--alternate-source-c",
            "--addr",
            addr,
            "--timeout",
            "60",
            str(CMP16_EXE),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def _extract_emitted_function_8616(output: str, function_name: str) -> str:
    emitted = output
    if "/* == c == */" in emitted:
        emitted = emitted.split("/* == c == */", 1)[-1]
    signature_match = None
    for match in re.finditer(rf"(?m)^[^\n;]*\b{re.escape(function_name)}\s*\([^;\n]*\)", emitted):
        suffix = emitted[match.end() : match.end() + 128]
        if "{" in suffix.split(";", 1)[0]:
            signature_match = match
            break
    if signature_match is None:
        return ""
    start = signature_match.start()
    function_text = emitted[start:]
    end = function_text.find("\n}\n")
    return function_text if end < 0 else function_text[: end + 3]


def _combined_output_8616(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stderr}{result.stdout}"


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
def test_msc6_cmp16_rel_i16_keeps_recovered_signature_and_avoids_implicit_arg_placeholders() -> None:
    result = _run_decompile_proc("rel_i16", proc_kind="NEAR")
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined

    emitted_body = _extract_emitted_function_8616(combined, "rel_i16")
    assert emitted_body, combined
    assert re.search(r"\b(?:int|short)\s+rel_i16\((?:int|short)\s+a,\s+(?:int|short)\s+b\)", emitted_body), (
        emitted_body
    )
    assert "unsigned short a" not in emitted_body
    assert "unsigned short b" not in emitted_body
    assert not re.search(r"\barg_[0-9]+\b", emitted_body), emitted_body
    assert not re.search(r"\bs_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert not re.search(r"\b(?:sp|bp)_0\b", emitted_body), emitted_body
    assert not re.search(r"\b(ir|vvar)_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert "return" in emitted_body and "return;" not in emitted_body
    assert "mask * 0x100" not in emitted_body
    assert ">> 8" not in emitted_body
    for fragment in (
        "if (b > a)",
        "mask |= 1;",
        "if (b >= a)",
        "mask |= 2;",
        "if (b < a)",
        "mask |= 4;",
        "if (b <= a)",
        "mask |= 8;",
    ):
        assert fragment in emitted_body, emitted_body
    assert "return mask;" in emitted_body


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
def test_msc6_cmp16_main_preserves_all_guarded_return_chain_values() -> None:
    result = _run_decompile_addr("0x101a7")
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted = combined.split("/* == c == */", 1)[-1]
    emitted_without_source_comments = "\n".join(
        line for line in emitted.splitlines() if not line.lstrip().startswith("///")
    )
    for value in range(1, 14):
        assert f"return {value};" in emitted_without_source_comments, emitted_without_source_comments
    assert "return 255;" in emitted_without_source_comments, emitted_without_source_comments
    assert "::0x" not in emitted_without_source_comments
    assert "cmp_i16(" in emitted_without_source_comments
    assert "rel_i16(" in emitted_without_source_comments
    assert "rel_u16(" in emitted_without_source_comments
    assert "clamp_u16(" in emitted_without_source_comments
    assert "in_window_i16(" in emitted_without_source_comments


@pytest.mark.skipif(not SIMPLE_EXE.is_file(), reason="SIMPLE example binary is not available in this workspace.")
def test_msc6_simple_switch_fold_direct_output_uses_source_argument_identity() -> None:
    result = _run_decompile_proc("switch_fold", proc_kind="NEAR", exe_path=SIMPLE_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "switch_fold")
    assert emitted_body, combined
    assert "int switch_fold(int x)" in emitted_body
    assert "if (!x)" in emitted_body
    assert "return x - 5;" in emitted_body
    assert "return x + 20;" in emitted_body
    assert "return x << 1;" in emitted_body
    assert not re.search(r"\b(?:arg|local)_4\b", emitted_body), emitted_body


@pytest.mark.skipif(not TYPES_EXE.is_file(), reason="TYPES example binary is not available in this workspace.")
def test_msc6_scalar_add_sc_keeps_byte_arg_source_identity_through_cli_regeneration() -> None:
    result = _run_decompile_proc("add_sc", proc_kind="NEAR", exe_path=TYPES_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "MS C 5.1 msc-dos syntax check failed" not in combined

    emitted_body = _extract_emitted_function_8616(combined, "add_sc")
    assert emitted_body, combined
    assert "signed char add_sc(signed char a, signed char b)" in emitted_body
    assert "return b + a;" in emitted_body or "return a + b;" in emitted_body
    assert not re.search(r"\b[A-Za-z_]\w*_[0-9]+\b", emitted_body), emitted_body


@pytest.mark.skipif(not TYPES_EXE.is_file(), reason="TYPES example binary is not available in this workspace.")
def test_msc6_scalar_sub_ulong_consumes_stack_probe_prologue_artifacts() -> None:
    result = _run_decompile_proc("sub_ulong", proc_kind="NEAR", exe_path=TYPES_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "MS C 5.1 msc-dos syntax check failed" not in combined

    emitted_body = _extract_emitted_function_8616(combined, "sub_ulong")
    assert emitted_body, combined
    assert "unsigned long sub_ulong(unsigned long a, unsigned long b)" in emitted_body
    assert "return a - b;" in emitted_body
    assert "sub_105ba" not in emitted_body
    assert "aNchkstk" not in emitted_body
    assert "a = &" not in emitted_body
    assert "v2" not in emitted_body
    assert "vvar_2" not in emitted_body


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
@pytest.mark.parametrize(
    ("function_name", "required_fragments"),
    [
        ("cmp_i16", ("return -1;", "return 1;", "return 0;", "return 2;", " == ")),
        (
            "rel_i16",
            (
                "if (b > a)",
                "mask |= 1;",
                "if (b >= a)",
                "mask |= 2;",
                "if (b < a)",
                "mask |= 4;",
                "if (b <= a)",
                "mask |= 8;",
                "return mask;",
            ),
        ),
        (
            "rel_u16",
            (
                "if (b > a)",
                "mask |= 1;",
                "if (b >= a)",
                "mask |= 2;",
                "if (b < a)",
                "mask |= 4;",
                "if (b <= a)",
                "mask |= 8;",
                "return mask;",
            ),
        ),
        ("clamp_u16", ("return value;", "return limit;")),
        ("in_window_i16", ("return 0;", "return 1;")),
    ],
)
def test_msc6_cmp16_all_helper_functions_pass_tail_validation_and_msc_recompile(
    function_name: str,
    required_fragments: tuple[str, ...],
) -> None:
    result = _run_decompile_proc(function_name, proc_kind="NEAR")
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "MS C 5.1 msc-dos syntax check failed" not in combined

    emitted_body = _extract_emitted_function_8616(combined, function_name)
    assert emitted_body, combined
    assert not re.search(r"\b[A-Za-z_]\w*_2\b", emitted_body), emitted_body
    assert not re.search(r"\barg_[0-9]+\b", emitted_body), emitted_body
    assert not re.search(r"\bs_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert "::0x" not in emitted_body
    assert "mask * 0x100" not in emitted_body
    assert ">> 8" not in emitted_body
    for fragment in required_fragments:
        assert fragment in emitted_body, emitted_body


@pytest.mark.skipif(not FPTR_EXE.is_file(), reason="FPTR example binary is not available in this workspace.")
def test_msc6_fptr_select_and_apply_materializes_branch_function_pointer_targets() -> None:
    result = _run_decompile_proc("select_and_apply", proc_kind="NEAR", exe_path=FPTR_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "select_and_apply")
    assert emitted_body, combined
    assert re.match(r"unsigned short\s+select_and_apply\s*\(", emitted_body), emitted_body
    assert "fn = inc_one;" in emitted_body
    assert "fn = dec_one;" in emitted_body
    assert "fn = which;" not in emitted_body
    assert "return apply_twice(fn, value);" in emitted_body


@pytest.mark.skipif(not FPTR_EXE.is_file(), reason="FPTR example binary is not available in this workspace.")
@pytest.mark.parametrize(
    ("function_name", "required_fragment"),
    [
        ("inc_one", "return value + 1;"),
        ("dec_one", "return value - 1;"),
    ],
)
def test_msc6_fptr_leaf_functions_materialize_terminal_ax_returns(
    function_name: str,
    required_fragment: str,
) -> None:
    result = _run_decompile_proc(function_name, proc_kind="NEAR", exe_path=FPTR_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, function_name)
    assert emitted_body, combined
    assert required_fragment in emitted_body
    assert "return;" not in emitted_body


@pytest.mark.skipif(not FPTR_EXE.is_file(), reason="FPTR example binary is not available in this workspace.")
def test_msc6_fptr_apply_twice_consumes_stack_probe_call_artifacts() -> None:
    result = _run_decompile_proc("apply_twice", proc_kind="NEAR", exe_path=FPTR_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "apply_twice")
    assert emitted_body, combined
    assert "apply_twice(" in emitted_body
    assert "fn" in emitted_body
    assert "value" in emitted_body
    assert emitted_body.count("fn(value)") == 2
    assert "return value;" in emitted_body
    assert "chkstk" not in emitted_body.lower()
    assert "SEG_U" not in emitted_body
    assert "local_2 =" not in emitted_body
    assert "v2 = fn" not in emitted_body
    assert "v4 =" not in emitted_body


@pytest.mark.skipif(not LOOPS_EXE.is_file(), reason="LOOPS example binary is not available in this workspace.")
def test_msc6_loops_nested_materializes_stack_counter_loop() -> None:
    result = _run_decompile_proc("nested_loops", proc_kind="NEAR", exe_path=LOOPS_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "nested_loops")
    assert emitted_body, combined
    assert "while (i < limit)" in emitted_body
    assert "do" in emitted_body
    assert "continue;" in emitted_body
    assert "break;" in emitted_body
    assert "return total;" in emitted_body
    assert "stack_base" not in emitted_body
    assert "SEG_U" not in emitted_body


@pytest.mark.skipif(not POINT_EXE.is_file(), reason="POINT example binary is not available in this workspace.")
def test_msc6_pointer_swap_preserves_loaded_temp_across_pointer_store() -> None:
    result = _run_decompile_proc("swap_ptrs", proc_kind="NEAR", exe_path=POINT_EXE)
    combined = _combined_output_8616(result)

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "swap_ptrs")
    assert emitted_body, combined
    assert "left[0] = right[0];" in emitted_body
    assert "right[0] = local_2;" in emitted_body or "right[0] = tmp;" in emitted_body
    assert "right[0] = left[0];" not in emitted_body


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
@pytest.mark.skipif(not KVIKDOS_PATH.is_file(), reason="kvikdos is not available in this workspace.")
@pytest.mark.skipif(not MSC6_ROOT.is_dir(), reason="MS C 6 root is not available in this workspace.")
@pytest.mark.parametrize(
    ("example_name", "exe_path"),
    [
        ("simple_control", SIMPLE_EXE),
        ("cmp16", CMP16_EXE),
        ("cmp32", CMP32_EXE),
        ("fptr", FPTR_EXE),
        ("loops_jumps", LOOPS_EXE),
        ("pointer_memory", POINT_EXE),
        ("scalar_types_io", TYPES_EXE),
    ],
)
def test_msc6_rebuilt_comparison_executable_runs_success_sentinel(
    tmp_path: Path,
    example_name: str,
    exe_path: Path,
) -> None:
    if not exe_path.is_file():
        pytest.skip(f"{example_name} example binary is not available in this workspace.")

    result = subprocess.run(
        [
            sys.executable,
            str(RUNTIME_GATE_PATH),
            "--example",
            example_name,
            "--expected-exit-code",
            "255",
            "--timeout",
            "60",
            "--out-dir",
            str(tmp_path / f"{example_name}_runtime_gate"),
            "--clean",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    combined = f"{result.stderr}\n{result.stdout}"
    assert result.returncode == 0, combined
    assert "status=passed" in combined
    assert "run_exit=255" in combined
