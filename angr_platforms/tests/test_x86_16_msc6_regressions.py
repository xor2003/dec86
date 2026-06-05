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
CLI_PATH = REPO_ROOT / "decompile.py"
RUNTIME_GATE_PATH = REPO_ROOT / "scripts" / "verify_msc_example_runtime_gate.py"
KVIKDOS_PATH = Path("/home/xor/kvikdos/kvikdos")
MSC6_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")


def _run_decompile_proc(
    function_name: str,
    *,
    proc_kind: str = "NEAR",
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
            str(CMP16_EXE),
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
    signature = f"int {function_name}("
    start = emitted.find(signature)
    if start < 0:
        return ""
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
    assert "int rel_i16(int a, int b)" in emitted_body
    assert not re.search(r"\barg_[0-9]+\b", emitted_body), emitted_body
    assert not re.search(r"\bs_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert not re.search(r"\b(?:sp|bp)_0\b", emitted_body), emitted_body
    assert not re.search(r"\b(ir|vvar)_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert "return" in emitted_body and "return;" not in emitted_body
    assert "mask * 0x100" not in emitted_body
    assert ">> 8" not in emitted_body
    for fragment in (
        "if (b > a)",
        "mask = mask | 1;",
        "if (b >= a)",
        "mask = mask | 2;",
        "if (b < a)",
        "mask = mask | 4;",
        "if (b <= a)",
        "mask = mask | 8;",
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


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
@pytest.mark.parametrize(
    ("function_name", "required_fragments"),
    [
        ("cmp_i16", ("return -1;", "return 1;", "return 0;", "return 2;", " == ")),
        (
            "rel_i16",
            (
                "if (b > a)",
                "mask = mask | 1;",
                "if (b >= a)",
                "mask = mask | 2;",
                "if (b < a)",
                "mask = mask | 4;",
                "if (b <= a)",
                "mask = mask | 8;",
                "return mask;",
            ),
        ),
        (
            "rel_u16",
            (
                "if (b > a)",
                "mask = mask | 1;",
                "if (b >= a)",
                "mask = mask | 2;",
                "if (b < a)",
                "mask = mask | 4;",
                "if (b <= a)",
                "mask = mask | 8;",
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


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
@pytest.mark.skipif(not KVIKDOS_PATH.is_file(), reason="kvikdos is not available in this workspace.")
@pytest.mark.skipif(not MSC6_ROOT.is_dir(), reason="MS C 6 root is not available in this workspace.")
@pytest.mark.parametrize(
    ("example_name", "exe_path"),
    [
        ("cmp16", CMP16_EXE),
        ("cmp32", CMP32_EXE),
        ("fptr", FPTR_EXE),
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
