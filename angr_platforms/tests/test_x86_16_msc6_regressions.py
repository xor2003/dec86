from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CMP16_EXE = REPO_ROOT / "examples" / "build_msc6" / "CMP16.EXE"
CLI_PATH = REPO_ROOT / "decompile.py"


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


def _extract_emitted_function_8616(stdout: str, function_name: str) -> str:
    emitted = stdout
    if "/* == c == */" in emitted:
        emitted = emitted.split("/* == c == */", 1)[-1]
    signature = f"int {function_name}("
    start = emitted.find(signature)
    if start < 0:
        return ""
    function_text = emitted[start:]
    end = function_text.find("\n}\n")
    return function_text if end < 0 else function_text[: end + 3]


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
def test_msc6_cmp16_rel_i16_keeps_recovered_signature_and_avoids_implicit_arg_placeholders() -> None:
    result = _run_decompile_proc("rel_i16", proc_kind="NEAR")
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined

    emitted_body = _extract_emitted_function_8616(result.stdout, "rel_i16")
    assert emitted_body, combined
    assert "int rel_i16(int a, int b)" in emitted_body
    assert not re.search(r"\barg_[0-9]+\b", emitted_body), emitted_body
    assert not re.search(r"\bs_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert not re.search(r"\b(?:sp|bp)_0\b", emitted_body), emitted_body
    assert not re.search(r"\b(ir|vvar)_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert "return" in emitted_body and "return;" not in emitted_body
    assert "return mask;" in emitted_body
