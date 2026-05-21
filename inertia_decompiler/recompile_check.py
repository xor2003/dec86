from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616


def _sanitize_nested_block_comments(text: str) -> str:
    """Replace /* inside /* */ block comments to prevent -Werror=comment failures."""
    def _fix_inner(match):
        content = match.group(1)
        content = content.replace("/*", "/ *")
        return "/*" + content + "*/"
    return re.sub(r"/\*(.*?)\*/", _fix_inner, text, flags=re.DOTALL)


@dataclass(frozen=True, slots=True)
class RecompileCheckResult:
    passed: bool
    target: str
    exit_code: int
    compiler: str | None
    stdout: str
    stderr: str
    command: tuple[str, ...]
    source_path: str | None = None


def _with_runtime_header_8616(c_text: str, *, target: str) -> str:
    text = str(c_text or "")
    if target != "portable-flat":
        return text
    if "extern uint8_t inertia_memory[];" in text and "#define SEG_U8(seg, off)" in text:
        return text
    return f"{render_c_runtime_header_8616(target)}\n{text.lstrip()}"


def check_c_recompiles_8616(c_text: str, *, target: str = "portable-flat") -> RecompileCheckResult:
    compiler = shutil.which("gcc")
    if compiler is None:
        return RecompileCheckResult(
            passed=False,
            target=target,
            exit_code=127,
            compiler=None,
            stdout="",
            stderr="gcc not found",
            command=("gcc", "-std=c99", "-Wall", "-Werror", "-fsyntax-only"),
            source_path=None,
        )

    tmpdir = Path(tempfile.mkdtemp(prefix="inertia-recompile-"))
    src_path = tmpdir / "generated.c"
    src_path.write_text(_sanitize_nested_block_comments(_with_runtime_header_8616(c_text, target=target)), encoding="utf-8")
    command = (
        compiler,
        "-std=c99",
        "-Wall",
        "-Werror",
        "-Wno-error=unused-but-set-variable",
        "-Wno-error=parentheses",
        "-Wno-error=unused-variable",
        "-Wno-error=nonnull",
        "-Wno-error=builtin-declaration-mismatch",
        "-fsyntax-only",
        str(src_path),
    )
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        source_path = None
    else:
        source_path = str(src_path)
    return RecompileCheckResult(
        passed=proc.returncode == 0,
        target=target,
        exit_code=proc.returncode,
        compiler=compiler,
        stdout=proc.stdout,
        stderr=proc.stderr,
        command=command,
        source_path=source_path,
    )
