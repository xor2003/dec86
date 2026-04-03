from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import io
import subprocess
import tempfile
import sys
from typing import Final

import angr
import keystone as ks

from .arch_86_16 import Arch86_16

__all__ = [
    "RecompilableSubsetCase",
    "describe_x86_16_recompilable_subset",
    "run_x86_16_recompilable_subset_syntax_checks",
]


@dataclass(frozen=True)
class RecompilableSubsetCase:
    name: str
    asm: str
    expected_kind: str
    note: str
    cod_path: Path | None = None
    proc_name: str | None = None
    proc_kind: str = "NEAR"
    expected_c_anchors: tuple[str, ...] = ()
    forbidden_c_anchors: tuple[str, ...] = ()


_RECOMPILABLE_SUBSET_CASES: Final[tuple[RecompilableSubsetCase, ...]] = (
    RecompilableSubsetCase(
        name="mov_add_ret",
        asm="mov ax,1; add ax,2; ret",
        expected_kind="trivial arithmetic",
        note="Minimal body that currently compiles to an empty translation unit body.",
    ),
    RecompilableSubsetCase(
        name="enter_stack",
        asm="enter 2, 0; mov word ptr [bp-2], 1; mov ax, [bp-2]; leave; ret",
        expected_kind="stack local",
        note="Preserves a stack local and compiles as syntax-valid C.",
    ),
    RecompilableSubsetCase(
        name="xor_ret",
        asm="xor ax,ax; ret",
        expected_kind="simple zeroing",
        note="A tiny zeroing body that decompiles to syntax-valid C.",
    ),
    RecompilableSubsetCase(
        name="push_pop_ret",
        asm="push ax; pop ax; ret",
        expected_kind="stack roundtrip",
        note="A tiny stack round-trip that remains syntax-valid after decompilation.",
    ),
    RecompilableSubsetCase(
        name="strlen_real",
        asm="",
        expected_kind="real recovered loop",
        note="Live repaired STRLEN.COD output for _strlen, used as a recompilation anchor.",
        cod_path=Path(__file__).resolve().parents[3] / "cod" / "default" / "STRLEN.COD",
        proc_name="_strlen",
    ),
    RecompilableSubsetCase(
        name="loadprog_real",
        asm="",
        expected_kind="real recovered DOS helper",
        note="Live repaired DOSFUNC.COD output for loadprog, used as a recompilation anchor.",
        cod_path=Path(__file__).resolve().parents[3] / "cod" / "DOSFUNC.COD",
        proc_name="loadprog",
    ),
    RecompilableSubsetCase(
        name="dos_loadOverlay_real",
        asm="",
        expected_kind="real recovered DOS helper",
        note="Live repaired DOSFUNC.COD output for _dos_loadOverlay, used as a recompilation anchor.",
        cod_path=Path(__file__).resolve().parents[3] / "cod" / "DOSFUNC.COD",
        proc_name="_dos_loadOverlay",
        expected_c_anchors=(
            "int _dos_loadOverlay(const char *file, const unsigned short segment)",
            "return loadprog(file, segment, DOS_LOAD_OVL, NULL);",
        ),
        forbidden_c_anchors=("return;",),
    ),
)


def describe_x86_16_recompilable_subset() -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "name": case.name,
            "expected_kind": case.expected_kind,
            "note": case.note,
        }
        for case in _RECOMPILABLE_SUBSET_CASES
    )


def _project_from_asm(asm: str) -> angr.Project:
    ks_ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_16)
    code, _ = ks_.asm(asm, as_bytes=True)
    return angr.Project(
        io.BytesIO(bytes(code)),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _extract_c_text_from_cli_output(stdout: str) -> str:
    marker = "/* == c == */"
    if marker not in stdout:
        raise RuntimeError("did not find generated C section in CLI output")
    return stdout.split(marker, 1)[1].lstrip("\n")


def _compat_syntax_prelude() -> str:
    return """#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef union REGS {
    struct {
        unsigned char al;
        unsigned char ah;
        unsigned char bl;
        unsigned char bh;
        unsigned char cl;
        unsigned char ch;
        unsigned char dl;
        unsigned char dh;
    } h;
    struct {
        unsigned short ax;
        unsigned short bx;
        unsigned short cx;
        unsigned short dx;
        unsigned short cflag;
        unsigned short si;
        unsigned short di;
        unsigned short flags;
        unsigned short es;
        unsigned short ds;
    } x;
} REGS;

static inline uintptr_t MK_FP(unsigned short seg, unsigned short off) {
    return ((uintptr_t)seg << 4) + off;
}

static inline int intdos(union REGS *in, union REGS *out) {
    (void)in;
    (void)out;
    return 0;
}

#define DOSF_ALLOCMEM 0
#define DOSF_LOADPROG 0x4b
#define DOS_LOAD_OVL 3
#define ERROR(...) do { } while (0)
"""


def _write_c_text_tempfile(c_text: str) -> Path:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tmp:
        path = Path(tmp.name)
        tmp.write(_compat_syntax_prelude())
        tmp.write("\n")
        tmp.write(c_text)
    return path


def _decompile_corpus_case(case: RecompilableSubsetCase) -> str:
    if case.cod_path is None or case.proc_name is None:
        raise ValueError("expected a corpus-backed case")

    proc = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parents[3] / "decompile.py"),
            str(case.cod_path),
            "--proc",
            case.proc_name,
            "--timeout",
            "20",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    return _extract_c_text_from_cli_output(proc.stdout)


def _decompile_subset_case(case: RecompilableSubsetCase) -> str:
    if case.cod_path is not None:
        return _decompile_corpus_case(case)
    project = _project_from_asm(case.asm)
    cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[0x1000], normalize=True)
    func = cfg.functions[min(cfg.functions.keys())]
    dec = project.analyses.Decompiler(func, cfg=cfg)
    if dec.codegen is None:
        raise RuntimeError(f"{case.name} did not produce codegen")
    return dec.codegen.text


def _syntax_check_c_text(c_text: str) -> subprocess.CompletedProcess[str]:
    path = _write_c_text_tempfile(c_text)
    try:
        return subprocess.run(
            ["gcc", "-std=c11", "-fsyntax-only", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        path.unlink(missing_ok=True)


def _compile_c_text(c_text: str) -> subprocess.CompletedProcess[str]:
    path = _write_c_text_tempfile(c_text)
    obj_path = path.with_suffix(".o")
    try:
        return subprocess.run(
            ["gcc", "-std=c11", "-c", "-o", str(obj_path), str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        path.unlink(missing_ok=True)
        obj_path.unlink(missing_ok=True)


def _check_c_text_shape(c_text: str, case: RecompilableSubsetCase) -> dict[str, object]:
    missing = tuple(anchor for anchor in case.expected_c_anchors if anchor not in c_text)
    forbidden = tuple(anchor for anchor in case.forbidden_c_anchors if anchor in c_text)
    return {
        "shape_ok": not missing and not forbidden,
        "shape_missing": missing,
        "shape_forbidden": forbidden,
    }


def run_x86_16_recompilable_subset_syntax_checks() -> tuple[dict[str, object], ...]:
    results = []
    for case in _RECOMPILABLE_SUBSET_CASES:
        c_text = _decompile_subset_case(case)
        proc = _syntax_check_c_text(c_text)
        compile_proc = _compile_c_text(c_text)
        shape = _check_c_text_shape(c_text, case)
        results.append(
            {
                "name": case.name,
                "expected_kind": case.expected_kind,
                "returncode": proc.returncode,
                "stderr": proc.stderr,
                "syntax_ok": proc.returncode == 0,
                "compile_returncode": compile_proc.returncode,
                "compile_stderr": compile_proc.stderr,
                "compile_ok": compile_proc.returncode == 0,
                **shape,
            }
        )
    return tuple(results)
