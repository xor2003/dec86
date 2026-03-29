from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import io
import subprocess
import tempfile
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


def _decompile_subset_case(case: RecompilableSubsetCase) -> str:
    project = _project_from_asm(case.asm)
    cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[0x1000], normalize=True)
    func = cfg.functions[min(cfg.functions.keys())]
    dec = project.analyses.Decompiler(func, cfg=cfg)
    if dec.codegen is None:
        raise RuntimeError(f"{case.name} did not produce codegen")
    return dec.codegen.text


def _syntax_check_c_text(c_text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tmp:
        path = Path(tmp.name)
        tmp.write(c_text)
    try:
        return subprocess.run(
            ["gcc", "-fsyntax-only", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        path.unlink(missing_ok=True)


def run_x86_16_recompilable_subset_syntax_checks() -> tuple[dict[str, object], ...]:
    results = []
    for case in _RECOMPILABLE_SUBSET_CASES:
        c_text = _decompile_subset_case(case)
        proc = _syntax_check_c_text(c_text)
        results.append(
            {
                "name": case.name,
                "expected_kind": case.expected_kind,
                "returncode": proc.returncode,
                "stderr": proc.stderr,
                "syntax_ok": proc.returncode == 0,
            }
        )
    return tuple(results)
