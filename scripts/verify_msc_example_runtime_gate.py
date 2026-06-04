#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_msc6_examples import (  # noqa: E402
    DEFAULT_KVIKDOS,
    DEFAULT_MSC6_ROOT,
    _compile_and_link,
    _run_example,
)

DEFAULT_DECOMPILE = REPO_ROOT / "decompile.py"
DEFAULT_BUILD_DIR = REPO_ROOT / "examples" / "build_msc6"
DEFAULT_OUT_DIR = DEFAULT_BUILD_DIR / "runtime_gate"


class RuntimeGateStage(Enum):
    DECOMPILE = auto()
    EXTRACT = auto()
    COMPILE = auto()
    LINK = auto()
    RUN = auto()


@dataclass(frozen=True)
class FunctionSpec:
    name: str
    proc_kind: str | None = None
    addr: str | None = None


@dataclass(frozen=True)
class ExampleSpec:
    name: str
    exe: Path
    output_stem: str
    functions: tuple[FunctionSpec, ...]


EXAMPLES: dict[str, ExampleSpec] = {
    "cmp16": ExampleSpec(
        name="cmp16",
        exe=DEFAULT_BUILD_DIR / "CMP16.EXE",
        output_stem="CMP16RT",
        functions=(
            FunctionSpec("cmp_i16", proc_kind="NEAR"),
            FunctionSpec("rel_i16", proc_kind="NEAR"),
            FunctionSpec("rel_u16", proc_kind="NEAR"),
            FunctionSpec("clamp_u16", proc_kind="NEAR"),
            FunctionSpec("in_window_i16", proc_kind="NEAR"),
            FunctionSpec("main", addr="0x101a7"),
        ),
    ),
    "cmp32": ExampleSpec(
        name="cmp32",
        exe=DEFAULT_BUILD_DIR / "COMP32.EXE",
        output_stem="CMP32RT",
        functions=(
            FunctionSpec("select_max", proc_kind="NEAR"),
            FunctionSpec("compare_signed", proc_kind="NEAR"),
            FunctionSpec("compare_unsigned", proc_kind="NEAR"),
            FunctionSpec("clamp_window", proc_kind="NEAR"),
            FunctionSpec("rel_signed32", proc_kind="NEAR"),
            FunctionSpec("rel_unsigned32", proc_kind="NEAR"),
            FunctionSpec("main", addr="0x10322"),
        ),
    ),
}


class RuntimeGateError(RuntimeError):
    def __init__(self, stage: RuntimeGateStage, message: str) -> None:
        self.stage = stage
        super().__init__(f"{stage.name.lower()}: {message}")


def _run_decompile(
    spec: FunctionSpec,
    *,
    exe_path: Path,
    decompile_py: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(decompile_py),
        "--alternate-source-c",
        "--timeout",
        str(timeout),
    ]
    if spec.addr is not None:
        cmd += ["--addr", spec.addr]
    else:
        cmd += ["--proc", spec.name, "--proc-kind", spec.proc_kind or "NEAR"]
    cmd.append(str(exe_path))

    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_ENABLE_REBASED_EXACT_SLICE", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout + 30,
        check=False,
    )


def _assert_valid_decompile(spec: FunctionSpec, proc: subprocess.CompletedProcess[str]) -> str:
    combined = f"{proc.stderr}\n{proc.stdout}"
    if proc.returncode != 0:
        raise RuntimeGateError(
            RuntimeGateStage.DECOMPILE,
            f"{spec.name} decompile exited {proc.returncode}\n{combined[-4000:]}",
        )
    if "[tail-validation] whole-tail validation clean across 1 functions" not in combined:
        raise RuntimeGateError(
            RuntimeGateStage.DECOMPILE,
            f"{spec.name} did not report clean tail validation\n{combined[-4000:]}",
        )
    reject_markers = (
        "whole-tail validation failed",
        "tail validation not collected",
        "tail_validation_failed",
        "MS C 5.1 msc-dos syntax check failed",
        "MS C 6.0 msc-dos syntax check failed",
        "== asm fallback ==",
        "Decompilation timeout",
    )
    for marker in reject_markers:
        if marker in combined:
            raise RuntimeGateError(
                RuntimeGateStage.DECOMPILE,
                f"{spec.name} has rejected marker {marker!r}\n{combined[-4000:]}",
            )
    return proc.stdout


def _find_function_definition(c_text: str, function_name: str) -> str:
    emitted = c_text.split("/* == c == */", 1)[-1] if "/* == c == */" in c_text else c_text
    name_re = re.escape(function_name)
    signature_re = re.compile(
        rf"(?m)^(?P<signature>(?:unsigned\s+)?(?:int|long|short|char|void)\s+\**{name_re}\s*\([^;{{)]*\))\s*\n+\s*\{{"
    )
    match = signature_re.search(emitted)
    if match is None:
        raise RuntimeGateError(RuntimeGateStage.EXTRACT, f"missing generated definition for {function_name}")

    brace_start = emitted.find("{", match.end("signature"))
    if brace_start < 0:
        raise RuntimeGateError(RuntimeGateStage.EXTRACT, f"missing opening brace for {function_name}")

    depth = 0
    for idx in range(brace_start, len(emitted)):
        ch = emitted[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return emitted[match.start("signature") : idx + 1].strip() + "\n"
    raise RuntimeGateError(RuntimeGateStage.EXTRACT, f"unterminated generated definition for {function_name}")


def _build_full_source(function_bodies: list[str]) -> str:
    return "\n".join(
        [
            "#include <stdbool.h>",
            "#include <stdint.h>",
            "",
            *function_bodies,
            "",
        ]
    )


def _verify_example(
    example: ExampleSpec,
    *,
    out_dir: Path,
    kvikdos: Path,
    msc6_root: Path,
    decompile_py: Path,
    expected_exit_code: int,
    timeout: int,
) -> Path:
    if not example.exe.is_file():
        raise RuntimeGateError(RuntimeGateStage.DECOMPILE, f"missing example executable: {example.exe}")
    if not kvikdos.is_file():
        raise RuntimeGateError(RuntimeGateStage.RUN, f"missing kvikdos executable: {kvikdos}")
    if not msc6_root.is_dir():
        raise RuntimeGateError(RuntimeGateStage.COMPILE, f"missing MS C 6 root: {msc6_root}")

    out_dir.mkdir(parents=True, exist_ok=True)
    bodies: list[str] = []
    for function in example.functions:
        proc = _run_decompile(
            function,
            exe_path=example.exe,
            decompile_py=decompile_py,
            timeout=timeout,
        )
        raw_path = out_dir / f"{example.output_stem}_{function.name}.dec.txt"
        err_path = out_dir / f"{example.output_stem}_{function.name}.dec.err.txt"
        raw_path.write_text(proc.stdout, encoding="utf-8")
        err_path.write_text(proc.stderr, encoding="utf-8")
        c_text = _assert_valid_decompile(function, proc)
        bodies.append(_find_function_definition(c_text, function.name))

    source_path = out_dir / f"{example.output_stem}.C"
    source_path.write_text(_build_full_source(bodies), encoding="utf-8")

    exe_name = f"{example.output_stem}.EXE"
    built_ok, compile_stdout, compile_stderr, link_stdout, link_stderr = _compile_and_link(
        source_path,
        out_dir,
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        obj_name=f"{example.output_stem}.OBJ",
        exe_name=exe_name,
        map_name=f"{example.output_stem}.MAP",
    )
    (out_dir / f"{example.output_stem}.compile.out.txt").write_text(compile_stdout, encoding="utf-8")
    (out_dir / f"{example.output_stem}.compile.err.txt").write_text(compile_stderr, encoding="utf-8")
    (out_dir / f"{example.output_stem}.link.out.txt").write_text(link_stdout, encoding="utf-8")
    (out_dir / f"{example.output_stem}.link.err.txt").write_text(link_stderr, encoding="utf-8")
    if not built_ok:
        raise RuntimeGateError(
            RuntimeGateStage.COMPILE,
            f"MS C 6 rebuild failed\n{compile_stdout}{compile_stderr}{link_stdout}{link_stderr}",
        )

    rebuilt_exe = out_dir / exe_name
    _, run_exit, run_stdout, run_stderr = _run_example(
        rebuilt_exe,
        out_dir,
        kvikdos=kvikdos,
        timeout=timeout,
    )
    (out_dir / f"{example.output_stem}.run.out.txt").write_text(run_stdout, encoding="utf-8")
    (out_dir / f"{example.output_stem}.run.err.txt").write_text(run_stderr, encoding="utf-8")
    if run_exit != expected_exit_code:
        raise RuntimeGateError(
            RuntimeGateStage.RUN,
            f"rebuilt {example.name} exited {run_exit}, expected {expected_exit_code}\n{run_stdout}{run_stderr}",
        )
    return rebuilt_exe


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a decompiled MS C example by rebuilding and running it.")
    parser.add_argument("--example", choices=tuple(sorted(EXAMPLES)), default="cmp16")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    parser.add_argument("--decompile-py", type=Path, default=DEFAULT_DECOMPILE)
    parser.add_argument("--expected-exit-code", type=int, default=255)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--clean", action="store_true", help="Remove the output directory before running the gate.")
    args = parser.parse_args()

    if args.clean and args.out_dir.exists():
        shutil.rmtree(args.out_dir)

    example = EXAMPLES[args.example]
    try:
        rebuilt_exe = _verify_example(
            example,
            out_dir=args.out_dir,
            kvikdos=args.kvikdos,
            msc6_root=args.msc6_root,
            decompile_py=args.decompile_py,
            expected_exit_code=args.expected_exit_code,
            timeout=args.timeout,
        )
    except RuntimeGateError as exc:
        print(f"[runtime-gate] failed stage={exc.stage.name.lower()} error={exc}", file=sys.stderr)
        return 1

    print(
        f"[runtime-gate] example={example.name} rebuilt={rebuilt_exe} "
        f"run_exit={args.expected_exit_code} status=passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
