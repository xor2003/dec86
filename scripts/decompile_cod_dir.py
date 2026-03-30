#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
DECOMPILE = REPO_ROOT / "decompile.py"
DEFAULT_MAX_MEMORY_MB = 15 * 1024

sys.path.insert(0, str(REPO_ROOT / "angr_platforms"))

from angr_platforms.X86_16.corpus_scan import extract_cod_functions


def _iter_cod_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() == ".cod":
            yield path


def _limit_virtual_memory(max_memory_mb: int):
    limit_bytes = max_memory_mb * 1024 * 1024

    def _apply():
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))

    return _apply


def _run_decompile(
    args: list[str], *, max_memory_mb: int, subprocess_timeout: int, stdout_path: Path
) -> tuple[int, str]:
    with stdout_path.open("wb") as stdout_file:
        proc = subprocess.run(
            [sys.executable, str(DECOMPILE), *args, "--max-memory-mb", str(max_memory_mb)],
            cwd=REPO_ROOT,
            text=True,
            stdout=stdout_file,
            stderr=subprocess.PIPE,
            check=False,
            timeout=subprocess_timeout,
            preexec_fn=_limit_virtual_memory(max_memory_mb),
        )
    return proc.returncode, proc.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description="Decompile all .COD files into sibling .dec files.")
    parser.add_argument("cod_dir", type=Path, help="Root directory containing .COD files.")
    parser.add_argument("--timeout", type=int, default=20, help="Per-function decompiler timeout.")
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=DEFAULT_MAX_MEMORY_MB,
        help="Per-process address-space cap in MB. Defaults to 15360.",
    )
    parser.add_argument(
        "--subprocess-timeout",
        type=int,
        default=900,
        help="Hard wall-clock timeout per file in seconds. Defaults to 900.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files whose sibling .dec already exists.",
    )
    args = parser.parse_args()

    cod_files = list(_iter_cod_files(args.cod_dir))
    print(f"found {len(cod_files)} COD files under {args.cod_dir}")
    failures = 0
    start = time.perf_counter()

    for index, cod_path in enumerate(cod_files, start=1):
        out_path = cod_path.with_suffix(".dec")
        if args.skip_existing and out_path.exists():
            print(f"[{index}/{len(cod_files)}] {cod_path}")
            print(f"  skip existing {out_path}")
            continue
        print(f"[{index}/{len(cod_files)}] {cod_path}")
        file_failed = False
        out_path.write_text("", encoding="utf-8")
        procs = [(proc_name, proc_kind) for proc_name, proc_kind, _code in extract_cod_functions(cod_path)]

        try:
            for proc_name, proc_kind in procs:
                with tempfile.TemporaryDirectory(prefix=f"{cod_path.stem}.{proc_name}.", dir=cod_path.parent) as tmpdir:
                    stdout_path = Path(tmpdir) / f"{cod_path.stem}.{proc_name}.dec.stdout"
                    returncode, stderr = _run_decompile(
                        [
                            str(cod_path),
                            "--proc",
                            proc_name,
                            "--proc-kind",
                            proc_kind,
                            "--timeout",
                            str(args.timeout),
                        ],
                        max_memory_mb=args.max_memory_mb,
                        subprocess_timeout=args.subprocess_timeout,
                        stdout_path=stdout_path,
                    )
                    with stdout_path.open("rb") as src, out_path.open("ab") as dst:
                        shutil.copyfileobj(src, dst)
                    if stderr.strip():
                        with out_path.open("a", encoding="utf-8") as fp:
                            fp.write(f"\n/* == stderr {proc_name} == */\n{stderr}")
                    if returncode != 0:
                        file_failed = True
                        with out_path.open("a", encoding="utf-8") as fp:
                            fp.write(f"\n/* == exit code {proc_name} == */\n{returncode}\n")
        except subprocess.TimeoutExpired:
            file_failed = True
            out_path.write_text(
                f"/* timed out after {args.subprocess_timeout}s while decompiling {cod_path.name} */\n",
                encoding="utf-8",
            )

        if file_failed:
            failures += 1
        print(f"  wrote {out_path}")

    elapsed = time.perf_counter() - start
    print(f"done in {elapsed:.1f}s; failures={failures}/{len(cod_files)}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
