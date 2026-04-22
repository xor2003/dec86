#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.monkeytype_tools import (
    DEFAULT_STUB_MODULE_PREFIXES,
    MONKEYTYPE_CACHE_DIR,
    ensure_monkeytype_dirs,
    parse_list_modules_output,
    source_line_count,
    source_path_for_module,
)

PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
MAX_SOURCE_LINES = 400


def _python() -> str:
    return str(PYTHON if PYTHON.exists() else Path(sys.executable))


def _run_monkeytype(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_python(), "-m", "monkeytype", "-c", "monkeytype_config:CONFIG", *args],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply MonkeyType annotations automatically to traced repo modules with source files <= 400 lines."
    )
    parser.add_argument(
        "--module-prefix",
        action="append",
        default=[],
        help="Module prefix to include. Can be repeated. Defaults to traced repo prefixes.",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=MAX_SOURCE_LINES,
        help="Maximum source file length eligible for automatic apply.",
    )
    parser.add_argument(
        "--per-module-timeout",
        type=int,
        default=20,
        help="Timeout in seconds for one monkeytype apply invocation.",
    )
    args = parser.parse_args(argv)

    ensure_monkeytype_dirs()
    prefixes = tuple(args.module_prefix) if args.module_prefix else DEFAULT_STUB_MODULE_PREFIXES
    listed = _run_monkeytype("list-modules")
    if listed.returncode:
        raise SystemExit(listed.stderr.strip() or listed.stdout.strip() or "monkeytype list-modules failed")
    modules = parse_list_modules_output(listed.stdout, prefixes=prefixes)

    applied: list[str] = []
    skipped: list[str] = []
    failures: list[str] = []

    for module_name in modules:
        source_path = source_path_for_module(module_name)
        if source_path is None or not source_path.exists():
            skipped.append(f"{module_name}: no source path")
            continue
        line_count = source_line_count(source_path)
        if line_count > args.max_lines:
            skipped.append(f"{module_name}: {line_count} lines > {args.max_lines}")
            continue
        try:
            applied_source = subprocess.run(
                [_python(), "-m", "monkeytype", "-c", "monkeytype_config:CONFIG", "apply", module_name],
                cwd=REPO_ROOT,
                check=False,
                text=True,
                capture_output=True,
                timeout=args.per_module_timeout,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{module_name}: timed out after {args.per_module_timeout}s")
            continue
        if applied_source.returncode:
            failures.append(f"{module_name}: {applied_source.stderr.strip() or applied_source.stdout.strip()}")
            continue
        rendered = applied_source.stdout
        if not rendered.strip():
            skipped.append(f"{module_name}: empty apply output")
            continue
        source_path.write_text(rendered, encoding="utf-8")
        applied.append(module_name)
        print(module_name)

    failures_path = MONKEYTYPE_CACHE_DIR / "apply_failures.txt"
    skipped_path = MONKEYTYPE_CACHE_DIR / "apply_skips.txt"
    if failures:
        failures_path.write_text("\n\n".join(failures) + "\n", encoding="utf-8")
        print(failures_path.relative_to(REPO_ROOT))
    elif failures_path.exists():
        failures_path.unlink()
    if skipped:
        skipped_path.write_text("\n".join(skipped) + "\n", encoding="utf-8")
        print(skipped_path.relative_to(REPO_ROOT))
    elif skipped_path.exists():
        skipped_path.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
