#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TARGET_MODULES = [
    "inertia_decompiler.decompile_file_summary",
]


def _setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build optional mypyc-compiled modules.")
    parser.add_argument(
        "setup_args",
        nargs="*",
        help="Arguments forwarded to setuptools (e.g. 'build_ext --inplace').",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        help="Extra modules to compile (append dotted module names).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _setup_parser()
    args = parser.parse_args(argv)
    modules = TARGET_MODULES + list(args.module)

    try:
        from mypyc.build import mypycify
        from setuptools import setup
    except Exception as exc:  # pragma: no cover
        print("mypy/mypyc is required for this build path. Install with: pip install .[mypyc]")
        print(f"Original error: {exc}")
        return 1

    setup(
        name="vextest-x86-16-mypyc",
        version="0.1",
        package_dir={"": "."},
        packages=["inertia_decompiler"],
        ext_modules=mypycify(modules),
        script_name=sys.argv[0],
        script_args=["build_ext", "--inplace"] if not args.setup_args else args.setup_args,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
