from __future__ import annotations

import argparse
from pathlib import Path


__all__ = ["_build_cli_argument_parser"]


def _parse_int(value: str) -> int:
    return int(value, 0)


def _build_cli_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decompile a DOS/x86-16 sample with angr-platforms.",
    )
    parser.add_argument("binary", type=Path, help="Path to the binary to decompile.")
    parser.add_argument(
        "--addr",
        type=_parse_int,
        default=None,
        help="Function start address to decompile. Defaults to the entry point.",
    )
    parser.add_argument(
        "--blob",
        action="store_true",
        help="Force blob loading instead of auto-detecting a loader backend.",
    )
    parser.add_argument(
        "--base-addr",
        type=_parse_int,
        default=0x1000,
        help="Base address for blob/.COM loading. Defaults to 0x1000.",
    )
    parser.add_argument(
        "--entry-point",
        type=_parse_int,
        default=0x1000,
        help="Entry point for blob/.COM loading. Defaults to 0x1000.",
    )
    parser.add_argument(
        "--show-asm",
        action="store_true",
        help="Print the first lifted block before the decompiled C.",
    )
    parser.add_argument(
        "--alternate-source-c",
        action="store_true",
        help="When a same-stem .c/.C source sidecar exists, print it before each decompiled C block.",
    )
    parser.add_argument(
        "--trace-c-stages",
        action="store_true",
        help="Print labeled C snapshots after major decompilation text stages so line origin is visible.",
    )
    parser.add_argument(
        "--proc",
        default=None,
        help="Extract and decompile one procedure from a .COD listing by PROC name.",
    )
    parser.add_argument(
        "--proc-kind",
        default="NEAR",
        help="Procedure kind for --proc lookup in .COD files. Defaults to NEAR.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Analysis timeout in seconds. Defaults to 120.",
    )
    parser.add_argument(
        "--window",
        type=_parse_int,
        default=0x200,
        help="Bound CFG recovery to [addr, addr+window). Defaults to 0x200.",
    )
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=2048,
        help="Best-effort address-space limit in MB. Defaults to 2048.",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Maximum number of recovered functions to print when decompiling a whole binary. Defaults to 0 (all functions).",
    )
    parser.add_argument(
        "--api-style",
        choices=("modern", "dos", "raw", "pseudo", "service", "msc", "compiler"),
        default="modern",
        help="Name recovered DOS helpers as modern-style calls, DOS/compiler-style calls, pseudo-callee service calls, or raw interrupt helpers.",
    )
    parser.add_argument(
        "--pat-backend",
        choices=("python_regex", "hyperscan"),
        default="hyperscan",
        help="PAT matcher backend. Use python_regex for the portable fallback or hyperscan for the faster scanner.",
    )
    parser.add_argument(
        "--signature-catalog",
        type=Path,
        default=None,
        help="Optional deduplicated PAT catalog built from .pat/.obj/.lib inputs.",
    )
    return parser