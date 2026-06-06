from __future__ import annotations

import argparse
import os
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
        "--c-target",
        choices=("msc-dos", "portable-flat"),
        default="portable-flat",
        help="Emit segmented-memory helper macros for a specific recompilable C target.",
    )
    parser.add_argument(
        "--trace-c-stages",
        action="store_true",
        help="Print labeled C snapshots after major decompilation text stages so line origin is visible.",
    )
    parser.add_argument(
        "--dump-layers",
        action="store_true",
        help=(
            "Dump every decompilation-stage C snapshot under a layer directory "
            "instead of printing to stdout only."
        ),
    )
    parser.add_argument(
        "--dump-layer-dir",
        type=Path,
        default=Path("angr_platforms/.cache/decompilation_layers"),
        help="Directory for per-layer decompilation artifacts (default: %(default)s).",
    )
    parser.add_argument(
        "--dump-layer-filter",
        default=os.environ.get("INERTIA_DUMP_LAYER_FILTER", ""),
        help="Comma-separated list of layer labels to dump (default: all).",
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
        "--include-library-functions",
        action="store_true",
        help="Include sidecar signature/library-labeled functions in whole-binary decompilation and tail-validation sweeps.",
    )
    parser.add_argument(
        "--ignore-local-sidecar-hints",
        action="store_true",
        help="Ignore on-disk sidecar hints for function discovery only.",
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
        "--function-discovery-backend",
        choices=("auto", "angr", "rizin", "hybrid"),
        default=os.environ.get("INERTIA_FUNCTION_DISCOVERY_BACKEND", "auto"),
        help="Function discovery backend for whole-binary EXE sweeps: angr, rizin, hybrid, or auto.",
    )
    parser.add_argument(
        "--rizin-timeout",
        type=int,
        default=int(os.environ.get("INERTIA_RIZIN_TIMEOUT", "8")),
        help="Timeout in seconds for optional rizin pre-discovery in hybrid/rizin modes.",
    )
    parser.add_argument(
        "--signature-catalog",
        type=Path,
        default=None,
        help="Optional deduplicated PAT catalog built from .pat/.obj/.lib inputs.",
    )
    parser.add_argument(
        "--seed-engine",
        choices=("auto", "angr", "rizin"),
        default="auto",
        help=(
            "Function seed discovery engine for whole-binary runs. "
            "'auto' tries rizin first only when no local sidecar discovery hints are present and then "
            "falls back to angr-ranked seeds."
        ),
    )
    parser.add_argument(
        "-q",
        "--brief",
        action="store_true",
        default=os.environ.get("INERTIA_BRIEF", "").lower() in ("1", "true", "yes"),
        help="Token-efficient output: suppress timestamps, progress, diagnostic commentary. "
        "Also set via INERTIA_BRIEF=1.",
    )
    parser.add_argument(
        "--otel-spans",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable compact OTLP-like span output for decompilation (default: INERTIA_OTEL_SPANS).",
    )
    parser.add_argument(
        "--otel-span-file",
        type=Path,
        default=None,
        help="Write telemetry summary/spans to this file.",
    )
    return parser
