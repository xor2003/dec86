#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import resource
import signal
import sys


_ROOT = Path(__file__).resolve().parent
_VENV_PYTHON = _ROOT / "venv" / "bin" / "python"

try:
    import angr
except ModuleNotFoundError:
    if _VENV_PYTHON.exists() and Path(sys.executable) != _VENV_PYTHON:
        os.execv(str(_VENV_PYTHON), [str(_VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]])
    raise

sys.path.insert(0, str(_ROOT / "angr_platforms"))

import angr_platforms.X86_16  # noqa: F401

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.analysis_helpers import extend_cfg_for_far_calls


logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.parse").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.lift_86_16").setLevel(logging.CRITICAL)


def _parse_int(value: str) -> int:
    return int(value, 0)


def _build_project(path: Path, *, force_blob: bool, base_addr: int, entry_point: int) -> angr.Project:
    suffix = path.suffix.lower()

    if force_blob or suffix in {".bin", ".raw"}:
        return angr.Project(
            path,
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
        )

    if suffix == ".com":
        return angr.Project(
            path,
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
            simos="DOS",
        )

    return angr.Project(path, auto_load_libs=False)


def _pick_function(project: angr.Project, addr: int | None, *, regions=None):
    target_addr = project.entry if addr is None else addr
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[target_addr],
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    if target_addr not in cfg.functions:
        raise KeyError(f"Function {target_addr:#x} was not recovered by CFGFast.")
    function = cfg.functions[target_addr]

    if project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]

    return cfg, function


class _AnalysisTimeout(Exception):
    pass


def _raise_timeout(_signum, _frame):
    raise _AnalysisTimeout()


def _apply_memory_limit(max_memory_mb: int | None) -> None:
    if max_memory_mb is None or max_memory_mb <= 0:
        return
    limit = max_memory_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ValueError, OSError):
        pass


def _infer_com_region(path: Path, base_addr: int, window: int) -> tuple[int, int]:
    data = path.read_bytes()
    end_limit = min(len(data), window)
    current = 0
    ah = None
    ax = None

    while current < end_limit:
        chunk = data[current : current + 16]
        insn = next(Arch86_16().capstone.disasm(chunk, base_addr + current, 1), None)
        if insn is None:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        if text.startswith("mov ah, "):
            ah = int(text.split(", ", 1)[1], 0)
        elif text.startswith("mov ax, "):
            ax = int(text.split(", ", 1)[1], 0)
            ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break
        if insn.mnemonic in {"ret", "retf", "iret", "jmp"}:
            break

    return base_addr, base_addr + max(current, 1)


def main() -> int:
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
        "--timeout",
        type=int,
        default=20,
        help="Analysis timeout in seconds. Defaults to 20.",
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
    args = parser.parse_args()

    _apply_memory_limit(args.max_memory_mb)

    print(f"loading: {args.binary}", flush=True)
    project = _build_project(
        args.binary,
        force_blob=args.blob,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    print("recovering function...", flush=True)

    regions = None
    target_addr = args.entry_point if args.addr is None else args.addr
    if args.binary.suffix.lower() == ".com" and args.addr is None:
        regions = [_infer_com_region(args.binary, args.base_addr, args.window)]
    else:
        regions = [(target_addr, target_addr + args.window)]

    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(args.timeout)
    try:
        cfg, func = _pick_function(project, args.addr, regions=regions)
    except _AnalysisTimeout:
        print(f"Timed out while recovering a function after {args.timeout}s.")
        print("Tip: try --addr 0x... for a specific function or raise --timeout for larger binaries.")
        return 3
    except Exception as ex:
        print(f"Function recovery failed: {ex}")
        if args.binary.suffix.lower() == ".com":
            try:
                block = project.factory.block(project.entry, opt_level=0)
                print("\n== first block asm ==")
                for insn in block.capstone.insns:
                    print(f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip())
                print("\nTip: tiny .COM files may include trailing data right after code.")
                print("Try decompiling a specific function with --addr, or use --show-asm for a quick inspection.")
            except Exception:
                pass
        return 5
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch.name}")
    print(f"entry: {project.entry:#x}")
    print(f"function: {func.addr:#x} {func.name}")

    if args.show_asm:
        block = project.factory.block(func.addr, opt_level=0)
        print("\n== asm ==")
        for insn in block.capstone.insns:
            print(f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip())

    print("decompiling...", flush=True)
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(args.timeout)
    try:
        dec = project.analyses.Decompiler(func, cfg=cfg)
    except _AnalysisTimeout:
        print(f"\nTimed out while decompiling after {args.timeout}s.")
        return 4
    except Exception as ex:
        print(f"\nDecompilation failed: {ex}")
        return 6
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    if dec.codegen is None:
        print("\nDecompilation did not produce code.")
        return 2

    print("\n== c ==")
    print(dec.codegen.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
