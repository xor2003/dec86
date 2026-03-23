#!/usr/bin/env python3

from __future__ import annotations

import argparse
import io
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
from angr_platforms.X86_16.analysis_helpers import extend_cfg_for_far_calls, infer_com_region
from angr_platforms.X86_16.cod_extract import extract_cod_function_entries, join_cod_entries


logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.parse").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.lift_86_16").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.clinic").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.callsite_maker").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.optimization_passes.optimization_pass").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.analysis").setLevel(logging.CRITICAL)


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


def _build_project_from_bytes(code: bytes, *, base_addr: int, entry_point: int) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": base_addr,
            "entry_point": entry_point,
        },
    )


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


def _recover_cfg(project: angr.Project, binary_path: Path, *, base_addr: int, window: int):
    if binary_path.suffix.lower() == ".com":
        regions = [infer_com_region(binary_path, base_addr=base_addr, window=window, arch=project.arch)]
        cfg = project.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[project.entry],
            regions=regions,
            normalize=True,
            force_complete_scan=False,
        )
    else:
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
        )

    if project.arch.name == "86_16" and project.entry in cfg.functions:
        extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
    return cfg


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


def _format_first_block_asm(project: angr.Project, addr: int) -> str:
    try:
        block = project.factory.block(addr, opt_level=0)
    except Exception as ex:
        return f"<assembly unavailable: {ex}>"

    lines = []
    for insn in block.capstone.insns[:16]:
        lines.append(f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip())
    return "\n".join(lines) if lines else "<no instructions>"


def _interesting_functions(cfg, *, limit: int):
    functions = [
        function
        for function in cfg.functions.values()
        if not function.is_plt and not function.name.startswith("Unresolvable")
    ]
    functions.sort(key=lambda function: function.addr)
    return functions[:limit], len(functions)


def _decompile_function(project: angr.Project, cfg, function, timeout: int) -> tuple[str, str]:
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(timeout)
    try:
        dec = project.analyses.Decompiler(function, cfg=cfg)
    except _AnalysisTimeout:
        return "timeout", f"Timed out after {timeout}s."
    except Exception as ex:
        return "error", str(ex)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if dec.codegen is None:
        return "empty", "Decompiler did not produce code."
    return "ok", dec.codegen.text


def _fallback_entry_function(project: angr.Project, *, timeout: int, window: int):
    regions = [(project.entry, project.entry + window)]
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(timeout)
    try:
        return _pick_function(project, project.entry, regions=regions)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _recover_blob_entry_function(project: angr.Project, entry_addr: int, *, timeout: int):
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(timeout)
    try:
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
        )
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if entry_addr not in cfg.functions:
        raise KeyError(f"Function {entry_addr:#x} was not recovered by CFGFast.")
    return cfg, cfg.functions[entry_addr]


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
    parser.add_argument(
        "--max-functions",
        type=int,
        default=32,
        help="Maximum number of recovered functions to print when decompiling a whole binary. Defaults to 32.",
    )
    args = parser.parse_args()

    _apply_memory_limit(args.max_memory_mb)

    print(f"loading: {args.binary}", flush=True)
    function_label = None
    if args.proc is not None:
        entries = extract_cod_function_entries(args.binary, args.proc, args.proc_kind)
        proc_code = join_cod_entries(entries)
        project = _build_project_from_bytes(
            proc_code,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
        function_label = args.proc
        if args.addr is None:
            args.addr = args.entry_point
        args.window = max(len(proc_code), 1)
    else:
        project = _build_project(
            args.binary,
            force_blob=args.blob,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
    if args.addr is not None:
        print("recovering function...", flush=True)

        try:
            if function_label is not None and args.addr == project.entry:
                cfg, func = _recover_blob_entry_function(project, args.addr, timeout=args.timeout)
            else:
                regions = [(args.addr, args.addr + args.window)]
                old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
                signal.alarm(args.timeout)
                try:
                    cfg, func = _pick_function(project, args.addr, regions=regions)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
        except _AnalysisTimeout:
            print(f"Timed out while recovering a function after {args.timeout}s.")
            print("Tip: try a larger --timeout for larger binaries.")
            return 3
        except Exception as ex:
            print(f"Function recovery failed: {ex}")
            print("\n== first block asm ==")
            print(_format_first_block_asm(project, args.addr))
            return 5

        if function_label is not None:
            func.name = function_label

        print(f"binary: {args.binary}")
        print(f"arch: {project.arch.name}")
        print(f"entry: {project.entry:#x}")
        print(f"function: {func.addr:#x} {func.name}")

        if args.show_asm:
            print("\n== asm ==")
            print(_format_first_block_asm(project, func.addr))

        print("decompiling...", flush=True)
        status, payload = _decompile_function(project, cfg, func, args.timeout)
        if status != "ok":
            print(f"\nDecompilation {status}: {payload}")
            print("\n== asm fallback ==")
            print(_format_first_block_asm(project, func.addr))
            return 6 if status == "error" else 4

        print("\n== c ==")
        print(payload)
        return 0

    print("recovering functions...", flush=True)
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(args.timeout)
    try:
        cfg = _recover_cfg(project, args.binary, base_addr=args.base_addr, window=args.window)
    except _AnalysisTimeout:
        print(f"Timed out while recovering functions after {args.timeout}s.")
        print("Trying bounded entry-function recovery instead...")
        try:
            cfg, func = _fallback_entry_function(project, timeout=args.timeout, window=args.window)
        except _AnalysisTimeout:
            print("Bounded entry-function recovery also timed out.")
            print("Tip: try a larger --timeout or decompile a specific function with --addr.")
            return 3
        except Exception as ex:
            print(f"Bounded entry-function recovery failed: {ex}")
            print("\n== entry asm ==")
            print(_format_first_block_asm(project, project.entry))
            return 5

        print(f"binary: {args.binary}")
        print(f"arch: {project.arch.name}")
        print(f"entry: {project.entry:#x}")
        print(f"fallback function: {func.addr:#x} {func.name}")
        status, payload = _decompile_function(project, cfg, func, args.timeout)
        if status != "ok":
            print(f"\nDecompilation {status}: {payload}")
            print("\n== asm fallback ==")
            print(_format_first_block_asm(project, func.addr))
            return 6 if status == "error" else 4

        print("\n== c ==")
        print(payload)
        return 0
    except Exception as ex:
        print(f"Function catalog recovery failed: {ex}")
        print("\n== entry asm ==")
        print(_format_first_block_asm(project, project.entry))
        return 5
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if function_label is not None and project.entry in cfg.functions:
        cfg.functions[project.entry].name = function_label

    functions, total_functions = _interesting_functions(cfg, limit=args.max_functions)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch.name}")
    print(f"entry: {project.entry:#x}")
    print(f"functions recovered: {total_functions}")
    if total_functions > len(functions):
        print(f"showing first {len(functions)} functions; use --max-functions to raise the cap")

    decompiled = 0
    failed = 0
    for function in functions:
        print(f"\n== function {function.addr:#x} {function.name} ==")
        if args.show_asm:
            print("-- asm --")
            print(_format_first_block_asm(project, function.addr))

        status, payload = _decompile_function(project, cfg, function, args.timeout)
        if status == "ok":
            decompiled += 1
            print("-- c --")
            print(payload)
        else:
            failed += 1
            print(f"-- {status} --")
            print(payload)
            print("-- asm fallback --")
            print(_format_first_block_asm(project, function.addr))

    print(f"\nsummary: decompiled {decompiled}/{len(functions)} shown functions")
    if failed:
        print(f"summary: {failed} functions fell back to asm/details")
    return 0 if decompiled else 2


if __name__ == "__main__":
    raise SystemExit(main())
