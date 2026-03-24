#!/usr/bin/env python3

from __future__ import annotations

import argparse
import io
import logging
import os
from pathlib import Path
import re
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
from angr_platforms.X86_16.analysis_helpers import (
    collect_dos_int21_calls,
    dos_helper_declarations,
    extend_cfg_for_far_calls,
    infer_com_region,
    normalize_api_style,
    patch_dos_int21_call_sites,
    render_dos_int21_call,
)
from angr_platforms.X86_16.cod_extract import (
    CODProcMetadata,
    extract_cod_function_entries,
    extract_cod_proc_metadata,
    extract_small_two_arg_cod_logic_bytes,
    extract_simple_cod_logic_bytes,
    infer_cod_logic_start,
    join_cod_entries,
)
from angr.analyses.decompiler.structured_codegen import c as structured_c


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
        patch_dos_int21_call_sites(function, getattr(project.loader.main_object, "binary", None))

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
        patch_dos_int21_call_sites(cfg.functions[project.entry], binary_path)
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


def _decompile_function(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
) -> tuple[str, str]:
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
    if _attach_dos_pseudo_callees(project, function, dec.codegen, api_style):
        dec.codegen.regenerate_text()
    formatted = _format_known_helper_calls(project, function, dec.codegen.text, api_style, binary_path)
    return "ok", _annotate_cod_proc_output(formatted, cod_metadata)


def _helper_name(project: angr.Project, addr: int) -> str | None:
    proc = project.hooked_by(addr)
    if proc is None:
        return None
    name = getattr(proc, "INT_NAME", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(proc, "display_name", None)
    if isinstance(name, str) and name:
        return name
    return proc.__class__.__name__


def _iter_c_nodes(node):
    yield node
    if isinstance(node, structured_c.CStatements):
        for stmt in node.statements:
            yield from _iter_c_nodes(stmt)
        return
    for attr in ("lhs", "rhs", "expr", "condition", "true_node", "false_node", "stmt", "callee_target"):
        if hasattr(node, attr):
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if value is not None and type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                yield from _iter_c_nodes(value)
    if hasattr(node, "args"):
        try:
            args = getattr(node, "args")
        except Exception:
            args = None
        if args:
            for arg in args:
                if type(arg).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                    yield from _iter_c_nodes(arg)


def _attach_dos_pseudo_callees(project: angr.Project, function, codegen, api_style: str) -> bool:
    if api_style != "pseudo" or getattr(codegen, "cfunc", None) is None:
        return False

    dos_calls = collect_dos_int21_calls(function)
    if not dos_calls:
        return False

    pseudo_funcs = []
    for call in dos_calls:
        target = function.get_call_target(call.insn_addr)
        if target is None:
            continue
        pseudo_funcs.append(project.kb.functions.function(addr=target))

    if not pseudo_funcs:
        return False

    call_nodes = [
        node
        for node in _iter_c_nodes(codegen.cfunc.statements)
        if isinstance(node, structured_c.CFunctionCall) and node.callee_func is None
    ]

    # Only patch when the structured C still preserves a clean one-to-one call
    # shape. The decompiler can sometimes collapse DOS interrupt helpers into a
    # much noisier tree where forcing a pseudo-callee onto the remaining call
    # node makes the output worse rather than better.
    if len(call_nodes) != len(pseudo_funcs):
        return False

    for node, pseudo_func in zip(call_nodes, pseudo_funcs):
        if pseudo_func is not None:
            node.callee_func = pseudo_func
    return True


def _int21_call_replacements(project: angr.Project, function, api_style: str, binary_path: Path | None) -> list[str]:
    return [
        render_dos_int21_call(call, api_style)
        for call in collect_dos_int21_calls(function, binary_path)
    ]


def _dos_helper_declarations(function, api_style: str, binary_path: Path | None) -> list[str]:
    return dos_helper_declarations(collect_dos_int21_calls(function, binary_path), api_style)


def _split_top_level_binary(expr: str, op: str) -> tuple[str, str] | None:
    depth = 0
    i = 0
    while i <= len(expr) - len(op):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if depth == 0 and expr.startswith(op, i):
            return expr[:i].strip(), expr[i + len(op) :].strip()
        i += 1
    return None


def _simplify_negated_condition(expr: str) -> str:
    expr = expr.strip()
    if not expr.startswith("!(") or not expr.endswith(")"):
        return expr

    inner = expr[2:-1].strip()
    if inner.startswith("!(") and inner.endswith(")"):
        return inner[2:-1].strip()

    for op, replacement in (("!=", "=="), ("==", "!="), (">=", "<"), ("<=", ">"), (">", "<="), ("<", ">=")):
        parts = _split_top_level_binary(inner, op)
        if parts is not None:
            lhs, rhs = parts
            return f"{lhs} {replacement} {rhs}"

    return expr


def _simplify_condition_line(line: str) -> str:
    marker = "if ("
    start = line.find(marker)
    if start < 0:
        return line

    cond_start = start + len(marker)
    depth = 1
    i = cond_start
    while i < len(line):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                condition = line[cond_start:i]
                simplified = _simplify_negated_condition(condition)
                if simplified != condition:
                    return line[:cond_start] + simplified + line[i:]
                return line
        i += 1
    return line


def _simplify_x86_16_conditions(c_text: str) -> str:
    return "\n".join(_simplify_condition_line(line) for line in c_text.splitlines())


def _format_bp_disp(disp: int) -> str:
    if disp >= 0:
        return f"[bp+0x{disp:x}]"
    return f"[bp-0x{-disp:x}]"


def _annotate_cod_proc_output(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None:
        return c_text

    lines: list[str] = []
    for line in c_text.splitlines():
        match = re.search(r"// \[bp([+-])0x([0-9a-f]+)\]", line)
        if match:
            disp = int(match.group(2), 16)
            if match.group(1) == "-":
                disp = -disp
            alias = metadata.stack_aliases.get(disp)
            if alias is None and disp > 0:
                alias = metadata.stack_aliases.get(disp + 2)
            if alias is not None and not line.rstrip().endswith(f" {alias}"):
                line = f"{line} {alias}"
        lines.append(line)

    comments: list[str] = []
    if metadata.stack_aliases or metadata.call_names or metadata.global_names:
        comments.append("/* COD annotations:")
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: (item[0] < 0, item[0])):
            comments.append(f" * {_format_bp_disp(disp)} = {name}")
        if metadata.global_names:
            comments.append(f" * globals = {', '.join(metadata.global_names)}")
        if metadata.call_names:
            comments.append(f" * calls = {', '.join(metadata.call_names)}")
        comments.append(" */")

    if comments:
        return "\n".join(comments) + "\n\n" + "\n".join(lines)
    return "\n".join(lines)


def _format_known_helper_calls(
    project: angr.Project, function, c_text: str, api_style: str, binary_path: Path | None
) -> str:
    mappings: dict[str, str] = {}
    for addr in getattr(project, "_sim_procedures", {}):
        name = _helper_name(project, addr)
        if not name:
            continue
        mappings[str(addr)] = name
        mappings[hex(addr)] = name
        mappings[hex(addr).upper().replace("X", "x")] = name

    for literal, name in sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True):
        c_text = re.sub(rf"(?<![A-Za-z_]){re.escape(literal)}(?=\s*\()", name, c_text)

    replacements = _int21_call_replacements(project, function, api_style, binary_path)
    for replacement in replacements:
        helper_name = replacement.split("(", 1)[0]
        for pattern in (
            r"(?<![A-Za-z_])dos_int21\s*\(\s*\)",
            rf"(?<![A-Za-z_]){re.escape(helper_name)}\s*\(\s*\)",
        ):
            c_text, count = re.subn(pattern, replacement, c_text, count=1)
            if count:
                break

    declarations = _dos_helper_declarations(function, api_style, binary_path)
    if declarations:
        c_text = "\n".join(declarations) + "\n\n" + c_text
    return _simplify_x86_16_conditions(c_text)


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
    parser.add_argument(
        "--api-style",
        choices=("modern", "dos", "raw", "pseudo", "service", "msc", "compiler"),
        default="modern",
        help="Name recovered DOS helpers as modern-style calls, DOS/compiler-style calls, pseudo-callee service calls, or raw interrupt helpers.",
    )
    args = parser.parse_args()

    _apply_memory_limit(args.max_memory_mb)

    print(f"loading: {args.binary}", flush=True)
    function_label = None
    cod_metadata = None
    if args.proc is not None:
        entries = extract_cod_function_entries(args.binary, args.proc, args.proc_kind)
        cod_metadata = extract_cod_proc_metadata(args.binary, args.proc, args.proc_kind)
        proc_code = extract_small_two_arg_cod_logic_bytes(entries)
        if proc_code is None:
            proc_code = extract_simple_cod_logic_bytes(entries)
        if proc_code is None:
            logic_start = infer_cod_logic_start(entries)
            proc_code = join_cod_entries(entries, start_offset=logic_start)
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
        status, payload = _decompile_function(
            project, cfg, func, args.timeout, args.api_style, args.binary, cod_metadata=cod_metadata
        )
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
        status, payload = _decompile_function(project, cfg, func, args.timeout, args.api_style, args.binary)
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

        status, payload = _decompile_function(project, cfg, function, args.timeout, args.api_style, args.binary)
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
