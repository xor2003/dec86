#!/usr/bin/env python3

from __future__ import annotations

import argparse
import io
import logging
import os
import re
import resource
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


_ROOT = Path(__file__).resolve().parent
_VENV_PYTHON = _ROOT / "venv" / "bin" / "python"
CURRENT_PROJECT: angr.Project | None = None
START_TIME = time.perf_counter()
LAST_STEP_TIME = START_TIME


def log_step(step: str) -> None:
    global LAST_STEP_TIME
    now = time.perf_counter()
    elapsed_total = now - START_TIME
    since_last = now - LAST_STEP_TIME
    LAST_STEP_TIME = now
    timestamp = datetime.utcnow().isoformat()
    print(f"[dbg][{timestamp}] {step} (total {elapsed_total:.2f}s, +{since_last:.2f}s)")
    sys.stdout.flush()


def _format_address(addr: int) -> str:
    return f"{addr:#x}"


class JumpkindLoggingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        msg = record.getMessage()
        if "Unsupported jumpkind" in msg and "address" in msg:
            match = re.search(r"address\s+(0x[0-9a-fA-F]+|[0-9]+)", msg)
            if match and CURRENT_PROJECT is not None:
                try:
                    addr = int(match.group(1), 0)
                    asm = _format_first_block_asm(CURRENT_PROJECT, addr)
                    print(f"[dbg][{datetime.utcnow().isoformat()}] NON-DECODED BLOCK {addr:#x}:\n{asm}")
                except Exception as exc:
                    print(f"[dbg] failed to format assembly for {msg}: {exc}")
            else:
                print(f"[dbg] {msg}")

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
    DOS_SERVICE_BASE_ADDR,
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
    extract_small_two_arg_cod_logic_entries,
    extract_simple_cod_logic_entries,
    infer_cod_logic_start,
    join_cod_entries_with_synthetic_globals,
)
from angr_platforms.X86_16.lst_extract import LSTMetadata, extract_lst_metadata
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort


logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.parse").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.lift_86_16").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.clinic").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.callsite_maker").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.optimization_passes.optimization_pass").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.analysis").setLevel(logging.CRITICAL)


def _parse_int(value: str) -> int:
    return int(value, 0)


def _load_lst_metadata(binary: Path, project: angr.Project) -> LSTMetadata | None:
    lst_path = binary.with_suffix(".lst")
    if not lst_path.exists():
        return None

    try:
        metadata = extract_lst_metadata(lst_path)
    except Exception as exc:
        print(f"[dbg] failed to parse source listing {lst_path}: {exc}")
        return None

    data_base = getattr(getattr(project.loader, "main_object", None), "mapped_base", None)
    code_base = project.entry
    if data_base is None:
        return None

    for offset, name in metadata.data_labels.items():
        project.kb.labels[data_base + offset] = name
    for offset, name in metadata.code_labels.items():
        project.kb.labels[code_base + offset] = name

    return metadata


def _lst_data_label(metadata: LSTMetadata | None, offset: int | None) -> str | None:
    if metadata is None or offset is None:
        return None
    return metadata.data_labels.get(offset)


def _build_project(path: Path, *, force_blob: bool, base_addr: int, entry_point: int) -> angr.Project:
    suffix = path.suffix.lower()

    print(f"[dbg] build_project: path={path} suffix={suffix} force_blob={force_blob}")
    sys.stdout.flush()
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

    proj = angr.Project(path, auto_load_libs=False)
    print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
    sys.stdout.flush()
    return proj


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


def _infer_x86_16_linear_region(project: angr.Project, start_addr: int, *, window: int) -> tuple[int, int]:
    end_limit = start_addr + max(window, 1)
    current = start_addr
    ah = None

    while current < end_limit:
        try:
            chunk = bytes(project.loader.memory.load(current, 16))
        except Exception:
            break
        if not chunk:
            break

        insn = next(project.arch.capstone.disasm(chunk, current, 1), None)
        if insn is None or insn.size <= 0:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        if text.startswith("mov ah, "):
            try:
                ah = int(text.split(", ", 1)[1], 0)
            except ValueError:
                ah = None
        elif text.startswith("mov ax, "):
            try:
                ax = int(text.split(", ", 1)[1], 0)
            except ValueError:
                ax = None
            if ax is not None:
                ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic in {"ret", "retf", "iret"}:
            break
        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break

    return start_addr, max(start_addr + 1, current)


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
    print(f"[dbg] recover_cfg: entry={hex(project.entry)} base_addr={hex(base_addr)} window={hex(window)} binary={binary_path}")
    sys.stdout.flush()
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
        print("[dbg] calling CFGFast (non-COM path)")
        sys.stdout.flush()
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
        )
        print("[dbg] CFGFast returned")
        sys.stdout.flush()

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


def _function_skip_reason(function):
    if getattr(function, "is_simprocedure", False):
        return "SimProcedure (DOS helper)"
    addr = getattr(function, "addr", None)
    if isinstance(addr, int) and addr >= DOS_SERVICE_BASE_ADDR:
        return "DOS service address"
    return None


def _interesting_functions(cfg, *, limit: int):
    functions = []
    skipped = 0
    for function in sorted(cfg.functions.values(), key=lambda function: function.addr):
        if function.is_plt or function.name.startswith("Unresolvable"):
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            print(f"[dbg] skipping {function.addr:#x} {function.name}: {reason}")
            skipped += 1
            continue
        functions.append(function)
    return functions[:limit], len(functions) + skipped


def _decompile_function(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
) -> tuple[str, str]:
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(timeout)
    try:
        print(f"[dbg] decompile_function: addr={hex(function.addr)} name={function.name}")
        sys.stdout.flush()
        # Ensure function is normalized before decompilation
        if not function.normalized:
            print(f"[dbg] function {function.addr:#x} not normalized, normalizing...")
            function.normalize()
        dec = project.analyses.Decompiler(function, cfg=cfg)
        if dec.codegen is None:
            logging.getLogger(__name__).debug(
                "Default decompiler structurer produced no code for %s; retrying with Phoenix.",
                function,
            )
            dec = project.analyses.Decompiler(function, cfg=cfg, options=[("structurer_cls", "Phoenix")])
        print(f"[dbg] Decompiler returned for {hex(function.addr)}")
        sys.stdout.flush()
    except _AnalysisTimeout:
        return "timeout", f"Timed out after {timeout}s."
    except Exception as ex:
        return "error", str(ex)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if dec.codegen is None:
        return "empty", "Decompiler did not produce code."
    setattr(project, "_inertia_rewrite_cache", {})
    changed = False
    rewrite_passes = (
        lambda: _attach_dos_pseudo_callees(project, function, dec.codegen, api_style),
        lambda: _attach_segment_register_names(dec.codegen, project),
        lambda: _elide_redundant_segment_pointer_dereferences(project, dec.codegen),
        lambda: _attach_ss_stack_variables(project, dec.codegen),
        lambda: _rewrite_ss_stack_byte_offsets(project, dec.codegen),
        lambda: _coalesce_direct_ss_local_word_statements(project, dec.codegen),
        lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
        lambda: _normalize_scalar_byte_register_types(dec.codegen),
        lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
        lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
        lambda: _coalesce_segmented_word_store_statements(project, dec.codegen),
        lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
        lambda: _coalesce_cod_word_global_statements(project, dec.codegen, synthetic_globals),
        lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
        lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
        lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
        lambda: _attach_lst_data_names(project, dec.codegen, lst_metadata),
        lambda: _collect_access_traits(project, dec.codegen),
        lambda: _attach_access_trait_field_names(project, dec.codegen),
        lambda: _attach_cod_variable_names(dec.codegen, cod_metadata),
        lambda: _attach_cod_callee_names(dec.codegen, cod_metadata),
    )
    if enable_structured_simplify:
        structured_simplify_failed = [False]

        def _safe_structured_simplify():
            if structured_simplify_failed[0]:
                return False
            try:
                return _simplify_structured_c_expressions(dec.codegen)
            except RecursionError:
                structured_simplify_failed[0] = True
                return False

        rewrite_passes += (_safe_structured_simplify,)
    for _ in range(2):
        iter_changed = False
        for rewrite in rewrite_passes:
            if rewrite():
                iter_changed = True
        if not iter_changed:
            break
        changed = True
    if changed:
        dec.codegen.regenerate_text()
    formatted = _format_known_helper_calls(project, function, dec.codegen.text, api_style, binary_path)
    return "ok", _annotate_cod_proc_output(formatted, cod_metadata)


def _function_complexity(function):
    project = function.project
    if project is None:
        return 0, 0
    block_addrs = sorted(getattr(function, "block_addrs_set", set()))
    total_bytes = 0
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        total_bytes += len(block.bytes)
    return len(block_addrs), total_bytes


def _decompile_function_with_stats(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
):
    block_count, byte_count = _function_complexity(function)
    print(
        f"[dbg] function complexity for {function.addr:#x} {function.name}: blocks={block_count}, bytes={byte_count}"
    )
    sys.stdout.flush()
    start = time.perf_counter()
    status, payload = _decompile_function(
        project,
        cfg,
        function,
        timeout,
        api_style,
        binary_path,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        enable_structured_simplify=enable_structured_simplify,
    )
    elapsed = time.perf_counter() - start
    print(f"[dbg] decompilation time for {function.addr:#x} {function.name}: {elapsed:.2f}s")
    sys.stdout.flush()
    return status, payload, block_count, byte_count, elapsed


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


def _attach_cod_callee_names(codegen, cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None or not cod_metadata.call_names or getattr(codegen, "cfunc", None) is None:
        return False

    call_nodes = [
        node
        for node in _iter_c_nodes_deep(codegen.cfunc.statements)
        if isinstance(node, structured_c.CFunctionCall)
        and getattr(node, "callee_func", None) is not None
        and getattr(node.callee_func, "name", "").startswith("sub_")
    ]
    if len(call_nodes) != len(cod_metadata.call_names):
        return False

    for node, call_name in zip(call_nodes, cod_metadata.call_names):
        node.callee_func.name = call_name
    return True


def _build_cod_positive_bp_alias_map(
    bp_disps: list[int], cod_metadata: CODProcMetadata | None
) -> dict[int, str]:
    if cod_metadata is None:
        return {}

    meta_positive = sorted((disp, name) for disp, name in cod_metadata.stack_aliases.items() if disp > 0)
    if not meta_positive:
        return {}

    var_positive = sorted(disp for disp in bp_disps if disp > 0)
    if not var_positive:
        return {}

    alias_map: dict[int, str] = {}
    if len(var_positive) <= len(meta_positive):
        for disp, (_, name) in zip(var_positive, meta_positive):
            alias_map[disp] = name

    for disp in var_positive:
        direct = cod_metadata.stack_aliases.get(disp)
        if direct is not None:
            alias_map.setdefault(disp, direct)

    return alias_map


def _cod_stack_alias_for_disp(
    disp: int,
    cod_metadata: CODProcMetadata | None,
    *,
    positive_aliases: dict[int, str] | None = None,
) -> str | None:
    if cod_metadata is None:
        return None
    if disp > 0 and positive_aliases is not None:
        alias = positive_aliases.get(disp)
        if alias is not None:
            return alias
    return cod_metadata.stack_aliases.get(disp)


def _attach_cod_variable_names(codegen, cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None or not cod_metadata.stack_aliases or getattr(codegen, "cfunc", None) is None:
        return False

    positive_aliases = _build_cod_positive_bp_alias_map(
        [
            getattr(variable, "offset", None)
            for variable in getattr(codegen.cfunc, "variables_in_use", {})
            if getattr(variable, "base", None) == "bp" and isinstance(getattr(variable, "offset", None), int)
        ],
        cod_metadata,
    )

    changed = False
    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if getattr(variable, "base", None) != "bp":
            continue
        disp = getattr(variable, "offset", None)
        if disp is None:
            continue
        alias = _cod_stack_alias_for_disp(disp, cod_metadata, positive_aliases=positive_aliases)
        if alias is None:
            continue

        if getattr(variable, "name", None) != alias:
            variable.name = alias
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != alias:
            unified.name = alias
            changed = True

    return changed


def _synthetic_global_entry(
    synthetic_globals: dict[int, tuple[str, int]] | None, addr: int
) -> tuple[str, int] | None:
    if not synthetic_globals:
        return None
    entry = synthetic_globals.get(addr)
    if entry is None:
        return None
    if isinstance(entry, tuple):
        return entry
    return entry, 1


def _sanitize_cod_identifier(name: str) -> str:
    name = name.lstrip("_")
    if name.startswith("$") and "_" in name:
        name = name.rsplit("_", 1)[-1]
    name = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not name:
        return "data"
    if name[0].isdigit():
        return f"g_{name}"
    return name


def _structured_codegen_node(value) -> bool:
    return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")


def _c_constant_value(node) -> int | None:
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _project_rewrite_cache(project: angr.Project) -> dict[str, dict[int, object]]:
    cache = getattr(project, "_inertia_rewrite_cache", None)
    if cache is None:
        cache = {}
        setattr(project, "_inertia_rewrite_cache", cache)
    return cache


@dataclass(frozen=True)
class _SegmentedAccess:
    kind: str
    seg_name: str | None
    linear: int | None = None
    cvar: structured_c.CVariable | None = None
    stack_var: SimStackVariable | None = None
    extra_offset: int = 0
    addr_expr: object | None = None


def _segment_reg_name(node, project: angr.Project) -> str | None:
    cache = _project_rewrite_cache(project).setdefault("segment_reg_name", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CVariable):
        cache[key] = None
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        cache[key] = None
        return None
    result = project.arch.register_names.get(variable.reg)
    cache[key] = result
    return result


def _classify_segmented_addr_expr(node, project: angr.Project) -> _SegmentedAccess | None:
    cache = _project_rewrite_cache(project).setdefault("segmented_addr_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    seg_name = None
    cvar = None
    stack_var = None
    const_offset = 0
    other_terms = []

    for term in _flatten_c_add_terms(node):
        inner = _unwrap_c_casts(term)

        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            local_seg = None
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                local_seg = _segment_reg_name(_unwrap_c_casts(maybe_seg), project)
                if local_seg is not None:
                    break
            if local_seg is not None:
                seg_name = local_seg
                continue

        constant = _c_constant_value(inner)
        if constant is not None:
            const_offset += constant
            continue

        matched_stack = _match_stack_cvar_and_offset(inner)
        if matched_stack is not None:
            cvar, stack_offset = matched_stack
            variable = getattr(cvar, "variable", None)
            if isinstance(variable, SimStackVariable):
                stack_var = variable
            const_offset += stack_offset
            continue

        other_terms.append(term)

    if seg_name is None:
        cache[key] = None
        return None

    if seg_name == "ss" and cvar is not None and not other_terms:
        result = _SegmentedAccess(
            "stack",
            seg_name,
            cvar=cvar,
            stack_var=stack_var,
            extra_offset=const_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    if cvar is None and not other_terms:
        if seg_name == "ds":
            kind = "global" if const_offset >= 0 else "unknown"
            linear = const_offset if const_offset >= 0 else None
        elif seg_name == "es":
            kind = "extra"
            linear = const_offset
        else:
            kind = "segment_const"
            linear = const_offset
        result = _SegmentedAccess(kind, seg_name, linear=linear, extra_offset=const_offset, addr_expr=node)
        cache[key] = result
        return result

    result = _SegmentedAccess(
        "unknown",
        seg_name,
        linear=const_offset if cvar is None else None,
        cvar=cvar,
        stack_var=stack_var,
        extra_offset=const_offset,
        addr_expr=node,
    )
    cache[key] = result
    return result


def _classify_segmented_dereference(node, project: angr.Project) -> _SegmentedAccess | None:
    cache = _project_rewrite_cache(project).setdefault("segmented_dereference_class", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        cache[key] = None
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    result = _classify_segmented_addr_expr(operand, project)
    cache[key] = result
    return result


def _match_real_mode_linear_expr(node, project: angr.Project) -> tuple[str | None, int | None]:
    cache = _project_rewrite_cache(project).setdefault("real_mode_linear_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_addr_expr(node, project)
    if classified is None or classified.kind not in {"global", "extra", "segment_const"}:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segmented_dereference(node, project: angr.Project) -> tuple[str | None, int | None]:
    cache = _project_rewrite_cache(project).setdefault("segmented_dereference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.linear is None:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segment_register_based_dereference(node, project: angr.Project):
    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
        return None

    addr_expr = classified.addr_expr
    base_terms = []
    for term in _flatten_c_add_terms(addr_expr):
        inner = _unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            segment_scale = False
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if _segment_reg_name(_unwrap_c_casts(maybe_seg), project) is not None:
                    segment_scale = True
                    break
            if segment_scale:
                continue

        if _c_constant_value(inner) is not None:
            continue

        if isinstance(inner, structured_c.CVariable) and isinstance(getattr(inner, "variable", None), SimRegisterVariable):
            base_terms.append(inner)
            continue

        return None

    if len(base_terms) != 1:
        return None
    return classified, base_terms[0]


def _strip_segment_scale_from_addr_expr(addr_expr, project: angr.Project):
    kept_terms = []
    for term in _flatten_c_add_terms(addr_expr):
        inner = _unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            segment_scale = False
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if _segment_reg_name(_unwrap_c_casts(maybe_seg), project) is not None:
                    segment_scale = True
                    break
            if segment_scale:
                continue
        kept_terms.append(term)

    if not kept_terms:
        return None
    result = kept_terms[0]
    for term in kept_terms[1:]:
        result = structured_c.CBinaryOp("Add", result, term, codegen=getattr(term, "codegen", None))
    return result


def _match_ss_stack_reference(node, project: angr.Project):
    cache = _project_rewrite_cache(project).setdefault("ss_stack_reference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is not None and classified.kind == "stack" and classified.extra_offset == 0 and classified.stack_var is not None:
        result = (classified.stack_var, classified.cvar)
        cache[key] = result
        return result

    cache[key] = None
    return None


def _flatten_c_add_terms(node):
    if isinstance(node, structured_c.CTypeCast):
        return _flatten_c_add_terms(node.expr)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_c_add_terms(node.lhs) + _flatten_c_add_terms(node.rhs)
    return [node]


def _match_stack_cvar_and_offset(node):
    node = _unwrap_c_casts(node)

    if isinstance(node, structured_c.CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
            return node, 0
        return None

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
        operand = _unwrap_c_casts(node.operand)
        if isinstance(operand, structured_c.CVariable):
            variable = getattr(operand, "variable", None)
            if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
                return operand, 0
        return None

    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = _match_stack_cvar_and_offset(node.lhs)
        rhs = _match_stack_cvar_and_offset(node.rhs)
        lhs_const = _c_constant_value(_unwrap_c_casts(node.lhs))
        rhs_const = _c_constant_value(_unwrap_c_casts(node.rhs))

        if lhs is not None and rhs_const is not None:
            base, offset = lhs
            return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
        if rhs is not None and lhs_const is not None:
            base, offset = rhs
            return base, offset + lhs_const
        return None

    return None


def _match_ss_local_plus_const(node, project: angr.Project):
    cache = _project_rewrite_cache(project).setdefault("ss_local_plus_const", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        cache[key] = None
        return None
    result = (classified.cvar, classified.extra_offset)
    cache[key] = result
    return result


def _replace_c_children(node, transform, seen: set[int] | None = None) -> bool:
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return False
    seen.add(node_id)
    try:
        changed = False

        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "callee_target",
            "else_node",
            "retval",
        ):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                new_value = transform(value)
                if new_value is not value:
                    setattr(node, attr, new_value)
                    changed = True
                    value = new_value
                if _replace_c_children(value, transform, seen):
                    changed = True

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            new_items = []
            list_changed = False
            for item in items:
                if _structured_codegen_node(item):
                    new_item = transform(item)
                    if new_item is not item:
                        list_changed = True
                    if _replace_c_children(new_item, transform, seen):
                        changed = True
                    new_items.append(new_item)
                else:
                    new_items.append(item)
            if list_changed:
                setattr(node, attr, new_items)
                changed = True

        if hasattr(node, "condition_and_nodes"):
            try:
                pairs = getattr(node, "condition_and_nodes")
            except Exception:
                pairs = None
            if pairs:
                new_pairs = []
                pair_changed = False
                for cond, body in pairs:
                    new_cond = transform(cond) if _structured_codegen_node(cond) else cond
                    new_body = transform(body) if _structured_codegen_node(body) else body
                    if new_cond is not cond or new_body is not body:
                        pair_changed = True
                    if _structured_codegen_node(new_cond) and _replace_c_children(new_cond, transform, seen):
                        changed = True
                    if _structured_codegen_node(new_body) and _replace_c_children(new_body, transform, seen):
                        changed = True
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
                    changed = True

        return changed
    finally:
        seen.remove(node_id)


def _iter_c_nodes_deep(node, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    if not _structured_codegen_node(node):
        return
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)
    yield node

    for attr in dir(node):
        if attr.startswith("_") or attr in {"codegen"}:
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if _structured_codegen_node(value):
            yield from _iter_c_nodes_deep(value, seen)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if _structured_codegen_node(item):
                    yield from _iter_c_nodes_deep(item, seen)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node(subitem):
                            yield from _iter_c_nodes_deep(subitem, seen)


def _same_c_expression(lhs, rhs) -> bool:
    if type(lhs) is not type(rhs):
        return False

    if isinstance(lhs, structured_c.CConstant):
        return lhs.value == rhs.value

    if isinstance(lhs, structured_c.CTypeCast):
        return _same_c_expression(lhs.expr, rhs.expr)

    if isinstance(lhs, structured_c.CUnaryOp):
        return lhs.op == rhs.op and _same_c_expression(lhs.operand, rhs.operand)

    if isinstance(lhs, structured_c.CBinaryOp):
        return (
            lhs.op == rhs.op
            and _same_c_expression(lhs.lhs, rhs.lhs)
            and _same_c_expression(lhs.rhs, rhs.rhs)
        )

    if isinstance(lhs, structured_c.CVariable):
        lvar = getattr(lhs, "variable", None)
        rvar = getattr(rhs, "variable", None)
        if type(lvar) is not type(rvar):
            return False
        if isinstance(lvar, SimRegisterVariable):
            return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
        if isinstance(lvar, SimStackVariable):
            return (
                getattr(lvar, "base", None) == getattr(rvar, "base", None)
                and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
                and getattr(lvar, "size", None) == getattr(rvar, "size", None)
            )
        if isinstance(lvar, SimMemoryVariable):
            return (
                getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
                and getattr(lvar, "size", None) == getattr(rvar, "size", None)
            )
        return lvar == rvar

    return lhs is rhs


def _same_c_storage(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False

    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    if type(lvar) is not type(rvar):
        return False

    if isinstance(lvar, SimRegisterVariable):
        return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
    if isinstance(lvar, SimStackVariable):
        return (
            getattr(lvar, "base", None) == getattr(rvar, "base", None)
            and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
        )
    if isinstance(lvar, SimMemoryVariable):
        return getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
    return lvar == rvar


def _is_c_constant_int(node, value: int) -> bool:
    return isinstance(node, structured_c.CConstant) and isinstance(node.value, int) and node.value == value


def _cite_is_negation(node) -> bool:
    return type(node).__name__ == "CITE" and _is_c_constant_int(node.iftrue, 0) and _is_c_constant_int(node.iffalse, 1)


def _invert_comparison_op(op: str) -> str | None:
    return {
        "==": "!=",
        "!=": "==",
        ">": "<=",
        "<": ">=",
        ">=": "<",
        "<=": ">",
    }.get(op)


def _make_inverted_comparison(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    inverted = _invert_comparison_op(node.op)
    if inverted is None:
        return None
    return structured_c.CBinaryOp(
        inverted,
        node.lhs,
        node.rhs,
        type=getattr(node, "type", None),
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )


def _extract_same_zero_compare_expr(node):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "CmpEQ":
        return None

    if _is_c_constant_int(node.rhs, 0):
        return node.lhs
    if _is_c_constant_int(node.lhs, 0):
        return node.rhs
    return None


def _extract_zero_flag_source_expr(node):
    if isinstance(node, structured_c.CBinaryOp):
        if node.op == "Mul":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            for maybe_logic, maybe_scale in pairs:
                if not _is_c_constant_int(maybe_scale, 64):
                    continue
                source_expr = _extract_same_zero_compare_expr(maybe_logic)
                if source_expr is not None:
                    return source_expr
                if not isinstance(maybe_logic, structured_c.CBinaryOp) or maybe_logic.op != "LogicalAnd":
                    continue
                lhs_expr = _extract_same_zero_compare_expr(maybe_logic.lhs)
                rhs_expr = _extract_same_zero_compare_expr(maybe_logic.rhs)
                if lhs_expr is not None and rhs_expr is not None and _same_c_expression(lhs_expr, rhs_expr):
                    return lhs_expr

        for attr in ("lhs", "rhs"):
            child = getattr(node, attr, None)
            if _structured_codegen_node(child):
                extracted = _extract_zero_flag_source_expr(child)
                if extracted is not None:
                    return extracted

    elif isinstance(node, structured_c.CUnaryOp):
        child = getattr(node, "operand", None)
        if _structured_codegen_node(child):
            return _extract_zero_flag_source_expr(child)

    elif isinstance(node, structured_c.CTypeCast):
        child = getattr(node, "expr", None)
        if _structured_codegen_node(child):
            return _extract_zero_flag_source_expr(child)

    return None


def _simplify_zero_flag_comparison(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _is_c_constant_int(node.rhs, 0):
        expr = node.lhs
    elif _is_c_constant_int(node.lhs, 0):
        expr = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr(expr)
    if source_expr is None:
        return node

    if node.op == "CmpEQ":
        return source_expr

    return structured_c.CUnaryOp("Not", source_expr, codegen=codegen)


def _simplify_boolean_expr(node, codegen):
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Not":
        operand = _unwrap_c_casts(node.operand)
        if isinstance(operand, structured_c.CBinaryOp) and operand.op == "Sub":
            lhs_const = _c_constant_value(_unwrap_c_casts(operand.lhs))
            rhs_const = _c_constant_value(_unwrap_c_casts(operand.rhs))
            if rhs_const is not None:
                return structured_c.CBinaryOp(
                    "CmpEQ",
                    operand.lhs,
                    structured_c.CConstant(
                        rhs_const,
                        getattr(operand.rhs, "type", None) or getattr(operand, "type", None) or SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                    tags=getattr(node, "tags", None),
                )
            if lhs_const is not None:
                return structured_c.CBinaryOp(
                    "CmpEQ",
                    operand.rhs,
                    structured_c.CConstant(
                        lhs_const,
                        getattr(operand.lhs, "type", None) or getattr(operand, "type", None) or SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                    tags=getattr(node, "tags", None),
                )

    simplified = _simplify_zero_flag_comparison(node, codegen)
    if simplified is not node:
        return simplified

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Not" and _cite_is_negation(node.operand):
        inverted = _make_inverted_comparison(node.operand.cond, codegen)
        return inverted if inverted is not None else node.operand.cond

    if _cite_is_negation(node):
        cond = node.cond
        inverted = _make_inverted_comparison(cond, codegen)
        if inverted is not None:
            return inverted

    return node


def _simplify_zero_mul_or_expr(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return node

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)

    def is_zero_mul(expr):
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Mul":
            return False
        return _c_constant_value(_unwrap_c_casts(expr.lhs)) == 0 or _c_constant_value(_unwrap_c_casts(expr.rhs)) == 0

    if _c_constant_value(lhs) == 0:
        return node.rhs
    if _c_constant_value(rhs) == 0:
        return node.lhs
    if is_zero_mul(lhs):
        return node.rhs
    if is_zero_mul(rhs):
        return node.lhs
    return node


def _simplify_structured_c_expressions(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _is_linear_register_temp(cvar) -> bool:
        return isinstance(cvar, structured_c.CVariable) and isinstance(getattr(cvar, "name", None), str) and re.fullmatch(r"v\d+", getattr(cvar, "name", "")) is not None

    def _collect_high_byte_temp_constants(node):
        aliases: dict[int, int] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            if not _is_linear_register_temp(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
                continue
            for maybe_const, maybe_other in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
                const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                if const_value is None or const_value & 0xFF:
                    continue
                aliases[id(getattr(walk_node.lhs, "variable", None))] = const_value >> 8
                break
        return aliases

    def _collect_shift_extract_aliases(node):
        aliases: dict[int, tuple[object, int]] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            if not _is_linear_register_temp(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Shr":
                continue
            shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
            base = _unwrap_c_casts(rhs.lhs)
            if shift is None or not isinstance(shift, int):
                continue
            if not isinstance(base, structured_c.CBinaryOp) or base.op != "And":
                continue
            mask_lhs = _c_constant_value(_unwrap_c_casts(base.lhs))
            mask_rhs = _c_constant_value(_unwrap_c_casts(base.rhs))
            inner = None
            if mask_lhs == 0xFF00:
                inner = base.rhs
            elif mask_rhs == 0xFF00:
                inner = base.lhs
            if inner is None:
                continue
            aliases[id(getattr(walk_node.lhs, "variable", None))] = (inner, shift)
        return aliases

    def _collect_mask_shift_aliases(node):
        aliases: dict[int, tuple[object, int, int]] = {}
        for _ in range(4):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp(walk_node.lhs):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                rhs = _unwrap_c_casts(walk_node.rhs)
                alias = None

                if isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "And":
                    lhs_const = _c_constant_value(_unwrap_c_casts(rhs.lhs))
                    rhs_const = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                    if lhs_const is not None:
                        alias = (rhs.rhs, lhs_const, 0)
                    elif rhs_const is not None:
                        alias = (rhs.lhs, rhs_const, 0)

                elif isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "Shr":
                    shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                    shifted = _unwrap_c_casts(rhs.lhs)
                    if isinstance(shifted, structured_c.CVariable) and isinstance(shift, int):
                        parent = aliases.get(id(getattr(shifted, "variable", None)))
                        if parent is not None:
                            base_expr, mask, base_shift = parent
                            alias = (base_expr, mask, base_shift + shift)

                if alias is None:
                    continue
                if aliases.get(key) != alias:
                    aliases[key] = alias
                    changed = True
            if not changed:
                break
        return aliases

    def _collect_copy_aliases(node):
        aliases: dict[int, object] = {}
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if not isinstance(rhs, structured_c.CVariable):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                rhs_var = getattr(rhs, "variable", None)
                if lhs_var is None or rhs_var is None:
                    continue
                key = id(lhs_var)
                value = aliases.get(id(rhs_var), rhs)
                if aliases.get(key) != value:
                    aliases[key] = value
                    changed = True
            if not changed:
                break
        return aliases

    def _extract_linear_delta(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0

        left_base, left_delta = _extract_linear_delta(expr.lhs)
        right_base, right_delta = _extract_linear_delta(expr.rhs)
        if left_base is not None and right_base is not None:
            if _same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if left_base is not None:
            if expr.op == "Add":
                return left_base, left_delta + right_delta
            return left_base, left_delta - right_delta
        if right_base is not None:
            if expr.op == "Add":
                return right_base, left_delta + right_delta
            return expr, 0
        if expr.op == "Add":
            return None, left_delta + right_delta
        return None, left_delta - right_delta

    def _fold_simple_add_constants(node):
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
            return node

        def _collect_add_terms(expr):
            terms = []
            stack = [_unwrap_c_casts(expr)]
            seen: set[int] = set()
            while stack:
                current = _unwrap_c_casts(stack.pop())
                key = id(current)
                if key in seen:
                    terms.append(current)
                    continue
                seen.add(key)
                if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
                    stack.append(current.rhs)
                    stack.append(current.lhs)
                else:
                    terms.append(current)
            return terms

        terms = _collect_add_terms(node)
        if len(terms) > 8:
            return node
        const_total = 0
        const_type = None
        base_terms = []
        for term in terms:
            const_value = _c_constant_value(term)
            if const_value is not None:
                const_total += const_value
                const_type = const_type or getattr(term, "type", None)
                continue
            base_terms.append(term)

        if len(base_terms) != 1 or not terms:
            return node

        base_expr = base_terms[0]
        if const_total == 0:
            return base_expr

        if const_type is None:
            const_type = getattr(base_expr, "type", None) or getattr(node, "type", None) or SimTypeShort(False)
        return structured_c.CBinaryOp(
            "Add" if const_total > 0 else "Sub",
            base_expr,
            structured_c.CConstant(
                const_total if const_total > 0 else -const_total,
                const_type,
                codegen=getattr(node, "codegen", None),
            ),
            codegen=getattr(node, "codegen", None),
        )

    def _build_linear_expr(base_expr, delta, codegen):
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _match_constant_high_byte_extract(node):
        node = _unwrap_c_casts(node)
        if isinstance(node, structured_c.CBinaryOp) and node.op == "And":
            for maybe_inner, maybe_mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_mask)) == 0xFF:
                    inner_val = _match_constant_high_byte_extract(maybe_inner)
                    if inner_val is not None:
                        return inner_val
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
            return None
        shift = _c_constant_value(_unwrap_c_casts(node.rhs))
        inner = _unwrap_c_casts(node.lhs)
        if shift != 8 or not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
            return None
        for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
            const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
            other = _unwrap_c_casts(maybe_other)
            if const_value is None or const_value & 0xFF:
                continue
            if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
                lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
                rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
                if lhs_mask == 0xFF or rhs_mask == 0xFF:
                    return (const_value >> 8) & 0xFF
        return None

    variable_use_counts: dict[int, int] = {}
    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(walk_node, structured_c.CVariable):
            continue
        variable = getattr(walk_node, "variable", None)
        if variable is not None:
            variable_use_counts[id(variable)] = variable_use_counts.get(id(variable), 0) + 1

    high_byte_aliases: dict[int, int] = {}
    shift_extract_aliases: dict[int, tuple[object, int]] = {}
    mask_shift_aliases: dict[int, tuple[object, int, int]] = {}
    copy_aliases: dict[int, object] = {}
    expr_aliases: dict[int, object] = {}
    linear_aliases: dict[int, object] = {}
    _no_match = object()
    adjacent_byte_pair_cache: dict[tuple[int, int], object] = {}
    word_plus_minus_one_cache: dict[int, object] = {}
    linear_word_delta_cache: dict[int, object] = {}
    high_byte_preserving_word_cache: dict[int, object] = {}

    def _resolve_copy_alias_expr(node, seen: set[int] | None = None):
        current = _unwrap_c_casts(node)
        if seen is None:
            seen = set()
        current_key = id(current)
        if current_key in seen:
            return current
        seen.add(current_key)
        while isinstance(current, structured_c.CVariable):
            variable = getattr(current, "variable", None)
            if variable is None:
                break
            key = id(variable)
            if key in seen:
                break
            seen.add(key)
            alias = copy_aliases.get(key)
            if alias is None:
                alias = expr_aliases.get(key)
                if alias is None:
                    break
            current = _unwrap_c_casts(alias)
        return current

    def _expr_is_safe_inline_candidate(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return _expr_is_safe_inline_candidate(expr.lhs) and _expr_is_safe_inline_candidate(expr.rhs)
        return False

    def _match_adjacent_byte_pair_var_expr(low_expr, high_expr):
        key = (id(low_expr), id(high_expr))
        if key in adjacent_byte_pair_cache:
            cached = adjacent_byte_pair_cache[key]
            return None if cached is _no_match else cached
        low_expr = _resolve_copy_alias_expr(low_expr)
        high_expr = _resolve_copy_alias_expr(high_expr)

        if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
                if scale not in {8, 0x100}:
                    continue
                high_expr = _resolve_copy_alias_expr(maybe_inner)
                break

        low_var = getattr(low_expr, "variable", None) if isinstance(low_expr, structured_c.CVariable) else None
        high_var = getattr(high_expr, "variable", None) if isinstance(high_expr, structured_c.CVariable) else None
        if not isinstance(low_var, SimMemoryVariable) or not isinstance(high_var, SimMemoryVariable):
            adjacent_byte_pair_cache[key] = _no_match
            return None
        if getattr(low_var, "region", None) != getattr(high_var, "region", None):
            adjacent_byte_pair_cache[key] = _no_match
            return None
        if getattr(high_var, "addr", None) != getattr(low_var, "addr", None) + 1:
            adjacent_byte_pair_cache[key] = _no_match
            return None
        low_name = getattr(low_var, "name", None)
        if not isinstance(low_name, str) or not low_name:
            low_name = f"field_{low_var.addr:x}"
        result = structured_c.CVariable(
            SimMemoryVariable(low_var.addr, 2, name=_sanitize_cod_identifier(low_name), region=codegen.cfunc.addr),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        adjacent_byte_pair_cache[key] = result
        return result

    def _match_word_plus_minus_one_expr(node):
        key = id(node)
        if key in word_plus_minus_one_cache:
            cached = word_plus_minus_one_cache[key]
            return None if cached is _no_match else cached
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            word_plus_minus_one_cache[key] = _no_match
            return None

        def _strip_byte_cast(expr):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, structured_c.CTypeCast):
                type_ = getattr(expr, "type", None)
                if getattr(type_, "size", None) == 8:
                    return _unwrap_c_casts(expr.expr)
            return expr

        def _match_masked_high_word(expr):
            expr = _unwrap_c_casts(expr)
            if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "And":
                return None
            for maybe_word, maybe_mask in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 0xFF00:
                    continue
                return _unwrap_c_casts(maybe_word)
            return None

        for masked_expr, delta_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            base_expr = _match_masked_high_word(masked_expr)
            if base_expr is None:
                continue
            delta_expr = _unwrap_c_casts(delta_expr)
            if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
                continue
            low_expr, const_expr = delta_expr.lhs, delta_expr.rhs
            if _c_constant_value(_unwrap_c_casts(low_expr)) is None and _c_constant_value(_unwrap_c_casts(const_expr)) is None:
                continue
            if _same_c_expression(_strip_byte_cast(low_expr), base_expr) and _c_constant_value(_unwrap_c_casts(const_expr)) == 1:
                return structured_c.CBinaryOp(
                    "Add" if delta_expr.op == "Add" else "Sub",
                    base_expr,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            if _same_c_expression(_strip_byte_cast(const_expr), base_expr) and _c_constant_value(_unwrap_c_casts(low_expr)) == 1:
                return structured_c.CBinaryOp(
                    "Add" if delta_expr.op == "Add" else "Sub",
                    base_expr,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )

        word_plus_minus_one_cache[key] = _no_match
        return None

    def _match_linear_word_delta_expr(node):
        key = id(node)
        if key in linear_word_delta_cache:
            cached = linear_word_delta_cache[key]
            return None if cached is _no_match else cached
        node = _resolve_copy_alias_expr(_unwrap_c_casts(node))

        def _extract(expr, seen: set[int] | None = None):
            expr = _resolve_copy_alias_expr(_unwrap_c_casts(expr))
            if seen is None:
                seen = set()
            key = id(expr)
            if key in seen:
                return expr, 0
            seen.add(key)
            if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
                return None, int(expr.value)
            if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
                return expr, 0

            left_base, left_delta = _extract(expr.lhs, seen)
            right_base, right_delta = _extract(expr.rhs, seen)
            if left_base is not None and right_base is not None:
                if _same_c_expression(left_base, right_base) and expr.op == "Add":
                    return left_base, left_delta + right_delta
                return expr, 0
            if left_base is not None:
                if expr.op == "Add":
                    return left_base, left_delta + right_delta
                return left_base, left_delta - right_delta
            if right_base is not None:
                if expr.op == "Add":
                    return right_base, left_delta + right_delta
                return expr, 0
            if expr.op == "Add":
                return None, left_delta + right_delta
            return None, left_delta - right_delta

        base_expr, delta = _extract(node)
        if base_expr is None or delta == 0:
            linear_word_delta_cache[key] = _no_match
            return None
        if not isinstance(delta, int):
            linear_word_delta_cache[key] = _no_match
            return None

        if delta > 0:
            op = "Add"
            magnitude = delta
        else:
            op = "Sub"
            magnitude = -delta

        result = structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        linear_word_delta_cache[key] = result
        return result

    for _ in range(3):
        changed = False
        for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            if not _is_linear_register_temp(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op not in {"Add", "Sub"}:
                continue
            resolved_rhs = _resolve_copy_alias_expr(rhs)
            linear_rhs = _match_linear_word_delta_expr(resolved_rhs)
            if linear_rhs is None:
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if lhs_var is None:
                continue
            key = id(lhs_var)
            if linear_aliases.get(key) != linear_rhs:
                linear_aliases[key] = linear_rhs
                changed = True
        if not changed:
            break

    def _match_high_byte_preserving_word_expr(node):
        key = id(node)
        if key in high_byte_preserving_word_cache:
            cached = high_byte_preserving_word_cache[key]
            return None if cached is _no_match else cached
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            high_byte_preserving_word_cache[key] = _no_match
            return None

        def _strip_byte_cast(expr):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, structured_c.CTypeCast):
                type_ = getattr(expr, "type", None)
                if getattr(type_, "size", None) == 8:
                    return _unwrap_c_casts(expr.expr)
            return expr

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_expr = _unwrap_c_casts(low_expr)
            high_expr = _unwrap_c_casts(high_expr)
            if not isinstance(low_expr, structured_c.CBinaryOp) or low_expr.op != "And":
                continue

            base_expr = None
            for maybe_word, maybe_mask in ((low_expr.lhs, low_expr.rhs), (low_expr.rhs, low_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 255:
                    continue
                base_expr = _unwrap_c_casts(maybe_word)
                break
            if base_expr is None:
                continue

            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op != "Mul":
                continue

            for maybe_delta, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                    continue
                delta_expr = _strip_byte_cast(maybe_delta)
                if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
                    continue

                for maybe_inner, maybe_const in ((delta_expr.lhs, delta_expr.rhs), (delta_expr.rhs, delta_expr.lhs)):
                    if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
                        continue
                    inner = _strip_byte_cast(maybe_inner)
                    if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Shr":
                        continue
                    if _c_constant_value(_unwrap_c_casts(inner.rhs)) != 8:
                        continue
                    if not _same_c_expression(_unwrap_c_casts(inner.lhs), base_expr):
                        continue
                    return structured_c.CBinaryOp(
                        "Add" if delta_expr.op == "Add" else "Sub",
                        base_expr,
                        structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )

        high_byte_preserving_word_cache[key] = _no_match
        return None

    def _is_dead_stack_address_init(stmt) -> bool:
        if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
            return False
        lhs_var = getattr(stmt.lhs, "variable", None)
        if not isinstance(lhs_var, SimStackVariable) or getattr(lhs_var, "base", None) != "bp":
            return False
        if variable_use_counts.get(id(lhs_var), 0) != 1:
            return False
        rhs = stmt.rhs
        if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Reference":
            return False
        operand = rhs.operand
        if not isinstance(operand, structured_c.CVariable):
            return False
        ref_var = getattr(operand, "variable", None)
        return isinstance(ref_var, SimStackVariable) and getattr(ref_var, "base", None) == "bp"

    def _is_redundant_self_copy(stmt) -> bool:
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _unwrap_c_casts(stmt.lhs)
        rhs = _unwrap_c_casts(stmt.rhs)
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = getattr(lhs, "variable", None)
        rhs_var = getattr(rhs, "variable", None)
        if lhs_var is None or rhs_var is None or lhs_var is not rhs_var:
            return False
        return _is_linear_register_temp(lhs)

    def _flatten_bitwise_terms(expr, op):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == op:
            return _flatten_bitwise_terms(expr.lhs, op) + _flatten_bitwise_terms(expr.rhs, op)
        return [expr]

    def _rewrite_and_over_or(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
            return None
        for or_expr, const_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            or_expr = _unwrap_c_casts(or_expr)
            const_value = _c_constant_value(_unwrap_c_casts(const_expr))
            if const_value is None or not isinstance(or_expr, structured_c.CBinaryOp) or or_expr.op != "Or":
                continue
            for and_expr, inner_const_expr in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                inner_const = _c_constant_value(_unwrap_c_casts(inner_const_expr))
                if inner_const is None or not isinstance(and_expr, structured_c.CBinaryOp) or and_expr.op != "And":
                    continue
                for inner_base, inner_mask_expr in ((and_expr.lhs, and_expr.rhs), (and_expr.rhs, and_expr.lhs)):
                    inner_mask = _c_constant_value(_unwrap_c_casts(inner_mask_expr))
                    if inner_mask is None:
                        continue
                    left = structured_c.CBinaryOp(
                        "And",
                        _unwrap_c_casts(inner_base),
                        structured_c.CConstant(const_value, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                    right_const = inner_const & const_value
                    if right_const == 0:
                        return left
                    right = structured_c.CConstant(right_const, SimTypeShort(False), codegen=codegen)
                    return structured_c.CBinaryOp("Or", left, right, codegen=codegen)
        return None

    def transform(node):
        if isinstance(node, structured_c.CTypeCast):
            target_type = getattr(node, "type", None)
            rendered = str(target_type) if target_type is not None else ""
            if "[" in rendered and isinstance(node.expr, structured_c.CVariable):
                return node.expr
            if "[" in rendered and not isinstance(node.expr, structured_c.CConstant):
                return node.expr

        if isinstance(node, structured_c.CBinaryOp):
            lhs = _resolve_copy_alias_expr(_unwrap_c_casts(node.lhs))
            rhs = _resolve_copy_alias_expr(_unwrap_c_casts(node.rhs))
            if node.op in {"Add", "Or"}:
                widened = _match_adjacent_byte_pair_var_expr(lhs, rhs)
                if widened is None:
                    widened = _match_adjacent_byte_pair_var_expr(rhs, lhs)
                if widened is not None:
                    return widened
                delta = _match_word_plus_minus_one_expr(node)
                if delta is not None:
                    return delta
                linear = _match_linear_word_delta_expr(node)
                if linear is not None:
                    return linear
                high_update = _match_high_byte_preserving_word_expr(node)
                if high_update is not None:
                    return high_update
            if node.op in {"Add", "Sub"}:
                resolved = structured_c.CBinaryOp(node.op, lhs, rhs, codegen=codegen)
                linear = _match_linear_word_delta_expr(resolved)
                if linear is not None:
                    return linear
            if isinstance(lhs, structured_c.CConstant) and isinstance(rhs, structured_c.CConstant):
                if isinstance(lhs.value, int) and isinstance(rhs.value, int):
                    result = None
                    if node.op == "Add":
                        result = lhs.value + rhs.value
                    elif node.op == "Sub":
                        result = lhs.value - rhs.value
                    elif node.op == "Mul":
                        result = lhs.value * rhs.value
                    elif node.op == "And":
                        result = lhs.value & rhs.value
                    elif node.op == "Or":
                        result = lhs.value | rhs.value
                    elif node.op == "Xor":
                        result = lhs.value ^ rhs.value
                    elif node.op == "Shl":
                        result = lhs.value << rhs.value
                    elif node.op == "Shr":
                        result = lhs.value >> rhs.value
                    if result is not None:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(result, type_, codegen=codegen)
            rewritten_and = _rewrite_and_over_or(node)
            if rewritten_and is not None:
                return rewritten_and
            if node.op in {"And", "Or"}:
                terms = _flatten_bitwise_terms(node, node.op)
                const_value = None
                const_type = None
                non_constants = []
                for term in terms:
                    value = _c_constant_value(term)
                    if value is None:
                        non_constants.append(term)
                        continue
                    const_type = getattr(term, "type", None) or const_type
                    if const_value is None:
                        const_value = value
                    elif node.op == "And":
                        const_value &= value
                    else:
                        const_value |= value
                if len(terms) > 2 or len(non_constants) != len(terms):
                    rebuilt_terms = list(non_constants)
                    if const_value is not None:
                        if not ((node.op == "And" and const_value == -1) or (node.op == "Or" and const_value == 0)):
                            rebuilt_terms.append(
                                structured_c.CConstant(
                                    const_value,
                                    const_type or getattr(node, "type", None) or SimTypeShort(False),
                                    codegen=codegen,
                                )
                            )
                    if not rebuilt_terms:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(const_value if const_value is not None else 0, type_, codegen=codegen)
                    result = rebuilt_terms[0]
                    for term in rebuilt_terms[1:]:
                        result = structured_c.CBinaryOp(node.op, result, term, codegen=codegen)
                    return result
            if node.op in {"Add", "Or", "Xor"}:
                if _c_constant_value(lhs) == 0:
                    return node.rhs
                if _c_constant_value(rhs) == 0:
                    return node.lhs
            if node.op == "Sub":
                if _c_constant_value(rhs) == 0:
                    return node.lhs
            if node.op == "Add":
                folded = _fold_simple_add_constants(node)
                if folded is not node:
                    return folded
            if node.op == "Sub":
                base_expr, delta = _extract_linear_delta(node)
                if base_expr is not None:
                    rebuilt = _build_linear_expr(base_expr, delta, codegen)
                    if not _same_c_expression(rebuilt, node):
                        return rebuilt
            if node.op in {"And", "Or"} and _same_c_expression(lhs, rhs):
                return lhs
            if node.op == "Xor" and _same_c_expression(lhs, rhs):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=codegen)
            if node.op == "Mul":
                if _c_constant_value(lhs) == 0 or _c_constant_value(rhs) == 0:
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
                if _c_constant_value(lhs) == 1:
                    return node.rhs
                if _c_constant_value(rhs) == 1:
                    return node.lhs
            if node.op == "And":
                if _c_constant_value(lhs) == 0 or _c_constant_value(rhs) == 0:
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
                for maybe_inner, maybe_mask in ((lhs, rhs), (rhs, lhs)):
                    if _c_constant_value(maybe_mask) != 0xFF:
                        continue
                    const_high = _match_constant_high_byte_extract(maybe_inner)
                    if const_high is not None:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(const_high, type_, codegen=codegen)
                    if isinstance(maybe_inner, structured_c.CVariable):
                        alias = mask_shift_aliases.get(id(getattr(maybe_inner, "variable", None)))
                        if alias is not None:
                            base_expr, mask, total_shift = alias
                            if mask == 0xFF00:
                                simplified = structured_c.CBinaryOp(
                                    "Shr",
                                    base_expr,
                                    structured_c.CConstant(total_shift, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                                base_type = getattr(getattr(base_expr, "type", None), "size", None)
                                if total_shift == 8 and base_type == 16:
                                    return simplified
                                return structured_c.CBinaryOp(
                                    "And",
                                    simplified,
                                    structured_c.CConstant(0xFF, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                    inner = _unwrap_c_casts(maybe_inner)
                    if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Shr":
                        shift = _c_constant_value(_unwrap_c_casts(inner.rhs))
                        shifted = _unwrap_c_casts(inner.lhs)
                        if isinstance(shifted, structured_c.CVariable):
                            alias = shift_extract_aliases.get(id(getattr(shifted, "variable", None)))
                            if alias is not None and isinstance(shift, int):
                                base_expr, base_shift = alias
                                total_shift = base_shift + shift
                                simplified = structured_c.CBinaryOp(
                                    "Shr",
                                    base_expr,
                                    structured_c.CConstant(total_shift, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                                base_type = getattr(getattr(base_expr, "type", None), "size", None)
                                if total_shift == 8 and base_type == 16:
                                    return simplified
                                return structured_c.CBinaryOp(
                                    "And",
                                    simplified,
                                    structured_c.CConstant(0xFF, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
            simplified_or = _simplify_zero_mul_or_expr(node, codegen)
            if simplified_or is not node:
                return simplified_or
            if node.op == "Shr":
                if isinstance(lhs, structured_c.CBinaryOp) and lhs.op == "Shr":
                    inner_shift = _c_constant_value(_unwrap_c_casts(lhs.rhs))
                    outer_shift = _c_constant_value(rhs)
                    if isinstance(inner_shift, int) and isinstance(outer_shift, int):
                        return structured_c.CBinaryOp(
                            "Shr",
                            lhs.lhs,
                            structured_c.CConstant(inner_shift + outer_shift, SimTypeShort(False), codegen=codegen),
                            codegen=codegen,
                        )
                if _is_c_constant_int(rhs, 8) and isinstance(lhs, structured_c.CVariable):
                    alias = high_byte_aliases.get(id(getattr(lhs, "variable", None)))
                    if alias is not None:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(alias, type_, codegen=codegen)
        simplified = _simplify_boolean_expr(node, codegen)
        if simplified is not node:
            return simplified
        if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
            if _same_c_expression(node.lhs, node.rhs):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=codegen)
        if isinstance(node, structured_c.CAssignment) and _is_redundant_self_copy(node):
            return structured_c.CConstant(0, getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None), codegen=codegen)
        return node

    def prune_dead_stack_address_inits(node) -> bool:
        changed = False
        if isinstance(node, structured_c.CStatements):
            new_statements = []
            for stmt in node.statements:
                if _is_dead_stack_address_init(stmt):
                    changed = True
                    continue
                if _is_redundant_self_copy(stmt):
                    changed = True
                    continue
                if prune_dead_stack_address_inits(stmt):
                    changed = True
                new_statements.append(stmt)
            if len(new_statements) != len(node.statements):
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                if prune_dead_stack_address_inits(body):
                    changed = True
            if node.else_node is not None and prune_dead_stack_address_inits(node.else_node):
                changed = True
        return changed

    root = codegen.cfunc.statements
    changed = False
    for _ in range(3):
        iter_changed = False
        high_byte_aliases = _collect_high_byte_temp_constants(root)
        shift_extract_aliases = _collect_shift_extract_aliases(root)
        mask_shift_aliases = _collect_mask_shift_aliases(root)
        copy_aliases = _collect_copy_aliases(root)
        new_root = transform(root)
        if new_root is not root:
            codegen.cfunc.statements = new_root
            root = new_root
            iter_changed = True
        if _replace_c_children(root, transform):
            iter_changed = True
        if prune_dead_stack_address_inits(root):
            iter_changed = True
        changed |= iter_changed
        if not iter_changed:
            break
    return changed


def _unwrap_c_casts(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _match_shift_right_8_expr(node):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return None
    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)
    if _is_c_constant_int(rhs, 8):
        return lhs
    if _is_c_constant_int(lhs, 8):
        return rhs
    return None


def _attach_cod_global_names(project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                linear = getattr(variable, "addr", None)
                symbol = _synthetic_global_entry(synthetic_globals, linear) if isinstance(linear, int) else None
                if symbol is not None:
                    type_ = getattr(node, "variable_type", None)
                    if type_ is None:
                        return node
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    key = (linear, size)
                    existing = created.get(key)
                    if existing is not None:
                        return existing
                    name, _width = symbol
                    name = _sanitize_cod_identifier(name)
                    cvar = structured_c.CVariable(
                        SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
                        variable_type=type_,
                        codegen=codegen,
                    )
                    created[key] = cvar
                    return cvar

        seg_name, linear = _match_segmented_dereference(node, project)
        symbol = _synthetic_global_entry(synthetic_globals, linear)
        if seg_name != "ds" or symbol is None:
            return node

        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        bits = getattr(type_, "size", None)
        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        key = (linear, size)
        existing = created.get(key)
        if existing is not None:
            return existing

        name, _width = symbol
        name = _sanitize_cod_identifier(name)
        cvar = structured_c.CVariable(
            SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
            variable_type=type_,
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _attach_cod_global_declaration_names(codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
        if symbol is None:
            continue
        raw_name, _width = symbol
        name = _sanitize_cod_identifier(raw_name)
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        if getattr(cvar, "name", None) != name:
            cvar.name = name
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimMemoryVariable):
                continue
            symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
            if symbol is None:
                continue
            raw_name, _width = symbol
            name = _sanitize_cod_identifier(raw_name)
            new_entries = set()
            for cvariable, vartype in cvar_and_vartypes:
                if getattr(cvariable, "name", None) != name:
                    cvariable.name = name
                    changed = True
                new_entries.add((cvariable, vartype))
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _attach_cod_global_declaration_types(codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = SimTypeShort(False)

    def desired_type(variable):
        symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
        if symbol is None:
            return None
        _raw_name, width = symbol
        if width == 2:
            return target_type
        return None

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type = desired_type(variable)
        if new_type is None:
            continue
        if getattr(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        if getattr(cvar, "variable_type", None) != new_type:
            cvar.variable_type = new_type
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "size", None) != 2:
            try:
                unified.size = 2
                changed = True
            except Exception:
                pass

    for cextern in getattr(codegen, "cexterns", ()) or ():
        variable = getattr(cextern, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type = desired_type(variable)
        if new_type is None:
            continue
        if getattr(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        if getattr(cextern, "variable_type", None) != new_type:
            cextern.variable_type = new_type
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimMemoryVariable):
                continue
            new_type = desired_type(variable)
            if new_type is None:
                continue
            if getattr(variable, "size", None) != 2:
                variable.size = 2
                changed = True
            new_entries = {(cvariable, new_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _access_trait_field_name(offset: int, size: int) -> str:
    return f"field_{offset:x}"


def _attach_access_trait_field_names(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(codegen.cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False

    repeated_offsets = {
        key[2]
        for key in traits.get("repeated_offsets", {})
        if isinstance(key, tuple)
        and len(key) >= 3
        and key[0] in {"ds", "es"}
        and isinstance(key[2], int)
    }
    if not repeated_offsets:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    changed = False

    def make_field_var(offset: int, size: int, name: str):
        key = (offset, size)
        existing = created.get(key)
        if existing is not None:
            return existing
        cvar = structured_c.CVariable(
            SimMemoryVariable(offset, size, name=_sanitize_cod_identifier(name), region=codegen.cfunc.addr),
            variable_type=SimTypeChar() if size == 1 else SimTypeShort(False),
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                addr = getattr(variable, "addr", None)
                if isinstance(addr, int) and addr in repeated_offsets:
                    type_ = getattr(node, "variable_type", None)
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    name = _access_trait_field_name(addr, size)
                    return make_field_var(addr, size, name)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            classified = _classify_segmented_dereference(node, project)
            if classified is None or classified.linear is None or classified.linear not in repeated_offsets:
                return node
            if classified.seg_name not in {"ds", "es"}:
                return node
            type_ = getattr(node, "type", None)
            bits = getattr(type_, "size", None)
            if bits not in {8, 16}:
                return node
            size = max(bits // project.arch.byte_width, 1)
            name = _access_trait_field_name(classified.linear, size)
            return make_field_var(classified.linear, size, name)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True
    return changed


def _attach_lst_data_names(project: angr.Project, codegen, lst_metadata: LSTMetadata | None) -> bool:
    if lst_metadata is None or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    temp_const_aliases: dict[int, int] = {}

    def is_linear_temp(cvar) -> bool:
        return (
            isinstance(cvar, structured_c.CVariable)
            and isinstance(getattr(cvar, "name", None), str)
            and re.fullmatch(r"v\d+", getattr(cvar, "name", "")) is not None
        )

    def collect_temp_aliases() -> None:
        aliases: dict[int, int] = {}
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not is_linear_temp(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                value = None
                if isinstance(rhs, structured_c.CConstant) and isinstance(rhs.value, int):
                    value = rhs.value
                elif isinstance(rhs, structured_c.CVariable):
                    value = aliases.get(id(getattr(rhs, "variable", None)))
                if value is None:
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                if aliases.get(key) != value:
                    aliases[key] = value
                    changed = True
            if not changed:
                break
        temp_const_aliases.update(aliases)

    def resolved_constant_value(node) -> int | None:
        node = _unwrap_c_casts(node)
        constant = _c_constant_value(node)
        if constant is not None:
            return constant
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if variable is not None:
                return temp_const_aliases.get(id(variable))
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = resolved_constant_value(node.lhs)
            rhs = resolved_constant_value(node.rhs)
            if lhs is not None and rhs is not None:
                return lhs + rhs if node.op == "Add" else lhs - rhs
        return None

    collect_temp_aliases()

    def make_data_var(offset: int, size: int, label: str):
        key = (offset, size)
        existing = created.get(key)
        if existing is not None:
            return existing
        cvar = structured_c.CVariable(
            SimMemoryVariable(offset, size, name=_sanitize_cod_identifier(label), region=codegen.cfunc.addr),
            variable_type=SimTypeChar() if size == 1 else SimTypeShort(False),
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                addr = getattr(variable, "addr", None)
                label = lst_metadata.data_labels.get(addr) if isinstance(addr, int) else None
                if label is not None and isinstance(addr, int):
                    type_ = getattr(node, "variable_type", None)
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    return make_data_var(addr, size, label)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            operand = node.operand
            if isinstance(operand, structured_c.CTypeCast):
                operand = operand.expr

            seg_name = None
            linear = 0
            saw_segment = False
            other_terms: list[object] = []
            for term in _flatten_c_add_terms(operand):
                inner = _unwrap_c_casts(term)
                if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                    for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                            continue
                        name = _segment_reg_name(_unwrap_c_casts(maybe_seg), project)
                        if name is not None:
                            seg_name = name
                            saw_segment = True
                            break
                    if saw_segment:
                        continue

                const_value = resolved_constant_value(inner)
                if const_value is not None:
                    linear += const_value
                    continue

                other_terms.append(inner)

            if seg_name == "ds" and not other_terms:
                label = _lst_data_label(lst_metadata, linear)
                if label is not None:
                    type_ = getattr(node, "type", None)
                    if type_ is not None:
                        bits = getattr(type_, "size", None)
                        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                        return make_data_var(linear, size, label)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _normalize_scalar_byte_register_types(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    target_type = SimTypeChar()
    changed = False

    def is_suspicious_scalar_type(type_) -> bool:
        if type_ is None:
            return False
        if getattr(type_, "size", None) == 8:
            return False
        type_name = type(type_).__name__
        if "Pointer" in type_name or "Array" in type_name:
            return True
        rendered = str(type_)
        return "[" in rendered or "*" in rendered

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimRegisterVariable):
            continue
        if getattr(variable, "size", None) != 1:
            continue
        current_type = getattr(cvar, "variable_type", None)
        if not is_suspicious_scalar_type(current_type):
            continue
        if current_type != target_type:
            cvar.variable_type = target_type
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if getattr(variable, "size", None) != 1:
                continue
            if not any(is_suspicious_scalar_type(vartype) for _cvariable, vartype in cvar_and_vartypes):
                continue
            new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _attach_segment_register_names(codegen, project: angr.Project | None = None) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    desired_names = {"cs", "ds", "es", "ss", "fs", "gs"}
    changed = False

    def reg_name(variable) -> str | None:
        if not isinstance(variable, SimRegisterVariable):
            return None
        if project is not None:
            name = project.arch.register_names.get(getattr(variable, "reg", None))
            if name in desired_names:
                return name
        name = getattr(variable, "name", None)
        if isinstance(name, str) and name in desired_names:
            return name
        return None

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        name = reg_name(variable)
        if name is None:
            continue
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            name = reg_name(variable)
            if name is None:
                continue
            new_entries = set()
            for cvariable, vartype in cvar_and_vartypes:
                new_entries.add((cvariable, vartype))
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _elide_redundant_segment_pointer_dereferences(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    eligible_bases: dict[int, tuple[structured_c.CVariable, set[int]]] = {}

    def collect_candidate_bases() -> None:
        for node in _iter_c_nodes_deep(codegen.cfunc.statements):
            classified = _classify_segmented_dereference(node, project)
            if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
                continue

            addr_expr = classified.addr_expr
            base_terms = []
            for term in _flatten_c_add_terms(addr_expr):
                inner = _unwrap_c_casts(term)
                if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                    segment_scale = False
                    for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                            continue
                        if _segment_reg_name(_unwrap_c_casts(maybe_seg), project) is not None:
                            segment_scale = True
                            break
                    if segment_scale:
                        continue

                if _c_constant_value(inner) is not None:
                    continue

                if isinstance(inner, structured_c.CVariable) and isinstance(getattr(inner, "variable", None), SimRegisterVariable):
                    base_terms.append(inner)
                    continue

                base_terms = []
                break

            if len(base_terms) != 1:
                continue
            base_var = getattr(base_terms[0], "variable", None)
            if not isinstance(base_var, SimRegisterVariable):
                continue
            entry = eligible_bases.get(id(base_var))
            if entry is None:
                eligible_bases[id(base_var)] = (base_terms[0], {classified.extra_offset})
            else:
                entry[1].add(classified.extra_offset)

    collect_candidate_bases()

    def _addr_expr_is_safe_projection(addr_expr) -> bool:
        allowed_ops = {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Div"}

        def _check(node) -> bool:
            node = _unwrap_c_casts(node)
            if _c_constant_value(node) is not None:
                return True
            if isinstance(node, structured_c.CVariable) and isinstance(getattr(node, "variable", None), SimRegisterVariable):
                return True
            if isinstance(node, structured_c.CUnaryOp) and node.op in {"Neg", "BitNot"}:
                return _check(node.operand)
            if isinstance(node, structured_c.CBinaryOp) and node.op in allowed_ops:
                return _check(node.lhs) and _check(node.rhs)
            return False

        return _check(addr_expr)

    def make_deref(base_expr, bits: int):
        element_type = SimTypeChar() if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, base_expr, codegen=codegen),
            codegen=codegen,
        )

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        match = _match_segment_register_based_dereference(node, project)
        if match is None:
            classified = _classify_segmented_dereference(node, project)
            if classified is None or classified.seg_name not in {"ds", "es"} or classified.addr_expr is None:
                return node
            base_expr = _strip_segment_scale_from_addr_expr(classified.addr_expr, project)
            if base_expr is None or not _addr_expr_is_safe_projection(base_expr):
                return node
        else:
            classified, base_expr = match
            base_var = getattr(getattr(base_expr, "variable", None), "reg", None)
            if base_var is None:
                return node
            eligible = eligible_bases.get(id(getattr(base_expr, "variable", None)))
            if eligible is None or eligible[1] != {0}:
                return node
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits != 8:
            return node
        # Keep the segment register visible elsewhere, but treat the register base
        # itself as the pointer value. This is the source-like shape we want.
        return make_deref(base_expr, bits)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True

    return changed


def _collect_access_traits(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    traits: dict[str, dict[tuple[object, ...], int]] = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
    }

    cache = getattr(project, "_inertia_access_traits", None)
    if isinstance(cache, dict):
        existing = cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(existing, dict):
            for bucket, bucket_data in existing.items():
                if bucket not in traits or not isinstance(bucket_data, dict):
                    continue
                traits[bucket].update(bucket_data)

    def record(bucket: str, key: tuple[object, ...]) -> None:
        store = traits[bucket]
        store[key] = store.get(key, 0) + 1

    def summarize_address(addr_expr):
        base_terms: list[object] = []
        offset = 0
        stride_terms: list[tuple[object, int]] = []

        for term in _flatten_c_add_terms(addr_expr):
            inner = _unwrap_c_casts(term)
            const_value = _c_constant_value(inner)
            if const_value is not None:
                offset += const_value
                continue

            if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                for maybe_index, maybe_stride in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                    stride = _c_constant_value(_unwrap_c_casts(maybe_stride))
                    if stride is None:
                        continue
                    index = _unwrap_c_casts(maybe_index)
                    if isinstance(index, structured_c.CVariable):
                        stride_terms.append((index, stride))
                        break
                else:
                    base_terms.append(inner)
                continue

            if isinstance(inner, structured_c.CVariable):
                base_terms.append(inner)
                continue

            base_terms.append(inner)

        return base_terms, offset, stride_terms

    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue

        classified = _classify_segmented_dereference(node, project)
        if classified is None:
            continue

        base_terms, offset, stride_terms = summarize_address(classified.addr_expr)
        if len(base_terms) == 1 and isinstance(base_terms[0], structured_c.CVariable):
            base_var = getattr(base_terms[0], "variable", None)
            if isinstance(base_var, SimRegisterVariable):
                record("base_const", (classified.seg_name, getattr(base_var, "reg", None), offset, getattr(node, "type", None)))
                record("repeated_offsets", (classified.seg_name, getattr(base_var, "reg", None), offset))
        for index_expr, stride in stride_terms:
            index_var = getattr(index_expr, "variable", None)
            if isinstance(index_var, SimRegisterVariable):
                record("base_stride", (classified.seg_name, getattr(index_var, "reg", None), stride, offset, getattr(node, "type", None)))

    for key, count in list(traits["repeated_offsets"].items()):
        if count < 2:
            del traits["repeated_offsets"][key]

    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_access_traits", cache)
    cache[getattr(codegen.cfunc, "addr", 0)] = traits
    return False


def _prune_unused_unnamed_memory_declarations(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            cvar = variables_in_use[variable]
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and id(unified) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            entries = unified_locals[variable]
            if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed


def _prune_unused_linear_register_declarations(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    def _is_linear_temp_name(name: str | None) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if not _is_linear_temp_name(getattr(variable, "name", None)):
                continue
            if id(variable) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if not _is_linear_temp_name(getattr(variable, "name", None)):
                continue
            entries = unified_locals[variable]
            if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed

def _attach_ss_stack_variables(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    promoted: set[tuple[int, int]] = set()

    def _stack_local_name(offset: int) -> str:
        return f"local_{offset:x}"

    def _stack_local_name_or_existing(*names: str | None, offset: int) -> str:
        for name in names:
            if isinstance(name, str) and name and not re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
                return name
        return _stack_local_name(offset)

    def transform(node):
        nonlocal promoted
        matched = _match_ss_stack_reference(node, project)
        if matched is None:
            return node
        stack_var, ref_cvar = matched

        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        bits = getattr(type_, "size", None)
        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        key = (stack_var.offset, size)
        promoted.add(key)
        existing = created.get(key)
        if existing is not None:
            return existing
        local_name = _stack_local_name_or_existing(
            getattr(ref_cvar, "name", None),
            getattr(stack_var, "name", None),
            offset=stack_var.offset,
        )

        cvar = structured_c.CVariable(
            SimStackVariable(
                stack_var.offset,
                size,
                base=getattr(stack_var, "base", "bp"),
                name=local_name,
                region=codegen.cfunc.addr,
            ),
            variable_type=type_,
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True

    target_type = SimTypeShort(False)
    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if getattr(variable, "base", None) != "bp":
            continue
        key = (getattr(variable, "offset", None), 2)
        if key not in promoted:
            continue
        if getattr(variable, "size", 0) < 2:
            variable.size = 2
            changed = True
        if getattr(cvar, "variable_type", None) != target_type:
            cvar.variable_type = target_type
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "size", 0) < 2:
            try:
                unified.size = 2
                changed = True
            except Exception:
                pass

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if getattr(variable, "base", None) != "bp":
                continue
            key = (getattr(variable, "offset", None), 2)
            if key not in promoted:
                continue
            new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True
    return changed


def _rewrite_ss_stack_byte_offsets(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    stack_pointer_aliases: dict[int, tuple[structured_c.CVariable, int]] = {}

    def _is_linear_temp(cvar) -> bool:
        return isinstance(cvar, structured_c.CVariable) and isinstance(getattr(cvar, "name", None), str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", getattr(cvar, "name", "")) is not None

    def _resolve_stack_pointer_alias(node):
        node = _unwrap_c_casts(node)
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
                return node, 0
            alias = stack_pointer_aliases.get(id(variable))
            if alias is not None:
                return alias
            return None
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = _unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CVariable):
                variable = getattr(operand, "variable", None)
                if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
                    return operand, 0
                alias = stack_pointer_aliases.get(id(variable))
                if alias is not None:
                    base_cvar, base_offset = alias
                    return base_cvar, base_offset
            return None
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = _resolve_stack_pointer_alias(node.lhs)
            rhs = _resolve_stack_pointer_alias(node.rhs)
            lhs_const = _c_constant_value(_unwrap_c_casts(node.lhs))
            rhs_const = _c_constant_value(_unwrap_c_casts(node.rhs))
            if lhs is not None and rhs_const is not None:
                base, offset = lhs
                return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
            if rhs is not None and lhs_const is not None:
                base, offset = rhs
                return base, offset + lhs_const
        return None

    def _collect_stack_pointer_aliases() -> None:
        aliases: dict[int, tuple[structured_c.CVariable, int]] = {}
        for _ in range(3):
            changed_local = False
            for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_temp(walk_node.lhs):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                resolved = _resolve_stack_pointer_alias(rhs)
                if resolved is None:
                    continue
                if aliases.get(id(lhs_var)) != resolved:
                    aliases[id(lhs_var)] = resolved
                    changed_local = True
            if not changed_local:
                break
        stack_pointer_aliases.update(aliases)

    _collect_stack_pointer_aliases()

    def make_stack_deref(cvar, offset: int, bits: int):
        element_type = SimTypeChar() if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        base_ref = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)
        if offset > 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        elif offset < 0:
            addr_expr = structured_c.CBinaryOp(
                "Sub",
                base_ref,
                structured_c.CConstant(-offset, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        else:
            addr_expr = base_ref
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def make_addr_deref(addr_expr, bits: int):
        element_type = SimTypeChar() if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        classified = _classify_segmented_dereference(node, project)
        if classified is None or classified.kind != "stack" or classified.cvar is None:
            if classified is None or classified.seg_name != "ss":
                return node
            addr_expr = _strip_segment_scale_from_addr_expr(getattr(classified, "addr_expr", None), project)
            if addr_expr is None:
                return node
            type_ = getattr(node, "type", None)
            bits = getattr(type_, "size", None)
            if bits not in {8, 16}:
                return node
            return make_addr_deref(addr_expr, bits)
        else:
            if classified.extra_offset <= 0:
                return node
            cvar = classified.cvar
            extra_offset = classified.extra_offset
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits not in {8, 16}:
            return node
        return make_stack_deref(cvar, extra_offset, bits)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True

    return changed


def _promote_direct_stack_cvariable(codegen, cvar, size: int, type_) -> bool:
    changed = False

    variable = getattr(cvar, "variable", None)
    if variable is None:
        return False

    if getattr(variable, "size", 0) < size:
        variable.size = size
        changed = True
    if getattr(cvar, "variable_type", None) != type_:
        cvar.variable_type = type_
        changed = True

    unified = getattr(cvar, "unified_variable", None)
    if unified is not None and getattr(unified, "size", 0) < size:
        try:
            unified.size = size
            changed = True
        except Exception:
            pass

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        tracked = variables_in_use.get(variable)
        if tracked is not None and getattr(tracked, "variable_type", None) != type_:
            tracked.variable_type = type_
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for tracked_var, cvar_and_vartypes in list(unified_locals.items()):
            if tracked_var is not variable:
                continue
            new_entries = set()
            for tracked_cvar, _vartype in cvar_and_vartypes:
                if getattr(tracked_cvar, "variable_type", None) != type_:
                    tracked_cvar.variable_type = type_
                    changed = True
                new_entries.add((tracked_cvar, type_))
            if new_entries != cvar_and_vartypes:
                unified_locals[tracked_var] = new_entries
                changed = True
            break

    return changed


def _coalesce_direct_ss_local_word_statements(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = SimTypeShort(False)

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    matched = _match_ss_local_plus_const(next_stmt.lhs, project)
                    if matched is not None:
                        target_cvar, extra_offset = matched
                        high_expr = _match_shift_right_8_expr(next_stmt.rhs)
                        if (
                            extra_offset == 1
                            and _same_c_storage(target_cvar, stmt.lhs)
                            and high_expr is not None
                            and _same_c_expression(_unwrap_c_casts(high_expr), _unwrap_c_casts(stmt.rhs))
                        ):
                            if _promote_direct_stack_cvariable(codegen, stmt.lhs, 2, target_type):
                                changed = True
                            new_statements.append(stmt)
                            changed = True
                            i += 2
                            continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed


def _coalesce_linear_recurrence_statements(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    linear_defs: dict[object, tuple[object, int]] = {}
    shift_defs: dict[int, tuple[object, int]] = {}
    expr_aliases: dict[int, object] = {}

    def _is_linear_register_temp(cvar) -> bool:
        return isinstance(cvar, structured_c.CVariable) and isinstance(getattr(cvar, "name", None), str) and re.fullmatch(
            r"v\d+", getattr(cvar, "name", "")
        ) is not None

    variable_use_counts: dict[int, int] = {}
    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if isinstance(walk_node, structured_c.CVariable):
            variable = getattr(walk_node, "variable", None)
            if variable is not None:
                key = id(variable)
                variable_use_counts[key] = variable_use_counts.get(key, 0) + 1

    def _extract_linear_delta(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0
        left_base, left_delta = _extract_linear_delta(expr.lhs)
        right_base, right_delta = _extract_linear_delta(expr.rhs)
        if left_base is not None and right_base is not None:
            if _same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if left_base is not None:
            if expr.op == "Add":
                return left_base, left_delta + right_delta
            return left_base, left_delta - right_delta
        if right_base is not None:
            if expr.op == "Add":
                return right_base, left_delta + right_delta
            return expr, 0
        if expr.op == "Add":
            return None, left_delta + right_delta
        return None, left_delta - right_delta

    def _build_linear_expr(base_expr, delta, codegen):
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _build_shift_expr(base_expr, count, codegen):
        if count == 0:
            return base_expr
        return structured_c.CBinaryOp(
            "Shr",
            base_expr,
            structured_c.CConstant(count, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _expr_is_safe_inline_candidate(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return _expr_is_safe_inline_candidate(expr.lhs) and _expr_is_safe_inline_candidate(expr.rhs)
        return False

    def _inline_known_linear_defs(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            linear = None
            variable = getattr(expr, "variable", None)
            if variable is not None:
                linear = linear_defs.get(id(variable))
            if linear is not None:
                base_expr, delta = linear
                return _build_linear_expr(base_expr, delta, codegen)
            return expr
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = _inline_known_linear_defs(expr.lhs)
            rhs = _inline_known_linear_defs(expr.rhs)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=codegen)
        if isinstance(expr, structured_c.CUnaryOp):
            operand = _inline_known_linear_defs(expr.operand)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=codegen)
        return expr

    def _inline_known_expr_aliases(expr, seen: set[int] | None = None):
        expr = _unwrap_c_casts(expr)
        if seen is None:
            seen = set()
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is None:
                return expr
            key = id(variable)
            if key in seen:
                return expr
            seen.add(key)
            alias = expr_aliases.get(key)
            if alias is None:
                return expr
            return _inline_known_expr_aliases(alias, seen)
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = _inline_known_expr_aliases(expr.lhs, set(seen))
            rhs = _inline_known_expr_aliases(expr.rhs, set(seen))
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
        if isinstance(expr, structured_c.CUnaryOp):
            operand = _inline_known_expr_aliases(expr.operand, set(seen))
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
        return expr

    def _extract_shift_delta(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
            return expr, 0
        shift = _c_constant_value(_unwrap_c_casts(expr.rhs))
        if not isinstance(shift, int):
            return expr, 0
        base = _unwrap_c_casts(expr.lhs)
        if isinstance(base, structured_c.CVariable):
            variable = getattr(base, "variable", None)
            if variable is not None:
                alias = shift_defs.get(id(variable))
                if alias is not None:
                    alias_base, alias_shift = alias
                    return alias_base, alias_shift + shift
        return base, shift

    def _inline_known_shift_defs(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                alias = shift_defs.get(id(variable))
                if alias is not None:
                    base_expr, count = alias
                    return _build_shift_expr(base_expr, count, codegen)
            return expr
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = _inline_known_shift_defs(expr.lhs)
            rhs = _inline_known_shift_defs(expr.rhs)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=codegen)
        if isinstance(expr, structured_c.CUnaryOp):
            operand = _inline_known_shift_defs(expr.operand)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=codegen)
        return expr

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None

                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(next_stmt.lhs, structured_c.CVariable)
                ):
                    temp_var = getattr(stmt.lhs, "variable", None)
                    temp_use_count = variable_use_counts.get(id(temp_var), 0) if temp_var is not None else 0

                    if (
                        temp_use_count == 2
                        and _is_linear_register_temp(stmt.lhs)
                        and _is_linear_register_temp(next_stmt.lhs)
                    ):
                        stmt_base, stmt_delta = _extract_linear_delta(stmt.rhs)
                        next_rhs = _unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_rhs, structured_c.CBinaryOp) and next_rhs.op in {"Add", "Sub"}:
                            if _same_c_expression(_unwrap_c_casts(next_rhs.lhs), stmt.lhs):
                                next_delta = _c_constant_value(_unwrap_c_casts(next_rhs.rhs))
                                next_base = stmt_base
                            elif _same_c_expression(_unwrap_c_casts(next_rhs.rhs), stmt.lhs):
                                next_delta = _c_constant_value(_unwrap_c_casts(next_rhs.lhs))
                                next_base = stmt_base
                            else:
                                next_delta = None
                                next_base = None

                            if next_base is not None and isinstance(next_delta, int):
                                combined = stmt_delta + next_delta if next_rhs.op == "Add" else stmt_delta - next_delta
                                replacement = structured_c.CAssignment(
                                    next_stmt.lhs,
                                    _build_linear_expr(next_base, combined, codegen),
                                    codegen=codegen,
                                )
                                new_statements.append(replacement)
                                changed = True
                                i += 2
                                continue

                    if (
                        temp_use_count == 2
                        and _is_linear_register_temp(stmt.lhs)
                        and _is_linear_register_temp(next_stmt.lhs)
                    ):
                        stmt_shift_base, stmt_shift_count = _extract_shift_delta(stmt.rhs)
                        next_shift_rhs = _unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_shift_rhs, structured_c.CBinaryOp) and next_shift_rhs.op == "Shr":
                            if _same_c_expression(_unwrap_c_casts(next_shift_rhs.lhs), stmt.lhs):
                                next_shift_count = _c_constant_value(_unwrap_c_casts(next_shift_rhs.rhs))
                                if isinstance(next_shift_count, int) and stmt_shift_count >= 0:
                                    combined_shift = stmt_shift_count + next_shift_count
                                    replacement = structured_c.CAssignment(
                                        next_stmt.lhs,
                                        _build_shift_expr(stmt_shift_base, combined_shift, codegen),
                                        codegen=codegen,
                                    )
                                    shift_var = getattr(next_stmt.lhs, "variable", None)
                                    if shift_var is not None:
                                        shift_defs[id(shift_var)] = (stmt_shift_base, combined_shift)
                                    new_statements.append(replacement)
                                    changed = True
                                    i += 2
                                    continue

                    if _is_linear_register_temp(stmt.lhs):
                        rhs = _inline_known_expr_aliases(stmt.rhs)
                        stmt_base, stmt_delta = _extract_linear_delta(stmt.rhs)
                        if stmt_base is not None:
                            linear_defs[id(temp_var)] = (stmt_base, stmt_delta)
                            canonical_rhs = _build_linear_expr(stmt_base, stmt_delta, codegen)
                            if not _same_c_expression(stmt.rhs, canonical_rhs):
                                stmt = structured_c.CAssignment(stmt.lhs, canonical_rhs, codegen=codegen)
                                changed = True
                        rhs = _inline_known_linear_defs(rhs)
                        inlined_base, inlined_delta = _extract_linear_delta(rhs)
                        if inlined_base is not None and not _same_c_expression(rhs, stmt.rhs):
                            stmt = structured_c.CAssignment(
                                stmt.lhs,
                                _build_linear_expr(inlined_base, inlined_delta, codegen),
                                codegen=codegen,
                            )
                            rhs = stmt.rhs
                            changed = True
                        current_linear = None
                        if temp_var is not None:
                            current_linear = linear_defs.get(id(temp_var))
                        if current_linear is not None and isinstance(rhs, structured_c.CBinaryOp) and rhs.op in {"Add", "Sub"}:
                            if _same_c_expression(_unwrap_c_casts(rhs.lhs), stmt.lhs) or _same_c_expression(
                                _unwrap_c_casts(rhs.rhs), stmt.lhs
                            ):
                                current_delta = _c_constant_value(_unwrap_c_casts(rhs.lhs))
                                if current_delta is None:
                                    current_delta = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                                if isinstance(current_delta, int):
                                    base_expr, base_delta = current_linear
                                    combined = base_delta + current_delta if rhs.op == "Add" else base_delta - current_delta
                                    stmt = structured_c.CAssignment(
                                        stmt.lhs,
                                        _build_linear_expr(base_expr, combined, codegen),
                                        codegen=codegen,
                                    )
                                    changed = True
                        if rhs is not stmt.rhs:
                            stmt = structured_c.CAssignment(stmt.lhs, rhs, codegen=codegen)
                            changed = True
                        if temp_use_count == 1 and _expr_is_safe_inline_candidate(stmt.rhs):
                            expr_aliases[id(temp_var)] = stmt.rhs

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed


def _coalesce_segmented_word_store_statements(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = SimTypeShort(False)

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None

                if isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment):
                    replacement = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = _match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            rhs_word = _match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                            if (
                                extra_offset == 1
                                and _same_c_storage(target_cvar, stmt.lhs)
                                and rhs_word is not None
                            ):
                                if _promote_direct_stack_cvariable(codegen, stmt.lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(stmt.lhs, rhs_word, codegen=codegen)

                    if replacement is None:
                        low_addr_expr = _match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = _match_byte_store_addr_expr(next_stmt.lhs)
                        rhs_word = _match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and rhs_word is not None
                            and _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                        ):
                            replacement = structured_c.CAssignment(
                                _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
                                rhs_word,
                                codegen=codegen,
                            )

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed


def _global_memory_addr(node) -> int | None:
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) else None


def _global_load_addr(node, project: angr.Project) -> int | None:
    addr = _global_memory_addr(node)
    if addr is not None:
        return addr
    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "global":
        return None
    return classified.linear


def _match_scaled_high_byte(node, project: angr.Project) -> int | None:
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(maybe_scale) != 0x100:
                continue
            addr = _global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(maybe_scale) != 8:
                continue
            addr = _global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    return None


def _extract_dereference_addr_expr(node):
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        return operand.expr
    return operand


def _match_byte_load_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits not in {8, None}:
        return None
    return addr_expr


def _match_byte_store_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits != 8:
        return None
    return addr_expr


def _match_shifted_high_byte_addr_expr(node):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) == 0x100:
                return _match_byte_load_addr_expr(_unwrap_c_casts(maybe_load))

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) == 8:
                return _match_byte_load_addr_expr(_unwrap_c_casts(maybe_load))

    return None


def _match_word_pair_low_addr_expr(node, project: angr.Project):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
        return None

    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_addr_expr = _match_byte_load_addr_expr(_unwrap_c_casts(low_expr))
        high_addr_expr = _match_shifted_high_byte_addr_expr(high_expr)
        if low_addr_expr is None or high_addr_expr is None:
            continue
        if _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
            return low_addr_expr

    return None


def _split_expr_const_offset(node):
    terms = _flatten_c_add_terms(node)
    const_sum = 0
    others = []
    for term in terms:
        constant = _c_constant_value(_unwrap_c_casts(term))
        if constant is not None:
            const_sum += constant
        else:
            others.append(term)
    return others, const_sum


def _same_expression_list(lhs_terms, rhs_terms) -> bool:
    if len(lhs_terms) != len(rhs_terms):
        return False

    used = [False] * len(rhs_terms)
    for lhs in lhs_terms:
        matched = False
        for idx, rhs in enumerate(rhs_terms):
            if used[idx]:
                continue
            if _same_c_expression(lhs, rhs):
                used[idx] = True
                matched = True
                break
        if not matched:
            return False
    return True


def _addr_exprs_are_same(low_addr_expr, high_addr_expr, project: angr.Project) -> bool:
    low_class = _classify_segmented_addr_expr(low_addr_expr, project)
    high_class = _classify_segmented_addr_expr(high_addr_expr, project)

    if low_class is not None and high_class is not None:
        if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
            if low_class.kind == "stack" and low_class.cvar is not None and high_class.cvar is not None:
                if _same_c_expression(low_class.cvar, high_class.cvar):
                    return low_class.extra_offset == high_class.extra_offset
            if low_class.kind in {"global", "extra", "segment_const"}:
                return low_class.linear == high_class.linear

    low_terms, low_const = _split_expr_const_offset(low_addr_expr)
    high_terms, high_const = _split_expr_const_offset(high_addr_expr)
    return low_const == high_const and _same_expression_list(low_terms, high_terms)


def _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project: angr.Project | None = None) -> bool:
    if project is not None:
        low_class = _classify_segmented_addr_expr(low_addr_expr, project)
        high_class = _classify_segmented_addr_expr(high_addr_expr, project)
        if low_class is not None and high_class is not None:
            if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
                if low_class.kind == "stack" and low_class.cvar is not None and high_class.cvar is not None:
                    if _same_c_expression(low_class.cvar, high_class.cvar):
                        return high_class.extra_offset == low_class.extra_offset + 1
                if low_class.kind in {"global", "extra", "segment_const"}:
                    if low_class.linear is not None and high_class.linear is not None:
                        return high_class.linear == low_class.linear + 1

    low_terms, low_const = _split_expr_const_offset(low_addr_expr)
    high_terms, high_const = _split_expr_const_offset(high_addr_expr)
    return _same_expression_list(low_terms, high_terms) and high_const == low_const + 1


def _make_word_dereference_from_addr_expr(codegen, project: angr.Project, addr_expr):
    word_type = SimTypeShort(False)
    ptr_type = SimTypePointer(word_type).with_arch(project.arch)
    return structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
        codegen=codegen,
    )


def _match_word_dereference_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits != 16:
        return None
    return addr_expr


def _match_word_rhs_from_byte_pair(low_rhs, high_rhs, codegen, project: angr.Project):
    low_unwrapped = _unwrap_c_casts(low_rhs)
    high_unwrapped = _unwrap_c_casts(high_rhs)

    if (
        isinstance(low_unwrapped, structured_c.CConstant)
        and isinstance(low_unwrapped.value, int)
        and isinstance(high_unwrapped, structured_c.CConstant)
        and isinstance(high_unwrapped.value, int)
    ):
        return structured_c.CConstant(
            (low_unwrapped.value & 0xFF) | ((high_unwrapped.value & 0xFF) << 8),
            SimTypeShort(False),
            codegen=codegen,
        )

    low_mem_addr = _global_memory_addr(low_unwrapped)
    high_mem_addr = _global_memory_addr(high_unwrapped)
    if (
        isinstance(low_unwrapped, structured_c.CVariable)
        and isinstance(high_unwrapped, structured_c.CVariable)
        and isinstance(getattr(low_unwrapped, "variable", None), SimMemoryVariable)
        and isinstance(getattr(high_unwrapped, "variable", None), SimMemoryVariable)
        and low_mem_addr is not None
        and high_mem_addr == low_mem_addr + 1
    ):
        low_var = getattr(low_unwrapped, "variable", None)
        name = getattr(low_var, "name", None) if isinstance(low_var, SimMemoryVariable) else None
        if not isinstance(name, str) or not name:
            name = f"field_{low_mem_addr:x}"
        return structured_c.CVariable(
            SimMemoryVariable(low_mem_addr, 2, name=_sanitize_cod_identifier(name), region=codegen.cfunc.addr),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )

    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is not None:
        shifted_source = _unwrap_c_casts(shifted_source)
        low_bits = getattr(getattr(low_unwrapped, "type", None), "size", None)
        if (
            _same_c_expression(_unwrap_c_casts(low_rhs), shifted_source)
            and (
                isinstance(low_unwrapped, (structured_c.CVariable, structured_c.CConstant))
                or low_bits == 16
            )
        ):
            return low_rhs

        low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
        word_addr_expr = _match_word_dereference_addr_expr(shifted_source)
        if (
            low_addr_expr is not None
            and word_addr_expr is not None
            and _addr_exprs_are_same(low_addr_expr, word_addr_expr, project)
        ):
            return shifted_source

    low_pair_addr = _match_word_pair_low_addr_expr(low_unwrapped, project)
    if low_pair_addr is not None:
        shifted_source = _match_shift_right_8_expr(high_rhs)
        if shifted_source is not None:
            word_addr_expr = _match_word_dereference_addr_expr(_unwrap_c_casts(shifted_source))
            if word_addr_expr is not None and _addr_exprs_are_same(low_pair_addr, word_addr_expr, project):
                return _make_word_dereference_from_addr_expr(codegen, project, low_pair_addr)

    low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
    high_addr_expr = _match_shifted_high_byte_addr_expr(high_rhs)
    if low_addr_expr is not None and high_addr_expr is not None and _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
        return _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

    return None


def _high_byte_store_addr(node, project: angr.Project) -> int | None:
    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "global":
        return None
    return classified.linear


def _make_word_global(codegen, addr: int, name: str):
    return structured_c.CVariable(
        SimMemoryVariable(addr, 2, name=name, region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _coalesce_cod_word_global_loads(
    project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[int, structured_c.CVariable] = {}

    def make_word_global(addr: int):
        existing = created.get(addr)
        if existing is not None:
            return existing
        raw_name, _width = _synthetic_global_entry(synthetic_globals, addr)
        cvar = _make_word_global(codegen, addr, _sanitize_cod_identifier(raw_name))
        created[addr] = cvar
        return cvar

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = _global_load_addr(low_expr, project)
            if low_addr is None:
                continue

            symbol = _synthetic_global_entry(synthetic_globals, low_addr)
            if symbol is None:
                continue
            _raw_name, width = symbol
            if width < 2:
                continue

            high_addr = _match_scaled_high_byte(high_expr, project)
            if high_addr != low_addr + 1:
                continue

            return make_word_global(low_addr)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _coalesce_segmented_word_load_expressions(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr_expr = _match_byte_load_addr_expr(_unwrap_c_casts(low_expr))
            if low_addr_expr is None:
                continue

            high_addr_expr = _match_shifted_high_byte_addr_expr(high_expr)
            if high_addr_expr is None:
                continue

            if _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
                return _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _coalesce_cod_word_global_statements(
    project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]

                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    base_addr = _global_memory_addr(stmt.lhs)
                    next_addr = _high_byte_store_addr(next_stmt.lhs, project)
                    symbol = _synthetic_global_entry(synthetic_globals, base_addr) if base_addr is not None else None

                    if base_addr is not None and next_addr == base_addr + 1 and symbol is not None:
                        raw_name, width = symbol
                        name = _sanitize_cod_identifier(raw_name)

                        if isinstance(stmt.rhs, structured_c.CConstant) and isinstance(next_stmt.rhs, structured_c.CConstant):
                            value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
                            new_statements.append(
                                structured_c.CAssignment(
                                    _make_word_global(codegen, base_addr, name),
                                    structured_c.CConstant(value, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                            )
                            changed = True
                            i += 2
                            continue

                        if width >= 2:
                            changed = True
                            new_statements.append(stmt)
                            i += 2
                            continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed


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

    positive_aliases = _build_cod_positive_bp_alias_map(
        [
            disp
            for disp in (
                int(match.group(2), 16) if match.group(1) == "+" else -int(match.group(2), 16)
                for match in re.finditer(r"// \[bp([+-])0x([0-9a-f]+)\]", c_text)
            )
            if disp > 0
        ],
        metadata,
    )

    lines: list[str] = []
    for line in c_text.splitlines():
        match = re.search(r"// \[bp([+-])0x([0-9a-f]+)\]", line)
        if match:
            disp = int(match.group(2), 16)
            if match.group(1) == "-":
                disp = -disp
            alias = _cod_stack_alias_for_disp(disp, metadata, positive_aliases=positive_aliases)
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

    print(f"/* loading: {args.binary} */", flush=True)
    function_label = None
    cod_metadata = None
    synthetic_globals = None
    lst_metadata = None
    if args.proc is not None:
        entries = extract_cod_function_entries(args.binary, args.proc, args.proc_kind)
        cod_metadata = extract_cod_proc_metadata(args.binary, args.proc, args.proc_kind)
        selected_entries = extract_small_two_arg_cod_logic_entries(entries)
        if selected_entries is None:
            selected_entries = extract_simple_cod_logic_entries(entries)
        if selected_entries is None:
            logic_start = infer_cod_logic_start(entries)
            proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(entries, start_offset=logic_start)
        else:
            proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(selected_entries)
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
        lst_metadata = _load_lst_metadata(args.binary, project)
    if args.addr is not None:
        print("/* recovering function... */", flush=True)

        try:
            if function_label is not None and args.addr == project.entry:
                cfg, func = _recover_blob_entry_function(project, args.addr, timeout=args.timeout)
            else:
                if project.arch.name == "86_16":
                    regions = [_infer_x86_16_linear_region(project, args.addr, window=args.window)]
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
            print(f"/* Timed out while recovering a function after {args.timeout}s. */")
            print("/* Tip: try a larger --timeout for larger binaries. */")
            return 3
        except Exception as ex:
            print(f"/* Function recovery failed: {ex} */")
            print("\n/* == first block asm == */")
            print(_format_first_block_asm(project, args.addr))
            return 5

        if function_label is not None:
            func.name = function_label
        elif lst_metadata is not None:
            code_name = lst_metadata.code_labels.get(func.addr)
            if code_name is not None:
                func.name = code_name

        print(f"/* binary: {args.binary} */")
        print(f"/* arch: {project.arch.name} */")
        print(f"/* entry: {project.entry:#x} */")
        print(f"/* function: {func.addr:#x} {func.name} */")

        if args.show_asm:
            print("\n/* == asm == */")
            print(_format_first_block_asm(project, func.addr))

        print("/* decompiling... */", flush=True)
        status, payload, *_ = _decompile_function_with_stats(
            project,
            cfg,
            func,
            args.timeout,
            args.api_style,
            args.binary,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
        )
        if status != "ok":
            print(f"\n/* Decompilation {status}: {payload} */")
            print("\n/* == asm fallback == */")
            print(_format_first_block_asm(project, func.addr))
            return 6 if status == "error" else 4

        print("\n/* == c == */")
        print(payload)
        return 0

    print("/* recovering functions... */", flush=True)
    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(args.timeout)
    try:
        cfg = _recover_cfg(project, args.binary, base_addr=args.base_addr, window=args.window)
    except _AnalysisTimeout:
        print(f"/* Timed out while recovering functions after {args.timeout}s. */")
        print("/* Trying bounded entry-function recovery instead... */")
        try:
            cfg, func = _fallback_entry_function(project, timeout=args.timeout, window=args.window)
        except _AnalysisTimeout:
            print("/* Bounded entry-function recovery also timed out. */")
            print("/* Tip: try a larger --timeout or decompile a specific function with --addr. */")
            return 3
        except Exception as ex:
            print(f"/* Bounded entry-function recovery failed: {ex} */")
            print("\n/* == entry asm == */")
            print(_format_first_block_asm(project, project.entry))
            return 5

        print(f"/* binary: {args.binary} */")
        print(f"/* arch: {project.arch.name} */")
        print(f"/* entry: {project.entry:#x} */")
        print(f"/* fallback function: {func.addr:#x} {func.name} */")
        status, payload, *_ = _decompile_function_with_stats(
            project,
            cfg,
            func,
            args.timeout,
            args.api_style,
            args.binary,
            lst_metadata=lst_metadata,
        )
        if status != "ok":
            print(f"\n/* Decompilation {status}: {payload} */")
            print("\n/* == asm fallback == */")
            print(_format_first_block_asm(project, func.addr))
            return 6 if status == "error" else 4

        print("\n/* == c == */")
        print(payload)
        return 0
    except Exception as ex:
        print(f"/* Function catalog recovery failed: {ex} */")
        print("\n/* == entry asm == */")
        print(_format_first_block_asm(project, project.entry))
        return 5
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if function_label is not None and project.entry in cfg.functions:
        cfg.functions[project.entry].name = function_label
    elif lst_metadata is not None:
        for addr, func in cfg.functions.items():
            code_name = lst_metadata.code_labels.get(addr)
            if code_name is not None:
                func.name = code_name

    functions, total_functions = _interesting_functions(cfg, limit=args.max_functions)

    print(f"/* binary: {args.binary} */")
    print(f"/* arch: {project.arch.name} */")
    print(f"/* entry: {project.entry:#x} */")
    print(f"/* functions recovered: {total_functions} */")
    if total_functions > len(functions):
        print(f"/* showing first {len(functions)} functions; use --max-functions to raise the cap */")

    decompiled = 0
    failed = 0
    for function in functions:
        print(f"\n/* == function {function.addr:#x} {function.name} == */")
        if args.show_asm:
            print("/* -- asm -- */")
            print(_format_first_block_asm(project, function.addr))

        status, payload, *_ = _decompile_function_with_stats(
            project,
            cfg,
            function,
            args.timeout,
            args.api_style,
            args.binary,
            lst_metadata=lst_metadata,
            enable_structured_simplify=args.addr is not None,
        )
        if status == "ok":
            decompiled += 1
            print("/* -- c -- */")
            print(payload)
        else:
            failed += 1
            asm_fallback = _format_first_block_asm(project, function.addr)
            # If decompiler produced no code and there are no bytes for the
            # function block, print a concise explanatory comment instead of
            # an empty '...' body and an unhelpful asm fallback.
            if status == "empty":
                if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
                    print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
                else:
                    print(f"-- {status} --")
                    print(payload)
                    print("-- asm fallback --")
                    print(asm_fallback)
            else:
                print(f"-- {status} --")
                print(payload)
                print("-- asm fallback --")
                print(asm_fallback)

    print(f"\nsummary: decompiled {decompiled}/{len(functions)} shown functions")
    if failed:
        print(f"summary: {failed} functions fell back to asm/details")
    return 0 if decompiled else 2


if __name__ == "__main__":
    raise SystemExit(main())
