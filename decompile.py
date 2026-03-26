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
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr.sim_type import SimTypeChar, SimTypeShort


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
    changed = False
    if _attach_dos_pseudo_callees(project, function, dec.codegen, api_style):
        changed = True
    if _attach_ss_stack_variables(project, dec.codegen):
        changed = True
    if _normalize_scalar_byte_register_types(dec.codegen):
        changed = True
    if _prune_unused_unnamed_memory_declarations(dec.codegen):
        changed = True
    if _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals):
        changed = True
    if _coalesce_cod_word_global_statements(project, dec.codegen, synthetic_globals):
        changed = True
    if _attach_cod_global_names(project, dec.codegen, synthetic_globals):
        changed = True
    if _attach_cod_global_declaration_names(dec.codegen, synthetic_globals):
        changed = True
    if _attach_cod_global_declaration_types(dec.codegen, synthetic_globals):
        changed = True
    if _simplify_structured_c_expressions(dec.codegen):
        changed = True
    if _attach_cod_variable_names(dec.codegen, cod_metadata):
        changed = True
    if _attach_cod_callee_names(dec.codegen, cod_metadata):
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


def _segment_reg_name(node, project: angr.Project) -> str | None:
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return None
    return project.arch.register_names.get(variable.reg)


def _match_real_mode_linear_expr(node, project: angr.Project) -> tuple[str | None, int | None]:
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
        return None, None

    pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
    for maybe_mul, maybe_const in pairs:
        linear = _c_constant_value(maybe_const)
        if linear is None:
            continue
        if not isinstance(maybe_mul, structured_c.CBinaryOp) or maybe_mul.op != "Mul":
            continue

        mul_pairs = ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs))
        for maybe_seg, maybe_scale in mul_pairs:
            scale = _c_constant_value(maybe_scale)
            if scale != 16:
                continue
            seg_name = _segment_reg_name(maybe_seg, project)
            if seg_name is not None:
                return seg_name, linear

    return None, None


def _match_segmented_dereference(node, project: angr.Project) -> tuple[str | None, int | None]:
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None, None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    return _match_real_mode_linear_expr(operand, project)


def _match_ss_stack_reference(node, project: angr.Project):
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    operand = node.operand
    if not isinstance(operand, structured_c.CTypeCast):
        return None
    expr = operand.expr
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None

    for maybe_mul, other in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
        if not isinstance(maybe_mul, structured_c.CBinaryOp) or maybe_mul.op != "Mul":
            continue
        seg_name = None
        for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
            if _c_constant_value(maybe_scale) != 16:
                continue
            seg_name = _segment_reg_name(maybe_seg, project)
            if seg_name is not None:
                break
        if seg_name != "ss":
            continue
        if not isinstance(other, structured_c.CTypeCast):
            continue
        inner = other.expr
        if not isinstance(inner, structured_c.CUnaryOp) or inner.op != "Reference":
            continue
        if not isinstance(inner.operand, structured_c.CVariable):
            continue
        cvar = inner.operand
        stack_var = getattr(cvar, "variable", None)
        if not isinstance(stack_var, SimStackVariable):
            continue
        return stack_var, cvar

    return None


def _replace_c_children(node, transform) -> bool:
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
            if _replace_c_children(value, transform):
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
                if _replace_c_children(new_item, transform):
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
                if _structured_codegen_node(new_cond) and _replace_c_children(new_cond, transform):
                    changed = True
                if _structured_codegen_node(new_body) and _replace_c_children(new_body, transform):
                    changed = True
                new_pairs.append((new_cond, new_body))
            if pair_changed:
                setattr(node, "condition_and_nodes", new_pairs)
                changed = True

    return changed


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


def _simplify_structured_c_expressions(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def transform(node):
        if isinstance(node, structured_c.CBinaryOp):
            if node.op in {"Add", "Or", "Xor"}:
                if _is_c_constant_int(node.lhs, 0):
                    return node.rhs
                if _is_c_constant_int(node.rhs, 0):
                    return node.lhs
            if node.op == "Mul":
                if _is_c_constant_int(node.lhs, 0) or _is_c_constant_int(node.rhs, 0):
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
                if _is_c_constant_int(node.lhs, 1):
                    return node.rhs
                if _is_c_constant_int(node.rhs, 1):
                    return node.lhs
        simplified = _simplify_boolean_expr(node, codegen)
        if simplified is not node:
            return simplified
        if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
            if _same_c_expression(node.lhs, node.rhs):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=codegen)
        return node

    root = codegen.cfunc.statements
    changed = False
    for _ in range(3):
        iter_changed = False
        new_root = transform(root)
        if new_root is not root:
            codegen.cfunc.statements = new_root
            root = new_root
            iter_changed = True
        if _replace_c_children(root, transform):
            iter_changed = True
        changed |= iter_changed
        if not iter_changed:
            break
    return changed


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


def _attach_ss_stack_variables(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    promoted: set[tuple[int, int]] = set()

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

        cvar = structured_c.CVariable(
            SimStackVariable(
                stack_var.offset,
                size,
                base=getattr(stack_var, "base", "bp"),
                name=getattr(ref_cvar, "name", None) or getattr(stack_var, "name", None),
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
    seg_name, linear = _match_segmented_dereference(node, project)
    if seg_name != "ds":
        return None
    return linear


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


def _high_byte_store_addr(node, project: angr.Project) -> int | None:
    seg_name, linear = _match_segmented_dereference(node, project)
    if seg_name != "ds":
        return None
    return linear


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
        status, payload, *_ = _decompile_function_with_stats(project, cfg, func, args.timeout, args.api_style, args.binary)
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

        status, payload, *_ = _decompile_function_with_stats(project, cfg, function, args.timeout, args.api_style, args.binary)
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
