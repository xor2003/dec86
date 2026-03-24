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
    extract_small_two_arg_cod_logic_entries,
    extract_simple_cod_logic_entries,
    infer_cod_logic_start,
    join_cod_entries_with_synthetic_globals,
)
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from angr.sim_type import SimTypeShort


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
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
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
    changed = False
    if _attach_dos_pseudo_callees(project, function, dec.codegen, api_style):
        changed = True
    if _attach_cod_global_names(project, dec.codegen, synthetic_globals):
        changed = True
    if _coalesce_cod_word_global_statements(project, dec.codegen, synthetic_globals):
        changed = True
    if _attach_cod_variable_names(dec.codegen, cod_metadata):
        changed = True
    if _attach_cod_callee_names(dec.codegen, cod_metadata):
        changed = True
    if changed:
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


def _attach_cod_callee_names(codegen, cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None or not cod_metadata.call_names or getattr(codegen, "cfunc", None) is None:
        return False

    call_nodes = [
        node
        for node in _iter_c_nodes(codegen.cfunc.statements)
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


def _replace_c_children(node, transform) -> bool:
    changed = False

    for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "iffalse", "iftrue", "callee_target", "else_node"):
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


def _attach_cod_global_names(project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}

    def transform(node):
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


def _global_memory_addr(node) -> int | None:
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) else None


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

    print(f"loading: {args.binary}", flush=True)
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
