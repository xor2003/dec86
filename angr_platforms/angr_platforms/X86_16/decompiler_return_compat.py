from __future__ import annotations

import contextlib
import logging
import os
import struct
import sys
from pathlib import Path

from angr import ailment
from angr.ailment.expression import BasePointerOffset
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable, MakeTypecastsImplicit
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.calling_conventions import SimComboArg, SimRegArg
from angr.sim_type import SimTypeBottom, SimTypeDouble, SimTypeFloat, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

__all__ = [
    "apply_x86_16_decompiler_return_compatibility",
    "describe_x86_16_decompiler_return_compatibility",
    "x86_16_msvc_x87_scalar_stack_args",
]

l = logging.getLogger(__name__)


def _describe_c_expr_8616(expr, *, depth: int = 0) -> str:
    if expr is None:
        return "None"
    if depth >= 3:
        return type(expr).__name__
    parts = [type(expr).__name__]
    for attr in ("op", "variable", "reg", "reg_name", "value"):
        if hasattr(expr, attr):
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            parts.append(f"{attr}={value!r}")
    for attr in ("operand", "lhs", "rhs", "expr"):
        if hasattr(expr, attr):
            try:
                child = getattr(expr, attr)
            except Exception:
                continue
            parts.append(f"{attr}=({_describe_c_expr_8616(child, depth=depth + 1)})")
    return " ".join(parts)


def _is_stack_base_return_register_8616(reg_arg: SimRegArg) -> bool:
    return reg_arg.reg_name.lower() in {"sp", "bp", "ebp", "esp", "rbp", "rsp"}


def _is_void_return_type_8616(return_type) -> bool:
    return type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void"


def _prototype_has_return_type_8616(prototype) -> bool:
    return prototype is not None and getattr(prototype, "returnty", None) is not None


def _resolve_codegen_prototype_8616(codegen):
    if codegen is None:
        return None, None

    codegen_func = getattr(codegen, "_func", None)
    prototype = getattr(codegen_func, "prototype", None)
    if _prototype_has_return_type_8616(prototype):
        return codegen_func, prototype

    cfunc = getattr(codegen, "cfunc", None)
    for attr_name in ("functy", "prototype"):
        prototype = getattr(cfunc, attr_name, None)
        if _prototype_has_return_type_8616(prototype):
            if codegen_func is not None:
                with contextlib.suppress(Exception):
                    codegen_func.prototype = prototype
            return codegen_func, prototype

    project = getattr(codegen, "project", None)
    if project is None:
        project = getattr(codegen_func, "project", None)
    func_addr = getattr(cfunc, "addr", None)
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
        print(
            "[dbg-return] prototype-resolve "
            f"codegen_project={project is not None} "
            f"func_project={getattr(codegen_func, 'project', None) is not None} "
            f"cfunc={cfunc is not None} "
            f"cfunc_addr={func_addr!r} "
            f"functions={functions is not None} "
            f"func_proto={getattr(codegen_func, 'prototype', None)!r} "
            f"cfunc_functy={getattr(cfunc, 'functy', None)!r} "
            f"cfunc_proto={getattr(cfunc, 'prototype', None)!r}",
            file=sys.stderr,
            flush=True,
        )
    if not isinstance(func_addr, int) or functions is None:
        return codegen_func, None

    try:
        kb_func = functions.function(addr=func_addr, create=False)
    except Exception:
        kb_func = None
    prototype = getattr(kb_func, "prototype", None)
    if not _prototype_has_return_type_8616(prototype):
        return codegen_func or kb_func, None

    for target in (codegen_func, cfunc):
        if target is None:
            continue
        with contextlib.suppress(Exception):
            target.prototype = prototype
        with contextlib.suppress(Exception):
            target.functy = prototype
    with contextlib.suppress(Exception):
        kb_func._inertia_return_compat_codegen_prototype_resolved_count = (
            int(getattr(kb_func, "_inertia_return_compat_codegen_prototype_resolved_count", 0) or 0) + 1
        )
    return codegen_func or kb_func, prototype


def describe_x86_16_decompiler_return_compatibility():
    return ("ReturnMaker._handle_Return: SimComboArg support",)


def _make_return_register_expr_8616(self, stmt, reg_arg: SimRegArg):
    reg = self.arch.registers[reg_arg.reg_name]
    reg_name = self.arch.translate_register_name(reg[0], reg_arg.size)
    if reg_name is None:
        reg_name = reg_arg.reg_name
    reg_expr = ailment.Expr.Register(
        self._next_atom(),
        None,
        reg[0],
        reg_arg.size * self.arch.byte_width,
        reg_name=reg_name,
        ins_addr=stmt.tags["ins_addr"],
    )
    return reg_expr


def _register_assignment_source_8616(stmt, *, reg_offset: int, reg_size: int):
    if not isinstance(stmt, ailment.Stmt.Assignment):
        return None
    dst = getattr(stmt, "dst", None)
    if not isinstance(dst, ailment.Expr.Register):
        return None
    if getattr(dst, "reg_offset", None) != reg_offset:
        return None
    if getattr(dst, "bits", None) != reg_size * 8:
        return None
    return getattr(stmt, "src", None)


def _tmp_assignment_source_8616(stmt, *, tmp_idx: int):
    if not isinstance(stmt, ailment.Stmt.Assignment):
        return None
    dst = getattr(stmt, "dst", None)
    if not isinstance(dst, ailment.Expr.Tmp):
        return None
    if getattr(dst, "tmp_idx", None) != tmp_idx:
        return None
    return getattr(stmt, "src", None)


def _resolve_same_block_tmp_source_8616(expr, statements, *, before_index: int, depth: int = 0):
    if depth > 8 or not isinstance(expr, ailment.Expr.Tmp):
        return expr
    tmp_idx = getattr(expr, "tmp_idx", None)
    if not isinstance(tmp_idx, int):
        return expr
    for idx in range(before_index - 1, -1, -1):
        src = _tmp_assignment_source_8616(statements[idx], tmp_idx=tmp_idx)
        if src is None:
            continue
        if isinstance(src, ailment.Expr.Tmp):
            return _resolve_same_block_tmp_source_8616(src, statements, before_index=idx, depth=depth + 1)
        return src
    return expr


def _resolve_same_block_tmps_in_expr_8616(expr, statements, *, before_index: int, depth: int = 0):
    if depth > 8 or expr is None:
        return expr
    if isinstance(expr, ailment.Expr.Tmp):
        resolved = _resolve_same_block_tmp_source_8616(expr, statements, before_index=before_index, depth=depth)
        if resolved is expr:
            return expr
        return _resolve_same_block_tmps_in_expr_8616(resolved, statements, before_index=before_index, depth=depth + 1)

    copy = _copy_ail_expr_8616(expr)
    for attr in ("addr", "operand", "expr"):
        if not hasattr(copy, attr):
            continue
        try:
            child = getattr(copy, attr)
            setattr(
                copy,
                attr,
                _resolve_same_block_tmps_in_expr_8616(child, statements, before_index=before_index, depth=depth + 1),
            )
        except Exception:
            pass
    if hasattr(copy, "operands"):
        try:
            operands = getattr(copy, "operands")
            setattr(
                copy,
                "operands",
                [
                    _resolve_same_block_tmps_in_expr_8616(child, statements, before_index=before_index, depth=depth + 1)
                    for child in operands
                ],
            )
        except Exception:
            pass
    return copy


def _copy_ail_expr_8616(expr):
    copy = getattr(expr, "copy", None)
    if callable(copy):
        return copy()
    return expr


def _ail_const_value_8616(expr) -> int | None:
    if isinstance(expr, ailment.Expr.Const):
        value = getattr(expr, "value", None)
        return int(value) if isinstance(value, int) else None
    return None


def _ail_register_name_8616(self, expr) -> str | None:
    if not isinstance(expr, ailment.Expr.Register):
        return None
    reg_offset = getattr(expr, "reg_offset", None)
    size_bits = getattr(expr, "bits", None)
    if not isinstance(reg_offset, int) or not isinstance(size_bits, int):
        return None
    size_bytes = max(size_bits // self.arch.byte_width, 1)
    return self.arch.translate_register_name(reg_offset, size_bytes)


def _strip_ail_convert_8616(expr):
    while isinstance(expr, ailment.Expr.Convert):
        expr = getattr(expr, "operand", expr)
    return expr


def _bp_offset_expr_8616(self, expr) -> int | None:
    expr = _strip_ail_convert_8616(expr)
    if _ail_register_name_8616(self, expr) == "bp":
        return 0
    if not isinstance(expr, ailment.Expr.BinaryOp):
        return None
    op = getattr(expr, "op", None)
    operands = tuple(getattr(expr, "operands", ()) or ())
    if len(operands) != 2 or op not in {"Add", "Sub"}:
        return None
    lhs, rhs = operands
    lhs_offset = _bp_offset_expr_8616(self, lhs)
    rhs_offset = _bp_offset_expr_8616(self, rhs)
    lhs_const = _ail_const_value_8616(_strip_ail_convert_8616(lhs))
    rhs_const = _ail_const_value_8616(_strip_ail_convert_8616(rhs))
    if lhs_offset is not None and rhs_const is not None:
        return lhs_offset + (rhs_const if op == "Add" else -rhs_const)
    if op == "Add" and rhs_offset is not None and lhs_const is not None:
        return rhs_offset + lhs_const
    return None


def _is_ss_segment_scale_8616(self, expr) -> bool:
    expr = _strip_ail_convert_8616(expr)
    if not isinstance(expr, ailment.Expr.BinaryOp):
        return False
    op = getattr(expr, "op", None)
    operands = tuple(getattr(expr, "operands", ()) or ())
    if len(operands) != 2 or op not in {"Shl", "Mul"}:
        return False
    scale = 4 if op == "Shl" else 16
    for maybe_seg, maybe_scale in (operands, tuple(reversed(operands))):
        if _ail_const_value_8616(_strip_ail_convert_8616(maybe_scale)) != scale:
            continue
        if _ail_register_name_8616(self, _strip_ail_convert_8616(maybe_seg)) == "ss":
            return True
    return False


def _bp_offset_from_linear_stack_addr_8616(self, addr_expr) -> int | None:
    addr_expr = _strip_ail_convert_8616(addr_expr)
    direct = _bp_offset_expr_8616(self, addr_expr)
    if direct is not None:
        return direct
    if not isinstance(addr_expr, ailment.Expr.BinaryOp) or getattr(addr_expr, "op", None) != "Add":
        return None
    operands = tuple(getattr(addr_expr, "operands", ()) or ())
    if len(operands) != 2:
        return None
    lhs, rhs = operands
    if _is_ss_segment_scale_8616(self, lhs):
        return _bp_offset_expr_8616(self, rhs)
    if _is_ss_segment_scale_8616(self, rhs):
        return _bp_offset_expr_8616(self, lhs)
    return None


def _materialize_return_stack_load_8616(self, expr):
    if not isinstance(expr, ailment.Expr.Load):
        return expr
    offset = _bp_offset_from_linear_stack_addr_8616(self, getattr(expr, "addr", None))
    if not isinstance(offset, int):
        return expr
    bits = getattr(expr, "bits", None)
    size = max(bits // self.arch.byte_width, 1) if isinstance(bits, int) and bits > 0 else 2
    region = getattr(getattr(self, "function", None), "addr", None)
    variable = SimStackVariable(offset, size, base="bp", region=region)
    materialized_addr = BasePointerOffset(
        self._next_atom(),
        size * self.arch.byte_width,
        "bp",
        offset,
        variable=variable,
        ins_addr=getattr(expr, "tags", {}).get("ins_addr", None),
    )
    result = _copy_ail_expr_8616(expr)
    try:
        result.addr = materialized_addr
    except Exception:
        return expr
    return result


def _find_terminal_register_source_8616(self, stmt, *, reg_offset: int, reg_size: int, max_insn_distance: int = 32):
    graph = getattr(self, "graph", None)
    if graph is None:
        return None
    return_ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
    if not isinstance(return_ins_addr, int):
        return None

    best: tuple[int, object] | None = None
    tied = False
    for graph_block in tuple(graph.nodes()):
        statements = tuple(getattr(graph_block, "statements", ()) or ())
        for idx, graph_stmt in enumerate(statements):
            ins_addr = getattr(graph_stmt, "tags", {}).get("ins_addr", None)
            if not isinstance(ins_addr, int):
                continue
            if ins_addr > return_ins_addr or return_ins_addr - ins_addr > max_insn_distance:
                continue
            src = _register_assignment_source_8616(graph_stmt, reg_offset=reg_offset, reg_size=reg_size)
            if src is None:
                continue
            src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
            src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
            if best is None or ins_addr > best[0]:
                best = (ins_addr, src)
                tied = False
            elif ins_addr == best[0]:
                tied = True
    if best is None or tied:
        return None
    return _materialize_return_stack_load_8616(self, _copy_ail_expr_8616(best[1]))


def _find_reaching_register_source_8616(self, block, *, reg_offset: int, reg_size: int, max_depth: int = 8):
    graph = getattr(self, "graph", None)
    if graph is None or block is None:
        return None

    candidates = []
    seen_blocks: set[int] = set()

    def scan_predecessors(node, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            predecessors = tuple(graph.predecessors(node))
        except Exception:
            return
        for pred in predecessors:
            pred_id = id(pred)
            if pred_id in seen_blocks:
                continue
            seen_blocks.add(pred_id)
            statements = tuple(getattr(pred, "statements", ()) or ())
            for idx in range(len(statements) - 1, -1, -1):
                pred_stmt = statements[idx]
                src = _register_assignment_source_8616(pred_stmt, reg_offset=reg_offset, reg_size=reg_size)
                if src is not None:
                    src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
                    src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
                    candidates.append(src)
                    break
            else:
                scan_predecessors(pred, depth + 1)

    scan_predecessors(block, 0)
    if len(candidates) != 1:
        return None
    return _materialize_return_stack_load_8616(self, _copy_ail_expr_8616(candidates[0]))


def _infer_x86_16_ax_return_expr_8616(self, stmt, block):
    """
    Infer a 16-bit scalar return only from concrete AX producer evidence.

    This is deliberately narrower than prototype-driven ReturnMaker recovery: if
    no terminal/reaching AX assignment is found, the caller must keep upstream's
    original return handling.
    """

    arch = getattr(self, "arch", None)
    registers = getattr(arch, "registers", {}) if arch is not None else {}
    ax_reg = registers.get("ax") if isinstance(registers, dict) else None
    if not isinstance(ax_reg, tuple) or len(ax_reg) < 2:
        return None

    reg_offset = ax_reg[0]
    reg_size = int(ax_reg[1])
    if reg_size <= 0:
        reg_size = 2

    ret_expr = _find_terminal_register_source_8616(self, stmt, reg_offset=reg_offset, reg_size=reg_size)
    if ret_expr is None:
        ret_expr = _find_reaching_register_source_8616(self, block, reg_offset=reg_offset, reg_size=reg_size)
    if ret_expr is None:
        function = getattr(self, "function", None)
        if function is not None:
            try:
                function._inertia_return_compat_ax_refused_count = (
                    int(getattr(function, "_inertia_return_compat_ax_refused_count", 0) or 0) + 1
                )
            except Exception:
                pass
        return None

    function = getattr(self, "function", None)
    if function is not None:
        try:
            function._inertia_return_compat_ax_materialized_count = (
                int(getattr(function, "_inertia_return_compat_ax_materialized_count", 0) or 0) + 1
            )
        except Exception:
            pass
    return ret_expr


def _iter_function_ail_blocks_8616(function, graph=None):
    if graph is None:
        graph = getattr(function, "graph", None)
    if graph is None:
        return ()
    try:
        return tuple(graph.nodes())
    except Exception:
        return ()


def _return_insn_addrs_8616(function, graph=None) -> tuple[int, ...]:
    addrs: list[int] = []
    fallback_addrs: list[int] = []
    for block in _iter_function_ail_blocks_8616(function, graph=graph):
        for stmt in tuple(getattr(block, "statements", ()) or ()):
            ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
            if isinstance(ins_addr, int):
                fallback_addrs.append(ins_addr)
            if not isinstance(stmt, ailment.Stmt.Return):
                continue
            if isinstance(ins_addr, int):
                addrs.append(ins_addr)
    if addrs:
        return tuple(sorted(set(addrs)))
    if fallback_addrs:
        return (max(fallback_addrs),)
    return ()


def _terminal_register_sources_for_function_8616(
    *,
    arch,
    function,
    graph=None,
    reg_offset: int,
    reg_size: int,
    max_insn_distance: int = 32,
) -> tuple[object, ...]:
    return_addrs = _return_insn_addrs_8616(function, graph=graph)
    if not return_addrs:
        return ()
    sources: list[object] = []
    for return_ins_addr in return_addrs:
        best: tuple[int, object] | None = None
        tied = False
        for block in _iter_function_ail_blocks_8616(function, graph=graph):
            statements = tuple(getattr(block, "statements", ()) or ())
            for idx, graph_stmt in enumerate(statements):
                ins_addr = getattr(graph_stmt, "tags", {}).get("ins_addr", None)
                if not isinstance(ins_addr, int):
                    continue
                if ins_addr > return_ins_addr or return_ins_addr - ins_addr > max_insn_distance:
                    continue
                src = _register_assignment_source_8616(graph_stmt, reg_offset=reg_offset, reg_size=reg_size)
                if src is None:
                    continue
                src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
                src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
                if best is None or ins_addr > best[0]:
                    best = (ins_addr, src)
                    tied = False
                elif ins_addr == best[0]:
                    tied = True
        if best is not None and not tied:
            sources.append(best[1])
    return tuple(sources)


def _stack_annotation_name_for_bp_disp_8616(function, bp_disp: int) -> str | None:
    info = getattr(function, "info", None)
    annotations = info.get("x86_16_annotations") if isinstance(info, dict) else None
    stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
    if not isinstance(stack_vars, dict):
        return None
    for key in (bp_disp, bp_disp - 2):
        spec = stack_vars.get(key)
        if isinstance(spec, str) and spec:
            return spec
        if isinstance(spec, dict):
            name = spec.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def _stack_name_preference_8616(cvar) -> int:
    variable = getattr(cvar, "variable", None)
    name = getattr(variable, "name", None) or getattr(cvar, "name", None)
    if not isinstance(name, str) or not name:
        return 0
    if name.startswith(("vvar_", "tmp_", "ir_", "s_")):
        return 1
    if name.startswith(("local_", "arg_")):
        return 2
    return 3


def _existing_stack_cvar_for_bp_disp_8616(codegen, bp_disp: int):
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return None
    candidate_offsets = (bp_disp, bp_disp - 2) if bp_disp < 0 else (bp_disp,)
    best = None
    best_score = None
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable) or not isinstance(cvar, CVariable):
            continue
        offset = getattr(variable, "offset", None)
        if offset not in candidate_offsets:
            continue
        score = (_stack_name_preference_8616(cvar), int(getattr(variable, "size", 0) or 0), -abs(offset - bp_disp))
        if best_score is None or score > best_score:
            best = cvar
            best_score = score
    return best


def _make_c_stack_return_value_8616(codegen, *, bp_disp: int, size: int):
    return _make_c_stack_value_8616(codegen, bp_disp=bp_disp, size=size, variable_type=SimTypeShort(False))


def _update_cfunc_arg_type_for_bp_disp_8616(codegen, *, bp_disp: int, variable_type) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    arg_list = getattr(cfunc, "arg_list", None)
    functy = getattr(cfunc, "functy", None)
    arg_types = getattr(functy, "args", None)
    if not isinstance(arg_list, list) or not isinstance(arg_types, (list, tuple)):
        return
    if isinstance(arg_types, tuple):
        arg_types = list(arg_types)
        with contextlib.suppress(Exception):
            functy.args = arg_types
    for idx, cvar in enumerate(arg_list):
        variable = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            continue
        if getattr(variable, "offset", None) not in {bp_disp, bp_disp - 2}:
            continue
        with contextlib.suppress(Exception):
            cvar.variable_type = variable_type
        if idx < len(arg_types):
            arg_types[idx] = variable_type
        variable_manager = getattr(cfunc, "variable_manager", None)
        if variable_manager is not None:
            with contextlib.suppress(Exception):
                variable_manager.set_variable_type(variable, variable_type)
        return


def _make_c_stack_value_8616(codegen, *, bp_disp: int, size: int, variable_type):
    existing = _existing_stack_cvar_for_bp_disp_8616(codegen, bp_disp)
    if existing is not None and getattr(existing, "type", None) is not None:
        return existing
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(variable_type, "with_arch"):
        variable_type = variable_type.with_arch(arch)
    _update_cfunc_arg_type_for_bp_disp_8616(codegen, bp_disp=bp_disp, variable_type=variable_type)
    if existing is not None:
        with contextlib.suppress(Exception):
            existing.variable_type = variable_type
        return existing
    function = getattr(codegen, "_func", None)
    region = getattr(function, "addr", None)
    internal_offset = bp_disp - 2 if bp_disp < 0 else bp_disp
    name = _stack_annotation_name_for_bp_disp_8616(function, bp_disp) or (
        f"local_{max(((-internal_offset) + 1) // 2, 1)}" if internal_offset < 0 else f"arg_{max(internal_offset // 2, 1)}"
    )
    variable = SimStackVariable(internal_offset, max(size, 1), base="bp", name=name, region=region)
    cvar = CVariable(variable, variable_type=variable_type, codegen=codegen)
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, variable_type)}
    return cvar


_MSVC_X87_INT_TO_OPCODE_8616 = {
    0x34: 0xD8,
    0x35: 0xD9,
    0x38: 0xDC,
    0x39: 0xDD,
}


def _return_scan_project_and_addr_8616(project, function):
    start = getattr(function, "addr", None)
    if not isinstance(start, int):
        return project, 0
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is not None and isinstance(original_delta, int):
        return original_project, start + original_delta
    return project, start


def _function_bytes_for_return_scan_8616(project, function) -> tuple[object, int, bytes]:
    scan_project, start = _return_scan_project_and_addr_8616(project, function)
    if not isinstance(start, int):
        return project, 0, b""
    size = getattr(function, "size", None)
    if not isinstance(size, int) or size <= 0:
        end = start
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            scan_block_addr = int(block_addr)
            original_delta = getattr(project, "_inertia_original_linear_delta", None)
            if scan_project is not project and isinstance(original_delta, int):
                scan_block_addr += original_delta
            try:
                block = scan_project.factory.block(scan_block_addr, opt_level=0)
            except Exception:
                continue
            block_size = getattr(block, "size", 0)
            if isinstance(block_size, int) and block_size > 0:
                end = max(end, scan_block_addr + block_size)
        size = end - start
    if not isinstance(size, int) or size <= 0 or size > 0x1000:
        return scan_project, start, b""
    try:
        return scan_project, start, bytes(scan_project.loader.memory.load(start, size))
    except Exception:
        return scan_project, start, b""


def _modrm16_operand_8616(data: bytes, index: int) -> tuple[dict[str, int] | None, int]:
    if index >= len(data):
        return None, index
    modrm = data[index]
    index += 1
    mod = modrm >> 6
    reg = (modrm >> 3) & 0x7
    rm = modrm & 0x7
    operand: dict[str, int] = {"reg": reg, "mod": mod, "rm": rm}
    if mod == 3:
        operand["kind"] = 2
        return operand, index
    if mod == 0 and rm == 6:
        if index + 2 > len(data):
            return None, index
        operand["kind"] = 0
        operand["offset"] = int.from_bytes(data[index : index + 2], "little")
        return operand, index + 2
    if mod == 1:
        if index >= len(data):
            return None, index
        disp = struct.unpack("b", data[index : index + 1])[0]
        operand["disp"] = disp
        operand["kind"] = 1 if rm == 6 else 3
        return operand, index + 1
    if mod == 2:
        if index + 2 > len(data):
            return None, index
        disp = int.from_bytes(data[index : index + 2], "little")
        if disp >= 0x8000:
            disp -= 0x10000
        operand["disp"] = disp
        operand["kind"] = 1 if rm == 6 else 3
        return operand, index + 2
    operand["kind"] = 3
    return operand, index


def _x87_scalar_type_for_size_8616(project, size: int):
    scalar_type = SimTypeFloat() if size == 4 else SimTypeDouble()
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(scalar_type, "with_arch"):
        scalar_type = scalar_type.with_arch(arch)
    return scalar_type


def _x87_opcode_reads_memory_operand_8616(opcode: int, reg: int) -> bool:
    if opcode in (0xD8, 0xDC):
        # D8/DC group operations read a float/double memory operand:
        # arithmetic and compare variants all consume the operand as scalar data.
        return 0 <= reg <= 7
    if opcode == 0xD9:
        return reg == 0
    if opcode == 0xDD:
        return reg == 0
    return False


def x86_16_msvc_x87_scalar_stack_args(project, function) -> dict[int, object]:
    """
    Return BP-relative stack arguments that are proven scalar FP operands.

    Microsoft C's no-FPU runtime encodes x87 ESC instructions as INT 34h/35h/
    38h/39h followed by the original ModR/M operand.  A BP-relative memory
    operand read by those decoded x87 operations is scalar data, not a near
    pointer, so later prototype promotion must not reinterpret it as a pointer.
    """

    scan_project, _start, data = _function_bytes_for_return_scan_8616(project, function)
    if not data:
        return {}

    offsets: dict[int, int] = {}
    conflicts: set[int] = set()
    index = 0
    while index < len(data):
        byte = data[index]
        if byte != 0xCD or index + 1 >= len(data):
            index += 1
            continue
        int_no = data[index + 1]
        opcode = _MSVC_X87_INT_TO_OPCODE_8616.get(int_no)
        if opcode is None:
            index += 2
            continue
        operand, next_index = _modrm16_operand_8616(data, index + 2)
        if operand is None:
            return {}
        reg = int(operand.get("reg", -1))
        if _x87_opcode_reads_memory_operand_8616(opcode, reg) and operand.get("kind") == 1:
            disp = int(operand.get("disp", 0))
            if disp > 0:
                size = 8 if opcode in (0xDC, 0xDD) else 4
                previous = offsets.get(disp)
                if previous is not None and previous != size:
                    conflicts.add(disp)
                    offsets.pop(disp, None)
                elif disp not in conflicts:
                    offsets[disp] = size
        index = max(next_index, index + 2)

    if not offsets:
        return {}
    return {
        offset: _x87_scalar_type_for_size_8616(scan_project, size)
        for offset, size in sorted(offsets.items())
        if offset not in conflicts
    }


def _peer_map_dgroup_base_8616(project) -> int | None:
    obj = getattr(getattr(project, "loader", None), "main_object", None)
    binary = getattr(obj, "binary", None)
    if not isinstance(binary, str):
        return None
    map_path = Path(binary).with_suffix(".MAP")
    if not map_path.is_file():
        map_path = Path(binary).with_suffix(".map")
    if not map_path.is_file():
        return None
    try:
        lines = map_path.read_text(errors="ignore").splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1].upper() == "DGROUP" and ":" in parts[0]:
            seg_text, off_text = parts[0].split(":", 1)
            try:
                seg = int(seg_text, 16)
                off = int(off_text, 16)
            except ValueError:
                continue
            linked_base = getattr(obj, "linked_base", None)
            if not isinstance(linked_base, int):
                linked_base = getattr(obj, "mapped_base", 0)
            return int(linked_base) + (seg << 4) + off
    return None


def _read_x87_constant_8616(codegen, *, project=None, offset: int, size: int) -> float | None:
    if project is None:
        project = getattr(codegen, "project", None)
    if project is None:
        return None
    dgroup_base = _peer_map_dgroup_base_8616(project)
    if dgroup_base is None:
        return None
    try:
        data = bytes(project.loader.memory.load(dgroup_base + offset, size))
    except Exception:
        return None
    if len(data) != size:
        return None
    try:
        if size == 4:
            return float(struct.unpack("<f", data)[0])
        if size == 8:
            return float(struct.unpack("<d", data)[0])
    except struct.error:
        return None
    return None


def _c_expr_from_x87_operand_8616(codegen, operand: dict[str, int], *, project=None, size: int):
    kind = operand.get("kind")
    value_type = SimTypeFloat() if size == 4 else SimTypeDouble()
    if kind == 1:
        return _make_c_stack_value_8616(codegen, bp_disp=int(operand.get("disp", 0)), size=size, variable_type=value_type)
    if kind == 0:
        value = _read_x87_constant_8616(codegen, project=project, offset=int(operand.get("offset", 0)), size=size)
        if value is None:
            return None
        return CConstant(value, value_type, codegen=codegen)
    return None


def _decode_msvc_x87_return_expr_8616(codegen):
    project = getattr(codegen, "project", None)
    function = getattr(codegen, "_func", None)
    if project is None or function is None:
        return None
    scan_project, _start, data = _function_bytes_for_return_scan_8616(project, function)
    if not data:
        return None

    stack: list[object] = []
    final_expr = None
    final_store_offset = None
    final_store_index = None
    fpu_ops = 0
    index = 0
    while index < len(data):
        byte = data[index]
        if byte == 0xCD and index + 1 < len(data):
            int_no = data[index + 1]
            opcode = _MSVC_X87_INT_TO_OPCODE_8616.get(int_no)
            if opcode is None:
                index += 2
                continue
            operand, next_index = _modrm16_operand_8616(data, index + 2)
            if operand is None:
                return None
            reg = int(operand.get("reg", -1))
            size = 8 if opcode in (0xDC, 0xDD) else 4
            if (opcode, reg) in ((0xD9, 0), (0xDD, 0)):
                expr = _c_expr_from_x87_operand_8616(codegen, operand, project=scan_project, size=size)
                if expr is None:
                    return None
                stack.append(expr)
                fpu_ops += 1
            elif (opcode, reg) in ((0xD8, 0), (0xDC, 0), (0xD8, 1), (0xDC, 1)):
                if not stack:
                    return None
                expr = _c_expr_from_x87_operand_8616(codegen, operand, project=scan_project, size=size)
                if expr is None:
                    return None
                op = "Add" if reg == 0 else "Mul"
                stack[-1] = CBinaryOp(op, stack[-1], expr, codegen=codegen)
                fpu_ops += 1
            elif (opcode, reg) in ((0xD9, 3), (0xDD, 3)):
                if not stack:
                    return None
                if operand.get("kind") != 0:
                    return None
                final_expr = stack.pop()
                final_store_offset = int(operand.get("offset", -1))
                final_store_index = index
                fpu_ops += 1
            index = max(next_index, index + 2)
            continue
        index += 1

    if final_expr is None or final_store_offset is None or final_store_index is None or fpu_ops < 2:
        return None
    return_pattern = bytes((0xB8, final_store_offset & 0xFF, (final_store_offset >> 8) & 0xFF))
    if data.find(return_pattern, final_store_index + 1) < 0:
        return None
    try:
        function._inertia_msvc_x87_return_materialized_count = (
            int(getattr(function, "_inertia_msvc_x87_return_materialized_count", 0) or 0) + 1
        )
    except Exception:
        pass
    return final_expr


def _infer_x86_16_c_return_value_from_ax_8616(codegen):
    def _debug_refuse(reason: str) -> None:
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            print(f"[dbg-return] CReturn compat-refused={reason}", file=sys.stderr, flush=True)

    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", {}) if arch is not None else {}
    ax_reg = registers.get("ax") if isinstance(registers, dict) else None
    if not isinstance(ax_reg, tuple) or len(ax_reg) < 2:
        _debug_refuse("missing-ax-register")
        return None
    function = getattr(codegen, "_func", None)
    if function is None:
        _debug_refuse("missing-function")
        return None
    reg_size = int(ax_reg[1]) if isinstance(ax_reg[1], int) and ax_reg[1] > 0 else 2
    sources = _terminal_register_sources_for_function_8616(
        arch=arch,
        function=function,
        graph=getattr(codegen, "ail_graph", None),
        reg_offset=int(ax_reg[0]),
        reg_size=reg_size,
    )
    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
        graph = getattr(codegen, "ail_graph", None)
        blocks = _iter_function_ail_blocks_8616(function, graph=graph)
        stmt_count = sum(len(tuple(getattr(block, "statements", ()) or ())) for block in blocks)
        ins_addrs = []
        for block in blocks:
            for stmt in tuple(getattr(block, "statements", ()) or ()):
                ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
                if isinstance(ins_addr, int):
                    ins_addrs.append(ins_addr)
        if len(sources) == 0:
            tail_stmts = []
            for block in blocks:
                for stmt in tuple(getattr(block, "statements", ()) or ()):
                    ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
                    if isinstance(ins_addr, int) and ins_addr >= (max(ins_addrs) - 0x30 if ins_addrs else 0):
                        tail_stmts.append((ins_addr, type(stmt).__name__, str(stmt)))
            for ins_addr, stmt_type, stmt_text in tail_stmts[-10:]:
                print(
                    f"[dbg-return] CReturn tail-stmt ins={ins_addr:#x} type={stmt_type} stmt={stmt_text}",
                    file=sys.stderr,
                    flush=True,
                )
        print(
            f"[dbg-return] CReturn compat-source-count={len(sources)} function=0x{getattr(function, 'addr', 0):x} "
            f"blocks={len(blocks)} statements={stmt_count} max_ins={hex(max(ins_addrs)) if ins_addrs else None}",
            file=sys.stderr,
            flush=True,
        )
    offsets: set[int] = set()
    sizes: set[int] = set()
    ctx = type("_ReturnCompatCtx8616", (), {"arch": arch})()
    for source in sources:
        if not isinstance(source, ailment.Expr.Load):
            continue
        bp_disp = _bp_offset_from_linear_stack_addr_8616(ctx, getattr(source, "addr", None))
        if not isinstance(bp_disp, int):
            continue
        bits = getattr(source, "bits", None)
        size = max(bits // getattr(arch, "byte_width", 8), 1) if isinstance(bits, int) and bits > 0 else reg_size
        offsets.add(bp_disp)
        sizes.add(size)
    if len(offsets) != 1:
        _debug_refuse(f"offset-count:{len(offsets)}")
        try:
            function._inertia_return_compat_c_ast_refused_count = (
                int(getattr(function, "_inertia_return_compat_c_ast_refused_count", 0) or 0) + 1
            )
        except Exception:
            pass
        return None
    bp_disp = next(iter(offsets))
    size = next(iter(sizes)) if len(sizes) == 1 else reg_size
    retval = _make_c_stack_return_value_8616(codegen, bp_disp=bp_disp, size=size)
    try:
        function._inertia_return_compat_c_ast_materialized_count = (
            int(getattr(function, "_inertia_return_compat_c_ast_materialized_count", 0) or 0) + 1
        )
    except Exception:
        pass
    return retval


def _make_return_combo_expr_8616(self, stmt, ret_val: SimComboArg):
    parts = []
    for loc in reversed(ret_val.locations):
        if isinstance(loc, SimRegArg) and _is_stack_base_return_register_8616(loc):
            return None
        if not isinstance(loc, SimRegArg):
            return None
        parts.append(_make_return_register_expr_8616(self, stmt, loc))

    if not parts:
        return None

    expr = parts[0]
    for part in parts[1:]:
        expr = ailment.Expr.BinaryOp(
            self._next_atom(),
            "Concat",
            [expr, part],
            bits=getattr(expr, "bits", 0) + getattr(part, "bits", 0),
            ins_addr=stmt.tags["ins_addr"],
        )
    return expr


def _raw_capstone_insn_8616(insn):
    return getattr(insn, "insn", insn)


def _capstone_reg_name_8616(insn, reg_id: int) -> str:
    raw = _raw_capstone_insn_8616(insn)
    try:
        return str(raw.reg_name(reg_id)).lower()
    except Exception:
        return ""


def _mem_bp_disp_operand_8616(insn, operand_index: int) -> int | None:
    raw = _raw_capstone_insn_8616(insn)
    operands = tuple(getattr(raw, "operands", ()) or ())
    if operand_index >= len(operands):
        return None
    operand = operands[operand_index]
    if int(getattr(operand, "type", -1)) != 3:
        return None
    if int(getattr(operand, "size", 0) or 0) != 2:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None or not getattr(mem, "base", None):
        return None
    if _capstone_reg_name_8616(raw, int(mem.base)) != "bp":
        return None
    disp = int(getattr(mem, "disp", 0) or 0)
    if 0x8000 <= disp <= 0xFFFF:
        disp -= 0x10000
    return disp


def _reg_operand_name_8616(insn, operand_index: int) -> str | None:
    raw = _raw_capstone_insn_8616(insn)
    operands = tuple(getattr(raw, "operands", ()) or ())
    if operand_index >= len(operands):
        return None
    operand = operands[operand_index]
    if int(getattr(operand, "type", -1)) != 1:
        return None
    return _capstone_reg_name_8616(raw, int(getattr(operand, "reg", 0) or 0))


def _insn_mnemonic_8616(insn) -> str:
    return str(getattr(_raw_capstone_insn_8616(insn), "mnemonic", "") or "").lower()


def _match_wide_stack_arith_sequence_8616(insns) -> tuple[str, int, int] | None:
    for index in range(0, max(0, len(insns) - 3)):
        first, second, third, fourth = insns[index : index + 4]
        if _insn_mnemonic_8616(first) != "mov" or _reg_operand_name_8616(first, 0) != "ax":
            continue
        if _insn_mnemonic_8616(second) != "mov" or _reg_operand_name_8616(second, 0) != "dx":
            continue
        first_low = _mem_bp_disp_operand_8616(first, 1)
        first_high = _mem_bp_disp_operand_8616(second, 1)
        if first_low is None or first_high != first_low + 2:
            continue
        low_op = _insn_mnemonic_8616(third)
        high_op = _insn_mnemonic_8616(fourth)
        if _reg_operand_name_8616(third, 0) != "ax" or _reg_operand_name_8616(fourth, 0) != "dx":
            continue
        second_low = _mem_bp_disp_operand_8616(third, 1)
        second_high = _mem_bp_disp_operand_8616(fourth, 1)
        if second_low is None or second_high != second_low + 2:
            continue
        if low_op == "add" and high_op == "adc":
            return "Add", second_low, first_low
        if low_op == "sub" and high_op == "sbb":
            return "Sub", first_low, second_low
    return None


def _terminal_wide_stack_arith_return_8616(self) -> tuple[str, int, int] | None:
    function = getattr(self, "function", None)
    project = getattr(function, "project", None) or getattr(self, "project", None)
    if function is None or project is None:
        return None
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = project.factory.block(int(block_addr), opt_level=0)
        except Exception:
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        matched = _match_wide_stack_arith_sequence_8616(insns)
        if matched is not None:
            return matched
    return None


def _make_bp_stack_load_expr_8616(self, stmt, *, bp_disp: int, size: int):
    function = getattr(self, "function", None)
    variable = SimStackVariable(bp_disp, size, base="bp", region=getattr(function, "addr", None))
    ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
    addr = BasePointerOffset(
        self._next_atom(),
        size * self.arch.byte_width,
        "bp",
        bp_disp,
        variable=variable,
        ins_addr=ins_addr,
    )
    return ailment.Expr.Load(
        self._next_atom(),
        addr,
        size,
        "Iend_LE",
        variable=variable,
        ins_addr=ins_addr,
    )


def _make_wide_stack_arith_return_expr_8616(self, stmt, prototype):
    returnty = getattr(prototype, "returnty", None)
    if not isinstance(returnty, SimTypeLong):
        return None
    matched = _terminal_wide_stack_arith_return_8616(self)
    if matched is None:
        return None
    op, lhs_offset, rhs_offset = matched
    lhs = _make_bp_stack_load_expr_8616(self, stmt, bp_disp=lhs_offset, size=4)
    rhs = _make_bp_stack_load_expr_8616(self, stmt, bp_disp=rhs_offset, size=4)
    signed = bool(getattr(returnty, "signed", True))
    return ailment.Expr.BinaryOp(
        self._next_atom(),
        op,
        [lhs, rhs],
        signed=signed,
        bits=32,
        ins_addr=getattr(stmt, "tags", {}).get("ins_addr", None),
    )


def apply_x86_16_decompiler_return_compatibility() -> None:
    if os.environ.get("INERTIA_DISABLE_RETURN_COMPAT") == "1":
        return

    _orig_handle_return = ReturnMaker._handle_Return

    def _handle_Return_8616(self, stmt_idx: int, stmt: ailment.Stmt.Return, block):  # pylint:disable=unused-argument
        function = getattr(self, "function", None)
        function_addr = getattr(function, "addr", 0)
        prototype = getattr(function, "prototype", None)
        calling_convention = getattr(function, "calling_convention", None)
        retty = getattr(prototype, "returnty", None)
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            if block is not None and stmt_idx > 0:
                window_start = max(0, stmt_idx - 20)
                for i in range(window_start, stmt_idx + 1):
                    if i >= len(block.statements):
                        continue
                    window_stmt = block.statements[i]
                    print(
                        f"[dbg-return] stmt[{i}]={type(window_stmt).__name__} ins=0x{getattr(window_stmt, 'tags', {}).get('ins_addr', 0):x} "
                        f"repr={window_stmt}",
                        file=sys.stderr,
                        flush=True,
                    )
                prev_stmt = block.statements[stmt_idx - 1] if stmt_idx - 1 < len(block.statements) else None
                print(
                    f"[dbg-return] prev_stmt={type(prev_stmt).__name__ if prev_stmt is not None else None} "
                    f"ins_addr={getattr(prev_stmt, 'tags', {}).get('ins_addr', None)} "
                    f"addr=0x{getattr(prev_stmt, 'tags', {}).get('ins_addr', 0):x} "
                    f"idx={stmt_idx - 1 if prev_stmt is not None else None}",
                    file=sys.stderr,
                    flush=True,
                )
                print(f"[dbg-return] prev_stmt_repr={prev_stmt}", file=sys.stderr, flush=True)
            print(
                f"[dbg-return] ReturnMaker.handle_Return_8616 addr=0x{function_addr:x} "
                f"stmt_idx={stmt_idx} block={'none' if block is None else 'set'} "
                f"retty={type(retty).__name__ if retty is not None else 'none'} "
                f"ret_exprs={len(getattr(stmt, 'ret_exprs', ()) or ())}",
                file=sys.stderr,
                flush=True,
            )
            l.debug(
                "ReturnMaker.handle_Return_8616 addr=%#x stmt_idx=%d block=%s retty=%s ret_exprs=%d",
                function_addr,
                stmt_idx,
                "set" if block is not None else "none",
                type(retty).__name__ if retty is not None else "none",
                len(getattr(stmt, "ret_exprs", ()) or ()),
            )
        if not stmt.ret_exprs and block is not None:
            if _is_void_return_type_8616(retty):
                try:
                    function._inertia_return_compat_void_refused_count = (
                        int(getattr(function, "_inertia_return_compat_void_refused_count", 0) or 0) + 1
                    )
                except Exception:
                    pass
                try:
                    return _orig_handle_return(self, stmt_idx, stmt, block)
                except AttributeError as ex:
                    if "returnty" in str(ex):
                        l.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            has_prototype_return = (
                prototype is not None
                and getattr(prototype, "returnty", None) is not None
                and type(getattr(prototype, "returnty", None)) is not SimTypeBottom
                and calling_convention is not None
            )
            if not has_prototype_return:
                ret_expr = _infer_x86_16_ax_return_expr_8616(self, stmt, block)
                if ret_expr is not None:
                    new_stmt = stmt.copy()
                    new_stmt.ret_exprs.append(ret_expr)
                    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                        print(
                            f"[dbg-return] compat-inferred-ax-ret-stmt-count={len(new_stmt.ret_exprs)} "
                            f"value={new_stmt.ret_exprs[0] if new_stmt.ret_exprs else None}",
                            file=sys.stderr,
                            flush=True,
                        )
                    return new_stmt
                try:
                    return _orig_handle_return(self, stmt_idx, stmt, block)
                except AttributeError as ex:
                    if "returnty" in str(ex):
                        l.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            ret_val = calling_convention.return_val(getattr(prototype, "returnty", None))
            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                print(
                    f"[dbg-return] ret_val={type(ret_val).__name__} value={getattr(ret_val, 'reg_name', None)} "
                    f"size={getattr(ret_val, 'size', None)} locations={getattr(ret_val, 'locations', None)}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    f"[dbg-return] ret_val_is_simreg={isinstance(ret_val, SimRegArg)} "
                    f"ret_val_is_combo={isinstance(ret_val, SimComboArg)}",
                    file=sys.stderr,
                    flush=True,
                )
            if isinstance(ret_val, SimRegArg) and _is_stack_base_return_register_8616(ret_val):
                if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                    print(
                        f"[dbg-return] skip-sp-based-return-compat addr=0x{getattr(self.function, 'addr', 0):x} "
                        f"return-reg={ret_val.reg_name}",
                        file=sys.stderr,
                        flush=True,
                    )
                try:
                    return _orig_handle_return(self, stmt_idx, stmt, block)
                except AttributeError as ex:
                    if "returnty" in str(ex):
                        l.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            ret_expr = None
            if isinstance(ret_val, SimRegArg):
                try:
                    reg = self.arch.registers[ret_val.reg_name]
                    ret_expr = _find_terminal_register_source_8616(
                        self,
                        stmt,
                        reg_offset=reg[0],
                        reg_size=ret_val.size,
                    )
                    if ret_expr is None:
                        ret_expr = _find_reaching_register_source_8616(
                            self,
                            block,
                            reg_offset=reg[0],
                            reg_size=ret_val.size,
                        )
                    if ret_expr is None:
                        ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
                except Exception as ex:
                    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                        print(
                            f"[dbg-return] compat-ret-register-error={type(ex).__name__}: {ex}",
                            file=sys.stderr,
                            flush=True,
                        )
                    raise
            elif isinstance(ret_val, SimComboArg):
                ret_expr = _make_wide_stack_arith_return_expr_8616(self, stmt, prototype)
                if ret_expr is None:
                    ret_expr = _make_return_combo_expr_8616(self, stmt, ret_val)

            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1" and ret_expr is not None:
                reg_name = getattr(ret_expr, "reg_name", None)
                print(
                    f"[dbg-return] compat-ret-expr-class={type(ret_expr).__name__} reg={reg_name}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    f"[dbg-return] compat-ret-expr-variable={getattr(ret_expr, 'variable', None)} "
                    f"bits={getattr(ret_expr, 'bits', None)} reg_offset={getattr(ret_expr, 'reg_offset', None)}",
                    file=sys.stderr,
                    flush=True,
                )

            if ret_expr is None:
                try:
                    return _orig_handle_return(self, stmt_idx, stmt, block)
                except AttributeError as ex:
                    # Some tiny/irregular functions can reach ReturnMaker with a
                    # missing prototype return type in upstream angr internals.
                    # Keep decompilation alive by preserving the original
                    # statement when the failure is prototype-shape related.
                    if "returnty" in str(ex):
                        l.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            new_stmt = stmt.copy()
            new_stmt.ret_exprs.append(ret_expr)
            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                print(
                    f"[dbg-return] compat-ret-stmt-count={len(new_stmt.ret_exprs)} "
                    f"value={new_stmt.ret_exprs[0] if new_stmt.ret_exprs else None}",
                    file=sys.stderr,
                    flush=True,
                )
            new_statements = block.statements[::]
            new_statements[stmt_idx] = new_stmt
            return new_stmt

        try:
            return _orig_handle_return(self, stmt_idx, stmt, block)
        except AttributeError as ex:
            if "returnty" in str(ex):
                l.warning("ReturnMaker skipped due to missing returnty: %s", ex)
                return None
            raise

    if getattr(ReturnMaker._handle_Return, "__name__", "") != "_handle_Return_8616":
        ReturnMaker._handle_Return = _handle_Return_8616

    _orig_handle_c_return = MakeTypecastsImplicit.handle_CReturn

    def _handle_CReturn_8616(self, obj):
        codegen = getattr(self, "codegen", None)
        if codegen is None:
            codegen = getattr(obj, "codegen", None)
        codegen_func, prototype = _resolve_codegen_prototype_8616(codegen)
        return_type = getattr(prototype, "returnty", None)
        return_type_size = getattr(return_type, "size", None)
        if (
            getattr(obj, "retval", None) is None
            and codegen is not None
            and return_type is not None
            and not isinstance(return_type, SimTypeBottom)
            and isinstance(return_type_size, int)
            and return_type_size <= 16
        ):
            retval = _infer_x86_16_c_return_value_from_ax_8616(codegen)
            if retval is not None:
                obj.retval = retval
                if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                    print(
                        f"[dbg-return] CReturn compat-inferred-ax-retval={_describe_c_expr_8616(retval)}",
                        file=sys.stderr,
                        flush=True,
                    )
        if (
            codegen is not None
            and not _is_void_return_type_8616(return_type)
            and isinstance(getattr(obj, "retval", None), CConstant)
        ):
            x87_retval = _decode_msvc_x87_return_expr_8616(codegen)
            if x87_retval is not None:
                obj.retval = x87_retval
                if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                    print(
                        f"[dbg-return] CReturn msvc-x87-retval={_describe_c_expr_8616(x87_retval)}",
                        file=sys.stderr,
                        flush=True,
                    )
            else:
                with contextlib.suppress(Exception):
                    codegen_func._inertia_msvc_x87_return_refused_count = (
                        int(getattr(codegen_func, "_inertia_msvc_x87_return_refused_count", 0) or 0) + 1
                    )
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            if codegen is not None:
                graph_attrs = tuple(
                    sorted(
                        name
                        for name in dir(codegen)
                        if "graph" in name.lower() or name in {"_func", "function", "cfunc"}
                    )
                )
                print(f"[dbg-return] CReturn codegen-graph-attrs={graph_attrs}", file=sys.stderr, flush=True)
            print(
                f"[dbg-return] CReturn obj={type(obj).__name__} return_type={return_type_size}",
                file=sys.stderr,
                flush=True,
            )
            print(
                f"[dbg-return] CReturn retval-before={type(getattr(obj, 'retval', None)).__name__} "
                f"expr={_describe_c_expr_8616(getattr(obj, 'retval', None))}",
                file=sys.stderr,
                flush=True,
            )
        try:
            result = _orig_handle_c_return(self, obj)
            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                print(
                    f"[dbg-return] CReturn result={type(result).__name__}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    f"[dbg-return] CReturn retval-after={type(getattr(result, 'retval', None)).__name__} "
                    f"expr={_describe_c_expr_8616(getattr(result, 'retval', None))}",
                    file=sys.stderr,
                    flush=True,
                )
            return result
        except AttributeError as ex:
            if "returnty" in str(ex):
                # Some irregular functions can reach this pass without a resolved
                # prototype. Keep return expression unchanged instead of aborting
                # the entire decompilation.
                l.warning("MakeTypecastsImplicit skipped CReturn collapse due to missing returnty: %s", ex)
                return obj
            raise

    if getattr(MakeTypecastsImplicit.handle_CReturn, "__name__", "") != "_handle_CReturn_8616":
        MakeTypecastsImplicit.handle_CReturn = _handle_CReturn_8616
