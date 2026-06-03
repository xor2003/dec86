from __future__ import annotations

import logging
import os
import sys

from angr import ailment
from angr.ailment.expression import BasePointerOffset
from angr.analyses.decompiler.structured_codegen.c import MakeTypecastsImplicit
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.calling_conventions import SimComboArg, SimRegArg
from angr.sim_type import SimTypeBottom
from angr.sim_variable import SimStackVariable

__all__ = [
    "apply_x86_16_decompiler_return_compatibility",
    "describe_x86_16_decompiler_return_compatibility",
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


def _find_terminal_register_source_8616(self, stmt, *, reg_offset: int, reg_size: int):
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
            if ins_addr > return_ins_addr or return_ins_addr - ins_addr > 8:
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
        if (
            not stmt.ret_exprs
            and block is not None
            and prototype is not None
            and getattr(prototype, "returnty", None) is not None
            and type(getattr(prototype, "returnty", None)) is not SimTypeBottom
            and calling_convention is not None
        ):
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
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            codegen = getattr(self, "codegen", None)
            if codegen is None:
                codegen = getattr(obj, "codegen", None)
            codegen_func = getattr(codegen, "_func", None)
            prototype = getattr(codegen_func, "prototype", None)
            return_type_size = getattr(getattr(prototype, "returnty", None), "size", None)
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
