from __future__ import annotations

from collections.abc import Callable
import re

from .condition_ir import build_condition_ir_8616, harmonize_condition_args_8616, normalize_condition_op_8616
from .core import IRCondition, IRValue

__all__ = [
    "build_condition_from_binop",
    "expr_to_condition",
]


def _zero_fold(cond_op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    if cond_op not in {"eq", "ne"}:
        return None
    if right.const == 0:
        return build_condition_ir_8616("zero" if cond_op == "eq" else "nonzero", left, expr=("zero_fold",))
    if left.const == 0:
        return build_condition_ir_8616("zero" if cond_op == "eq" else "nonzero", right, expr=("zero_fold",))
    return None


def _compare_size_bytes(op: str) -> int:
    match = re.search(r"(\d+)(?:[SU])?$", op)
    if match is None:
        return 0
    bits = int(match.group(1))
    return 0 if bits <= 0 else max(1, bits // 8)


def build_condition_from_binop(op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    folded = op.lower()
    left, right = harmonize_condition_args_8616(left, right, size=_compare_size_bytes(op))
    variants = {
        "cmpeq": "eq",
        "cmpne": "ne",
        "cmplt": "lt",
        "cmple": "le",
        "cmpgt": "gt",
        "cmpge": "ge",
        "cascmp": "eq",
    }
    for needle, cond_op in variants.items():
        if needle not in folded:
            continue
        zero_fold = _zero_fold(cond_op, left, right)
        if zero_fold is not None:
            return zero_fold
        if folded.endswith("s"):
            return build_condition_ir_8616(normalize_condition_op_8616(f"s{cond_op}"), left, right, expr=(op,))
        if folded.endswith("u"):
            return build_condition_ir_8616(normalize_condition_op_8616(f"u{cond_op}"), left, right, expr=(op,))
        return build_condition_ir_8616(normalize_condition_op_8616(cond_op), left, right, expr=(op,))
    return None


def _nonzero_condition(value: IRValue, *, source: str) -> IRCondition:
    return build_condition_ir_8616("nonzero", value, expr=(source,))


def _masked_nonzero_condition(left: IRValue, right: IRValue, *, source: str) -> IRCondition:
    return IRCondition(op="masked_nonzero", args=(left, right), expr=(source,))


def _const_value(expr) -> int | None:
    con = getattr(expr, "con", None)
    if con is None:
        return None
    value = getattr(con, "value", None)
    return None if value is None else int(value)


def _try_expr_to_condition(expr, tmps, conditions, *, expr_to_value: Callable) -> IRCondition | None:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        return conditions.get(tmp_id)
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return None
        lowered = op.lower()
        if "and" in lowered:
            return _logical_condition("and", args[0], args[1], tmps, conditions, expr_to_value=expr_to_value, source=op)
        if "or" in lowered:
            return _logical_condition("or", args[0], args[1], tmps, conditions, expr_to_value=expr_to_value, source=op)
        left = expr_to_value(args[0], tmps, conditions)
        right = expr_to_value(args[1], tmps, conditions)
        return build_condition_from_binop(op, left, right)
    if tag == "Iex_ITE":
        cond_expr = getattr(expr, "cond", None)
        iftrue = getattr(expr, "iftrue", None)
        iffalse = getattr(expr, "iffalse", None)
        cond = _try_expr_to_condition(cond_expr, tmps, conditions, expr_to_value=expr_to_value)
        if cond is None:
            return None
        iftrue_const = _const_value(iftrue)
        iffalse_const = _const_value(iffalse)
        if (iftrue_const, iffalse_const) == (1, 0):
            return cond
        if (iftrue_const, iffalse_const) == (0, 1):
            return build_condition_ir_8616("not", cond, expr=(tag,))
    return None


def _logical_condition(op: str, lhs, rhs, tmps, conditions, *, expr_to_value: Callable, source: str) -> IRCondition | None:
    lhs_cond = _try_expr_to_condition(lhs, tmps, conditions, expr_to_value=expr_to_value)
    rhs_cond = _try_expr_to_condition(rhs, tmps, conditions, expr_to_value=expr_to_value)
    if lhs_cond is None or rhs_cond is None:
        return None
    return build_condition_ir_8616(op, lhs_cond, rhs_cond, expr=(source,))


def expr_to_condition(expr, tmps, conditions, *, expr_to_value: Callable) -> IRCondition:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        if tmp_id in conditions:
            return conditions[tmp_id]
        return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=f"rdtmp:{tmp_id}")
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) == 2:
            left = expr_to_value(args[0], tmps, conditions)
            right = expr_to_value(args[1], tmps, conditions)
            cond = build_condition_from_binop(op, left, right)
            if cond is not None:
                return cond
            logical = _try_expr_to_condition(expr, tmps, conditions, expr_to_value=expr_to_value)
            if logical is not None:
                return logical
            if "And" in op:
                return _masked_nonzero_condition(left, right, source=op)
    if tag == "Iex_ITE":
        cond = _try_expr_to_condition(expr, tmps, conditions, expr_to_value=expr_to_value)
        if cond is not None:
            return cond
    return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=tag or "expr")
