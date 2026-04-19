from __future__ import annotations

from collections.abc import Callable

from ..condition_ir import build_condition_ir_8616, normalize_condition_op_8616
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


def build_condition_from_binop(op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    folded = op.lower()
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
            if "And" in op:
                return _masked_nonzero_condition(left, right, source=op)
    return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=tag or "expr")
