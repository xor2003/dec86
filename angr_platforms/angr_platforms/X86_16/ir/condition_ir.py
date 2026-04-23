from __future__ import annotations

# Layer: IR
# Responsibility: typed condition domain representation.
# Forbidden: late rewrite ownership and text-pattern semantics.

from dataclasses import replace
from typing import Literal

from .core import IRCondition, IRValue

ConditionOp = Literal[
    "and",
    "compare",
    "eq",
    "ne",
    "not",
    "or",
    "slt",
    "sle",
    "sgt",
    "sge",
    "ult",
    "ule",
    "ugt",
    "uge",
    "zero",
    "nonzero",
]

_COMPARE_SYMBOLS_8616: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "slt": "<",
    "sle": "<=",
    "sgt": ">",
    "sge": ">=",
    "ult": "<",
    "ule": "<=",
    "ugt": ">",
    "uge": ">=",
}


def build_condition_ir_8616(op: ConditionOp, *args: IRValue, expr: tuple[str, ...] | None = None) -> IRCondition:
    return IRCondition(op=op, args=tuple(args), expr=expr)


def coerce_condition_value_size_8616(value: IRValue, size: int) -> IRValue:
    if size <= 0 or value.size == size:
        return value
    return replace(value, size=size)


def harmonize_condition_args_8616(*args: IRValue, size: int = 0) -> tuple[IRValue, ...]:
    target_size = int(size or 0)
    if target_size <= 0:
        target_size = max((int(arg.size or 0) for arg in args), default=0)
    if target_size <= 0:
        return tuple(args)
    return tuple(coerce_condition_value_size_8616(arg, target_size) for arg in args)


def normalize_condition_op_8616(op: str) -> ConditionOp:
    if op in {"and", "or", "not"}:
        return op  # type: ignore[return-value]
    if op in {"masked_nonzero", "nonzero"}:
        return "nonzero"
    if op in {"masked_zero", "zero"}:
        return "zero"
    if op in {"eq", "ne", "slt", "sle", "sgt", "sge", "ult", "ule", "ugt", "uge", "compare"}:
        return op  # type: ignore[return-value]
    if op in {"lt", "le", "gt", "ge"}:
        return f"s{op}"  # type: ignore[return-value]
    if op in {"lt_u", "le_u", "gt_u", "ge_u"}:
        return f"u{op[:-2]}"  # type: ignore[return-value]
    return "compare"


def is_condition_truth_test_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"zero", "nonzero", "and", "or", "not"}


def is_condition_compare_family_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"compare", "eq", "ne", "slt", "sle", "sgt", "sge", "ult", "ule", "ugt", "uge"}


def condition_compare_symbol_8616(op: str) -> str | None:
    return _COMPARE_SYMBOLS_8616.get(normalize_condition_op_8616(op))


def is_signed_condition_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"slt", "sle", "sgt", "sge"}


def is_unsigned_condition_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"ult", "ule", "ugt", "uge"}
