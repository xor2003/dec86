from __future__ import annotations

from typing import Literal

from .ir.core import IRCondition, IRValue

ConditionOp = Literal[
    "compare",
    "eq",
    "ne",
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


def normalize_condition_op_8616(op: str) -> ConditionOp:
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
    return normalize_condition_op_8616(op) in {"zero", "nonzero"}


def is_condition_compare_family_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"compare", "eq", "ne", "slt", "sle", "sgt", "sge", "ult", "ule", "ugt", "uge"}


def condition_compare_symbol_8616(op: str) -> str | None:
    return _COMPARE_SYMBOLS_8616.get(normalize_condition_op_8616(op))


def is_signed_condition_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"slt", "sle", "sgt", "sge"}


def is_unsigned_condition_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"ult", "ule", "ugt", "uge"}
