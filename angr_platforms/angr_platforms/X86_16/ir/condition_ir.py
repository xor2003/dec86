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


_INVERTED_COMPARISON_OPS_8616: dict[str, str] = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
}


def inverted_comparison_op_8616(op: str) -> str | None:
    """Return the inverted comparison op name, e.g. ``CmpEQ`` → ``CmpNE``.

    This lives in the IR layer because condition-op inversion is a semantic
    identity that belongs to typed condition representation, not to
    late-rewrite or validation-string normalization.
    """
    return _INVERTED_COMPARISON_OPS_8616.get(op)


def normalize_condition_fingerprint_string_8616(value: str, *, control_flow_prefixes: tuple[str, ...] | None = None) -> str:
    """Canonicalize a condition fingerprint string by inverting ``Not(CmpEQ(...))`` → ``CmpNE(...)``.

    This operates on fingerprint-string representations of conditions.
    The normalization is driven by the IR-layer ``inverted_comparison_op_8616``
    mapping, but the string parsing is fingerprint-format specific.
    """
    if not isinstance(value, str) or not value:
        return value

    if control_flow_prefixes is None:
        control_flow_prefixes = (
            "if:",
            "ifbreak:",
            "while:",
            "dowhile:",
            "for:",
            "switch:",
        )

    for prefix in control_flow_prefixes:
        if value.startswith(prefix):
            return prefix + normalize_condition_fingerprint_string_8616(value[len(prefix):], control_flow_prefixes=control_flow_prefixes)

    call = _split_fingerprint_call_8616(value)
    if call is None:
        return value
    op, inner = call
    if op == "Not":
        inner_call = _split_fingerprint_call_8616(inner)
        if inner_call is None:
            return value
        inner_op, inner_args = inner_call
        inverted = inverted_comparison_op_8616(inner_op)
        if inverted is not None:
            return f"{inverted}({inner_args})"
    return value


def _split_fingerprint_call_8616(value: str) -> tuple[str, str] | None:
    """Split ``CmpEQ(reg:ax,#0x0)`` into (``CmpEQ``, ``reg:ax,#0x0``)."""
    if not isinstance(value, str) or not value.endswith(")"):
        return None
    open_idx = value.find("(")
    if open_idx <= 0:
        return None
    return value[:open_idx], value[open_idx + 1 : -1]


def _split_fingerprint_args_8616(args_str: str) -> list[str]:
    """Split fingerprint arguments by top-level commas, respecting nested parens."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in args_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts


def normalize_condition_fingerprint_algebraic_8616(value: str) -> str:
    """Apply algebraic normalization to a condition fingerprint string.

    Rules (validation-only, deterministic, side-effect-free):

        CmpEQ(Sub(x,const:c),const:0) → CmpEQ(x,const:c)
        CmpNE(Sub(x,const:c),const:0) → CmpNE(x,const:c)
        CmpEQ(Sub(x,y),const:0) → CmpEQ(x,y)
        CmpNE(Sub(x,y),const:0) → CmpNE(x,y)

    Also handles doubled Sub nesting:

        CmpEQ(Sub(Sub(x,const:a),const:b),const:0) → CmpEQ(x,const:a+b)

    This is a pure string-level normalization that preserves the fingerprint
    format.  It does not mutate IR or feed results back into recovery.
    """
    if not isinstance(value, str) or not value:
        return value

    # Handle control-flow prefixes
    for prefix in ("if:", "ifbreak:", "while:", "dowhile:", "for:", "switch:"):
        if value.startswith(prefix):
            return prefix + normalize_condition_fingerprint_algebraic_8616(value[len(prefix):])

    call = _split_fingerprint_call_8616(value)
    if call is None:
        return value

    op, args_str = call

    # Rule: CmpEQ(Sub(x,const:c),const:0) → CmpEQ(x,const:c)
    # Rule: CmpNE(Sub(x,const:c),const:0) → CmpNE(x,const:c)
    if op in ("CmpEQ", "CmpNE"):
        args = _split_fingerprint_args_8616(args_str)
        if len(args) == 2 and args[1] == "const:0":
            lhs_call = _split_fingerprint_call_8616(args[0])
            if lhs_call is not None:
                lhs_op, lhs_args = lhs_call
                if lhs_op == "Sub":
                    sub_args = _split_fingerprint_args_8616(lhs_args)
                    if len(sub_args) == 2:
                        # Sub(x, const:c) == 0  →  x == const:c
                        if sub_args[1].startswith("const:"):
                            return f"{op}({sub_args[0]},{sub_args[1]})"
                        # Sub(x, y) == 0  →  x == y
                        return f"{op}({sub_args[0]},{sub_args[1]})"
                    # Handle nested Sub: Sub(Sub(x, a), b) == 0  →  x == a+b
                    if len(sub_args) == 2:
                        inner_call = _split_fingerprint_call_8616(sub_args[0])
                        if inner_call is not None and inner_call[0] == "Sub":
                            inner_args = _split_fingerprint_args_8616(inner_call[1])
                            if len(inner_args) == 2 and inner_args[1].startswith("const:") and sub_args[1].startswith("const:"):
                                try:
                                    a = int(inner_args[1].split(":")[-1], 0) if inner_args[1].startswith("const:") else 0
                                    b = int(sub_args[1].split(":")[-1], 0) if sub_args[1].startswith("const:") else 0
                                except (ValueError, IndexError):
                                    return value
                                c_sum = a + b
                                if c_sum >= 0:
                                    c_str = f"const:{c_sum:#x}"
                                else:
                                    c_str = f"const:{c_sum}"
                                return f"{op}({inner_args[0]},{c_str})"

    # Recurse into args for nested normalization
    args = _split_fingerprint_args_8616(args_str)
    normalized_args = [_normalize_arg_fingerprint_8616(a) for a in args]
    if normalized_args != args:
        return f"{op}({','.join(normalized_args)})"

    return value


def _normalize_arg_fingerprint_8616(arg: str) -> str:
    """Recursively normalize a fingerprint arg, handling nested calls."""
    call = _split_fingerprint_call_8616(arg)
    if call is None:
        return arg
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    normalized_args = [_normalize_arg_fingerprint_8616(a) for a in args]
    return f"{op}({','.join(normalized_args)})"
