"""Cleanup-only condition expression canonicalization patterns.

Layer: Rewrite/Postprocess cleanup.
Responsibility: normalize already-recovered condition expression shapes only.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
This module may canonicalize already-recovered comparison expressions.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Condition nodes cross a dynamic third-party angr/decompiler boundary; dynamic
attribute access here must stay limited to already-recovered condition fields.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

__all__ = [
    "_strengthen_condition_8616",
    "_canonicalize_cmp_sub_8616",
]


def _is_const_expr(expr: object) -> bool:
    """Check whether a dynamic third-party angr boundary node is constant."""
    return hasattr(expr, "value") and isinstance(getattr(expr, "value"), int)


def _get_const_val(expr: object) -> int | None:
    """Extract a constant int from a dynamic third-party angr boundary node."""
    if _is_const_expr(expr):
        return int(getattr(expr, "value"))
    return None


def _canonicalize_cmp_sub_8616(cond: object) -> object | None:
    """Canonicalize an already-recovered CMP-SUB condition shape."""

    def _impl() -> object | None:
        """Canonicalize CMP-SUB patterns to direct comparisons.

        Conditions cross a dynamic third-party angr/decompiler boundary, so this
        helper accepts both left/right and lhs/rhs field spellings.

        CmpLT(Sub(x, N), 0)  → CmpLT(x, N)
        CmpGE(Sub(x, N), 0)  → CmpGE(x, N)
        CmpGT(Sub(x, N), 0)  → CmpGT(x, N)
        CmpLE(Sub(x, N), 0)  → CmpLE(x, N)
        CmpLT(Sub(x, y), 0)  → CmpLT(x, y)   [reg-to-reg, no constant needed]
        CmpGE(Sub(x, y), 0)  → CmpGE(x, y)

        Returns the strengthened condition node or None.
        """
        if cond is None:
            return None

        op = getattr(cond, "op", None)
        # Get operands via either attribute naming convention
        left = getattr(cond, "left", None) or getattr(cond, "lhs", None)
        right = getattr(cond, "right", None) or getattr(cond, "rhs", None)
        if op is None or left is None or right is None:
            return None

        # Only fire when comparing against zero
        right_val = _get_const_val(right)
        if right_val != 0:
            return None

        op_str = str(op).upper()
        # Only for comparison operators
        if op_str not in ("LT", "LE", "GT", "GE", "EQ", "NE"):
            return None

        # Check if left is Sub(x, N) or Sub(x, y)
        left_op = getattr(left, "op", None)
        if str(left_op) != "Sub":
            return None

        sub_left = getattr(left, "left", None) or getattr(left, "lhs", None)
        sub_right = getattr(left, "right", None) or getattr(left, "rhs", None)
        if sub_left is None or sub_right is None:
            return None

        # Build strengthened comparison: CmpOP(x, N) or CmpOP(x, y)
        cond_factory = cast(Callable[..., object], type(cond))
        return cond_factory(
            left=sub_left,
            right=sub_right,
            op=op_str,
        )

    return _impl()


def _strengthen_condition_8616(cond: object) -> object | None:
    """Apply all condition strengthening transforms.

    Returns strengthened condition or None if no transform applied.
    """
    # Try CMP-SUB canonicalization first
    result = _canonicalize_cmp_sub_8616(cond)
    if result is not None:
        return result
    return None
