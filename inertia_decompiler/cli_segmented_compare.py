"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeAlias

from angr_platforms.X86_16.lowering.segmented_lowering import _SegmentedAccess

ClassifySegmentedAddrExpr: TypeAlias = Callable[[object, object], _SegmentedAccess | None]


def _split_expr_const_offset(
    node: object,
    *,
    flatten_c_add_terms: Callable[[object], Sequence[object]],
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], int | None],
) -> tuple[list[object], int]:
    terms = flatten_c_add_terms(node)
    const_sum = 0
    others = []
    for term in terms:
        constant = c_constant_value(unwrap_c_casts(term))
        if constant is not None:
            const_sum += constant
        else:
            others.append(term)
    return others, const_sum


def _same_expression_list(
    lhs_terms: Sequence[object],
    rhs_terms: Sequence[object],
    *,
    same_c_expression: Callable[[object, object], bool],
) -> bool:
    if len(lhs_terms) != len(rhs_terms):
        return False

    used = [False] * len(rhs_terms)
    for lhs in lhs_terms:
        matched = False
        for idx, rhs in enumerate(rhs_terms):
            if used[idx]:
                continue
            if same_c_expression(lhs, rhs):
                used[idx] = True
                matched = True
                break
        if not matched:
            return False
    return True


def _addr_exprs_are_same(
    low_addr_expr: object,
    high_addr_expr: object,
    project: object,
    *,
    classify_segmented_addr_expr: ClassifySegmentedAddrExpr,
    same_c_expression: Callable[[object, object], bool],
    split_expr_const_offset: Callable[[object], tuple[Sequence[object], int]],
    same_expression_list: Callable[[Sequence[object], Sequence[object]], bool],
) -> bool:
    def _impl() -> bool:
        low_class = classify_segmented_addr_expr(low_addr_expr, project)
        high_class = classify_segmented_addr_expr(high_addr_expr, project)

        if low_class is not None and high_class is not None:
            if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
                if low_class.kind == "stack" and low_class.cvar is not None and high_class.cvar is not None:
                    if same_c_expression(low_class.cvar, high_class.cvar):
                        return bool(low_class.extra_offset == high_class.extra_offset)
                if low_class.kind in {"extra", "segment_const"}:
                    return bool(low_class.linear == high_class.linear)

        low_terms, low_const = split_expr_const_offset(low_addr_expr)
        high_terms, high_const = split_expr_const_offset(high_addr_expr)
        return low_const == high_const and same_expression_list(low_terms, high_terms)

    return _impl()


def _addr_exprs_are_byte_pair(
    low_addr_expr: object,
    high_addr_expr: object,
    project: object | None = None,
    *,
    classify_segmented_addr_expr: ClassifySegmentedAddrExpr,
    stack_slot_identity_can_join_var: Callable[[object, object], bool],
    split_expr_const_offset: Callable[[object], tuple[Sequence[object], int]],
    same_expression_list: Callable[[Sequence[object], Sequence[object]], bool],
) -> bool:
    def _impl() -> bool:
        def _strip_zero_segment_scale_terms(terms: Sequence[object]) -> Sequence[object]:
            if project is None:
                return terms
            kept = []
            for term in terms:
                classified = classify_segmented_addr_expr(term, project)
                if classified is not None and classified.kind in {"segment_const", "extra"} and classified.linear == 0:
                    continue
                kept.append(term)
            return kept

        if project is not None:
            low_class = classify_segmented_addr_expr(low_addr_expr, project)
            high_class = classify_segmented_addr_expr(high_addr_expr, project)
            if low_class is not None and high_class is not None:
                if low_class.kind != high_class.kind or low_class.seg_name != high_class.seg_name:
                    return False
                if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
                    if (
                        low_class.kind == "stack"
                        and low_class.stack_var is not None
                        and high_class.stack_var is not None
                    ):
                        if stack_slot_identity_can_join_var(low_class.stack_var, high_class.stack_var):
                            return bool(high_class.extra_offset == low_class.extra_offset + 1)
                    if low_class.kind in {"extra", "segment_const"}:
                        if low_class.linear is not None and high_class.linear is not None:
                            return bool(high_class.linear == low_class.linear + 1)

        low_terms, low_const = split_expr_const_offset(low_addr_expr)
        high_terms, high_const = split_expr_const_offset(high_addr_expr)
        low_terms = _strip_zero_segment_scale_terms(low_terms)
        high_terms = _strip_zero_segment_scale_terms(high_terms)
        return same_expression_list(low_terms, high_terms) and high_const == low_const + 1

    return _impl()
