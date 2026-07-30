"""Prove and materialize adjacent segmented scalar loads as wider values.

Layer: Widening.
Responsibility: join exact adjacent segmented-load identities after Alias and
materialize lowering-owned byte pairs before Rewrite consumes the wider value.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CTypeCast,
)

from ..c_ast_utils import _replace_c_children_8616, _same_c_expression_8616
from .segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_identity_8616,
    segmented_load_tags_8616,
)

__all__ = [
    "SegmentedLoadWideningReport8616",
    "apply_segmented_load_widening_8616",
    "join_adjacent_segmented_load_identities_8616",
]


class _CodegenBoundary8616(Protocol):
    """Owned view of widening metadata attached to the dynamic angr codegen."""

    cfunc: object
    _inertia_segmented_load_widening_report_8616: SegmentedLoadWideningReport8616


@dataclass(frozen=True, slots=True)
class SegmentedLoadWideningReport8616:
    """Closed evidence loop for adjacent segmented-load widening."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _dynamic_cfunc_attr_8616(cfunc: object, name: str) -> object | None:
    """Read version-dependent attributes at the dynamic angr C-function boundary."""
    return builtins.getattr(cfunc, name, None)


def _dynamic_cfunc_setattr_8616(cfunc: object, name: str, value: object) -> None:
    """Write version-dependent attributes at the dynamic angr C-function boundary."""
    builtins.setattr(cfunc, name, value)


def join_adjacent_segmented_load_identities_8616(
    low: SegmentedLoadIdentity8616 | None,
    high: SegmentedLoadIdentity8616 | None,
) -> SegmentedLoadIdentity8616 | None:
    """Return the exact two-byte identity for two proven adjacent byte loads."""
    if low is None or high is None:
        return None
    if low.width != 1 or high.width != 1:
        return None
    if low.space is not high.space or low.region != high.region:
        return None
    if low.offset == 0xFFFF or high.offset != low.offset + 1:
        return None
    return SegmentedLoadIdentity8616(
        space=low.space,
        offset=low.offset,
        width=2,
        region=low.region,
    )


def _strip_casts_8616(node: object) -> object:
    """Return an expression without syntax-only casts."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


def _pure_constant_value_8616(node: object) -> int | None:
    """Evaluate integer-only offset and shift expressions."""
    node = _strip_casts_8616(node)
    if isinstance(node, CConstant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if not isinstance(node, CBinaryOp):
        return None
    lhs = _pure_constant_value_8616(node.lhs)
    rhs = _pure_constant_value_8616(node.rhs)
    if lhs is None or rhs is None:
        return None
    if node.op == "Add":
        return lhs + rhs
    if node.op == "Sub":
        return lhs - rhs
    if node.op == "Mul":
        return lhs * rhs
    if node.op == "Shl" and 0 <= rhs <= 63:
        return lhs << rhs
    return None


def _flatten_offset_terms_8616(
    node: object,
    sign: int = 1,
) -> tuple[int, tuple[tuple[int, object], ...]]:
    """Split an offset into a constant and signed symbolic terms."""
    node = _strip_casts_8616(node)
    constant = _pure_constant_value_8616(node)
    if constant is not None:
        return sign * constant, ()
    if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs_constant, lhs_terms = _flatten_offset_terms_8616(node.lhs, sign)
        rhs_sign = sign if node.op == "Add" else -sign
        rhs_constant, rhs_terms = _flatten_offset_terms_8616(node.rhs, rhs_sign)
        return lhs_constant + rhs_constant, lhs_terms + rhs_terms
    return 0, ((sign, node),)


def _same_signed_terms_8616(
    lhs: tuple[tuple[int, object], ...],
    rhs: tuple[tuple[int, object], ...],
) -> bool:
    """Return whether two symbolic offset term multisets are equal."""
    unmatched = list(rhs)
    for lhs_sign, lhs_node in lhs:
        match_index = next(
            (
                index
                for index, (rhs_sign, rhs_node) in enumerate(unmatched)
                if lhs_sign == rhs_sign and _same_c_expression_8616(lhs_node, rhs_node)
            ),
            None,
        )
        if match_index is None:
            return False
        del unmatched[match_index]
    return not unmatched


def _adjacent_offsets_8616(low: object, high: object) -> bool:
    """Prove that two structured offsets differ by exactly one byte."""
    low_constant, low_terms = _flatten_offset_terms_8616(low)
    high_constant, high_terms = _flatten_offset_terms_8616(high)
    return high_constant == low_constant + 1 and _same_signed_terms_8616(low_terms, high_terms)


def _segmented_byte_load_8616(node: object) -> tuple[CFunctionCall, object, object] | None:
    """Return a lowering-owned segmented byte load and its arguments."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CFunctionCall) or not isinstance(node.tags, dict):
        return None
    if node.tags.get("inertia_x86_16_runtime_segment_helper") != "SEG_U8":
        return None
    if not isinstance(node.args, (list, tuple)) or len(node.args) != 2:
        return None
    return node, node.args[0], node.args[1]


def _shifted_high_byte_8616(node: object) -> tuple[CFunctionCall, object, object] | None:
    """Return a segmented byte load widened into the high byte position."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    expected = 8 if node.op == "Shl" else 0x100 if node.op == "Mul" else None
    if expected is None:
        return None
    for possible_load, possible_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _pure_constant_value_8616(possible_scale) == expected:
            return _segmented_byte_load_8616(possible_load)
    return None


def apply_segmented_load_widening_8616(codegen: object) -> bool:
    """Widen proven adjacent segmented byte loads in one structured C tree."""
    typed_codegen = cast(_CodegenBoundary8616, codegen)
    cfunc = typed_codegen.cfunc
    raw = 0
    normalized = 0
    classified = 0
    materialized = 0

    def transform(node: object) -> object:
        """Materialize one adjacent byte pair when all widening facts agree."""
        nonlocal classified, materialized, normalized, raw
        if not isinstance(node, CBinaryOp) or node.op not in {"Or", "Add"}:
            return node
        for possible_low, possible_high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low = _segmented_byte_load_8616(possible_low)
            high = _shifted_high_byte_8616(possible_high)
            if low is None or high is None:
                continue
            raw += 1
            low_call, low_segment, low_offset = low
            high_call, high_segment, high_offset = high
            if not _same_c_expression_8616(low_segment, high_segment):
                continue
            normalized += 1
            if not _adjacent_offsets_8616(low_offset, high_offset):
                continue
            classified += 1
            identity = join_adjacent_segmented_load_identities_8616(
                segmented_load_identity_8616(low_call),
                segmented_load_identity_8616(high_call),
            )
            tags: dict[str, object] = {"inertia_x86_16_runtime_segment_helper": "SEG_U16"}
            if identity is not None:
                tags = segmented_load_tags_8616(identity, existing=tags)
            materialized += 1
            return CFunctionCall(
                "SEG_U16",
                None,
                [low_segment, low_offset],
                codegen=codegen,
                tags=tags,
            )
        return node

    roots: list[tuple[list[str], object]] = []
    seen_roots: dict[int, list[str]] = {}
    for attribute in ("body", "statements", "stmt"):
        root = _dynamic_cfunc_attr_8616(cfunc, attribute)
        if root is None:
            continue
        if id(root) in seen_roots:
            seen_roots[id(root)].append(attribute)
            continue
        attributes = [attribute]
        seen_roots[id(root)] = attributes
        roots.append((attributes, root))

    changed = False
    for attributes, root in roots:
        replacement = transform(root)
        if replacement is not root:
            if isinstance(root, CStatements) and not isinstance(replacement, CStatements):
                replacement = CStatements([replacement], codegen=codegen)
            for attribute in attributes:
                _dynamic_cfunc_setattr_8616(cfunc, attribute, replacement)
            root = replacement
            changed = True
        for _ in range(3):
            if not _replace_c_children_8616(root, transform):
                break
            changed = True

    typed_codegen._inertia_segmented_load_widening_report_8616 = SegmentedLoadWideningReport8616(
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=raw - materialized,
    )
    return changed
