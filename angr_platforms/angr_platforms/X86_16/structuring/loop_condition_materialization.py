"""Materialize CFG-oriented typed loop continuation conditions.

Layer: Structuring.
Responsibility: orient proven ``ConditionIR`` facts as structured loop continuation expressions.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This pass consumes exact instruction/block identity and CFG reachability.  It
does not decode instructions, recover operands, or infer semantics from
rendered C.  Ambiguous condition ownership or continuation polarity is refused
and leaves the existing loop condition unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CUnaryOp,
    CWhileLoop,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..ir.condition_ir import ConditionIR


class LoopContinuationEdge8616(Enum):
    """CFG edge whose target returns to the loop condition block."""

    TAKEN = "taken"
    FALLTHROUGH = "fallthrough"


class _TaggedExpressionBoundary8616(Protocol):
    """Dynamic angr C-expression tag surface used at the Structuring boundary."""

    tags: dict[str, object]


class _LoopBoundary8616(Protocol):
    """Dynamic angr structured-loop condition slot."""

    condition: CExpression | None
    body: object


@dataclass(frozen=True, slots=True)
class LoopConditionMaterializationStats8616:
    """Evidence accounting for typed loop continuation materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0
    taken_continuation_count: int = 0
    fallthrough_continuation_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one loop condition was replaced."""
        return self.changed_count > 0


def _condition_key_8616(condition: ConditionIR) -> tuple[int, int] | None:
    """Return the exact JCC/block identity carried by one typed condition."""
    if not isinstance(condition.src_insn, int) or not isinstance(condition.block_addr, int):
        return None
    return condition.src_insn, condition.block_addr


def _tag_pairs_8616(expression: CExpression) -> frozenset[tuple[int, int]]:
    """Return all complete instruction/block identities in one expression."""
    pairs: set[tuple[int, int]] = set()
    for node in _iter_c_nodes_deep_8616(expression):
        boundary = cast(_TaggedExpressionBoundary8616, node)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        ins_addr = tags.get("ins_addr")
        block_addr = tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            pairs.add((ins_addr, block_addr))
    return frozenset(pairs)


def _reaches_8616(successors: Mapping[int, tuple[int, ...]], start: int, target: int) -> bool:
    """Return whether an in-function CFG path reaches ``target``."""
    pending = [start]
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        if address == target:
            return True
        if address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def _structured_body_block_addrs_8616(body: object) -> frozenset[int]:
    """Return exact CFG block addresses carried by one structured loop body."""
    addresses: set[int] = set()
    for node in _iter_c_nodes_deep_8616(body):
        boundary = cast(_TaggedExpressionBoundary8616, node)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        block_addr = tags.get("vex_block_addr")
        if isinstance(block_addr, int):
            addresses.add(block_addr)
    return frozenset(addresses)


def _enters_body_through_linear_trampoline_8616(
    successors: Mapping[int, tuple[int, ...]],
    start: int,
    body_block_addrs: frozenset[int],
    condition_block_addr: int,
) -> bool:
    """Return whether a deterministic trampoline enters the structured body.

    angr may omit a terminal jump-only block from the structured loop body.
    Following only single-successor blocks recovers that exact CFG ownership
    without allowing an enclosing loop's later re-entry to claim the edge.
    """
    current = start
    visited: set[int] = set()
    while current not in visited and current != condition_block_addr:
        if current in body_block_addrs:
            return True
        visited.add(current)
        next_blocks = successors.get(current, ())
        if len(next_blocks) != 1:
            return False
        current = next_blocks[0]
    return False


def _continuation_edge_8616(
    condition: ConditionIR,
    successors: Mapping[int, tuple[int, ...]],
    *,
    body_block_addrs: frozenset[int] = frozenset(),
) -> LoopContinuationEdge8616 | None:
    """Classify the loop-continuation edge from structured ownership or CFG reachability."""
    if not all(
        isinstance(address, int)
        for address in (condition.block_addr, condition.taken_target, condition.fallthrough_target)
    ):
        return None
    taken_target = cast(int, condition.taken_target)
    fallthrough_target = cast(int, condition.fallthrough_target)
    block_addr = cast(int, condition.block_addr)
    taken_owned = _enters_body_through_linear_trampoline_8616(
        successors,
        taken_target,
        body_block_addrs,
        block_addr,
    )
    fallthrough_owned = _enters_body_through_linear_trampoline_8616(
        successors,
        fallthrough_target,
        body_block_addrs,
        block_addr,
    )
    if taken_owned != fallthrough_owned:
        return LoopContinuationEdge8616.TAKEN if taken_owned else LoopContinuationEdge8616.FALLTHROUGH
    taken_reaches = _reaches_8616(successors, taken_target, block_addr)
    fallthrough_reaches = _reaches_8616(successors, fallthrough_target, block_addr)
    if taken_reaches == fallthrough_reaches:
        return None
    return LoopContinuationEdge8616.TAKEN if taken_reaches else LoopContinuationEdge8616.FALLTHROUGH


def _expression_tags_8616(expression: CExpression) -> dict[str, object]:
    """Copy tags from one dynamic angr C expression."""
    boundary = cast(_TaggedExpressionBoundary8616, expression)
    try:
        return dict(boundary.tags)
    except AttributeError:
        return {}


def _invert_condition_8616(condition: CExpression, codegen: object) -> CExpression:
    """Invert one already-materialized condition without recovering semantics."""
    inverted_ops = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
    }
    if isinstance(condition, CBinaryOp) and condition.op in inverted_ops:
        return CBinaryOp(
            inverted_ops[condition.op],
            condition.lhs,
            condition.rhs,
            codegen=codegen,
            tags=_expression_tags_8616(condition),
        )
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        return condition.operand
    return CUnaryOp(
        "Not",
        condition,
        codegen=codegen,
        tags=_expression_tags_8616(condition),
    )


def _is_owned_materialization_8616(
    expression: CExpression,
    key: tuple[int, int],
    edge: LoopContinuationEdge8616,
) -> bool:
    """Return whether this pass already materialized the exact condition fact."""
    tags = _expression_tags_8616(expression)
    return (
        tags.get("inertia_typed_loop_condition_key_8616") == key
        and tags.get("inertia_typed_loop_continuation_edge_8616") == edge.value
    )


def _mark_materialization_8616(
    expression: CExpression,
    key: tuple[int, int],
    edge: LoopContinuationEdge8616,
) -> None:
    """Record exact typed-condition ownership on a materialized expression."""
    boundary = cast(_TaggedExpressionBoundary8616, expression)
    tags = _expression_tags_8616(expression)
    tags.update(
        {
            "ins_addr": key[0],
            "vex_block_addr": key[1],
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": key,
            "inertia_typed_loop_continuation_edge_8616": edge.value,
        }
    )
    boundary.tags = tags


def _mark_condition_binding_8616(expression: CExpression, key: tuple[int, int]) -> None:
    """Expose unique typed loop ownership to the Validation layer."""
    boundary = cast(_TaggedExpressionBoundary8616, expression)
    tags = _expression_tags_8616(expression)
    tags.update(
        {
            "ins_addr": key[0],
            "vex_block_addr": key[1],
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": key,
        }
    )
    boundary.tags = tags


def materialize_typed_loop_continuation_conditions_8616(
    root: object,
    codegen: object,
    typed_conditions: tuple[ConditionIR, ...],
    successors: Mapping[int, tuple[int, ...]],
    lower_condition: Callable[[ConditionIR], CExpression | None],
) -> LoopConditionMaterializationStats8616:
    """Replace loop guards only when exact typed and CFG evidence agree."""
    conditions_by_key: dict[tuple[int, int], list[ConditionIR]] = {}
    for condition in typed_conditions:
        key = _condition_key_8616(condition)
        if key is not None:
            conditions_by_key.setdefault(key, []).append(condition)

    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    changed_count = 0
    taken_count = 0
    fallthrough_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            continue
        loop = cast(_LoopBoundary8616, node)
        current = loop.condition
        if not isinstance(current, CExpression):
            continue
        matching_keys = _tag_pairs_8616(current).intersection(conditions_by_key)
        if not matching_keys:
            continue
        raw_count += 1
        if len(matching_keys) != 1:
            continue
        key = next(iter(matching_keys))
        candidates = conditions_by_key[key]
        if len(candidates) != 1:
            continue
        normalized_count += 1
        _mark_condition_binding_8616(current, key)
        condition = candidates[0]
        edge = _continuation_edge_8616(
            condition,
            successors,
            body_block_addrs=_structured_body_block_addrs_8616(loop.body),
        )
        if edge is None:
            continue
        classified_count += 1
        if edge is LoopContinuationEdge8616.TAKEN:
            taken_count += 1
        else:
            fallthrough_count += 1
        replacement = lower_condition(condition)
        if replacement is None:
            continue
        if edge is LoopContinuationEdge8616.FALLTHROUGH:
            replacement = _invert_condition_8616(replacement, codegen)
        if _is_owned_materialization_8616(current, key, edge) and _same_c_expression_8616(current, replacement):
            materialized_count += 1
            continue
        _mark_materialization_8616(replacement, key, edge)
        loop.condition = replacement
        materialized_count += 1
        changed_count += 1

    failure_count = raw_count - normalized_count + normalized_count - classified_count
    failure_count += classified_count - materialized_count
    return LoopConditionMaterializationStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        changed_count=changed_count,
        taken_continuation_count=taken_count,
        fallthrough_continuation_count=fallthrough_count,
    )
