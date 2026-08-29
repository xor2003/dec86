"""Classify typed condition-chain ownership of structured loop exits.

Layer: Structuring.
Responsibility: identify exact composite exits in the current loop scope so one
binary condition fact is not represented again as a loop-header guard.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CWhileLoop,
)

from ..c_ast_utils import (
    _iter_c_node_children_8616,
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)


class CompositeLoopExitOwnershipStatus8616(Enum):
    """Typed ownership verdict for one loop-condition fact."""

    NONE = "none"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class CompositeLoopExitOwnership8616:
    """Exact composite loop-exit matches for one instruction/block identity."""

    key: tuple[int, int]
    status: CompositeLoopExitOwnershipStatus8616
    matching_exit_count: int


class _TaggedExpression8616(Protocol):
    """Dynamic angr expression tag surface at the Structuring boundary."""

    tags: dict[str, object]


def _iter_current_loop_scope_nodes_8616(body: object) -> Iterator[object]:
    """Iterate one loop body without descending into nested loop bodies."""
    loop_types = (CForLoop, CWhileLoop, CDoWhileLoop)
    pending = [body]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        if current is not body and isinstance(current, loop_types):
            continue
        seen_values: set[int] = set()
        for attr in _structured_slot_names_8616(current):
            try:
                # Dynamic third-party angr C-AST boundary slots are runtime-named.
                value = getattr(current, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                pending.append(value)
            elif isinstance(value, (dict, list, tuple, set)):
                pending.extend(_iter_c_node_children_8616(value, seen_values))


def _reaches_loop_header_8616(
    successors: Mapping[int, tuple[int, ...]],
    start: int,
    header: int,
) -> bool:
    """Return whether an exact shared-body target can re-enter the loop."""
    pending = [start]
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        if address == header:
            return True
        if address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def _condition_chain_exit_8616(
    node: object,
    key: tuple[int, int],
    successors: Mapping[int, tuple[int, ...]],
) -> CExpression | None:
    """Return one exact CFG-proven condition-chain exit expression."""
    if isinstance(node, CIfBreak):
        condition = node.condition
    elif isinstance(node, CIfElse) and node.else_node is None:
        pairs = tuple(node.condition_and_nodes)
        if len(pairs) != 1:
            return None
        condition, _body = pairs[0]
    else:
        return None
    boundary = cast(_TaggedExpression8616, condition)
    try:
        tags = boundary.tags
    except AttributeError:
        return None
    target = tags.get("inertia_structuring_shared_body_target_8616")
    if (
        tags.get("inertia_structuring_shared_body_condition_chain_materialized_8616") is not True
        or tags.get("ins_addr") != key[0]
        or tags.get("vex_block_addr") != key[1]
        or not isinstance(target, int)
        or target not in successors
        or _reaches_loop_header_8616(successors, target, key[1])
    ):
        return None
    return condition


def classify_composite_loop_exit_ownership_8616(
    body: object,
    key: tuple[int, int],
    successors: Mapping[int, tuple[int, ...]],
) -> CompositeLoopExitOwnership8616:
    """Classify exact CFG-materialized loop exits that consume ``key``."""
    matching_exit_count = sum(
        _condition_chain_exit_8616(node, key, successors) is not None
        for node in _iter_current_loop_scope_nodes_8616(body)
    )
    status = (
        CompositeLoopExitOwnershipStatus8616.NONE
        if matching_exit_count == 0
        else CompositeLoopExitOwnershipStatus8616.UNIQUE
        if matching_exit_count == 1
        else CompositeLoopExitOwnershipStatus8616.AMBIGUOUS
    )
    return CompositeLoopExitOwnership8616(
        key=key,
        status=status,
        matching_exit_count=matching_exit_count,
    )
