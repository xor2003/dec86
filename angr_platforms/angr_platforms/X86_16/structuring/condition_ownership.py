"""Prove structured-condition ownership from typed CFG addresses.

Layer: Structuring.
Responsibility: bind a structured condition container to its exact branch or
to a CFG-proven linear preheader that reaches that branch without crossing a
different typed condition.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This module does not recover condition meaning or inspect rendered C. It only
answers whether existing address and CFG evidence establishes ownership.
"""

from __future__ import annotations

from ..ir.condition_ir import ConditionIR


def structured_node_owns_condition_fact_8616(
    node_addr: int | None,
    condition: ConditionIR,
    successors: dict[int, tuple[int, ...]],
    condition_blocks: frozenset[int],
) -> bool:
    """Accept exact ownership or an unambiguous linear CFG preheader path."""
    if node_addr is None:
        return True
    if node_addr == condition.src_insn or node_addr == condition.block_addr:
        return True
    if not isinstance(condition.block_addr, int) or node_addr not in successors:
        return False

    current = node_addr
    visited: set[int] = set()
    while current not in visited and len(visited) < 24:
        visited.add(current)
        next_addrs = successors.get(current, ())
        if len(next_addrs) != 1:
            return False
        current = next_addrs[0]
        if current == condition.block_addr:
            return True
        if current in condition_blocks:
            return False
    return False
