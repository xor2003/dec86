"""Normalize condition exits only through proven empty SSA blocks.

Layer: Structuring.
Responsibility: consume authoritative SSA effects and CFG edges to identify
equivalent condition-chain exits, without moving or discarding effects.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..ir.ssa_function import SSAFunctionArtifact


def transparent_condition_exit_8616(
    artifact: SSAFunctionArtifact | None,
    target: int,
    successors: Mapping[int, tuple[int, ...]],
    *,
    stop_at: int,
) -> int:
    """Follow empty, refusal-free SSA blocks; retain the input on uncertain edges.

    The opposite outcome is a boundary, never an equivalent exit. Instructions,
    bindings and phi nodes stop traversal before their effects. Missing blocks,
    conflicting graphs and cycles invalidate normalization altogether.
    """
    if artifact is None:
        return target
    refused_blocks = {refusal.block_addr for refusal in artifact.memory_refusals}
    if None in refused_blocks:
        return target
    blocks = {block.addr: block for block in artifact.blocks}
    phi_blocks = {phi.block_addr for phi in artifact.phi_nodes}
    phi_blocks.update(phi.block_addr for phi in artifact.memory_phi_nodes)
    current = target
    visited: set[int] = set()
    while current != stop_at:
        if current in visited:
            return target
        visited.add(current)
        block = blocks.get(current)
        if block is None or block.refusals or current in refused_blocks:
            return target
        if block.instrs or block.bindings or current in phi_blocks:
            return current
        edges = successors.get(current, ())
        ssa_edges = tuple(
            sorted(addr for addr, preds in artifact.predecessor_map.items() if current in preds)
        )
        if len(edges) != 1 or tuple(sorted(edges)) != ssa_edges:
            return target
        current = edges[0]
    return target
