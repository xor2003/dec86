"""Build exact function boundaries from bounded binary reachability.

Layer: Frontend.
Responsibility: turn a proven executable range and entry into one immutable
function boundary whose blocks and instructions come from the closed Frontend
reachability census. This module does not infer signatures, types, aliases, or
structured control flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .frontend_instruction_reachability import collect_instruction_reachability_8616

__all__ = [
    "ExactFunctionRangeBoundary8616",
    "exact_function_range_boundary_8616",
]


@dataclass(frozen=True, slots=True)
class ExactFunctionRangeBoundary8616:
    """One closed binary-framed function boundary for IR import."""

    project: object = field(compare=False, repr=False)
    addr: int
    size: int
    block_addrs_set: frozenset[int]
    reachable_instruction_addrs: frozenset[int]
    successor_edges: tuple[tuple[int, int], ...]
    blocks: tuple[object, ...] = field(default=(), compare=False, repr=False)
    info: dict[str, object] = field(default_factory=dict, compare=False, repr=False)

    @property
    def predecessors_by_block(self) -> dict[int, frozenset[int]]:
        """Project the closed Frontend edge census as predecessor identities."""
        return {
            block_addr: frozenset(
                source for source, target in self.successor_edges if target == block_addr
            )
            for block_addr in self.block_addrs_set
        }


def exact_function_range_boundary_8616(
    project: object,
    start: int,
    end: int,
) -> ExactFunctionRangeBoundary8616 | None:
    """Materialize a range only when every reachable block is classified."""
    if not isinstance(start, int) or not isinstance(end, int) or end <= start:
        return None
    reachability = collect_instruction_reachability_8616(
        project,
        entry=start,
        region_start=start,
        region_end=end,
    )
    if not reachability.complete or not reachability.reachable_block_addrs:
        return None
    return ExactFunctionRangeBoundary8616(
        project=project,
        addr=start,
        size=end - start,
        block_addrs_set=frozenset(reachability.reachable_block_addrs),
        reachable_instruction_addrs=frozenset(reachability.reachable_instruction_addrs),
        successor_edges=reachability.successor_edges,
        blocks=reachability.blocks,
    )
