"""Typed contracts emitted by exact stack-memory SSA.

Layer: IR.
Responsibility: define immutable memory range, binding, phi, refusal, and
evidence-accounting projections shared by the function SSA solver and consumers.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from .core import IRAddress, IRRefusal
from .ssa import SSABlock

MemoryRangeKey8616: TypeAlias = tuple[str, tuple[str, ...], int, int]


class SSAMemoryOverlapRelation8616(StrEnum):
    """Byte-exact relation between two non-identical stack ranges."""

    LEFT_CONTAINS_RIGHT = "left_contains_right"
    RIGHT_CONTAINS_LEFT = "right_contains_left"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class SSAMemoryOverlap8616:
    """One canonical pair of stack ranges and their exact byte intersection."""

    left: IRAddress
    right: IRAddress
    intersection: IRAddress
    relation: SSAMemoryOverlapRelation8616

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
            "intersection": self.intersection.to_dict(),
            "relation": self.relation.value,
        }


@dataclass(frozen=True, slots=True)
class SSAMemoryBinding8616:
    """One versioned definition of an exact stack-memory range."""

    block_addr: int
    instr_index: int
    address: IRAddress

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "address": self.address.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SSAMemoryIncomingValue8616:
    """One predecessor's reaching version of an exact memory range."""

    source_block_addr: int
    address: IRAddress

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "source_block_addr": self.source_block_addr,
            "address": self.address.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SSAMemoryPhiNode8616:
    """Phi node joining exact versions of one stack-memory range."""

    block_addr: int
    key: MemoryRangeKey8616
    target: IRAddress
    incoming: tuple[SSAMemoryIncomingValue8616, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "key": [self.key[0], list(self.key[1]), self.key[2], self.key[3]],
            "target": self.target.to_dict(),
            "incoming": [item.to_dict() for item in self.incoming],
        }


@dataclass(frozen=True, slots=True)
class SSAMemoryStats8616:
    """Closed evidence accounting for stack accesses and overlap relations."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every discovered memory fact was handled honestly."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class SSAFunctionMemoryResult8616:
    """Rewritten blocks plus exact memory definitions, joins, and refusals."""

    blocks: tuple[SSABlock, ...]
    bindings: tuple[SSAMemoryBinding8616, ...]
    phi_nodes: tuple[SSAMemoryPhiNode8616, ...]
    refusals: tuple[IRRefusal, ...]
    stats: SSAMemoryStats8616
    overlaps: tuple[SSAMemoryOverlap8616, ...] = ()


__all__ = [
    "MemoryRangeKey8616",
    "SSAFunctionMemoryResult8616",
    "SSAMemoryBinding8616",
    "SSAMemoryIncomingValue8616",
    "SSAMemoryOverlap8616",
    "SSAMemoryOverlapRelation8616",
    "SSAMemoryPhiNode8616",
    "SSAMemoryStats8616",
]
