"""Canonicalize overlapping recovered blocks without losing IR instructions.

Layer: IR.
Responsibility: assign each machine-instruction address to the latest recovered
block start that contains an exact decode, removing only proven duplicate IR
facts and retaining typed refusals for ambiguous overlaps.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRBlock

__all__ = [
    "IRBlockOwnershipArtifact8616",
    "IRBlockOwnershipFailure8616",
    "IRBlockOwnershipRefusal8616",
    "IRBlockOwnershipRemoval8616",
    "IRBlockOwnershipStats8616",
    "canonicalize_ir_block_ownership_8616",
]


class IRBlockOwnershipFailure8616(StrEnum):
    """Stable reason an overlapping instruction cannot change ownership."""

    CANONICAL_OWNER_MISSING_INSTRUCTION = "canonical_owner_missing_instruction"


@dataclass(frozen=True, slots=True)
class IRBlockOwnershipRemoval8616:
    """One duplicate IR instruction removed in favor of its canonical block."""

    source_block_addr: int
    canonical_block_addr: int
    instr_index: int
    instr_addr: int


@dataclass(frozen=True, slots=True)
class IRBlockOwnershipRefusal8616:
    """One ambiguous overlap retained without changing the input IR."""

    source_block_addr: int
    proposed_owner_addr: int
    instr_index: int
    instr_addr: int
    failure: IRBlockOwnershipFailure8616


@dataclass(frozen=True, slots=True)
class IRBlockOwnershipStats8616:
    """Closed evidence accounting for overlapping instruction ownership."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every overlap candidate has one retained outcome."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_summary(self) -> dict[str, int]:
        """Return stable flat counters for the function IR summary."""
        return {
            "block_ownership_raw_fact_count": self.raw_fact_count,
            "block_ownership_normalized_fact_count": self.normalized_fact_count,
            "block_ownership_classified_fact_count": self.classified_fact_count,
            "block_ownership_materialized_count": self.materialized_count,
            "block_ownership_failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class IRBlockOwnershipArtifact8616:
    """Canonical blocks plus every duplicate removal and overlap refusal."""

    blocks: tuple[IRBlock, ...]
    removals: tuple[IRBlockOwnershipRemoval8616, ...]
    refusals: tuple[IRBlockOwnershipRefusal8616, ...]
    stats: IRBlockOwnershipStats8616

    @property
    def complete(self) -> bool:
        """Return whether all input instructions remain owned or canonicalized."""
        retained_count = sum(len(block.instrs) for block in self.blocks)
        return (
            self.stats.complete
            and retained_count + self.stats.materialized_count
            == self.stats.raw_fact_count
        )


def canonicalize_ir_block_ownership_8616(
    blocks: tuple[IRBlock, ...],
) -> IRBlockOwnershipArtifact8616:
    """Remove only overlap instructions exactly decoded by a later block."""
    ordered = tuple(sorted(blocks, key=lambda block: block.addr))
    starts = tuple(block.addr for block in ordered)
    by_addr = {block.addr: block for block in ordered}
    removals: list[IRBlockOwnershipRemoval8616] = []
    refusals: list[IRBlockOwnershipRefusal8616] = []
    canonical_blocks: list[IRBlock] = []

    for block_index, block in enumerate(ordered):
        later_starts = starts[block_index + 1 :]
        next_start = later_starts[0] if later_starts else None
        retained = []
        for instr_index, instruction in enumerate(block.instrs):
            instr_addr = instruction.addr
            if next_start is None or instr_addr is None or instr_addr < next_start:
                retained.append(instruction)
                continue
            owner_addr = max(start for start in later_starts if start <= instr_addr)
            owner = by_addr[owner_addr]
            if any(candidate.addr == instr_addr for candidate in owner.instrs):
                removals.append(
                    IRBlockOwnershipRemoval8616(
                        block.addr,
                        owner_addr,
                        instr_index,
                        instr_addr,
                    )
                )
                continue
            refusals.append(
                IRBlockOwnershipRefusal8616(
                    block.addr,
                    owner_addr,
                    instr_index,
                    instr_addr,
                    IRBlockOwnershipFailure8616.CANONICAL_OWNER_MISSING_INSTRUCTION,
                )
            )
            retained.append(instruction)
        canonical_blocks.append(
            IRBlock(
                addr=block.addr,
                instrs=tuple(retained),
                refusals=block.refusals,
                successor_addrs=block.successor_addrs,
            )
        )

    raw_count = sum(len(block.instrs) for block in ordered)
    stats = IRBlockOwnershipStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=len(removals) + len(refusals),
        materialized_count=len(removals),
        failure_count=len(refusals),
    )
    return IRBlockOwnershipArtifact8616(
        blocks=tuple(canonical_blocks),
        removals=tuple(removals),
        refusals=tuple(refusals),
        stats=stats,
    )
