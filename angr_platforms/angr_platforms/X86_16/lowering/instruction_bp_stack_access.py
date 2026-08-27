"""Project exact Alias stack accesses by source instruction address.

Layer: Types/Lowering.
Responsibility: index already-proven ``SS:BP`` Alias accesses for C AST
materializers that carry exact instruction-origin tags. Alias remains the
authoritative storage owner; this module only projects its facts into a lookup
shape suitable for Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from ..alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasArtifact8616,
)
from ..ir.core import AddressStatus, IRAddress, MemSpace
from ..ir.logical_memory_contracts import IRMemoryAccessKind8616
from ..ir.ssa_memory_contracts import SSAMemoryAccessKind8616


@dataclass(frozen=True, slots=True)
class InstructionBpStackAccess8616:
    """One exact Alias-proven BP access at an instruction address."""

    displacement: int
    size: int
    kind: StackMemoryAliasFactKind8616


class InstructionBpStackAccessRefusalKind8616(StrEnum):
    """Reason one direct-BP Alias fact could not enter the instruction index."""

    SOURCE_INSTRUCTION_MISSING = "source_instruction_missing"


@dataclass(frozen=True, slots=True)
class InstructionBpStackAccessRefusal8616:
    """One typed refusal retained by the instruction projection."""

    kind: InstructionBpStackAccessRefusalKind8616
    block_addr: int
    instr_index: int
    detail: str


@dataclass(frozen=True, slots=True)
class InstructionBpStackAccessStats8616:
    """Closed evidence accounting for the Alias-to-Lowering projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every direct-BP input was indexed or refused."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class InstructionBpStackAccessIndex8616:
    """Immutable instruction lookup projected from one exact Alias artifact."""

    source_alias: StackMemorySSAAliasArtifact8616
    by_instruction_addr: Mapping[int, tuple[InstructionBpStackAccess8616, ...]]
    refusals: tuple[InstructionBpStackAccessRefusal8616, ...]
    stats: InstructionBpStackAccessStats8616

    @property
    def fact_count(self) -> int:
        """Return the number of distinct indexed instruction access facts."""
        return sum(len(facts) for facts in self.by_instruction_addr.values())

    @property
    def complete(self) -> bool:
        """Return whether evidence accounting and source Alias both close."""
        return self.source_alias.complete and self.stats.complete

    @property
    def logical_inventory(self) -> tuple[tuple[int, int, int, IRMemoryAccessKind8616], ...]:
        """Return logical machine address, BP range, and kind diagnostics."""
        return tuple(
            (
                access.source.key.insn_addr,
                access.address.offset,
                access.address.size,
                access.source.kind,
            )
            for access in self.source_alias.logical_accesses
        )


class _CodegenBoundary8616(Protocol):
    """Dynamic codegen extension used to retain the typed index."""

    _inertia_instruction_bp_stack_access_index_8616: InstructionBpStackAccessIndex8616


def _is_direct_stable_bp_address_8616(address: IRAddress) -> bool:
    """Return whether Alias proved one exact stable SS:BP range."""
    return (
        address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.size > 0
    )


def _instruction_addr_8616(
    source: StackMemorySSAAliasArtifact8616,
    block_addr: int,
    instr_index: int,
) -> int | None:
    """Resolve one Alias source position through its exact SSA owner."""
    block = next(
        (candidate for candidate in source.source_ssa.blocks if candidate.addr == block_addr),
        None,
    )
    if block is None or not 0 <= instr_index < len(block.instrs):
        return None
    instruction_addr = block.instrs[instr_index].addr
    return instruction_addr if isinstance(instruction_addr, int) else None


def _access_kind_8616(kind: SSAMemoryAccessKind8616) -> StackMemoryAliasFactKind8616:
    """Project the IR access kind into the existing Alias fact enum."""
    return (
        StackMemoryAliasFactKind8616.STORE
        if kind is SSAMemoryAccessKind8616.STORE
        else StackMemoryAliasFactKind8616.LOAD
    )


def _logical_access_kind_8616(
    kind: IRMemoryAccessKind8616,
) -> StackMemoryAliasFactKind8616:
    """Project one authoritative logical access kind into Alias terminology."""
    return (
        StackMemoryAliasFactKind8616.STORE
        if kind is IRMemoryAccessKind8616.WRITE
        else StackMemoryAliasFactKind8616.LOAD
    )


def build_instruction_bp_stack_access_index_8616(
    source: StackMemorySSAAliasArtifact8616,
) -> InstructionBpStackAccessIndex8616:
    """Project direct stable BP accesses from one exact Alias artifact."""
    candidates = [
        (fact.block_addr, fact.instr_index, fact.address, fact.kind)
        for fact in source.facts
        if fact.kind is not StackMemoryAliasFactKind8616.PHI
        and isinstance(fact.instr_index, int)
        and _is_direct_stable_bp_address_8616(fact.address)
    ]
    candidates.extend(
        (
            access.source.block_addr,
            access.source.instr_index,
            access.source.address,
            _access_kind_8616(access.source.kind),
        )
        for access in source.accesses
        if _is_direct_stable_bp_address_8616(access.source.address)
    )
    logical_candidates = tuple(
        (
            access.source.key.insn_addr,
            access.address,
            _logical_access_kind_8616(access.source.kind),
        )
        for access in source.logical_accesses
        if _is_direct_stable_bp_address_8616(access.address)
    )
    collected: dict[int, set[InstructionBpStackAccess8616]] = {}
    refusals: list[InstructionBpStackAccessRefusal8616] = []
    materialized_count = 0
    for block_addr, instr_index, address, kind in candidates:
        instruction_addr = _instruction_addr_8616(source, block_addr, instr_index)
        if instruction_addr is None:
            refusals.append(
                InstructionBpStackAccessRefusal8616(
                    InstructionBpStackAccessRefusalKind8616.SOURCE_INSTRUCTION_MISSING,
                    block_addr,
                    instr_index,
                    "Alias source position has no exact SSA instruction address",
                )
            )
            continue
        collected.setdefault(instruction_addr, set()).add(
            InstructionBpStackAccess8616(address.offset, address.size, kind)
        )
        materialized_count += 1
    for instruction_addr, address, kind in logical_candidates:
        collected.setdefault(instruction_addr, set()).add(
            InstructionBpStackAccess8616(address.offset, address.size, kind)
        )
        materialized_count += 1
    stats = InstructionBpStackAccessStats8616(
        raw_fact_count=len(candidates) + len(logical_candidates),
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    return InstructionBpStackAccessIndex8616(
        source,
        {
            addr: tuple(
                sorted(
                    facts,
                    key=lambda fact: (
                        fact.displacement,
                        fact.size,
                        fact.kind.value,
                    ),
                )
            )
            for addr, facts in sorted(collected.items())
        },
        tuple(refusals),
        stats,
    )


def ensure_instruction_bp_stack_access_index_8616(
    codegen: object,
    source: StackMemorySSAAliasArtifact8616,
) -> InstructionBpStackAccessIndex8616:
    """Return the index consuming this exact immutable Alias artifact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        existing = boundary._inertia_instruction_bp_stack_access_index_8616
    except AttributeError:
        existing = None
    if (
        isinstance(existing, InstructionBpStackAccessIndex8616)
        and existing.source_alias is source
    ):
        return existing
    built = build_instruction_bp_stack_access_index_8616(source)
    boundary._inertia_instruction_bp_stack_access_index_8616 = built
    return built


__all__ = [
    "InstructionBpStackAccess8616",
    "InstructionBpStackAccessIndex8616",
    "InstructionBpStackAccessRefusal8616",
    "InstructionBpStackAccessRefusalKind8616",
    "InstructionBpStackAccessStats8616",
    "build_instruction_bp_stack_access_index_8616",
    "ensure_instruction_bp_stack_access_index_8616",
]
