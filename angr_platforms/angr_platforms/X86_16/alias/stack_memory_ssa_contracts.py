"""Typed contracts for the stack-memory SSA Alias projection.

Layer: Alias.
Responsibility: define immutable Alias facts, refusals, and closed evidence
accounting for versioned stack-memory inputs.
Owns storage identity contracts only. Do not infer locals or types, widen
ranges, structure control flow, rewrite generated C, or inspect rendered text.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..ir.core import IRAddress, IRRefusal
from .alias_model_impl import AliasStorageFacts


class StackMemoryAliasFactKind8616(str, Enum):
    """Kind of versioned memory fact projected into Alias."""

    LOAD = "load"
    STORE = "store"
    PHI = "phi"


class StackMemoryAliasRefusalKind8616(str, Enum):
    """Typed reason why one stack-memory SSA input was not projected."""

    UPSTREAM_INCOMPLETE = "upstream_incomplete"
    UPSTREAM_MEMORY_REFUSAL = "upstream_memory_refusal"
    UNVERSIONED_ADDRESS = "unversioned_address"
    ALIAS_FAILURE = "alias_failure"
    UNCLASSIFIABLE_ADDRESS = "unclassifiable_address"
    UNVERSIONED_PHI = "unversioned_phi"
    INCONSISTENT_PHI_STORAGE = "inconsistent_phi_storage"
    ORPHAN_UPSTREAM_REFUSAL = "orphan_upstream_refusal"


@dataclass(frozen=True, slots=True)
class StackMemorySSAAliasFact8616:
    """One exact SSA memory version bound to an Alias storage identity."""

    kind: StackMemoryAliasFactKind8616
    block_addr: int
    instr_index: int | None
    address: IRAddress
    storage: AliasStorageFacts
    incoming_versions: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        identity = self.storage.identity
        return {
            "kind": self.kind.value,
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "address": self.address.to_dict(),
            "storage_kind": identity[0] if identity is not None else None,
            "incoming_versions": list(self.incoming_versions),
        }


@dataclass(frozen=True, slots=True)
class StackMemoryAliasRefusal8616:
    """One honestly retained Alias projection failure."""

    kind: StackMemoryAliasRefusalKind8616
    block_addr: int | None
    instr_index: int | None
    detail: str
    address: IRAddress | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "kind": self.kind.value,
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "detail": self.detail,
            "address": self.address.to_dict() if self.address is not None else None,
        }


@dataclass(frozen=True, slots=True)
class StackMemoryAliasStats8616:
    """Closed evidence accounting for the IR-to-Alias projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every input became one fact or one refusal."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )

    def to_dict(self) -> dict[str, int]:
        """Return the five mandatory evidence counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSAAliasArtifact8616:
    """Alias facts and refusals projected from one function SSA artifact."""

    function_addr: int = 0
    facts: tuple[StackMemorySSAAliasFact8616, ...] = ()
    refusals: tuple[StackMemoryAliasRefusal8616, ...] = ()
    source_refusals: tuple[IRRefusal, ...] = ()
    stats: StackMemoryAliasStats8616 = StackMemoryAliasStats8616()
    upstream_complete: bool = True

    @property
    def complete(self) -> bool:
        """Return whether upstream and Alias evidence accounting both close."""
        return self.upstream_complete and self.stats.complete

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "facts": [fact.to_dict() for fact in self.facts],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
            "source_refusals": [refusal.to_dict() for refusal in self.source_refusals],
            "stats": self.stats.to_dict(),
            "upstream_complete": self.upstream_complete,
            "complete": self.complete,
        }


__all__ = [
    "StackMemoryAliasFactKind8616",
    "StackMemoryAliasRefusal8616",
    "StackMemoryAliasRefusalKind8616",
    "StackMemoryAliasStats8616",
    "StackMemorySSAAliasArtifact8616",
    "StackMemorySSAAliasFact8616",
]
