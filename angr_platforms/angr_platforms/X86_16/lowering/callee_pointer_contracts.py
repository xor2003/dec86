"""Own validated project-level callee pointer evidence.

Layer: Types/Lowering.
Responsibility: define the immutable pointer-parameter evidence contract and
its authoritative per-project registry. Collection remains in
``callee_pointer_evidence``; transport may only copy records accepted here.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

__all__ = [
    "CalleePointerArgumentEvidence8616",
    "callee_pointer_argument_evidence_by_addr_8616",
    "record_callee_pointer_argument_evidence_8616",
]


@dataclass(frozen=True, slots=True)
class CalleePointerArgumentEvidence8616:
    """Closed evidence loop for one callee's near-pointer parameter classes."""

    target_addr: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    pointer_stack_offsets: tuple[int, ...]
    pointer_argument_indices: tuple[int, ...]
    ambiguous_displaced_stack_offsets: tuple[int, ...]

    def validate(self) -> None:
        """Reject malformed counters, target identity, or pointer coordinates."""
        counters = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if self.target_addr < 0 or any(count < 0 for count in counters):
            raise ValueError("callee pointer evidence has negative coordinates")
        if not (
            self.raw_fact_count
            >= self.normalized_fact_count
            >= self.classified_fact_count
        ):
            raise ValueError("callee pointer evidence counters are not monotonic")
        if self.normalized_fact_count != len(self.pointer_stack_offsets):
            raise ValueError("callee pointer normalized count disagrees with offsets")
        if self.classified_fact_count != len(self.pointer_argument_indices):
            raise ValueError("callee pointer classified count disagrees with indices")
        if self.materialized_count != self.classified_fact_count:
            raise ValueError("callee pointer materialization count is incomplete")
        expected_failures = (
            self.normalized_fact_count - self.classified_fact_count
            + len(self.ambiguous_displaced_stack_offsets)
        )
        if self.failure_count != expected_failures:
            raise ValueError("callee pointer failure count does not close collection")
        if self.pointer_stack_offsets != tuple(sorted(set(self.pointer_stack_offsets))):
            raise ValueError("callee pointer stack offsets are not canonical")
        if self.pointer_argument_indices != tuple(
            sorted(set(self.pointer_argument_indices))
        ):
            raise ValueError("callee pointer argument indices are not canonical")
        if self.ambiguous_displaced_stack_offsets != tuple(
            sorted(set(self.ambiguous_displaced_stack_offsets))
        ):
            raise ValueError("callee pointer ambiguous offsets are not canonical")
        if any(offset < 4 for offset in self.pointer_stack_offsets):
            raise ValueError("callee pointer stack offset precedes the first argument")
        if any(index < 0 for index in self.pointer_argument_indices):
            raise ValueError("callee pointer argument index is negative")
        if set(self.pointer_stack_offsets) & set(
            self.ambiguous_displaced_stack_offsets
        ):
            raise ValueError("callee pointer proven and ambiguous offsets overlap")

    @property
    def closes_classification(self) -> bool:
        """Return whether every normalized pointer slot was materialized."""
        try:
            self.validate()
        except ValueError:
            return False
        return bool(
            self.failure_count == 0
            and self.classified_fact_count > 0
            and self.normalized_fact_count == self.classified_fact_count
        )


class _ProjectEvidenceCarrier8616(Protocol):
    """Owned lowering evidence registry carried across one angr project."""

    _inertia_callee_pointer_argument_evidence_8616: dict[
        int,
        CalleePointerArgumentEvidence8616,
    ]


def _project_evidence_registry_8616(
    project: object,
) -> dict[int, CalleePointerArgumentEvidence8616]:
    """Return the authoritative mutable registry at the project boundary."""
    carrier = cast(_ProjectEvidenceCarrier8616, project)
    try:
        registry = carrier._inertia_callee_pointer_argument_evidence_8616
    except AttributeError:
        registry = {}
        carrier._inertia_callee_pointer_argument_evidence_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("callee pointer evidence registry must be a dict")
    return registry


def callee_pointer_argument_evidence_by_addr_8616(
    project: object,
) -> dict[int, CalleePointerArgumentEvidence8616]:
    """Return a validated snapshot of retained callee pointer evidence."""
    snapshot = dict(_project_evidence_registry_8616(project))
    for target_addr, evidence in snapshot.items():
        if not isinstance(target_addr, int) or isinstance(target_addr, bool):
            raise TypeError("callee pointer evidence registry key must be an integer")
        if not isinstance(evidence, CalleePointerArgumentEvidence8616):
            raise TypeError("callee pointer evidence registry value has a wrong type")
        evidence.validate()
        if evidence.target_addr != target_addr:
            raise ValueError("callee pointer evidence target disagrees with registry key")
    return snapshot


def record_callee_pointer_argument_evidence_8616(
    project: object,
    evidence: CalleePointerArgumentEvidence8616,
) -> None:
    """Record one validated result under its exact callee address."""
    evidence.validate()
    _project_evidence_registry_8616(project)[evidence.target_addr] = evidence
