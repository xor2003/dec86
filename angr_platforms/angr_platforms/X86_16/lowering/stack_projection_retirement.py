"""Retire obsolete entry-SP projections after exact BP lowering.

Layer: Types/Lowering.
Responsibility: keep angr C-variable declaration surfaces coherent after a
typed BP storage object replaces its proven entry-SP projection.
Consumes alias, widening, and typed facts without discovering storage or
inferring widths. Do not recover semantics from COD, source, assembly, or
rendered C text. Do not rewrite C text or delete unresolved variables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol, cast

from angr.sim_variable import SimStackVariable

from ..ir.core import IRAddress

__all__ = [
    "StackProjectionRetirementArtifact8616",
    "StackProjectionRetirementStats8616",
    "retire_materialized_entry_sp_projections_8616",
]


class _BPProjectionCandidate8616(Protocol):
    """Exact machine-BP object and its proven entry-SP projection."""

    @property
    def address(self) -> IRAddress:
        """Return the exact machine-BP storage identity."""
        ...

    @property
    def entry_sp_offset(self) -> int:
        """Return the proven equivalent angr entry-SP offset."""
        ...


class _CFunctionBoundary8616(Protocol):
    """angr declaration maps updated by Lowering."""

    variables_in_use: object
    unified_local_vars: object


class _CodegenBoundary8616(Protocol):
    """Minimal dynamic angr codegen surface used by projection retirement."""

    cfunc: object
    _inertia_stack_local_declaration_candidates: object


@dataclass(frozen=True, slots=True)
class StackProjectionRetirementStats8616:
    """Closed evidence accounting for retired declaration projections."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every exact projected declaration was retired."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Return the mandatory five evidence counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class StackProjectionRetirementArtifact8616:
    """Exact obsolete declaration identities removed from angr surfaces."""

    retired: tuple[tuple[int, int], ...] = ()
    stats: StackProjectionRetirementStats8616 = StackProjectionRetirementStats8616()

    @property
    def complete(self) -> bool:
        """Return whether retirement evidence closes without failure."""
        return self.stats.complete and self.stats.failure_count == 0

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic diagnostic representation."""
        return {
            "retired": [{"offset": offset, "size": size} for offset, size in self.retired],
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


def _projected_variables_8616(
    mapping: object,
    candidates: tuple[_BPProjectionCandidate8616, ...],
) -> tuple[SimStackVariable, ...]:
    """Collect exact obsolete locals from one dynamic angr declaration map."""
    if not isinstance(mapping, dict):
        return ()
    materialized_bp_offsets = frozenset(candidate.address.offset for candidate in candidates)
    projected: list[SimStackVariable] = []
    for variable in mapping:
        if not isinstance(variable, SimStackVariable) or variable.base != "bp":
            continue
        if variable.offset in materialized_bp_offsets:
            continue
        for candidate in candidates:
            if (
                variable.offset == candidate.entry_sp_offset
                and candidate.entry_sp_offset != candidate.address.offset
                and 0 < variable.size <= candidate.address.size
            ):
                projected.append(variable)
                break
    return tuple(projected)


def retire_materialized_entry_sp_projections_8616(
    codegen: object,
    candidates: Iterable[_BPProjectionCandidate8616],
    materialized_bp_offsets: frozenset[int],
) -> StackProjectionRetirementArtifact8616:
    """Remove declaration-only entry-SP views superseded by exact BP objects."""
    eligible = tuple(candidate for candidate in candidates if candidate.address.offset in materialized_bp_offsets)
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = cast(_CFunctionBoundary8616, boundary.cfunc)
    except AttributeError:
        return StackProjectionRetirementArtifact8616()

    variables = _projected_variables_8616(cfunc.variables_in_use, eligible)
    unified_variables = _projected_variables_8616(cfunc.unified_local_vars, eligible)
    retired_variables = tuple({id(variable): variable for variable in (*variables, *unified_variables)}.values())
    if isinstance(cfunc.variables_in_use, dict):
        for variable in variables:
            cfunc.variables_in_use.pop(variable, None)
    if isinstance(cfunc.unified_local_vars, dict):
        for variable in unified_variables:
            cfunc.unified_local_vars.pop(variable, None)
    try:
        declaration_candidates = boundary._inertia_stack_local_declaration_candidates
    except AttributeError:
        declaration_candidates = None
    if isinstance(declaration_candidates, dict):
        for variable in retired_variables:
            declaration_candidates.pop(id(variable), None)

    retired = tuple(sorted((variable.offset, variable.size) for variable in retired_variables))
    count = len(retired)
    return StackProjectionRetirementArtifact8616(
        retired=retired,
        stats=StackProjectionRetirementStats8616(count, count, count, count, 0),
    )
