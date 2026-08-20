"""Materialize exact stack-memory SSA storage through Lowering.

Layer: Types/Lowering.
Responsibility: deduplicate Alias-proved SSA versions into exact BP stack
objects and invoke the canonical stack-variable materializer.
Consumes alias, widening, and typed facts without rediscovering storage
semantics. Do not recover semantics from COD, source, assembly, or rendered C
text. Do not perform structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, TypeAlias, cast

from ..alias.alias_model_impl import AliasStorageFacts
from ..alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasArtifact8616,
    StackMemorySSAAliasFact8616,
)
from ..analysis.stack_frame_ir import FrameAccessArtifact, FrameCoordinateStatus8616
from ..ir.core import IRAddress
from ..pipeline.errors import PipelineHardError
from ..widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616
from .carry_borrow_stack_storage import (
    WideCarryBorrowStackArtifact8616,
    project_wide_carry_borrow_stack_storage_8616,
)
from .stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616
from .stack_lowering_result import StackLoweringResult, StackLoweringStatus
from .stack_projection_retirement import (
    StackProjectionRetirementArtifact8616,
    retire_materialized_entry_sp_projections_8616,
)

_StorageKey8616: TypeAlias = tuple[str, tuple[str, ...], int, int]

__all__ = [
    "StackMemoryObjectKind8616",
    "StackMemorySSALoweringArtifact8616",
    "StackMemorySSALoweringCandidate8616",
    "StackMemorySSALoweringRefusal8616",
    "StackMemorySSALoweringRefusalKind8616",
    "StackMemorySSALoweringStats8616",
    "lower_x86_16_stack_memory_ssa_alias_artifact",
]


class _CodegenBoundary8616(Protocol):
    """Owned artifacts carried across the dynamic angr codegen boundary."""

    _inertia_stack_memory_ssa_alias_artifact: object
    _inertia_stack_memory_ssa_lowering_artifact: StackMemorySSALoweringArtifact8616
    _inertia_wide_carry_borrow_stack_artifact: WideCarryBorrowStackArtifact8616
    _inertia_carry_borrow_widening_pipeline_8616: CarryBorrowWideningPipeline8616
    _inertia_semantic_alias_facts: list[object]
    _inertia_vex_ir_frame: object


class StackMemoryObjectKind8616(str, Enum):
    """Lowering role proven by one exact BP offset."""

    LOCAL = "local"
    ARGUMENT = "argument"


class StackMemorySSALoweringRefusalKind8616(str, Enum):
    """Typed reason why one storage group did not become a C variable."""

    SOURCE_ALIAS_REFUSAL = "source_alias_refusal"
    INCONSISTENT_ALIAS_STORAGE = "inconsistent_alias_storage"
    PHI_WITHOUT_ACCESS = "phi_without_access"
    FRAME_CONTROL_SLOT = "frame_control_slot"
    FRAME_COORDINATE_UNPROVEN = "frame_coordinate_unproven"
    ARGUMENT_STORAGE_TRIAL_REQUIRED = "argument_storage_trial_required"
    MATERIALIZATION_FAILED = "materialization_failed"


@dataclass(frozen=True, slots=True)
class StackMemorySSALoweringCandidate8616:
    """One exact Alias storage range ready for C-variable materialization."""

    role: StackMemoryObjectKind8616
    address: IRAddress
    entry_sp_offset: int
    storage: AliasStorageFacts
    versions: tuple[int, ...]
    fact_kinds: tuple[StackMemoryAliasFactKind8616, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "role": self.role.value,
            "address": self.address.to_dict(),
            "entry_sp_offset": self.entry_sp_offset,
            "versions": list(self.versions),
            "fact_kinds": [kind.value for kind in self.fact_kinds],
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSALoweringRefusal8616:
    """One honestly retained stack-object materialization refusal."""

    kind: StackMemorySSALoweringRefusalKind8616
    detail: str
    address: IRAddress | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "kind": self.kind.value,
            "detail": self.detail,
            "address": self.address.to_dict() if self.address is not None else None,
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSALoweringStats8616:
    """Closed evidence accounting for exact storage materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every distinct storage input has one outcome."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count <= self.raw_fact_count
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
class StackMemorySSALoweringArtifact8616:
    """Exact stack-object candidates, outcomes, and materializer diagnostics."""

    function_addr: int
    candidates: tuple[StackMemorySSALoweringCandidate8616, ...] = ()
    refusals: tuple[StackMemorySSALoweringRefusal8616, ...] = ()
    result: StackLoweringResult | None = None
    projection_retirement: StackProjectionRetirementArtifact8616 = StackProjectionRetirementArtifact8616()
    stats: StackMemorySSALoweringStats8616 = StackMemorySSALoweringStats8616()

    @property
    def complete(self) -> bool:
        """Return whether evidence closes and the materializer accepted all candidates."""
        return self.stats.complete and (self.result is None or self.result.is_ok)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
            "result": self.result.to_dict() if self.result is not None else None,
            "projection_retirement": self.projection_retirement.to_dict(),
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


def _storage_key_8616(fact: StackMemorySSAAliasFact8616) -> _StorageKey8616:
    """Return exact segmented storage identity without its SSA version."""
    return _address_key_8616(fact.address)


def _address_key_8616(address: IRAddress) -> _StorageKey8616:
    """Return exact segmented range identity without an SSA version."""
    return (address.space.value, address.base, address.offset, address.size)


def _unversioned_address_8616(address: IRAddress) -> IRAddress:
    """Project a versioned access back to its exact storage-range identity."""
    return IRAddress(
        space=address.space,
        base=address.base,
        offset=address.offset,
        size=address.size,
        status=address.status,
        segment_origin=address.segment_origin,
        expr=address.expr,
    )


def _classify_storage_groups_8616(
    source: StackMemorySSAAliasArtifact8616,
    bp_entry_sp_delta: int | None,
) -> tuple[
    list[StackMemorySSALoweringCandidate8616],
    list[StackMemorySSALoweringRefusal8616],
]:
    """Collapse SSA versions only when their exact Alias storage agrees."""
    groups: dict[_StorageKey8616, list[StackMemorySSAAliasFact8616]] = {}
    for fact in source.facts:
        groups.setdefault(_storage_key_8616(fact), []).append(fact)
    candidates: list[StackMemorySSALoweringCandidate8616] = []
    refusals = [
        StackMemorySSALoweringRefusal8616(
            StackMemorySSALoweringRefusalKind8616.SOURCE_ALIAS_REFUSAL,
            refusal.detail,
            refusal.address,
        )
        for refusal in source.refusals
    ]
    for key in sorted(groups):
        facts = groups[key]
        representative = facts[0]
        if any(fact.storage != representative.storage for fact in facts[1:]):
            refusals.append(
                StackMemorySSALoweringRefusal8616(
                    StackMemorySSALoweringRefusalKind8616.INCONSISTENT_ALIAS_STORAGE,
                    "SSA versions for one range have different Alias storage identities",
                    representative.address,
                )
            )
            continue
        kinds = tuple(sorted({fact.kind for fact in facts}, key=lambda item: item.value))
        if all(kind is StackMemoryAliasFactKind8616.PHI for kind in kinds):
            refusals.append(
                StackMemorySSALoweringRefusal8616(
                    StackMemorySSALoweringRefusalKind8616.PHI_WITHOUT_ACCESS,
                    "memory phi has no concrete load or store",
                    representative.address,
                )
            )
            continue
        address = representative.address
        offset = address.offset
        if offset < 4 and offset + address.size > 0:
            refusals.append(
                StackMemorySSALoweringRefusal8616(
                    StackMemorySSALoweringRefusalKind8616.FRAME_CONTROL_SLOT,
                    "saved frame pointer and return-address storage are not C objects",
                    representative.address,
                )
            )
            continue
        if offset >= 4:
            refusals.append(
                StackMemorySSALoweringRefusal8616(
                    StackMemorySSALoweringRefusalKind8616.ARGUMENT_STORAGE_TRIAL_REQUIRED,
                    "positive BP storage remains unresolved until argument storage trials agree",
                    address,
                )
            )
            continue
        if bp_entry_sp_delta is None:
            refusals.append(
                StackMemorySSALoweringRefusal8616(
                    StackMemorySSALoweringRefusalKind8616.FRAME_COORDINATE_UNPROVEN,
                    "local BP storage has no proven relation to angr's entry-SP coordinate",
                    address,
                )
            )
            continue
        candidates.append(
            StackMemorySSALoweringCandidate8616(
                StackMemoryObjectKind8616.LOCAL if offset < 0 else StackMemoryObjectKind8616.ARGUMENT,
                _unversioned_address_8616(address),
                offset + bp_entry_sp_delta,
                representative.storage,
                tuple(sorted({cast(int, fact.address.version) for fact in facts})),
                kinds,
            )
        )
    return candidates, refusals


def lower_x86_16_stack_memory_ssa_alias_artifact(
    codegen: object,
) -> StackMemorySSALoweringArtifact8616 | None:
    """Materialize exact SSA storage through the existing Lowering consumer."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        return None
    if not isinstance(source, StackMemorySSAAliasArtifact8616):
        return None
    if not source.complete:
        raise PipelineHardError(
            "stack-memory SSA Alias artifact is incomplete before Lowering",
            layer="stack_lowering",
        )
    try:
        frame = boundary._inertia_vex_ir_frame
    except AttributeError:
        frame = None
    bp_coordinate = frame.bp_coordinate if isinstance(frame, FrameAccessArtifact) else None
    bp_entry_sp_delta = (
        bp_coordinate.bp_entry_sp_delta
        if bp_coordinate is not None and bp_coordinate.status is FrameCoordinateStatus8616.PROVEN
        else None
    )
    candidates, refusals = _classify_storage_groups_8616(source, bp_entry_sp_delta)
    try:
        carry_pipeline = boundary._inertia_carry_borrow_widening_pipeline_8616
    except AttributeError:
        carry_pipeline = None
    if isinstance(carry_pipeline, CarryBorrowWideningPipeline8616):
        if not carry_pipeline.complete or carry_pipeline.source_stack_alias is not source:
            raise PipelineHardError(
                "carry Widening does not consume this exact stack-memory Alias artifact",
                layer="stack_lowering",
            )
        wide_stack = project_wide_carry_borrow_stack_storage_8616(
            carry_pipeline,
            bp_entry_sp_delta,
        )
        covered = {
            _address_key_8616(address)
            for candidate in wide_stack.candidates
            for address in candidate.source_ranges
        }
        candidates = [candidate for candidate in candidates if _address_key_8616(candidate.address) not in covered]
        candidates.extend(
            StackMemorySSALoweringCandidate8616(
                StackMemoryObjectKind8616.LOCAL,
                candidate.address,
                candidate.entry_sp_offset,
                candidate.storage,
                candidate.source.source_versions,
                (StackMemoryAliasFactKind8616.STORE,),
            )
            for candidate in wide_stack.candidates
        )
        boundary._inertia_wide_carry_borrow_stack_artifact = wide_stack
    boundary._inertia_semantic_alias_facts = [candidate.storage for candidate in candidates]
    result = (
        lower_stack_accesses_from_alias_facts_8616(
            codegen,
            list(boundary._inertia_semantic_alias_facts),
            required_bp_ranges=frozenset(
                (candidate.address.offset, candidate.address.size) for candidate in candidates
            ),
        )
        if candidates
        else StackLoweringResult(status=StackLoweringStatus.OK)
    )
    materialized_offsets = {offset for offset, _name in result.materialized}
    missing = [candidate for candidate in candidates if candidate.address.offset not in materialized_offsets]
    projection_retirement = retire_materialized_entry_sp_projections_8616(
        codegen,
        candidates,
        frozenset(materialized_offsets),
    )
    refusals.extend(
        StackMemorySSALoweringRefusal8616(
            StackMemorySSALoweringRefusalKind8616.MATERIALIZATION_FAILED,
            "canonical stack Lowering did not materialize the exact range",
            candidate.address,
        )
        for candidate in missing
    )
    artifact = StackMemorySSALoweringArtifact8616(
        function_addr=source.function_addr,
        candidates=tuple(candidates),
        refusals=tuple(refusals),
        result=result,
        projection_retirement=projection_retirement,
        stats=StackMemorySSALoweringStats8616(
            raw_fact_count=len(candidates) + len(refusals) - len(missing),
            normalized_fact_count=len(candidates),
            classified_fact_count=len(candidates),
            materialized_count=len(candidates) - len(missing),
            failure_count=len(refusals),
        ),
    )
    boundary._inertia_stack_memory_ssa_lowering_artifact = artifact
    if not artifact.complete:
        raise PipelineHardError(
            "exact stack-memory SSA range was not fully materialized",
            layer="stack_lowering",
            details=artifact.to_dict(),
        )
    return artifact
