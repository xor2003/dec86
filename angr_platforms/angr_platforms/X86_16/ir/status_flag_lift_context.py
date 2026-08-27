"""Publish proven function-CFG flag liveness to one frontend lift.

Layer: IR.
Responsibility: transport typed, function-owned dead status-flag decisions from
Semantics to the custom frontend while angr rebuilds VEX. This bridge contains
no instruction semantics: it checks exact instruction addresses and write
masks, records every consumed decision, and refuses unmaterialized evidence.
Unknown or unavailable projection evidence leaves architectural flag writes in
place. The context is task-local so parallel function workers cannot share it.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

from ..pipeline.errors import PipelineHardError
from ..semantics.status_flag_contracts import (
    STATUS_FLAGS_8616,
    StatusFlag8616,
    StatusFlagLivenessStats8616,
)

if TYPE_CHECKING:
    from .status_flag_cfg_projection import StatusFlagFunctionProjection8616


class _ArchBoundary8616(Protocol):
    """Third-party architecture identity used to select this frontend bridge."""

    name: str


class _LiftEngineBoundary8616(Protocol):
    """Third-party angr lift engine cache invalidation surface."""

    def clear_cache(self) -> None:
        """Discard cached VEX so active decisions can be materialized."""


class _FactoryBoundary8616(Protocol):
    """Third-party angr factory surface used by the publication bridge."""

    default_engine: _LiftEngineBoundary8616


class _ProjectBoundary8616(Protocol):
    """Third-party project fields required before function-local publication."""

    arch: _ArchBoundary8616
    factory: _FactoryBoundary8616


class _FunctionBoundary8616(Protocol):
    """Third-party function identity and diagnostics mapping."""

    addr: int
    info: MutableMapping[str, object]


@dataclass(frozen=True, slots=True, order=True)
class StatusFlagLiftCandidate8616:
    """One exact instruction write with a CFG-proven dead status-bit subset."""

    instruction_address: int
    written: StatusFlag8616
    dead_writes: StatusFlag8616


@dataclass(frozen=True, slots=True)
class StatusFlagLiftArtifact8616:
    """Immutable frontend evidence published for downstream validation."""

    function_address: int
    candidates: tuple[StatusFlagLiftCandidate8616, ...]
    packed_preservation_addresses: frozenset[int]

    @property
    def partial_write_addresses(self) -> frozenset[int]:
        """Return writes that retain at least one status bit and omit another."""
        return frozenset(
            candidate.instruction_address
            for candidate in self.candidates
            if candidate.dead_writes != candidate.written
        )


@dataclass(slots=True)
class StatusFlagLiftSession8616:
    """Function-local candidates, materialization hits, and final accounting."""

    function_address: int
    candidates: tuple[StatusFlagLiftCandidate8616, ...]
    packed_preservation_addresses: frozenset[int] = frozenset()
    projection_failure_count: int = 0
    stats: StatusFlagLivenessStats8616 = field(
        default_factory=lambda: StatusFlagLivenessStats8616(0, 0, 0, 0, 0)
    )
    _candidate_by_address: dict[int, StatusFlagLiftCandidate8616] = field(
        init=False,
        repr=False,
    )
    _materialized_addresses: set[int] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        """Index the immutable candidate surface for hot frontend lookups."""
        self._candidate_by_address = {
            candidate.instruction_address: candidate for candidate in self.candidates
        }

    @property
    def materialized_addresses(self) -> frozenset[int]:
        """Return exact instructions whose proven flag writes were omitted."""
        return frozenset(self._materialized_addresses)

    @property
    def artifact(self) -> StatusFlagLiftArtifact8616:
        """Return immutable evidence suitable for downstream consumers."""
        return StatusFlagLiftArtifact8616(
            self.function_address,
            self.candidates,
            self.packed_preservation_addresses,
        )

    def dead_write_mask(
        self,
        instruction_address: int,
        written: StatusFlag8616,
    ) -> StatusFlag8616:
        """Consume one exact candidate and return its proven-dead bit subset."""
        candidate = self._candidate_by_address.get(instruction_address)
        normalized_written = written & STATUS_FLAGS_8616
        if candidate is None or candidate.written != normalized_written:
            return StatusFlag8616.NONE
        self._materialized_addresses.add(instruction_address)
        return candidate.dead_writes

    def finalize(self) -> None:
        """Close publication counters and reject wholly unconsumed evidence."""
        classified_count = len(self.candidates)
        materialized_count = len(self._materialized_addresses)
        failure_count = self.projection_failure_count + classified_count - materialized_count
        details = {
            "raw_fact_count": classified_count,
            "normalized_fact_count": classified_count,
            "classified_fact_count": classified_count,
            "materialized_count": materialized_count,
            "failure_count": failure_count,
        }
        if classified_count > 0 and materialized_count == 0:
            raise PipelineHardError(
                "proven dead status-flag writes were not consumed by the frontend lifter",
                layer="ir:status_flag_lift_context",
                function_addr=self.function_address,
                details=details,
            )
        self.stats = StatusFlagLivenessStats8616(
            classified_count,
            classified_count,
            classified_count,
            materialized_count,
            failure_count,
        )


_active_session: ContextVar[StatusFlagLiftSession8616 | None] = ContextVar(
    "x86_16_active_status_flag_lift_session",
    default=None,
)


def _suppression_candidates_8616(
    projection: StatusFlagFunctionProjection8616,
) -> tuple[StatusFlagLiftCandidate8616, ...]:
    """Intersect supported dead bits across every CFG use of one address."""
    decisions_by_address = defaultdict(list)
    for decision in projection.liveness.decisions:
        decisions_by_address[decision.instruction_address].append(decision)
    candidates: list[StatusFlagLiftCandidate8616] = []
    for address, decisions in decisions_by_address.items():
        written_masks = {decision.written for decision in decisions}
        if len(written_masks) != 1 or not all(decision.suppression_supported for decision in decisions):
            continue
        written = next(iter(written_masks))
        dead_writes = written
        for decision in decisions:
            dead_writes &= decision.dead_writes
        if int(dead_writes) != 0:
            candidates.append(StatusFlagLiftCandidate8616(address, written, dead_writes))
    return tuple(sorted(candidates))


def _packed_preservation_addresses_8616(
    projection: StatusFlagFunctionProjection8616,
) -> frozenset[int]:
    """Return address-unambiguous flag writers that read no status input."""
    decisions_by_address = defaultdict(list)
    for decision in projection.liveness.decisions:
        decisions_by_address[decision.instruction_address].append(decision)
    return frozenset(
        address
        for address, decisions in decisions_by_address.items()
        if all(
            decision.suppression_supported and int(decision.written) != 0
            for decision in decisions
        )
    )


def _function_address_8616(function: object) -> int:
    """Read one exact third-party function address or return an inert identity."""
    try:
        return int(cast(_FunctionBoundary8616, function).addr)
    except (AttributeError, TypeError, ValueError):
        return -1


def _is_x86_16_project_8616(project: object) -> bool:
    """Return whether this third-party project uses the custom 16-bit frontend."""
    try:
        return cast(_ProjectBoundary8616, project).arch.name == "86_16"
    except (AttributeError, TypeError, ValueError):
        return False


def _clear_lift_cache_8616(project: object) -> bool:
    """Invalidate third-party VEX caches before publishing new lift evidence."""
    try:
        cast(_ProjectBoundary8616, project).factory.default_engine.clear_cache()
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _publish_stats_8616(function: object, session: StatusFlagLiftSession8616) -> None:
    """Attach the typed publication result to angr function diagnostics."""
    try:
        info = cast(_FunctionBoundary8616, function).info
    except AttributeError:
        return
    if isinstance(info, MutableMapping):
        info["status_flag_lift_stats_8616"] = session.stats.to_dict()


@contextmanager
def active_status_flag_lift_context_8616(
    project: object,
    function: object,
) -> Iterator[StatusFlagLiftSession8616]:
    """Build, publish, and close one function's proven flag suppression facts."""
    function_address = _function_address_8616(function)
    if not _is_x86_16_project_8616(project):
        yield StatusFlagLiftSession8616(function_address, ())
        return

    from .status_flag_cfg_projection import build_status_flag_function_projection_8616

    try:
        projection = build_status_flag_function_projection_8616(project, function)
    except (AttributeError, KeyError, TypeError, ValueError):
        session = StatusFlagLiftSession8616(
            function_address,
            (),
            projection_failure_count=1,
        )
        yield session
        session.finalize()
        _publish_stats_8616(function, session)
        return

    candidates = _suppression_candidates_8616(projection)
    if candidates and not _clear_lift_cache_8616(project):
        session = StatusFlagLiftSession8616(
            function_address,
            (),
            projection_failure_count=1,
        )
        yield session
        session.finalize()
        _publish_stats_8616(function, session)
        return

    session = StatusFlagLiftSession8616(
        function_address,
        candidates,
        _packed_preservation_addresses_8616(projection),
    )
    token = _active_session.set(session)
    completed = False
    try:
        yield session
        completed = True
    finally:
        _active_session.reset(token)
    if completed:
        session.finalize()
        _publish_stats_8616(function, session)


def cfg_status_flag_dead_write_mask_8616(
    instruction_address: int,
    written: StatusFlag8616,
) -> StatusFlag8616 | None:
    """Return an active CFG proof's dead subset, or ``None`` without a proof."""
    session = _active_session.get()
    if session is None:
        return None
    return session.dead_write_mask(instruction_address, written)


def active_status_flag_lift_artifact_8616(
    function_address: int,
) -> StatusFlagLiftArtifact8616 | None:
    """Return exact task-local lift evidence for the active function only."""
    session = _active_session.get()
    if session is None or session.function_address != function_address:
        return None
    return session.artifact


__all__ = [
    "StatusFlagLiftArtifact8616",
    "StatusFlagLiftCandidate8616",
    "StatusFlagLiftSession8616",
    "active_status_flag_lift_artifact_8616",
    "active_status_flag_lift_context_8616",
    "cfg_status_flag_dead_write_mask_8616",
]
