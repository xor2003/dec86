"""Resolve structured stack views against the current Widening artifact.

Layer: Widening.
Responsibility: bind one third-party structured-C stack variable to the unique
Alias-derived stack-object candidate that owns its exact byte range. This
module proves storage identity only; C expression materialization remains in
``stack_subview_projection``.
Consumes alias-proven storage identity through the typed object artifact.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

Missing syntax is not a candidate. A range covered by a refused, ambiguous,
stale, incomplete, or cross-function artifact is never accepted. Do not infer
ownership from names, rendered C, assembly text, or numeric proximity alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from ..ir.core import IRAddress, MemSpace
from ..pipeline.errors import PipelineHardError
from .stack_memory_objects_contracts import (
    StackMemoryObjectWideningArtifact8616,
    StackMemoryObjectWideningCandidate8616,
)


class StackObjectViewResolutionKind8616(Enum):
    """Typed outcome of resolving one structured stack variable."""

    NOT_CANDIDATE = "not_candidate"
    ACCEPTED = "accepted"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class StackObjectViewProof8616:
    """One exact contained view and its unique materialized object owner."""

    view: structured_c.CVariable
    owner: structured_c.CVariable
    source: StackMemoryObjectWideningCandidate8616
    relative_offset: int
    view_size: int
    owner_size: int


@dataclass(frozen=True, slots=True)
class StackObjectViewResolution8616:
    """Accepted proof, explicit refusal, or unrelated structured variable."""

    kind: StackObjectViewResolutionKind8616
    proof: StackObjectViewProof8616 | None = None
    reason: str | None = None


class _CodegenBoundary8616(Protocol):
    """Owned proof artifacts carried on the dynamic angr codegen boundary."""

    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616
    _inertia_stack_memory_object_widening_artifact: StackMemoryObjectWideningArtifact8616


class _CFunctionBoundary8616(Protocol):
    """Minimal third-party structured function surface used for projection."""

    addr: int
    variables_in_use: dict[object, object]


def current_stack_object_widening_8616(
    codegen: object,
) -> StackMemoryObjectWideningArtifact8616 | None:
    """Return the current complete object proof or reject a layer bypass."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        source = None
    try:
        artifact = boundary._inertia_stack_memory_object_widening_artifact
    except AttributeError:
        artifact = None
    if source is None and artifact is None:
        return None
    if (
        not isinstance(source, StackMemorySSAAliasArtifact8616)
        or not isinstance(artifact, StackMemoryObjectWideningArtifact8616)
        or artifact.source_alias is not source
        or not artifact.complete
    ):
        raise PipelineHardError(
            "stack subview projection does not consume the current complete Widening artifact",
            layer="widening",
        )
    return artifact


def stack_variable_range_8616(variable: object, function_addr: int) -> tuple[int, int] | None:
    """Return one exact BP-relative range from a third-party stack variable."""
    if not isinstance(variable, SimStackVariable):
        return None
    if variable.base != "bp" or variable.region != function_addr:
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
        return None
    return (variable.offset, variable.size) if variable.size > 0 else None


def _address_range_8616(address: IRAddress) -> tuple[int, int] | None:
    """Return one exact SS:BP range from a Widening address."""
    if address.space is not MemSpace.SS or address.base != ("bp",) or address.size <= 0:
        return None
    return address.offset, address.size


def _owner_cvariable_8616(
    cfunc: _CFunctionBoundary8616,
    candidate: StackMemoryObjectWideningCandidate8616,
    function_addr: int,
) -> structured_c.CVariable | None:
    """Return the unique C variable that represents one proven owner range."""
    owner_range = _address_range_8616(candidate.address)
    if owner_range is None:
        return None
    owners = [
        cvar
        for variable, cvar in cfunc.variables_in_use.items()
        if stack_variable_range_8616(variable, function_addr) == owner_range
        and isinstance(cvar, structured_c.CVariable)
    ]
    unique = {id(owner): owner for owner in owners}
    return next(iter(unique.values())) if len(unique) == 1 else None


def resolve_stack_object_view_8616(
    cfunc: object,
    artifact: StackMemoryObjectWideningArtifact8616 | None,
    view: structured_c.CVariable,
) -> StackObjectViewResolution8616:
    """Resolve one exact contained C variable through the typed object proof."""
    if artifact is None:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
    function = cast(_CFunctionBoundary8616, cfunc)
    try:
        function_addr = function.addr
    except AttributeError as ex:
        raise PipelineHardError(
            "stack subview projection has no exact structured function identity",
            layer="widening",
        ) from ex
    if not isinstance(function_addr, int) or function_addr != artifact.function_addr:
        raise PipelineHardError(
            "stack subview projection received a Widening artifact for another function",
            layer="widening",
        )
    view_range = stack_variable_range_8616(view.variable, function_addr)
    if view_range is None:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)

    matching_candidates: list[StackMemoryObjectWideningCandidate8616] = []
    for candidate in artifact.candidates:
        owner_range = _address_range_8616(candidate.address)
        covered_ranges = {
            address_range
            for address in candidate.covered_addresses
            if (address_range := _address_range_8616(address)) is not None
        }
        if owner_range != view_range and view_range in covered_ranges:
            matching_candidates.append(candidate)
    refused = any(
        view_range
        in {
            address_range
            for address in refusal.addresses
            if (address_range := _address_range_8616(address)) is not None
        }
        for refusal in artifact.refusals
    )
    if refused or len(matching_candidates) > 1:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack byte view belongs to a refused or ambiguous object component",
        )
    if not matching_candidates:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)

    candidate = matching_candidates[0]
    owner_range = _address_range_8616(candidate.address)
    if owner_range is None:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack object owner is not an exact SS:BP range",
        )
    try:
        owner = _owner_cvariable_8616(function, candidate, function_addr)
    except AttributeError:
        owner = None
    if owner is None:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack object owner has no unique structured-C variable",
        )
    relative_offset = view_range[0] - owner_range[0]
    if relative_offset < 0 or relative_offset + view_range[1] > owner_range[1]:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack byte view falls outside its accepted object owner",
        )
    return StackObjectViewResolution8616(
        StackObjectViewResolutionKind8616.ACCEPTED,
        StackObjectViewProof8616(
            view=view,
            owner=owner,
            source=candidate,
            relative_offset=relative_offset,
            view_size=view_range[1],
            owner_size=owner_range[1],
        ),
    )


__all__ = [
    "StackObjectViewProof8616",
    "StackObjectViewResolution8616",
    "StackObjectViewResolutionKind8616",
    "current_stack_object_widening_8616",
    "resolve_stack_object_view_8616",
    "stack_variable_range_8616",
]
