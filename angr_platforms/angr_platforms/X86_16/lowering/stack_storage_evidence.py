"""Query Alias-owned stack storage ranges from Lowering.

Layer: Types/Lowering.
Responsibility: expose byte-range containment already proved by the current
complete stack-memory Alias artifact. This module does not create storage
identity, widen objects, or infer arguments from C syntax.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from ..alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from ..analysis.stack_frame_ir import (
    FrameAccessArtifact,
    FrameCoordinateStatus8616,
)
from ..ir.core import AddressStatus, IRAddress, MemSpace


class _CodegenBoundary8616(Protocol):
    """Dynamic codegen boundary carrying the current Alias artifact."""

    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616


class _FrameCodegenBoundary8616(Protocol):
    """Dynamic codegen boundary carrying the typed frame-access artifact."""

    _inertia_vex_ir_frame: FrameAccessArtifact


def _contains_bp_range_8616(address: IRAddress, offset: int, size: int) -> bool:
    """Return whether one stable BP address contains the requested range."""
    return (
        address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.offset <= offset
        and address.offset + address.size >= offset + size
    )


def alias_proves_stack_range_8616(
    codegen: object,
    offset: int,
    size: int | None,
) -> bool:
    """Return whether complete Alias evidence contains one exact byte range."""
    if not isinstance(size, int) or size <= 0:
        return False
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        artifact = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, StackMemorySSAAliasArtifact8616) or not artifact.complete:
        return False
    return any(
        _contains_bp_range_8616(fact.address, offset, size)
        for fact in artifact.facts
    ) or any(
        _contains_bp_range_8616(access.source.address, offset, size)
        for access in artifact.logical_accesses
    )


def alias_excludes_stack_range_8616(
    codegen: object,
    offset: int,
    size: int,
) -> bool:
    """Return whether complete refusal-free Alias evidence excludes a BP range."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        artifact = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        return False
    if (
        not isinstance(artifact, StackMemorySSAAliasArtifact8616)
        or not artifact.complete
        or artifact.refusals
        or artifact.source_refusals
        or artifact.logical_refusals
    ):
        return False
    return not alias_proves_stack_range_8616(codegen, offset, size)


def proven_bp_entry_sp_delta_8616(codegen: object) -> int | None:
    """Return the typed BP-to-entry-SP delta, refusing absent frame proof."""
    try:
        artifact = cast(_FrameCodegenBoundary8616, codegen)._inertia_vex_ir_frame
    except AttributeError:
        return None
    if (
        not isinstance(artifact, FrameAccessArtifact)
        or artifact.bp_coordinate.status is not FrameCoordinateStatus8616.PROVEN
        or not isinstance(artifact.bp_coordinate.bp_entry_sp_delta, int)
    ):
        return None
    return artifact.bp_coordinate.bp_entry_sp_delta


def typed_frame_excludes_stack_range_8616(
    codegen: object,
    offset: int,
    size: int,
) -> bool:
    """Return whether refusal-free typed frame evidence excludes a BP range."""
    try:
        artifact = cast(_FrameCodegenBoundary8616, codegen)._inertia_vex_ir_frame
    except AttributeError:
        return False
    if (
        not isinstance(artifact, FrameAccessArtifact)
        or artifact.refusals
        or not artifact.bp_coordinate.complete
        or artifact.bp_coordinate.status is not FrameCoordinateStatus8616.PROVEN
    ):
        return False
    return not any(
        slot.base == "bp"
        and slot.offset <= offset
        and slot.offset + slot.size >= offset + size
        for slot in artifact.slots
    )


__all__ = [
    "alias_excludes_stack_range_8616",
    "alias_proves_stack_range_8616",
    "proven_bp_entry_sp_delta_8616",
    "typed_frame_excludes_stack_range_8616",
]
