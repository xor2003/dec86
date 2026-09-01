"""Project typed values from Alias-owned machine-BP stack storage.

Layer: Types/Lowering.
Responsibility: turn a proven byte range inside one canonical stack value into
an unsigned structured-C load expression. This preserves the ``SEG_U*`` load
contract while reusing the owning function argument instead of materializing a
second stack object. Storage identity remains owned by
``stack_variable_coordinates``.
Do not infer ranges from source, COD, assembly text, or rendered C.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypePointer, SimTypeShort

from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import (
    StackVariableCoordinateProjection8616,
    stack_variable_coordinate_registry_8616,
)


class StackValueProjectionStatus8616(StrEnum):
    """Typed outcome of one machine-BP value projection attempt."""

    EXACT_VALUE = "exact-value"
    CONTAINED_VALUE = "contained-value"
    INVALID_RANGE = "invalid-range"
    NO_OWNER = "no-owner"
    AMBIGUOUS_OWNER = "ambiguous-owner"
    OUTSIDE_VALUE = "outside-value"
    OWNER_NOT_EXPRESSION = "owner-not-expression"
    UNSUPPORTED_POINTER_WIDTH = "unsupported-pointer-width"


@dataclass(frozen=True, slots=True)
class StackValueProjectionResult8616:
    """One projected stack expression or an evidence-backed refusal."""

    status: StackValueProjectionStatus8616
    expression: structured_c.CExpression | None = None
    owner: StackVariableCoordinateProjection8616 | None = None

    @property
    def materialized(self) -> bool:
        """Return whether this result owns a usable structured expression."""
        return self.expression is not None and self.owner is not None


@dataclass(frozen=True, slots=True)
class StackValueProjectionStats8616:
    """Closed evidence loop for typed stack-value projections."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def record(
        self,
        result: StackValueProjectionResult8616,
    ) -> StackValueProjectionStats8616:
        """Return counters including one classified projection result."""
        return StackValueProjectionStats8616(
            raw_fact_count=self.raw_fact_count + 1,
            normalized_fact_count=self.normalized_fact_count + 1,
            classified_fact_count=self.classified_fact_count + 1,
            materialized_count=self.materialized_count + int(result.materialized),
            failure_count=self.failure_count + int(not result.materialized),
        )


class _ProjectBoundary8616(Protocol):
    """Third-party project field used to bind C integer widths."""

    arch: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen fields used by stack-value projection."""

    project: _ProjectBoundary8616
    cfunc: _CFunctionBoundary8616
    _inertia_stack_value_projection_stats_8616: StackValueProjectionStats8616


class _CFunctionBoundary8616(Protocol):
    """Third-party function interface used to identify canonical arguments."""

    arg_list: list[object] | tuple[object, ...]


def stack_value_projection_stats_8616(
    codegen: object,
) -> StackValueProjectionStats8616:
    """Return typed projection counters attached at the angr boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        stats = boundary._inertia_stack_value_projection_stats_8616
    except AttributeError:
        return StackValueProjectionStats8616()
    return stats if isinstance(stats, StackValueProjectionStats8616) else StackValueProjectionStats8616()


def _publish_result_8616(
    codegen: object,
    result: StackValueProjectionResult8616,
) -> StackValueProjectionResult8616:
    """Publish one projection outcome and return it unchanged."""
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_value_projection_stats_8616 = (
        stack_value_projection_stats_8616(codegen).record(result)
    )
    return result


def _unsigned_type_for_width_8616(codegen: object, width: int) -> SimType:
    """Return an unsigned C type matching one supported runtime load width."""
    type_: SimType
    if width == 1:
        type_ = SimTypeChar(False)
    elif width == 2:
        type_ = SimTypeShort(False)
    elif width == 4:
        type_ = SimTypeLong(False)
    else:
        type_ = SimTypeInt(False)
    try:
        return type_.with_arch(cast(_CodegenBoundary8616, codegen).project.arch)
    except AttributeError:
        return type_


def project_stack_value_range_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> StackValueProjectionResult8616:
    """Project one proven stack value range as a typed C expression.

    ABI padding is not part of the typed value. A byte read at ``arg+1`` may
    therefore project from a word argument, but must refuse for a one-byte
    argument occupying a two-byte stack slot. An exact function-pointer load
    remains a function pointer; only data-pointer storage views become numeric
    guest offsets.
    """
    if size <= 0:
        return _publish_result_8616(
            codegen,
            StackValueProjectionResult8616(StackValueProjectionStatus8616.INVALID_RANGE),
        )
    registry = stack_variable_coordinate_registry_8616(codegen)
    owners = tuple(
        projection
        for projection in registry.projections
        if projection.bp_offset <= bp_offset
        and projection.bp_offset + projection.size >= bp_offset + size
    )
    if len(owners) > 1:
        try:
            arguments = tuple(cast(_CodegenBoundary8616, codegen).cfunc.arg_list)
        except AttributeError:
            arguments = ()
        interface_owners = tuple(
            owner
            for owner in owners
            if any(owner.cvar is argument for argument in arguments)
        )
        if len(interface_owners) == 1:
            owners = interface_owners
    if not owners:
        return _publish_result_8616(
            codegen,
            StackValueProjectionResult8616(StackValueProjectionStatus8616.NO_OWNER),
        )
    if len(owners) != 1:
        return _publish_result_8616(
            codegen,
            StackValueProjectionResult8616(StackValueProjectionStatus8616.AMBIGUOUS_OWNER),
        )
    owner = owners[0]
    relative_offset = bp_offset - owner.bp_offset
    if relative_offset < 0 or relative_offset + size > owner.value_size:
        return _publish_result_8616(
            codegen,
            StackValueProjectionResult8616(
                StackValueProjectionStatus8616.OUTSIDE_VALUE,
                owner=owner,
            ),
        )
    if not isinstance(owner.cvar, structured_c.CExpression):
        return _publish_result_8616(
            codegen,
            StackValueProjectionResult8616(
                StackValueProjectionStatus8616.OWNER_NOT_EXPRESSION,
                owner=owner,
            ),
        )
    try:
        source_type = owner.cvar.type
    except (AttributeError, ValueError):
        source_type = None
    expression: structured_c.CExpression = owner.cvar
    if (
        isinstance(source_type, SimTypePointer)
        and isinstance(source_type.pts_to, SimTypeFunction)
        and relative_offset == 0
        and size == owner.value_size
    ):
        return _publish_result_8616(
            codegen,
            StackValueProjectionResult8616(
                StackValueProjectionStatus8616.EXACT_VALUE,
                expression=expression,
                owner=owner,
            ),
        )
    if isinstance(source_type, SimTypePointer):
        helper_name = {2: "PTR_U16", 4: "PTR_U32"}.get(owner.value_size)
        if helper_name is None:
            return _publish_result_8616(
                codegen,
                StackValueProjectionResult8616(
                    StackValueProjectionStatus8616.UNSUPPORTED_POINTER_WIDTH,
                    owner=owner,
                ),
            )
        expression = structured_c.CFunctionCall(
            helper_name,
            None,
            [expression],
            codegen=codegen,
        )
        source_type = _unsigned_type_for_width_8616(codegen, owner.value_size)
    if relative_offset:
        shift_type = _unsigned_type_for_width_8616(codegen, 2)
        expression = structured_c.CBinaryOp(
            "Shr",
            expression,
            structured_c.CConstant(relative_offset * 8, shift_type, codegen=codegen),
            codegen=codegen,
        )
    expression = CSemanticCast8616(
        source_type,
        _unsigned_type_for_width_8616(codegen, size),
        expression,
        codegen=codegen,
    )
    status = (
        StackValueProjectionStatus8616.EXACT_VALUE
        if relative_offset == 0 and size == owner.value_size
        else StackValueProjectionStatus8616.CONTAINED_VALUE
    )
    return _publish_result_8616(
        codegen,
        StackValueProjectionResult8616(status, expression=expression, owner=owner),
    )


__all__ = [
    "StackValueProjectionResult8616",
    "StackValueProjectionStats8616",
    "StackValueProjectionStatus8616",
    "project_stack_value_range_8616",
    "stack_value_projection_stats_8616",
]
