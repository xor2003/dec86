"""Keep machine-BP and angr entry-SP stack coordinates coherent.

Layer: Types/Lowering.
Responsibility: record the exact coordinate projection used when Alias-proven
SS:BP storage is materialized as angr ``SimStackVariable`` objects. Consumers
must ask this owner for machine-BP offsets instead of interpreting angr's
entry-SP ``variable.offset`` as a BP displacement.
Dynamic boundary: the registry is attached to third-party angr codegen objects.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.sim_variable import SimStackVariable


@dataclass(frozen=True, slots=True)
class StackVariableCoordinateProjection8616:
    """One exact machine-BP to angr entry-SP variable projection."""

    variable: SimStackVariable
    cvar: object
    bp_offset: int
    entry_sp_offset: int
    size: int
    display_name: str = ""


@dataclass(frozen=True, slots=True)
class StackVariableCoordinateRegistry8616:
    """Immutable coordinate projections owned by one codegen surface."""

    projections: tuple[StackVariableCoordinateProjection8616, ...] = ()

    def for_variable(
        self,
        variable: SimStackVariable,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the projection for the exact angr variable object."""
        return next(
            (projection for projection in self.projections if projection.variable is variable),
            None,
        )

    def for_bp_range(
        self,
        bp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projection for one exact machine-BP byte range."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.bp_offset == bp_offset and projection.size == size
        )
        return matches[0] if len(matches) == 1 else None

    def for_entry_sp_range(
        self,
        entry_sp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projection surviving an AST variable clone."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset == entry_sp_offset and projection.size == size
        )
        return matches[0] if len(matches) == 1 else None

    def containing_entry_sp_range(
        self,
        entry_sp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projected owner containing one entry-SP range."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset <= entry_sp_offset
            and projection.entry_sp_offset + projection.size
            >= entry_sp_offset + size
        )
        return matches[0] if len(matches) == 1 else None


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen extension carrying the owned registry."""

    _inertia_stack_variable_coordinate_registry_8616: StackVariableCoordinateRegistry8616


class _CVariableBoundary8616(Protocol):
    """Third-party C variable field needed to publish a selected projection."""

    variable: object


def stack_variable_coordinate_registry_8616(
    codegen: object,
) -> StackVariableCoordinateRegistry8616:
    """Return the typed registry attached to an angr codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        registry = boundary._inertia_stack_variable_coordinate_registry_8616
    except AttributeError:
        return StackVariableCoordinateRegistry8616()
    return registry if isinstance(registry, StackVariableCoordinateRegistry8616) else StackVariableCoordinateRegistry8616()


def reset_stack_variable_coordinate_registry_8616(codegen: object) -> None:
    """Reset projections before replaying exact stack materialization."""
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616()
    )


def record_stack_variable_coordinate_projection_8616(
    codegen: object,
    *,
    variable: SimStackVariable,
    cvar: object,
    bp_offset: int,
    entry_sp_offset: int,
    size: int,
    display_name: str | None = None,
) -> StackVariableCoordinateProjection8616:
    """Record one exact projection, replacing prior data for that variable."""
    if size <= 0:
        raise ValueError("stack coordinate projection size must be positive")
    projection = StackVariableCoordinateProjection8616(
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=entry_sp_offset,
        size=size,
        display_name=(
            display_name
            if isinstance(display_name, str) and display_name
            else variable.name or ""
        ),
    )
    registry = stack_variable_coordinate_registry_8616(codegen)
    retained = tuple(
        item
        for item in registry.projections
        if item.variable is not variable
        and not (item.bp_offset == bp_offset and item.size == size)
    )
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616((*retained, projection))
    )
    return projection


def publish_selected_stack_cvar_projection_8616(
    codegen: object,
    cvar: object,
    *,
    bp_offset: int,
    size: int,
) -> StackVariableCoordinateProjection8616 | None:
    """Publish the coordinate identity of one already-selected stack C variable."""
    try:
        variable = cast(_CVariableBoundary8616, cvar).variable
    except AttributeError:
        return None
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != "bp"
        or not isinstance(variable.offset, int)
        or not isinstance(variable.size, int)
        or variable.size != size
    ):
        return None
    return record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=variable.offset,
        size=size,
        display_name=variable.name,
    )


def machine_bp_offset_for_stack_variable_8616(
    codegen: object,
    variable: SimStackVariable,
) -> int | None:
    """Return the machine-BP offset across original and cloned AST variables."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_variable(variable)
    if projection is not None:
        return projection.bp_offset
    if isinstance(variable.offset, int) and isinstance(variable.size, int):
        projection = registry.for_entry_sp_range(variable.offset, variable.size)
        if projection is not None:
            return projection.bp_offset
        projection = registry.containing_entry_sp_range(variable.offset, variable.size)
        if projection is not None:
            return projection.bp_offset + variable.offset - projection.entry_sp_offset
    return variable.offset if isinstance(variable.offset, int) else None


def stack_cvar_for_machine_bp_range_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> object | None:
    """Return the canonical CVariable for one exact projected BP range."""
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(
        bp_offset,
        size,
    )
    return projection.cvar if projection is not None else None


__all__ = [
    "StackVariableCoordinateProjection8616",
    "StackVariableCoordinateRegistry8616",
    "machine_bp_offset_for_stack_variable_8616",
    "publish_selected_stack_cvar_projection_8616",
    "record_stack_variable_coordinate_projection_8616",
    "reset_stack_variable_coordinate_registry_8616",
    "stack_cvar_for_machine_bp_range_8616",
    "stack_variable_coordinate_registry_8616",
]
