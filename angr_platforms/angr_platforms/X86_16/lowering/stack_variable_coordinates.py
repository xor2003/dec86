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

from .stack_storage_evidence import (
    alias_excludes_stack_range_8616,
    alias_proves_stack_range_8616,
    proven_bp_entry_sp_delta_8616,
    typed_frame_excludes_stack_range_8616,
)


@dataclass(frozen=True, slots=True)
class StackVariableCoordinateProjection8616:
    """One exact machine-BP to angr entry-SP variable projection."""

    variable: SimStackVariable
    cvar: object
    bp_offset: int
    entry_sp_offset: int
    size: int
    display_name: str = ""
    equivalent_variables: tuple[SimStackVariable, ...] = ()


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
            (
                projection
                for projection in self.projections
                if projection.variable is variable
                or any(alias is variable for alias in projection.equivalent_variables)
            ),
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

    def containing_bp_range(
        self,
        bp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projected owner containing one machine-BP range."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.bp_offset <= bp_offset
            and projection.bp_offset + projection.size >= bp_offset + size
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

    def for_equivalent_entry_sp_variable(
        self,
        variable: SimStackVariable,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return a clone projection only when angr identity also agrees.

        A raw machine-BP variable can have the same numeric offset as another
        variable's projected entry-SP coordinate. Range equality alone cannot
        distinguish those domains, so an absent or different identifier must
        refuse clone recovery.
        """
        if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
            return None
        ident = variable.ident
        if not isinstance(ident, str) or not ident:
            return None
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset == variable.offset
            and projection.size == variable.size
            and any(
                candidate.ident == ident
                for candidate in (projection.variable, *projection.equivalent_variables)
            )
        )
        return matches[0] if len(matches) == 1 else None

    def for_named_entry_sp_variable(
        self,
        variable: SimStackVariable,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique durable-name projection for an AST snapshot clone."""
        if (
            not isinstance(variable.offset, int)
            or not isinstance(variable.size, int)
            or not isinstance(variable.name, str)
            or not variable.name
        ):
            return None
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset == variable.offset
            and projection.size == variable.size
            and projection.display_name == variable.name
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


def record_stack_variable_coordinate_alias_8616(
    codegen: object,
    *,
    bp_offset: int,
    size: int,
    variable: SimStackVariable,
) -> StackVariableCoordinateProjection8616 | None:
    """Attach one Lowering-reconciled angr view to a canonical projection."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_bp_range(bp_offset, size)
    if projection is None:
        return None
    if projection.variable is variable or any(
        alias is variable for alias in projection.equivalent_variables
    ):
        return projection
    rebound = StackVariableCoordinateProjection8616(
        variable=projection.variable,
        cvar=projection.cvar,
        bp_offset=projection.bp_offset,
        entry_sp_offset=projection.entry_sp_offset,
        size=projection.size,
        display_name=projection.display_name,
        equivalent_variables=(*projection.equivalent_variables, variable),
    )
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616(
            tuple(rebound if item is projection else item for item in registry.projections)
        )
    )
    return rebound


def bind_stack_variable_coordinate_cvar_8616(
    codegen: object,
    *,
    bp_offset: int,
    size: int,
    cvar: object,
    display_name: str | None = None,
) -> StackVariableCoordinateProjection8616 | None:
    """Bind an existing projection to its canonical C interface variable.

    The projection variable retains angr's entry-SP coordinate. The C variable
    may instead be the canonical machine-BP function argument selected from the
    same Alias identity; consumers must resolve through this registry.
    """
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_bp_range(bp_offset, size)
    if projection is None:
        return None
    rebound = StackVariableCoordinateProjection8616(
        variable=projection.variable,
        cvar=cvar,
        bp_offset=projection.bp_offset,
        entry_sp_offset=projection.entry_sp_offset,
        size=projection.size,
        display_name=display_name or projection.display_name,
        equivalent_variables=projection.equivalent_variables,
    )
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616(
            tuple(rebound if item is projection else item for item in registry.projections)
        )
    )
    return rebound


def publish_selected_stack_cvar_projection_8616(
    codegen: object,
    cvar: object,
    *,
    bp_offset: int,
    size: int,
    entry_sp_offset: int | None = None,
) -> StackVariableCoordinateProjection8616 | None:
    """Publish one selected C variable with an optional proven entry-SP coordinate."""
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
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(
        bp_offset,
        size,
    )
    if (
        projection is not None
        and isinstance(entry_sp_offset, int)
        and projection.entry_sp_offset != entry_sp_offset
    ):
        return record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=size,
            display_name=variable.name,
        )
    if projection is not None:
        record_stack_variable_coordinate_alias_8616(
            codegen,
            bp_offset=bp_offset,
            size=size,
            variable=variable,
        )
        return bind_stack_variable_coordinate_cvar_8616(
            codegen,
            bp_offset=bp_offset,
            size=size,
            cvar=cvar,
            display_name=variable.name,
        )
    return record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=(
            entry_sp_offset if isinstance(entry_sp_offset, int) else variable.offset
        ),
        size=size,
        display_name=variable.name,
    )


def machine_bp_offset_for_stack_variable_8616(
    codegen: object,
    variable: SimStackVariable,
) -> int | None:
    """Return machine-BP offset, refusing unresolved coordinate collisions."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_variable(variable)
    if projection is not None:
        return projection.bp_offset
    if isinstance(variable.offset, int) and isinstance(variable.size, int):
        projection = registry.for_equivalent_entry_sp_variable(variable)
        if projection is not None:
            return projection.bp_offset
        named_projection = registry.for_named_entry_sp_variable(variable)
        raw_projection = registry.for_bp_range(variable.offset, variable.size)
        if (
            named_projection is not None
            and (
                raw_projection is None
                or raw_projection is named_projection
                or raw_projection.display_name != variable.name
            )
        ):
            return named_projection.bp_offset
        projection = registry.for_entry_sp_range(variable.offset, variable.size)
        if (
            projection is not None
            and registry.for_bp_range(variable.offset, variable.size) is None
            and (
                alias_excludes_stack_range_8616(
                    codegen,
                    variable.offset,
                    variable.size,
                )
                or typed_frame_excludes_stack_range_8616(
                    codegen,
                    variable.offset,
                    variable.size,
                )
            )
        ):
            return projection.bp_offset
        if projection is not None:
            return (
                variable.offset
                if raw_projection is None or raw_projection is projection
                else None
            )
        projection = registry.containing_entry_sp_range(variable.offset, variable.size)
        if projection is not None:
            return projection.bp_offset + variable.offset - projection.entry_sp_offset
        delta = proven_bp_entry_sp_delta_8616(codegen)
        if isinstance(delta, int):
            projected_bp_offset = variable.offset - delta
            if alias_proves_stack_range_8616(
                codegen,
                projected_bp_offset,
                variable.size,
            ) and not alias_proves_stack_range_8616(
                codegen,
                variable.offset,
                variable.size,
            ):
                return projected_bp_offset
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
    "bind_stack_variable_coordinate_cvar_8616",
    "machine_bp_offset_for_stack_variable_8616",
    "publish_selected_stack_cvar_projection_8616",
    "record_stack_variable_coordinate_alias_8616",
    "record_stack_variable_coordinate_projection_8616",
    "reset_stack_variable_coordinate_registry_8616",
    "stack_cvar_for_machine_bp_range_8616",
    "stack_variable_coordinate_registry_8616",
]
