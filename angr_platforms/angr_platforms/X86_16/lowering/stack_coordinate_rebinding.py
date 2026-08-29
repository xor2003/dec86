"""Rebind stack-coordinate projections after C AST snapshot restoration.

Layer: Types/Lowering.
Responsibility: reconcile the machine-BP/entry-SP registry with live angr
``CVariable`` objects after validation rollback deep-copies the C AST.
Consumes only typed coordinate projections and structured AST identity. It
does not infer new stack storage or inspect rendered text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .stack_variable_coordinates import (
    StackVariableCoordinateProjection8616,
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    reset_stack_variable_coordinate_registry_8616,
    stack_variable_coordinate_registry_8616,
)


class StackCoordinateRebindRefusal8616(StrEnum):
    """Reason one live AST projection could not be selected safely."""

    AMBIGUOUS_NAME = "ambiguous_name"


@dataclass(frozen=True, slots=True)
class StackCoordinateRebindReport8616:
    """Closed evidence loop for one restored coordinate registry."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    refusals: tuple[StackCoordinateRebindRefusal8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return classified projections that were not rebound."""
        return self.classified_fact_count - self.materialized_count


def _projection_idents_8616(
    projection: StackVariableCoordinateProjection8616,
) -> frozenset[int | str]:
    """Return durable non-empty angr identifiers from one projection."""
    return frozenset(
        variable.ident
        for variable in (projection.variable, *projection.equivalent_variables)
        if isinstance(variable.ident, (int, str)) and variable.ident != ""
    )


def _numeric_projection_candidates_8616(
    projection: StackVariableCoordinateProjection8616,
    cvars: tuple[structured_c.CVariable, ...],
) -> tuple[structured_c.CVariable, ...]:
    """Return live C variables in the projection's entry-SP byte range."""
    return tuple(
        cvar
        for cvar in cvars
        if isinstance(cvar.variable, SimStackVariable)
        and cvar.variable.offset == projection.entry_sp_offset
        and cvar.variable.size == projection.size
    )


def _live_projection_cvars_8616(
    projection: StackVariableCoordinateProjection8616,
    cvars: tuple[structured_c.CVariable, ...],
) -> tuple[structured_c.CVariable, ...]:
    """Select exact restored identities, falling back to one unique name."""
    candidates = _numeric_projection_candidates_8616(projection, cvars)
    idents = _projection_idents_8616(projection)
    identified = tuple(
        cvar
        for cvar in candidates
        if isinstance(cvar.variable, SimStackVariable)
        and cvar.variable.ident in idents
    )
    if identified:
        return identified
    if not projection.display_name:
        return ()
    named = tuple(
        cvar
        for cvar in candidates
        if isinstance(cvar.variable, SimStackVariable)
        and cvar.variable.name == projection.display_name
    )
    named_variable_ids = {id(cvar.variable) for cvar in named}
    return named if len(named_variable_ids) == 1 else ()


def _retain_projection_8616(
    codegen: object,
    projection: StackVariableCoordinateProjection8616,
) -> None:
    """Retain an unused projection when no live AST identity is present."""
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projection.variable,
        cvar=projection.cvar,
        bp_offset=projection.bp_offset,
        entry_sp_offset=projection.entry_sp_offset,
        size=projection.size,
        display_name=projection.display_name,
    )
    for variable in projection.equivalent_variables:
        record_stack_variable_coordinate_alias_8616(
            codegen,
            bp_offset=projection.bp_offset,
            size=projection.size,
            variable=variable,
        )


def rebind_restored_stack_coordinate_registry_8616(
    codegen: object,
    root: object,
) -> StackCoordinateRebindReport8616:
    """Rebind registry entries to exact C variables in a restored AST."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    cvars = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CVariable)
    )
    normalized = 0
    classified = 0
    materialized = 0
    refusals: list[StackCoordinateRebindRefusal8616] = []
    reset_stack_variable_coordinate_registry_8616(codegen)
    for projection in registry.projections:
        numeric_candidates = _numeric_projection_candidates_8616(projection, cvars)
        if numeric_candidates:
            normalized += 1
        live_cvars = _live_projection_cvars_8616(projection, cvars)
        if not live_cvars:
            if numeric_candidates and not _projection_idents_8616(projection):
                classified += 1
                refusals.append(StackCoordinateRebindRefusal8616.AMBIGUOUS_NAME)
            _retain_projection_8616(codegen, projection)
            continue
        classified += 1
        selected = live_cvars[0]
        variable = selected.variable
        if not isinstance(variable, SimStackVariable):
            _retain_projection_8616(codegen, projection)
            continue
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=selected,
            bp_offset=projection.bp_offset,
            entry_sp_offset=projection.entry_sp_offset,
            size=projection.size,
            display_name=projection.display_name or variable.name,
        )
        for cvar in live_cvars[1:]:
            alias = cvar.variable
            if isinstance(alias, SimStackVariable) and alias is not variable:
                record_stack_variable_coordinate_alias_8616(
                    codegen,
                    bp_offset=projection.bp_offset,
                    size=projection.size,
                    variable=alias,
                )
        materialized += 1
    return StackCoordinateRebindReport8616(
        raw_fact_count=len(registry.projections),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        refusals=tuple(refusals),
    )


__all__ = [
    "StackCoordinateRebindRefusal8616",
    "StackCoordinateRebindReport8616",
    "rebind_restored_stack_coordinate_registry_8616",
]
