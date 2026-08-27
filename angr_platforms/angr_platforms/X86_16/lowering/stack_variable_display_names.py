"""Project proven stack storage names onto regenerated C-AST variables.

Layer: Types/Lowering.
Responsibility: consume the authoritative BP/entry-SP coordinate registry and
replay only its display-name projection onto exact angr stack ranges. This
module does not discover storage identity or infer names from rendered text.
Dynamic boundary: angr codegen and C-AST objects are third-party contracts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .stack_variable_coordinates import (
    StackVariableCoordinateRegistry8616,
    stack_variable_coordinate_registry_8616,
)

_GENERATED_STACK_NAME_PREFIXES_8616 = ("arg_", "local_", "s_", "stack_", "var_")


class _CVariableBoundary8616(Protocol):
    """Third-party CVariable fields used to synchronize projected names."""

    variable: object
    unified_variable: object | None


class _CFunctionBoundary8616(Protocol):
    """Third-party CFunction surfaces containing stack projections."""

    variables_in_use: object
    unified_local_vars: object
    statements: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen field exposing the rendered C function."""

    cfunc: _CFunctionBoundary8616


def generated_stack_variable_name_8616(name: object) -> bool:
    """Return whether a stack name is a generated, replaceable placeholder."""
    return (
        not isinstance(name, str)
        or not name
        or name.startswith(_GENERATED_STACK_NAME_PREFIXES_8616)
        or (name.startswith("v") and name[1:].isdigit())
    )


def _rename_generated_stack_variable_8616(variable: object, name: str) -> None:
    """Rename one exact stack projection without overriding evidence names."""
    if isinstance(variable, SimStackVariable) and generated_stack_variable_name_8616(variable.name):
        variable.name = name


def _rename_projected_cvariable_8616(cvar: object, name: str) -> None:
    """Rename the physical and unified variables referenced by one CVariable."""
    boundary = cast(_CVariableBoundary8616, cvar)
    try:
        variable = boundary.variable
        unified_variable = boundary.unified_variable
    except AttributeError:
        return
    _rename_generated_stack_variable_8616(variable, name)
    _rename_generated_stack_variable_8616(unified_variable, name)


def _matches_entry_sp_range_8616(variable: object, entry_sp_offset: int, size: int) -> bool:
    """Return whether a variable is the exact projected storage range."""
    return (
        isinstance(variable, SimStackVariable)
        and variable.offset == entry_sp_offset
        and variable.size == size
    )


def apply_stack_variable_projection_name_8616(
    codegen: object,
    *,
    cvar: object,
    entry_sp_offset: int,
    size: int,
    name: str,
) -> None:
    """Synchronize one proven display name across exact C-AST projections."""
    _rename_projected_cvariable_8616(cvar, name)
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return
    if isinstance(cfunc.variables_in_use, dict):
        for variable, candidate in cfunc.variables_in_use.items():
            if _matches_entry_sp_range_8616(variable, entry_sp_offset, size):
                _rename_generated_stack_variable_8616(variable, name)
                _rename_projected_cvariable_8616(candidate, name)
    if isinstance(cfunc.unified_local_vars, dict):
        for variable, entries in cfunc.unified_local_vars.items():
            if not _matches_entry_sp_range_8616(variable, entry_sp_offset, size):
                continue
            _rename_generated_stack_variable_8616(variable, name)
            if isinstance(entries, (list, set, tuple)):
                for entry in entries:
                    if isinstance(entry, tuple) and entry:
                        _rename_projected_cvariable_8616(entry[0], name)


def _projected_display_name_8616(
    registry: StackVariableCoordinateRegistry8616,
    target_names: frozenset[str],
    variable: SimStackVariable,
) -> str | None:
    """Select a durable name for one exact or colliding stack projection."""
    projection = registry.for_entry_sp_range(variable.offset, variable.size)
    if projection is not None:
        return projection.display_name or None
    if variable.name in target_names and generated_stack_variable_name_8616(variable.name):
        sign = "m" if variable.offset < 0 else "p"
        return f"stack_sp_{sign}{abs(variable.offset):x}_{variable.size}"
    return None


def _reapply_cvariable_name_8616(
    registry: StackVariableCoordinateRegistry8616,
    target_names: frozenset[str],
    cvar: CVariable,
) -> bool:
    """Replay one coordinate-backed name onto an angr CVariable."""
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable):
        return False
    name = _projected_display_name_8616(registry, target_names, variable)
    if name is None:
        return False
    previous_name = variable.name
    _rename_projected_cvariable_8616(cvar, name)
    return bool(variable.name != previous_name)


def reapply_stack_variable_projection_names_8616(codegen: object) -> bool:
    """Restore durable projected names across maps and regenerated AST clones."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    target_names = frozenset(item.display_name for item in registry.projections if item.display_name)
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return False
    changed = False
    if isinstance(cfunc.variables_in_use, dict):
        for cvar in cfunc.variables_in_use.values():
            if isinstance(cvar, CVariable):
                changed = _reapply_cvariable_name_8616(registry, target_names, cvar) or changed
    try:
        statements = cfunc.statements
    except AttributeError:
        statements = None
    for node in _iter_c_nodes_deep_8616(statements):
        if isinstance(node, CVariable):
            changed = _reapply_cvariable_name_8616(registry, target_names, node) or changed
    return changed


__all__ = [
    "apply_stack_variable_projection_name_8616",
    "generated_stack_variable_name_8616",
    "reapply_stack_variable_projection_names_8616",
]
