"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

_LINEAR_TEMP_NAME_RE = re.compile(r"(?:v\d+|vvar_\d+)")


class _CFunctionLike(Protocol):
    """C function shape needed by local declaration pruning."""

    statements: object
    variables_in_use: object
    unified_local_vars: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by local declaration pruning."""

    cfunc: _CFunctionLike | None


class _AliasStorageLike(Protocol):
    """Alias-storage summary shape used by local declaration pruning."""

    identity: tuple[object, ...] | None


def _is_linear_temp_name(name: str | None) -> bool:
    return isinstance(name, str) and _LINEAR_TEMP_NAME_RE.fullmatch(name) is not None


def _prune_unused_linear_register_declarations(
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> bool:
    def _impl() -> bool:
        cfunc = codegen.cfunc
        if cfunc is None:
            return False

        used_variables: set[int] = set()
        for node in iter_c_nodes_deep(cfunc.statements):
            if not isinstance(node, structured_c.CVariable):
                continue
            # dynamic codegen boundary: structured C variable nodes come from angr.
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
            # dynamic codegen boundary: unified variables are optional angr codegen fields.
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))

        changed = False

        variables_in_use = cfunc.variables_in_use
        if isinstance(variables_in_use, dict):
            for variable in list(variables_in_use):
                if not isinstance(variable, SimRegisterVariable):
                    continue
                # dynamic codegen boundary: SimVariable names are supplied by angr.
                if not _is_linear_temp_name(getattr(variable, "name", None)):
                    continue
                if id(variable) in used_variables:
                    continue
                del variables_in_use[variable]
                changed = True

        unified_locals = cfunc.unified_local_vars
        if isinstance(unified_locals, dict):
            for variable in list(unified_locals):
                if not isinstance(variable, SimRegisterVariable):
                    continue
                # dynamic codegen boundary: SimVariable names are supplied by angr.
                if not _is_linear_temp_name(getattr(variable, "name", None)):
                    continue
                entries = unified_locals[variable]
                # dynamic codegen boundary: CVariable entries are supplied by angr.
                if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                    continue
                del unified_locals[variable]
                changed = True

        return changed

    return _impl()


def _prune_unused_local_declarations(
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    def _impl() -> bool:
        cfunc = codegen.cfunc
        if cfunc is None:
            return False

        used_variables: set[int] = set()
        used_storage_identities: set[tuple[object, ...]] = set()
        for node in iter_c_nodes_deep(cfunc.statements):
            if not isinstance(node, structured_c.CVariable):
                continue
            # dynamic codegen boundary: structured C variable nodes come from angr.
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
            # dynamic codegen boundary: unified variables are optional angr codegen fields.
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))
            storage_identity = describe_alias_storage(node).identity
            if storage_identity is not None:
                used_storage_identities.add(storage_identity)

        changed = False

        variables_in_use = cfunc.variables_in_use
        if isinstance(variables_in_use, dict):
            for variable in list(variables_in_use):
                if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                    continue
                if id(variable) in used_variables:
                    continue
                cvar = variables_in_use[variable]
                if describe_alias_storage(cvar).identity in used_storage_identities:
                    continue
                del variables_in_use[variable]
                changed = True

        unified_locals = cfunc.unified_local_vars
        if isinstance(unified_locals, dict):
            for variable in list(unified_locals):
                if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                    continue
                if id(variable) in used_variables:
                    continue
                entries = unified_locals[variable]
                if any(
                    describe_alias_storage(cvariable).identity in used_storage_identities
                    for cvariable, _vartype in entries
                ):
                    continue
                del unified_locals[variable]
                changed = True

        return changed

    return _impl()
