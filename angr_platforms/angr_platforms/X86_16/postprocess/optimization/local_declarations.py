"""Layer: Rewrite/Postprocess cleanup.

Responsibility: canonicalize equivalent declarations for already-proven local storage.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Consumes already-proven stack identity and type surfaces. This module may remove only
declaration duplicates with identical BP-relative storage, name, size, and type.
It must not merge expressions, infer alias/type facts, or repair rendered C text.
"""

from __future__ import annotations

import os
import sys
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable


class _CFunctionLike(Protocol):
    """Third-party C function fields that own emitted local declarations."""

    variables_in_use: object
    unified_local_vars: object


class _CodegenLike(Protocol):
    """Third-party structured-codegen surface used by declaration cleanup."""

    cfunc: _CFunctionLike | None


def _stack_declaration_identity(
    variable: object,
    cvar: object,
) -> tuple[object, ...] | None:
    """Return exact physical and emitted-name identity for one stack declaration."""
    if not isinstance(variable, SimStackVariable):
        return None
    if not isinstance(cvar, structured_c.CVariable):
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
        return None
    return (variable.base, variable.offset, variable.size, cvar.name)


def _unified_stack_declaration_identity(variable: object) -> tuple[object, ...] | None:
    """Return exact physical identity for one named unified stack declaration."""
    if not isinstance(variable, SimStackVariable):
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
        return None
    if not isinstance(variable.name, str) or not variable.name:
        return None
    return (variable.base, variable.offset, variable.size, variable.name)


def _unified_declaration_types(entries: object) -> frozenset[object] | None:
    """Return the complete declared type set or refuse malformed angr entries."""
    if not isinstance(entries, (list, set, tuple)):
        return None
    types: list[object] = []
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 2:
            return None
        types.append(entry[1])
    try:
        return frozenset(types)
    except TypeError:
        return None


def dedupe_equivalent_stack_local_declarations_8616(codegen: _CodegenLike) -> bool:
    """Remove only exact duplicate stack declarations with equivalent C types."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    debug = os.environ.get("INERTIA_DEBUG_LOCAL_DECLARATIONS") == "1"
    changed = False
    variables_in_use = cfunc.variables_in_use
    if isinstance(variables_in_use, dict):
        canonical_by_identity: dict[tuple[object, ...], structured_c.CVariable] = {}
        for variable, cvar in tuple(variables_in_use.items()):
            identity = _stack_declaration_identity(variable, cvar)
            if identity is None:
                continue
            if debug:
                print(
                    "[local-declaration] "
                    f"surface=variables_in_use identity={identity!r} type={cvar.variable_type!r} "
                    f"variable={variable!r} unified={cvar.unified_variable!r}",
                    file=sys.stderr,
                    flush=True,
                )
            canonical = canonical_by_identity.get(identity)
            if canonical is None:
                canonical_by_identity[identity] = cvar
                continue
            if cvar.variable_type != canonical.variable_type:
                continue
            del variables_in_use[variable]
            changed = True

    unified_local_vars = cfunc.unified_local_vars
    if isinstance(unified_local_vars, dict):
        canonical_unified: dict[tuple[object, ...], frozenset[object]] = {}
        for variable, entries in tuple(unified_local_vars.items()):
            identity = _unified_stack_declaration_identity(variable)
            declared_types = _unified_declaration_types(entries)
            if identity is None or declared_types is None:
                continue
            if debug:
                print(
                    "[local-declaration] "
                    f"surface=unified_local_vars identity={identity!r} types={declared_types!r} "
                    f"variable={variable!r}",
                    file=sys.stderr,
                    flush=True,
                )
            canonical_types = canonical_unified.get(identity)
            if canonical_types is None:
                canonical_unified[identity] = declared_types
                continue
            if declared_types != canonical_types:
                continue
            del unified_local_vars[variable]
            changed = True
    return changed


__all__ = ["dedupe_equivalent_stack_local_declarations_8616"]
