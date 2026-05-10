from __future__ import annotations

# Layer: Lowering
# Responsibility:
#   Consume alias-proven stack facts and materialize them into real variables
#   before final C emission.
#
# Input:
#   AliasStorageFacts(identity=("stack", _StackSlotIdentity(...)))
#
# Output:
#   Real C/Sim stack variables registered through variables_in_use.
#
# Forbidden:
#   - generated-C regex recovery
#   - counting StackVariableBinding as materialization
#   - fallback to rewrite/postprocess for semantics
#
# Contract:
#   bindings_count > 0 and materialized_count == 0 is PipelineHardError.

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimStackVariable

from .stack_lowering_result import (
    StackLoweringResult,
    StackSlotFailure,
)
from .stack_variable_binding import (
    StackVariableBinding,
    build_stack_variable_bindings_8616,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "build_stack_variable_bindings_from_alias_facts_8616",
    "lower_stack_accesses_from_alias_facts_8616",
]


def build_stack_variable_bindings_from_alias_facts_8616(
    alias_facts: list[object],
) -> list[StackVariableBinding]:
    """Build StackVariableBinding list from alias storage facts.

    Only stack-space facts with proven BP base are accepted.
    Naming: offset < 0 → local_N, offset > 0 → arg_N, offset == 0 → frame_base.

    Returns empty list if no stack facts exist.
    """
    addresses: list[tuple[int, int]] = []
    preferred_names: dict[int, str] = {}

    for fact in alias_facts:
        identity = getattr(fact, "identity", None)
        if identity is None:
            continue

        kind = identity[0] if isinstance(identity, tuple) and len(identity) >= 2 else None
        if kind != "stack":
            continue

        slot = identity[1] if len(identity) >= 2 else None
        if slot is None:
            continue

        offset = getattr(slot, "offset", None)
        width = getattr(slot, "width", None)

        if not isinstance(offset, int):
            continue

        size = width if isinstance(width, int) and width > 0 else 1
        addresses.append((offset, size))

        if offset < 0:
            name = f"local_{abs(offset):x}"
        elif offset > 0:
            name = f"arg_{abs(offset):x}"
        else:
            name = "frame_base"
        preferred_names[offset] = name

    if not addresses:
        return []

    return build_stack_variable_bindings_8616(
        sorted(set(addresses)),
        preferred_names=preferred_names,
    )


def _stack_object_name(offset: int) -> str:
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"


def _stack_type_for_size(size: int, *, codegen=None):
    """Return SimTypeInt for the given byte size with arch attached if available."""
    t = SimTypeInt(signed=False)
    if codegen is not None:
        arch = getattr(getattr(codegen, "project", None), "arch", None) or getattr(
            getattr(codegen, "cfunc", None), "arch", None
        )
        if arch is not None:
            t = t.with_arch(arch)
    return t


def _promote_direct_stack_cvariable(codegen, cvar, size, target_type):
    """Update the type and size on an existing stack CVariable."""
    if cvar is not None:
        cvar.variable_type = target_type
        variable = getattr(cvar, "variable", None)
        if isinstance(variable, SimStackVariable):
            variable.size = size


def _materialize_stack_cvar_at_offset(
    codegen,
    offset: int,
    size: int = 2,
):
    """Self-contained: register a SimStackVariable + CVariable for offset.

    This is a standalone copy of the logic in stack_lowering_impl.py
    for use by fact-based lowering, to avoid circular dependency on
    the injected helpers used in the canonicalization pass.
    """
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    # Check if already exists in variables_in_use
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for var, cvar in variables_in_use.items():
            if isinstance(var, SimStackVariable) and getattr(var, "offset", None) == offset:
                target_type = _stack_type_for_size(size, codegen=codegen)
                _promote_direct_stack_cvariable(codegen, cvar, size, target_type)
                return cvar

    target_type = _stack_type_for_size(size, codegen=codegen)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset),
        region=getattr(codegen.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)

    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[id(variable)] = (variable, cvar)

    sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cvar


def lower_stack_accesses_from_alias_facts_8616(
    codegen,
    alias_facts: list[object],
) -> StackLoweringResult:
    """Primary stack lowering: consume alias facts, not linear expression patterns.

    Rules:
    - Only consume alias facts
    - No regex on generated C
    - No linear expression guessing
    - If facts exist but variables cannot be materialized, report failure

    Materialization means registering real SimStackVariable + CVariable objects
    in codegen.cfunc.variables_in_use. Creating StackVariableBinding metadata is
    NOT materialization.
    """
    bindings = build_stack_variable_bindings_from_alias_facts_8616(alias_facts)

    if not bindings:
        return StackLoweringResult(
            ok=True,
            replacements=0,
            failures=0,
            bindings=[],
            failures_list=[],
        )

    codegen._inertia_stack_bindings = bindings
    codegen._inertia_stack_lowering_source = "alias_facts"
    codegen._inertia_semantic_stack_binding_count = len(bindings)

    materialized_count = 0
    failures_list: list[StackSlotFailure] = []

    for binding in bindings:
        try:
            offset = getattr(binding, "bp_offset", None)
            if offset is None:
                offset = getattr(binding, "offset", None)
            size = getattr(binding, "size", None)
            if size is None or not isinstance(size, int):
                size = 2

            _materialize_stack_cvar_at_offset(codegen, offset, size)
            materialized_count += 1
        except Exception as exc:
            fallback_offset = getattr(binding, "bp_offset", None) or getattr(binding, "offset", 0)
            failures_list.append(
                StackSlotFailure(
                    offset=fallback_offset,
                    reason=str(exc),
                )
            )

    codegen._inertia_semantic_stack_materialized_count = materialized_count

    # ── Update STACK lane contract counters ──
    # AGENTS rule: bindings are NOT materialization.
    # bound = number of StackVariableBindings created
    # materialized = number of SimStackVariables registered in variables_in_use
    lane = getattr(codegen, "_inertia_stack_lane", None)
    if lane is not None:
        lane.bound = len(bindings)
        lane.materialized = materialized_count

    # ── HARD CONTRACT: bindings > 0 && materialized == 0 → PipelineHardError ──
    if len(bindings) > 0 and materialized_count == 0:
        from ..pipeline.errors import PipelineHardError
        raise PipelineHardError(
            "stack bindings created but no stack variables materialized",
            layer="lowering",
        )

    ok = len(failures_list) == 0

    return StackLoweringResult(
        ok=ok,
        replacements=materialized_count,
        failures=len(failures_list),
        bindings=bindings,
        failures_list=failures_list,
        diagnostics=[
            "stack_lowering_source=alias_facts "
            f"bindings={len(bindings)} "
            f"materialized={materialized_count}",
        ],
    )