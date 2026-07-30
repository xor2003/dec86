"""Canonicalize positive-BP argument storage after typed pointer lowering.

Layer: Types/Lowering.
Responsibility: join body stack variables to canonical argument variables using
alias identities, then keep angr declaration maps consistent with that join.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not infer arguments or pointer classes; it only consumes
prototype and alias facts already materialized by earlier pipeline owners.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..alias.alias_model import _stack_slot_identity_for_variable
from ..c_ast_utils import _replace_c_children_8616


class _ArgumentIdentityCFunction8616(Protocol):
    """Dynamic angr C-function fields consumed by argument identity lowering."""

    arg_list: Sequence[object] | None
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _ArgumentIdentityCodegen8616(Protocol):
    """Dynamic angr codegen fields used by argument identity lowering."""

    cfunc: _ArgumentIdentityCFunction8616 | None
    _inertia_arg_stack_identity_stats_8616: StackArgumentIdentityStats8616
    _inertia_arg_stack_identity_unified_8616: int
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_return_selector_materialized_8616: bool


@dataclass(frozen=True, slots=True)
class StackArgumentIdentityStats8616:
    """Closed evidence counts for one argument-storage identity pass."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _positive_stack_variable_8616(node: object) -> SimStackVariable | None:
    """Return a positive-BP stack variable exposed by one structured-C node."""
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if (
        not isinstance(variable, SimStackVariable)
        or not isinstance(variable.offset, int)
        or variable.offset <= 0
    ):
        return None
    return variable


def _clone_argument_reference_8616(
    argument: structured_c.CVariable,
) -> structured_c.CVariable:
    """Clone one canonical argument reference for insertion into the C tree."""
    clone = structured_c.CVariable(
        argument.variable,
        variable_type=argument.variable_type,
        codegen=argument.codegen,
    )
    clone.tags = dict(argument.tags or {})
    return clone


def unify_positive_bp_argument_identity_8616(
    codegen: object,
) -> bool:
    """Join body references to exact canonical positive-BP argument storage."""
    typed_codegen = cast(_ArgumentIdentityCodegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return False
    if cfunc is None:
        return False
    try:
        if typed_codegen._inertia_return_selector_materialized_8616:
            return False
    except AttributeError:
        pass

    arguments_by_identity: dict[object, list[structured_c.CVariable]] = {}
    for candidate in tuple(cfunc.arg_list or ()):
        if not isinstance(candidate, structured_c.CVariable):
            continue
        variable = _positive_stack_variable_8616(candidate)
        if variable is None:
            continue
        identity = _stack_slot_identity_for_variable(variable)
        if identity is not None:
            arguments_by_identity.setdefault(identity, []).append(candidate)
    canonical_by_identity = {
        identity: arguments[0]
        for identity, arguments in arguments_by_identity.items()
        if len(arguments) == 1
    }
    if not canonical_by_identity:
        typed_codegen._inertia_arg_stack_identity_stats_8616 = (
            StackArgumentIdentityStats8616()
        )
        return False

    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    changed = False

    def transform(node: object) -> object:
        nonlocal raw_count, normalized_count, classified_count
        nonlocal materialized_count, changed
        variable = _positive_stack_variable_8616(node)
        if variable is None:
            return node
        raw_count += 1
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return node
        normalized_count += 1
        argument = canonical_by_identity.get(identity)
        if argument is None:
            return node
        classified_count += 1
        materialized_count += 1
        if variable is argument.variable:
            return node
        changed = True
        return _clone_argument_reference_8616(argument)

    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True

    canonical_variables = {
        argument.variable for argument in canonical_by_identity.values()
    }
    variables_in_use = cfunc.variables_in_use
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            argument = canonical_by_identity.get(identity)
            if argument is None:
                continue
            if variable in canonical_variables:
                if cvar is not argument:
                    variables_in_use[variable] = argument
                    changed = True
                continue
            del variables_in_use[variable]
            changed = True

    unified_local_vars = cfunc.unified_local_vars
    if isinstance(unified_local_vars, dict):
        for variable in tuple(unified_local_vars):
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity in canonical_by_identity:
                del unified_local_vars[variable]
                changed = True

    failure_count = max(classified_count - materialized_count, 0)
    typed_codegen._inertia_arg_stack_identity_stats_8616 = (
        StackArgumentIdentityStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        )
    )
    if classified_count > 0 and materialized_count == 0:
        raise RuntimeError(
            "argument stack identities were classified but not materialized"
        )
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
        try:
            unified_count = typed_codegen._inertia_arg_stack_identity_unified_8616
        except AttributeError:
            unified_count = 0
        typed_codegen._inertia_arg_stack_identity_unified_8616 = unified_count + 1
    return changed


__all__ = [
    "StackArgumentIdentityStats8616",
    "unify_positive_bp_argument_identity_8616",
]
