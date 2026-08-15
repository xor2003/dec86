"""Materialize binary-derived positive-BP storage as function arguments.

Layer: Types/Lowering.
Responsibility: convert structured angr BP+4-and-above stack variables into one
canonical near-call argument interface before argument-identity unification.
Consumes alias, widening, and typed facts from binary-derived C-AST storage.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol, Sequence, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeShort
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..calling_convention_compat import collect_bp_word_stack_access_offsets_8616
from .callee_argument_count_evidence import CalleeArgumentCountVerdict8616
from .callee_argument_interface import (
    CalleeArgumentInterfaceDecision8616,
    reconcile_callee_argument_interface_8616,
)
from .stack_c_ast_matching import _stack_variable_read_offsets_8616


class _PositiveBpCFunction8616(Protocol):
    """angr C-function fields consumed at the dynamic Lowering boundary."""

    addr: int
    arg_list: Sequence[object] | None
    functy: object
    prototype: object
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _PositiveBpCodegen8616(Protocol):
    """angr codegen fields consumed and updated by this Lowering pass."""

    cfunc: _PositiveBpCFunction8616 | None
    _inertia_authoritative_zero_arg_prototype_8616: bool
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_positive_bp_argument_stats_8616: PositiveBpArgumentStats8616
    _inertia_return_selector_materialized_8616: bool


class _FunctionSurface8616(Protocol):
    """angr function metadata updated with the recovered binary ABI."""

    prototype: object
    is_prototype_guessed: bool


@dataclass(frozen=True, slots=True)
class PositiveBpArgumentStats8616:
    """Closed evidence counts for one positive-BP interface materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _positive_bp_cvar_8616(node: object) -> structured_c.CVariable | None:
    """Return a structured BP argument candidate from a dynamic C-AST node."""
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != "bp"
        or not isinstance(variable.offset, int)
        or variable.offset < 4
    ):
        return None
    return node


def _candidate_width_8616(candidate: structured_c.CVariable) -> int:
    """Return the ABI storage width proven by one stack variable."""
    size = candidate.variable.size
    return max(2, size if isinstance(size, int) and size > 0 else 2)


def _canonical_argument_name_8616(candidate: structured_c.CVariable) -> str:
    """Keep meaningful names and replace local placeholders deterministically."""
    variable = cast(SimStackVariable, candidate.variable)
    name = variable.name or candidate.name
    if isinstance(name, str) and not re.fullmatch(r"(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|local(?:_[0-9a-fA-F]+)?)", name):
        return name
    return f"arg_{variable.offset:x}"


def _function_for_codegen_8616(project: object, address: int) -> _FunctionSurface8616 | None:
    """Resolve an existing angr function through its dynamic project boundary."""
    try:
        project_dynamic = cast(Any, project)
        function = project_dynamic.kb.functions.function(addr=address, create=False)
    except (AttributeError, KeyError):
        return None
    return cast(_FunctionSurface8616, function) if function is not None else None


def _existing_interface_matches_8616(
    cfunc: _PositiveBpCFunction8616,
    desired: Sequence[structured_c.CVariable],
) -> bool:
    """Return whether angr already owns the exact contiguous BP interface."""
    prototype = cfunc.functy if isinstance(cfunc.functy, SimTypeFunction) else cfunc.prototype
    if not isinstance(prototype, SimTypeFunction):
        return False
    existing = tuple(cfunc.arg_list or ())
    if len(existing) != len(desired) or len(tuple(prototype.args or ())) != len(desired):
        return False
    cursor = 4
    for current, wanted in zip(existing, desired):
        if not isinstance(current, structured_c.CVariable):
            return False
        current_variable = current.variable
        wanted_variable = wanted.variable
        if (
            not isinstance(current_variable, SimStackVariable)
            or not isinstance(wanted_variable, SimStackVariable)
            or current_variable.offset != cursor
            or wanted_variable.offset != cursor
            or not isinstance(current_variable.size, int)
            or current_variable.size <= 0
        ):
            return False
        cursor += max(2, current_variable.size)
    return True


def _portable_word_argument_type_8616(project: object, argument_type: SimType) -> SimType:
    """Keep signedness while spelling a 16-bit integer portably as short."""
    if not isinstance(argument_type, SimTypeInt) or isinstance(argument_type, SimTypeShort):
        return argument_type
    try:
        if argument_type.size != 16:
            return argument_type
    except ValueError:
        return argument_type
    normalized = SimTypeShort(argument_type.signed)
    try:
        project_dynamic = cast(Any, project)
        return cast(SimType, normalized.with_arch(project_dynamic.arch))
    except AttributeError:
        return normalized


def _argument_type_for_proven_stack_width_8616(
    project: object,
    argument_type: SimType,
    *,
    proven_width: int | None,
) -> SimType:
    """Apply an exact decoded stack-access width to one scalar argument type."""
    if proven_width == 2 and isinstance(argument_type, SimTypeChar):
        word_type = SimTypeShort(argument_type.signed)
        try:
            project_dynamic = cast(Any, project)
            return cast(SimType, word_type.with_arch(project_dynamic.arch))
        except AttributeError:
            return word_type
    return _portable_word_argument_type_8616(project, argument_type)


def materialize_positive_bp_arguments_8616(project: object, codegen: object) -> bool:
    """Build one contiguous near-call argument interface from BP stack storage.

    Only exact ``SimStackVariable(base="bp", offset>=4)`` nodes are considered.
    Arguments must form a contiguous ABI layout beginning at BP+4. Contained
    byte/word views are folded into their wider owner; a gap ends recovery.
    """
    typed_codegen = cast(_PositiveBpCodegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return False
    if cfunc is None:
        return False
    # angr and focused codegen adapters may omit optional C-function indexes.
    # Capture that dynamic boundary once; owned lowering state remains explicit.
    try:
        existing_arg_list = tuple(cfunc.arg_list or ())
    except AttributeError:
        existing_arg_list = ()
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = None
    try:
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError:
        unified_local_vars = None
    try:
        if typed_codegen._inertia_authoritative_zero_arg_prototype_8616:
            return False
    except AttributeError:
        pass

    function = _function_for_codegen_8616(project, cfunc.addr)
    word_access_offsets = frozenset(
        collect_bp_word_stack_access_offsets_8616(project, function)
        if function is not None
        else ()
    )
    try:
        if typed_codegen._inertia_return_selector_materialized_8616:
            return False
    except AttributeError:
        pass

    candidates: dict[int, list[structured_c.CVariable]] = {}
    body_variable_ids: set[int] = set()

    def collect(candidate: object, *, body: bool) -> None:
        """Collect one positive-BP candidate without duplicating object identity."""
        cvar = _positive_bp_cvar_8616(candidate)
        if cvar is None:
            return
        variable = cast(SimStackVariable, cvar.variable)
        bucket = candidates.setdefault(variable.offset, [])
        if all(existing is not cvar for existing in bucket):
            bucket.append(cvar)
        if body:
            body_variable_ids.add(id(variable))

    for node in _iter_c_nodes_deep_8616(cfunc.statements):
        collect(node, body=True)
    if isinstance(variables_in_use, dict):
        for cvar in tuple(variables_in_use.values()):
            collect(cvar, body=False)
    for cvar in existing_arg_list:
        collect(cvar, body=False)

    raw_count = sum(len(bucket) for bucket in candidates.values())
    normalized_count = len(candidates)
    read_offsets = _stack_variable_read_offsets_8616(cfunc.statements)
    desired: list[structured_c.CVariable] = []
    desired_names: list[str] = []
    desired_variables: set[SimStackVariable] = set()
    cursor = 4
    for offset in sorted(candidates):
        if offset < cursor:
            continue
        if offset != cursor:
            break
        if offset not in read_offsets:
            break
        bucket = candidates[offset]
        body_bucket = [item for item in bucket if id(item.variable) in body_variable_ids]
        if not body_bucket:
            break
        canonical = max(
            body_bucket,
            key=_candidate_width_8616,
        )
        width = max(_candidate_width_8616(item) for item in body_bucket)
        variable = cast(SimStackVariable, canonical.variable)
        variable.size = width
        name = _canonical_argument_name_8616(canonical)
        variable.name = name
        if not isinstance(canonical.variable_type, SimType):
            canonical.variable_type = SimTypeShort(False)
        desired.append(canonical)
        desired_names.append(name)
        desired_variables.add(variable)
        cursor += width

    candidate_count = len(desired)
    if not desired:
        existing_argument_count = len(existing_arg_list)
        interface_result = reconcile_callee_argument_interface_8616(
            project,
            typed_codegen,
            candidate_count=existing_argument_count,
        )
        typed_codegen._inertia_positive_bp_argument_stats_8616 = PositiveBpArgumentStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
        )
        return bool(interface_result.changed)

    interface_result = reconcile_callee_argument_interface_8616(
        project,
        typed_codegen,
        candidate_count=candidate_count,
    )
    if interface_result.decision is not CalleeArgumentInterfaceDecision8616.ACCEPT:
        typed_codegen._inertia_positive_bp_argument_stats_8616 = PositiveBpArgumentStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=candidate_count,
        )
        return bool(interface_result.changed)

    existing_args = existing_arg_list
    if (
        len(desired) < len(existing_args)
        and interface_result.evidence.verdict is not CalleeArgumentCountVerdict8616.CONSISTENT
    ):
        typed_codegen._inertia_positive_bp_argument_stats_8616 = PositiveBpArgumentStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=len(existing_args) - len(desired),
        )
        return bool(interface_result.changed)

    classified_count = candidate_count

    current_prototype = cfunc.functy if isinstance(cfunc.functy, SimTypeFunction) else cfunc.prototype
    return_type = current_prototype.returnty if isinstance(current_prototype, SimTypeFunction) else SimTypeShort(False)
    variadic = current_prototype.variadic if isinstance(current_prototype, SimTypeFunction) else False
    preserve_existing_types = _existing_interface_matches_8616(cfunc, desired)
    source_types = (
        list(current_prototype.args or ())
        if preserve_existing_types and isinstance(current_prototype, SimTypeFunction)
        else [cast(SimType, candidate.variable_type) for candidate in desired]
    )
    argument_types = [
        _argument_type_for_proven_stack_width_8616(
            project,
            argument_type,
            proven_width=2 if cast(SimStackVariable, candidate.variable).offset in word_access_offsets else None,
        )
        for candidate, argument_type in zip(desired, source_types)
    ]
    for candidate, argument_type in zip(desired, argument_types):
        candidate.variable_type = argument_type
    new_prototype = SimTypeFunction(argument_types, return_type, arg_names=desired_names, variadic=variadic)
    try:
        project_dynamic = cast(Any, project)
        new_prototype = cast(SimTypeFunction, new_prototype.with_arch(project_dynamic.arch))
    except AttributeError:
        pass

    changed = len(existing_args) != len(desired) or any(current is not wanted for current, wanted in zip(existing_args, desired))
    if changed:
        cfunc.arg_list = desired
    if cfunc.functy != new_prototype:
        cfunc.functy = new_prototype
        changed = True
    try:
        if cfunc.prototype != new_prototype:
            cfunc.prototype = new_prototype
            changed = True
    except AttributeError:
        pass

    if function is not None:
        function.prototype = new_prototype
        function.is_prototype_guessed = False

    if isinstance(variables_in_use, dict):
        for variable in tuple(variables_in_use):
            if (
                isinstance(variable, SimStackVariable)
                and variable.offset >= 4
                and variable not in desired_variables
                and id(variable) not in body_variable_ids
            ):
                del variables_in_use[variable]
                changed = True
    if isinstance(unified_local_vars, dict):
        for variable in tuple(unified_local_vars):
            if isinstance(variable, SimStackVariable) and variable in desired_variables:
                del unified_local_vars[variable]
                changed = True

    typed_codegen._inertia_positive_bp_argument_stats_8616 = PositiveBpArgumentStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=len(desired),
    )
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


__all__ = ["PositiveBpArgumentStats8616", "materialize_positive_bp_arguments_8616"]
