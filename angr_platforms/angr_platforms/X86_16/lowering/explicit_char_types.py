"""Materialize explicit C spellings for proven scalar character signedness.

Layer: Types/Lowering.
Responsibility: preserve existing scalar ``SimTypeChar`` signedness when angr
renders typed C declarations. This module does not infer signedness and does
not inspect assembly, source, sidecars, or rendered C text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

angr's ``SimTypeChar.c_repr()`` emits plain ``char`` for both signed and
unsigned instances. On hosts where plain ``char`` is signed, that loses the
already-recovered ``signed=False`` contract and can change byte MUL/DIV
behavior. The lowering below gives scalar character types an explicit C label;
pointee and aggregate element types remain untouched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction

from ..c_ast_utils import _iter_c_nodes_deep_8616

__all__ = [
    "ExplicitScalarCharTypeStats8616",
    "explicit_scalar_char_type_8616",
    "materialize_explicit_scalar_char_types_8616",
]


@dataclass(frozen=True, slots=True)
class ExplicitScalarCharTypeStats8616:
    """Closed evidence counters for explicit scalar character type spelling."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _CFunctionExplicitCharTypes8616(Protocol):
    """Third-party structured C function fields consumed by this lowering."""

    statements: object | None
    variables_in_use: dict[object, structured_c.CVariable]
    unified_local_vars: dict[object, set[tuple[structured_c.CVariable, object]]]
    arg_list: list[structured_c.CVariable]
    functy: SimTypeFunction


class _CodegenExplicitCharTypes8616(Protocol):
    """Dynamic codegen boundary used by explicit character type lowering."""

    cfunc: _CFunctionExplicitCharTypes8616 | None
    _inertia_explicit_scalar_char_type_stats_8616: ExplicitScalarCharTypeStats8616


def explicit_scalar_char_type_8616(type_: object) -> object:
    """Return an explicitly rendered equivalent of one scalar character type."""
    if not isinstance(type_, SimTypeChar) or not isinstance(type_.signed, bool):
        return type_
    label = "signed char" if type_.signed else "unsigned char"
    if type_.label == label:
        return type_
    explicit = SimTypeChar(
        signed=type_.signed,
        label=label,
        qualifier=type_.qualifier,
    )
    if type_._arch is not None:
        explicit = explicit.with_arch(type_._arch)
    return explicit


def materialize_explicit_scalar_char_types_8616(codegen: object) -> bool:
    """Preserve known scalar character signedness in structured C declarations."""
    typed_codegen = cast(_CodegenExplicitCharTypes8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        typed_codegen._inertia_explicit_scalar_char_type_stats_8616 = ExplicitScalarCharTypeStats8616(
            0, 0, 0, 0, 0
        )
        return False

    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    changed = False

    def normalize(type_: object) -> object:
        """Normalize one scalar type slot and update the closed counters."""
        nonlocal raw_count, normalized_count, classified_count, materialized_count, changed
        if not isinstance(type_, SimTypeChar):
            return type_
        raw_count += 1
        if not isinstance(type_.signed, bool):
            return type_
        normalized_count += 1
        classified_count += 1
        explicit = explicit_scalar_char_type_8616(type_)
        if isinstance(explicit, SimTypeChar) and explicit.label in {"signed char", "unsigned char"}:
            materialized_count += 1
        if explicit is not type_:
            changed = True
        return explicit

    cvariables: dict[int, structured_c.CVariable] = {}
    for cvar in cfunc.variables_in_use.values():
        cvariables[id(cvar)] = cvar
    for cvar in cfunc.arg_list:
        cvariables[id(cvar)] = cvar
    if cfunc.statements is not None:
        for node in _iter_c_nodes_deep_8616(cfunc.statements):
            if isinstance(node, structured_c.CVariable):
                cvariables[id(node)] = node
    for cvar in cvariables.values():
        cvar.variable_type = cast(SimType | None, normalize(cvar.variable_type))

    for variable, entries in tuple(cfunc.unified_local_vars.items()):
        rebuilt: set[tuple[structured_c.CVariable, object]] = set()
        for cvar, variable_type in entries:
            rebuilt.add((cvar, normalize(variable_type)))
        cfunc.unified_local_vars[variable] = rebuilt

    cfunc.functy.returnty = cast(SimType | None, normalize(cfunc.functy.returnty))
    cfunc.functy.args = tuple(cast(SimType, normalize(arg_type)) for arg_type in cfunc.functy.args)

    failure_count = max(classified_count - materialized_count, 0)
    typed_codegen._inertia_explicit_scalar_char_type_stats_8616 = ExplicitScalarCharTypeStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    return changed
