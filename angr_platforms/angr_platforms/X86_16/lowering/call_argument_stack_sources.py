"""Select proven stack objects for call-argument source materialization.

Layer: Types/Lowering.
Responsibility: resolve call sources to typed BP-stack objects and distinguish
outgoing carriers by their machine-BP coordinates.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

The selector consumes objects already materialized by lowering, including
objects created earlier in the same call pass.  It must not infer arguments
from rendered C, assembly text, symbol names, or compiler-specific shapes.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
)


class _CallArgumentCFunction8616(Protocol):
    """Third-party C function surface needed for stack-object selection."""

    arg_list: list[object] | tuple[object, ...]
    statements: object
    variables_in_use: Mapping[object, object]


class _CallArgumentCodegen8616(Protocol):
    """Third-party structured-codegen surface needed by this lowering pass."""

    cfunc: _CallArgumentCFunction8616


def _stack_name_preference_8616(name: str | None) -> int:
    """Rank evidence-bearing names above anonymous temporary carriers."""
    if not name:
        return 0
    if name.startswith(("vvar_", "tmp_", "ir_", "s_", "stack_bp_", "stack_sp_")):
        return 1
    if name.startswith(("local_", "arg_")):
        return 3
    return 4


def iter_stack_cvariable_candidates_8616(
    codegen: object,
    synthetic_stack_cvars: Mapping[int, CVariable],
) -> Iterator[CVariable]:
    """Yield lowering-created and angr-owned stack variables once, in stable order."""
    boundary = cast(_CallArgumentCodegen8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return

    yielded: set[int] = set()

    def _yield_candidate(value: object) -> Iterator[CVariable]:
        if not isinstance(value, CVariable) or not isinstance(value.variable, SimStackVariable):
            return
        marker = id(value)
        if marker in yielded:
            return
        yielded.add(marker)
        yield value

    for cvar in synthetic_stack_cvars.values():
        yield from _yield_candidate(cvar)

    try:
        arguments = cfunc.arg_list
    except AttributeError:
        arguments = ()
    for argument in arguments or ():
        yield from _yield_candidate(argument)

    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = {}
    if isinstance(variables_in_use, Mapping):
        for cvar in variables_in_use.values():
            yield from _yield_candidate(cvar)

    try:
        root = cfunc.statements
    except AttributeError:
        root = None
    if root is not None:
        for node in _iter_c_nodes_deep_8616(root):
            yield from _yield_candidate(node)


def containing_stack_cvariable_8616(
    codegen: object,
    synthetic_stack_cvars: Mapping[int, CVariable],
    *,
    offset: int,
    size_hint: int = 1,
) -> CVariable | None:
    """Return the strongest existing BP-stack object proven to contain ``offset``."""
    minimum_size = max(size_hint, 1)
    canonical = stack_cvar_for_machine_bp_range_8616(codegen, offset, minimum_size)
    if isinstance(canonical, CVariable) and isinstance(canonical.variable, SimStackVariable):
        return canonical
    best: CVariable | None = None
    best_score: tuple[int, int, int, int, int] | None = None
    for cvar in iter_stack_cvariable_candidates_8616(codegen, synthetic_stack_cvars):
        variable = cvar.variable
        base_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        size = variable.size
        if variable.base != "bp" or not isinstance(base_offset, int) or not isinstance(size, int):
            continue
        if size < minimum_size or not (base_offset <= offset < base_offset + size):
            continue
        name_preference = _stack_name_preference_8616(variable.name or cvar.name)
        if name_preference <= 1:
            continue
        score = (
            int(base_offset == offset),
            int(size == minimum_size),
            -abs(base_offset - offset),
            -abs(size - minimum_size),
            name_preference,
        )
        if best_score is None or score > best_score:
            best = cvar
            best_score = score

    return best


def outgoing_call_stack_carrier_offset_8616(
    codegen: object,
    expression: object,
) -> int | None:
    """Return the machine-BP offset only for an outgoing call-stack carrier."""
    bp_offset = call_argument_stack_variable_offset_8616(codegen, expression)
    return bp_offset if isinstance(bp_offset, int) and 0 <= bp_offset <= 2 else None


def call_argument_stack_variable_offset_8616(
    codegen: object,
    expression: object,
) -> int | None:
    """Return a direct call argument's proven machine-BP storage offset."""
    if not isinstance(expression, CVariable):
        return None
    variable = expression.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return None
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return bp_offset if isinstance(bp_offset, int) else None
