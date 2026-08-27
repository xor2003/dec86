"""Layer: Types/Lowering.

Responsibility: lower typed ConditionIR stack operands onto proven stack storage.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Signedness evidence belongs to the condition operation, so conflicting signedness
is represented as a typed expression view instead of a second stack declaration.
This module must not infer storage from rendered C or create overlapping aliases
when an exact BP-relative object already exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
)


class _ProjectLike(Protocol):
    """Project surface required to bind angr C types."""

    arch: object


class _CFunctionLike(Protocol):
    """C function storage surfaces used by typed operand lowering."""

    addr: int | None
    arg_list: object
    variables_in_use: object
    unified_local_vars: object


class _CodegenLike(Protocol):
    """Structured-codegen surface used by typed operand lowering."""

    project: _ProjectLike
    cfunc: _CFunctionLike | None


def _cfunc_for_codegen(codegen: object) -> _CFunctionLike | None:
    """Read the optional C function at the explicit third-party codegen boundary."""
    try:
        return cast(_CodegenLike, codegen).cfunc
    except AttributeError:
        return None


def _variables_in_use(cfunc: object) -> object:
    """Read the optional angr declaration map without inventing a fallback contract."""
    try:
        return cast(_CFunctionLike, cfunc).variables_in_use
    except AttributeError:
        return None


def _unified_local_vars(cfunc: object) -> object:
    """Read the optional angr unified-local map at the dynamic boundary."""
    try:
        return cast(_CFunctionLike, cfunc).unified_local_vars
    except AttributeError:
        return None


def _cfunc_addr(cfunc: object) -> int | None:
    """Read the optional function region used for newly materialized storage."""
    try:
        return cast(_CFunctionLike, cfunc).addr
    except AttributeError:
        return None


def _condition_integer_type(codegen: object, size: int, *, signed: bool) -> SimType:
    """Return an architecture-bound integer type for one condition operand."""
    if size == 1:
        type_ = SimTypeChar(signed)
    elif size == 4:
        type_ = SimTypeLong(signed)
    else:
        type_ = SimTypeShort(signed)
    return type_.with_arch(cast(_CodegenLike, codegen).project.arch)


def _matches_stack_storage(
    codegen: object,
    variable: object,
    *,
    base: str,
    offset: int,
    size: int,
) -> bool:
    """Match an exact machine stack identity across projected C coordinates."""
    if not isinstance(variable, SimStackVariable) or variable.base != base or variable.size != size:
        return False
    storage_offset = (
        machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if base == "bp"
        else variable.offset if isinstance(variable.offset, int) else None
    )
    return storage_offset == offset


def _existing_stack_cvar(
    codegen: object,
    cfunc: _CFunctionLike,
    *,
    base: str,
    offset: int,
    size: int,
) -> structured_c.CVariable | None:
    """Resolve an exact stack declaration from angr's structured surfaces."""
    variables_in_use = _variables_in_use(cfunc)
    if isinstance(variables_in_use, dict):
        for variable, cvar in variables_in_use.items():
            if _matches_stack_storage(codegen, variable, base=base, offset=offset, size=size) and isinstance(
                cvar, structured_c.CVariable
            ):
                return cvar
    unified_local_vars = _unified_local_vars(cfunc)
    if isinstance(unified_local_vars, dict):
        for variable, entries in unified_local_vars.items():
            if not _matches_stack_storage(codegen, variable, base=base, offset=offset, size=size):
                continue
            if not isinstance(entries, (list, set, tuple)):
                continue
            for entry in entries:
                if isinstance(entry, tuple) and entry and isinstance(entry[0], structured_c.CVariable):
                    return entry[0]
    return None


def _existing_wide_stack_cvar(
    codegen: object,
    cfunc: _CFunctionLike,
    *,
    base: str,
    offset: int,
    size: int,
) -> structured_c.CVariable | None:
    """Resolve a proven wide owner containing one word slice."""
    if size != 2:
        return None
    candidates: list[structured_c.CVariable] = []
    variables_in_use = _variables_in_use(cfunc)
    if isinstance(variables_in_use, dict):
        candidates.extend(
            cvar for cvar in variables_in_use.values() if isinstance(cvar, structured_c.CVariable)
        )
    try:
        arg_list = cfunc.arg_list
    except AttributeError:
        arg_list = None
    if isinstance(arg_list, (list, tuple)):
        candidates.extend(cvar for cvar in arg_list if isinstance(cvar, structured_c.CVariable))

    for cvar in candidates:
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable):
            continue
        if variable.base != base or variable.size != 4:
            continue
        variable_offset = (
            machine_bp_offset_for_stack_variable_8616(codegen, variable)
            if base == "bp"
            else variable.offset
        )
        if not isinstance(variable_offset, int) or offset not in {variable_offset, variable_offset + 2}:
            continue
        return cvar
    return None


def _wide_stack_word_projection(
    codegen: object,
    declaration: structured_c.CVariable,
    *,
    offset: int,
    signed: bool,
    prefer_word_view: bool = False,
) -> structured_c.CExpression | None:
    """Project a proven low/high word without declaring an overlapping object."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant

    variable = declaration.variable
    if not isinstance(variable, SimStackVariable) or variable.size != 4:
        return None
    shift = offset - variable.offset
    if shift not in {0, 2}:
        return None
    word_type = _condition_integer_type(codegen, 2, signed=signed)
    view = structured_c.CVariable(
        variable,
        unified_variable=declaration.unified_variable,
        variable_type=word_type if prefer_word_view else declaration.variable_type,
        codegen=codegen,
        tags=dict(declaration.tags),
    )
    projected: structured_c.CExpression = view
    if prefer_word_view and shift == 0:
        return view
    if shift == 2:
        projected = CBinaryOp(
            "Shr",
            projected,
            CConstant(16, word_type, codegen=codegen),
            codegen=codegen,
        )
    projected = CBinaryOp(
        "And",
        projected,
        CConstant(0xFFFF, word_type, codegen=codegen),
        codegen=codegen,
    )
    if signed:
        return CSemanticCast8616(
            declaration.variable_type,
            word_type,
            projected,
            codegen=codegen,
            tags=dict(declaration.tags),
        )
    return projected


def materialize_typed_condition_stack_operand_8616(
    codegen: object,
    *,
    base: str,
    offset: int,
    size: int,
    name: str,
    signed: bool,
    tags: Mapping[str, object] | None = None,
    preferred: structured_c.CVariable | None = None,
    prefer_signed_local_storage: bool = False,
    storage_size: int | None = None,
) -> structured_c.CExpression | None:
    """Return a typed expression view over one exact BP-relative stack object.

    ``storage_size`` preserves a wider object proven by the IR while the
    condition consumes a narrower typed view.  The wider declaration is the
    storage owner; the returned expression is only a word projection.  This
    prevents condition width from silently narrowing a live stack object.
    """
    if size <= 0:
        return None
    cfunc = _cfunc_for_codegen(codegen)

    if (
        cfunc is not None
        and isinstance(storage_size, int)
        and storage_size > size
    ):
        storage_declaration = _existing_stack_cvar(
            codegen,
            cfunc,
            base=base,
            offset=offset,
            size=storage_size,
        )
        if storage_declaration is None:
            storage_variable = SimStackVariable(
                offset,
                storage_size,
                base=base,
                name=name,
                region=_cfunc_addr(cfunc),
            )
            storage_declaration = structured_c.CVariable(
                storage_variable,
                variable_type=_condition_integer_type(codegen, storage_size, signed=False),
                codegen=codegen,
                tags=dict(tags or {}),
            )
            variables_in_use = _variables_in_use(cfunc)
            if isinstance(variables_in_use, dict):
                variables_in_use[storage_variable] = storage_declaration
            unified_local_vars = _unified_local_vars(cfunc)
            if isinstance(unified_local_vars, dict):
                unified_local_vars[storage_variable] = {
                    (storage_declaration, storage_declaration.variable_type)
                }
        projected = _wide_stack_word_projection(
            codegen,
            storage_declaration,
            offset=offset,
            signed=signed,
            prefer_word_view=(prefer_signed_local_storage and base == "bp" and offset > 0),
        )
        if projected is not None:
            return projected

    declaration = preferred
    if declaration is not None and not _matches_stack_storage(
        codegen,
        declaration.variable,
        base=base,
        offset=offset,
        size=size,
    ):
        declaration = None
    if declaration is None and base == "bp":
        projected = stack_cvar_for_machine_bp_range_8616(codegen, offset, size)
        if isinstance(projected, structured_c.CVariable):
            declaration = projected
    if declaration is None and cfunc is not None:
        declaration = _existing_stack_cvar(codegen, cfunc, base=base, offset=offset, size=size)
    if declaration is None and cfunc is not None and size == 2:
        wide_declaration = _existing_wide_stack_cvar(
            codegen,
            cfunc,
            base=base,
            offset=offset,
            size=size,
        )
        if wide_declaration is not None:
            projected = _wide_stack_word_projection(
                codegen,
                wide_declaration,
                offset=offset,
                signed=signed,
                prefer_word_view=(prefer_signed_local_storage and base == "bp" and offset > 0),
            )
            if projected is not None:
                return projected
    if declaration is None:
        variable = SimStackVariable(
            offset,
            size,
            base=base,
            name=name,
            region=_cfunc_addr(cfunc) if cfunc is not None else None,
        )
        declaration = structured_c.CVariable(
            variable,
            variable_type=_condition_integer_type(codegen, size, signed=signed),
            codegen=codegen,
            tags=dict(tags or {}),
        )
        if cfunc is not None:
            variables_in_use = _variables_in_use(cfunc)
            if isinstance(variables_in_use, dict):
                variables_in_use[variable] = declaration
            unified_local_vars = _unified_local_vars(cfunc)
            if isinstance(unified_local_vars, dict):
                unified_local_vars[variable] = {(declaration, declaration.variable_type)}

    current_type = declaration.variable_type
    target_type = _condition_integer_type(codegen, size, signed=signed)
    condition_local_view = (
        prefer_signed_local_storage
        and signed
        and base == "bp"
        and offset < 0
        and isinstance(current_type, (SimTypeChar, SimTypeShort, SimTypeLong))
        and not bool(current_type.signed)
    )
    view = structured_c.CVariable(
        declaration.variable,
        unified_variable=declaration.unified_variable,
        variable_type=target_type if condition_local_view else current_type or target_type,
        codegen=codegen,
        tags=dict(tags or declaration.tags),
    )
    if condition_local_view:
        return view
    current_signed = current_type.signed if isinstance(current_type, (SimTypeChar, SimTypeShort, SimTypeLong)) else None
    if current_signed is None or bool(current_signed) == signed:
        return view
    return CSemanticCast8616(
        current_type,
        target_type,
        view,
        codegen=codegen,
        tags=dict(tags or declaration.tags),
    )


__all__ = [
    "materialize_typed_condition_stack_operand_8616",
]
