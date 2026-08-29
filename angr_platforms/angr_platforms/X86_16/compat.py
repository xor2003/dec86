"""Layer: Frontend/runtime.

Responsibility: install runtime compatibility patches needed before x86-16 decompilation.
Forbidden: recovering alias, type, or validation semantics through compatibility hooks.
"""

from __future__ import annotations

from typing import Any, Protocol, cast

from angr import ailment
from angr.analyses.decompiler.clinic import Clinic
from angr.knowledge_plugins.functions.function import Function, PrototypeSource

from .patch_dirty import apply_patch as _apply_dirty_patch
from .stack_compat import apply_x86_16_stack_compatibility as _apply_stack_compatibility
from .typehoon_compat import apply_x86_16_typehoon_compatibility as _apply_typehoon_compatibility

__all__ = ["apply_x86_16_compatibility"]


class _ClinicArchBoundary8616(Protocol):
    """Third-party architecture identity required by the Clinic guard."""

    name: str


class _ClinicProjectBoundary8616(Protocol):
    """Third-party project surface required by the Clinic guard."""

    arch: _ClinicArchBoundary8616


class _ClinicBoundary8616(Protocol):
    """Third-party Clinic surface required by the custom-lifter guard."""

    project: _ClinicProjectBoundary8616


def _normalize_x86_16_io_dirty_statements(
    block: object,
) -> tuple[object, int, int, int, int]:
    """Convert typed OUT Dirty statements into ordinary AIL side-effect calls."""
    if not isinstance(block, ailment.Block):
        return block, 0, 0, 0, 0
    raw_fact_count = 0
    normalized_fact_count = 0
    materialized_count = 0
    failure_count = 0
    statements: list[object] = []
    helper_by_width = {
        8: "inertia_io_out8",
        16: "inertia_io_out16",
        32: "inertia_io_out32",
    }
    for statement in block.statements:
        if not isinstance(statement, ailment.Stmt.DirtyStatement):
            statements.append(statement)
            continue
        dirty = statement.dirty
        if dirty.callee != "x86g_dirtyhelper_OUT":
            statements.append(statement)
            continue
        raw_fact_count += 1
        operands = tuple(dirty.operands)
        width = operands[-1].value if len(operands) == 3 and isinstance(operands[-1], ailment.Expr.Const) else None
        helper = helper_by_width.get(width)
        if helper is None:
            failure_count += 1
            statements.append(statement)
            continue
        normalized_fact_count += 1
        call = ailment.Expr.Call(
            dirty.idx,
            helper,
            args=operands[:2],
            bits=0,
            **dict(dirty.tags),
        )
        statements.append(
            ailment.Stmt.SideEffectStatement(
                statement.idx,
                call,
                **dict(statement.tags),
            )
        )
        materialized_count += 1
    block.statements = cast(Any, statements)
    return block, raw_fact_count, normalized_fact_count, materialized_count, failure_count


def _apply_function_prototype_source_compatibility() -> None:
    """Restore the writable guessed-prototype view over angr's source enum."""
    guessed_property = Function.is_prototype_guessed
    if guessed_property.fset is not None:
        return

    def _set_is_prototype_guessed(function: Function, guessed: bool) -> None:
        """Translate the legacy boolean assignment into typed prototype provenance."""
        if guessed:
            function.prototype_source = PrototypeSource.GUESSED
        elif function.prototype_source in {
            PrototypeSource.NONE,
            PrototypeSource.GUESSED,
            PrototypeSource.CCA_LOW,
        }:
            function.prototype_source = PrototypeSource.USER

    function_type = cast(Any, Function)
    function_type.is_prototype_guessed = property(
        guessed_property.fget,
        _set_is_prototype_guessed,
        guessed_property.fdel,
        guessed_property.__doc__,
    )


def _apply_clinic_custom_lifter_compatibility() -> None:
    """Keep Clinic's native fast relift from bypassing the x86-16 lifter."""
    current = Clinic._convert_vex_fast
    if getattr(current, "_inertia_x86_16_custom_lifter_guard", False):
        return

    def _convert_vex_fast_with_custom_lifter_guard(
        clinic: _ClinicBoundary8616,
        block: object,
    ) -> object | None:
        """Use cached custom VEX for x86-16 and retain angr's fast path otherwise."""
        if clinic.project.arch.name == "86_16":
            return None
        return current(cast(Any, clinic), cast(Any, block))

    guarded = cast(Any, _convert_vex_fast_with_custom_lifter_guard)
    guarded._inertia_x86_16_custom_lifter_guard = True
    Clinic._convert_vex_fast = guarded

    current_convert = Clinic._convert_vex
    if getattr(current_convert, "_inertia_x86_16_io_dirty_normalizer", False):
        return

    def _convert_vex_with_io_normalization(
        clinic: _ClinicBoundary8616,
        block: object,
    ) -> object:
        """Materialize x86-16 port writes immediately after VEX-to-AIL conversion."""
        converted = current_convert(cast(Any, clinic), cast(Any, block))
        if clinic.project.arch.name != "86_16":
            return converted
        converted, raw, _normalized, materialized, failures = _normalize_x86_16_io_dirty_statements(converted)
        if raw > 0 and materialized == 0:
            msg = f"x86-16 I/O effects were not materialized: raw={raw} failures={failures}"
            raise TypeError(msg)
        return converted

    convert_guarded = cast(Any, _convert_vex_with_io_normalization)
    convert_guarded._inertia_x86_16_io_dirty_normalizer = True
    Clinic._convert_vex = convert_guarded


def apply_x86_16_compatibility() -> None:
    """Install all frontend/runtime compatibility patches for x86-16 support."""
    _apply_function_prototype_source_compatibility()
    _apply_clinic_custom_lifter_compatibility()
    _apply_stack_compatibility()
    _apply_typehoon_compatibility()
    _apply_dirty_patch()
