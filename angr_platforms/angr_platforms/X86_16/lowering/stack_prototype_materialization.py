"""Layer: Types/Lowering.

Responsibility: materialize stack-prototype facts before rewrite.
Consumes alias, widening, and typed facts from structured stack-slot annotations
already attached to function metadata, then turns positive BP slots into codegen
argument variables and a typed function prototype.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
import typing
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable

from ..annotations import ANNOTATION_KEY

__all__ = [
    "FunctionParameterWidthFact8616",
    "materialize_exact_trailing_stack_argument_8616",
    "materialize_annotated_stack_prototype_8616",
    "reconcile_callsite_interface_declarations_8616",
    "reconcile_exact_stack_argument_prototype_8616",
]


class _PrototypeFunction8616(Protocol):
    """Function metadata written at the dynamic third-party angr boundary."""

    info: object
    prototype: object
    is_prototype_guessed: bool


class _StackPrototypeCodegen8616(Protocol):
    """Codegen metadata written at the dynamic third-party angr boundary."""

    cfunc: object
    next_idx: object
    _inertia_annotated_stack_prototype_materialized_8616: int
    _inertia_authoritative_zero_arg_prototype_8616: bool
    _inertia_callsite_summaries: object
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_function_parameter_width_facts_8616: tuple[FunctionParameterWidthFact8616, ...]
    _inertia_stack_prototype_width_stats_8616: StackPrototypeWidthStats8616


class _StackPrototypeCFunction8616(Protocol):
    """C-function fields consumed after the dynamic codegen entry boundary."""

    addr: int
    arg_list: list[structured_c.CVariable]
    functy: object
    unified_local_vars: object
    variables_in_use: object


class _ProjectArch8616(Protocol):
    """Project fields exposed after the dynamic third-party entry boundary."""

    arch: object
    kb: _KnowledgeBase8616


class _ArchBytes8616(Protocol):
    """Target architecture field that defines the C ABI word size."""

    bytes: int


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base surface required by stack prototype lowering."""

    functions: _FunctionManager8616


class _FunctionManager8616(Protocol):
    """angr function-manager surface required by stack prototype lowering."""

    def function(self, *, addr: int, create: bool) -> object:
        """Return an existing function by address."""
        ...


class _SizedType8616(Protocol):
    """Third-party type surface used to query an architecture-sized width."""

    size: int


class _ArchBindableType8616(Protocol):
    """Third-party type surface used to bind an architecture."""

    def with_arch(self, arch: object) -> object:
        """Return this type bound to ``arch``."""
        ...


class _CallsiteSummary8616(Protocol):
    """Typed callsite fields consumed from the semantics layer."""

    arg_widths: tuple[int, ...]
    push_arg_sources: tuple[tuple[str, int] | None, ...]


@dataclass(frozen=True)
class StackPrototypeWidthStats8616:
    """Evidence accounting for exact stack-slot argument-width constraints."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, order=True, slots=True)
class FunctionParameterWidthFact8616:
    """Exact binary/IR-backed width of one positive BP function parameter."""

    stack_offset: int
    width_bytes: int


def _debug_parameter_width_facts_8616(
    phase: str,
    facts: tuple[FunctionParameterWidthFact8616, ...],
) -> None:
    """Log parameter-width fact lifecycle when prototype diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") != "1":
        return
    print(
        f"[dbg-x87-proto] parameter_width_facts phase={phase} facts={facts!r}",
        file=sys.stderr,
        flush=True,
    )


def _function_for_codegen_8616(project: object, codegen: object) -> object | None:
    """Return metadata through the dynamic third-party angr project/codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return None
    func_addr = cast(_StackPrototypeCFunction8616, cfunc).addr
    if not isinstance(func_addr, int):
        return None
    with contextlib.suppress(Exception):
        return cast(_ProjectArch8616, project).kb.functions.function(addr=func_addr, create=False)
    return None


def _positive_stack_specs_8616(func: object) -> tuple[tuple[int, str | None], ...]:
    """Read stack annotations through the dynamic third-party angr metadata boundary."""
    info = cast(_PrototypeFunction8616, func).info
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
    if not isinstance(annotations, Mapping):
        return ()
    stack_specs = annotations.get("stack_vars")
    if not isinstance(stack_specs, Mapping):
        return ()
    positive_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
    if not positive_offsets:
        return ()
    normalized = positive_offsets[0] == 2
    entries: list[tuple[int, str | None]] = []
    for raw_offset in positive_offsets:
        spec = stack_specs.get(raw_offset)
        name: str | None = None
        if isinstance(spec, str):
            name = spec
        elif isinstance(spec, Mapping):
            spec_name = spec.get("name")
            if isinstance(spec_name, str):
                name = spec_name
        if isinstance(name, str) and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            name = None
        entries.append((raw_offset + 2 if normalized else raw_offset, name))
    return tuple(entries)


def _existing_stack_cvars_by_offset_8616(codegen: object) -> dict[int, structured_c.CVariable]:
    """Read stack C variables through the dynamic third-party angr codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return {}
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars: dict[int, structured_c.CVariable] = {}
    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, Mapping):
        for variable, cvar in variables_in_use.items():
            if not isinstance(variable, SimStackVariable) or not isinstance(cvar, structured_c.CVariable):
                continue
            offset = variable.offset
            if isinstance(offset, int):
                cvars.setdefault(offset, cvar)
    for cvar in typed_cfunc.arg_list or ():
        if not isinstance(cvar, structured_c.CVariable):
            continue
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable):
            continue
        offset = variable.offset
        if isinstance(offset, int):
            cvars.setdefault(offset, cvar)
    return cvars


def _iter_existing_stack_cvars_at_offset_8616(codegen: object, offset: int) -> tuple[structured_c.CVariable, ...]:
    """Iterate stack C variables through the dynamic third-party angr codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return ()
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars: list[structured_c.CVariable] = []
    seen: set[int] = set()

    def _append(cvar: object) -> None:
        """Read stack variables through the dynamic third-party angr boundary."""
        if not isinstance(cvar, structured_c.CVariable):
            return
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable) or variable.offset != offset:
            return
        identity = id(cvar)
        if identity in seen:
            return
        seen.add(identity)
        cvars.append(cvar)

    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, Mapping):
        for cvar in variables_in_use.values():
            _append(cvar)
    for cvar in typed_cfunc.arg_list or ():
        _append(cvar)
    return tuple(cvars)


def _apply_arg_cvar_surface_8616(cvar: structured_c.CVariable, *, name: str, variable_type: object) -> bool:
    """Apply argument surface updates across the dynamic third-party angr C AST boundary."""
    changed = False
    variable = cvar.variable
    if isinstance(variable, SimStackVariable) and variable.name != name:
        variable.name = name
        changed = True
    if cvar.variable_type != variable_type:
        typing.cast(typing.Any, cvar).variable_type = variable_type
        changed = True
    unified_variable = cvar.unified_variable
    if unified_variable is not None and unified_variable.name != name:
        unified_variable.name = name
        changed = True
    return changed


def _reconciled_positive_arg_name_8616(
    variable: SimStackVariable,
    prototype_name: str | None,
) -> str:
    """Replace provisional local names once a positive BP slot is proven an argument."""
    variable_name = variable.name
    for candidate in (prototype_name, variable_name):
        if (
            isinstance(candidate, str)
            and candidate
            and candidate != "local"
            and not candidate.startswith("local_")
        ):
            return candidate
    return f"arg_{variable.offset:x}"


def _abi_word_size_8616(arch: object | None) -> int:
    """Return the target C ABI word size, independent of VEX register width."""
    try:
        width = cast(_ArchBytes8616, arch).bytes
    except AttributeError:
        width = None
    return width if isinstance(width, int) and width > 0 else 2


def _type_size_bytes_8616(
    type_: object,
    *,
    arch: object | None = None,
    default: int = 2,
) -> int:
    """Read one x86-16 ABI type width at the dynamic angr type boundary.

    ``Arch86_16.bits`` is intentionally 32 for VEX compatibility, while its C
    ABI word is 16 bits. An angr ``SimTypeInt`` therefore occupies
    ``arch.bytes`` here; explicit ``SimTypeLong`` values retain their 32-bit
    size.
    """
    if isinstance(type_, SimTypeInt) and not isinstance(type_, SimTypeLong):
        return _abi_word_size_8616(arch)
    try:
        bits = cast(_SizedType8616, type_).size
    except (AttributeError, ValueError):
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _exact_stack_slot_width_8616(
    codegen: object,
    offset: int,
    *,
    arch: object,
) -> int | None:
    """Return the binary-derived width of an exact C stack slot."""
    cvar = _existing_stack_cvars_by_offset_8616(codegen).get(offset)
    if cvar is None or not isinstance(cvar.variable, SimStackVariable):
        return None
    if isinstance(cvar.variable_type, SimTypeInt) and not isinstance(
        cvar.variable_type,
        SimTypeLong,
    ):
        return _abi_word_size_8616(arch)
    width = cvar.variable.size
    return width if isinstance(width, int) and width > 0 else None


def _exact_typed_cvar_width_8616(cvar: structured_c.CVariable, arch: object) -> int | None:
    """Return an exact argument width from its typed stack storage.

    Pointer ``size`` follows ``Arch86_16.bits`` and is therefore not a near/far
    pointer ABI discriminator. The exact ``SimStackVariable`` width remains the
    binary-owned storage fact for non-integer arguments.
    """
    variable_type = cvar.variable_type
    if not isinstance(variable_type, SimType):
        return None
    if isinstance(variable_type, SimTypeInt) and not isinstance(
        variable_type,
        SimTypeLong,
    ):
        return _abi_word_size_8616(arch)
    variable = cvar.variable
    if not isinstance(variable_type, SimTypeInt):
        if isinstance(variable, SimStackVariable) and isinstance(variable.size, int) and variable.size > 0:
            return variable.size
        return None
    bound_type = _with_arch_8616(variable_type, arch)
    try:
        bits = cast(_SizedType8616, bound_type).size
    except (AttributeError, ValueError):
        return None
    if not isinstance(bits, int) or bits <= 0:
        return None
    return max(1, (bits + 7) // 8)


def _callsite_stack_arg_widths_8616(codegen: object) -> dict[int, int]:
    """Return unambiguous BP-source widths from typed callsite summaries."""
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    try:
        summaries = typed_codegen._inertia_callsite_summaries
    except AttributeError:
        return {}
    if not isinstance(summaries, Mapping):
        return {}
    widths_by_offset: dict[int, set[int]] = {}
    for summary_value in summaries.values():
        summary = cast(_CallsiteSummary8616, summary_value)
        for source, width in zip(tuple(summary.push_arg_sources or ()), tuple(summary.arg_widths or ())):
            if (
                isinstance(source, tuple)
                and len(source) >= 2
                and source[0] == "bp"
                and isinstance(source[1], int)
                and source[1] >= 4
                and isinstance(width, int)
                and width > 0
            ):
                widths_by_offset.setdefault(source[1], set()).add(width)
    return {
        offset: next(iter(widths))
        for offset, widths in widths_by_offset.items()
        if len(widths) == 1
    }


def _normalized_header_arg_widths_8616(
    codegen: object,
    entries: tuple[tuple[int, str | None], ...],
) -> tuple[int, ...]:
    """Return widths when the entire angr header omits the return-address word."""
    cfunc = cast(_StackPrototypeCFunction8616, cast(_StackPrototypeCodegen8616, codegen).cfunc)
    arg_list = tuple(cfunc.arg_list or ())
    if len(arg_list) != len(entries):
        return ()
    widths: list[int] = []
    for cvar, (expected_offset, _name) in zip(arg_list, entries):
        variable = cvar.variable
        if (
            not isinstance(variable, SimStackVariable)
            or variable.offset + 2 != expected_offset
            or not isinstance(variable.size, int)
            or variable.size <= 0
        ):
            return ()
        widths.append(variable.size)
    return tuple(widths)


def _constrain_scalar_arg_type_to_stack_slot_8616(
    arg_type: SimType,
    *,
    slot_width: int | None,
    arch: object,
) -> tuple[SimType, bool, bool]:
    """Constrain a guessed scalar type to non-overlapping stack storage."""
    if isinstance(arg_type, SimTypePointer):
        return arg_type, False, False
    if slot_width is None or _type_size_bytes_8616(arg_type, arch=arch) <= slot_width:
        return arg_type, False, False
    if slot_width != 2 or not isinstance(arg_type, SimTypeInt):
        return arg_type, False, True
    narrowed = SimTypeShort(signed=arg_type.signed, label=arg_type.label)
    return cast(SimType, _with_arch_8616(narrowed, arch)), True, False


def _ensure_arg_cvar_8616(
    *,
    codegen: object,
    offset: int,
    name: str,
    variable_type: object,
    width: int,
) -> tuple[structured_c.CVariable | None, bool]:
    """Materialize a BP argument variable through the dynamic third-party angr codegen boundary."""
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return None, False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars_by_offset = _existing_stack_cvars_by_offset_8616(codegen)
    cvar = cvars_by_offset.get(offset)
    changed = False
    if cvar is None:
        if not callable(typed_codegen.next_idx):
            return None, False
        func_addr = typed_cfunc.addr
        stack_var = SimStackVariable(offset, width, base="bp", name=name, region=func_addr)
        cvar = structured_c.CVariable(stack_var, variable_type=variable_type, codegen=codegen)
        variables_in_use = typed_cfunc.variables_in_use
        if isinstance(variables_in_use, dict):
            variables_in_use[stack_var] = cvar
        unified = typed_cfunc.unified_local_vars
        if isinstance(unified, dict):
            unified[stack_var] = {(cvar, variable_type)}
        changed = True
    variable = cvar.variable
    if isinstance(variable, SimStackVariable) and variable.size != width:
        variable.size = width
        changed = True
    changed = _apply_arg_cvar_surface_8616(cvar, name=name, variable_type=variable_type) or changed
    return cvar, changed


def _prune_stack_slots_covered_by_wide_args_8616(
    codegen: object,
    owned_ranges: Mapping[int, int],
    owner_variables: set[SimStackVariable],
) -> bool:
    """Prune stack slots through the dynamic third-party angr codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    covered_offsets = {
        covered
        for base_offset, width in owned_ranges.items()
        if width > 2
        for covered in range(base_offset + 2, base_offset + width, 2)
    }
    if not covered_offsets:
        return False
    changed = False
    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, dict):
        for variable in tuple(variables_in_use):
            if variable in owner_variables or not isinstance(variable, SimStackVariable):
                continue
            if variable.offset in covered_offsets:
                del variables_in_use[variable]
                changed = True
    unified = typed_cfunc.unified_local_vars
    if isinstance(unified, dict):
        for variable in tuple(unified):
            if variable in owner_variables or not isinstance(variable, SimStackVariable):
                continue
            if variable.offset in covered_offsets:
                del unified[variable]
                changed = True
    return changed


def _with_arch_8616(type_: object, arch: object) -> object:
    """Attach architecture through the dynamic third-party angr type boundary."""
    with contextlib.suppress(Exception):
        return cast(_ArchBindableType8616, type_).with_arch(arch)
    return type_


def _prototype_equivalent_8616(left: object, right: object) -> bool:
    """Compare prototypes through the dynamic third-party angr type boundary."""
    if left is right:
        return True
    if left is None or right is None:
        return False
    with contextlib.suppress(Exception):
        return bool(left == right)
    return False


def materialize_exact_trailing_stack_argument_8616(
    project: object,
    codegen: object,
    *,
    candidate: structured_c.CVariable,
    stack_offset: int,
    argument_type: SimType,
    width: int,
) -> structured_c.CVariable | None:
    """Append one evidence-proven contiguous trailing BP argument.

    The caller owns the semantic proof for the candidate storage and type. This
    consumer updates the interface only when the existing argument list and
    prototype agree, all existing arguments occupy contiguous BP slots starting
    at ``BP+4``, and the candidate is exactly the next slot. Gaps, overlaps,
    malformed interfaces, and authoritative zero-argument contracts are
    refused without mutation.
    """
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return None
    try:
        if typed_codegen._inertia_authoritative_zero_arg_prototype_8616:
            return None
    except AttributeError:
        pass
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    prototype = typed_cfunc.functy
    if not isinstance(prototype, SimTypeFunction) or width <= 0:
        return None
    prototype_args = tuple(prototype.args or ())
    existing_args = tuple(typed_cfunc.arg_list or ())
    if len(existing_args) != len(prototype_args):
        return None
    candidate_variable = candidate.variable
    if (
        not isinstance(candidate_variable, SimStackVariable)
        or candidate_variable.offset != stack_offset
        or stack_offset < 4
    ):
        return None
    expected_offset = 4
    for existing in existing_args:
        variable = existing.variable
        if (
            not isinstance(variable, SimStackVariable)
            or not isinstance(variable.offset, int)
            or not isinstance(variable.size, int)
            or variable.size <= 0
            or variable.offset != expected_offset
        ):
            return None
        expected_offset += max(2, variable.size)
    if stack_offset != expected_offset:
        return None

    name = f"arg_{stack_offset:x}"
    candidate_variable.size = width
    _apply_arg_cvar_surface_8616(candidate, name=name, variable_type=argument_type)
    for sibling in _iter_existing_stack_cvars_at_offset_8616(codegen, stack_offset):
        _apply_arg_cvar_surface_8616(sibling, name=name, variable_type=argument_type)
    typed_cfunc.arg_list = [*existing_args, candidate]

    arg_names = tuple(prototype.arg_names or ())
    if len(arg_names) != len(existing_args):
        recovered_names: list[str] = []
        for existing in existing_args:
            variable = existing.variable
            if not isinstance(variable, SimStackVariable) or not isinstance(variable.offset, int):
                return None
            recovered_names.append(variable.name or f"arg_{variable.offset:x}")
        arg_names = tuple(recovered_names)
    arch = cast(_ProjectArch8616, project).arch
    new_prototype = SimTypeFunction(
        [*prototype_args, argument_type],
        prototype.returnty,
        arg_names=(*arg_names, name),
        variadic=prototype.variadic,
    )
    new_prototype = cast(SimTypeFunction, _with_arch_8616(new_prototype, arch))
    typed_cfunc.functy = new_prototype
    func = _function_for_codegen_8616(project, codegen)
    if func is not None:
        cast(_PrototypeFunction8616, func).prototype = new_prototype
    typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return candidate


def _materialize_annotated_zero_arg_prototype_8616(
    *,
    project: object,
    codegen: object,
    func: object,
    prototype: SimTypeFunction,
) -> bool:
    """Materialize an explicit zero-argument annotation as the authoritative typed contract."""
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    typed_func = cast(_PrototypeFunction8616, func)
    arch = cast(_ProjectArch8616, project).arch
    new_proto = _with_arch_8616(prototype, arch) if arch is not None else prototype
    changed = False
    if typed_cfunc.arg_list:
        typed_cfunc.arg_list = []
        changed = True
    if not _prototype_equivalent_8616(typed_func.prototype, new_proto):
        typed_func.prototype = new_proto
        changed = True
    if typed_func.is_prototype_guessed:
        typed_func.is_prototype_guessed = False
        changed = True
    if not _prototype_equivalent_8616(typed_cfunc.functy, new_proto):
        typed_cfunc.functy = new_proto
        changed = True
    typed_codegen._inertia_authoritative_zero_arg_prototype_8616 = True
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def reconcile_exact_stack_argument_prototype_8616(project: object, codegen: object) -> bool:
    """Reconcile a prototype with exact typed argument C variables.

    This runs after stack-variable materialization has exposed architectural BP
    offsets. It only narrows numeric types when every argument has one exact,
    non-overlapping stack slot; unresolved or unsupported shapes are refused.
    """
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    prototype = typed_cfunc.functy
    if not isinstance(prototype, SimTypeFunction):
        return False
    args = tuple(prototype.args or ())
    arg_cvars = tuple(typed_cfunc.arg_list or ())
    if not args or len(args) != len(arg_cvars):
        return False
    arch = cast(_ProjectArch8616, project).arch
    reconciled_args: list[SimType] = []
    classified_count = 0
    failure_count = 0
    previous_end = 4
    callsite_widths = _callsite_stack_arg_widths_8616(codegen)
    width_facts: list[FunctionParameterWidthFact8616] = []
    prototype_names = tuple(prototype.arg_names or ())
    reconciled_names: list[str] = []
    debug_rows: list[tuple[object, ...]] = []
    changed = False
    for index, (arg_type, cvar) in enumerate(zip(args, arg_cvars)):
        variable = cvar.variable
        exact_width = _exact_typed_cvar_width_8616(cvar, arch)
        if isinstance(arg_type, SimTypeInt) and isinstance(variable, SimStackVariable):
            exact_width = callsite_widths.get(variable.offset, exact_width)
        if (
            not isinstance(arg_type, SimType)
            or not isinstance(variable, SimStackVariable)
            or not isinstance(variable.offset, int)
            or not isinstance(variable.size, int)
            or exact_width is None
            or variable.offset < previous_end
            or variable.size <= 0
        ):
            return False
        width_facts.append(
            FunctionParameterWidthFact8616(
                stack_offset=variable.offset,
                width_bytes=exact_width,
            )
        )
        reconciled_name = _reconciled_positive_arg_name_8616(
            variable,
            prototype_names[index] if index < len(prototype_names) else None,
        )
        reconciled_names.append(reconciled_name)
        changed = (
            _apply_arg_cvar_surface_8616(
                cvar,
                name=reconciled_name,
                variable_type=cvar.variable_type,
            )
            or changed
        )
        reconciled, materialized, failed = _constrain_scalar_arg_type_to_stack_slot_8616(
            arg_type,
            slot_width=exact_width,
            arch=arch,
        )
        reconciled_args.append(reconciled)
        classified_count += int(not failed)
        failure_count += int(failed)
        if materialized and cvar.variable_type != reconciled:
            typing.cast(typing.Any, cvar).variable_type = reconciled
            changed = True
        debug_rows.append(
            (
                variable.offset,
                variable.size,
                repr(arg_type),
                repr(cvar.variable_type),
                exact_width,
                materialized,
                failed,
            )
        )
        if materialized and variable.size != exact_width:
            variable.size = exact_width
            changed = True
        previous_end = variable.offset + exact_width
    parameter_width_facts = tuple(width_facts)
    typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
    _debug_parameter_width_facts_8616("reconcile", parameter_width_facts)
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
        print(f"[dbg-x87-proto] reconcile_stack_proto rows={tuple(debug_rows)!r}", file=sys.stderr, flush=True)
    typed_codegen._inertia_stack_prototype_width_stats_8616 = StackPrototypeWidthStats8616(
        raw_fact_count=len(arg_cvars),
        normalized_fact_count=len(arg_cvars),
        classified_fact_count=classified_count,
        materialized_count=classified_count,
        failure_count=failure_count,
    )
    if failure_count or classified_count == 0:
        return False
    new_prototype = SimTypeFunction(
        reconciled_args,
        prototype.returnty,
        arg_names=tuple(reconciled_names),
        variadic=prototype.variadic,
    )
    new_prototype = cast(SimTypeFunction, _with_arch_8616(new_prototype, arch))
    cfunc_names = (
        tuple(typed_cfunc.functy.arg_names or ())
        if isinstance(typed_cfunc.functy, SimTypeFunction)
        else ()
    )
    if (
        not _prototype_equivalent_8616(typed_cfunc.functy, new_prototype)
        or cfunc_names != tuple(reconciled_names)
    ):
        typed_cfunc.functy = new_prototype
        changed = True
    func = _function_for_codegen_8616(project, codegen)
    if func is not None:
        typed_func = cast(_PrototypeFunction8616, func)
        function_names = (
            tuple(typed_func.prototype.arg_names or ())
            if isinstance(typed_func.prototype, SimTypeFunction)
            else ()
        )
        if (
            not _prototype_equivalent_8616(typed_func.prototype, new_prototype)
            or function_names != tuple(reconciled_names)
        ):
            typed_func.prototype = new_prototype
            changed = True
        if typed_func.is_prototype_guessed:
            typed_func.is_prototype_guessed = False
            changed = True
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def reconcile_callsite_interface_declarations_8616(project: object, codegen: object) -> bool:
    """Finalize stack widths before lowering the corresponding declarations.

    The local peer import avoids a module cycle while keeping this lifecycle
    operation wholly inside types/lowering. Stage orchestrators must call this
    entry point instead of independently ordering width and declaration passes.
    """
    from .callsite_prototype_declarations import materialize_callsite_prototype_declarations_8616

    prototype_changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)
    materialize_callsite_prototype_declarations_8616(project, codegen)
    # Declaration metadata does not mutate the C AST and must not activate a
    # stage semantic-validation delta by itself.
    return prototype_changed


def materialize_annotated_stack_prototype_8616(project: object, codegen: object) -> bool:
    """Materialize positive BP stack annotations as typed codegen arguments.

    The input annotations are structured metadata produced before C emission.
    This function only consumes positive stack slots, which represent near-call
    x86-16 arguments after BP+2 return-address normalization.
    The codegen, function, C AST, and prototype objects cross a dynamic
    third-party angr boundary; owned Inertia state is written via typed protocol
    casts.
    """
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    func = _function_for_codegen_8616(project, codegen)
    if func is None:
        return False
    info = cast(_PrototypeFunction8616, func).info
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
    annotated_prototype = annotations.get("prototype") if isinstance(annotations, Mapping) else None
    if (
        isinstance(annotated_prototype, SimTypeFunction)
        and not tuple(annotated_prototype.args or ())
        and not annotated_prototype.variadic
    ):
        return _materialize_annotated_zero_arg_prototype_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=annotated_prototype,
        )
    entries = _positive_stack_specs_8616(func)
    if not entries:
        metadata_prototype = cast(_PrototypeFunction8616, func).prototype
        if (
            isinstance(metadata_prototype, SimTypeFunction)
            and not tuple(metadata_prototype.args or ())
            and not metadata_prototype.variadic
            and not cast(_PrototypeFunction8616, func).is_prototype_guessed
        ):
            return _materialize_annotated_zero_arg_prototype_8616(
                project=project,
                codegen=codegen,
                func=func,
                prototype=metadata_prototype,
            )
        return False
    arch = cast(_ProjectArch8616, project).arch
    typed_func = cast(_PrototypeFunction8616, func)
    current_proto = typed_cfunc.functy or typed_func.prototype
    if isinstance(current_proto, SimTypeFunction):
        current_args = list(current_proto.args or ())
        return_type = current_proto.returnty
        variadic = current_proto.variadic
    else:
        current_args = []
        return_type = None
        variadic = False
    if return_type is None or (isinstance(return_type, SimTypeBottom) and return_type.label != "void"):
        return_type = SimTypeShort(False)
    arg_cvars: list[structured_c.CVariable] = []
    arg_types: list[SimType] = []
    arg_names: list[str] = []
    owned_ranges: dict[int, int] = {}
    owner_variables: set[SimStackVariable] = set()
    width_stats = StackPrototypeWidthStats8616()
    width_facts: list[FunctionParameterWidthFact8616] = []
    normalized_header_widths = _normalized_header_arg_widths_8616(codegen, entries)
    changed = False
    for index, (offset, maybe_name) in enumerate(entries):
        name = maybe_name or f"arg_{offset:x}"
        if index < len(current_args):
            arg_type = current_args[index]
        else:
            arg_type = SimTypeShort(False)
        if arch is not None:
            arg_type = _with_arch_8616(arg_type, arch)
        if not isinstance(arg_type, SimType):
            arg_type = SimTypeShort(False)
        slot_width = (
            normalized_header_widths[index]
            if index < len(normalized_header_widths)
            else _exact_stack_slot_width_8616(codegen, offset, arch=arch)
        )
        raw_width_fact = int(slot_width is not None)
        normalized_width_fact = int(isinstance(slot_width, int) and slot_width > 0)
        if normalized_width_fact:
            assert isinstance(slot_width, int)
            width_facts.append(
                FunctionParameterWidthFact8616(
                    stack_offset=offset,
                    width_bytes=slot_width,
                )
            )
        arg_type, width_materialized, width_failure = _constrain_scalar_arg_type_to_stack_slot_8616(
            arg_type,
            slot_width=slot_width,
            arch=arch,
        )
        width_stats = StackPrototypeWidthStats8616(
            raw_fact_count=width_stats.raw_fact_count + raw_width_fact,
            normalized_fact_count=width_stats.normalized_fact_count + normalized_width_fact,
            classified_fact_count=width_stats.classified_fact_count + int(width_materialized),
            materialized_count=width_stats.materialized_count + int(width_materialized),
            failure_count=width_stats.failure_count + int(width_failure),
        )
        width = (
            slot_width
            if isinstance(slot_width, int) and slot_width > 0
            else max(2, _type_size_bytes_8616(arg_type, arch=arch))
        )
        cvar, cvar_changed = _ensure_arg_cvar_8616(
            codegen=codegen,
            offset=offset,
            name=name,
            variable_type=arg_type,
            width=width,
        )
        if cvar is None:
            continue
        for sibling_cvar in _iter_existing_stack_cvars_at_offset_8616(codegen, offset):
            cvar_changed = _apply_arg_cvar_surface_8616(sibling_cvar, name=name, variable_type=arg_type) or cvar_changed
        changed = cvar_changed or changed
        owned_ranges[offset] = width
        variable = cvar.variable
        if isinstance(variable, SimStackVariable):
            owner_variables.add(variable)
        arg_cvars.append(cvar)
        arg_types.append(arg_type)
        arg_names.append(name)
    if not arg_cvars:
        typed_codegen._inertia_stack_prototype_width_stats_8616 = width_stats
        parameter_width_facts = tuple(width_facts)
        typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
        _debug_parameter_width_facts_8616("materialize-empty", parameter_width_facts)
        return changed
    typed_codegen._inertia_stack_prototype_width_stats_8616 = width_stats
    parameter_width_facts = tuple(width_facts)
    typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
    _debug_parameter_width_facts_8616("materialize", parameter_width_facts)
    if width_stats.classified_fact_count > 0 and width_stats.materialized_count == 0:
        raise RuntimeError("stack prototype width evidence was classified but not materialized")
    changed = _prune_stack_slots_covered_by_wide_args_8616(codegen, owned_ranges, owner_variables) or changed
    existing_args = list(typed_cfunc.arg_list or ())
    if len(existing_args) != len(arg_cvars) or any(existing is not desired for existing, desired in zip(existing_args, arg_cvars)):
        typed_cfunc.arg_list = arg_cvars
        changed = True
    new_proto = SimTypeFunction(arg_types, return_type, arg_names=arg_names, variadic=variadic)
    if arch is not None:
        new_proto = _with_arch_8616(new_proto, arch)
    if not _prototype_equivalent_8616(typed_func.prototype, new_proto):
        typed_func.prototype = new_proto
        typed_func.is_prototype_guessed = False
        changed = True
    if not _prototype_equivalent_8616(typed_cfunc.functy, new_proto):
        typed_cfunc.functy = new_proto
        changed = True
    if changed:
        try:
            materialized_count = typed_codegen._inertia_annotated_stack_prototype_materialized_8616
        except AttributeError:
            materialized_count = 0
        typed_codegen._inertia_annotated_stack_prototype_materialized_8616 = (
            int(materialized_count or 0) + len(arg_cvars)
        )
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed
