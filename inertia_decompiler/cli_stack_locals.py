"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable


class _ArchLike(Protocol):
    """Architecture surface needed to size stack references."""

    byte_width: int


class _ProjectLike(Protocol):
    """Project surface needed by stack-local materialization."""

    arch: _ArchLike


class _CFunctionLike(Protocol):
    """Structured C function surface needed by stack-local materialization."""

    addr: int
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _CodegenLike(Protocol):
    """Codegen surface needed by stack-local materialization."""

    cfunc: _CFunctionLike | None


def _stack_type_for_size(size: int) -> SimType:
    return SimTypeChar(False) if size == 1 else SimTypeShort(False)


def _promote_direct_stack_cvariable(
    codegen: _CodegenLike, cvar: structured_c.CVariable, size: int, type_: SimType
) -> bool:
    def _impl() -> bool:
        changed = False

        # Dynamic codegen boundary: angr CVariable nodes expose optional SimVariable payloads.
        variable = getattr(cvar, "variable", None)
        if variable is None:
            return False
        # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
        target_base = getattr(variable, "base", None)
        # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
        target_offset = getattr(variable, "offset", None)

        def same_stack_slot(candidate: object) -> bool:
            return (
                isinstance(candidate, SimStackVariable)
                # Dynamic codegen boundary: stack variable identity comes from angr SimVariable fields.
                and getattr(candidate, "base", None) == target_base
                # Dynamic codegen boundary: stack variable identity comes from angr SimVariable fields.
                and getattr(candidate, "offset", None) == target_offset
            )

        def promote_view(candidate_var: object, candidate_cvar: structured_c.CVariable) -> None:
            nonlocal changed
            if not isinstance(candidate_var, SimStackVariable) or not same_stack_slot(candidate_var):
                return
            if candidate_var.size < size:
                candidate_var.size = size
                changed = True
            # Dynamic codegen boundary: angr CVariable type metadata is optional.
            if getattr(candidate_cvar, "variable_type", None) != type_:
                candidate_cvar.variable_type = type_
                changed = True

        promote_view(variable, cvar)

        # Dynamic codegen boundary: unified variables are optional codegen metadata.
        unified = getattr(cvar, "unified_variable", None)
        # Dynamic codegen boundary: unified variable size is optional codegen metadata.
        if unified is not None and getattr(unified, "size", 0) < size:
            try:
                unified.size = size
                changed = True
            except Exception:
                pass

        cfunc = codegen.cfunc
        if cfunc is None:
            return changed
        variables_in_use = cfunc.variables_in_use
        if isinstance(variables_in_use, dict):
            for tracked_var, tracked in list(variables_in_use.items()):
                if isinstance(tracked, structured_c.CVariable):
                    promote_view(tracked_var, tracked)

        unified_locals = cfunc.unified_local_vars
        if isinstance(unified_locals, dict):
            for tracked_var, cvar_and_vartypes in list(unified_locals.items()):
                if not same_stack_slot(tracked_var):
                    continue
                new_entries = set()
                for tracked_cvar, _vartype in cvar_and_vartypes:
                    # Dynamic codegen boundary: angr CVariable type metadata is optional.
                    if getattr(tracked_cvar, "variable_type", None) != type_:
                        tracked_cvar.variable_type = type_
                        changed = True
                    new_entries.add((tracked_cvar, type_))
                if new_entries != cvar_and_vartypes:
                    unified_locals[tracked_var] = new_entries
                    changed = True
                break

        return changed

    return _impl()


def _attach_ss_stack_variables(
    project: _ProjectLike,
    codegen: _CodegenLike,
    *,
    match_ss_stack_reference: Callable[[object, _ProjectLike], tuple[SimStackVariable, structured_c.CVariable, int] | None],
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], structured_c.CVariable],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> bool:
    def _impl() -> bool:
        cfunc = codegen.cfunc
        if cfunc is None:
            return False

        created: dict[tuple[int, int], structured_c.CVariable] = {}
        promoted: set[tuple[int, int]] = set()

        def _stack_object_name(offset: int) -> str:
            if offset >= 0:
                return f"arg_{offset:x}"
            return f"local_{-offset:x}"

        def _stack_local_name_or_existing(*names: str | None, offset: int) -> str:
            for name in names:
                if isinstance(name, str) and name and not re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
                    return name
            return _stack_object_name(offset)

        def transform(node: object) -> object:
            nonlocal promoted
            matched = match_ss_stack_reference(node, project)
            if matched is None:
                return node
            stack_var, ref_cvar, extra_offset = matched

            # Dynamic codegen boundary: angr C AST node type metadata is optional.
            type_ = getattr(node, "type", None)
            if type_ is None:
                return node

            # Dynamic codegen boundary: concrete angr SimType instances expose size.
            bits = getattr(type_, "size", None)
            size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
            final_offset = stack_var.offset + extra_offset
            promoted_offset = final_offset

            if size >= 4:
                resolved_cvar = resolve_stack_cvar_at_offset(codegen, final_offset)
                # Dynamic codegen boundary: resolved CVariable payloads are supplied by angr codegen.
                resolved_variable = getattr(resolved_cvar, "variable", None)
                if isinstance(resolved_variable, SimStackVariable):
                    # Dynamic codegen boundary: SimStackVariable offset is supplied by angr.
                    resolved_offset = getattr(resolved_variable, "offset", None)
                    if resolved_offset == final_offset:
                        _promote_direct_stack_cvariable(codegen, resolved_cvar, size, type_)
                        key = (final_offset, size)
                        promoted.add(key)
                        existing = created.get(key)
                        if existing is not None:
                            return existing
                        created[key] = resolved_cvar
                        return resolved_cvar

            key = (promoted_offset, size)
            promoted.add(key)
            existing = created.get(key)
            if existing is not None:
                return existing
            if extra_offset == 0:
                local_name = _stack_local_name_or_existing(
                    # Dynamic codegen boundary: names on CVariable/SimVariable payloads are optional.
                    getattr(ref_cvar, "name", None),
                    # Dynamic codegen boundary: names on CVariable/SimVariable payloads are optional.
                    getattr(stack_var, "name", None),
                    offset=promoted_offset,
                )
            else:
                local_name = _stack_object_name(promoted_offset)

            cvar = structured_c.CVariable(
                SimStackVariable(
                    promoted_offset,
                    size,
                    # Dynamic codegen boundary: SimStackVariable base is supplied by angr.
                    base=getattr(stack_var, "base", "bp"),
                    name=local_name,
                    region=cfunc.addr,
                ),
                variable_type=type_,
                codegen=codegen,
            )
            created[key] = cvar
            return cvar

        root = cfunc.statements
        new_root = transform(root)
        if new_root is not root:
            cfunc.statements = new_root
            root = new_root
            changed = True
        else:
            changed = False

        if replace_c_children(root, transform):
            changed = True

        variables_in_use = cfunc.variables_in_use
        for variable, cvar in variables_in_use.items() if isinstance(variables_in_use, dict) else ():
            identity = stack_slot_identity_for_variable(variable)
            if identity is None:
                continue
            # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
            offset = getattr(variable, "offset", None)
            matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
            if not matching:
                continue
            size = max(matching)
            target_type = _stack_type_for_size(size)
            # Dynamic codegen boundary: SimVariable size is supplied by angr.
            if getattr(variable, "size", 0) < size:
                variable.size = size
                changed = True
            # Dynamic codegen boundary: CVariable type metadata is optional.
            if getattr(cvar, "variable_type", None) != target_type:
                cvar.variable_type = target_type
                changed = True
            # Dynamic codegen boundary: unified variables are optional codegen metadata.
            unified = getattr(cvar, "unified_variable", None)
            # Dynamic codegen boundary: unified variable size is optional codegen metadata.
            if unified is not None and getattr(unified, "size", 0) < size:
                try:
                    unified.size = size
                    changed = True
                except Exception:
                    pass

        unified_locals = cfunc.unified_local_vars
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                identity = stack_slot_identity_for_variable(variable)
                if identity is None:
                    continue
                # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
                offset = getattr(variable, "offset", None)
                matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
                if not matching:
                    continue
                size = max(matching)
                target_type = _stack_type_for_size(size)
                new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
                if new_entries != cvar_and_vartypes:
                    unified_locals[variable] = new_entries
                    changed = True
        return changed

    return _impl()
