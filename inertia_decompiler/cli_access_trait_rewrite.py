"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
import typing
from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
from .cli_access_rewrite_artifact import AccessRewriteArtifact

type StableHints = dict[BaseKey, AccessTraitObjectHint]
type ReplaceCChildren = Callable[[object, Callable[[object], object]], bool]


class _CFunctionLike(Protocol):
    """Structured C function surface needed by access-trait renaming."""

    addr: int
    statements: object
    variables_in_use: object


class _CodegenLike(Protocol):
    """Codegen surface needed by access-trait renaming."""

    cfunc: _CFunctionLike | None


def _should_attach_access_trait_names(
    codegen: object,
    *,
    has_access_rewrite_artifact: Callable[[object], bool],
) -> bool:
    return has_access_rewrite_artifact(codegen)


def _attach_access_trait_field_names(
    project: object,
    codegen: _CodegenLike,
    *,
    should_attach_access_trait_names: Callable[[object], bool],
    load_access_rewrite_artifact: Callable[[object, object], AccessRewriteArtifact | None],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[object], BaseKey | None],
    stack_object_name: Callable[[int], str],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    if not should_attach_access_trait_names(codegen):
        return False
    artifact = load_access_rewrite_artifact(project, cfunc.addr)
    if artifact is None or not artifact.object_hints:
        return False
    object_hints = artifact.object_hints

    def is_generic_stack_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def stack_rewrite_decision(variable: object) -> AccessTraitObjectHint | None:
        base_key = access_trait_variable_key(variable)
        if base_key is None:
            return None
        if base_key in artifact.refusal_reasons or (len(base_key) == 4 and base_key[:3] in artifact.refusal_reasons):
            return None
        return stable_access_object_hint_for_key(object_hints, base_key)

    changed = False

    def rename_stack_variable(cvar: structured_c.CVariable, *, suffix: int = 0) -> object | None:
        nonlocal changed
        # Dynamic codegen boundary: angr CVariable payloads are optional.
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        decision = stack_rewrite_decision(variable)
        if decision is None or not decision.should_rename_stack():
            return None
        name = variable.name
        if not is_generic_stack_name(name) and not (isinstance(name, str) and name.startswith("field_")):
            return None
        if decision.kind == "stack":
            field_name = stack_object_name(variable.offset)
        else:
            field_name = access_trait_field_name(suffix, variable.size)
        if variable.name != field_name:
            variable.name = field_name
            changed = True
        # Dynamic codegen boundary: structured C variables may expose a rendered name.
        if getattr(cvar, "name", None) != field_name:
            try:
                # Dynamic codegen boundary: angr CVariable.name is runtime-mutable despite a read-only stub.
                typing.cast(typing.Any, cvar).name = field_name
            except Exception:
                pass
            else:
                changed = True
        return typing.cast(object, cvar)

    def transform(node: object) -> object:
        if isinstance(node, structured_c.CVariable):
            renamed = rename_stack_variable(node, suffix=0)
            if renamed is not None:
                return renamed
        return node

    root = cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True
    return changed


def _attach_pointer_member_names(
    project: object,
    codegen: _CodegenLike,
    *,
    should_attach_access_trait_names: Callable[[object], bool],
    load_access_rewrite_artifact: Callable[[object, object], AccessRewriteArtifact | None],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[object], BaseKey | None],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren,
) -> bool:
    def _impl() -> bool:
        cfunc = codegen.cfunc
        if cfunc is None:
            return False
        if not should_attach_access_trait_names(codegen):
            return False
        artifact = load_access_rewrite_artifact(project, cfunc.addr)
        if artifact is None or not artifact.object_hints:
            return False
        object_hints = artifact.object_hints

        def is_generic_name(name: object) -> bool:
            return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

        def candidate_field_names(base_key: BaseKey) -> tuple[str, ...]:
            if base_key in artifact.refusal_reasons or (
                len(base_key) == 4 and base_key[:3] in artifact.refusal_reasons
            ):
                return ()
            hint = stable_access_object_hint_for_key(object_hints, base_key)
            if hint is None:
                return ()
            if hint.kind not in {"member", "array", "induction"}:
                return ()
            return typing.cast(
                tuple[str, ...],
                hint.candidate_field_names(access_trait_field_name=access_trait_field_name),
            )

        changed = False
        assigned_names: dict[int, str] = {}
        name_cursors: dict[BaseKey, int] = {}

        def assign_member_name(base_key: BaseKey) -> str | None:
            names = candidate_field_names(base_key)
            if not names:
                return None
            index = name_cursors.get(base_key, 0)
            if index < len(names):
                field_name = names[index]
                name_cursors[base_key] = index + 1
                return field_name
            return names[-1]

        variables_in_use = cfunc.variables_in_use
        if isinstance(variables_in_use, dict):
            for variable, cvar in list(variables_in_use.items()):
                if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                    continue
                # Dynamic codegen boundary: CVariable rendered names are optional.
                if not is_generic_name(variable.name) and not is_generic_name(getattr(cvar, "name", None)):
                    continue
                base_key = access_trait_variable_key(variable)
                if base_key is None:
                    continue
                field_name = assign_member_name(base_key)
                if field_name is None:
                    continue
                # Dynamic codegen boundary: CVariable may carry a unified variable payload.
                target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
                # Dynamic codegen boundary: target variable names are optional codegen metadata.
                if target is not None and getattr(target, "name", None) != field_name:
                    target.name = field_name
                    changed = True
                if variable.name != field_name:
                    variable.name = field_name
                    changed = True
                # Dynamic codegen boundary: CVariable rendered names are optional.
                if getattr(cvar, "name", None) != field_name:
                    cvar.name = field_name
                    changed = True
                assigned_names[id(variable)] = field_name

        def rename_member_variable(cvar: object) -> object | None:
            nonlocal changed
            if not isinstance(cvar, structured_c.CVariable):
                return None
            # Dynamic codegen boundary: angr CVariable payloads are optional.
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                return None
            # Dynamic codegen boundary: CVariable rendered names are optional.
            if not is_generic_name(variable.name) and not is_generic_name(getattr(cvar, "name", None)):
                return None
            base_key = access_trait_variable_key(variable)
            if base_key is None:
                return None
            field_name = assigned_names.get(id(variable))
            if field_name is None:
                field_name = assign_member_name(base_key)
            if field_name is None:
                return None
            if variable.name != field_name:
                variable.name = field_name
                changed = True
            # Dynamic codegen boundary: CVariable rendered names are optional.
            if getattr(cvar, "name", None) != field_name:
                try:
                    # Dynamic codegen boundary: angr CVariable.name is runtime-mutable despite a read-only stub.
                    typing.cast(typing.Any, cvar).name = field_name
                except Exception:
                    pass
                else:
                    changed = True
            renamed_cvar = typing.cast(object, cvar)
            return renamed_cvar
            return None

        def transform(node: object) -> object:
            if isinstance(node, structured_c.CVariable):
                renamed = rename_member_variable(node)
                if renamed is not None:
                    return renamed
            return node

        root = cfunc.statements
        new_root = transform(root)
        if new_root is not root:
            cfunc.statements = new_root
            root = new_root
            changed = True
        if replace_c_children(root, transform):
            changed = True
        return changed

    return _impl()
