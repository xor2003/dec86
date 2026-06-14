from __future__ import annotations

import contextlib
import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

_STACK_BP_PLACEHOLDER_RE = re.compile(
    r"<[^>\n]*\|Stack\s+(?P<base>bp)(?P<sign>[+-])0x(?P<offset>[0-9A-Fa-f]+),\s*(?P<size>\d+)\s*B>"
)


def _materialized_stack_placeholder_variable(codegen, cvar, *, stack_type_for_size):
    variable = getattr(cvar, "variable", None)
    placeholder_name = getattr(variable, "name", None)
    if not isinstance(placeholder_name, str):
        placeholder_name = getattr(cvar, "name", None)
    if not isinstance(placeholder_name, str):
        return None

    match = _STACK_BP_PLACEHOLDER_RE.search(placeholder_name)
    if match is None:
        return None

    offset = int(match.group("offset"), 16)
    if match.group("sign") == "-":
        offset = -offset
    size = max(int(match.group("size")), 1)
    region = getattr(getattr(codegen, "cfunc", None), "addr", None)
    stack_var = SimStackVariable(
        offset,
        size,
        base=match.group("base"),
        name=f"s_{offset & 0xFFFF:x}",
        region=region,
    )
    variable_type = getattr(cvar, "variable_type", None)
    if variable_type is None:
        variable_type = stack_type_for_size(size)
    return stack_var, variable_type


def _is_materialized_named_stack_cvar(node) -> bool:
    if not isinstance(node, structured_c.CVariable):
        return False
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return False
    name = getattr(node, "name", None) or getattr(variable, "name", None)
    if not isinstance(name, str):
        return False
    if _STACK_BP_PLACEHOLDER_RE.search(name) is not None:
        return False
    return re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is None


def _generic_stack_local_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is not None
    )


def _stack_name_from_cvar(cvar) -> str | None:
    for candidate in (
        getattr(cvar, "name", None),
        getattr(getattr(cvar, "variable", None), "name", None),
        getattr(getattr(cvar, "unified_variable", None), "name", None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _set_stack_cvar_name(cvar, name: str) -> bool:
    changed = False
    for target in (
        getattr(cvar, "variable", None),
        getattr(cvar, "unified_variable", None),
    ):
        if target is None:
            continue
        with contextlib.suppress(Exception):
            if getattr(target, "name", None) != name:
                target.name = name
                changed = True
    with contextlib.suppress(Exception):
        if getattr(cvar, "name", None) != name:
            cvar.name = name
            changed = True
    return changed


def _canonical_stack_declaration_name(
    variable,
    *,
    identity,
    arg_variables: set[int],
    arg_identities: set[object],
) -> str | None:
    if not isinstance(variable, SimStackVariable):
        return None
    offset = getattr(identity, "offset", getattr(variable, "offset", None))
    if not isinstance(offset, int):
        return None
    if id(variable) in arg_variables or identity in arg_identities:
        return f"arg_{offset:x}"
    if offset >= 0:
        return f"local_{offset:x}"
    return f"local_{-offset:x}"


def _normalize_generic_stack_cvar_name(
    cvar,
    *,
    identity,
    arg_variables: set[int],
    arg_identities: set[object],
) -> bool:
    current = _stack_name_from_cvar(cvar)
    if not _generic_stack_local_name(current):
        return False
    new_name = _canonical_stack_declaration_name(
        getattr(cvar, "variable", None),
        identity=identity,
        arg_variables=arg_variables,
        arg_identities=arg_identities,
    )
    if not isinstance(new_name, str) or not new_name or new_name == current:
        return False
    return _set_stack_cvar_name(cvar, new_name)


def _sync_unified_stack_local_names_from_live_cvars(
    *,
    cfunc,
    unified_locals,
    stack_slot_identity_for_variable,
    iter_c_nodes_deep,
) -> bool:
    root = getattr(cfunc, "statements", None)
    if root is None or not isinstance(unified_locals, dict):
        return False

    live_name_by_identity: dict[object, str] = {}
    for node in iter_c_nodes_deep(root):
        if not _is_materialized_named_stack_cvar(node):
            continue
        variable = getattr(node, "variable", None)
        identity = stack_slot_identity_for_variable(variable)
        if identity is None or identity in live_name_by_identity:
            continue
        name = _stack_name_from_cvar(node)
        if isinstance(name, str) and name and not _generic_stack_local_name(name):
            live_name_by_identity[identity] = name

    if not live_name_by_identity:
        return False

    changed = False
    for variable, entries in list(unified_locals.items()):
        identity = stack_slot_identity_for_variable(variable)
        name = live_name_by_identity.get(identity)
        if name is None:
            continue
        current = getattr(variable, "name", None)
        if isinstance(current, str) and current and not _generic_stack_local_name(current) and current != name:
            continue
        with contextlib.suppress(Exception):
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
        if not isinstance(entries, set):
            continue
        rebuilt = set()
        for cvar, vartype in entries:
            changed = _set_stack_cvar_name(cvar, name) or changed
            rebuilt.add((cvar, vartype))
        unified_locals[variable] = rebuilt
    return changed


def _make_placeholder_canonicalizer(
    *,
    codegen,
    stack_type_for_size,
    variables_in_use,
    stack_local_candidates,
    placeholder_cache: dict[str, structured_c.CVariable],
    changed_ref: dict[str, bool],
):
    def _canonical_placeholder_cvar(node):
        if not isinstance(node, structured_c.CVariable):
            return node
        replacement = _materialized_stack_placeholder_variable(
            codegen,
            node,
            stack_type_for_size=stack_type_for_size,
        )
        if replacement is None:
            return node
        stack_var, variable_type = replacement
        key = getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)
        if isinstance(key, str) and key in placeholder_cache:
            return placeholder_cache[key]
        original_var = getattr(node, "variable", None)
        try:
            node.variable = stack_var
        except Exception:
            replacement_cvar = structured_c.CVariable(stack_var, variable_type=variable_type, codegen=codegen)
            if isinstance(key, str):
                placeholder_cache[key] = replacement_cvar
            if isinstance(variables_in_use, dict):
                if original_var in variables_in_use:
                    variables_in_use.pop(original_var, None)
                variables_in_use[stack_var] = replacement_cvar
            if isinstance(stack_local_candidates, dict):
                stack_local_candidates[id(stack_var)] = (stack_var, replacement_cvar)
            changed_ref["changed"] = True
            return replacement_cvar
        node.variable_type = variable_type
        replacement_cvar = node
        replacement_var = stack_var
        if isinstance(variables_in_use, dict):
            if original_var in variables_in_use:
                variables_in_use.pop(original_var, None)
            variables_in_use[replacement_var] = replacement_cvar
        if isinstance(stack_local_candidates, dict):
            if original_var is not None:
                stack_local_candidates.pop(id(original_var), None)
            stack_local_candidates[id(replacement_var)] = (replacement_var, replacement_cvar)
        if isinstance(key, str):
            placeholder_cache[key] = replacement_cvar
        changed_ref["changed"] = True
        return replacement_cvar

    return _canonical_placeholder_cvar


def _prune_dead_placeholder_variables(
    *,
    cfunc,
    variables_in_use,
    stack_local_candidates,
    unified_locals,
    iter_c_nodes_deep,
) -> bool:
    def _impl():
        root = getattr(cfunc, "statements", None)
        if not isinstance(variables_in_use, dict) or root is None:
            return False
        changed = False
        live_variable_ids = {
            id(getattr(node, "variable", None))
            for node in iter_c_nodes_deep(cfunc.statements)
            if isinstance(node, structured_c.CVariable) and getattr(node, "variable", None) is not None
        }
        for variable in list(variables_in_use):
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or _STACK_BP_PLACEHOLDER_RE.search(name) is None:
                continue
            if id(variable) in live_variable_ids:
                continue
            variables_in_use.pop(variable, None)
            if isinstance(stack_local_candidates, dict):
                stack_local_candidates.pop(id(variable), None)
            unified_locals.pop(variable, None)
            changed = True
        return changed

    return _impl()


def _materialize_unified_stack_locals(
    *,
    source_variables,
    unified_locals,
    arg_variables,
    arg_identities,
    existing_identities,
    stack_slot_identity_for_variable,
    stack_type_for_size,
) -> bool:
    changed = False
    for variable, cvar in source_variables:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if id(variable) in arg_variables or identity in arg_identities:
            continue
        if _normalize_generic_stack_cvar_name(
            cvar,
            identity=identity,
            arg_variables=arg_variables,
            arg_identities=arg_identities,
        ):
            changed = True
        if identity is None or identity in existing_identities:
            continue
        variable_type = getattr(cvar, "variable_type", None)
        if variable_type is None:
            variable_type = stack_type_for_size(getattr(variable, "size", 0) or 2)
        unified_locals[variable] = {(cvar, variable_type)}
        existing_identities.add(identity)
        changed = True
    return changed


def _materialize_missing_stack_local_declarations(
    codegen,
    *,
    stack_slot_identity_for_variable,
    stack_type_for_size,
    replace_c_children,
    iter_c_nodes_deep,
):
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        unified_locals = getattr(cfunc, "unified_local_vars", None)
        if not isinstance(unified_locals, dict):
            unified_locals = {}
            setattr(cfunc, "unified_local_vars", unified_locals)

        arg_variables = {
            id(getattr(arg, "variable", None))
            for arg in getattr(cfunc, "arg_list", ()) or ()
            if getattr(arg, "variable", None) is not None
        }
        arg_identities = {
            stack_slot_identity_for_variable(getattr(arg, "variable", None))
            for arg in getattr(cfunc, "arg_list", ()) or ()
            if isinstance(getattr(arg, "variable", None), SimStackVariable)
        }
        arg_identities.discard(None)
        existing_identities = {
            identity
            for variable in unified_locals
            for identity in (stack_slot_identity_for_variable(variable),)
            if identity is not None
        }

        stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
        source_by_id: dict[int, tuple[object, object]] = {}
        if isinstance(stack_local_candidates, dict):
            for variable, cvar in stack_local_candidates.values():
                source_by_id[id(variable)] = (variable, cvar)
        variables_in_use_obj = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use_obj, dict):
            for variable, cvar in variables_in_use_obj.items():
                source_by_id.setdefault(id(variable), (variable, cvar))

        changed_ref = {"changed": False}
        placeholder_cache: dict[str, structured_c.CVariable] = {}
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        _canonical_placeholder_cvar = _make_placeholder_canonicalizer(
            codegen=codegen,
            stack_type_for_size=stack_type_for_size,
            variables_in_use=variables_in_use,
            stack_local_candidates=stack_local_candidates,
            placeholder_cache=placeholder_cache,
            changed_ref=changed_ref,
        )

        root = getattr(cfunc, "statements", None)
        if root is not None:
            new_root = _canonical_placeholder_cvar(root)
            if new_root is not root:
                cfunc.statements = new_root
                if hasattr(cfunc, "body"):
                    cfunc.body = new_root
            if replace_c_children(cfunc.statements, _canonical_placeholder_cvar):
                changed_ref["changed"] = True
            existing_identities.update(
                identity
                for node in iter_c_nodes_deep(cfunc.statements)
                if _is_materialized_named_stack_cvar(node)
                for identity in (stack_slot_identity_for_variable(getattr(node, "variable", None)),)
                if identity is not None
            )
            for node in iter_c_nodes_deep(cfunc.statements):
                if not isinstance(node, structured_c.CVariable):
                    continue
                variable = getattr(node, "variable", None)
                if isinstance(variable, SimStackVariable):
                    source_by_id.setdefault(id(variable), (variable, node))
            if _sync_unified_stack_local_names_from_live_cvars(
                cfunc=cfunc,
                unified_locals=unified_locals,
                stack_slot_identity_for_variable=stack_slot_identity_for_variable,
                iter_c_nodes_deep=iter_c_nodes_deep,
            ):
                changed_ref["changed"] = True
                codegen._inertia_stack_declaration_name_synced_count_8616 = (
                    int(getattr(codegen, "_inertia_stack_declaration_name_synced_count_8616", 0) or 0) + 1
                )
        if _prune_dead_placeholder_variables(
            cfunc=cfunc,
            variables_in_use=variables_in_use,
            stack_local_candidates=stack_local_candidates,
            unified_locals=unified_locals,
            iter_c_nodes_deep=iter_c_nodes_deep,
        ):
            changed_ref["changed"] = True

        if _materialize_unified_stack_locals(
            source_variables=tuple(source_by_id.values()),
            unified_locals=unified_locals,
            arg_variables=arg_variables,
            arg_identities=arg_identities,
            existing_identities=existing_identities,
            stack_slot_identity_for_variable=stack_slot_identity_for_variable,
            stack_type_for_size=stack_type_for_size,
        ):
            changed_ref["changed"] = True

        if changed_ref["changed"]:
            sort_local_vars = getattr(cfunc, "sort_local_vars", None)
            if callable(sort_local_vars):
                with contextlib.suppress(Exception):
                    sort_local_vars()
        return changed_ref["changed"]

    return _impl()


def _dedupe_codegen_variable_names_8616(codegen, *, make_unique_identifier):
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
            return False

        def is_generic_name(name: object) -> bool:
            return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

        def preferred_name(variable, cvar) -> str | None:
            candidates = [
                getattr(variable, "name", None),
                getattr(cvar, "name", None),
                getattr(getattr(cvar, "unified_variable", None), "name", None),
            ]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate and not is_generic_name(candidate):
                    return candidate
            for candidate in candidates:
                if isinstance(candidate, str) and candidate:
                    return candidate
            return None

        def normalize_sort_ident(variable, cvar) -> None:
            ident = getattr(variable, "ident", None)
            if isinstance(ident, str):
                return
            fallback = preferred_name(variable, cvar)
            if not isinstance(fallback, str) or not fallback:
                fallback = getattr(variable, "name", None)
            if not isinstance(fallback, str) or not fallback:
                fallback = f"var_{id(variable):x}"
            try:
                variable.ident = fallback if ident is None else str(ident)
            except Exception:
                pass

        def sort_key(item):
            variable, cvar = item
            variable_name = getattr(variable, "name", None)
            cvar_name = getattr(cvar, "name", None)
            variable_name_key = variable_name if isinstance(variable_name, str) else ""
            cvar_name_key = cvar_name if isinstance(cvar_name, str) else ""
            if isinstance(variable, SimStackVariable):
                offset = getattr(variable, "offset", 0)
                size = getattr(variable, "size", 0)
                return (
                    0,
                    0 if isinstance(offset, int) and offset > 0 else 1,
                    offset if isinstance(offset, int) else 0,
                    -size if isinstance(size, int) else 0,
                    variable_name_key,
                )
            if isinstance(variable, SimRegisterVariable):
                reg = getattr(variable, "reg", 0)
                return (
                    1,
                    reg if isinstance(reg, int) else 0,
                    getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                    variable_name_key,
                )
            if isinstance(variable, SimMemoryVariable):
                addr = getattr(variable, "addr", 0)
                return (
                    2,
                    addr if isinstance(addr, int) else 0,
                    getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                    variable_name_key,
                )
            return (3, variable_name_key, cvar_name_key)

        ordered_items = []
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
            variable = getattr(arg, "variable", None)
            if variable is not None:
                ordered_items.append((variable, arg))
        ordered_items.extend(list(variables_in_use.items()) if isinstance(variables_in_use, dict) else [])
        if isinstance(unified_locals, dict):
            for variable, cvars in unified_locals.items():
                if variable not in variables_in_use and cvars:
                    ordered_items.append((variable, next(iter(cvars))[0]))

        ordered_items.sort(key=sort_key)

        used_names: set[str] = set()
        seen_variables: set[int] = set()
        changed = False

        def apply_name(variable, cvar, new_name: str) -> None:
            nonlocal changed
            if getattr(variable, "name", None) != new_name:
                variable.name = new_name
                changed = True
            if getattr(cvar, "name", None) != new_name:
                try:
                    cvar.name = new_name
                except Exception:
                    pass
                else:
                    changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != new_name:
                unified.name = new_name
                changed = True

        for variable, cvar in ordered_items:
            if id(variable) in seen_variables:
                continue
            seen_variables.add(id(variable))
            normalize_sort_ident(variable, cvar)
            name = preferred_name(variable, cvar)
            if name is None:
                continue
            if name in used_names:
                name = make_unique_identifier(name, used_names)
            else:
                used_names.add(name)
            apply_name(variable, cvar, name)

        if changed:
            sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
            if callable(sort_local_vars):
                with contextlib.suppress(Exception):
                    sort_local_vars()
        return changed

    return _impl()


def _materialize_missing_register_local_declarations(
    codegen,
    *,
    stack_slot_identity_for_variable,
    stack_type_for_size,
    structured_codegen_node,
    iter_c_nodes_deep,
):
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        unified_locals = getattr(cfunc, "unified_local_vars", None)
        if not isinstance(unified_locals, dict):
            unified_locals = {}
            setattr(cfunc, "unified_local_vars", unified_locals)

        arg_variables = {
            id(getattr(arg, "variable", None))
            for arg in getattr(cfunc, "arg_list", ()) or ()
            if getattr(arg, "variable", None) is not None
        }

        def _local_identity(variable) -> tuple[object, ...] | None:
            if isinstance(variable, SimStackVariable):
                identity = stack_slot_identity_for_variable(variable)
                if identity is not None:
                    return ("stack", identity.base, getattr(identity, "offset", None), getattr(variable, "size", None))
                return (
                    "stack",
                    getattr(variable, "base", None),
                    getattr(variable, "offset", None),
                    getattr(variable, "size", None),
                )
            if isinstance(variable, SimRegisterVariable):
                return ("reg", getattr(variable, "reg", None), getattr(variable, "size", None))
            return None

        existing_identities = {
            identity for variable in unified_locals if (identity := _local_identity(variable)) is not None
        }

        desired_segment_regs = {"cs", "ds", "es", "ss", "fs", "gs", "flags"}
        changed = False

        register_candidates: dict[int, tuple[object, object]] = {}
        for variable, cvar in getattr(cfunc, "variables_in_use", {}).items():
            if isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                register_candidates[id(variable)] = (variable, cvar)

        root = getattr(cfunc, "statements", None)
        if structured_codegen_node(root):
            for node in iter_c_nodes_deep(root):
                if not isinstance(node, structured_c.CVariable):
                    continue
                variable = getattr(node, "variable", None)
                if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                    continue
                register_candidates.setdefault(id(variable), (variable, node))

        for variable, cvar in register_candidates.values():
            identity = _local_identity(variable)
            if id(variable) in arg_variables:
                continue
            if isinstance(variable, SimRegisterVariable):
                declared_variable = next(
                    (
                        candidate
                        for candidate in unified_locals
                        if isinstance(candidate, SimRegisterVariable) and candidate == variable
                    ),
                    None,
                )
                if declared_variable is not None:
                    if getattr(cvar, "unified_variable", None) is not declared_variable:
                        with contextlib.suppress(Exception):
                            cvar.unified_variable = declared_variable
                            changed = True
                    continue
            elif identity in existing_identities:
                continue

            reg_name = getattr(variable, "name", None)
            if isinstance(reg_name, str) and reg_name in desired_segment_regs:
                continue

            variable_type = getattr(cvar, "variable_type", None)
            if variable_type is None:
                variable_type = stack_type_for_size(getattr(variable, "size", 0) or 2)
            if variable_type is None:
                continue

            unified_locals[variable] = {(cvar, variable_type)}
            if identity is not None:
                existing_identities.add(identity)
            changed = True

        if changed:
            sort_local_vars = getattr(cfunc, "sort_local_vars", None)
            if callable(sort_local_vars):
                with contextlib.suppress(Exception):
                    sort_local_vars()
        return changed

    return _impl()


def _prune_void_function_return_values(codegen, *, iter_c_nodes_deep):
    if getattr(codegen, "cfunc", None) is None:
        return False

    prototype = None
    for candidate in (
        getattr(codegen.cfunc, "prototype", None),
        getattr(codegen.cfunc, "functy", None),
        getattr(getattr(codegen, "_func", None), "prototype", None),
        getattr(getattr(codegen, "_inertia_current_function_8616", None), "prototype", None),
    ):
        if candidate is not None and getattr(candidate, "returnty", None) is not None:
            prototype = candidate
            break
    returnty = getattr(prototype, "returnty", None) if prototype is not None else None
    if type(returnty) is not SimTypeBottom or getattr(returnty, "label", None) != "void":
        return False

    if not getattr(codegen, "cfunc", None):
        return False
    changed = False
    for container in tuple(iter_c_nodes_deep(codegen.cfunc.statements)):
        if not isinstance(container, structured_c.CStatements):
            continue
        statements = list(getattr(container, "statements", ()) or ())
        if not statements:
            continue
        is_root_container = container is codegen.cfunc.statements
        rewritten: list[object] = []
        local_changed = False
        for index, stmt in enumerate(statements):
            if not isinstance(stmt, structured_c.CReturn):
                rewritten.append(stmt)
                continue
            retval = getattr(stmt, "retval", None)
            if retval is None:
                rewritten.append(stmt)
                continue
            if isinstance(retval, structured_c.CFunctionCall):
                rewritten.append(structured_c.CExpressionStatement(retval, codegen=getattr(stmt, "codegen", codegen)))
                if not (is_root_container and index == len(statements) - 1):
                    rewritten.append(structured_c.CReturn(None, codegen=getattr(stmt, "codegen", codegen)))
            else:
                stmt.retval = None
                rewritten.append(stmt)
            local_changed = True
        if local_changed:
            container.statements = (
                rewritten if isinstance(getattr(container, "statements", None), list) else tuple(rewritten)
            )
            changed = True

    return changed
