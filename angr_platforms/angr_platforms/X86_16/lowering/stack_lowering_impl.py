from __future__ import annotations

# Layer: Lowering
# Responsibility: stack-slot/cvar lowering from typed alias evidence.
# Forbidden: rendered-text parsing and CLI guess-based recovery.

import contextlib
import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer
from angr.sim_variable import SimStackVariable

from ..decompiler_postprocess_utils import _match_bp_stack_dereference_8616

def _resolve_stack_cvar_at_offset(codegen, offset: int, *, stack_slot_identity_for_variable):
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    arg_candidates: list[tuple[object, object]] = []
    arg_variable_ids = {
        id(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    arg_slot_identities = {
        stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_slot_identities.discard(None)
    for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable):
            arg_candidates.append((variable, arg))

    best_exact = None
    best_exact_score = None
    best_covering = None
    best_covering_score = None

    def _stack_name_is_generic(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(
            r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)",
            name,
        ) is not None

    def _stack_candidate_score(variable, cvar, *, exact: bool):
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            return (-1, -1, -1, -1, -1)
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
        preferred_name = next(
            (
                name
                for name in (variable_name, cvar_name, unified_name)
                if isinstance(name, str) and name and not _stack_name_is_generic(name)
            ),
            None,
        )
        is_arg_variable = 1 if id(variable) in arg_variable_ids else 0
        is_arg_slot = 1 if identity in arg_slot_identities else 0
        has_preferred_name = 1 if preferred_name is not None else 0
        size = getattr(variable, "size", None)
        size_rank = -size if isinstance(size, int) else 0
        exact_rank = 1 if exact else 0
        return (exact_rank, is_arg_variable, is_arg_slot, has_preferred_name, size_rank, -getattr(variable, "offset", 0))

    candidates = list(arg_candidates)
    candidates.extend(list(getattr(codegen.cfunc, "variables_in_use", {}).items()))

    for variable, cvar in candidates:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue

        base_offset = getattr(variable, "offset", None)
        size = getattr(variable, "size", None)
        if not isinstance(base_offset, int) or not isinstance(size, int):
            continue

        if base_offset == offset:
            score = _stack_candidate_score(variable, cvar, exact=True)
            if best_exact_score is None or score > best_exact_score:
                best_exact = cvar
                best_exact_score = score
            continue

        if base_offset <= offset < base_offset + size:
            score = _stack_candidate_score(variable, cvar, exact=False)
            if best_covering_score is None or score > best_covering_score:
                best_covering = cvar
                best_covering_score = score

    if best_exact is not None:
        return best_exact
    return best_covering


def _materialize_stack_cvar_at_offset(
    codegen,
    offset: int,
    size: int = 2,
    *,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    stack_type_for_size,
):
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    resolved = resolve_stack_cvar_at_offset(codegen, offset)
    resolved_variable = getattr(resolved, "variable", None)
    if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "offset", None) == offset:
        target_type = stack_type_for_size(size)
        promote_direct_stack_cvariable(codegen, resolved, size, target_type)
        return resolved

    target_type = stack_type_for_size(size)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset),
        region=getattr(codegen.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[id(variable)] = (variable, cvar)

    sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cvar


def _canonicalize_stack_cvar_expr(
    expr,
    codegen,
    *,
    unwrap_c_casts,
    resolve_stack_cvar_at_offset,
    materialize_stack_cvar_at_offset=None,
    active_expr_ids: set[int] | None = None,
):
    expr = unwrap_c_casts(expr)
    if active_expr_ids is None:
        active_expr_ids = set()
    expr_id = id(expr)
    if expr_id in active_expr_ids:
        return expr
    active_expr_ids.add(expr_id)

    def _iter_statement_nodes(root):
        stack = [root]
        seen_nodes: set[int] = set()
        while stack:
            node = stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            yield node
            for attr in ("statements", "condition_and_nodes", "else_node", "lhs", "rhs", "operand", "expr", "init", "condition", "iteration", "body", "args", "operands"):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if value is None:
                    continue
                if isinstance(value, list | tuple):
                    for item in reversed(tuple(value)):
                        if isinstance(item, tuple):
                            for nested in reversed(item):
                                stack.append(nested)
                        else:
                            stack.append(item)
                else:
                    stack.append(value)

    def _is_pointer_capable_stack_variable(var: object, cvar: object | None = None) -> bool:
        if not isinstance(var, SimStackVariable):
            return False
        if getattr(var, "base", None) != "bp":
            return False
        size = getattr(var, "size", None)
        if isinstance(size, int) and size >= 2:
            return True
        var_type = getattr(cvar, "variable_type", None)
        return isinstance(var_type, SimTypePointer)

    def _stack_pointer_aliases():
        cached = getattr(codegen, "_inertia_stack_pointer_aliases_for_cvars", None)
        cache_key = getattr(codegen.cfunc, "statements", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is cache_key:
            return cached[1]

        aliases: dict[int, tuple[object, int]] = {}

        def _resolve_stack_pointer_alias(node):
            node = unwrap_c_casts(node)
            if isinstance(node, structured_c.CVariable):
                variable = getattr(node, "variable", None)
                alias = aliases.get(id(variable))
                if alias is not None:
                    return alias
                if _is_pointer_capable_stack_variable(variable, node):
                    if getattr(variable, "base", None) == "bp":
                        return node, 0
                return None
            if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
                operand = unwrap_c_casts(node.operand)
                if isinstance(operand, structured_c.CVariable):
                    variable = getattr(operand, "variable", None)
                    if isinstance(variable, SimStackVariable):
                        if getattr(variable, "base", None) == "bp":
                            return operand, 0
                return None
            if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
                lhs = _resolve_stack_pointer_alias(node.lhs)
                rhs = _resolve_stack_pointer_alias(node.rhs)
                lhs_value = getattr(unwrap_c_casts(node.lhs), "value", None)
                rhs_value = getattr(unwrap_c_casts(node.rhs), "value", None)
                if lhs is not None and isinstance(rhs_value, int):
                    base, offset = lhs
                    return base, offset + (rhs_value if node.op == "Add" else -rhs_value)
                if rhs is not None and isinstance(lhs_value, int) and node.op == "Add":
                    base, offset = rhs
                    return base, offset + lhs_value
            return None

        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is not None:
            for _ in range(3):
                changed_local = False
                for node in _iter_statement_nodes(root):
                    if not isinstance(node, structured_c.CAssignment):
                        continue
                    lhs = unwrap_c_casts(getattr(node, "lhs", None))
                    if not isinstance(lhs, structured_c.CVariable):
                        continue
                    lhs_var = getattr(lhs, "variable", None)
                    if not isinstance(lhs_var, SimStackVariable) or getattr(lhs_var, "base", None) != "bp":
                        continue
                    resolved = _resolve_stack_pointer_alias(getattr(node, "rhs", None))
                    if resolved is None:
                        continue
                    if not _is_pointer_capable_stack_variable(lhs_var, lhs):
                        # Accept tiny stack temporaries that are proved to carry a stack pointer.
                        # These appear in helper prologue/epilogue carrier patterns.
                        rhs_expr = unwrap_c_casts(getattr(node, "rhs", None))
                        if not (
                            isinstance(rhs_expr, structured_c.CUnaryOp)
                            and rhs_expr.op == "Reference"
                            or isinstance(rhs_expr, structured_c.CBinaryOp)
                        ):
                            continue
                    if aliases.get(id(lhs_var)) != resolved:
                        aliases[id(lhs_var)] = resolved
                        changed_local = True
                if not changed_local:
                    break

        setattr(codegen, "_inertia_stack_pointer_aliases_for_cvars", (cache_key, aliases))
        return aliases

    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                resolved = resolve_stack_cvar_at_offset(codegen, offset)
                if isinstance(resolved, structured_c.CVariable):
                    active_expr_ids.discard(expr_id)
                    return resolved
                resolved_variable = getattr(resolved, "variable", None)
                if isinstance(resolved_variable, SimStackVariable):
                    variable_type = getattr(resolved, "variable_type", None) or getattr(expr, "variable_type", None)
                    active_expr_ids.discard(expr_id)
                    return structured_c.CVariable(resolved_variable, variable_type=variable_type, codegen=codegen)
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CIndexedVariable):
        base_expr = _canonicalize_stack_cvar_expr(
            expr.variable,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        index_expr = _canonicalize_stack_cvar_expr(
            expr.index,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        base_ref = unwrap_c_casts(base_expr)
        if isinstance(base_ref, structured_c.CUnaryOp) and base_ref.op == "Reference":
            base_var_expr = unwrap_c_casts(base_ref.operand)
            base_var = getattr(base_var_expr, "variable", None)
            index_value = getattr(index_expr, "value", None)
            if isinstance(base_var_expr, structured_c.CVariable) and isinstance(base_var, SimStackVariable) and isinstance(index_value, int):
                alias_state = _stack_pointer_aliases().get(id(base_var))
                if alias_state is not None:
                    alias_base_expr, alias_offset = alias_state
                    alias_base_var = getattr(alias_base_expr, "variable", None)
                    target_offset = getattr(alias_base_var, "offset", None)
                    if isinstance(target_offset, int):
                        target_offset += alias_offset
                else:
                    target_offset = getattr(base_var, "offset", None)
                if isinstance(target_offset, int):
                    resolved_offset = target_offset + index_value
                    resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset)
                    resolved_var = getattr(resolved, "variable", None)
                    if (
                        isinstance(resolved, structured_c.CVariable)
                        and isinstance(resolved_var, SimStackVariable)
                        and getattr(resolved_var, "offset", None) == resolved_offset
                    ):
                        active_expr_ids.discard(expr_id)
                        return resolved
                    arch = getattr(getattr(codegen, "project", None), "arch", None)
                    byte_width = getattr(arch, "byte_width", None)
                    type_size_bits = getattr(getattr(expr, "type", None), "size", None)
                    requested_size = (
                        max(type_size_bits // byte_width, 1)
                        if isinstance(type_size_bits, int) and type_size_bits > 0 and isinstance(byte_width, int) and byte_width > 0
                        else None
                    )
                    base_size = getattr(base_var, "size", None)
                    if (
                        callable(materialize_stack_cvar_at_offset)
                        and isinstance(requested_size, int)
                        and isinstance(base_size, int)
                        and requested_size > base_size
                    ):
                        materialized = materialize_stack_cvar_at_offset(codegen, resolved_offset, requested_size)
                        materialized_var = getattr(materialized, "variable", None)
                        if (
                            isinstance(materialized, structured_c.CVariable)
                            and isinstance(materialized_var, SimStackVariable)
                            and getattr(materialized_var, "offset", None) == resolved_offset
                        ):
                            active_expr_ids.discard(expr_id)
                            return materialized
                    if callable(materialize_stack_cvar_at_offset):
                        materialized = materialize_stack_cvar_at_offset(
                            codegen,
                            resolved_offset,
                            requested_size if isinstance(requested_size, int) and requested_size > 0 else 1,
                        )
                        materialized_var = getattr(materialized, "variable", None)
                        if (
                            isinstance(materialized, structured_c.CVariable)
                            and isinstance(materialized_var, SimStackVariable)
                            and getattr(materialized_var, "offset", None) == resolved_offset
                        ):
                            active_expr_ids.discard(expr_id)
                            return materialized
        if base_expr is not expr.variable or index_expr is not expr.index:
            active_expr_ids.discard(expr_id)
            return structured_c.CIndexedVariable(base_expr, index_expr, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CUnaryOp):
        operand = _canonicalize_stack_cvar_expr(
            expr.operand,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        deref_operand = unwrap_c_casts(operand)
        if expr.op == "Dereference":
            project = getattr(codegen, "project", None)
            displacement = _match_bp_stack_dereference_8616(
                structured_c.CUnaryOp(expr.op, deref_operand, codegen=getattr(expr, "codegen", None)),
                project,
                codegen,
            )
            if isinstance(displacement, int):
                type_bits = getattr(getattr(expr, "type", None), "size", None)
                arch = getattr(getattr(codegen, "project", None), "arch", None)
                byte_width = getattr(arch, "byte_width", None)
                access_size = (
                    max(type_bits // byte_width, 1)
                    if isinstance(type_bits, int) and type_bits > 0 and isinstance(byte_width, int) and byte_width > 0
                    else 2
                )
                resolved = resolve_stack_cvar_at_offset(codegen, displacement)
                resolved_var = getattr(resolved, "variable", None)
                if (
                    isinstance(resolved, structured_c.CVariable)
                    and isinstance(resolved_var, SimStackVariable)
                    and getattr(resolved_var, "offset", None) == displacement
                ):
                    active_expr_ids.discard(expr_id)
                    return resolved
                if callable(materialize_stack_cvar_at_offset):
                    materialized = materialize_stack_cvar_at_offset(codegen, displacement, access_size)
                    materialized_var = getattr(materialized, "variable", None)
                    if (
                        isinstance(materialized, structured_c.CVariable)
                        and isinstance(materialized_var, SimStackVariable)
                        and getattr(materialized_var, "offset", None) == displacement
                    ):
                        active_expr_ids.discard(expr_id)
                        return materialized
        if (
            expr.op == "Dereference"
            and isinstance(deref_operand, structured_c.CUnaryOp)
            and deref_operand.op == "Reference"
        ):
            referenced = unwrap_c_casts(deref_operand.operand)
            if isinstance(referenced, (structured_c.CVariable, structured_c.CIndexedVariable)):
                active_expr_ids.discard(expr_id)
                return referenced
        if operand is not expr.operand:
            active_expr_ids.discard(expr_id)
            return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CBinaryOp):
        lhs = _canonicalize_stack_cvar_expr(
            expr.lhs,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        rhs = _canonicalize_stack_cvar_expr(
            expr.rhs,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if lhs is not expr.lhs or rhs is not expr.rhs:
            active_expr_ids.discard(expr_id)
            return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CTypeCast):
        inner = _canonicalize_stack_cvar_expr(
            expr.expr,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if inner is not expr.expr:
            active_expr_ids.discard(expr_id)
            return structured_c.CTypeCast(None, expr.type, inner, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    active_expr_ids.discard(expr_id)
    return expr


def _canonicalize_stack_cvars(codegen, *, replace_c_children, canonicalize_stack_cvar_expr) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        canonical = canonicalize_stack_cvar_expr(node, codegen)
        if canonical is not node:
            changed = True
            return canonical
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed


def _resolve_stack_cvar_from_addr_expr(
    project,
    codegen,
    addr_expr,
    *,
    classify_segmented_addr_expr,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    materialize_stack_cvar_at_offset,
    stack_type_for_size,
):
    classified = classify_segmented_addr_expr(addr_expr, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        return None

    variable = getattr(classified.cvar, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None

    target_offset = getattr(variable, "offset", None)
    if not isinstance(target_offset, int):
        return None

    resolved_offset = target_offset + classified.extra_offset
    resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset)
    resolved_variable = getattr(resolved, "variable", None)
    if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "offset", None) == resolved_offset:
        promote_direct_stack_cvariable(codegen, resolved, 2, stack_type_for_size(2))
        return resolved
    return materialize_stack_cvar_at_offset(codegen, resolved_offset, 2)


def _stack_object_name(offset: int) -> str:
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"
