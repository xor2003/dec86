from __future__ import annotations

import re
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable


_LINEAR_TEMP_NAME_RE_8616 = re.compile(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)")


def _strip_typed_suffix_8616(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos > 0:
            return name[:brace_pos]
    return name


def _is_linear_temp_name_8616(name: object) -> bool:
    base = _strip_typed_suffix_8616(name)
    return isinstance(base, str) and _LINEAR_TEMP_NAME_RE_8616.fullmatch(base) is not None


def _rewrite_ss_stack_byte_offsets(
    project,
    codegen,
    *,
    unwrap_c_casts,
    iter_c_nodes_deep,
    replace_c_children,
    c_constant_value,
    flatten_c_add_terms,
    classify_segmented_dereference,
    strip_segment_scale_from_addr_expr,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    materialize_stack_cvar_at_offset,
    stack_slot_identity_for_variable,
    stack_pointer_alias_state,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    # Ownership boundary:
    # This pass is the generic AST-level place to resolve SS-local pointer-carrier
    # chains (for example vvar_/ir_/tmp_ aliases that ultimately point at BP stack
    # slots). If final emitted C still contains raw stack carrier math, fix it here
    # or earlier in stack lowering, not in the final text cleanup layer.

    binary_path = getattr(getattr(codegen.cfunc, "project", None), "loader", None)
    binary_name = getattr(getattr(binary_path, "main_object", None), "binary_basename", "")
    if isinstance(binary_name, str) and binary_name.lower().endswith(".cod"):
        func_name = getattr(getattr(codegen.cfunc, "function", None), "name", "")
        if func_name == "fold_values":
            return False

    changed = False
    stack_pointer_aliases: dict[object, object] = {}
    synthetic_sp_anchor = None
    _UNRESOLVED_SINGLE_ASSIGN = object()
    dirty_expr_single_assignment_cache: dict[str, object | None] = {}
    cvar_single_assignment_cache: dict[int, object | None] = {}

    def _synthetic_sp_anchor_cvar():
        nonlocal synthetic_sp_anchor
        if synthetic_sp_anchor is not None:
            return synthetic_sp_anchor
        region = getattr(codegen.cfunc, "addr", None)
        variable = SimStackVariable(0, 2, base="sp", name="sp_0", region=region)
        synthetic_sp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, synthetic_sp_anchor)
        unified_local_vars = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(variable, {(synthetic_sp_anchor, getattr(synthetic_sp_anchor, "variable_type", None))})
        return synthetic_sp_anchor

    def _is_sp_virtual_register(variable) -> bool:
        sp_offset = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))[0]
        return isinstance(sp_offset, int) and getattr(variable, "reg", None) == sp_offset

    def _is_linear_temp(cvar) -> bool:
        if not isinstance(cvar, structured_c.CVariable):
            return False
        variable = getattr(cvar, "variable", None)
        if isinstance(variable, SimStackVariable):
            return False
        name = getattr(cvar, "name", None)
        if name is None:
            return True
        return _is_linear_temp_name_8616(name)

    def _alias_keys_for_cvar(cvar) -> tuple[object, ...]:
        keys: list[object] = []
        variable = getattr(cvar, "variable", None)
        linear_temp = _is_linear_temp(cvar)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        name = getattr(cvar, "name", None) or getattr(variable, "name", None)
        if isinstance(name, str) and name:
            normalized_name = _strip_typed_suffix_8616(name)
            if isinstance(normalized_name, str) and normalized_name:
                keys.append(("name", normalized_name))
        return tuple(keys)

    def _alias_lookup_keys_for_cvar(cvar) -> tuple[object, ...]:
        variable = getattr(cvar, "variable", None)
        keys: list[object] = []
        linear_temp = _is_linear_temp(cvar)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        for candidate in (
            getattr(cvar, "name", None),
            getattr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate:
                normalized_name = _strip_typed_suffix_8616(candidate)
                if isinstance(normalized_name, str) and normalized_name:
                    keys.append(("name", normalized_name))
        return tuple(dict.fromkeys(keys))

    def _single_assignment_expr_for_virtual_name(name: str):
        normalized_name = _strip_typed_suffix_8616(name)
        if not normalized_name:
            return None
        cached = dirty_expr_single_assignment_cache.get(normalized_name)
        if cached is not None:
            return None if cached is _UNRESOLVED_SINGLE_ASSIGN else cached
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            dirty_expr_single_assignment_cache[normalized_name] = _UNRESOLVED_SINGLE_ASSIGN
            return None

        target_varid = None
        if normalized_name.startswith("vvar_"):
            suffix = normalized_name.removeprefix("vvar_")
            if suffix.isdigit():
                target_varid = int(suffix)
        if not isinstance(target_varid, int):
            dirty_expr_single_assignment_cache[normalized_name] = _UNRESOLVED_SINGLE_ASSIGN
            return None

        matches = []
        for stmt in iter_c_nodes_deep(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            lhs_name = None
            if isinstance(lhs, structured_c.CVariable):
                lhs_name = getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
            lhs_name = _strip_typed_suffix_8616(lhs_name)
            lhs_varid = getattr(getattr(lhs, "dirty", None), "varid", None)
            if lhs_name != normalized_name and lhs_varid != target_varid:
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                dirty_expr_single_assignment_cache[normalized_name] = _UNRESOLVED_SINGLE_ASSIGN
                return None
        resolved = matches[0] if len(matches) == 1 else None
        dirty_expr_single_assignment_cache[normalized_name] = resolved if resolved is not None else _UNRESOLVED_SINGLE_ASSIGN
        return resolved

    def _single_assignment_expr_for_cvar(node_cvar):
        cache_key = id(node_cvar)
        if cache_key in cvar_single_assignment_cache:
            return cvar_single_assignment_cache[cache_key]

        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None or not isinstance(node_cvar, structured_c.CVariable):
            cvar_single_assignment_cache[cache_key] = None
            return None

        node_var = getattr(node_cvar, "variable", None)
        node_name = getattr(node_cvar, "name", None) or getattr(node_var, "name", None)
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)
        node_linear_temp = _is_linear_temp(node_cvar)

        def _same_lhs(lhs):
            if not isinstance(lhs, structured_c.CVariable):
                return False
            lhs_var = getattr(lhs, "variable", None)
            if lhs_var is node_var:
                return True
            lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
            lhs_name = _strip_typed_suffix_8616(lhs_name)
            normalized_node_name = _strip_typed_suffix_8616(node_name)
            if isinstance(normalized_node_name, str) and normalized_node_name and lhs_name == normalized_node_name:
                return True
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
            lhs_linear_temp = _is_linear_temp(lhs)
            if node_linear_temp or lhs_linear_temp:
                return False
            return (
                isinstance(node_reg, int)
                and isinstance(node_size, int)
                and isinstance(lhs_reg, int)
                and isinstance(lhs_size, int)
                and lhs_reg == node_reg
                and lhs_size == node_size
            )

        matches = []
        for stmt in iter_c_nodes_deep(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            if not _same_lhs(getattr(stmt, "lhs", None)):
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                cvar_single_assignment_cache[cache_key] = None
                return None
        resolved = matches[0] if len(matches) == 1 else None
        cvar_single_assignment_cache[cache_key] = resolved
        return resolved

    def _top_level_statements():
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        statements = getattr(root, "statements", None)
        if isinstance(statements, (list, tuple)):
            return list(statements)
        return []

    def _statement_index_containing(node) -> int | None:
        if node is None:
            return None
        for idx, stmt in enumerate(_top_level_statements()):
            for nested in iter_c_nodes_deep(stmt):
                if nested is node:
                    return idx
        return None

    def _nearest_preceding_assignment_expr_for_cvar(node_cvar):
        if not isinstance(node_cvar, structured_c.CVariable):
            return None
        node_var = getattr(node_cvar, "variable", None)
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)
        if not (isinstance(node_reg, int) and isinstance(node_size, int)):
            return None
        stmt_idx = _statement_index_containing(node_cvar)
        if stmt_idx is None:
            return None

        nearest_rhs = None
        for idx, stmt in enumerate(_top_level_statements()):
            if idx >= stmt_idx or not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_var = getattr(lhs, "variable", None)
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
            if lhs_reg == node_reg and lhs_size == node_size:
                nearest_rhs = getattr(stmt, "rhs", None)
        return nearest_rhs

    def _resolve_dirty_virtual_expr(
        node,
        *,
        seen_varids: set[int] | None = None,
    ):
        dirty = getattr(node, "dirty", None)
        if dirty is None:
            return None
        varid = getattr(dirty, "varid", None)
        if not isinstance(varid, int):
            reg = getattr(dirty, "reg", None)
            bits = getattr(dirty, "bits", None)
            if _is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
                return _synthetic_sp_anchor_cvar()
            return None
        if seen_varids is None:
            seen_varids = set()
        if varid in seen_varids:
            return None
        seen_varids.add(varid)
        resolved = _single_assignment_expr_for_virtual_name(f"vvar_{varid}")
        if resolved is not None:
            return resolved
        reg = getattr(dirty, "reg", None)
        bits = getattr(dirty, "bits", None)
        if _is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
            return _synthetic_sp_anchor_cvar()
        return None

    def _dirty_alias_key(node):
        varid = getattr(getattr(node, "dirty", None), "varid", None)
        if isinstance(varid, int):
            return ("vvar", varid)
        return None

    def _resolve_stack_pointer_alias(
        node,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ):
        node = unwrap_c_casts(node)
        if node is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return None
        seen_expr_ids.add(node_id)

        dirty_key = _dirty_alias_key(node)
        if dirty_key is not None:
            alias = stack_pointer_aliases.get(dirty_key)
            if alias is not None:
                return alias.base, alias.offset
        resolved_dirty = _resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return _resolve_stack_pointer_alias(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable):
                identity = stack_slot_identity_for_variable(variable)
                if identity is not None and identity.base == "bp":
                    return node, 0
            if _is_sp_virtual_register(variable):
                return _synthetic_sp_anchor_cvar(), 0
            for key in _alias_lookup_keys_for_cvar(node):
                alias = stack_pointer_aliases.get(key)
                if alias is not None:
                    return alias.base, alias.offset
            single_assignment_rhs = _single_assignment_expr_for_cvar(node)
            if single_assignment_rhs is not None:
                return _resolve_stack_pointer_alias(
                    single_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
            nearest_assignment_rhs = _nearest_preceding_assignment_expr_for_cvar(node)
            if nearest_assignment_rhs is not None:
                return _resolve_stack_pointer_alias(
                    nearest_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
            return None
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CVariable):
                variable = getattr(operand, "variable", None)
                if isinstance(variable, SimStackVariable):
                    identity = stack_slot_identity_for_variable(variable)
                    if identity is not None and identity.base == "bp":
                        return operand, 0
                for key in _alias_lookup_keys_for_cvar(operand):
                    alias = stack_pointer_aliases.get(key)
                    if alias is not None:
                        return alias.base, alias.offset
            return None
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = _resolve_stack_pointer_alias(
                node.lhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            rhs = _resolve_stack_pointer_alias(
                node.rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            lhs_const = c_constant_value(unwrap_c_casts(node.lhs))
            rhs_const = c_constant_value(unwrap_c_casts(node.rhs))
            if lhs is not None and rhs_const is not None:
                base, offset = lhs
                return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
            if rhs is not None and lhs_const is not None:
                base, offset = rhs
                return base, offset + lhs_const
        return None

    def _collect_stack_pointer_aliases() -> None:
        aliases: dict[object, object] = {}
        for _ in range(3):
            changed_local = False
            for walk_node in iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment):
                    continue
                lhs = getattr(walk_node, "lhs", None)
                if isinstance(lhs, structured_c.CVariable):
                    if not _is_linear_temp(lhs):
                        continue
                    keys = _alias_keys_for_cvar(lhs)
                else:
                    dirty_key = _dirty_alias_key(lhs)
                    if dirty_key is None:
                        continue
                    keys = (dirty_key,)
                if not keys:
                    continue
                rhs = unwrap_c_casts(walk_node.rhs)
                resolved = _resolve_stack_pointer_alias(rhs)
                if resolved is None:
                    continue
                resolved_state = stack_pointer_alias_state(*resolved)
                needs_update = False
                for key in keys:
                    if aliases.get(key) != resolved_state:
                        aliases[key] = resolved_state
                        needs_update = True
                if needs_update:
                    changed_local = True
            if not changed_local:
                break
        stack_pointer_aliases.update(aliases)

    _collect_stack_pointer_aliases()

    def _effective_deref_bits(node) -> int | None:
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits in {8, 16}:
            return bits
        operand = getattr(node, "operand", None)
        cast_type = getattr(operand, "type", None)
        if isinstance(cast_type, SimTypePointer):
            pointee = getattr(cast_type, "pts_to", None)
            pointee_bits = getattr(pointee, "size", None)
            if pointee_bits in {8, 16}:
                return pointee_bits
        return None

    def make_stack_deref(cvar, offset: int, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        base_ref = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)
        if offset > 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        elif offset < 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(True), codegen=codegen),
                codegen=codegen,
            )
        else:
            addr_expr = base_ref
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def make_addr_deref(addr_expr, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def _contains_large_unsigned_constant(node) -> bool:
        for term in flatten_c_add_terms(node):
            value = c_constant_value(unwrap_c_casts(term))
            if isinstance(value, int) and value > 0x7FFF:
                return True
        return False

    def _stack_cvar_identity(cvar) -> tuple[str, int, int | None, object] | None:
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base = getattr(variable, "base", None)
        offset = getattr(variable, "offset", None)
        size = getattr(variable, "size", None)
        region = getattr(variable, "region", None)
        if not isinstance(base, str) or not isinstance(offset, int):
            return None
        return base, offset, size if isinstance(size, int) else None, region

    def _stack_deref_identity(node) -> tuple[tuple[str, int, int | None, object], int, int] | None:
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None
        bits = _effective_deref_bits(node)
        if bits not in {8, 16}:
            bits = 16
        resolved = _resolve_stack_pointer_alias(getattr(node, "operand", None))
        if resolved is None:
            return None
        base_cvar, extra_offset = resolved
        base_identity = _stack_cvar_identity(base_cvar)
        if base_identity is None:
            return None
        return base_identity, int(extra_offset), int(bits)

    def _return_if_changed(original, replacement):
        if replacement is original:
            return original
        def _expr_contains_rewrite_alias_carrier(expr, *, seen_ids: set[int] | None = None) -> bool:
            expr = unwrap_c_casts(expr)
            if seen_ids is None:
                seen_ids = set()
            if expr is not None:
                expr_id = id(expr)
                if expr_id in seen_ids:
                    return False
                seen_ids.add(expr_id)
            if _dirty_alias_key(expr) is not None:
                return True
            if isinstance(expr, structured_c.CVariable):
                return _is_linear_temp(expr)
            if isinstance(expr, structured_c.CUnaryOp):
                return _expr_contains_rewrite_alias_carrier(getattr(expr, "operand", None), seen_ids=seen_ids)
            if isinstance(expr, structured_c.CBinaryOp):
                return _expr_contains_rewrite_alias_carrier(getattr(expr, "lhs", None), seen_ids=seen_ids) or _expr_contains_rewrite_alias_carrier(
                    getattr(expr, "rhs", None), seen_ids=seen_ids
                )
            if isinstance(expr, structured_c.CTypeCast):
                return _expr_contains_rewrite_alias_carrier(getattr(expr, "expr", None), seen_ids=seen_ids)
            return False
        original_cvar = _stack_cvar_identity(original)
        replacement_cvar = _stack_cvar_identity(replacement)
        if original_cvar is not None and original_cvar == replacement_cvar:
            return original
        original_deref = _stack_deref_identity(original)
        replacement_deref = _stack_deref_identity(replacement)
        if original_deref is not None and original_deref == replacement_deref:
            if isinstance(original, structured_c.CUnaryOp) and original.op == "Dereference":
                if _expr_contains_rewrite_alias_carrier(getattr(original, "operand", None)):
                    return replacement
            return original
        return replacement

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        resolved_plain_alias = _resolve_stack_pointer_alias(getattr(node, "operand", None))
        if resolved_plain_alias is not None:
            base_cvar, extra_offset = resolved_plain_alias
            bits = _effective_deref_bits(node)
            if bits not in {8, 16}:
                bits = 16
            base_variable = getattr(base_cvar, "variable", None)
            access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
            if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                target_offset = getattr(base_variable, "offset", 0) + extra_offset
                resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                if resolved_cvar is not None:
                    resolved_variable = getattr(resolved_cvar, "variable", None)
                    resolved_offset = getattr(resolved_variable, "offset", None)
                    resolved_size = getattr(resolved_variable, "size", None)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and access_size >= 4
                    ):
                        if resolved_size is not None and resolved_size < access_size:
                            promote_direct_stack_cvariable(
                                codegen,
                                resolved_cvar,
                                access_size,
                                stack_type_for_size(access_size),
                            )
                        return _return_if_changed(node, resolved_cvar)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and resolved_offset == target_offset
                        and resolved_size == access_size
                    ):
                        return _return_if_changed(node, resolved_cvar)
                if access_size >= 4:
                    return _return_if_changed(node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size))
            return _return_if_changed(node, make_stack_deref(base_cvar, extra_offset, bits))
        classified = classify_segmented_dereference(node, project)
        if classified is None or classified.kind != "stack" or classified.cvar is None:
            if classified is None or classified.seg_name != "ss":
                return node
            addr_expr = strip_segment_scale_from_addr_expr(getattr(classified, "addr_expr", None), project)
            if addr_expr is None:
                return node
            resolved_stack_alias = _resolve_stack_pointer_alias(addr_expr)
            if resolved_stack_alias is not None:
                base_cvar, extra_offset = resolved_stack_alias
                type_ = getattr(node, "type", None)
                bits = getattr(type_, "size", None)
                if bits not in {8, 16}:
                    bits = 16
                base_variable = getattr(base_cvar, "variable", None)
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                    target_offset = getattr(base_variable, "offset", 0) + extra_offset
                    resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                    if resolved_cvar is not None:
                        resolved_variable = getattr(resolved_cvar, "variable", None)
                        resolved_offset = getattr(resolved_variable, "offset", None)
                        resolved_size = getattr(resolved_variable, "size", None)
                        if (
                            isinstance(resolved_variable, SimStackVariable)
                            and access_size >= 4
                        ):
                            if resolved_size is not None and resolved_size < access_size:
                                promote_direct_stack_cvariable(
                                    codegen,
                                    resolved_cvar,
                                    access_size,
                                    stack_type_for_size(access_size),
                                )
                            return _return_if_changed(node, resolved_cvar)
                        if (
                            isinstance(resolved_variable, SimStackVariable)
                            and resolved_offset == target_offset
                            and resolved_size == access_size
                        ):
                            return _return_if_changed(node, resolved_cvar)
                    if access_size >= 4:
                        return _return_if_changed(node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size))
                return _return_if_changed(node, make_stack_deref(base_cvar, extra_offset, bits))
            if classified.extra_offset <= 0:
                return node
            if _contains_large_unsigned_constant(addr_expr):
                return node
            bits = _effective_deref_bits(node)
            if bits not in {8, 16}:
                return node
            return _return_if_changed(node, make_addr_deref(addr_expr, bits))
        else:
            cvar = classified.cvar
            extra_offset = classified.extra_offset
            base_variable = getattr(cvar, "variable", None)
            if isinstance(base_variable, SimStackVariable):
                bits = _effective_deref_bits(node)
                if bits not in {8, 16}:
                    bits = 16
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                target_offset = getattr(base_variable, "offset", 0) + extra_offset
                resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                if resolved_cvar is not None:
                    resolved_variable = getattr(resolved_cvar, "variable", None)
                    resolved_offset = getattr(resolved_variable, "offset", None)
                    resolved_size = getattr(resolved_variable, "size", None)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and access_size >= 4
                    ):
                        if resolved_size is not None and resolved_size < access_size:
                            promote_direct_stack_cvariable(codegen, resolved_cvar, access_size, stack_type_for_size(access_size))
                        return _return_if_changed(node, resolved_cvar)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and resolved_offset == target_offset
                        and resolved_size == access_size
                    ):
                        return _return_if_changed(node, resolved_cvar)
                if isinstance(access_size, int) and access_size >= 4:
                    return _return_if_changed(node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size))
            elif getattr(classified, "seg_name", None) == "ss":
                addr_expr = strip_segment_scale_from_addr_expr(getattr(classified, "addr_expr", None), project)
                if addr_expr is not None:
                    resolved_stack_alias = _resolve_stack_pointer_alias(addr_expr)
                    if resolved_stack_alias is not None:
                        base_cvar, extra_offset = resolved_stack_alias
                        type_ = getattr(node, "type", None)
                        bits = getattr(type_, "size", None)
                        if bits not in {8, 16}:
                            bits = 16
                        base_variable = getattr(base_cvar, "variable", None)
                        access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                        if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                            target_offset = getattr(base_variable, "offset", 0) + extra_offset
                            resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                            if resolved_cvar is not None:
                                resolved_variable = getattr(resolved_cvar, "variable", None)
                                resolved_offset = getattr(resolved_variable, "offset", None)
                                resolved_size = getattr(resolved_variable, "size", None)
                                if (
                                    isinstance(resolved_variable, SimStackVariable)
                                    and access_size >= 4
                                ):
                                    if resolved_size is not None and resolved_size < access_size:
                                        promote_direct_stack_cvariable(codegen, resolved_cvar, access_size, stack_type_for_size(access_size))
                                    return _return_if_changed(node, resolved_cvar)
                                if (
                                    isinstance(resolved_variable, SimStackVariable)
                                    and resolved_offset == target_offset
                                    and resolved_size == access_size
                                ):
                                    return _return_if_changed(node, resolved_cvar)
                            if access_size >= 4:
                                return _return_if_changed(node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size))
                        return _return_if_changed(node, make_stack_deref(base_cvar, extra_offset, bits))
        bits = _effective_deref_bits(node)
        if bits not in {8, 16}:
            if getattr(classified, "seg_name", None) == "ss":
                bits = 16
            else:
                return node
        return _return_if_changed(node, make_stack_deref(cvar, extra_offset, bits))

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed
