from __future__ import annotations

import re
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable


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

    binary_path = getattr(getattr(codegen.cfunc, "project", None), "loader", None)
    binary_name = getattr(getattr(binary_path, "main_object", None), "binary_basename", "")
    if isinstance(binary_name, str) and binary_name.lower().endswith(".cod"):
        func_name = getattr(getattr(codegen.cfunc, "function", None), "name", "")
        if func_name == "fold_values":
            return False

    changed = False
    stack_pointer_aliases: dict[object, object] = {}
    synthetic_sp_anchor = None

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
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)", name) is not None

    def _alias_keys_for_cvar(cvar) -> tuple[object, ...]:
        keys: list[object] = []
        variable = getattr(cvar, "variable", None)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        name = getattr(cvar, "name", None) or getattr(variable, "name", None)
        if isinstance(name, str) and name:
            keys.append(("name", name))
        return tuple(keys)

    def _alias_lookup_keys_for_cvar(cvar) -> tuple[object, ...]:
        variable = getattr(cvar, "variable", None)
        keys: list[object] = []
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        for candidate in (
            getattr(cvar, "name", None),
            getattr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate:
                keys.append(("name", candidate))
        return tuple(dict.fromkeys(keys))

    def _single_assignment_expr_for_virtual_name(name: str):
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return None

        matches = []
        for stmt in iter_c_nodes_deep(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_name = getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
            if lhs_name != name:
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                return None
        return matches[0] if len(matches) == 1 else None

    def _single_assignment_expr_for_cvar(node_cvar):
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None or not isinstance(node_cvar, structured_c.CVariable):
            return None

        node_var = getattr(node_cvar, "variable", None)
        node_name = getattr(node_cvar, "name", None) or getattr(node_var, "name", None)
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)

        def _same_lhs(lhs):
            if not isinstance(lhs, structured_c.CVariable):
                return False
            lhs_var = getattr(lhs, "variable", None)
            if lhs_var is node_var:
                return True
            lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
            if isinstance(node_name, str) and node_name and lhs_name == node_name:
                return True
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
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
                return None
        return matches[0] if len(matches) == 1 else None

    def _resolve_dirty_virtual_expr(node):
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
        resolved = _single_assignment_expr_for_virtual_name(f"vvar_{varid}")
        if resolved is not None:
            return resolved
        reg = getattr(dirty, "reg", None)
        bits = getattr(dirty, "bits", None)
        if _is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
            return _synthetic_sp_anchor_cvar()
        return None

    def _resolve_stack_pointer_alias(node):
        node = unwrap_c_casts(node)
        resolved_dirty = _resolve_dirty_virtual_expr(node)
        if resolved_dirty is not None:
            return _resolve_stack_pointer_alias(resolved_dirty)
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
                return _resolve_stack_pointer_alias(single_assignment_rhs)
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
            lhs = _resolve_stack_pointer_alias(node.lhs)
            rhs = _resolve_stack_pointer_alias(node.rhs)
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
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_temp(walk_node.lhs):
                    continue
                keys = _alias_keys_for_cvar(walk_node.lhs)
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

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
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
                            return resolved_cvar
                        if (
                            isinstance(resolved_variable, SimStackVariable)
                            and resolved_offset == target_offset
                            and resolved_size == access_size
                        ):
                            return resolved_cvar
                    if access_size >= 4:
                        return materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                return make_stack_deref(base_cvar, extra_offset, bits)
            if classified.extra_offset <= 0:
                return node
            if _contains_large_unsigned_constant(addr_expr):
                return node
            bits = _effective_deref_bits(node)
            if bits not in {8, 16}:
                return node
            return make_addr_deref(addr_expr, bits)
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
                        return resolved_cvar
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and resolved_offset == target_offset
                        and resolved_size == access_size
                    ):
                        return resolved_cvar
                if isinstance(access_size, int) and access_size >= 4:
                    return materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
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
                                    return resolved_cvar
                                if (
                                    isinstance(resolved_variable, SimStackVariable)
                                    and resolved_offset == target_offset
                                    and resolved_size == access_size
                                ):
                                    return resolved_cvar
                            if access_size >= 4:
                                return materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                        return make_stack_deref(base_cvar, extra_offset, bits)
        bits = _effective_deref_bits(node)
        if bits not in {8, 16}:
            if getattr(classified, "seg_name", None) == "ss":
                bits = 16
            else:
                return node
        return make_stack_deref(cvar, extra_offset, bits)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed
