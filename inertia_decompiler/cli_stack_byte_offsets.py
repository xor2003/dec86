"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from types import SimpleNamespace
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable

_LINEAR_TEMP_NAME_RE_8616 = re.compile(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)")


def _dynamic_codegen_attr(obj: object, name: str, default: Any = None) -> Any:  # noqa: ANN401
    """Read a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    return getattr(obj, name, default)


def _dynamic_codegen_setattr(obj: object, name: str, value: object) -> None:
    """Write a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    setattr(obj, name, value)


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
    project: Any,  # noqa: ANN401
    codegen: Any,  # noqa: ANN401
    *,
    unwrap_c_casts: Callable[[object], object],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
    c_constant_value: Callable[[object], int | None],
    flatten_c_add_terms: Callable[[object], Iterable[object]],
    classify_segmented_dereference: Callable[[object, object], Any],
    strip_segment_scale_from_addr_expr: Callable[[object, object], Any],
    resolve_stack_cvar_at_offset: Callable[[object, int], Any],
    promote_direct_stack_cvariable: Callable[[object, object, int, object], Any],
    stack_type_for_size: Callable[[int], object],
    materialize_stack_cvar_at_offset: Callable[[object, int, int], Any],
    stack_slot_identity_for_variable: Callable[[object], Any],
    stack_pointer_alias_state: Callable[[object, int], Any],
) -> bool:
    if _dynamic_codegen_attr(codegen, "cfunc", None) is None:
        return False

    # Ownership boundary:
    # This pass is the generic AST-level place to resolve SS-local pointer-carrier
    # chains (for example vvar_/ir_/tmp_ aliases that ultimately point at BP stack
    # slots). If final emitted C still contains raw stack carrier math, fix it here
    # or earlier in stack lowering, not in the final text cleanup layer.

    binary_path = _dynamic_codegen_attr(_dynamic_codegen_attr(codegen.cfunc, "project", None), "loader", None)
    binary_name = _dynamic_codegen_attr(_dynamic_codegen_attr(binary_path, "main_object", None), "binary_basename", "")
    if isinstance(binary_name, str) and binary_name.lower().endswith(".cod"):
        func_name = _dynamic_codegen_attr(_dynamic_codegen_attr(codegen.cfunc, "function", None), "name", "")
        if func_name == "fold_values":
            return False

    changed = False
    stack_pointer_aliases: dict[object, Any] = {}
    synthetic_sp_anchor: Any | None = None
    _UNRESOLVED_SINGLE_ASSIGN = object()
    dirty_expr_single_assignment_cache: dict[str, object | None] = {}
    dirty_expr_single_assignment_index: dict[str, object | None] | None = None
    cvar_single_assignment_cache: dict[int, object | None] = {}

    def _safe_dirty_attr_8616(obj: object, attr: str) -> object | None:
        try:
            return _dynamic_codegen_attr(obj, attr, None)
        except (AttributeError, TypeError, ValueError):
            return None

    def _synthetic_sp_anchor_cvar() -> object:
        nonlocal synthetic_sp_anchor
        if synthetic_sp_anchor is not None:
            return synthetic_sp_anchor
        region = _dynamic_codegen_attr(codegen.cfunc, "addr", None)
        variable = SimStackVariable(0, 2, base="sp", name="sp_0", region=region)
        synthetic_sp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        variables_in_use = _dynamic_codegen_attr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, synthetic_sp_anchor)
        unified_local_vars = _dynamic_codegen_attr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(
                variable, {(synthetic_sp_anchor, _dynamic_codegen_attr(synthetic_sp_anchor, "variable_type", None))}
            )
        return synthetic_sp_anchor

    def _is_sp_virtual_register(variable: object) -> bool:
        sp_offset = _dynamic_codegen_attr(_dynamic_codegen_attr(project, "arch", None), "registers", {}).get("sp", (None, None))[0]
        return isinstance(sp_offset, int) and _dynamic_codegen_attr(variable, "reg", None) == sp_offset

    def _is_ss_virtual_register(variable: object) -> bool:
        ss_offset = _dynamic_codegen_attr(_dynamic_codegen_attr(project, "arch", None), "registers", {}).get("ss", (None, None))[0]
        return isinstance(ss_offset, int) and _dynamic_codegen_attr(variable, "reg", None) == ss_offset

    def _dirty_reg_offset_8616(node: object) -> int | None:
        dirty = _dynamic_codegen_attr(node, "dirty", None)
        if dirty is None:
            return None
        for attr in ("reg_offset", "reg"):
            reg = _safe_dirty_attr_8616(dirty, attr)
            if isinstance(reg, int):
                return int(reg)
        return None

    def _dirty_is_ss_virtual_register_8616(node: object) -> bool:
        return _is_ss_virtual_register(SimpleNamespace(reg=_dirty_reg_offset_8616(node)))

    def _is_linear_temp(cvar: object) -> bool:
        if not isinstance(cvar, structured_c.CVariable):
            return False
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        if isinstance(variable, SimStackVariable):
            return False
        name = _dynamic_codegen_attr(cvar, "name", None)
        if name is None:
            return True
        return _is_linear_temp_name_8616(name)

    def _alias_keys_for_cvar(cvar: object) -> tuple[object, ...]:
        keys: list[object] = []
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        linear_temp = _is_linear_temp(cvar)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = _dynamic_codegen_attr(variable, "reg", None)
            size = _dynamic_codegen_attr(variable, "size", None)
            if not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        name = _dynamic_codegen_attr(cvar, "name", None) or _dynamic_codegen_attr(variable, "name", None)
        if isinstance(name, str) and name:
            normalized_name = _strip_typed_suffix_8616(name)
            if isinstance(normalized_name, str) and normalized_name:
                keys.append(("name", normalized_name))
        return tuple(keys)

    def _alias_lookup_keys_for_cvar(cvar: object) -> tuple[object, ...]:
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        keys: list[object] = []
        linear_temp = _is_linear_temp(cvar)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = _dynamic_codegen_attr(variable, "reg", None)
            size = _dynamic_codegen_attr(variable, "size", None)
            if not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        for candidate in (
            _dynamic_codegen_attr(cvar, "name", None),
            _dynamic_codegen_attr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate:
                normalized_name = _strip_typed_suffix_8616(candidate)
                if isinstance(normalized_name, str) and normalized_name:
                    keys.append(("name", normalized_name))
        return tuple(dict.fromkeys(keys))

    def _single_assignment_expr_for_virtual_name(name: str) -> object | None:
        nonlocal dirty_expr_single_assignment_index
        normalized_name = _strip_typed_suffix_8616(name)
        if not normalized_name:
            return None
        cached = dirty_expr_single_assignment_cache.get(normalized_name)
        if cached is not None:
            return None if cached is _UNRESOLVED_SINGLE_ASSIGN else cached
        root = _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "statements", None)
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

        if dirty_expr_single_assignment_index is None:
            index: dict[str, object | None] = {}
            scanned = 0
            for stmt in iter_c_nodes_deep(root):
                if not isinstance(stmt, structured_c.CAssignment):
                    continue
                scanned += 1
                lhs = _dynamic_codegen_attr(stmt, "lhs", None)
                lhs_keys: set[str] = set()
                if isinstance(lhs, structured_c.CVariable):
                    lhs_name = _dynamic_codegen_attr(lhs, "name", None) or _dynamic_codegen_attr(_dynamic_codegen_attr(lhs, "variable", None), "name", None)
                    lhs_name = _strip_typed_suffix_8616(lhs_name)
                    if isinstance(lhs_name, str) and lhs_name:
                        lhs_keys.add(lhs_name)
                lhs_varid = _safe_dirty_attr_8616(_dynamic_codegen_attr(lhs, "dirty", None), "varid")
                if isinstance(lhs_varid, int):
                    lhs_keys.add(f"vvar_{lhs_varid}")
                if not lhs_keys:
                    continue
                rhs = _dynamic_codegen_attr(stmt, "rhs", None)
                for lhs_key in lhs_keys:
                    if lhs_key in index:
                        index[lhs_key] = _UNRESOLVED_SINGLE_ASSIGN
                    else:
                        index[lhs_key] = rhs
            dirty_expr_single_assignment_index = index
            codegen._inertia_ss_stack_virtual_assignment_index_scanned = (
                int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_virtual_assignment_index_scanned", 0) or 0) + scanned
            )
            codegen._inertia_ss_stack_virtual_assignment_index_keys = int(
                _dynamic_codegen_attr(codegen, "_inertia_ss_stack_virtual_assignment_index_keys", 0) or 0
            ) + len(index)

        resolved = dirty_expr_single_assignment_index.get(normalized_name)
        if resolved is _UNRESOLVED_SINGLE_ASSIGN:
            dirty_expr_single_assignment_cache[normalized_name] = _UNRESOLVED_SINGLE_ASSIGN
            return None
        dirty_expr_single_assignment_cache[normalized_name] = (
            resolved if resolved is not None else _UNRESOLVED_SINGLE_ASSIGN
        )
        if resolved is not None:
            codegen._inertia_ss_stack_virtual_assignment_index_hits = (
                int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_virtual_assignment_index_hits", 0) or 0) + 1
            )
        return resolved

    def _single_assignment_expr_for_cvar(node_cvar: object) -> object | None:
        cache_key = id(node_cvar)
        if cache_key in cvar_single_assignment_cache:
            return cvar_single_assignment_cache[cache_key]

        root = _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "statements", None)
        if root is None or not isinstance(node_cvar, structured_c.CVariable):
            cvar_single_assignment_cache[cache_key] = None
            return None

        node_var = _dynamic_codegen_attr(node_cvar, "variable", None)
        node_name = _dynamic_codegen_attr(node_cvar, "name", None) or _dynamic_codegen_attr(node_var, "name", None)
        node_reg = _dynamic_codegen_attr(node_var, "reg", None)
        node_size = _dynamic_codegen_attr(node_var, "size", None)
        node_linear_temp = _is_linear_temp(node_cvar)

        def _same_lhs(lhs: object) -> bool:
            if not isinstance(lhs, structured_c.CVariable):
                return False
            lhs_var = _dynamic_codegen_attr(lhs, "variable", None)
            if lhs_var is node_var:
                return True
            lhs_name = _dynamic_codegen_attr(lhs, "name", None) or _dynamic_codegen_attr(lhs_var, "name", None)
            lhs_name = _strip_typed_suffix_8616(lhs_name)
            normalized_node_name = _strip_typed_suffix_8616(node_name)
            if isinstance(normalized_node_name, str) and normalized_node_name and lhs_name == normalized_node_name:
                return True
            lhs_reg = _dynamic_codegen_attr(lhs_var, "reg", None)
            lhs_size = _dynamic_codegen_attr(lhs_var, "size", None)
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
            if not _same_lhs(_dynamic_codegen_attr(stmt, "lhs", None)):
                continue
            matches.append(_dynamic_codegen_attr(stmt, "rhs", None))
            if len(matches) > 1:
                cvar_single_assignment_cache[cache_key] = None
                return None
        resolved = matches[0] if len(matches) == 1 else None
        cvar_single_assignment_cache[cache_key] = resolved
        return resolved

    def _top_level_statements() -> list[object]:
        root = _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "statements", None)
        statements = _dynamic_codegen_attr(root, "statements", None)
        if isinstance(statements, (list, tuple)):
            return list(statements)
        return []

    def _statement_index_containing(node: object) -> int | None:
        if node is None:
            return None
        for idx, stmt in enumerate(_top_level_statements()):
            for nested in iter_c_nodes_deep(stmt):
                if nested is node:
                    return idx
        return None

    def _nearest_preceding_assignment_expr_for_cvar(node_cvar: object) -> object | None:
        if not isinstance(node_cvar, structured_c.CVariable):
            return None
        node_var = _dynamic_codegen_attr(node_cvar, "variable", None)
        node_reg = _dynamic_codegen_attr(node_var, "reg", None)
        node_size = _dynamic_codegen_attr(node_var, "size", None)
        if not (isinstance(node_reg, int) and isinstance(node_size, int)):
            return None
        stmt_idx = _statement_index_containing(node_cvar)
        if stmt_idx is None:
            return None

        nearest_rhs = None
        for idx, stmt in enumerate(_top_level_statements()):
            if idx >= stmt_idx or not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = _dynamic_codegen_attr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_var = _dynamic_codegen_attr(lhs, "variable", None)
            lhs_reg = _dynamic_codegen_attr(lhs_var, "reg", None)
            lhs_size = _dynamic_codegen_attr(lhs_var, "size", None)
            if lhs_reg == node_reg and lhs_size == node_size:
                nearest_rhs = _dynamic_codegen_attr(stmt, "rhs", None)
        return nearest_rhs

    def _resolve_dirty_virtual_expr(
        node: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> object | None:
        dirty = _dynamic_codegen_attr(node, "dirty", None)
        if dirty is None:
            return None
        varid = _safe_dirty_attr_8616(dirty, "varid")
        if not isinstance(varid, int):
            reg = _safe_dirty_attr_8616(dirty, "reg")
            bits = _safe_dirty_attr_8616(dirty, "bits")
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
        reg = _safe_dirty_attr_8616(dirty, "reg")
        bits = _safe_dirty_attr_8616(dirty, "bits")
        if _is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
            return _synthetic_sp_anchor_cvar()
        return None

    def _dirty_alias_key(node: object) -> tuple[str, int] | None:
        varid = _safe_dirty_attr_8616(_dynamic_codegen_attr(node, "dirty", None), "varid")
        if isinstance(varid, int):
            return ("vvar", varid)
        return None

    def _resolve_stack_pointer_alias(
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
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
                return _dynamic_codegen_attr(alias, "base"), int(_dynamic_codegen_attr(alias, "offset", 0))
        resolved_dirty = _resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return _resolve_stack_pointer_alias(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(node, structured_c.CVariable):
            variable = _dynamic_codegen_attr(node, "variable", None)
            if isinstance(variable, SimStackVariable):
                identity = stack_slot_identity_for_variable(variable)
                if identity is not None and _dynamic_codegen_attr(identity, "base", None) == "bp":
                    return node, 0
            if _is_sp_virtual_register(variable):
                return _synthetic_sp_anchor_cvar(), 0
            for key in _alias_lookup_keys_for_cvar(node):
                alias = stack_pointer_aliases.get(key)
                if alias is not None:
                    return _dynamic_codegen_attr(alias, "base"), int(_dynamic_codegen_attr(alias, "offset", 0))
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
                variable = _dynamic_codegen_attr(operand, "variable", None)
                if isinstance(variable, SimStackVariable):
                    identity = stack_slot_identity_for_variable(variable)
                    if identity is not None and _dynamic_codegen_attr(identity, "base", None) == "bp":
                        return operand, 0
                for key in _alias_lookup_keys_for_cvar(operand):
                    alias = stack_pointer_aliases.get(key)
                    if alias is not None:
                        return _dynamic_codegen_attr(alias, "base"), int(_dynamic_codegen_attr(alias, "offset", 0))
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

    def _expr_is_ss_segment_value_8616(
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> bool:
        node = unwrap_c_casts(node)
        if node is None:
            return False
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return False
        seen_expr_ids.add(node_id)

        if isinstance(node, structured_c.CVariable):
            variable = _dynamic_codegen_attr(node, "variable", None)
            if _is_ss_virtual_register(variable):
                codegen._inertia_ss_stack_byte_ss_virtual_register_evidence_8616 = (
                    int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_byte_ss_virtual_register_evidence_8616", 0) or 0) + 1
                )
                return True
            if _dirty_is_ss_virtual_register_8616(node):
                codegen._inertia_ss_stack_byte_ss_dirty_register_evidence_8616 = (
                    int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_byte_ss_dirty_register_evidence_8616", 0) or 0) + 1
                )
                return True
            name = _dynamic_codegen_attr(node, "name", None) or _dynamic_codegen_attr(variable, "name", None)
            if isinstance(name, str) and name.lower() == "ss":
                return True
            single_assignment_rhs = _single_assignment_expr_for_cvar(node)
            if single_assignment_rhs is not None:
                return _expr_is_ss_segment_value_8616(
                    single_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
            return False

        resolved_dirty = _resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return _expr_is_ss_segment_value_8616(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if _dirty_is_ss_virtual_register_8616(node):
            codegen._inertia_ss_stack_byte_ss_dirty_register_evidence_8616 = (
                int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_byte_ss_dirty_register_evidence_8616", 0) or 0) + 1
            )
            return True
        return False

    def _expr_is_ss_segment_scale_term_8616(node: object, *, seen_varids: set[int] | None = None) -> bool:
        node = unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp):
            return False
        op = _dynamic_codegen_attr(node, "op", None)
        lhs = _dynamic_codegen_attr(node, "lhs", None)
        rhs = _dynamic_codegen_attr(node, "rhs", None)
        lhs_const = c_constant_value(unwrap_c_casts(lhs))
        rhs_const = c_constant_value(unwrap_c_casts(rhs))
        if op == "Shl" and rhs_const == 4:
            return _expr_is_ss_segment_value_8616(lhs, seen_varids=seen_varids)
        if op != "Mul":
            return False
        if rhs_const == 16 and _expr_is_ss_segment_value_8616(lhs, seen_varids=seen_varids):
            return True
        return lhs_const == 16 and _expr_is_ss_segment_value_8616(rhs, seen_varids=seen_varids)

    def _strip_proven_ss_segment_scale_from_addr_expr_8616(
        addr_expr: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> object | None:
        terms = flatten_c_add_terms(addr_expr)
        if not terms:
            return None
        kept_terms = []
        stripped = 0
        for term in terms:
            inner = unwrap_c_casts(term)
            if _expr_is_ss_segment_scale_term_8616(inner, seen_varids=seen_varids):
                stripped += 1
                continue
            kept_terms.append(term)
        if stripped != 1 or not kept_terms:
            if stripped > 1:
                codegen._inertia_ss_stack_byte_segment_strip_refused_8616 = (
                    int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_byte_segment_strip_refused_8616", 0) or 0) + 1
                )
            return None
        result = kept_terms[0]
        for term in kept_terms[1:]:
            result = structured_c.CBinaryOp("Add", result, term, codegen=_dynamic_codegen_attr(term, "codegen", None))
        codegen._inertia_ss_stack_byte_segment_strip_materialized_8616 = (
            int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_byte_segment_strip_materialized_8616", 0) or 0) + 1
        )
        return result

    def _expr_contains_ss_segment_scale_8616(
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> bool:
        node = unwrap_c_casts(node)
        if node is None:
            return False
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return False
        seen_expr_ids.add(node_id)

        if isinstance(node, structured_c.CBinaryOp):
            op = _dynamic_codegen_attr(node, "op", None)
            lhs = _dynamic_codegen_attr(node, "lhs", None)
            rhs = _dynamic_codegen_attr(node, "rhs", None)
            lhs_const = c_constant_value(unwrap_c_casts(lhs))
            rhs_const = c_constant_value(unwrap_c_casts(rhs))
            if (
                op == "Shl"
                and rhs_const == 4
                and _expr_is_ss_segment_value_8616(
                    lhs,
                    seen_varids=seen_varids,
                )
            ):
                return True
            if op == "Mul":
                if rhs_const == 16 and _expr_is_ss_segment_value_8616(lhs, seen_varids=seen_varids):
                    return True
                if lhs_const == 16 and _expr_is_ss_segment_value_8616(rhs, seen_varids=seen_varids):
                    return True
            return _expr_contains_ss_segment_scale_8616(
                lhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            ) or _expr_contains_ss_segment_scale_8616(
                rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )

        resolved_dirty = _resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return _expr_contains_ss_segment_scale_8616(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(node, structured_c.CVariable):
            single_assignment_rhs = _single_assignment_expr_for_cvar(node)
            if single_assignment_rhs is not None:
                return _expr_contains_ss_segment_scale_8616(
                    single_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
        return False

    def _resolve_ss_linear_stack_pointer_alias(
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        node = unwrap_c_casts(node)
        if node is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return None
        seen_expr_ids.add(node_id)

        direct = _resolve_stack_pointer_alias(node, seen_varids=seen_varids)
        if direct is not None:
            return direct

        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs_const = c_constant_value(unwrap_c_casts(node.lhs))
            rhs_const = c_constant_value(unwrap_c_casts(node.rhs))
            if rhs_const is not None:
                lhs = _resolve_ss_linear_stack_pointer_alias(
                    node.lhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
                if lhs is not None:
                    base, offset = lhs
                    return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
            if lhs_const is not None and node.op == "Add":
                rhs = _resolve_ss_linear_stack_pointer_alias(
                    node.rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
                if rhs is not None:
                    base, offset = rhs
                    return base, offset + lhs_const

        resolved_expr = None
        resolved_dirty = _resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            resolved_expr = resolved_dirty
        elif isinstance(node, structured_c.CVariable):
            resolved_expr = _single_assignment_expr_for_cvar(node)
            if resolved_expr is None:
                resolved_expr = _nearest_preceding_assignment_expr_for_cvar(node)
        if resolved_expr is None:
            return None

        if _expr_contains_ss_segment_scale_8616(resolved_expr, seen_varids=seen_varids):
            addr_expr = strip_segment_scale_from_addr_expr(resolved_expr, project)
            if addr_expr is None or _expr_contains_ss_segment_scale_8616(addr_expr, seen_varids=seen_varids):
                addr_expr = _strip_proven_ss_segment_scale_from_addr_expr_8616(
                    resolved_expr,
                    seen_varids=seen_varids,
                )
            if addr_expr is not None:
                resolved = _resolve_stack_pointer_alias(addr_expr, seen_varids=seen_varids)
                if resolved is not None:
                    codegen._inertia_ss_stack_byte_linear_carrier_resolved_8616 = (
                        int(_dynamic_codegen_attr(codegen, "_inertia_ss_stack_byte_linear_carrier_resolved_8616", 0) or 0) + 1
                    )
                    return resolved
        return _resolve_ss_linear_stack_pointer_alias(
            resolved_expr,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )

    def _is_uncast_ss_linear_carrier_byte_offset_8616(node: object) -> bool:
        if isinstance(node, structured_c.CTypeCast):
            return False
        node = unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Add", "Sub"}:
            return False
        lhs_const = c_constant_value(unwrap_c_casts(node.lhs))
        rhs_const = c_constant_value(unwrap_c_casts(node.rhs))
        if rhs_const not in (1, -1) and lhs_const not in (1, -1):
            return False
        base_expr = node.rhs if lhs_const in (1, -1) and node.op == "Add" else node.lhs
        resolved_dirty = _resolve_dirty_virtual_expr(base_expr)
        if resolved_dirty is not None:
            base_expr = resolved_dirty
        elif isinstance(unwrap_c_casts(base_expr), structured_c.CVariable):
            base_expr = (
                _single_assignment_expr_for_cvar(unwrap_c_casts(base_expr))
                or _nearest_preceding_assignment_expr_for_cvar(unwrap_c_casts(base_expr))
                or base_expr
            )
        return _expr_contains_ss_segment_scale_8616(base_expr)

    def _collect_stack_pointer_aliases() -> None:
        aliases: dict[object, object] = {}
        for _ in range(3):
            changed_local = False
            for walk_node in iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment):
                    continue
                lhs = _dynamic_codegen_attr(walk_node, "lhs", None)
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

    def _effective_deref_bits(node: object) -> int | None:
        type_ = _dynamic_codegen_attr(node, "type", None)
        bits = _dynamic_codegen_attr(type_, "size", None)
        if bits in {8, 16}:
            return bits
        operand = _dynamic_codegen_attr(node, "operand", None)
        cast_type = _dynamic_codegen_attr(operand, "type", None)
        if isinstance(cast_type, SimTypePointer):
            pointee = _dynamic_codegen_attr(cast_type, "pts_to", None)
            pointee_bits = _dynamic_codegen_attr(pointee, "size", None)
            if pointee_bits in {8, 16}:
                return pointee_bits
        return None

    def make_stack_deref(cvar: Any, offset: int, bits: int) -> object:  # noqa: ANN401
        """Build a typed dereference for a proven stack-relative address."""
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
            structured_c.CTypeCast(
                _dynamic_codegen_attr(addr_expr, "type", None) or ptr_type,
                ptr_type,
                addr_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    def make_addr_deref(addr_expr: Any, bits: int) -> object:  # noqa: ANN401
        """Build a typed dereference for a proven 16-bit address expression."""
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        source_type = _dynamic_codegen_attr(addr_expr, "type", None) or SimTypeShort(False)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(source_type, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def _contains_large_unsigned_constant(node: object) -> bool:
        for term in flatten_c_add_terms(node):
            value = c_constant_value(unwrap_c_casts(term))
            if isinstance(value, int) and value > 0x7FFF:
                return True
        return False

    def _stack_cvar_identity(cvar: object) -> tuple[str, int, int | None, object] | None:
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base = _dynamic_codegen_attr(variable, "base", None)
        offset = _dynamic_codegen_attr(variable, "offset", None)
        size = _dynamic_codegen_attr(variable, "size", None)
        region = _dynamic_codegen_attr(variable, "region", None)
        if not isinstance(base, str) or not isinstance(offset, int):
            return None
        return base, offset, size if isinstance(size, int) else None, region

    def _stack_deref_identity(node: object) -> tuple[tuple[str, int, int | None, object], int, int] | None:
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None
        bits = _effective_deref_bits(node)
        if bits not in {8, 16}:
            bits = 16
        resolved = _resolve_stack_pointer_alias(_dynamic_codegen_attr(node, "operand", None))
        if resolved is None:
            return None
        base_cvar, extra_offset = resolved
        base_identity = _stack_cvar_identity(base_cvar)
        if base_identity is None:
            return None
        return base_identity, int(extra_offset), int(bits)

    def _return_if_changed(original: object, replacement: object) -> object:
        if replacement is original:
            return original

        def _expr_contains_rewrite_alias_carrier(expr: object, *, seen_ids: set[int] | None = None) -> bool:
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
                return _expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(expr, "operand", None), seen_ids=seen_ids)
            if isinstance(expr, structured_c.CBinaryOp):
                return _expr_contains_rewrite_alias_carrier(
                    _dynamic_codegen_attr(expr, "lhs", None), seen_ids=seen_ids
                ) or _expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(expr, "rhs", None), seen_ids=seen_ids)
            if isinstance(expr, structured_c.CTypeCast):
                return _expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(expr, "expr", None), seen_ids=seen_ids)
            return False

        original_cvar = _stack_cvar_identity(original)
        replacement_cvar = _stack_cvar_identity(replacement)
        if original_cvar is not None and original_cvar == replacement_cvar:
            return original
        original_deref = _stack_deref_identity(original)
        replacement_deref = _stack_deref_identity(replacement)
        if original_deref is not None and original_deref == replacement_deref:
            if isinstance(original, structured_c.CUnaryOp) and original.op == "Dereference":
                if _expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(original, "operand", None)):
                    return replacement
            return original
        return replacement

    def transform(node: object) -> object:
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        resolved_plain_alias = _resolve_stack_pointer_alias(_dynamic_codegen_attr(node, "operand", None))
        if resolved_plain_alias is None:
            resolved_plain_alias = _resolve_ss_linear_stack_pointer_alias(_dynamic_codegen_attr(node, "operand", None))
        if resolved_plain_alias is not None:
            base_cvar, extra_offset = resolved_plain_alias
            bits = _effective_deref_bits(node)
            if extra_offset != 0 and _is_uncast_ss_linear_carrier_byte_offset_8616(_dynamic_codegen_attr(node, "operand", None)):
                bits = 8
            elif bits not in {8, 16}:
                bits = 8 if extra_offset != 0 else 16
            base_variable = _dynamic_codegen_attr(base_cvar, "variable", None)
            access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
            if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
                resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                if resolved_cvar is not None:
                    resolved_variable = _dynamic_codegen_attr(resolved_cvar, "variable", None)
                    resolved_offset = _dynamic_codegen_attr(resolved_variable, "offset", None)
                    resolved_size = _dynamic_codegen_attr(resolved_variable, "size", None)
                    if isinstance(resolved_variable, SimStackVariable) and access_size >= 4:
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
                    return _return_if_changed(
                        node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                    )
            return _return_if_changed(node, make_stack_deref(base_cvar, extra_offset, bits))
        classified = classify_segmented_dereference(node, project)
        if classified is None or classified.kind != "stack" or classified.cvar is None:
            if classified is None or classified.seg_name != "ss":
                return node
            addr_expr = strip_segment_scale_from_addr_expr(_dynamic_codegen_attr(classified, "addr_expr", None), project)
            if addr_expr is None or _expr_contains_ss_segment_scale_8616(addr_expr):
                addr_expr = _strip_proven_ss_segment_scale_from_addr_expr_8616(
                    _dynamic_codegen_attr(classified, "addr_expr", None),
                )
            if addr_expr is None:
                return node
            resolved_stack_alias = _resolve_stack_pointer_alias(addr_expr)
            if resolved_stack_alias is not None:
                base_cvar, extra_offset = resolved_stack_alias
                type_ = _dynamic_codegen_attr(node, "type", None)
                bits = _dynamic_codegen_attr(type_, "size", None)
                if bits not in {8, 16}:
                    bits = 16
                base_variable = _dynamic_codegen_attr(base_cvar, "variable", None)
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                    target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
                    resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                    if resolved_cvar is not None:
                        resolved_variable = _dynamic_codegen_attr(resolved_cvar, "variable", None)
                        resolved_offset = _dynamic_codegen_attr(resolved_variable, "offset", None)
                        resolved_size = _dynamic_codegen_attr(resolved_variable, "size", None)
                        if isinstance(resolved_variable, SimStackVariable) and access_size >= 4:
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
                        return _return_if_changed(
                            node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                        )
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
            base_variable = _dynamic_codegen_attr(cvar, "variable", None)
            if isinstance(base_variable, SimStackVariable):
                bits = _effective_deref_bits(node)
                if bits not in {8, 16}:
                    bits = 16
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
                resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                if resolved_cvar is not None:
                    resolved_variable = _dynamic_codegen_attr(resolved_cvar, "variable", None)
                    resolved_offset = _dynamic_codegen_attr(resolved_variable, "offset", None)
                    resolved_size = _dynamic_codegen_attr(resolved_variable, "size", None)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and access_size >= 4
                    ):
                        if resolved_size is not None and resolved_size < access_size:
                            promote_direct_stack_cvariable(
                                codegen, resolved_cvar, access_size, stack_type_for_size(access_size)
                            )
                        return _return_if_changed(node, resolved_cvar)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and resolved_offset == target_offset
                        and resolved_size == access_size
                    ):
                        return _return_if_changed(node, resolved_cvar)
                if isinstance(access_size, int) and access_size >= 4:
                    return _return_if_changed(
                        node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                    )
            elif _dynamic_codegen_attr(classified, "seg_name", None) == "ss":
                addr_expr = strip_segment_scale_from_addr_expr(_dynamic_codegen_attr(classified, "addr_expr", None), project)
                if addr_expr is None or _expr_contains_ss_segment_scale_8616(addr_expr):
                    addr_expr = _strip_proven_ss_segment_scale_from_addr_expr_8616(
                        _dynamic_codegen_attr(classified, "addr_expr", None),
                    )
                if addr_expr is not None:
                    resolved_stack_alias = _resolve_stack_pointer_alias(addr_expr)
                    if resolved_stack_alias is not None:
                        base_cvar, extra_offset = resolved_stack_alias
                        type_ = _dynamic_codegen_attr(node, "type", None)
                        bits = _dynamic_codegen_attr(type_, "size", None)
                        if bits not in {8, 16}:
                            bits = 16
                        base_variable = _dynamic_codegen_attr(base_cvar, "variable", None)
                        access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                        if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                            target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
                            resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                            if resolved_cvar is not None:
                                resolved_variable = _dynamic_codegen_attr(resolved_cvar, "variable", None)
                                resolved_offset = _dynamic_codegen_attr(resolved_variable, "offset", None)
                                resolved_size = _dynamic_codegen_attr(resolved_variable, "size", None)
                                if isinstance(resolved_variable, SimStackVariable) and access_size >= 4:
                                    if resolved_size is not None and resolved_size < access_size:
                                        promote_direct_stack_cvariable(
                                            codegen, resolved_cvar, access_size, stack_type_for_size(access_size)
                                        )
                                    return _return_if_changed(node, resolved_cvar)
                                if (
                                    isinstance(resolved_variable, SimStackVariable)
                                    and resolved_offset == target_offset
                                    and resolved_size == access_size
                                ):
                                    return _return_if_changed(node, resolved_cvar)
                            if access_size >= 4:
                                return _return_if_changed(
                                    node, materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                                )
                        return _return_if_changed(node, make_stack_deref(base_cvar, extra_offset, bits))
        bits = _effective_deref_bits(node)
        if bits not in {8, 16}:
            if _dynamic_codegen_attr(classified, "seg_name", None) == "ss":
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
