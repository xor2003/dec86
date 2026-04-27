from __future__ import annotations

"""Typed helpers for recognizing real-mode segment:offset linearizations.

The x86-16 lifter represents a real-mode memory address as
``(segment << 4) + offset`` (or equivalently ``segment * 16 + offset``).
This module centralizes that structural recognition so stack lowering can
consume a typed SS address fact instead of re-learning the arithmetic shape in
late cleanup code.
"""

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..alias.alias_model import _stack_storage_facts_for_segmented_address_8616


@dataclass(frozen=True, slots=True)
class RealModeLinearStackAccess8616:
    """Stable SS stack access recovered from real-mode linear address math."""

    displacement: int
    width: int | None


def _strip_casts_8616(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _segment_base_name_8616(node, project) -> str | None:
    """Return the segment register name for ``seg << 4`` or ``seg * 16``."""

    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    expected_scale = 4 if node.op == "Shl" else 16 if node.op == "Mul" else None
    if expected_scale is None:
        return None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_value_8616(maybe_scale) != expected_scale:
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        if not isinstance(maybe_seg, structured_c.CVariable):
            continue
        variable = getattr(maybe_seg, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            continue
        return getattr(project.arch, "register_names", {}).get(variable.reg)
    return None


def _flatten_signed_terms_8616(node, sign: int = 1) -> tuple[tuple[int, object], ...]:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, sign)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, -sign)
    return ((sign, node),)


def _iter_statement_nodes_8616(root):
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current is None or not type(current).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "condition", "init", "iteration"):
            value = getattr(current, attr, None)
            if value is None:
                continue
            if isinstance(value, list | tuple):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)


def _same_variable_storage_8616(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lhs_var = getattr(lhs, "variable", None)
    rhs_var = getattr(rhs, "variable", None)
    if lhs_var is rhs_var:
        return True
    lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
    rhs_name = getattr(rhs, "name", None) or getattr(rhs_var, "name", None)
    if isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name:
        return True
    return (
        isinstance(lhs_var, SimRegisterVariable)
        and isinstance(rhs_var, SimRegisterVariable)
        and getattr(lhs_var, "reg", None) == getattr(rhs_var, "reg", None)
        and getattr(lhs_var, "size", None) == getattr(rhs_var, "size", None)
    )


def _single_assignment_rhs_8616(codegen, target):
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None or not isinstance(target, structured_c.CVariable):
        return None
    matches = []
    for stmt in _iter_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        if not _same_variable_storage_8616(getattr(stmt, "lhs", None), target):
            continue
        matches.append(getattr(stmt, "rhs", None))
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def _stack_pointer_carrier_offset_8616(node, project, codegen) -> int | None:
    """Recover a stack-pointer carrier from existing stack-probe facts."""

    variable = getattr(node, "variable", None) if isinstance(node, structured_c.CVariable) else None
    dirty = getattr(node, "dirty", None)
    if isinstance(variable, SimRegisterVariable):
        reg = getattr(variable, "reg", None)
        size = getattr(variable, "size", None)
    else:
        reg = getattr(dirty, "reg", None)
        bits = getattr(dirty, "bits", None)
        size = (bits // 8) if isinstance(bits, int) else None
        varid = getattr(dirty, "varid", None)
        if not isinstance(reg, int) and isinstance(varid, int):
            target_name = f"vvar_{varid}"
            resolved = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name)
            if resolved is not None:
                return _stack_offset_from_expr_8616(resolved, project, codegen)
            delta = _stack_probe_carrier_delta_8616(node, codegen)
            if delta is not None:
                return delta
    sp_reg, sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
    if not (isinstance(sp_reg, int) and reg == sp_reg and (size is None or size == sp_size)):
        return None
    facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
    if not facts:
        return None
    for fact in facts.values():
        if getattr(fact, "segment_space", None) != "ss":
            continue
        width = getattr(fact, "width", None)
        if isinstance(width, int) and width > 0:
            return 0
    return None


def _lhs_name_8616(lhs) -> str | None:
    """Extract variable name from CVariable or CDirtyExpression LHS."""
    if isinstance(lhs, structured_c.CVariable):
        return getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
    dirty = getattr(lhs, "dirty", None)
    if dirty is not None:
        name = getattr(dirty, "name", None)
        if isinstance(name, str):
            return name
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
    return None


def _single_assignment_rhs_for_virtual_name_8616(codegen, target_name: str, *, allow_multi: bool = False):
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return None
    matches = []
    for stmt in _iter_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs = getattr(stmt, "lhs", None)
        lhs_name = _lhs_name_8616(lhs)
        if lhs_name != target_name:
            continue
        matches.append(getattr(stmt, "rhs", None))
        if not allow_multi and len(matches) > 1:
            return None
    return matches[0] if matches else None


def _extract_vvar_id_8616(node) -> int | None:
    dirty = getattr(node, "dirty", None)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        return varid
    if isinstance(node, structured_c.CVariable):
        for candidate in (getattr(node, "name", None), getattr(getattr(node, "variable", None), "name", None)):
            if not (isinstance(candidate, str) and candidate.startswith("vvar_")):
                continue
            try:
                return int(candidate.removeprefix("vvar_"), 10)
            except ValueError:
                return None
    return None


def _stack_probe_carrier_delta_8616(node, codegen) -> int | None:
    varid = _extract_vvar_id_8616(node)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if not isinstance(varid, int) or root is None:
        return None

    # Seed deltas from vvars assigned directly from stack-pointer expressions.
    # A base carrier is either the SP register (when SS stack-probe facts exist)
    # or a reference to a stack variable (&stack_var) whose offset is known.
    deltas: dict[int, int] = {}
    project = getattr(codegen, "project", None)
    sp_reg, _sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
    facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
    has_ss_facts = any(
        getattr(fact, "segment_space", None) == "ss" for fact in facts.values()
    )
    def _seed_from_init(expr, lhs_id):
        """Try to seed a carrier delta from a single init expression."""
        if expr is None:
            return None
        rhs_stripped = _strip_casts_8616(expr)
        ref_node: object = None
        const_delta: int = 0
        if isinstance(rhs_stripped, structured_c.CUnaryOp) and rhs_stripped.op == "Reference":
            ref_node = rhs_stripped.operand
        elif isinstance(rhs_stripped, structured_c.CBinaryOp) and rhs_stripped.op in {"Add", "Sub"}:
            if isinstance(_strip_casts_8616(rhs_stripped.lhs), structured_c.CUnaryOp):
                lhs_u = _strip_casts_8616(rhs_stripped.lhs)
                if lhs_u.op == "Reference":
                    ref_node = lhs_u.operand
                    rhs_const = _constant_value_8616(rhs_stripped.rhs)
                    if rhs_const is not None:
                        const_delta = rhs_const if rhs_stripped.op == "Add" else -rhs_const
            if ref_node is None and isinstance(_strip_casts_8616(rhs_stripped.rhs), structured_c.CUnaryOp):
                rhs_u = _strip_casts_8616(rhs_stripped.rhs)
                if rhs_u.op == "Reference" and rhs_stripped.op == "Add":
                    ref_node = rhs_u.operand
                    lhs_const = _constant_value_8616(rhs_stripped.lhs)
                    if lhs_const is not None:
                        const_delta = lhs_const
        if ref_node is not None:
            operand = _strip_casts_8616(ref_node)
            if isinstance(operand, structured_c.CVariable):
                var = getattr(operand, "variable", None)
                if isinstance(var, SimStackVariable):
                    offset = getattr(var, "offset", None)
                    if isinstance(offset, int):
                        deltas[lhs_id] = offset + const_delta
                        return True
        # SP register with SS stack-probe facts
        if isinstance(rhs_stripped, structured_c.CVariable):
            var = getattr(rhs_stripped, "variable", None)
            if isinstance(var, SimRegisterVariable) and getattr(var, "reg", None) == sp_reg and has_ss_facts:
                deltas[lhs_id] = 0
                return True
        return None

    for stmt in _iter_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs_id = _extract_vvar_id_8616(getattr(stmt, "lhs", None))
        if not isinstance(lhs_id, int):
            continue
        _seed_from_init(getattr(stmt, "rhs", None), lhs_id)

    changed = True
    while changed:
        changed = False
        for stmt in _iter_statement_nodes_8616(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs_id = _extract_vvar_id_8616(getattr(stmt, "lhs", None))
            if not isinstance(lhs_id, int) or lhs_id in deltas:
                continue
            base_ids: list[tuple[int, int]] = []
            const_total = 0
            unknown = False
            for sign, term in _flatten_signed_terms_8616(getattr(stmt, "rhs", None)):
                base_id = _extract_vvar_id_8616(term)
                if isinstance(base_id, int):
                    base_ids.append((sign, base_id))
                    continue
                const = _constant_value_8616(term)
                if const is not None:
                    const_total += sign * const
                    continue
                unknown = True
            if unknown or len(base_ids) != 1:
                continue
            sign, base_id = base_ids[0]
            if sign != 1 or base_id not in deltas:
                continue
            deltas[lhs_id] = deltas[base_id] + const_total
            changed = True
    return deltas.get(varid)


def _stack_offset_from_expr_8616(node, project, codegen, seen: set[int] | None = None) -> int | None:
    if seen is None:
        seen = set()
    node = _strip_casts_8616(node)
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)

    const = _constant_value_8616(node)
    if const is not None:
        return const

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
        operand = _strip_casts_8616(node.operand)
        variable = getattr(operand, "variable", None) if isinstance(operand, structured_c.CVariable) else None
        if isinstance(variable, SimStackVariable) and isinstance(getattr(variable, "offset", None), int):
            return variable.offset
        return None

    if isinstance(node, structured_c.CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimRegisterVariable):
            carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen)
            if carrier_offset is not None:
                return carrier_offset
        rhs = _single_assignment_rhs_8616(codegen, node)
        if rhs is not None:
            return _stack_offset_from_expr_8616(rhs, project, codegen, seen)
        # Fallback: try name-based lookup for virtual variables (vvar_*, tmp_*, ir_*)
        node_name = getattr(node, "name", None) or getattr(variable, "name", None)
        if isinstance(node_name, str) and (
            node_name.startswith("vvar_")
            or node_name.startswith("tmp_")
            or node_name.startswith("ir_")
        ):
            rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, node_name)
            if rhs is not None:
                return _stack_offset_from_expr_8616(rhs, project, codegen, seen)
        # Fallback: try vvar carrier-delta resolution for ss << 4 + vvar patterns
        if isinstance(node_name, str) and node_name.startswith("vvar_"):
            delta = _stack_probe_carrier_delta_8616(node, codegen)
            if delta is not None:
                return delta
        return None

    # CDirtyExpression: extract varid/name and try vvar resolution
    dirty = getattr(node, "dirty", None)
    if dirty is not None:
        varid = getattr(dirty, "varid", None)
        dirty_name = getattr(dirty, "name", None)
        _diag = {}
        if isinstance(varid, int):
            _diag["varid"] = varid
            target_name = f"vvar_{varid}"
            rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name, allow_multi=True)
            if rhs is not None:
                resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
                if resolved is not None:
                    return resolved
                _diag["rhs_found_but_unresolvable"] = True
            else:
                _diag["rhs_not_found"] = True
            delta = _stack_probe_carrier_delta_8616(node, codegen)
            if delta is not None:
                return delta
            _diag["carrier_delta_none"] = True
        elif isinstance(dirty_name, str):
            _diag["dirty_name"] = dirty_name
            if dirty_name.startswith("vvar_") or dirty_name.startswith("tmp_") or dirty_name.startswith("ir_"):
                rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
                if rhs is not None:
                    resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
                    if resolved is not None:
                        return resolved
                    _diag["rhs_found_but_unresolvable"] = True
                else:
                    _diag["rhs_not_found"] = True
        else:
            _diag["no_varid_or_name"] = True
        # Try SP carrier
        carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen)
        if carrier_offset is not None:
            return carrier_offset
        _diag["carrier_none"] = True
        _log_refusal_8616(codegen, "cdirty_diag", **_diag)
        return None

    dirty_carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen)
    if dirty_carrier_offset is not None:
        return dirty_carrier_offset

    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = _stack_offset_from_expr_8616(node.lhs, project, codegen, seen)
        rhs = _stack_offset_from_expr_8616(node.rhs, project, codegen, seen)
        if lhs is None and _constant_value_8616(node.rhs) is not None:
            return None
        if rhs is None and _constant_value_8616(node.lhs) is not None and node.op == "Add":
            return None
        if lhs is None or rhs is None:
            return None
        return lhs + rhs if node.op == "Add" else lhs - rhs

    return None


def _log_refusal_8616(codegen, kind: str, /, **details: object) -> None:
    refusals = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
    if isinstance(refusals, list):
        refusals.append({"kind": kind, **{k: str(v) for k, v in details.items()}})


def match_stable_ss_linear_stack_access_8616(node, project, codegen) -> RealModeLinearStackAccess8616 | None:
    """Match a dereference of ``(ss << 4) + stack_offset`` with stack proof."""

    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None

    segment_name: str | None = None
    offset_total = 0
    offset_terms: list[object] = []
    for sign, term in _flatten_signed_terms_8616(node.operand):
        seg = _segment_base_name_8616(term, project)
        if seg is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = seg
            continue
        const = _constant_value_8616(term)
        if const is not None:
            offset_total += sign * const
            continue
        offset_terms.append(term if sign == 1 else structured_c.CBinaryOp("Sub", structured_c.CConstant(0, None, codegen=codegen), term, codegen=codegen))

    if segment_name != "ss" or len(offset_terms) != 1:
        _log_refusal_8616(codegen, "segment_or_terms", segment=segment_name, terms=len(offset_terms))
        return None
    base_offset = _stack_offset_from_expr_8616(offset_terms[0], project, codegen)
    if base_offset is None:
        _log_refusal_8616(codegen, "offset_unresolved", segment=segment_name, offset_expr_type=type(offset_terms[0]).__name__, const_offset=offset_total)
        return None
    displacement = base_offset + offset_total
    width_bits = getattr(getattr(node, "type", None), "size", None)
    width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
    region = getattr(getattr(codegen, "cfunc", None), "addr", None)
    facts = _stack_storage_facts_for_segmented_address_8616("ss", displacement, width, region=region)
    if facts is None or facts.identity is None:
        _log_refusal_8616(codegen, "no_stack_facts", displacement=displacement, width=width, region=region)
        return None
    return RealModeLinearStackAccess8616(displacement=displacement, width=width)


def lower_stable_ss_linear_stack_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable SS real-mode linear dereferences with stack variables."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def stack_cvar(access: RealModeLinearStackAccess8616):
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) == access.displacement:
                    return cvar
        variable = SimStackVariable(access.displacement, access.width or 1, base="bp", name=f"s_{access.displacement & 0xffff:x}", region=getattr(codegen.cfunc, "addr", None))
        cvar = structured_c.CVariable(variable, variable_type=None, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    changed = False

    def transform(node):
        nonlocal changed
        access = match_stable_ss_linear_stack_access_8616(node, project, codegen)
        if access is not None:
            changed = True
            return stack_cvar(access)
        return node

    def replace_children(node) -> bool:
        local_changed = False
        for attr in ("statements", "lhs", "rhs", "operand", "expr", "init", "condition", "iteration", "body", "else_node"):
            if not hasattr(node, attr):
                continue
            value = getattr(node, attr)
            if isinstance(value, list):
                for index, item in enumerate(tuple(value)):
                    replacement = transform(item)
                    if replacement is not item:
                        value[index] = replacement
                        local_changed = True
                    if replace_children(value[index]):
                        local_changed = True
            elif value is not None:
                replacement = transform(value)
                if replacement is not value:
                    setattr(node, attr, replacement)
                    local_changed = True
                    value = replacement
                if replace_children(value):
                    local_changed = True
        return local_changed

    if replace_children(root):
        changed = True
    return changed


__all__ = (
    "RealModeLinearStackAccess8616",
    "lower_stable_ss_linear_stack_dereferences_8616",
    "match_stable_ss_linear_stack_access_8616",
)
