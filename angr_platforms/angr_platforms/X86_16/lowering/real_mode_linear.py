"""Typed helpers for recognizing real-mode segment:offset linearizations.

The x86-16 lifter represents a real-mode memory address as
``(segment << 4) + offset`` (or equivalently ``segment * 16 + offset``).
This module centralizes that structural recognition so stack lowering can
consume a typed SS address fact instead of re-learning the arithmetic shape in
late cleanup code.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable
from capstone.x86_const import X86_INS_MOV, X86_INS_POP, X86_INS_PUSH, X86_INS_RET, X86_REG_BP, X86_REG_SP

from ..alias.alias_model import _stack_storage_facts_for_segmented_address_8616
from .stack_lowering_from_facts import _canonical_stack_offset_8616, _stack_object_name

_SEGMENT_REGISTER_NAMES_8616 = {"cs", "ds", "es", "ss"}
log = logging.getLogger(__name__)


def _dirty_reg_offset_8616(dirty) -> int | None:
    for attr in ("reg", "reg_offset", "parameter_reg_offset"):
        value = getattr(dirty, attr, None)
        if isinstance(value, int):
            return value
    return None


@dataclass(frozen=True, slots=True)
class RealModeLinearStackAccess8616:
    """Stable SS stack access recovered from real-mode linear address math."""

    displacement: int
    width: int | None


@dataclass(frozen=True, slots=True)
class RealModeLinearGlobalAddress8616:
    """Stable DS/ES address-valued expression recovered from real-mode linear math."""

    segment_name: str
    displacement: int
    residual_terms: tuple[tuple[int, object], ...]
    width: int | None = None


_UNRESOLVED_STACK_OFFSET_8616 = object()


def _type_for_access_width_8616(width: int | None):
    if width == 1:
        return SimTypeChar(False)
    return SimTypeShort(False)


def _strip_casts_8616(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _stack_base_bp_bias_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base":
        # Preserve a neutral anchor for direct stack_base arithmetic. The
        # conversion to BP-relative byte offsets happens in expression-specific
        # handling below.
        return 0
    return None


def _is_stack_base_placeholder_8616(node) -> bool:
    node = _strip_casts_8616(node)
    return isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base"


def _segment_base_name_8616(node, project, codegen=None) -> str | None:
    """Return the segment register name for ``seg << 4`` or ``seg * 16``.

    If the segment term is a temporary name (for example ``vvar_*``), resolve
    its defining expression and retry. This keeps SS/DS/ES lowering sound while
    still avoiding speculative text-driven matching.
    """

    return _segment_base_name_8616_impl(node, project, codegen, set())


def _segment_base_name_8616_impl(
    node,
    project,
    codegen,
    seen: set[int],
) -> str | None:
    node = _strip_casts_8616(node)
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)

    if not isinstance(node, structured_c.CBinaryOp):
        dirty = getattr(node, "dirty", None)
        if dirty is not None:
            reg = _dirty_reg_offset_8616(dirty)
            if isinstance(reg, int):
                reg_name = getattr(project.arch, "register_names", {}).get(reg)
                if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
                    return reg_name
            dirty_name = getattr(dirty, "name", None)
            varid = getattr(dirty, "varid", None)
            if isinstance(varid, int):
                dirty_name = f"vvar_{varid}"
            if isinstance(dirty_name, str) and dirty_name.startswith(("vvar_", "tmp_", "ir_")) and codegen is not None:
                rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
                if rhs is not None:
                    return _segment_base_name_8616_impl(rhs, project, codegen, seen)
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                reg_name = getattr(project.arch, "register_names", {}).get(variable.reg)
                if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
                    return reg_name
                return None

            variable_name = getattr(node, "name", None) or getattr(variable, "name", None)
            if isinstance(variable_name, str) and variable_name.startswith(("vvar_", "tmp_", "ir_")) and codegen is not None:
                rhs = _single_assignment_rhs_8616(codegen, node)
                if rhs is not None:
                    return _segment_base_name_8616_impl(rhs, project, codegen, seen)
        return None

    expected_scale = 4 if node.op == "Shl" else 16 if node.op == "Mul" else None
    if expected_scale is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[ss-linear-lowering] segment-base non-scale op=%r expr=%s",
                getattr(node, "op", None),
                _debug_c_repr_8616(node),
            )
        return None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        scale_value = _constant_value_8616(maybe_scale)
        if scale_value != expected_scale:
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[ss-linear-lowering] segment-base scale mismatch op=%r expected=%r got=%r seg=%s scale=%s expr=%s",
                    node.op,
                    expected_scale,
                    scale_value,
                    _debug_c_repr_8616(maybe_seg),
                    _debug_c_repr_8616(maybe_scale),
                    _debug_c_repr_8616(node),
                )
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        segment_name = _segment_base_name_8616_impl(maybe_seg, project, codegen, seen)
        if segment_name is not None:
            return segment_name
    return None


def _flatten_signed_terms_8616(
    node,
    sign: int = 1,
) -> tuple[tuple[int, object], ...] | None:
    def _impl():
        terms: list[tuple[int, object]] = []
        # We use an explicit stack to avoid recursion depth crashes on very deep trees.
        # active path markers prevent infinite loops from cyclic expressions.
        pending: list[tuple[object, int, bool]] = [(node, sign, False)]
        active: set[int] = set()

        while pending:
            current, current_sign, exiting = pending.pop()
            current = _strip_casts_8616(current)
            if current is None:
                return None
            if exiting:
                if isinstance(current, int):
                    active.discard(current)
                continue

            node_id = id(current)
            if node_id in active:
                return None
            if len(active) > 1024:
                return None

            if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
                active.add(node_id)
                pending.append((node_id, 0, True))
                pending.append((current.rhs, current_sign, False))
                pending.append((current.lhs, current_sign, False))
                continue
            if isinstance(current, structured_c.CBinaryOp) and current.op == "Sub":
                active.add(node_id)
                pending.append((node_id, 0, True))
                pending.append((current.rhs, -current_sign, False))
                pending.append((current.lhs, current_sign, False))
                continue

            terms.append((current_sign, current))
            if len(terms) > 4096:
                return None

        return tuple(terms)

    return _impl()


def _decompose_linear_global_terms_8616(
    node,
    project,
    codegen=None,
) -> tuple[str | None, int, tuple[tuple[int, object], ...]] | None:
    segment_name: str | None = None
    displacement = 0
    residual_terms: list[tuple[int, object]] = []

    terms = _flatten_signed_terms_8616(node)
    if terms is None:
        return None
    for sign, term in terms:
        seg = _segment_base_name_8616(term, project, codegen=codegen)
        if seg is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = seg
            continue
        const = _constant_value_8616(term)
        if const is not None:
            displacement += sign * const
            continue
        if not _address_projection_term_is_safe_8616(term):
            return None
        residual_terms.append((sign, term))

    return segment_name, displacement, tuple(residual_terms)


def _global_displacement_known_8616(codegen, displacement: int) -> bool:
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    addr = displacement & 0xFFFF
    global_name = f"g_{addr:04X}"
    for variable in variables_in_use:
        if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
            return True
        if isinstance(variable, SimVariable) and getattr(variable, "name", None) == global_name:
            return True
    return False


def _global_size_from_displacement_8616(codegen, displacement: int) -> int | None:
    def _impl():
        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if not isinstance(variables_in_use, dict):
            return None
        addr = displacement & 0xFFFF
        global_name = f"g_{addr:04X}"
        for variable in variables_in_use:
            if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
                size = getattr(variable, "size", None)
                if isinstance(size, int) and size > 0:
                    return size
            if isinstance(variable, SimVariable) and getattr(variable, "name", None) == global_name:
                cvar = variables_in_use[variable]
                declared = getattr(cvar, "variable", None)
                if isinstance(declared, SimMemoryVariable):
                    size = getattr(declared, "size", None)
                    if isinstance(size, int) and size > 0:
                        return size
                size = getattr(declared, "size", None) if declared is not None else None
                if isinstance(size, int) and size > 0:
                    return size
        return None

    return _impl()


def _cvar_has_array_type_8616(cvar) -> bool:
    type_name = type(getattr(cvar, "variable_type", None)).__name__
    return "Array" in type_name


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
    def _impl():
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

    return _impl()


# ── Precomputed maps (built once per lowering pass) ──


def _build_assignment_maps_8616(codegen):
    def _impl():
        """Precompute assignment maps used by lowering and validation fingerprinting."""
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return ({}, {}, {}, set(), set(), set(), {}, {})

        var_id_map: dict[int, object] = {}
        name_map: dict[str, object] = {}
        reg_map: dict[tuple, object] = {}
        multi_var: set[int] = set()
        multi_name: set[str] = set()
        multi_reg: set[tuple] = set()
        first_name_map: dict[str, object] = {}
        first_reg_map: dict[tuple, object] = {}

        for stmt in _iter_statement_nodes_8616(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            rhs = getattr(stmt, "rhs", None)

            if not isinstance(lhs, structured_c.CVariable):
                # CDirtyExpression lhs — record via dirty.name / dirty.varid
                dirty_lhs = getattr(lhs, "dirty", None) if lhs is not None else None
                if dirty_lhs is not None and os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                    log.warning(
                        "[ss-linear-lowering] assignment-map dirty lhs text=%s varid=%r tmp_idx=%r reg_offset=%r variable_offset=%r category=%r was_reg=%r was_tmp=%r rhs=%s",
                        _debug_c_repr_8616(lhs),
                        getattr(dirty_lhs, "varid", None),
                        getattr(dirty_lhs, "tmp_idx", None),
                        getattr(dirty_lhs, "reg_offset", None),
                        getattr(dirty_lhs, "variable_offset", None),
                        getattr(dirty_lhs, "category", None),
                        getattr(dirty_lhs, "was_reg", None),
                        getattr(dirty_lhs, "was_tmp", None),
                        _debug_c_repr_8616(rhs),
                    )
                dirty_name = getattr(dirty_lhs, "name", None)
                dirty_varid = getattr(dirty_lhs, "varid", None)
                if isinstance(dirty_name, str):
                    if dirty_name not in first_name_map:
                        first_name_map[dirty_name] = rhs
                    if dirty_name in name_map:
                        multi_name.add(dirty_name)
                        name_map[dirty_name] = None
                    elif dirty_name not in multi_name:
                        name_map[dirty_name] = rhs
                if isinstance(dirty_varid, int):
                    vvar_name = f"vvar_{dirty_varid}"
                    if vvar_name not in first_name_map:
                        first_name_map[vvar_name] = rhs
                    if vvar_name in name_map:
                        multi_name.add(vvar_name)
                        name_map[vvar_name] = None
                    elif vvar_name not in multi_name:
                        name_map[vvar_name] = rhs
                continue

            var = getattr(lhs, "variable", None)

            var_id = id(var) if var is not None else None
            if var_id is not None:
                if var_id in var_id_map:
                    multi_var.add(var_id)
                    var_id_map[var_id] = None
                elif var_id not in multi_var:
                    var_id_map[var_id] = rhs

            name = getattr(lhs, "name", None) or getattr(var, "name", None)
            if isinstance(name, str) and name:
                if name not in first_name_map:
                    first_name_map[name] = rhs
                if name in name_map:
                    multi_name.add(name)
                    name_map[name] = None
                elif name not in multi_name:
                    name_map[name] = rhs

            if isinstance(var, SimRegisterVariable):
                reg = getattr(var, "reg", None)
                size = getattr(var, "size", None)
                if isinstance(reg, int) and isinstance(size, int):
                    reg_key = (reg, size)
                    if reg_key not in first_reg_map:
                        first_reg_map[reg_key] = rhs
                    if reg_key in reg_map:
                        multi_reg.add(reg_key)
                        reg_map[reg_key] = None
                    elif reg_key not in multi_reg:
                        reg_map[reg_key] = rhs

        return (var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, first_name_map, first_reg_map)

    return _impl()


def _ensure_assignment_maps_8616(codegen) -> tuple:
    """Return cached maps or build and cache them on codegen."""
    cached = getattr(codegen, "_inertia_assignment_maps", None)
    if cached is not None:
        return cached
    maps = _build_assignment_maps_8616(codegen)
    setattr(codegen, "_inertia_assignment_maps", maps)
    return maps


def _build_vvar_carrier_delta_map_8616(codegen) -> dict[int, int]:
    def _impl():
        """Precompute vvar_id → carrier_delta in a single pass, caching on codegen."""
        project = getattr(codegen, "project", None)
        sp_reg, _sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
        facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
        has_ss_facts = any(getattr(fact, "segment_space", None) == "ss" for fact in facts.values())
        deltas: dict[int, int] = {}
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return deltas

        def _seed_from_init(expr, lhs_id):
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
                terms = _flatten_signed_terms_8616(getattr(stmt, "rhs", None))
                if terms is None:
                    continue
                for sign, term in terms:
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
        return deltas

    return _impl()


def _ensure_vvar_carrier_delta_map_8616(codegen) -> dict[int, int]:
    """Return cached vvar_deltas or build and cache them on codegen."""
    cached = getattr(codegen, "_inertia_vvar_carrier_deltas", None)
    if cached is not None:
        return cached
    deltas = _build_vvar_carrier_delta_map_8616(codegen)
    setattr(codegen, "_inertia_vvar_carrier_deltas", deltas)
    return deltas


# ── O(1) lookup wrappers ──


def _single_assignment_rhs_8616(codegen, target):
    def _impl():
        if not isinstance(target, structured_c.CVariable):
            return None
        var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, _first_name_map, _first_reg_map = (
            _ensure_assignment_maps_8616(codegen)
        )
        var = getattr(target, "variable", None)
        var_id = id(var) if var is not None else None
        if var_id is not None and var_id in var_id_map and var_id not in multi_var:
            return var_id_map[var_id]
        name = getattr(target, "name", None) or getattr(var, "name", None)
        if isinstance(name, str) and name in name_map and name not in multi_name:
            return name_map[name]
        if isinstance(var, SimRegisterVariable):
            reg = getattr(var, "reg", None)
            size = getattr(var, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                reg_key = (reg, size)
                if reg_key in reg_map and reg_key not in multi_reg:
                    return reg_map[reg_key]
        return None

    return _impl()


def _stack_pointer_carrier_offset_8616(
    node,
    project,
    codegen,
    seen: set[int] | None = None,
) -> int | None:
    def _impl():
        nonlocal seen
        """Recover a stack-pointer carrier from existing stack-probe facts."""

        if seen is None:
            seen = set()

        variable = getattr(node, "variable", None) if isinstance(node, structured_c.CVariable) else None
        dirty = getattr(node, "dirty", None)
        if isinstance(variable, SimRegisterVariable):
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
        else:
            reg = _dirty_reg_offset_8616(dirty)
            bits = getattr(dirty, "bits", None)
            size = (bits // 8) if isinstance(bits, int) else None
            varid = getattr(dirty, "varid", None)
            if not isinstance(reg, int) and isinstance(varid, int):
                target_name = f"vvar_{varid}"
                resolved = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name)
                if resolved is not None:
                    return _stack_offset_from_expr_8616(resolved, project, codegen, seen)
                delta = _stack_probe_carrier_delta_8616(node, codegen)
                if delta is not None:
                    return delta
        bp_reg, bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
        if isinstance(bp_reg, int) and reg == bp_reg and (size is None or size == bp_size):
            return 0

        sp_reg, sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
        if not (isinstance(sp_reg, int) and reg == sp_reg and (size is None or size == sp_size)):
            return None
        if getattr(codegen, "_inertia_allow_direct_sp_for_callee_save_spill", False):
            return 0
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

    return _impl()


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
    (
        _unused_var_id_map,
        name_map,
        _unused_reg_map,
        _unused_multi_var,
        multi_name,
        _unused_multi_reg,
        first_name_map,
        _first_reg_map,
    ) = _ensure_assignment_maps_8616(codegen)
    if allow_multi:
        # O(1) lookup from precomputed first-assignment map
        return first_name_map.get(target_name)
    if target_name in name_map and target_name not in multi_name:
        return name_map[target_name]
    return None


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
    if not isinstance(varid, int):
        return None
    deltas = _ensure_vvar_carrier_delta_map_8616(codegen)
    return deltas.get(varid)


def _resolve_virtual_name_offset_8616(node_name: str, project, codegen, seen: set[int]) -> int | None:
    if not (
        node_name.startswith("vvar_")
        or node_name.startswith("tmp_")
        or node_name.startswith("ir_")
    ):
        return None
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, node_name)
    if rhs is None:
        return None
    return _stack_offset_from_expr_8616(rhs, project, codegen, seen)


def _resolve_stack_offset_from_variable_8616(node, project, codegen, seen: set[int]) -> int | None:
    variable = getattr(node, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
        if carrier_offset is not None:
            return carrier_offset
    rhs = _single_assignment_rhs_8616(codegen, node)
    if rhs is not None:
        return _stack_offset_from_expr_8616(rhs, project, codegen, seen)
    node_name = getattr(node, "name", None) or getattr(variable, "name", None)
    if isinstance(node_name, str):
        resolved = _resolve_virtual_name_offset_8616(node_name, project, codegen, seen)
        if resolved is not None:
            return resolved
        if node_name.startswith("vvar_"):
            return _stack_probe_carrier_delta_8616(node, codegen)
    return None


def _dirty_varid_offset_8616(varid: int, node, project, codegen, seen: set[int], diag: dict[str, object]) -> int | None:
    diag["varid"] = varid
    target_name = f"vvar_{varid}"
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name, allow_multi=True)
    if rhs is not None:
        resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
        if resolved is not None:
            return resolved
        diag["rhs_found_but_unresolvable"] = True
    else:
        diag["rhs_not_found"] = True
    delta = _stack_probe_carrier_delta_8616(node, codegen)
    if delta is not None:
        return delta
    diag["carrier_delta_none"] = True
    return None


def _dirty_name_offset_8616(dirty_name: str, project, codegen, seen: set[int], diag: dict[str, object]) -> int | None:
    diag["dirty_name"] = dirty_name
    resolved = _resolve_virtual_name_offset_8616(dirty_name, project, codegen, seen)
    if resolved is not None:
        return resolved
    if dirty_name.startswith("vvar_") or dirty_name.startswith("tmp_") or dirty_name.startswith("ir_"):
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
        if rhs is None:
            diag["rhs_not_found"] = True
        else:
            diag["rhs_found_but_unresolvable"] = True
    return None


def _resolve_stack_offset_from_dirty_8616(node, project, codegen, seen: set[int]) -> int | None:
    dirty = getattr(node, "dirty", None)
    if dirty is None:
        return None
    varid = getattr(dirty, "varid", None)
    dirty_name = getattr(dirty, "name", None)
    diag: dict[str, object] = {}
    if isinstance(varid, int):
        resolved = _dirty_varid_offset_8616(varid, node, project, codegen, seen, diag)
        if resolved is not None:
            return resolved
    elif isinstance(dirty_name, str):
        resolved = _dirty_name_offset_8616(dirty_name, project, codegen, seen, diag)
        if resolved is not None:
            return resolved
    else:
        diag["no_varid_or_name"] = True
    carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
    if carrier_offset is not None:
        return carrier_offset
    dirty_reg = _dirty_reg_offset_8616(dirty)
    bp_reg, _bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
    if isinstance(dirty_reg, int) and isinstance(bp_reg, int) and dirty_reg == bp_reg:
        return 0
    diag["carrier_none"] = True
    _log_refusal_8616(codegen, "cdirty_diag", **diag)
    return None


def _resolve_binary_stack_base_shortcuts_8616(node, codegen) -> int | None:
    if _is_stack_base_placeholder_8616(node.lhs):
        rhs_const = _constant_value_8616(node.rhs)
        if rhs_const is not None:
            base = _stack_base_bp_bias_8616(node.lhs) or 0
            scaled = int(rhs_const) * 2
            return base + (scaled if node.op == "Add" else -scaled)
    if node.op == "Add" and _is_stack_base_placeholder_8616(node.rhs):
        lhs_const = _constant_value_8616(node.lhs)
        if lhs_const is not None:
            base = _stack_base_bp_bias_8616(node.rhs) or 0
            return base + int(lhs_const) * 2
    return None


def _resolve_binary_stack_probe_fallback_8616(node, lhs, rhs, codegen) -> int | None:
    if lhs is None:
        rhs_const = _constant_value_8616(node.rhs)
        lhs_delta = _stack_probe_carrier_delta_8616(_strip_casts_8616(node.lhs), codegen)
        if isinstance(rhs_const, int) and isinstance(lhs_delta, int):
            return lhs_delta + (rhs_const if node.op == "Add" else -rhs_const)
    if rhs is None and node.op == "Add":
        lhs_const = _constant_value_8616(node.lhs)
        rhs_delta = _stack_probe_carrier_delta_8616(_strip_casts_8616(node.rhs), codegen)
        if isinstance(lhs_const, int) and isinstance(rhs_delta, int):
            return lhs_const + rhs_delta
    return None


def _resolve_stack_offset_from_binary_8616(node, project, codegen, seen: set[int]) -> int | None:
    def _impl():
        shortcut = _resolve_binary_stack_base_shortcuts_8616(node, codegen)
        if shortcut is not None:
            return shortcut
        lhs = _stack_offset_from_expr_8616(node.lhs, project, codegen, seen)
        rhs = _stack_offset_from_expr_8616(node.rhs, project, codegen, seen)
        fallback = _resolve_binary_stack_probe_fallback_8616(node, lhs, rhs, codegen)
        if fallback is not None:
            return fallback
        if lhs is None and _constant_value_8616(node.rhs) is not None:
            return None
        if rhs is None and _constant_value_8616(node.lhs) is not None and node.op == "Add":
            return None
        if lhs is None or rhs is None:
            return None
        return lhs + rhs if node.op == "Add" else lhs - rhs

    return _impl()


def _stack_offset_from_expr_8616(node, project, codegen, seen: set[int] | None = None) -> int | None:
    def _impl():
        nonlocal node, seen
        if seen is None:
            seen = set()
        node = _strip_casts_8616(node)
        node_id = id(node)
        offset_cache = getattr(codegen, "_inertia_stack_offset_cache", None)
        if not isinstance(offset_cache, dict):
            offset_cache = {}
            setattr(codegen, "_inertia_stack_offset_cache", offset_cache)

        if node_id in offset_cache:
            cached = offset_cache.get(node_id)
            if cached is _UNRESOLVED_STACK_OFFSET_8616:
                return None
            return cached

        if node_id in seen:
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        if len(seen) > 8192:
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        seen.add(node_id)

        const = _constant_value_8616(node)
        if const is not None:
            offset_cache[node_id] = const
            return const

        stack_base_bias = _stack_base_bp_bias_8616(node)
        if stack_base_bias is not None:
            offset_cache[node_id] = stack_base_bias
            return stack_base_bias

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = _strip_casts_8616(node.operand)
            variable = getattr(operand, "variable", None) if isinstance(operand, structured_c.CVariable) else None
            if isinstance(variable, SimStackVariable) and isinstance(getattr(variable, "offset", None), int):
                offset_cache[node_id] = variable.offset
                return variable.offset
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None

        if isinstance(node, structured_c.CVariable):
            resolved = _resolve_stack_offset_from_variable_8616(node, project, codegen, seen)
            offset_cache[node_id] = resolved if resolved is not None else _UNRESOLVED_STACK_OFFSET_8616
            return resolved

        dirty_resolved = _resolve_stack_offset_from_dirty_8616(node, project, codegen, seen)
        if dirty_resolved is not None:
            offset_cache[node_id] = dirty_resolved
            return dirty_resolved

        dirty_carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
        if dirty_carrier_offset is not None:
            offset_cache[node_id] = dirty_carrier_offset
            return dirty_carrier_offset

        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            resolved = _resolve_stack_offset_from_binary_8616(node, project, codegen, seen)
            offset_cache[node_id] = resolved if resolved is not None else _UNRESOLVED_STACK_OFFSET_8616
            return resolved

        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None

    return _impl()


def _log_refusal_8616(codegen, kind: str, /, **details: object) -> None:
    refusals = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
    normalized = {k: str(v) for k, v in details.items()}
    if isinstance(refusals, list):
        refusals.append({"kind": kind, **normalized})
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning("[ss-linear-lowering] refusal kind=%s details=%r", kind, normalized)


def _debug_c_repr_8616(node) -> str:
    try:
        chunks = node.c_repr_chunks(asexpr=True)
        return "".join(str(text) for text, _obj in chunks)
    except Exception:
        return repr(node)


def match_stable_ss_linear_stack_access_8616(node, project, codegen) -> RealModeLinearStackAccess8616 | None:
    def _impl():
        nonlocal node
        """Match a dereference of ``(ss << 4) + stack_offset`` with stack proof."""

        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None

        segment_name: str | None = None
        offset_total = 0
        offset_terms: list[object] = []
        terms = _flatten_signed_terms_8616(node.operand)
        if terms is None:
            return None
        for sign, term in terms:
            seg = _segment_base_name_8616(term, project, codegen=codegen)
            if seg is not None:
                if sign != 1 or segment_name is not None:
                    return None
                segment_name = seg
                continue
            const = _constant_value_8616(term)
            if const is not None:
                offset_total += sign * const
                continue
            offset_terms.append(
                term
                if sign == 1
                else structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeInt(signed=False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            )

        if segment_name != "ss" or len(offset_terms) > 1:
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                _log_refusal_8616(
                    codegen,
                    "segment_or_terms",
                    segment=segment_name,
                    terms=len(offset_terms),
                    operand=repr(node.operand),
                    offset_term_types=tuple(type(term).__name__ for term in offset_terms),
                    offset_terms=tuple(_debug_c_repr_8616(term) for term in offset_terms),
                )
            else:
                _log_refusal_8616(codegen, "segment_or_terms", segment=segment_name, terms=len(offset_terms))
            return None

        if len(offset_terms) == 0:
            base_offset = 0
        else:
            base_offset = _stack_offset_from_expr_8616(offset_terms[0], project, codegen)

        if base_offset is None:
            _log_refusal_8616(
                codegen,
                "offset_unresolved",
                segment=segment_name,
                offset_expr_type=type(offset_terms[0]).__name__ if offset_terms else "None",
                const_offset=offset_total,
            )
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

    return _impl()


def match_stable_ds_es_linear_global_access_8616(node, project, codegen) -> RealModeLinearGlobalAddress8616 | None:
    def _impl():
        nonlocal node
        """Match a dereference of ``(ds << 4) + addr`` or ``(es << 4) + addr``."""

        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None

        decomposed = _decompose_linear_global_terms_8616(node.operand, project, codegen=codegen)
        if decomposed is None:
            return None
        segment_name, displacement, residual_terms = decomposed

        if segment_name in {"ds", "es"}:
            width_bits = getattr(getattr(node, "type", None), "size", None)
            width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
            if width is None:
                inferred_width = _global_size_from_displacement_8616(codegen, displacement)
                if isinstance(inferred_width, int) and inferred_width > 0:
                    width = inferred_width
            return RealModeLinearGlobalAddress8616(
                segment_name=segment_name,
                displacement=displacement,
                residual_terms=tuple(residual_terms),
                width=width,
            )

        if segment_name is not None or not _global_displacement_known_8616(codegen, displacement):
            return None

        width_bits = getattr(getattr(node, "type", None), "size", None)
        width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
        if width is None:
            inferred_width = _global_size_from_displacement_8616(codegen, displacement)
            if isinstance(inferred_width, int) and inferred_width > 0:
                width = inferred_width
        return RealModeLinearGlobalAddress8616(
            segment_name="segless",
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=width,
        )

    return _impl()


def _address_projection_term_is_safe_8616(node) -> bool:
    allowed_unary = {"Neg", "BitNot", "Reference"}
    allowed_binary = {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
    pending: list[object] = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            return False
        expr_id = id(expr)
        if expr_id in seen:
            return False
        seen.add(expr_id)
        if _constant_value_8616(expr) is not None:
            continue
        if isinstance(expr, structured_c.CVariable):
            continue
        if isinstance(expr, structured_c.CUnaryOp) and expr.op in allowed_unary:
            pending.append(expr.operand)
            continue
        if isinstance(expr, structured_c.CBinaryOp) and expr.op in allowed_binary:
            pending.append(expr.rhs)
            pending.append(expr.lhs)
            continue
        return False
    return True


def _return_register_virtual_name_8616(node, project) -> str | None:
    ax_reg, _ax_size = getattr(getattr(project, "arch", None), "registers", {}).get("ax", (None, None))
    pending = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        dirty = getattr(current, "dirty", None)
        if dirty is not None:
            reg = _dirty_reg_offset_8616(dirty)
            varid = getattr(dirty, "varid", None)
            if isinstance(ax_reg, int) and reg == ax_reg and isinstance(varid, int):
                return f"vvar_{varid}"
        if isinstance(current, structured_c.CVariable):
            variable = getattr(current, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                reg = getattr(variable, "reg", None)
                name = getattr(current, "name", None) or getattr(variable, "name", None)
                if isinstance(ax_reg, int) and reg == ax_reg and isinstance(name, str) and name.startswith("vvar_"):
                    return name
        for attr in ("lhs", "rhs", "operand", "expr", "cond", "iftrue", "iffalse"):
            child = getattr(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("operands", "args"):
            seq = getattr(current, attr, None)
            if seq:
                pending.extend(item for item in seq if item is not None)
    return None


def _return_rhs_is_safe_8616(expr) -> bool:
    expr = _strip_casts_8616(expr)
    if isinstance(expr, (structured_c.CConstant, structured_c.CVariable, structured_c.CDirtyExpression)):
        return True
    if isinstance(expr, structured_c.CTypeCast):
        return _return_rhs_is_safe_8616(expr.expr)
    if isinstance(expr, structured_c.CUnaryOp):
        return expr.op != "Dereference" and _return_rhs_is_safe_8616(expr.operand)
    if isinstance(expr, structured_c.CBinaryOp):
        return _return_rhs_is_safe_8616(expr.lhs) and _return_rhs_is_safe_8616(expr.rhs)
    return False


def _materialize_return_register_assignments_8616(codegen, project) -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False
    changed = False
    stack = [root]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if node is None:
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        if isinstance(node, structured_c.CReturn):
            retval = getattr(node, "retval", None)
            virtual_name = _return_register_virtual_name_8616(retval, project)
            if virtual_name is not None:
                rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, virtual_name)
                if rhs is not None and _return_rhs_is_safe_8616(rhs):
                    node.retval = rhs
                    changed = True
                    codegen._inertia_return_register_materialized_count = int(
                        getattr(codegen, "_inertia_return_register_materialized_count", 0) or 0
                    ) + 1
                    continue
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "condition", "init", "iteration"):
            value = getattr(node, attr, None)
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
    return changed


def _op_reg_id_8616(insn, index: int) -> int | None:
    operands = getattr(insn, "operands", None)
    if operands is None or len(operands) <= index:
        return None
    operand = operands[index]
    if getattr(operand, "type", None) != 1:
        return None
    reg = getattr(operand, "reg", None)
    return int(reg) if isinstance(reg, int) else None


def _is_mov_sp_bp_8616(insn) -> bool:
    if getattr(insn, "id", None) != X86_INS_MOV:
        return False
    return _op_reg_id_8616(insn, 0) == X86_REG_SP and _op_reg_id_8616(insn, 1) == X86_REG_BP


def _decode_function_insns_at_8616(project, function_addr: int, *, limit: int = 0x100) -> tuple:
    try:
        code = bytes(project.loader.memory.load(function_addr, limit))
        capstone = project.arch.capstone
        previous_detail = getattr(capstone, "detail", False)
        try:
            capstone.detail = True
            insns = []
            for insn in capstone.disasm(code, function_addr):
                insns.append(insn)
                if getattr(insn, "id", None) == X86_INS_RET:
                    break
            return tuple(insns) if any(getattr(insn, "id", None) == X86_INS_RET for insn in insns) else ()
        finally:
            capstone.detail = previous_detail
    except Exception:
        return ()


def _decode_function_insns_8616(project, function_addr: int, *, limit: int = 0x100) -> tuple:
    insns = _decode_function_insns_at_8616(project, function_addr, limit=limit)
    if insns:
        return insns
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        return _decode_function_insns_at_8616(project, function_addr + delta, limit=limit)
    return ()


def _callee_saved_register_names_from_frame_evidence_8616(project, function_addr: int) -> frozenset[str]:
    insns = _decode_function_insns_8616(project, function_addr)
    if not insns:
        return frozenset()
    callee_saved = {"bx", "si", "di"}
    pushed: list[str] = []
    for insn in insns:
        if getattr(insn, "id", None) == X86_INS_PUSH:
            reg_id = _op_reg_id_8616(insn, 0)
            if isinstance(reg_id, int):
                reg_name = insn.reg_name(reg_id)
                if reg_name in callee_saved:
                    pushed.append(reg_name)
        if getattr(insn, "id", None) == X86_INS_RET:
            break
    if not pushed:
        return frozenset()

    ret_index = next((idx for idx, insn in enumerate(insns) if getattr(insn, "id", None) == X86_INS_RET), None)
    if ret_index is None:
        return frozenset()
    restored: list[str] = []
    scan = ret_index - 1
    while scan >= 0:
        insn = insns[scan]
        insn_id = getattr(insn, "id", None)
        if insn_id == X86_INS_POP:
            reg_id = _op_reg_id_8616(insn, 0)
            if reg_id == X86_REG_BP:
                scan -= 1
                continue
            if isinstance(reg_id, int):
                reg_name = insn.reg_name(reg_id)
                if reg_name in callee_saved:
                    restored.append(reg_name)
                    scan -= 1
                    continue
        if _is_mov_sp_bp_8616(insn):
            scan -= 1
            continue
        break
    if not restored:
        return frozenset()
    return frozenset(set(pushed) & set(restored))


def _expr_register_name_8616(node, project) -> str | None:
    node = _strip_casts_8616(node)
    dirty = getattr(node, "dirty", None)
    reg_offset = _dirty_reg_offset_8616(dirty) if dirty is not None else None
    if reg_offset is None and isinstance(node, structured_c.CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimRegisterVariable):
            reg_offset = getattr(variable, "reg", None)
    if not isinstance(reg_offset, int):
        return None
    reg_name = getattr(project.arch, "register_names", {}).get(reg_offset)
    return reg_name.lower() if isinstance(reg_name, str) else None


def _remove_callee_saved_stack_spills_8616(codegen, project) -> bool:
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(function_addr, int):
        return False
    saved_regs = _callee_saved_register_names_from_frame_evidence_8616(project, function_addr)
    if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
        log.warning("[callee-save-prune] func=%#x saved_regs=%r", function_addr, sorted(saved_regs))
    if not saved_regs:
        return False
    stats = getattr(codegen, "_inertia_callee_saved_spill_prune_stats", None)
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "pruned": 0, "refused": 0}
        codegen._inertia_callee_saved_spill_prune_stats = stats

    def is_prunable(stmt) -> bool:
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _strip_casts_8616(getattr(stmt, "lhs", None))
        if not isinstance(lhs, structured_c.CUnaryOp) or lhs.op != "Dereference":
            return False
        previous_allow_sp = getattr(codegen, "_inertia_allow_direct_sp_for_callee_save_spill", False)
        previous_offset_cache = getattr(codegen, "_inertia_stack_offset_cache", None)
        codegen._inertia_allow_direct_sp_for_callee_save_spill = True
        codegen._inertia_stack_offset_cache = None
        try:
            access = match_stable_ss_linear_stack_access_8616(lhs, project, codegen)
        finally:
            codegen._inertia_allow_direct_sp_for_callee_save_spill = previous_allow_sp
            codegen._inertia_stack_offset_cache = previous_offset_cache
        if access is None:
            if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
                log.warning("[callee-save-prune] refuse no-ss-access lhs=%s", _debug_c_repr_8616(lhs))
            return False
        if not isinstance(access.displacement, int) or access.displacement >= 0:
            if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
                log.warning(
                    "[callee-save-prune] refuse displacement=%r lhs=%s",
                    getattr(access, "displacement", None),
                    _debug_c_repr_8616(lhs),
                )
            return False
        rhs_reg = _expr_register_name_8616(getattr(stmt, "rhs", None), project)
        if rhs_reg not in saved_regs:
            stats["refused"] = int(stats.get("refused", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
                log.warning(
                    "[callee-save-prune] refuse rhs_reg=%r saved=%r rhs=%s",
                    rhs_reg,
                    sorted(saved_regs),
                    _debug_c_repr_8616(getattr(stmt, "rhs", None)),
                )
            return False
        stats["candidates"] = int(stats.get("candidates", 0) or 0) + 1
        if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
            log.warning(
                "[callee-save-prune] prune displacement=%r rhs_reg=%s stmt=%s",
                access.displacement,
                rhs_reg,
                _debug_c_repr_8616(stmt),
            )
        return True

    changed = False

    def rewrite_statement_list(statements: list) -> None:
        nonlocal changed
        kept = []
        for stmt in statements:
            if is_prunable(stmt):
                stats["pruned"] = int(stats.get("pruned", 0) or 0) + 1
                changed = True
                continue
            kept.append(stmt)
        if len(kept) != len(statements):
            statements[:] = kept
        for stmt in tuple(kept):
            for attr in ("statements", "body", "else_node"):
                value = getattr(stmt, attr, None)
                if isinstance(value, structured_c.CStatements):
                    rewrite_statement_list(value.statements)
                elif isinstance(value, list):
                    rewrite_statement_list(value)
            condition_nodes = getattr(stmt, "condition_and_nodes", None)
            if isinstance(condition_nodes, list | tuple):
                for item in condition_nodes:
                    if isinstance(item, tuple) and len(item) >= 2:
                        body = item[1]
                        if isinstance(body, structured_c.CStatements):
                            rewrite_statement_list(body.statements)

    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if isinstance(root, structured_c.CStatements):
        rewrite_statement_list(root.statements)
    elif isinstance(root, list):
        rewrite_statement_list(root)
    return changed


def match_stable_ds_es_linear_global_address_8616(node, project, codegen) -> RealModeLinearGlobalAddress8616 | None:
    """Match an address-valued ``(ds << 4) + base + projection`` expression."""

    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
        return None

    decomposed = _decompose_linear_global_terms_8616(node, project, codegen=codegen)
    if decomposed is None:
        return None
    segment_name, displacement, residual_terms = decomposed

    if segment_name in {"ds", "es"}:
        return RealModeLinearGlobalAddress8616(
            segment_name=segment_name,
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=None,
        )

    if segment_name is not None or not _global_displacement_known_8616(codegen, displacement):
        return None
    return RealModeLinearGlobalAddress8616(
        segment_name="segless",
        displacement=displacement & 0xFFFF,
        residual_terms=tuple(residual_terms),
        width=None,
    )


def lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable DS/ES real-mode linear dereferences with global variable references."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def global_cvar(access: RealModeLinearGlobalAddress8616):
        addr = access.displacement & 0xFFFF
        name = f"g_{addr:04X}"
        scalar_width = min(access.width or 1, 2)
        target_type = _type_for_access_width_8616(scalar_width)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
                    existing_size = getattr(variable, "size", None)
                    if _cvar_has_array_type_8616(cvar) or (isinstance(existing_size, int) and existing_size > 2):
                        continue
                    if getattr(variable, "size", None) != scalar_width:
                        variable.size = scalar_width
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if isinstance(variable, SimVariable) and getattr(variable, "name", None) == name:
                    if _cvar_has_array_type_8616(cvar):
                        continue
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) == access.displacement:
                    replacement = SimMemoryVariable(
                        addr,
                        scalar_width,
                        name=name,
                        region=getattr(codegen.cfunc, "addr", None),
                    )
                    replacement_type = getattr(cvar, "variable_type", None) or target_type
                    replacement_cvar = structured_c.CVariable(
                        replacement, variable_type=replacement_type, codegen=codegen
                    )
                    variables_in_use.pop(variable, None)
                    variables_in_use[replacement] = replacement_cvar
                    unified = getattr(codegen.cfunc, "unified_local_vars", None)
                    if isinstance(unified, dict):
                        unified.pop(variable, None)
                        unified[replacement] = {(replacement_cvar, getattr(replacement_cvar, "variable_type", None))}
                    return replacement_cvar
        variable = SimMemoryVariable(
            addr, scalar_width, name=f"mem_{addr:04X}", region=getattr(codegen.cfunc, "addr", None)
        )
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    def global_expr(access: RealModeLinearGlobalAddress8616):
        if not access.residual_terms:
            return global_cvar(access)
        target_type = _type_for_access_width_8616(access.width)
        ptr_type = SimTypePointer(target_type).with_arch(project.arch)
        rebuilt = structured_c.CUnaryOp(
            "Reference",
            global_cvar(access),
            codegen=codegen,
        )
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=codegen,
            )
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=codegen),
            codegen=codegen,
        )

    changed = False

    def transform(node):
        nonlocal changed
        access = match_stable_ds_es_linear_global_access_8616(node, project, codegen)
        if access is not None:
            changed = True
            return global_expr(access)
        return node

    _seen = set()

    def replace_children(root_node) -> bool:
        if root_node is None:
            return False
        node_stack: list[object] = [root_node]
        local_changed = False
        while node_stack:
            node = node_stack.pop()
            if not isinstance(node, object) or node is None:
                continue
            node_id = id(node)
            if node_id in _seen:
                continue
            _seen.add(node_id)

            for attr in (
                "statements",
                "lhs",
                "rhs",
                "operand",
                "expr",
                "init",
                "condition",
                "iteration",
                "body",
                "else_node",
            ):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue

                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        if not isinstance(item, object):
                            continue
                        replacement = transform(item)
                        if replacement is not item:
                            value[index] = replacement
                            local_changed = True
                        candidate = value[index]
                        if isinstance(candidate, object):
                            node_stack.append(candidate)
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        local_changed = True
                        value = replacement
                    node_stack.append(value)

            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                new_pairs = []
                pair_changed = False
                for cond, body in condition_and_nodes:
                    new_cond = transform(cond) if isinstance(cond, object) else cond
                    new_body = transform(body) if isinstance(body, object) else body
                    if new_cond is not cond:
                        pair_changed = True
                        local_changed = True
                    if new_body is not body:
                        pair_changed = True
                        local_changed = True
                    if isinstance(new_cond, object):
                        node_stack.append(new_cond)
                    if isinstance(new_body, object):
                        node_stack.append(new_body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    if replace_children(root):
        changed = True
    if _remove_callee_saved_stack_spills_8616(codegen, project):
        changed = True
    if _materialize_return_register_assignments_8616(codegen, project):
        changed = True
    return changed


def lower_stable_ds_es_linear_global_addresses_8616(codegen, project=None) -> bool:
    """Replace stable DS/ES address-valued expressions with data-space object references."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def global_address_cvar(displacement: int):
        addr = displacement & 0xFFFF
        name = f"g_{addr:04X}"
        target_type = SimTypeChar(False)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if (
                    isinstance(variable, SimMemoryVariable)
                    and getattr(variable, "addr", None) == addr
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if (
                    isinstance(variable, SimVariable)
                    and getattr(variable, "name", None) == name
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
        variable = SimMemoryVariable(addr, 1, name=name, region=getattr(codegen.cfunc, "addr", None))
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    changed = False

    def _reference_expr(displacement: int):
        base_cvar = global_address_cvar(displacement)
        return structured_c.CUnaryOp(
            "Reference",
            base_cvar,
            codegen=codegen,
        )

    def transform(node):
        nonlocal changed
        access = match_stable_ds_es_linear_global_address_8616(node, project, codegen)
        if access is None:
            return node
        base_expr = _reference_expr(access.displacement)
        rebuilt = base_expr
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=codegen,
            )
        ptr_type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
        changed = True
        return structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=codegen)

    _seen: set[int] = set()

    def replace_children(root_node) -> bool:
        if root_node is None:
            return False
        node_stack: list[object] = [root_node]
        local_changed = False
        while node_stack:
            node = node_stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in _seen:
                continue
            _seen.add(node_id)

            for attr in (
                "statements",
                "lhs",
                "rhs",
                "operand",
                "expr",
                "init",
                "condition",
                "iteration",
                "body",
                "else_node",
            ):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        replacement = transform(item)
                        if replacement is not item:
                            value[index] = replacement
                            local_changed = True
                        item_candidate = value[index]
                        if item_candidate is not None:
                            node_stack.append(item_candidate)
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        local_changed = True
                        value = replacement
                    node_stack.append(value)

            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                new_pairs = []
                pair_changed = False
                for cond, body in condition_and_nodes:
                    new_cond = transform(cond)
                    if new_cond is not cond:
                        pair_changed = True
                        local_changed = True
                    new_body = transform(body)
                    if new_body is not body:
                        pair_changed = True
                        local_changed = True
                    if new_cond is not None:
                        node_stack.append(new_cond)
                    if new_body is not None:
                        node_stack.append(new_body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_children(root):
        changed = True
    if _materialize_return_register_assignments_8616(codegen, project):
        changed = True
    return changed


def lower_stable_ss_linear_stack_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable SS real-mode linear dereferences with stack variables."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    # Invalidate cached maps so they are rebuilt against current codegen state
    setattr(codegen, "_inertia_assignment_maps", None)
    setattr(codegen, "_inertia_vvar_carrier_deltas", None)
    setattr(codegen, "_inertia_stack_offset_cache", None)

    def stack_cvar(access: RealModeLinearStackAccess8616):
        displacement = _canonical_stack_offset_8616(access.displacement)
        target_type = _type_for_access_width_8616(access.width)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if (
                    isinstance(variable, SimStackVariable)
                    and _canonical_stack_offset_8616(getattr(variable, "offset", None)) == displacement
                ):
                    requested_size = int(access.width or 1)
                    existing_size = getattr(variable, "size", None)
                    if not isinstance(existing_size, int) or existing_size < requested_size:
                        variable.size = requested_size
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
        variable = SimStackVariable(
            displacement,
            access.width or 1,
            base="bp",
            name=_stack_object_name(displacement, codegen=codegen),
            region=getattr(codegen.cfunc, "addr", None),
        )
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    changed = False

    def transform(node):
        nonlocal changed
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        access = match_stable_ss_linear_stack_access_8616(node, project, codegen)
        if access is not None:
            changed = True
            return stack_cvar(access)
        return node

    _node_count = [0]
    _seen = set()

    def replace_children(node) -> bool:
        if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return False
        _node_count[0] += 1
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and _node_count[0] % 500 == 0:
            print(f"[lower_ss_linear] tree walk: {_node_count[0]} nodes", file=sys.stderr, flush=True)
        if id(node) in _seen:
            return False
        _seen.add(id(node))
        local_changed = False
        for attr in (
            "statements",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "init",
            "condition",
            "iteration",
            "body",
            "else_node",
        ):
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
    "RealModeLinearGlobalAddress8616",
    "RealModeLinearStackAccess8616",
    "lower_stable_ds_es_linear_global_addresses_8616",
    "lower_stable_ss_linear_stack_dereferences_8616",
    "lower_stable_ds_es_linear_global_dereferences_8616",
    "match_stable_ds_es_linear_global_address_8616",
    "match_stable_ss_linear_stack_access_8616",
    "match_stable_ds_es_linear_global_access_8616",
)
