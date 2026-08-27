"""Lowering-owned C AST matchers for proven stack-address forms.

Layer: Types/Lowering.
Responsibility: recognize proven stack-address C AST carriers for lowering.
Consumes alias, widening, and typed facts by recognizing only carriers that
feed lowering-owned stack materialization.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module exists to keep stack lowering from depending on postprocess
compatibility utilities.  It may recognize C AST carriers for stack addresses
only as an input to lowering-owned stack-slot materialization.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Protocol

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _replace_c_children_8616, _same_c_expression_8616
from .real_mode_linear import _stack_base_bp_bias_8616, _stack_pointer_carrier_offset_8616

_SEGMENT_REGISTER_NAMES_8616 = {"cs", "ds", "es", "ss"}
_LINEAR_TEMP_NAME_RE_8616 = re.compile(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)(?:\{[^}]+\})?$")


def _stack_variable_read_offsets_8616(root: object) -> frozenset[int]:
    """Return BP-stack offsets used as values across the dynamic angr C AST boundary.

    Assignment destinations are storage writes, not high-byte projection reads.
    Keeping that distinction here prevents prototype lowering from classifying
    an unrewritable lvalue as a readable ``word >> 8`` expression.
    """
    offsets: set[int] = set()

    def _collect(node: object) -> object:
        if not isinstance(node, CVariable):
            return node
        variable = node.variable
        if isinstance(variable, SimStackVariable) and isinstance(variable.offset, int):
            offsets.add(variable.offset)
        return node

    def _is_read_child(parent: object, attr: str) -> bool:
        if isinstance(parent, CAssignment) and attr == "lhs":
            return False
        return attr != "variable"

    _replace_c_children_8616(root, _collect, should_process_child=_is_read_child)
    return frozenset(offsets)


class _ArchRegisterNames8616(Protocol):
    """Project architecture view needed for C AST boundary matching."""

    register_names: Mapping[int, str]


class _ProjectArch8616(Protocol):
    """Project view needed for register-name lookups."""

    arch: _ArchRegisterNames8616


def _strip_typed_name_suffix_8616(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos >= 0:
            return name[:brace_pos]
    return name


def _is_linear_temp_name_8616(name: object) -> bool:
    normalized = _strip_typed_name_suffix_8616(name)
    return isinstance(normalized, str) and _LINEAR_TEMP_NAME_RE_8616.fullmatch(normalized) is not None


def _c_constant_value_8616(node: object) -> int | None:
    if isinstance(node, CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _segment_reg_name_8616(node: object, project: _ProjectArch8616) -> str | None:
    """Read a segment register name across the dynamic angr C AST boundary."""
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimRegisterVariable):
        return None
    reg_name = project.arch.register_names.get(variable.reg)
    if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
        return reg_name
    return None


def _single_assignment_expr_for_variable_8616(codegen: object, target: object) -> object | None:
    """Find one assignment through the dynamic angr codegen/C AST boundary."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return None

    def _iter_statement_nodes(node: object) -> Iterator[object]:
        """Walk children through the dynamic angr structured-codegen boundary."""
        stack = [node]
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            if not type(current).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                continue
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            yield current

            nested_statements = getattr(current, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                for item in reversed(tuple(nested_statements)):
                    stack.append(item)  # noqa: PERF402

            body = getattr(current, "body", None)
            if body is not None:
                stack.append(body)

            else_node = getattr(current, "else_node", None)
            if else_node is not None:
                stack.append(else_node)

            condition_and_nodes = getattr(current, "condition_and_nodes", None)
            if isinstance(condition_and_nodes, (list, tuple)):
                for pair in reversed(tuple(condition_and_nodes)):
                    if isinstance(pair, tuple):
                        for item in reversed(pair):
                            stack.append(item)  # noqa: PERF402

    matches = []
    for stmt in _iter_statement_nodes(root):
        if not isinstance(stmt, CAssignment):
            continue
        lhs = stmt.lhs
        if not isinstance(lhs, CVariable):
            continue
        if not _same_c_expression_8616(lhs, target):
            continue
        matches.append(stmt.rhs)
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def _resolve_stack_bp_term_8616(
    node: object,
    project: _ProjectArch8616 | None = None,
    codegen: object | None = None,
    seen: set[int] | None = None,
) -> object:
    """Resolve stack BP carriers across the dynamic angr C AST/codegen boundary."""
    if seen is None:
        seen = set()
    if id(node) in seen:
        return node
    seen.add(id(node))

    if isinstance(node, CTypeCast):
        resolved = _resolve_stack_bp_term_8616(node.expr, project, codegen, seen)
        return resolved if resolved is not node.expr else node

    if not isinstance(node, CVariable) or codegen is None:
        return node

    variable = node.variable
    if variable is None:
        return node
    name = _strip_typed_name_suffix_8616(node.name or variable.name)
    should_follow_single_assignment = _is_linear_temp_name_8616(name)
    if isinstance(variable, SimStackVariable):
        should_follow_single_assignment = True
    if not should_follow_single_assignment:
        return node

    replacement = _single_assignment_expr_for_variable_8616(codegen, node)
    if replacement is None:
        return node
    resolved_replacement = _resolve_stack_bp_term_8616(replacement, project, codegen, seen)
    if isinstance(variable, SimStackVariable):
        stack_disp = _stack_bp_displacement_8616(resolved_replacement, project, codegen, seen=seen)
        if stack_disp is None:
            return node
    return resolved_replacement


def _match_real_mode_linear_expr_8616(
    node: object,
    project: _ProjectArch8616,
    codegen: object | None = None,
) -> tuple[str | None, int | None]:
    def _maybe_resolve(term: object) -> object:
        if codegen is None:
            return term
        return _resolve_stack_bp_term_8616(term, project, codegen)

    if isinstance(node, CBinaryOp) and node.op == "Shl":
        for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if _c_constant_value_8616(maybe_scale) != 4:
                continue
            seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
            if seg_name is not None:
                return seg_name, 0

    if isinstance(node, CBinaryOp) and node.op == "Mul":
        for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if _c_constant_value_8616(maybe_scale) != 16:
                continue
            seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
            if seg_name is not None:
                return seg_name, 0

    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None, None

    for maybe_mul, maybe_const in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        linear = _c_constant_value_8616(maybe_const)
        if linear is None:
            continue
        maybe_mul = _maybe_resolve(maybe_mul)
        if not isinstance(maybe_mul, CBinaryOp):
            continue
        if maybe_mul.op == "Mul":
            for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
                if _c_constant_value_8616(maybe_scale) != 16:
                    continue
                seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
                if seg_name is not None:
                    return seg_name, linear
        if maybe_mul.op == "Shl":
            for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
                if _c_constant_value_8616(maybe_scale) != 4:
                    continue
                seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
                if seg_name is not None:
                    return seg_name, linear
    return None, None


def _stack_bp_displacement_8616(
    node: object,
    project: _ProjectArch8616 | None = None,
    codegen: object | None = None,
    seen: set[int] | None = None,
) -> int | None:
    if seen is None:
        seen = set()
    total = 0
    stack_offsets: list[int] = []
    found_stack_ref = False

    def collect(term: object) -> None:
        """Collect offsets from terms crossing the dynamic angr C AST boundary."""
        nonlocal total
        nonlocal found_stack_ref

        term = _resolve_stack_bp_term_8616(term, project, codegen, seen)

        if isinstance(term, CTypeCast):
            collect(term.expr)
            return

        const = _c_constant_value_8616(term)
        if const is not None:
            total += const
            return

        if isinstance(term, CVariable):
            stack_base_bias = _stack_base_bp_bias_8616(term, codegen)
            if isinstance(stack_base_bias, int):
                stack_offsets.append(stack_base_bias)
                found_stack_ref = True
                return

        if isinstance(term, CUnaryOp) and term.op == "Reference":
            operand = term.operand
            if isinstance(operand, CVariable):
                variable = operand.variable
                if isinstance(variable, SimStackVariable):
                    offset = variable.offset
                    if isinstance(offset, int):
                        stack_offsets.append(offset)
                        found_stack_ref = True
                else:
                    stack_base_bias = _stack_base_bp_bias_8616(operand, codegen)
                    if isinstance(stack_base_bias, int):
                        stack_offsets.append(stack_base_bias)
                        found_stack_ref = True
            return

        if project is not None and codegen is not None:
            pointer_offset = _stack_pointer_carrier_offset_8616(term, project, codegen, seen)
            if isinstance(pointer_offset, int):
                stack_offsets.append(pointer_offset)
                found_stack_ref = True
                return

        if isinstance(term, CBinaryOp) and term.op == "Add":
            collect(term.lhs)
            collect(term.rhs)
            return

        if isinstance(term, CBinaryOp) and term.op == "Sub":
            collect(term.lhs)
            rhs_const = _c_constant_value_8616(term.rhs)
            if rhs_const is not None:
                total -= rhs_const
                return
            return

        if isinstance(term, CBinaryOp) and term.op in {"Mul", "Shl"}:
            if project is not None:
                seg_name, _linear = _match_real_mode_linear_expr_8616(term, project, codegen)
                if seg_name == "ss":
                    return
            return

    collect(node)
    if not found_stack_ref:
        return None
    if len(stack_offsets) != 1:
        return None
    return stack_offsets[0] + total


def _match_bp_stack_dereference_8616(
    node: object,
    project: _ProjectArch8616,
    codegen: object | None = None,
) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None

    operand = node.operand
    while isinstance(operand, CTypeCast):
        operand = operand.expr

    def _flatten_add_sub(term: object, sign: int = 1) -> list[tuple[object, int]]:
        while isinstance(term, CTypeCast):
            term = term.expr
        if isinstance(term, CBinaryOp) and term.op == "Add":
            return _flatten_add_sub(term.lhs, sign) + _flatten_add_sub(term.rhs, sign)
        if isinstance(term, CBinaryOp) and term.op == "Sub":
            return _flatten_add_sub(term.lhs, sign) + _flatten_add_sub(term.rhs, -sign)
        return [(term, sign)]

    terms = _flatten_add_sub(operand)
    if not terms:
        return None

    const_total = 0
    has_ss_segment = False
    non_segment_terms: list[tuple[object, int]] = []
    for term, sign in terms:
        value = _c_constant_value_8616(term)
        if value is not None:
            const_total += sign * value
            continue
        seg_name, linear = _match_real_mode_linear_expr_8616(term, project, codegen)
        if seg_name == "ss":
            has_ss_segment = True
            if isinstance(linear, int):
                const_total += sign * linear
            continue
        non_segment_terms.append((term, sign))

    if not has_ss_segment:
        return None
    if len(non_segment_terms) != 1:
        return None

    addr_term, sign = non_segment_terms[0]
    if sign != 1:
        return None
    base_disp = _stack_bp_displacement_8616(addr_term, project, codegen)
    if base_disp is None:
        return None
    return base_disp + const_total
