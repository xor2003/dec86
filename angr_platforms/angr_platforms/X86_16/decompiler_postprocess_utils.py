from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CITE,
    CBinaryOp,
    CConstant,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

__all__ = [
    "_structured_codegen_node_8616",
    "_c_constant_value_8616",
    "_segment_reg_name_8616",
    "_match_real_mode_linear_expr_8616",
    "_match_segmented_dereference_8616",
    "_replace_c_children_8616",
    "_iter_c_nodes_deep_8616",
    "_global_memory_addr_8616",
    "_make_word_global_8616",
    "_same_c_expression_8616",
    "_is_shifted_high_byte_8616",
    "_stack_bp_displacement_8616",
    "_match_bp_stack_load_8616",
    "_match_bp_stack_dereference_8616",
]


def _structured_codegen_node_8616(value) -> bool:
    return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")


def _c_constant_value_8616(node) -> int | None:
    if isinstance(node, CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _segment_reg_name_8616(node, project) -> str | None:
    if not isinstance(node, CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return None
    return project.arch.register_names.get(variable.reg)


def _match_real_mode_linear_expr_8616(node, project) -> tuple[str | None, int | None]:
    if isinstance(node, CBinaryOp) and node.op == "Shl":
        for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if _c_constant_value_8616(maybe_scale) != 4:
                continue
            seg_name = _segment_reg_name_8616(maybe_seg, project)
            if seg_name is not None:
                return seg_name, 0

    if isinstance(node, CBinaryOp) and node.op == "Mul":
        for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if _c_constant_value_8616(maybe_scale) != 16:
                continue
            seg_name = _segment_reg_name_8616(maybe_seg, project)
            if seg_name is not None:
                return seg_name, 0

    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None, None

    for maybe_mul, maybe_const in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        linear = _c_constant_value_8616(maybe_const)
        if linear is None:
            continue
        if not isinstance(maybe_mul, CBinaryOp) or maybe_mul.op != "Mul":
            continue
        for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
            if _c_constant_value_8616(maybe_scale) != 16:
                continue
            seg_name = _segment_reg_name_8616(maybe_seg, project)
            if seg_name is not None:
                return seg_name, linear
    return None, None


def _match_segmented_dereference_8616(node, project) -> tuple[str | None, int | None]:
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None, None
    operand = node.operand
    if isinstance(operand, CTypeCast):
        operand = operand.expr
    return _match_real_mode_linear_expr_8616(operand, project)


def _replace_c_children_8616(node, transform) -> bool:
    changed = False

    for attr in (
        "lhs",
        "rhs",
        "expr",
        "operand",
        "condition",
        "cond",
        "initializer",
        "iterator",
        "body",
        "iffalse",
        "iftrue",
        "callee_target",
        "else_node",
        "retval",
    ):
        if not hasattr(node, attr):
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if _structured_codegen_node_8616(value):
            new_value = transform(value)
            if new_value is not value:
                setattr(node, attr, new_value)
                changed = True
                value = new_value
            if _replace_c_children_8616(value, transform):
                changed = True

    for attr in ("args", "operands", "statements"):
        if not hasattr(node, attr):
            continue
        try:
            items = getattr(node, attr)
        except Exception:
            continue
        if not items:
            continue
        new_items = []
        list_changed = False
        for item in items:
            if _structured_codegen_node_8616(item):
                new_item = transform(item)
                if new_item is not item:
                    list_changed = True
                if _replace_c_children_8616(new_item, transform):
                    changed = True
                new_items.append(new_item)
            else:
                new_items.append(item)
        if list_changed:
            setattr(node, attr, new_items)
            changed = True

    if hasattr(node, "condition_and_nodes"):
        try:
            pairs = getattr(node, "condition_and_nodes")
        except Exception:
            pairs = None
        if pairs:
            new_pairs = []
            pair_changed = False
            for cond, body in pairs:
                new_cond = transform(cond) if _structured_codegen_node_8616(cond) else cond
                new_body = transform(body) if _structured_codegen_node_8616(body) else body
                if new_cond is not cond or new_body is not body:
                    pair_changed = True
                if _structured_codegen_node_8616(new_cond) and _replace_c_children_8616(new_cond, transform):
                    changed = True
                if _structured_codegen_node_8616(new_body) and _replace_c_children_8616(new_body, transform):
                    changed = True
                new_pairs.append((new_cond, new_body))
            if pair_changed:
                setattr(node, "condition_and_nodes", new_pairs)
                changed = True

    return changed


def _iter_c_nodes_deep_8616(node, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    if not _structured_codegen_node_8616(node):
        return
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)
    yield node

    for attr in dir(node):
        if attr.startswith("_") or attr in {"codegen"}:
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if _structured_codegen_node_8616(value):
            yield from _iter_c_nodes_deep_8616(value, seen)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if _structured_codegen_node_8616(item):
                    yield from _iter_c_nodes_deep_8616(item, seen)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            yield from _iter_c_nodes_deep_8616(subitem, seen)


def _global_memory_addr_8616(node) -> int | None:
    if not isinstance(node, CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) else None


def _make_word_global_8616(codegen, addr: int):
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_type import SimTypeShort

    return CVariable(
        SimMemoryVariable(addr, 2, name=f"g_{addr:x}", region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _same_c_expression_8616(lhs, rhs) -> bool:
    if type(lhs) is not type(rhs):
        return False
    if isinstance(lhs, CConstant):
        return lhs.value == rhs.value
    if isinstance(lhs, CTypeCast):
        return _same_c_expression_8616(lhs.expr, rhs.expr)
    if isinstance(lhs, CUnaryOp):
        return lhs.op == rhs.op and _same_c_expression_8616(lhs.operand, rhs.operand)
    if isinstance(lhs, CBinaryOp):
        return (
            lhs.op == rhs.op
            and _same_c_expression_8616(lhs.lhs, rhs.lhs)
            and _same_c_expression_8616(lhs.rhs, rhs.rhs)
        )
    if isinstance(lhs, CITE):
        return (
            _same_c_expression_8616(lhs.cond, rhs.cond)
            and _same_c_expression_8616(lhs.iftrue, rhs.iftrue)
            and _same_c_expression_8616(lhs.iffalse, rhs.iffalse)
        )
    if isinstance(lhs, CVariable):
        lvar = getattr(lhs, "variable", None)
        rvar = getattr(rhs, "variable", None)
        if type(lvar) is not type(rvar):
            return False
        if isinstance(lvar, SimRegisterVariable):
            return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
        if isinstance(lvar, SimMemoryVariable):
            return (
                getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
                and getattr(lvar, "size", None) == getattr(rvar, "size", None)
            )
    return lhs is rhs


def _is_shifted_high_byte_8616(high_expr, low_expr) -> bool:
    if not isinstance(high_expr, CBinaryOp) or high_expr.op != "Shr":
        return False
    if _c_constant_value_8616(high_expr.rhs) != 8:
        return False
    return _same_c_expression_8616(high_expr.lhs, low_expr)


def _single_assignment_expr_for_variable_8616(codegen, target):
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return None

    def _iter_statement_nodes(node):
        stack = [node]
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            if not _structured_codegen_node_8616(current):
                continue
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            yield current

            nested_statements = getattr(current, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                for item in reversed(tuple(nested_statements)):
                    stack.append(item)

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
                            stack.append(item)

    matches = []
    for stmt in _iter_statement_nodes(root):
        if not isinstance(stmt, CAssignment):
            continue
        lhs = getattr(stmt, "lhs", None)
        if not isinstance(lhs, CVariable):
            continue
        if not _same_c_expression_8616(lhs, target):
            continue
        matches.append(getattr(stmt, "rhs", None))
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def _resolve_stack_bp_term_8616(node, project=None, codegen=None, seen: set[int] | None = None):
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

    variable = getattr(node, "variable", None)
    if variable is None:
        return node
    name = getattr(variable, "name", None)
    should_follow_single_assignment = isinstance(name, str) and (
        name.startswith("vvar_") or name.startswith("tmp_") or name.startswith("ir_")
    )
    if isinstance(variable, SimStackVariable):
        should_follow_single_assignment = True
    if not should_follow_single_assignment:
        return node

    replacement = _single_assignment_expr_for_variable_8616(codegen, node)
    if replacement is None:
        return node
    resolved_replacement = _resolve_stack_bp_term_8616(replacement, project, codegen, seen)
    if isinstance(variable, SimStackVariable):
        stack_disp = _stack_bp_displacement_8616(resolved_replacement, project, codegen)
        if stack_disp is None:
            return node
    return resolved_replacement


def _stack_bp_displacement_8616(node, project=None, codegen=None) -> int | None:
    total = 0
    stack_offsets: list[int] = []
    found_stack_ref = False

    def collect(term) -> None:
        nonlocal total
        nonlocal found_stack_ref

        term = _resolve_stack_bp_term_8616(term, project, codegen)

        if isinstance(term, CTypeCast):
            collect(term.expr)
            return

        const = _c_constant_value_8616(term)
        if const is not None:
            total += const
            return

        if isinstance(term, CUnaryOp) and term.op == "Reference":
            operand = term.operand
            if isinstance(operand, CVariable):
                variable = getattr(operand, "variable", None)
                if isinstance(variable, SimStackVariable):
                    offset = getattr(variable, "offset", None)
                    if isinstance(offset, int):
                        stack_offsets.append(offset)
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
            # Segment-scale terms and byte-widening terms are not part of the bp displacement itself.
            if project is not None:
                seg_name, _linear = _match_real_mode_linear_expr_8616(term, project)
                if seg_name == "ss":
                    return
            return

        return

    collect(node)
    if not found_stack_ref:
        return None
    if len(stack_offsets) != 1:
        return None
    return stack_offsets[0] + total


def _match_bp_stack_dereference_8616(node, project, codegen=None) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None

    operand = node.operand
    while isinstance(operand, CTypeCast):
        operand = operand.expr

    def _flatten_add_sub(term, sign: int = 1) -> list[tuple[object, int]]:
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
        seg_name, linear = _match_real_mode_linear_expr_8616(term, project)
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


def _match_bp_stack_load_8616(node, project) -> int | None:
    direct = _match_bp_stack_dereference_8616(node, project)
    if direct is not None:
        return direct

    if not isinstance(node, CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value_8616(maybe_scale) != 0x100:
                continue
            direct = _match_bp_stack_dereference_8616(maybe_load, project)
            if direct is not None:
                return direct

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value_8616(maybe_scale) != 8:
                continue
            direct = _match_bp_stack_dereference_8616(maybe_load, project)
            if direct is not None:
                return direct

    return None
