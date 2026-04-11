from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
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


def _stack_bp_displacement_8616(node, project=None) -> int | None:
    total = 0
    stack_offsets: list[int] = []
    found_stack_ref = False

    def collect(term) -> None:
        nonlocal total
        nonlocal found_stack_ref

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


def _match_bp_stack_dereference_8616(node, project) -> int | None:
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None

    operand = node.operand
    if isinstance(operand, CTypeCast):
        operand = operand.expr

    def extract(add_node) -> int | None:
        if isinstance(add_node, CTypeCast):
            return extract(add_node.expr)

        if not isinstance(add_node, CBinaryOp) or add_node.op != "Add":
            return None

        for maybe_seg, maybe_addr in ((add_node.lhs, add_node.rhs), (add_node.rhs, add_node.lhs)):
            seg_name, _linear = _match_real_mode_linear_expr_8616(maybe_seg, project)
            if seg_name != "ss":
                continue
            disp = _stack_bp_displacement_8616(maybe_addr, project)
            if disp is not None:
                return disp

        for maybe_add, maybe_const in ((add_node.lhs, add_node.rhs), (add_node.rhs, add_node.lhs)):
            if not isinstance(maybe_add, CBinaryOp) or maybe_add.op != "Add":
                continue
            disp = extract(maybe_add)
            if disp is None:
                continue
            const = _c_constant_value_8616(maybe_const)
            if const is None:
                continue
            return disp + const

        return None

    return extract(operand)


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
