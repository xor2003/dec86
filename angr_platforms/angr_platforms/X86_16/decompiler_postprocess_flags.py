from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable

from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)

__all__ = [
    "_extract_flag_test_info_8616",
    "_extract_flag_predicate_from_expr_8616",
    "_c_expr_uses_var_8616",
    "_rewrite_flag_condition_pairs_8616",
    "_bool_cite_values_8616",
    "_extract_bool_compare_term_8616",
    "_make_bool_cite_8616",
    "_invert_cmp_op_8616",
    "_make_bool_expr_from_compare_8616",
    "_fix_impossible_interval_guard_expr_8616",
    "_fix_interval_guard_conditions_8616",
    "_prune_unused_flag_assignments_8616",
    "_c_expr_uses_register_8616",
    "_stmt_reads_reg_before_write_8616",
    "_prune_overwritten_flag_assignments_8616",
]


def _extract_flag_test_info_8616(node):
    invert = False
    while True:
        if isinstance(node, CUnaryOp) and node.op == "Not":
            invert = not invert
            node = node.operand
            continue
        if isinstance(node, CITE):
            values = _bool_cite_values_8616(node)
            if values == (1, 0):
                node = node.cond
                continue
            if values == (0, 1):
                invert = not invert
                node = node.cond
                continue
        break

    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None

    lhs = node.lhs
    rhs = node.rhs
    zero = None
    masked = None
    if isinstance(lhs, CBinaryOp) and lhs.op == "And" and isinstance(rhs, CConstant) and rhs.value == 0:
        masked = lhs
        zero = rhs
    elif isinstance(rhs, CBinaryOp) and rhs.op == "And" and isinstance(lhs, CConstant) and lhs.value == 0:
        masked = rhs
        zero = lhs
    if masked is None or zero is None:
        return None

    mask_lhs = masked.lhs
    mask_rhs = masked.rhs
    if isinstance(mask_lhs, CConstant) and isinstance(mask_lhs.value, int) and isinstance(mask_rhs, CVariable):
        bit = mask_lhs.value
        var = mask_rhs
    elif isinstance(mask_rhs, CConstant) and isinstance(mask_rhs.value, int) and isinstance(mask_lhs, CVariable):
        bit = mask_rhs.value
        var = mask_lhs
    else:
        return None

    predicate_negated = invert
    if node.op == "CmpEQ":
        predicate_negated = not predicate_negated
    return var, bit, predicate_negated


def _extract_flag_predicate_from_expr_8616(node, bit: int):
    if isinstance(node, CBinaryOp):
        if node.op == "Mul":
            if isinstance(node.lhs, CConstant) and node.lhs.value == bit:
                return node.rhs
            if isinstance(node.rhs, CConstant) and node.rhs.value == bit:
                return node.lhs
        if node.op in {"Or", "And"}:
            lhs = _extract_flag_predicate_from_expr_8616(node.lhs, bit)
            if lhs is not None:
                return lhs
            rhs = _extract_flag_predicate_from_expr_8616(node.rhs, bit)
            if rhs is not None:
                return rhs
    return None


def _c_expr_uses_var_8616(node, target) -> bool:
    if node is None:
        return False
    if isinstance(node, CVariable):
        return _same_c_expression_8616(node, target)
    for attr in (
        "lhs",
        "rhs",
        "operand",
        "cond",
        "iftrue",
        "iffalse",
        "expr",
        "condition",
        "else_node",
    ):
        child = getattr(node, attr, None)
        if hasattr(child, "__class__") and child.__class__.__name__.startswith("C"):
            if _c_expr_uses_var_8616(child, target):
                return True
    for attr in ("statements", "operands", "condition_and_nodes"):
        child = getattr(node, attr, None)
        if isinstance(child, list):
            for item in child:
                if isinstance(item, tuple):
                    for sub in item:
                        if hasattr(sub, "__class__") and sub.__class__.__name__.startswith("C"):
                            if _c_expr_uses_var_8616(sub, target):
                                return True
                elif hasattr(item, "__class__") and item.__class__.__name__.startswith("C"):
                    if _c_expr_uses_var_8616(item, target):
                        return True
    return False


def _rewrite_flag_condition_pairs_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def _last_assignment_in_stmt(stmt):
        if isinstance(stmt, CAssignment):
            return stmt, None
        if isinstance(stmt, CStatements) and stmt.statements:
            last = stmt.statements[-1]
            if isinstance(last, CAssignment):
                return last, stmt
        return None, None

    def transform(node):
        nonlocal changed
        if not isinstance(node, CStatements):
            return node

        new_statements = []
        statements = list(node.statements)
        i = 0
        while i < len(statements):
            stmt = statements[i]
            next_stmt = statements[i + 1] if i + 1 < len(statements) else None

            matched = False
            assign_stmt, assign_container = _last_assignment_in_stmt(stmt)
            if (
                isinstance(assign_stmt, CAssignment)
                and isinstance(assign_stmt.lhs, CVariable)
                and type(next_stmt).__name__ == "CIfElse"
            ):
                cond_nodes = getattr(next_stmt, "condition_and_nodes", None)
                if isinstance(cond_nodes, list) and cond_nodes:
                    cond, _body = cond_nodes[0]
                    info = _extract_flag_test_info_8616(cond)
                    if info is not None:
                        flag_var, bit, negate_predicate = info
                        if _same_c_expression_8616(assign_stmt.lhs, flag_var):
                            predicate = _extract_flag_predicate_from_expr_8616(assign_stmt.rhs, bit)
                            if predicate is not None:
                                new_cond = (
                                    CUnaryOp("Not", predicate, codegen=codegen)
                                    if negate_predicate
                                    else predicate
                                )
                                cond_nodes[0] = (new_cond, cond_nodes[0][1])
                                changed = True
                                later_uses = any(
                                    _c_expr_uses_var_8616(rest, assign_stmt.lhs) for rest in statements[i + 2 :]
                                )
                                if not later_uses:
                                    if assign_container is None:
                                        matched = True
                                    else:
                                        assign_container.statements = assign_container.statements[:-1]

            if not matched:
                new_statements.append(stmt)
            i += 1

        if len(new_statements) != len(node.statements):
            node.statements = new_statements
        return node

    root = codegen.cfunc.statements
    transform(root)
    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _bool_cite_values_8616(node):
    if not isinstance(node, CITE):
        return None
    iftrue = _c_constant_value_8616(node.iftrue)
    iffalse = _c_constant_value_8616(node.iffalse)
    if iftrue in (0, 1) and iffalse in (0, 1):
        return iftrue, iffalse
    return None


def _extract_bool_compare_term_8616(node):
    negated = False
    if isinstance(node, CUnaryOp) and node.op == "Not":
        negated = True
        node = node.operand
    if not isinstance(node, CITE):
        return None
    values = _bool_cite_values_8616(node)
    if values is None:
        return None
    if values == (1, 0):
        effective_negated = negated
    elif values == (0, 1):
        effective_negated = not negated
    else:
        return None
    compare = node.cond
    if not isinstance(compare, CBinaryOp):
        return None
    if compare.op not in {"CmpGT", "CmpGE", "CmpLT", "CmpLE"}:
        return None
    return compare, effective_negated, node


def _make_bool_cite_8616(template: CITE, negated: bool, codegen):
    values = _bool_cite_values_8616(template)
    if values is None:
        return template
    zero = CConstant(0, getattr(template.iftrue, "type", None) or template.type, codegen=codegen)
    one = CConstant(1, getattr(template.iftrue, "type", None) or template.type, codegen=codegen)
    if negated:
        return CITE(template.cond, zero, one, tags=getattr(template, "tags", None), codegen=codegen)
    return CITE(template.cond, one, zero, tags=getattr(template, "tags", None), codegen=codegen)


def _invert_cmp_op_8616(op: str) -> str | None:
    return {
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
    }.get(op)


def _make_bool_expr_from_compare_8616(compare: CBinaryOp, negated: bool, codegen):
    if negated:
        inverted = _invert_cmp_op_8616(compare.op)
        if inverted is not None:
            return CBinaryOp(
                inverted,
                compare.lhs,
                compare.rhs,
                codegen=codegen,
                tags=getattr(compare, "tags", None),
            )
    return CBinaryOp(
        compare.op,
        compare.lhs,
        compare.rhs,
        codegen=codegen,
        tags=getattr(compare, "tags", None),
    )


def _fix_impossible_interval_guard_expr_8616(node, codegen):
    if not isinstance(node, CBinaryOp) or node.op != "LogicalAnd":
        return node
    left_info = _extract_bool_compare_term_8616(node.lhs)
    right_info = _extract_bool_compare_term_8616(node.rhs)
    if left_info is None or right_info is None:
        return node
    left_cmp, left_negated, left_template = left_info
    right_cmp, right_negated, right_template = right_info
    if not _same_c_expression_8616(left_cmp.rhs, right_cmp.rhs):
        return node

    low_ops = {"CmpGT", "CmpGE"}
    high_ops = {"CmpLT", "CmpLE"}

    if left_cmp.op in low_ops and right_cmp.op in high_ops and not left_negated and not right_negated:
        return CBinaryOp(
            "LogicalAnd",
            _make_bool_expr_from_compare_8616(left_cmp, True, codegen),
            _make_bool_expr_from_compare_8616(right_cmp, True, codegen),
            codegen=codegen,
            tags=getattr(node, "tags", None),
        )

    if left_cmp.op in low_ops and right_cmp.op == "CmpGE" and not left_negated and right_negated:
        return CBinaryOp(
            "LogicalAnd",
            _make_bool_expr_from_compare_8616(left_cmp, True, codegen),
            _make_bool_expr_from_compare_8616(right_cmp, False, codegen),
            codegen=codegen,
            tags=getattr(node, "tags", None),
        )

    return node


def _fix_interval_guard_conditions_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def transform(node):
        fixed = _fix_impossible_interval_guard_expr_8616(node, codegen)
        if fixed is not node:
            return fixed
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _prune_unused_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    used_registers: set[int] = set()
    used_variables: set[int] = set()

    def collect_reads(node, *, assignment_lhs: bool = False):
        if not _structured_codegen_node_8616(node):
            return
        if isinstance(node, CVariable) and not assignment_lhs:
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
                if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
                    used_registers.add(variable.reg)
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))
                if isinstance(unified, SimRegisterVariable) and getattr(unified, "reg", None) is not None:
                    used_registers.add(unified.reg)
            return

        for attr in ("rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "callee_target", "else_node", "retval"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                collect_reads(child)
        lhs = getattr(node, "lhs", None)
        if _structured_codegen_node_8616(lhs):
            collect_reads(lhs, assignment_lhs=isinstance(node, CAssignment))
        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    collect_reads(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            collect_reads(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    collect_reads(cond)
                if _structured_codegen_node_8616(body):
                    collect_reads(body)

    collect_reads(codegen.cfunc.statements)

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            for stmt in node.statements:
                visit(stmt)
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if (
                        isinstance(variable, SimRegisterVariable)
                        and getattr(variable, "reg", None) == flags_offset
                        and id(variable) not in used_variables
                        and getattr(variable, "reg", None) not in used_registers
                    ):
                        changed = True
                        continue
                new_statements.append(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed


def _c_expr_uses_register_8616(node, reg_offset: int) -> bool:
    if not _structured_codegen_node_8616(node):
        return False
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        return isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == reg_offset

    for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iftrue", "iffalse", "callee_target", "else_node", "retval"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child) and _c_expr_uses_register_8616(child, reg_offset):
            return True

    for attr in ("args", "operands", "statements"):
        seq = getattr(node, attr, None)
        if not seq:
            continue
        for item in seq:
            if _structured_codegen_node_8616(item) and _c_expr_uses_register_8616(item, reg_offset):
                return True
            if isinstance(item, tuple):
                for subitem in item:
                    if _structured_codegen_node_8616(subitem) and _c_expr_uses_register_8616(subitem, reg_offset):
                        return True

    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for cond, body in pairs:
            if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                return True
            if _structured_codegen_node_8616(body) and _c_expr_uses_register_8616(body, reg_offset):
                return True

    return False


def _stmt_reads_reg_before_write_8616(stmt, reg_offset: int) -> tuple[bool, bool]:
    if not _structured_codegen_node_8616(stmt):
        return False, False

    if isinstance(stmt, CAssignment):
        lhs = stmt.lhs
        writes = (
            isinstance(lhs, CVariable)
            and isinstance(getattr(lhs, "variable", None), SimRegisterVariable)
            and getattr(lhs.variable, "reg", None) == reg_offset
        )
        reads = _c_expr_uses_register_8616(stmt.rhs, reg_offset)
        return reads, writes

    if isinstance(stmt, CStatements):
        for substmt in stmt.statements:
            reads, writes = _stmt_reads_reg_before_write_8616(substmt, reg_offset)
            if reads:
                return True, writes
            if writes:
                return False, True
        return False, False

    if type(stmt).__name__ == "CIfElse":
        cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
        for cond, body in cond_nodes:
            if _c_expr_uses_register_8616(cond, reg_offset):
                return True, False
            reads, writes = _stmt_reads_reg_before_write_8616(body, reg_offset)
            if reads:
                return True, writes
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            reads, writes = _stmt_reads_reg_before_write_8616(else_node, reg_offset)
            if reads:
                return True, writes
        return False, False

    if type(stmt).__name__ == "CWhileLoop":
        cond = getattr(stmt, "condition", None)
        if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
            return True, False
        body = getattr(stmt, "body", None)
        if body is not None:
            return _stmt_reads_reg_before_write_8616(body, reg_offset)
        return False, False

    return _c_expr_uses_register_8616(stmt, reg_offset), False


def _prune_overwritten_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            statements = list(node.statements)
            for idx, stmt in enumerate(statements):
                remove = False
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == flags_offset:
                        remainder = CStatements(statements[idx + 1 :], codegen=codegen)
                        reads, _writes = _stmt_reads_reg_before_write_8616(remainder, flags_offset)
                        if not reads:
                            remove = True
                if remove:
                    changed = True
                    continue
                new_statements.append(stmt)
                visit(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed
