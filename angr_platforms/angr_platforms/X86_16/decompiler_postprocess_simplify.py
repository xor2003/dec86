from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CITE, CTypeCast, CUnaryOp

from .decompiler_postprocess_flags import _bool_cite_values_8616
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)

__all__ = ["_simplify_structured_expressions_8616", "_simplify_boolean_cites_8616"]


def _simplify_boolean_cites_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        if not isinstance(node, CITE):
            return node
        values = _bool_cite_values_8616(node)
        if values == (1, 0):
            return node.cond
        if values == (0, 1):
            return CUnaryOp("Not", node.cond, codegen=codegen, tags=getattr(node, "tags", None))
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _simplify_structured_expressions_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _is_c_constant_int_8616(expr, value: int) -> bool:
        return isinstance(expr, CConstant) and isinstance(expr.value, int) and expr.value == value

    def _extract_same_zero_compare_expr_8616(expr):
        if not isinstance(expr, CBinaryOp) or expr.op != "CmpEQ":
            return None
        if _is_c_constant_int_8616(expr.rhs, 0):
            return expr.lhs
        if _is_c_constant_int_8616(expr.lhs, 0):
            return expr.rhs
        return None

    def _extract_zero_flag_source_expr_8616(expr):
        if isinstance(expr, CBinaryOp):
            if expr.op == "Mul":
                for maybe_logic, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                    if not _is_c_constant_int_8616(maybe_scale, 64):
                        continue
                    source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                    if source_expr is not None:
                        return source_expr
                    if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                        continue
                    lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                    rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                    if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                        return lhs_expr

            for child in (expr.lhs, expr.rhs):
                if _structured_codegen_node_8616(child):
                    extracted = _extract_zero_flag_source_expr_8616(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(expr, CUnaryOp):
            child = getattr(expr, "operand", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        elif isinstance(expr, CTypeCast):
            child = getattr(expr, "expr", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        return None

    def _simplify_zero_flag_comparison_8616(expr):
        if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
            return expr

        if _is_c_constant_int_8616(expr.rhs, 0):
            source = expr.lhs
        elif _is_c_constant_int_8616(expr.lhs, 0):
            source = expr.rhs
        else:
            return expr

        source_expr = _extract_zero_flag_source_expr_8616(source)
        if source_expr is None:
            return expr
        if expr.op == "CmpEQ":
            return source_expr
        return CUnaryOp("Not", source_expr, codegen=codegen)

    def transform(node):
        if isinstance(node, CBinaryOp) and node.op == "Concat":
            lhs_val = _c_constant_value_8616(node.lhs)
            rhs_val = _c_constant_value_8616(node.rhs)
            rhs_bits = getattr(getattr(node.rhs, "type", None), "size", None)
            lhs_bits = getattr(getattr(node.lhs, "type", None), "size", None)
            if rhs_bits is None:
                rhs_bits = lhs_bits if lhs_bits is not None else 16

            if lhs_val is not None and rhs_val is not None:
                return CConstant((lhs_val << rhs_bits) | rhs_val, getattr(node, "type", None), codegen=codegen)

            shift = CConstant(rhs_bits, getattr(node.rhs, "type", None) or getattr(node.lhs, "type", None), codegen=codegen)
            return CBinaryOp(
                "Or",
                CBinaryOp("Shl", node.lhs, shift, codegen=codegen, tags=getattr(node, "tags", None)),
                node.rhs,
                codegen=codegen,
                tags=getattr(node, "tags", None),
            )

        if isinstance(node, CBinaryOp) and node.op == "Mul":
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CBinaryOp) and node.op == "Or":
            if _is_c_constant_int_8616(node.lhs, 0):
                return node.rhs
            if _is_c_constant_int_8616(node.rhs, 0):
                return node.lhs

        if isinstance(node, CBinaryOp) and node.op == "And":
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CUnaryOp) and node.op == "Not":
            operand = getattr(node, "operand", None)
            if isinstance(operand, CUnaryOp) and operand.op == "Not":
                return operand.operand

        simplified = _simplify_zero_flag_comparison_8616(node)
        if simplified is not node:
            return simplified
        if (
            isinstance(node, CBinaryOp)
            and node.op in {"LogicalAnd", "LogicalOr", "And", "Or"}
            and _same_c_expression_8616(node.lhs, node.rhs)
        ):
            return node.lhs
        if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE"}:
            if isinstance(node.rhs, CConstant) and node.rhs.value == 0:
                if (
                    isinstance(node.lhs, CBinaryOp)
                    and node.lhs.op == "Sub"
                    and isinstance(node.lhs.rhs, CConstant)
                ):
                    return CBinaryOp(
                        node.op,
                        node.lhs.lhs,
                        node.lhs.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
            if isinstance(node.lhs, CConstant) and node.lhs.value == 0:
                if (
                    isinstance(node.rhs, CBinaryOp)
                    and node.rhs.op == "Sub"
                    and isinstance(node.rhs.rhs, CConstant)
                ):
                    return CBinaryOp(
                        node.op,
                        node.rhs.lhs,
                        node.rhs.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
        if isinstance(node, CBinaryOp) and node.op == "Sub" and _same_c_expression_8616(node.lhs, node.rhs):
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
            if type_ is not None:
                return CConstant(0, type_, codegen=codegen)
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    for _ in range(3):
        if not _replace_c_children_8616(root, transform):
            break
        changed = True
    return changed
