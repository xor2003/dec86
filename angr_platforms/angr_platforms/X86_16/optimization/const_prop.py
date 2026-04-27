from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Constant propagation pass: fold constant arithmetic expressions within blocks.

Forbidden: semantic recovery, alias decisions, type inference, C text generation."""

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CUnaryOp,
)

from ..decompiler_postprocess_utils import _c_constant_value_8616

__all__ = ["_constant_propagation_8616"]


_CONST_PROP_BINARY_OPS = {
    "Add": lambda a, b: CConstant(a + b),
    "Sub": lambda a, b: CConstant(a - b),
    "Mul": lambda a, b: CConstant(a * b),
    "And": lambda a, b: CConstant(a & b),
    "Or": lambda a, b: CConstant(a | b),
    "Xor": lambda a, b: CConstant(a ^ b),
    "Shl": lambda a, b: CConstant(a << b) if 0 <= b < 16 else None,
    "Shr": lambda a, b: CConstant(a >> b) if 0 <= b < 16 else None,
    "Div": lambda a, b: CConstant(a // b) if b != 0 else None,
}


def _is_const_expr(node) -> bool:
    if isinstance(node, CConstant):
        return True
    if isinstance(node, CBinaryOp):
        return _is_const_expr(node.lhs) and _is_const_expr(node.rhs)
    if isinstance(node, CUnaryOp) and node.op in ("Neg", "Not"):
        return _is_const_expr(node.operand)
    return False


def _eval_const_expr(node) -> int | None:
    if isinstance(node, CConstant):
        return _c_constant_value_8616(node)
    if isinstance(node, CBinaryOp):
        a = _eval_const_expr(node.lhs)
        b = _eval_const_expr(node.rhs)
        if a is None or b is None:
            return None
        fn = _CONST_PROP_BINARY_OPS.get(node.op)
        if fn is None:
            return None
        result = fn(a, b)
        return _c_constant_value_8616(result) if isinstance(result, CConstant) else None
    if isinstance(node, CUnaryOp):
        operand = _eval_const_expr(node.operand)
        if operand is None:
            return None
        if node.op == "Neg":
            return -operand
        if node.op == "Not":
            return int(not operand)
    return None


def _fold_constants_in_node(node) -> bool:
    """Fold constant sub-expressions in-place. Returns True if any folding occurred."""
    changed = False

    if isinstance(node, CBinaryOp):
        a_val = _eval_const_expr(node.lhs)
        b_val = _eval_const_expr(node.rhs)
        if a_val is not None and b_val is not None:
            fn = _CONST_PROP_BINARY_OPS.get(node.op)
            if fn is not None:
                result = fn(a_val, b_val)
                if isinstance(result, CConstant):
                    node.lhs = result
                    node.rhs = CConstant(0)
                    node.op = "Add"
                    changed = True
                    return changed

    if isinstance(node, CAssignment):
        rhs = getattr(node, "rhs", None)
        if isinstance(rhs, CBinaryOp) or isinstance(rhs, CUnaryOp):
            val = _eval_const_expr(rhs)
            if val is not None:
                node.rhs = CConstant(val)
                changed = True
                return changed

    return changed


def _constant_propagation_8616(codegen) -> bool:
    """Run constant folding on all C expressions in codegen.

    Returns True if any node was modified.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def walk_statements(statements):
        nonlocal changed
        for stmt in getattr(statements, "statements", ()) or ():
            _walk_node(stmt)

    def _walk_node(node):
        nonlocal changed
        if node is None:
            return
        if _fold_constants_in_node(node):
            changed = True
        for attr in ("condition", "cond", "body", "else_node", "iftrue", "iffalse",
                     "retval", "expr", "operand", "lhs", "rhs", "switch",
                     "initializer", "iterator"):
            child = getattr(node, attr, None)
            if child is not None:
                _walk_node(child)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                _walk_node(cond)
                _walk_node(body)
        if hasattr(node, "statements"):
            walk_statements(node)
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                _walk_node(case_body)
        if hasattr(node, "default"):
            _walk_node(getattr(node, "default", None))
        if hasattr(node, "args"):
            for arg in getattr(node, "args", ()) or ():
                _walk_node(arg)

    walk_statements(cfunc)
    return changed