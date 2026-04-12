from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .decompiler_postprocess_utils import (
    _match_bp_stack_dereference_8616,
    _match_segmented_dereference_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)

__all__ = [
    "TAIL_VALIDATION_FINGERPRINT_VERSION",
    "_bool_projection_fingerprint",
    "_c_constant_int_value",
    "_expr_fingerprint",
    "_extract_same_zero_compare_expr_8616",
    "_extract_zero_flag_source_expr_8616",
    "_location_fingerprint",
    "_normalize_zero_flag_comparison_8616",
    "_register_name",
    "_wrap_not_fingerprint",
]


TAIL_VALIDATION_FINGERPRINT_VERSION = 2

def _register_name(project, reg_offset: int) -> str:
    name = project.arch.register_names.get(reg_offset)
    return name if isinstance(name, str) else f"reg@{reg_offset}"


def _c_constant_int_value(node) -> int | None:
    if isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int):
        return node.value
    return None


def _wrap_not_fingerprint(fingerprint: str) -> str:
    if fingerprint.startswith("Not(") and fingerprint.endswith(")"):
        return fingerprint[4:-1]
    return f"Not({fingerprint})"


def _stack_word_pair_fingerprint(node, project) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    deref_low = _extract_deref_node(left)
    deref_high = _extract_deref_scaled_node(right, scale=256)
    if deref_low is None or deref_high is None:
        deref_low = _extract_deref_node(right)
        deref_high = _extract_deref_scaled_node(left, scale=256)
    if deref_low is None or deref_high is None:
        return None
    low_offset = _match_bp_stack_dereference_8616(deref_low, project)
    high_offset = _match_bp_stack_dereference_8616(deref_high, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return f"stack:{low_offset:+#x}"


def _extract_deref_node(node):
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        return node
    return None


def _extract_deref_scaled_node(node, *, scale: int):
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or node.op != "Mul":
        return None
    if _c_constant_int_value(node.lhs) == scale:
        return _extract_deref_node(node.rhs)
    if _c_constant_int_value(node.rhs) == scale:
        return _extract_deref_node(node.lhs)
    return None


def _bool_projection_fingerprint(node, project) -> str | None:
    while isinstance(node, CTypeCast):
        node = node.expr

    if isinstance(node, CUnaryOp) and node.op == "Not":
        operand = getattr(node, "operand", None)
        inner = _bool_projection_fingerprint(operand, project)
        if inner is not None:
            return _wrap_not_fingerprint(inner)
        if isinstance(operand, CUnaryOp) and operand.op == "Not":
            return _expr_fingerprint(operand.operand, project)
        return None

    if not isinstance(node, CITE):
        return None

    iftrue = _c_constant_int_value(getattr(node, "iftrue", None))
    iffalse = _c_constant_int_value(getattr(node, "iffalse", None))
    if (iftrue, iffalse) == (1, 0):
        inner = _bool_projection_fingerprint(node.cond, project)
        return inner if inner is not None else _expr_fingerprint(node.cond, project)
    if (iftrue, iffalse) == (0, 1):
        inner = _bool_projection_fingerprint(node.cond, project)
        if inner is None:
            inner = _expr_fingerprint(node.cond, project)
        return _wrap_not_fingerprint(inner)
    return None


def _extract_same_zero_compare_expr_8616(node):
    if not isinstance(node, CBinaryOp) or node.op != "CmpEQ":
        return None
    if _c_constant_int_value(node.rhs) == 0:
        return node.lhs
    if _c_constant_int_value(node.lhs) == 0:
        return node.rhs
    return None


def _extract_zero_flag_source_expr_8616(node):
    if isinstance(node, CBinaryOp):
        if node.op == "Mul":
            for maybe_logic, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_int_value(maybe_scale) != 64:
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

        for child in (node.lhs, node.rhs):
            if _structured_codegen_node_8616(child):
                extracted = _extract_zero_flag_source_expr_8616(child)
                if extracted is not None:
                    return extracted

    elif isinstance(node, CUnaryOp):
        child = getattr(node, "operand", None)
        if _structured_codegen_node_8616(child):
            return _extract_zero_flag_source_expr_8616(child)

    elif isinstance(node, CTypeCast):
        child = getattr(node, "expr", None)
        if _structured_codegen_node_8616(child):
            return _extract_zero_flag_source_expr_8616(child)

    return None


def _normalize_zero_flag_comparison_8616(node):
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _c_constant_int_value(node.rhs) == 0:
        source = node.lhs
    elif _c_constant_int_value(node.lhs) == 0:
        source = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr_8616(source)
    if source_expr is None:
        return node
    if node.op == "CmpEQ":
        return source_expr
    return CUnaryOp("Not", source_expr, codegen=getattr(node, "codegen", None))


def _expr_fingerprint(node, project) -> str:
    if node is None:
        return "none"
    stack_pair = _stack_word_pair_fingerprint(node, project)
    if stack_pair is not None:
        return stack_pair
    bool_projection = _bool_projection_fingerprint(node, project)
    if bool_projection is not None:
        return bool_projection
    node = _normalize_zero_flag_comparison_8616(node)
    if isinstance(node, CConstant):
        return f"const:{node.value!r}"
    if isinstance(node, CVariable):
        return _location_fingerprint(node, project)
    if isinstance(node, CTypeCast):
        return f"cast:{_expr_fingerprint(node.expr, project)}"
    if isinstance(node, CUnaryOp):
        return f"{node.op}({_expr_fingerprint(node.operand, project)})"
    if isinstance(node, CBinaryOp):
        lhs = _expr_fingerprint(node.lhs, project)
        rhs = _expr_fingerprint(node.rhs, project)
        return f"{node.op}({lhs},{rhs})"
    if isinstance(node, CFunctionCall):
        callee = _call_target_name(node)
        args = ",".join(_expr_fingerprint(arg, project) for arg in getattr(node, "args", ()) or ())
        return f"call:{callee}({args})"
    return type(node).__name__


def _call_target_name(node: CFunctionCall) -> str:
    callee = getattr(node, "callee_target", None)
    if isinstance(callee, str) and callee:
        return callee
    callee_func = getattr(node, "callee_func", None)
    name = getattr(callee_func, "name", None)
    if isinstance(name, str) and name:
        return name
    return "<indirect>"


def _location_fingerprint(node, project) -> str:
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
            return f"reg:{_register_name(project, variable.reg)}"
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            return f"stack:{offset:+#x}" if isinstance(offset, int) else "stack:unknown"
        if isinstance(variable, SimMemoryVariable):
            addr = getattr(variable, "addr", None)
            return f"global:{addr:#x}" if isinstance(addr, int) else "global:unknown"

    if isinstance(node, CTypeCast):
        return _location_fingerprint(node.expr, project)

    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        stack_disp = _match_bp_stack_dereference_8616(node, project)
        if isinstance(stack_disp, int):
            return f"stack:{stack_disp:+#x}"
        seg_name, linear = _match_segmented_dereference_8616(node, project)
        if seg_name is not None:
            return f"deref:{seg_name}:{linear:#x}" if isinstance(linear, int) else f"deref:{seg_name}:unknown"
        return f"deref:{_expr_fingerprint(node.operand, project)}"

    return _expr_fingerprint(node, project)
