from __future__ import annotations

from collections.abc import Callable
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable


BaseKey = tuple[object, ...]
BuildAccessTraitEvidenceProfiles = Callable[[dict[str, dict[tuple[object, ...], object]]], dict[BaseKey, Any]]
InferInductionVariable = Callable[[Any], Any | None]


def _loop_index_key(loop_var) -> BaseKey | None:
    variable = getattr(loop_var, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        return ("reg", getattr(variable, "reg", None))
    if isinstance(variable, SimStackVariable):
        base = getattr(variable, "base", None)
        offset = getattr(variable, "offset", None)
        region = getattr(variable, "region", None)
        if base is None or offset is None:
            return None
        return ("stack", base, offset, region)
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", None)
        if addr is None:
            return None
        return ("mem", addr)
    return None


def _const_int(node) -> int | None:
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return int(node.value)
    return None


def _expr_index_key(expr) -> BaseKey | None:
    if isinstance(expr, structured_c.CVariable):
        return _loop_index_key(expr)
    if isinstance(expr, structured_c.CTypeCast):
        return _expr_index_key(expr.expr)
    if isinstance(expr, structured_c.CUnaryOp) and expr.op in {"Dereference", "Reference"}:
        return _expr_index_key(expr.operand)
    if not isinstance(expr, structured_c.CIndexedVariable):
        return None
    base_expr = getattr(expr, "variable", None)
    if isinstance(base_expr, structured_c.CUnaryOp) and base_expr.op == "Reference":
        base_expr = base_expr.operand
    index_value = _const_int(getattr(expr, "index", None))
    if not isinstance(base_expr, structured_c.CVariable) or not isinstance(index_value, int):
        return None
    variable = getattr(base_expr, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None
    base = getattr(variable, "base", None)
    offset = getattr(variable, "offset", None)
    region = getattr(variable, "region", None)
    if base is None or not isinstance(offset, int):
        return None
    return ("stack", base, offset + index_value, region)


def _condition_index_key(node) -> BaseKey | None:
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    lhs_key = _expr_index_key(node.lhs)
    if lhs_key is not None:
        return lhs_key
    return _expr_index_key(node.rhs)


def _unwrap_boolified_condition(node):
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Not":
        return None
    operand = getattr(node, "operand", None)
    if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Not":
        cond = getattr(operand, "operand", None)
        if isinstance(cond, structured_c.CBinaryOp):
            return cond
        return None
    if type(operand).__name__ != "CITE":
        return None
    if _const_int(getattr(operand, "iftrue", None)) != 0:
        return None
    if _const_int(getattr(operand, "iffalse", None)) != 1:
        return None
    cond = getattr(operand, "cond", None)
    if isinstance(cond, structured_c.CBinaryOp):
        return cond
    return None


def rewrite_for_loop_conditions_from_access_traits(
    project,
    codegen,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
    infer_induction_variable: InferInductionVariable,
    iter_c_nodes_deep: Callable[[Any], Any],
) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False

    stable_index_keys = {
        getattr(candidate, "index_key", None)
        for candidate in (
            infer_induction_variable(profile)
            for profile in build_access_trait_evidence_profiles(traits).values()
        )
        if getattr(candidate, "index_key", None) is not None
    }
    if not stable_index_keys:
        return False

    changed = False
    for node in iter_c_nodes_deep(getattr(cfunc, "statements", None)):
        if not isinstance(node, structured_c.CForLoop):
            continue
        simplified = _unwrap_boolified_condition(getattr(node, "condition", None))
        if simplified is None:
            continue
        index_key = _condition_index_key(simplified)
        if index_key not in stable_index_keys:
            continue
        node.condition = simplified
        changed = True
    return changed
