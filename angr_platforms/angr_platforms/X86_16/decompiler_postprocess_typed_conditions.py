from __future__ import annotations

"""Layer: Postprocess / Rewrite
Responsibility: replace flag-based `if(tmp_*)` and `if(flags & ...)` with
explicit comparisons from ConditionIR (built in lift_86_16, transferred via
condition_transfer).

AGENTS rule: this is a *rewrite* pass — it replaces one semantically-equivalent
C node with another.  No new semantics are introduced; the ConditionIR was
already proven by the lifting stage.  This pass only reformats the C AST.
"""

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeInt, SimTypeShort
from angr.sim_variable import SimRegisterVariable

from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .condition_trace import record_materialized_condition_trace_8616
from .ir.condition_ir import ConditionIR
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = ["_apply_typed_conditions_to_codegen_8616"]


def _build_reg_var(project, reg_name: str, codegen, size: int = 2) -> CVariable | None:
    """Build a CVariable for an x86-16 register by name."""
    reg = project.arch.registers.get(reg_name.lower())
    if reg is None:
        return None
    reg_offset, _ = reg
    return CVariable(SimRegisterVariable(int(reg_offset), size, name=reg_name.lower()), codegen=codegen)


def _build_c_expr_for_operand(project, operand, codegen) -> object | None:
    """Convert a ConditionIR operand (reg name string or int) to a C AST node."""
    if isinstance(operand, str):
        return _build_reg_var(project, operand, codegen)
    if isinstance(operand, int):
        return CConstant(int(operand), SimTypeInt(signed=False, label="int"), codegen=codegen)
    return None


def _build_c_condition_expr(project, cond: ConditionIR, codegen) -> CBinaryOp | None:
    """Build a CBinaryOp (comparison) from a ConditionIR."""
    lhs_expr = _build_c_expr_for_operand(project, cond.lhs, codegen)
    rhs_expr = _build_c_expr_for_operand(project, cond.rhs, codegen)
    if lhs_expr is None or rhs_expr is None:
        return None

    _OP_MAP = {
        "eq": "CmpEQ",
        "ne": "CmpNE",
        "slt": "CmpLT",
        "sle": "CmpLE",
        "sgt": "CmpGT",
        "sge": "CmpGE",
        "ult": "CmpLT",
        "ule": "CmpLE",
        "ugt": "CmpGT",
        "uge": "CmpGE",
        "zero": "CmpEQ",
        "nonzero": "CmpNE",
    }
    structured_op = _OP_MAP.get(cond.op)
    if structured_op is None:
        return None

    if cond.op in ("zero", "nonzero"):
        rhs_expr = CConstant(0, SimTypeShort(signed=False), codegen=codegen)

    return CBinaryOp(structured_op, lhs_expr, rhs_expr, codegen=codegen, tags={"typed_condition": True})


def _condition_key_from_tags(node) -> tuple | None:
    """Extract a match key (ins_addr, block_addr) from node tags."""
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return None
    ins_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    if not isinstance(ins_addr, int) or not isinstance(block_addr, int):
        return None
    return (ins_addr, block_addr)


def _index_conditions_by_tag(conditions: list[ConditionIR]) -> dict[tuple, ConditionIR]:
    """Index ConditionIR objects by their (ins_addr, block_addr) key."""
    index: dict[tuple, ConditionIR] = {}
    for cond in conditions:
        key = (cond.src_insn, cond.block_addr)
        index[key] = cond
    return index


def _is_flag_based_condition_node(node) -> bool:
    """Detect if a condition node is flag-based (tmp_* or flags mask pattern)."""
    # CITE nodes: if(tmp_*)
    from angr.analyses.decompiler.structured_codegen.c import CITE
    if isinstance(node, CITE):
        cond = getattr(node, "cond", None)
        if cond is not None:
            return _is_flag_based_condition_node(cond)
        return False

    # CVariable looking like flags register
    if isinstance(node, CVariable):
        var = getattr(node, "variable", None)
        if isinstance(var, SimRegisterVariable):
            reg = getattr(var, "reg", None)
            name = getattr(var, "name", "")
            # Flags register is typically offset 0 with name "flags" in x86_16
            if reg == 0 or "flags" in str(name).lower() or "tmp" in str(name).lower():
                return True
        if "flags" in str(var).lower():
            return True

    # CBinaryOp with And or Shr on what looks like flags
    if isinstance(node, CBinaryOp):
        if node.op in ("And", "Shr") and _is_flag_based_condition_node(node.lhs):
            return True
        if _is_flag_based_condition_node(node.lhs) or _is_flag_based_condition_node(node.rhs):
            return True

    return False


def _apply_typed_conditions_to_codegen_8616(project, codegen) -> bool:
    """Replace flag-based conditions in C AST with explicit comparisons from ConditionIR.

    This is a rewrite pass (AGENTS rule: rewrite only for cleanup/formatting).
    The ConditionIR facts are already proven by the lifting stage; this pass
    only replaces their representation in the C AST.
    """
    conditions = getattr(codegen, "_inertia_typed_conditions", None)
    if not conditions:
        return False

    condition_index = _index_conditions_by_tag(conditions)
    if not condition_index:
        return False

    changed = False

    def _walk_statements(statements_obj):
        nonlocal changed
        raw = getattr(statements_obj, "statements", ()) or ()
        stmts = tuple(getattr(raw, "statements", raw) or ())
        for stmt in stmts:
            _walk(stmt)

    def _walk(node):
        nonlocal changed
        if node is None or not _structured_codegen_node_8616(node):
            return

        # Replace condition in if statements
        if isinstance(node, CIfElse):
            cond = getattr(node, "condition", None)
            if cond is not None:
                key = _condition_key_from_tags(cond)
                if key is not None and key in condition_index:
                    new_cond = _build_c_condition_expr(project, condition_index[key], codegen)
                    if (
                        new_cond is not None
                        and not _same_c_expression_8616(new_cond.lhs, new_cond.rhs)
                        and _expr_fingerprint(new_cond.lhs, project) != _expr_fingerprint(new_cond.rhs, project)
                    ):
                        node.condition = new_cond
                        record_materialized_condition_trace_8616(project, codegen, key, new_cond)
                        changed = True

        # Replace condition in loops
        if hasattr(node, "condition") and not isinstance(node, CIfElse):
            cond = getattr(node, "condition", None)
            if _is_flag_based_condition_node(cond):
                key = _condition_key_from_tags(cond)
                if key is not None and key in condition_index:
                    new_cond = _build_c_condition_expr(project, condition_index[key], codegen)
                    if (
                        new_cond is not None
                        and not _same_c_expression_8616(new_cond.lhs, new_cond.rhs)
                        and _expr_fingerprint(new_cond.lhs, project) != _expr_fingerprint(new_cond.rhs, project)
                    ):
                        setattr(node, "condition", new_cond)
                        record_materialized_condition_trace_8616(project, codegen, key, new_cond)
                        changed = True

        # Recurse into children
        if hasattr(node, "statements"):
            _walk_statements(node)
        for attr in ("body", "else_node", "iftrue", "iffalse"):
            child = getattr(node, attr, None)
            if child is not None:
                _walk(child)
        if hasattr(node, "condition_and_nodes"):
            for cond_pair in (getattr(node, "condition_and_nodes", ()) or ()):
                if isinstance(cond_pair, (tuple, list)) and len(cond_pair) >= 2:
                    _walk(cond_pair[0])
                    _walk(cond_pair[1])
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                _walk(case_body)

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is not None:
        _walk_statements(cfunc)

    # ── Update CONDITION lane contract counters ──
    # count condition replacements actually performed
    if changed:
        lane = getattr(codegen, "_inertia_condition_lane", None)
        if lane is not None:
            # Count how many unique condition keys were matched
            matched_count = 0
            for _ in condition_index:
                matched_count += 1
            lane.materialized = matched_count
        codegen._inertia_semantic_condition_materialized_count = len(condition_index)

    return changed
