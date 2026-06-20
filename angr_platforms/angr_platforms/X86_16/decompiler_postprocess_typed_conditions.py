"""Typed-condition C rewrite consumer.

This module replaces flag-shaped C conditions with explicit comparisons from
ConditionIR. The condition semantics must already be proven by the early
pipeline: lift/IR records the flag-producing operation, condition transfer binds
it to codegen nodes, and this file only builds the equivalent C AST.

Allowed work in this file:
- map ConditionIR operands to C AST nodes;
- replace matching tagged conditions without changing branch meaning;
- record materialization traces for validation/debugging.

Current migration debt:
- compatibility operand handling still accepts raw VEX-like wrappers;
- stack/global operand rendering still constructs fallback C expressions here;
- delta/tag fallback lookup exists because transfer is not complete.

Those behaviors should move to IR operand normalization, alias/stack lowering,
segmented memory lowering, or condition transfer. Do not add new flag, JCC,
polarity, operand, or branch inference here. If ConditionIR cannot describe the
condition, keep the original C and let validation/reporting expose the missing
early fact.
"""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .condition_trace import record_materialized_condition_trace_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .ir.condition_ir import ConditionIR
from .ir.core import IRValue, MemSpace
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = ["_apply_typed_conditions_to_codegen_8616"]


def _build_reg_var(project, reg_name: str, codegen, size: int = 2) -> CVariable | None:
    """Build a CVariable for an x86-16 register by name."""
    reg = project.arch.registers.get(reg_name.lower())
    if reg is None:
        return None
    reg_offset, _ = reg
    return CVariable(SimRegisterVariable(int(reg_offset), size, name=reg_name.lower()), codegen=codegen)


def _assignment_lhs_register_info_8616(project, lhs: object) -> tuple[int, int] | None:
    variable = getattr(lhs, "variable", None) if isinstance(lhs, CVariable) else None
    if isinstance(variable, SimRegisterVariable):
        return int(variable.reg), int(getattr(variable, "size", 0) or 0)
    name = getattr(lhs, "name", None)
    if isinstance(name, str):
        reg = getattr(project.arch, "registers", {}).get(name.lower())
        if reg is not None:
            return int(reg[0]), int(reg[1])
    return None


def _register_exprs_by_ins_addr_8616(codegen, project) -> dict[tuple[int, str, int], object]:
    cache = getattr(codegen, "_inertia_typed_condition_register_exprs_by_ins_addr_8616", None)
    if isinstance(cache, dict):
        return cache
    reg_exprs: dict[tuple[int, str, int], object] = {}
    cfunc = getattr(codegen, "cfunc", None)
    roots = (cfunc, getattr(cfunc, "statements", None), getattr(cfunc, "body", None))
    seen_nodes: set[int] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            node_id = id(node)
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            if not isinstance(node, CAssignment):
                continue
            tags = getattr(node, "tags", None)
            ins_addr = None if tags is None else tags.get("ins_addr")
            if not isinstance(ins_addr, int):
                continue
            lhs_reg_info = _assignment_lhs_register_info_8616(project, node.lhs)
            if lhs_reg_info is None:
                continue
            lhs_reg_offset, var_size = lhs_reg_info
            for reg_name, (reg_offset, reg_size) in project.arch.registers.items():
                if int(reg_offset) != int(lhs_reg_offset):
                    continue
                if var_size and int(reg_size) != var_size:
                    continue
                rhs = getattr(node, "rhs", None)
                expr = (
                    node.lhs
                    if any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(rhs))
                    else rhs
                )
                reg_exprs[(ins_addr, reg_name.lower(), int(reg_size))] = expr
    try:
        codegen._inertia_typed_condition_register_exprs_by_ins_addr_8616 = reg_exprs
    except Exception:
        pass
    return reg_exprs


def _lookup_register_expr_before_8616(
    reg_exprs: dict[tuple[int, str, int], object], ins_addr: int, reg_name: str, size: int
):
    best_addr = None
    best_expr = None
    for (candidate_addr, candidate_name, candidate_size), candidate_expr in reg_exprs.items():
        if candidate_name != reg_name.lower():
            continue
        if int(size) and int(candidate_size) != int(size):
            continue
        if int(candidate_addr) >= int(ins_addr):
            continue
        if best_addr is None or int(candidate_addr) > best_addr:
            best_addr = int(candidate_addr)
            best_expr = candidate_expr
    return best_expr


def _type_for_operand_size_8616(size: int):
    if size <= 1:
        return SimTypeChar(signed=False)
    if size >= 4:
        return SimTypeLong(signed=False)
    return SimTypeShort(signed=False)


def _build_segmented_operand_expr_8616(project, operand: IRValue, codegen) -> CFunctionCall | None:
    space_to_segment = {
        MemSpace.DS: "ds",
        MemSpace.ES: "es",
        MemSpace.SS: "ss",
    }
    segment_name = space_to_segment.get(operand.space)
    if segment_name is None:
        return None
    width = int(operand.size or 2)
    helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(width)
    if helper is None:
        return None
    segment = _build_reg_var(project, segment_name, codegen, size=2)
    if segment is None:
        return None
    offset = CConstant(int(operand.offset) & 0xFFFF, SimTypeShort(signed=False), codegen=codegen)
    return CFunctionCall(helper, None, [segment, offset], codegen=codegen)


def _build_stack_operand_expr_8616(operand: IRValue, codegen) -> CVariable | None:
    if operand.space != MemSpace.SS:
        return None
    base = operand.name if operand.name in {"bp", "sp"} else "bp"
    offset = int(operand.offset)
    size = int(operand.size or 2)
    prefix = "arg" if base == "bp" and offset > 0 else "local"
    name = f"{prefix}_{abs(offset):x}"
    variable = SimStackVariable(offset, max(size, 1), base=base, name=name)
    return CVariable(variable, variable_type=_type_for_operand_size_8616(size), codegen=codegen)


def _build_c_expr_for_operand(project, operand, codegen, cond: ConditionIR | None = None) -> object | None:
    def _impl():
        """Convert a ConditionIR operand (reg name string or int) to a C AST node."""
        if isinstance(operand, IRValue):
            if operand.space == MemSpace.CONST:
                return CConstant(int(operand.const or 0), SimTypeInt(signed=False, label="int"), codegen=codegen)
            if operand.space == MemSpace.REG and isinstance(operand.name, str) and operand.name:
                bind_addr = getattr(cond, "producer_insn", None) if cond is not None else None
                if not isinstance(bind_addr, int):
                    bind_addr = getattr(cond, "src_insn", None) if cond is not None else None
                if isinstance(bind_addr, int):
                    expr = _lookup_register_expr_before_8616(
                        _register_exprs_by_ins_addr_8616(codegen, project),
                        bind_addr,
                        operand.name,
                        max(1, int(operand.size or 2)),
                    )
                    if expr is not None:
                        return expr
                return _build_reg_var(project, operand.name, codegen, size=max(1, int(operand.size or 2)))
            if operand.space in {MemSpace.DS, MemSpace.ES}:
                return _build_segmented_operand_expr_8616(project, operand, codegen)
            if operand.space == MemSpace.SS:
                stack_expr = _build_stack_operand_expr_8616(operand, codegen)
                return stack_expr if stack_expr is not None else _build_segmented_operand_expr_8616(project, operand, codegen)
            return None
        if isinstance(operand, str):
            return _build_reg_var(project, operand, codegen)
        if isinstance(operand, int):
            return CConstant(int(operand), SimTypeInt(signed=False, label="int"), codegen=codegen)
        # Compatibility lane: some condition facts still carry raw VexValue-like
        # wrappers. Resolve register/const evidence if present.
        try:
            value_const = getattr(operand, "value", None)
        except Exception:
            value_const = None
        if isinstance(value_const, int):
            return CConstant(int(value_const), SimTypeInt(signed=False, label="int"), codegen=codegen)
        try:
            reg_name = getattr(operand, "reg_name", None)
        except Exception:
            reg_name = None
        if isinstance(reg_name, str) and reg_name:
            return _build_reg_var(project, reg_name, codegen)
        try:
            reg_offset = getattr(operand, "reg", None)
        except Exception:
            reg_offset = None
        if isinstance(reg_offset, int):
            reg_label = project.arch.register_names.get(int(reg_offset))
            if isinstance(reg_label, str) and reg_label:
                return _build_reg_var(project, reg_label, codegen)
        return None

    return _impl()


def _build_c_condition_expr(project, cond: ConditionIR, codegen) -> CBinaryOp | None:
    """Build a CBinaryOp (comparison) from a ConditionIR."""
    lhs_expr = _build_c_expr_for_operand(project, cond.lhs, codegen, cond)
    rhs_expr = _build_c_expr_for_operand(project, cond.rhs, codegen, cond)
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
    seen: set[int] = set()

    def _walk(current) -> tuple | None:
        if current is None:
            return None
        marker = id(current)
        if marker in seen:
            return None
        seen.add(marker)

        tags = getattr(current, "tags", None)
        if isinstance(tags, dict):
            ins_addr = tags.get("ins_addr")
            block_addr = tags.get("vex_block_addr")
            if isinstance(ins_addr, int) and isinstance(block_addr, int):
                return (ins_addr, block_addr)

        if isinstance(current, CUnaryOp):
            return _walk(getattr(current, "operand", None))
        if isinstance(current, CBinaryOp):
            return _walk(getattr(current, "lhs", None)) or _walk(getattr(current, "rhs", None))

        cond = getattr(current, "cond", None)
        if cond is not None:
            return _walk(cond)
        return None

    return _walk(node)


def _index_conditions_by_tag(conditions: list[ConditionIR]) -> dict[tuple, ConditionIR]:
    """Index ConditionIR objects by their (ins_addr, block_addr) key."""
    index: dict[tuple, ConditionIR] = {}
    for cond in conditions:
        if not isinstance(cond.src_insn, int) or not isinstance(cond.block_addr, int):
            continue
        key = (cond.src_insn, cond.block_addr)
        index[key] = cond
    return index


def _resolve_condition_by_tag_with_delta(
    project, index: dict[tuple, ConditionIR], key: tuple | None
) -> ConditionIR | None:
    def _impl():
        if key is None:
            return None
        cond = index.get(key)
        if cond is not None:
            return cond
        if not (isinstance(key, tuple) and len(key) == 2):
            return None
        ins_addr, block_addr = key
        if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
            return None
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if not isinstance(delta, int) or delta == 0:
            return None
        for signed in (delta, -delta):
            alt_key = (ins_addr + signed, block_addr + signed)
            cond = index.get(alt_key)
            if cond is not None:
                return cond
        return None

    return _impl()


def _is_flag_based_condition_node(node) -> bool:
    def _impl():
        """Detect if a condition node is flag-based (tmp_* or flags mask pattern)."""
        if isinstance(node, CITE):
            cond = getattr(node, "cond", None)
            if cond is not None:
                return _is_flag_based_condition_node(cond)
            return False

        # CVariable looking like flags register
        if isinstance(node, CVariable):
            node_text = str(node).lower()
            if "flags" in node_text or "tmp" in node_text or "vvar_" in node_text:
                return True
            var = getattr(node, "variable", None)
            if isinstance(var, SimRegisterVariable):
                reg = getattr(var, "reg", None)
                name = getattr(var, "name", "")
                name_text = str(name).lower()
                var_text = str(var).lower()
                if (
                    reg == 18
                    or "flags" in name_text
                    or "tmp" in name_text
                    or "vvar_" in name_text
                    or "flags" in var_text
                    or "tmp" in var_text
                    or "vvar_" in var_text
                ):
                    return True
            var_text = str(var).lower()
            if "flags" in var_text or "tmp" in var_text or "vvar_" in var_text:
                return True

        # CBinaryOp with And or Shr on what looks like flags
        if isinstance(node, CBinaryOp):
            if node.op in ("And", "Shr") and _is_flag_based_condition_node(node.lhs):
                return True
            if _is_flag_based_condition_node(node.lhs) or _is_flag_based_condition_node(node.rhs):
                return True

        if isinstance(node, CUnaryOp):
            return _is_flag_based_condition_node(getattr(node, "operand", None))

        return False

    return _impl()


def _contains_flag_mask_operator_8616(node) -> bool:
    if node is None or not _structured_codegen_node_8616(node):
        return False
    if isinstance(node, CBinaryOp):
        if node.op in {"And", "Shr"} and (_is_flag_based_condition_node(node.lhs) or _is_flag_based_condition_node(node.rhs)):
            return True
        return _contains_flag_mask_operator_8616(node.lhs) or _contains_flag_mask_operator_8616(node.rhs)
    if isinstance(node, CUnaryOp):
        return _contains_flag_mask_operator_8616(getattr(node, "operand", None))
    if isinstance(node, CITE):
        return _contains_flag_mask_operator_8616(getattr(node, "cond", None))
    return False


def _apply_typed_conditions_to_codegen_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
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
    matched_condition_keys: set[tuple] = set()

    def _is_literal_condition(expr) -> bool:
        node = expr
        while isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Not":
            node = getattr(node, "operand", None)
        return isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int)

    def _replacement_for_condition_node(cond):
        if isinstance(cond, CBinaryOp) and cond.op in {"LogicalAnd", "LogicalOr"}:
            return None
        if isinstance(cond, CBinaryOp) and str(cond.op).startswith("Cmp") and not _contains_flag_mask_operator_8616(cond):
            return None
        key = _condition_key_from_tags(cond)
        if not _is_flag_based_condition_node(cond):
            return None
        typed_cond = _resolve_condition_by_tag_with_delta(project, condition_index, key)
        if typed_cond is None:
            return None
        new_cond = _build_c_condition_expr(project, typed_cond, codegen)
        if new_cond is None:
            return None
        if _same_c_expression_8616(new_cond.lhs, new_cond.rhs):
            return None
        if _expr_fingerprint(new_cond.lhs, project) == _expr_fingerprint(new_cond.rhs, project):
            return None
        record_materialized_condition_trace_8616(project, codegen, key, new_cond)
        if key is not None:
            matched_condition_keys.add(key)
        return new_cond

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
                new_cond = _replacement_for_condition_node(cond)
                if new_cond is not None:
                    node.condition = new_cond
                    changed = True
            cond_pairs = getattr(node, "condition_and_nodes", None)
            if cond_pairs:
                rebuilt_pairs = []
                pair_changed = False
                for cond_pair in cond_pairs:
                    if isinstance(cond_pair, (tuple, list)) and len(cond_pair) >= 2:
                        pair_cond = cond_pair[0]
                        pair_body = cond_pair[1]
                        new_pair_cond = _replacement_for_condition_node(pair_cond)
                        if new_pair_cond is not None:
                            rebuilt_pairs.append((new_pair_cond, pair_body))
                            pair_changed = True
                            changed = True
                        else:
                            rebuilt_pairs.append(tuple(cond_pair))
                    else:
                        rebuilt_pairs.append(cond_pair)
                if pair_changed:
                    setattr(node, "condition_and_nodes", rebuilt_pairs)
                    primary = getattr(node, "condition", None)
                    if _is_literal_condition(primary):
                        first_pair = rebuilt_pairs[0] if rebuilt_pairs else None
                        if isinstance(first_pair, (tuple, list)) and len(first_pair) >= 1 and first_pair[0] is not None:
                            node.condition = first_pair[0]
                            changed = True

        # Replace condition in loops
        if hasattr(node, "condition") and not isinstance(node, CIfElse):
            cond = getattr(node, "condition", None)
            if _is_flag_based_condition_node(cond):
                new_cond = _replacement_for_condition_node(cond)
                if new_cond is not None:
                    setattr(node, "condition", new_cond)
                    changed = True

        # Recurse into children
        if hasattr(node, "statements"):
            _walk_statements(node)
        for attr in ("body", "else_node", "iftrue", "iffalse"):
            child = getattr(node, attr, None)
            if child is not None:
                _walk(child)
        if hasattr(node, "condition_and_nodes"):
            for cond_pair in getattr(node, "condition_and_nodes", ()) or ():
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
            matched_count = len(matched_condition_keys)
            lane.classified = max(int(getattr(lane, "classified", 0) or 0), matched_count)
            lane.materialized = matched_count
        codegen._inertia_semantic_condition_materialized_count = len(matched_condition_keys)

    return changed
