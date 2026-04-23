from __future__ import annotations

import logging

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_real_mode_linear_expr_8616,
    _segment_reg_name_8616,
)
from .lowering.stack_probe_return_facts import TypedStackProbeReturnFact8616

__all__ = ["prune_materialized_callsite_segment_metadata_8616"]

logger = logging.getLogger(__name__)


def _call_from_statement_8616(stmt: object) -> CFunctionCall | None:
    if isinstance(stmt, CFunctionCall):
        return stmt
    expr = getattr(stmt, "expr", None)
    if isinstance(expr, CFunctionCall):
        return expr
    return None


def _assignment_lhs_rhs_8616(node: object) -> tuple[object, object]:
    lhs = getattr(node, "lhs", None)
    rhs = getattr(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = getattr(node, "dst", None)
        rhs = getattr(node, "src", None)
    return lhs, rhs


def _is_assignment_node_8616(node: object) -> bool:
    class_name = node.__class__.__name__
    return class_name == "CAssignment" or class_name.endswith("Assignment") or (
        hasattr(node, "dst") and hasattr(node, "src")
    )


def _assignment_nodes_8616(stmt: object) -> tuple:
    candidates = []
    if _is_assignment_node_8616(stmt):
        candidates.append(stmt)
    for node in _iter_c_nodes_deep_8616(stmt):
        if _is_assignment_node_8616(node):
            candidates.append(node)
    return tuple(candidates)


def _lhs_writes_memory_8616(lhs: object) -> bool:
    if lhs is None:
        return False
    nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
    for raw_node in nodes:
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            return True
        if isinstance(getattr(node, "variable", None), SimMemoryVariable):
            return True
    return False


def _segment_register_value_expr_8616(expr: object, project: object) -> bool:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CBinaryOp) and node.op in {"Shr", "Shl", "And", "Or"}:
        return _segment_register_value_expr_8616(node.lhs, project)
    variable = getattr(node, "variable", None)
    name = getattr(variable, "name", None) or getattr(node, "name", None)
    if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
        return True
    if project is None:
        return False
    return _segment_reg_name_8616(node, project) in {"cs", "ds", "es", "ss"}


def _lhs_has_ss_address_evidence_8616(lhs: object, project: object) -> bool:
    nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
    for raw_node in nodes:
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        seg_name, _linear = _match_real_mode_linear_expr_8616(node, project)
        if seg_name == "ss":
            return True
    return False


def _segment_metadata_store_8616(stmt: object, project: object, *, allow_carried_high_byte: bool) -> bool:
    assignments = _assignment_nodes_8616(stmt)
    if not assignments:
        return False
    lhs, rhs = _assignment_lhs_rhs_8616(assignments[-1])
    if not _lhs_writes_memory_8616(lhs):
        return False
    if not _segment_register_value_expr_8616(rhs, project):
        return False
    return allow_carried_high_byte or _lhs_has_ss_address_evidence_8616(lhs, project)


CarrierKey8616 = tuple[str, str | int]


def _generic_stack_carrier_name_8616(node: object) -> str | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    variable = getattr(node, "variable", None)
    for name in (getattr(node, "name", None), getattr(variable, "name", None)):
        if isinstance(name, str) and name.startswith(("vvar_", "ir_", "tmp_")):
            return name
    return None


def _stack_carrier_key_8616(node: object) -> CarrierKey8616 | None:
    """Return a stable AST-local key for a stack-address carrier variable."""
    name = _generic_stack_carrier_name_8616(node)
    if name is not None:
        return ("name", name)
    while isinstance(node, CTypeCast):
        node = node.expr
    variable = getattr(node, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        stable_name = getattr(variable, "name", None) or getattr(node, "name", None)
        if isinstance(stable_name, str) and stable_name.lower() in {
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "bp",
            "sp",
        }:
            return None
        return ("var", id(variable))
    return None


def _generic_stack_carrier_keys_8616(node: object) -> set[CarrierKey8616]:
    names: set[CarrierKey8616] = set()
    for raw_node in (node, *_iter_c_nodes_deep_8616(node)):
        key = _stack_carrier_key_8616(raw_node)
        if key is not None:
            names.add(key)
    return names


def _expr_is_pure_stack_address_carrier_8616(
    expr: object,
    known_carriers: set[CarrierKey8616] | None = None,
) -> bool:
    """Return true for side-effect-free stack-address shuttle expressions."""
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CFunctionCall):
        return False
    if isinstance(node, CUnaryOp):
        if node.op == "Dereference":
            return False
        if node.op == "Reference":
            return True
        return _expr_is_pure_stack_address_carrier_8616(getattr(node, "operand", None), known_carriers)
    if isinstance(node, CBinaryOp):
        if node.op not in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}:
            return False
        return _expr_is_pure_stack_address_carrier_8616(
            node.lhs, known_carriers
        ) or _expr_is_pure_stack_address_carrier_8616(node.rhs, known_carriers)
    key = _stack_carrier_key_8616(node)
    return key is not None and (
        _generic_stack_carrier_name_8616(node) is not None or key in (known_carriers or set())
    )


def _dead_stack_carrier_assignment_8616(
    stmt: object,
    known_carriers: set[CarrierKey8616],
) -> tuple[CarrierKey8616, object] | None:
    assignments = _assignment_nodes_8616(stmt)
    if not assignments:
        return None
    lhs, rhs = _assignment_lhs_rhs_8616(assignments[-1])
    if _lhs_writes_memory_8616(lhs):
        return None
    lhs_key = _stack_carrier_key_8616(lhs)
    if lhs_key is None or lhs_key not in known_carriers:
        return None
    if not _expr_is_pure_stack_address_carrier_8616(rhs, known_carriers):
        return None
    return lhs_key, rhs


def _collect_stack_carrier_assignments_8616(block: object) -> set[CarrierKey8616]:
    """Collect variables proven to carry stack addresses within this block."""
    known: set[CarrierKey8616] = set()
    statements = getattr(block, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return known
    for stmt in statements:
        for assignment in _assignment_nodes_8616(stmt):
            lhs, rhs = _assignment_lhs_rhs_8616(assignment)
            if _lhs_writes_memory_8616(lhs):
                continue
            lhs_key = _stack_carrier_key_8616(lhs)
            if lhs_key is not None and _expr_is_pure_stack_address_carrier_8616(rhs, known):
                known.add(lhs_key)
    return known


def _prune_dead_stack_carrier_assignments_8616(block: object) -> bool:
    """Remove dead generic address carriers left after call arguments are materialized."""
    changed = False
    statements = getattr(block, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return False

    for stmt in list(statements):
        for child in (
            getattr(stmt, "body", None),
            getattr(stmt, "else_node", None),
        ):
            if isinstance(getattr(child, "statements", None), (list, tuple)):
                changed |= _prune_dead_stack_carrier_assignments_8616(child)
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            changed |= _prune_dead_stack_carrier_assignments_8616(stmt)
        for pair in getattr(stmt, "condition_and_nodes", ()) or ():
            if (
                isinstance(pair, tuple)
                and len(pair) == 2
                and isinstance(getattr(pair[1], "statements", None), (list, tuple))
            ):
                changed |= _prune_dead_stack_carrier_assignments_8616(pair[1])

    known_carriers = _collect_stack_carrier_assignments_8616(block)
    live: set[CarrierKey8616] = set()
    kept_reversed: list = []
    removed = 0
    for stmt in reversed(list(getattr(block, "statements", ()) or ())):
        carrier = _dead_stack_carrier_assignment_8616(stmt, known_carriers)
        if carrier is not None:
            lhs_key, rhs = carrier
            if lhs_key not in live:
                changed = True
                removed += 1
                continue
            live.discard(lhs_key)
            live.update(_generic_stack_carrier_keys_8616(rhs).intersection(known_carriers))
            kept_reversed.append(stmt)
            continue
        live.update(_generic_stack_carrier_keys_8616(stmt).intersection(known_carriers))
        kept_reversed.append(stmt)

    if changed:
        logger.debug(
            "Pruned %d dead stack-address carrier assignment(s) from callsite metadata block with %d carrier key(s)",
            removed,
            len(known_carriers),
        )
        kept_reversed.reverse()
        block.statements = kept_reversed if isinstance(statements, list) else tuple(kept_reversed)
    return changed


def _prune_trailing_segment_metadata_8616(statements: list, project: object) -> bool:
    changed = False
    removed_store = False
    while statements:
        if _segment_metadata_store_8616(statements[-1], project, allow_carried_high_byte=removed_store):
            statements.pop()
            removed_store = True
            changed = True
            continue
        if (
            not removed_store
            and len(statements) >= 2
            and _segment_metadata_store_8616(statements[-1], project, allow_carried_high_byte=True)
            and _segment_metadata_store_8616(statements[-2], project, allow_carried_high_byte=False)
        ):
            statements.pop()
            removed_store = True
            changed = True
            continue
        break
    return changed


def prune_materialized_callsite_segment_metadata_8616(project: object, codegen: object) -> bool:
    """Drop stack-probe segment metadata stores after their call args are materialized."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    if not isinstance(getattr(root, "statements", None), (list, tuple)):
        return False

    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    typed_fact_map = getattr(codegen, "_inertia_typed_stack_probe_return_facts", None)
    if not isinstance(typed_fact_map, dict):
        typed_fact_map = {}
    else:
        typed_fact_map = {
            key: value for key, value in typed_fact_map.items() if isinstance(key, int) and isinstance(value, TypedStackProbeReturnFact8616)
        }
    materialized_metadata_ids = getattr(codegen, "_inertia_materialized_callsite_metadata_ids", None)
    if not isinstance(materialized_metadata_ids, dict):
        materialized_metadata_ids = {}
    use_typed_facts = bool(typed_fact_map)

    changed = False

    def rewrite_block(block: object, inherited_stack_probe_address_seen: bool = False) -> bool:
        nonlocal changed
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return inherited_stack_probe_address_seen

        stack_probe_address_seen = inherited_stack_probe_address_seen or (
            bool(typed_fact_map)
            if use_typed_facts
            else any(
                bool(getattr(item, "stack_probe_helper", False))
                and getattr(item, "helper_return_state", None) == "stack_address"
                and getattr(item, "helper_return_space", None) in {None, "ss"}
                for item in summary_map.values()
            )
        )
        new_statements = []
        for stmt in list(statements):
            call = _call_from_statement_8616(stmt)
            summary = summary_map.get(id(call)) if call is not None else None
            if call is not None and bool(getattr(summary, "stack_probe_helper", False)):
                if use_typed_facts:
                    stack_probe_address_seen = id(call) in typed_fact_map
                elif getattr(summary, "helper_return_state", None) == "stack_address":
                    stack_probe_address_seen = getattr(summary, "helper_return_space", None) in {None, "ss"}
            if call is not None and stack_probe_address_seen and not bool(getattr(summary, "stack_probe_helper", False)):
                args = tuple(getattr(call, "args", ()) or ())
                if args and all(not _segment_register_value_expr_8616(arg, project) for arg in args):
                    prunable_ids = {
                        stmt_id for stmt_id in materialized_metadata_ids.get(id(call), ()) if isinstance(stmt_id, int)
                    }
                    if prunable_ids:
                        kept_statements = [old_stmt for old_stmt in new_statements if id(old_stmt) not in prunable_ids]
                        if len(kept_statements) != len(new_statements):
                            new_statements = kept_statements
                            changed = True
            new_statements.append(stmt)

        if new_statements != list(statements):
            block.statements = new_statements if isinstance(statements, list) else tuple(new_statements)

        for stmt in getattr(block, "statements", ()) or ():
            for child in (
                getattr(stmt, "body", None),
                getattr(stmt, "else_node", None),
            ):
                if isinstance(getattr(child, "statements", None), (list, tuple)):
                    rewrite_block(child, stack_probe_address_seen)
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                rewrite_block(stmt, stack_probe_address_seen)
            for pair in getattr(stmt, "condition_and_nodes", ()) or ():
                if (
                    isinstance(pair, tuple)
                    and len(pair) == 2
                    and isinstance(getattr(pair[1], "statements", None), (list, tuple))
                ):
                    rewrite_block(pair[1], stack_probe_address_seen)
        return stack_probe_address_seen

    rewrite_block(root)
    if _prune_dead_stack_carrier_assignments_8616(root):
        changed = True
    return changed
