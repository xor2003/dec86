from __future__ import annotations

import logging
import os

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.pipeline.errors import PipelineHardError

from inertia_decompiler.cli_linear_recurrence_state import LinearRecurrenceState

log = logging.getLogger(__name__)


def _linear_recurrence_debug_enabled() -> bool:
    return bool(os.environ.get("INERTIA_DEBUG_LINEAR_RECURRENCE"))


def _node_summary_8616(node) -> str:
    if node is None:
        return "None"
    try:
        if hasattr(node, "c_repr"):
            text = node.c_repr(indent=0)
        else:
            text = repr(node)
    except Exception as ex:
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] failed c_repr for %s: %s", type(node).__name__, ex)
        text = repr(node)
    text = text.replace("\n", " ")
    if len(text) > 220:
        text = text[:217] + "..."
    return f"{type(node).__name__}: {text}"


def _iter_nested_statement_summaries_8616(node):
    if node is None:
        return
    if isinstance(node, structured_c.CStatements):
        for stmt in getattr(node, "statements", ()) or ():
            yield _node_summary_8616(stmt)
            yield from _iter_nested_statement_summaries_8616(stmt)
        return
    for attr in ("body", "else_node"):
        child = getattr(node, attr, None)
        if child is not None:
            yield from _iter_nested_statement_summaries_8616(child)


def _debug_loop_structure_8616(loop) -> None:
    if not _linear_recurrence_debug_enabled():
        return
    body = getattr(loop, "body", None)
    body_statements = tuple(getattr(body, "statements", ()) or ()) if isinstance(body, structured_c.CStatements) else ()
    log.warning("[linear-recurrence] loop type=%s", type(loop).__name__)
    log.warning("[linear-recurrence] initializer=%s", _node_summary_8616(getattr(loop, "initializer", None)))
    log.warning("[linear-recurrence] init=%s", _node_summary_8616(getattr(loop, "init", None)))
    log.warning("[linear-recurrence] condition=%s", _node_summary_8616(getattr(loop, "condition", None)))
    log.warning("[linear-recurrence] iteration=%s", _node_summary_8616(getattr(loop, "iteration", None)))
    log.warning("[linear-recurrence] iterator=%s", _node_summary_8616(getattr(loop, "iterator", None)))
    log.warning("[linear-recurrence] body_count=%d", len(body_statements))
    for idx, summary in enumerate(_iter_nested_statement_summaries_8616(body)):
        log.warning("[linear-recurrence] body[%d]=%s", idx, summary)


def _rewrite_linear_condition(node, state, *, structured_codegen_node, same_c_expression, rules) -> None:
    candidate = None
    current = getattr(node, "condition", None)
    if structured_codegen_node(current):
        candidate = state.resolve_known_copy_alias_expr(current)
        candidate = state.inline_known_linear_defs(candidate)
        if candidate is not current and rules._should_commit_linear_rewrite(
            current,
            candidate,
            expr_contains_dereference=state.expr_contains_dereference,
            same_c_expression=same_c_expression,
        ):
            node.condition = candidate
            state.changed = True


def _match_self_delta_assignment(stmt, state):
    if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] low-delta reject: stmt=%s", _node_summary_8616(stmt))
        return None
    lhs = stmt.lhs
    rhs = state.resolve_known_copy_alias_expr(stmt.rhs)
    base_expr, delta = state.extract_linear_delta(rhs)
    if base_expr is None:
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] low-delta reject: no linear delta lhs=%s rhs=%s",
                _node_summary_8616(lhs),
                _node_summary_8616(rhs),
            )
        return None
    if not state.same_c_expression(state.unwrap_c_casts(base_expr), state.unwrap_c_casts(lhs)):
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] low-delta reject: base mismatch lhs=%s base=%s delta=%r",
                _node_summary_8616(lhs),
                _node_summary_8616(base_expr),
                delta,
            )
        return None
    if delta not in {1, -1}:
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] low-delta reject: unsupported delta lhs=%s delta=%r rhs=%s",
                _node_summary_8616(lhs),
                delta,
                _node_summary_8616(rhs),
            )
        return None
    if _linear_recurrence_debug_enabled():
        log.warning(
            "[linear-recurrence] low-delta match lhs=%s base=%s delta=%r",
            _node_summary_8616(lhs),
            _node_summary_8616(base_expr),
            delta,
        )
    return delta


def _match_byte_carrier_high_update(expr, state):
    expr = state.unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] high-carry reject: expr=%s", _node_summary_8616(expr))
        return None
    shift = state.c_constant_value(state.unwrap_c_casts(expr.rhs))
    if shift != 8:
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] high-carry reject: shift=%r expr=%s", shift, _node_summary_8616(expr))
        return None
    inner = state.unwrap_c_casts(expr.lhs)
    if not isinstance(inner, structured_c.CBinaryOp) or inner.op not in {"Add", "Sub"}:
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] high-carry reject: inner=%s", _node_summary_8616(inner))
        return None
    for maybe_low, maybe_const in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
        const = state.c_constant_value(state.unwrap_c_casts(maybe_const))
        if const != 1:
            continue
        low_expr = state.unwrap_c_casts(maybe_low)
        if isinstance(low_expr, structured_c.CVariable):
            if _linear_recurrence_debug_enabled():
                log.warning(
                    "[linear-recurrence] high-carry match low=%s delta=%r expr=%s",
                    _node_summary_8616(low_expr),
                    (1 if inner.op == "Add" else -1),
                    _node_summary_8616(expr),
                )
            return low_expr, (1 if inner.op == "Add" else -1)
    if _linear_recurrence_debug_enabled():
        log.warning("[linear-recurrence] high-carry reject: no variable low expr inner=%s", _node_summary_8616(inner))
    return None


def _collect_body_assignments_8616(node) -> list[structured_c.CAssignment]:
    assignments: list[structured_c.CAssignment] = []
    if node is None:
        return assignments
    if isinstance(node, structured_c.CStatements):
        for stmt in getattr(node, "statements", ()) or ():
            assignments.extend(_collect_body_assignments_8616(stmt))
        return assignments
    if isinstance(node, structured_c.CAssignment):
        assignments.append(node)
        return assignments
    for attr in ("body", "else_node"):
        child = getattr(node, attr, None)
        if child is not None:
            assignments.extend(_collect_body_assignments_8616(child))
    return assignments


def _find_low_delta_stmt_8616(assignments, state, low_carrier, candidate_delta):
    for stmt in reversed(assignments):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        tail_delta = _match_self_delta_assignment(stmt, state)
        if tail_delta != candidate_delta:
            continue
        if state.same_c_expression(
            state.unwrap_c_casts(stmt.lhs),
            state.unwrap_c_casts(low_carrier),
        ):
            return stmt
    return None


def _remove_statement_from_tree_8616(node, target_stmt) -> bool:
    if node is None or target_stmt is None:
        return False
    removed = False
    if isinstance(node, structured_c.CStatements):
        new_statements = []
        for stmt in getattr(node, "statements", ()) or ():
            if stmt is target_stmt:
                removed = True
                continue
            child_removed = _remove_statement_from_tree_8616(stmt, target_stmt)
            removed = removed or child_removed
            new_statements.append(stmt)
        if removed:
            node.statements = new_statements
        return removed
    for attr in ("body", "else_node"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        child_removed = _remove_statement_from_tree_8616(child, target_stmt)
        removed = removed or child_removed
    return removed


def _rebind_for_loop_byte_carrier_recurrence(loop, state, *, rules) -> bool:
    _debug_loop_structure_8616(loop)
    init = getattr(loop, "initializer", None)
    if init is None:
        init = getattr(loop, "init", None)
    iteration_attr = "iteration" if getattr(loop, "iteration", None) is not None else "iterator"
    iteration = getattr(loop, iteration_attr, None)
    body = getattr(loop, "body", None)
    if not isinstance(init, structured_c.CAssignment):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] reject loop: init not assignment")
        return False
    if not isinstance(init.lhs, structured_c.CVariable):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] reject loop: init lhs not CVariable")
        return False
    if not state.is_materialized_stack_local(init.lhs):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] reject loop: init lhs not materialized local: %r", init.lhs)
        return False
    if not isinstance(iteration, structured_c.CAssignment):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] reject loop: iteration attr=%s value=%r", iteration_attr, iteration)
        iteration = None
    if not isinstance(body, structured_c.CStatements) or not getattr(body, "statements", None):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] reject loop: body=%r", body)
        return False

    iterator_local = init.lhs
    body_assignments = _collect_body_assignments_8616(body)
    if _linear_recurrence_debug_enabled():
        log.warning("[linear-recurrence] body_assignment_count=%d", len(body_assignments))
        for idx, stmt in enumerate(body_assignments):
            log.warning("[linear-recurrence] assignment[%d]=%s", idx, _node_summary_8616(stmt))
    candidate_delta = None
    low_carrier = None
    low_stmt = None

    if isinstance(iteration, structured_c.CAssignment):
        carry_base = state.match_duplicate_word_increment_shift_expr(
            iteration.rhs,
            state.resolve_known_copy_alias_expr,
            state.codegen,
        )
        carry_rewrite = rules._carry_base_rewrite_plan(
            carry_base,
            expr_contains_dereference=state.expr_contains_dereference,
            extract_linear_delta=state.extract_linear_delta,
        )
        if carry_rewrite is not None:
            candidate_expr = state.resolve_known_copy_alias_expr(carry_rewrite["replacement"])
            candidate_base, candidate_delta = state.extract_linear_delta(candidate_expr)
            if candidate_base is None or candidate_delta not in {1, -1}:
                state._record_recurrence_reason("ambiguous_delta")
                return False
            if not state.same_c_expression(state.unwrap_c_casts(candidate_base), state.unwrap_c_casts(iterator_local)):
                state._record_recurrence_reason("not_materialized_local")
                return False
            low_stmt = _find_low_delta_stmt_8616(body_assignments, state, iterator_local, candidate_delta)
        else:
            reduced = _match_byte_carrier_high_update(iteration.rhs, state)
            if reduced is not None:
                low_carrier, candidate_delta = reduced
                low_stmt = _find_low_delta_stmt_8616(body_assignments, state, low_carrier, candidate_delta)

    if low_stmt is None:
        for idx, stmt in enumerate(body_assignments[:-1]):
            reduced = _match_byte_carrier_high_update(stmt.rhs, state)
            if reduced is None:
                continue
            maybe_low_carrier, maybe_delta = reduced
            if _linear_recurrence_debug_enabled():
                log.warning(
                    "[linear-recurrence] high-carry candidate[%d] lhs=%s low=%s delta=%r",
                    idx,
                    _node_summary_8616(stmt.lhs),
                    _node_summary_8616(maybe_low_carrier),
                    maybe_delta,
                )
            maybe_low_stmt = _find_low_delta_stmt_8616(body_assignments[idx + 1 :], state, maybe_low_carrier, maybe_delta)
            if maybe_low_stmt is None:
                if _linear_recurrence_debug_enabled():
                    log.warning("[linear-recurrence] candidate[%d] rejected: no matching low-delta stmt", idx)
                continue
            low_carrier = maybe_low_carrier
            candidate_delta = maybe_delta
            low_stmt = maybe_low_stmt
            break

    if candidate_delta not in {1, -1} or low_stmt is None:
        state._record_recurrence_reason("no_carry_pattern")
        return False

    state._record_recurrence_candidate()

    if low_carrier is not None and not state.same_c_expression(
        state.unwrap_c_casts(low_stmt.lhs),
        state.unwrap_c_casts(low_carrier),
    ):
        state._record_recurrence_reason("carrier_pair_mismatch")
        return False

    setattr(
        loop,
        iteration_attr,
        structured_c.CAssignment(
        iterator_local,
        state.build_linear_expr(iterator_local, candidate_delta),
        codegen=state.codegen,
        ),
    )
    removed_low_stmt = _remove_statement_from_tree_8616(body, low_stmt)
    if _linear_recurrence_debug_enabled():
        log.warning("[linear-recurrence] removed_low_stmt=%s", removed_low_stmt)
    state.changed = True
    state._record_recurrence_success()
    return True


def _coalesce_linear_recurrence_statements(
    project,
    codegen,
    *,
    unwrap_c_casts,
    structured_codegen_node,
    iter_c_nodes_deep,
    same_c_expression,
    c_constant_value,
    canonicalize_stack_cvar_expr,
    seed_adjacent_byte_pair_aliases,
    describe_alias_storage,
    analyze_widening_expr,
    match_high_byte_projection_base,
    match_duplicate_word_base_expr,
    match_duplicate_word_increment_shift_expr,
    same_stack_slot_identity_var,
    rules,
):
    if getattr(codegen, "cfunc", None) is None:
        return False
    state = LinearRecurrenceState(
        project=project,
        codegen=codegen,
        unwrap_c_casts=unwrap_c_casts,
        structured_codegen_node=structured_codegen_node,
        iter_c_nodes_deep=iter_c_nodes_deep,
        same_c_expression=same_c_expression,
        c_constant_value=c_constant_value,
        canonicalize_stack_cvar_expr=canonicalize_stack_cvar_expr,
        seed_adjacent_byte_pair_aliases=seed_adjacent_byte_pair_aliases,
        describe_alias_storage=describe_alias_storage,
        analyze_widening_expr=analyze_widening_expr,
        match_high_byte_projection_base=match_high_byte_projection_base,
        match_duplicate_word_base_expr=match_duplicate_word_base_expr,
        match_duplicate_word_increment_shift_expr=match_duplicate_word_increment_shift_expr,
        same_stack_slot_identity_var=same_stack_slot_identity_var,
    )
    state.prepare()

    def visit(node):
        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None
                if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
                    stmt_var = getattr(stmt.lhs, "variable", None)
                    if stmt_var is not None and id(stmt_var) in state.dereferenced_variable_ids:
                        visit(stmt)
                        new_statements.append(stmt)
                        i += 1
                        continue
                    carry_base = match_duplicate_word_increment_shift_expr(stmt.rhs, state.resolve_known_copy_alias_expr, codegen)
                    carry_rewrite = rules._carry_base_rewrite_plan(
                        carry_base,
                        expr_contains_dereference=state.expr_contains_dereference,
                        extract_linear_delta=state.extract_linear_delta,
                    )
                    if carry_rewrite is not None:
                        if stmt_var is not None and carry_rewrite["linear"] is not None:
                            state.linear_defs[id(stmt_var)] = carry_rewrite["linear"]
                        new_statements.append(structured_c.CAssignment(stmt.lhs, carry_rewrite["replacement"], codegen=codegen))
                        state.changed = True
                        i += 1
                        continue
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(next_stmt.lhs, structured_c.CVariable)
                ):
                    temp_var = getattr(stmt.lhs, "variable", None)
                    next_var = getattr(next_stmt.lhs, "variable", None)
                    temp_use_count = state.variable_use_counts.get(id(temp_var), 0) if temp_var is not None else 0
                    if (
                        (temp_var is not None and id(temp_var) in state.dereferenced_variable_ids)
                        or (next_var is not None and id(next_var) in state.dereferenced_variable_ids)
                        or (temp_var is not None and id(temp_var) in state.protected_linear_alias_ids)
                        or (next_var is not None and id(next_var) in state.protected_linear_alias_ids)
                    ):
                        visit(stmt)
                        new_statements.append(stmt)
                        i += 1
                        continue
                    if temp_use_count >= 2 and state.is_linear_register_temp(stmt.lhs) and state.is_linear_register_temp(next_stmt.lhs):
                        stmt_base, stmt_delta = state.extract_linear_delta(stmt.rhs)
                        next_rhs = unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_rhs, structured_c.CBinaryOp) and next_rhs.op in {"Add", "Sub"}:
                            if same_c_expression(unwrap_c_casts(next_rhs.lhs), stmt.lhs):
                                next_delta = c_constant_value(unwrap_c_casts(next_rhs.rhs))
                                next_base = stmt_base
                            elif same_c_expression(unwrap_c_casts(next_rhs.rhs), stmt.lhs):
                                next_delta = c_constant_value(unwrap_c_casts(next_rhs.lhs))
                                next_base = stmt_base
                            else:
                                next_delta = None
                                next_base = None
                            if next_base is not None and isinstance(next_delta, int):
                                combined = stmt_delta + next_delta if next_rhs.op == "Add" else stmt_delta - next_delta
                                new_statements.append(structured_c.CAssignment(next_stmt.lhs, state.build_linear_expr(next_base, combined), codegen=codegen))
                                state.changed = True
                                i += 2
                                continue
                    if temp_use_count >= 2 and state.is_linear_register_temp(stmt.lhs) and state.is_linear_register_temp(next_stmt.lhs):
                        stmt_shift_base, stmt_shift_count = state.extract_shift_delta(stmt.rhs)
                        next_shift_rhs = unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_shift_rhs, structured_c.CBinaryOp) and next_shift_rhs.op == "Shr":
                            if same_c_expression(unwrap_c_casts(next_shift_rhs.lhs), stmt.lhs):
                                next_shift_count = c_constant_value(unwrap_c_casts(next_shift_rhs.rhs))
                                if isinstance(next_shift_count, int) and stmt_shift_count >= 0:
                                    combined_shift = stmt_shift_count + next_shift_count
                                    shift_repl = structured_c.CAssignment(next_stmt.lhs, state.build_shift_expr(stmt_shift_base, combined_shift), codegen=codegen)
                                    shift_var = getattr(next_stmt.lhs, "variable", None)
                                    if shift_var is not None:
                                        state.shift_defs[id(shift_var)] = (stmt_shift_base, combined_shift)
                                    new_statements.append(shift_repl)
                                    state.changed = True
                                    i += 2
                                    continue
                    if state.is_linear_register_temp(stmt.lhs):
                        stmt_base, stmt_delta = state.extract_linear_delta(stmt.rhs)
                        if stmt_base is not None:
                            resolved_stmt_base = state.resolve_known_copy_alias_expr(stmt_base)
                            if state.expr_contains_dereference(stmt_base) or state.expr_contains_dereference(resolved_stmt_base):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            base_var = getattr(stmt_base, "variable", None) if isinstance(stmt_base, structured_c.CVariable) else None
                            if base_var is not None and (id(base_var) in state.dereferenced_variable_ids or id(base_var) in state.protected_linear_alias_ids):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            state.linear_defs[id(temp_var)] = (stmt_base, stmt_delta)
                            resolved_base = state.resolve_known_copy_alias_expr(stmt_base)
                            if isinstance(resolved_base, structured_c.CVariable) and isinstance(getattr(resolved_base, "variable", None), SimStackVariable):
                                state.protected_linear_defs.add(id(temp_var))
                            canonical_rhs = state.build_linear_expr(stmt_base, stmt_delta)
                            if not same_c_expression(stmt.rhs, canonical_rhs):
                                stmt = structured_c.CAssignment(stmt.lhs, canonical_rhs, codegen=codegen)
                                state.changed = True
                        rhs = state.inline_known_linear_defs(stmt.rhs)
                        inlined_base, inlined_delta = state.extract_linear_delta(rhs)
                        if inlined_base is not None and not same_c_expression(rhs, stmt.rhs):
                            stmt = structured_c.CAssignment(stmt.lhs, state.build_linear_expr(inlined_base, inlined_delta), codegen=codegen)
                            rhs = stmt.rhs
                            state.changed = True
                        current_linear = state.linear_defs.get(id(temp_var)) if temp_var is not None else None
                        if current_linear is not None and isinstance(rhs, structured_c.CBinaryOp) and rhs.op in {"Add", "Sub"}:
                            if same_c_expression(unwrap_c_casts(rhs.lhs), stmt.lhs) or same_c_expression(unwrap_c_casts(rhs.rhs), stmt.lhs):
                                current_delta = c_constant_value(unwrap_c_casts(rhs.lhs))
                                if current_delta is None:
                                    current_delta = c_constant_value(unwrap_c_casts(rhs.rhs))
                                if isinstance(current_delta, int):
                                    base_expr, base_delta = current_linear
                                    resolved_base = state.resolve_known_copy_alias_expr(base_expr)
                                    if isinstance(resolved_base, structured_c.CVariable) and isinstance(getattr(resolved_base, "variable", None), SimStackVariable):
                                        state.protected_linear_defs.add(id(temp_var))
                                    combined = base_delta + current_delta if rhs.op == "Add" else base_delta - current_delta
                                    stmt = structured_c.CAssignment(stmt.lhs, state.build_linear_expr(base_expr, combined), codegen=codegen)
                                    state.changed = True
                        if temp_var is not None and state.is_copy_alias_candidate(stmt.rhs):
                            alias = unwrap_c_casts(stmt.rhs)
                            alias_var = getattr(alias, "variable", None)
                            if alias_var is not None and alias_var is not temp_var:
                                state.expr_aliases[id(temp_var)] = alias
                                storage_key = state.alias_storage_key(stmt.lhs)
                                if storage_key is not None:
                                    state.expr_aliases[storage_key] = alias
                        if isinstance(temp_var, SimStackVariable) and state.is_copy_alias_candidate(stmt.rhs):
                            alias = unwrap_c_casts(stmt.rhs)
                            alias_var = getattr(alias, "variable", None)
                            if isinstance(alias_var, SimStackVariable) and alias_var is not temp_var and same_stack_slot_identity_var(temp_var, alias_var):
                                state.expr_aliases[id(temp_var)] = alias
                                storage_key = state.alias_storage_key(stmt.lhs)
                                if storage_key is not None:
                                    state.expr_aliases[storage_key] = alias
                visit(stmt)
                new_statements.append(stmt)
                i += 1
            if state.changed or new_statements != node.statements:
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            new_pairs = []
            pair_changed = False
            for cond, body in node.condition_and_nodes:
                new_cond = cond
                if structured_codegen_node(cond):
                    candidate_cond = state.resolve_known_copy_alias_expr(new_cond)
                    candidate_cond = state.inline_known_linear_defs(candidate_cond)
                    if rules._should_commit_linear_rewrite(cond, candidate_cond, expr_contains_dereference=state.expr_contains_dereference, same_c_expression=same_c_expression):
                        new_cond = candidate_cond
                if new_cond is not cond:
                    pair_changed = True
                visit(body)
                new_pairs.append((new_cond, body))
            if pair_changed:
                node.condition_and_nodes = new_pairs
                state.changed = True
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning("[linear-recurrence] saw while-loop function=%#x", getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1)
            _rewrite_linear_condition(node, state, structured_codegen_node=structured_codegen_node, same_c_expression=same_c_expression, rules=rules)
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning("[linear-recurrence] saw do-while-loop function=%#x", getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1)
            _rewrite_linear_condition(node, state, structured_codegen_node=structured_codegen_node, same_c_expression=same_c_expression, rules=rules)
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning("[linear-recurrence] saw for-loop function=%#x", getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1)
            for attr in ("initializer", "init", "condition", "iteration", "iterator"):
                current = getattr(node, attr, None)
                if structured_codegen_node(current):
                    candidate = state.resolve_known_copy_alias_expr(current)
                    candidate = state.inline_known_linear_defs(candidate)
                    if candidate is not current and rules._should_commit_linear_rewrite(current, candidate, expr_contains_dereference=state.expr_contains_dereference, same_c_expression=same_c_expression):
                        setattr(node, attr, candidate)
                        state.changed = True
            visit(getattr(node, "initializer", None))
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "iterator", None))
            visit(getattr(node, "body", None))
            _rebind_for_loop_byte_carrier_recurrence(node, state, rules=rules)

    visit(codegen.cfunc.statements)
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[linear-recurrence] function=%#x candidates=%d bound=%d failed=%d reasons=%r",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            state.recurrence_candidates,
            state.recurrence_bound_to_materialized_local,
            state.recurrence_failed_to_bind,
            state.recurrence_reasons,
        )
    if state.recurrence_candidates > 0 and state.recurrence_bound_to_materialized_local == 0:
        raise PipelineHardError(
            "byte-carrier recurrence not rebound to materialized local",
            layer="stack_lowering",
        )
    codegen._inertia_recurrence_state = state
    return state.changed
