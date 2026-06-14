from __future__ import annotations

import copy
import os
import sys
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..structuring.simple_loop_recovery import _function_instruction_summaries_8616


def run_typed_widening_pass_8616(
    project,
    codegen,
    *,
    coalesce_direct_ss_local_word_statements,
    coalesce_segmented_word_store_statements,
    copy_propagation_fn=None,
    promote_stack_slots_from_instruction_widths=None,
) -> bool:
    """Execute widening-owned passes in deterministic order.

    Order:
    1. Stack-slot width promotion from instruction evidence
    2. Word-store coalescing (SROA-like)
    3. Copy propagation (EarlyCSE-like)
    4. Load/store folding (GVN-like)

    This pass is the widening ownership boundary: callers provide typed helpers,
    widening decides pass ordering and changed-state aggregation.
    """
    changed = False
    if promote_stack_slots_from_instruction_widths is not None:
        changed = promote_stack_slots_from_instruction_widths(project, codegen) or changed
    changed = coalesce_direct_ss_local_word_statements(project, codegen) or changed
    changed = coalesce_segmented_word_store_statements(project, codegen) or changed
    if copy_propagation_fn is not None:
        changed = copy_propagation_fn(codegen) or changed
    return changed


def collect_bp_stack_access_widths_from_instructions_8616(project, codegen) -> dict[int, int]:
    """Collect BP-relative stack slot widths directly from decoded instructions."""
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return {}

    kb = getattr(project, "kb", None)
    functions = getattr(kb, "functions", None)
    function = None
    if functions is not None:
        try:
            function = functions.function(addr=int(func_addr), create=False)
        except Exception:
            function = None
    if function is None:
        function = SimpleNamespace(
            addr=int(func_addr),
            size=getattr(cfunc, "size", None),
            name=getattr(cfunc, "name", None),
        )

    widths: dict[int, int] = {}
    for insn in _function_instruction_summaries_8616(project, function):
        for operand_kind, operand_value, operand_size in (
            (insn.op0_kind, insn.op0_value, insn.op0_size),
            (insn.op1_kind, insn.op1_value, insn.op1_size),
        ):
            if operand_kind != "bp_mem" or not isinstance(operand_value, int):
                continue
            size = int(operand_size or 0)
            if size <= 0:
                continue
            widths[int(operand_value)] = max(widths.get(int(operand_value), 0), size)
    if widths:
        return widths

    block_addrs = tuple(sorted(getattr(function, "block_addrs", ()) or ()))
    if not block_addrs:
        block_addrs = (int(func_addr),)

    for block_addr in block_addrs:
        try:
            block = project.factory.block(int(block_addr), opt_level=0)
        except Exception:
            continue
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            for operand in tuple(getattr(insn, "operands", ()) or ()):
                if int(getattr(operand, "type", -1)) != 3 or getattr(operand, "mem", None) is None:
                    continue
                mem = operand.mem
                if not getattr(mem, "base", None):
                    continue
                try:
                    base_name = str(insn.reg_name(mem.base)).lower()
                except Exception:
                    continue
                if base_name != "bp":
                    continue
                size = int(getattr(operand, "size", 0) or 0)
                if size <= 0:
                    continue
                disp = int(getattr(mem, "disp", 0) or 0)
                if 0x8000 <= disp <= 0xFFFF:
                    disp -= 0x10000
                widths[disp] = max(widths.get(disp, 0), size)
    return widths


def promote_stack_slots_from_instruction_widths_8616(
    project,
    codegen,
    *,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    stack_type_for_size,
) -> bool:
    """Promote existing stack C variables when instruction evidence proves a wider slot."""
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    promoted = 0
    widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)
    for offset, size in sorted(widths.items()):
        if size <= 1:
            continue
        cvar = resolve_stack_cvar_at_offset(codegen, offset, preferred_size=size)
        variable = getattr(cvar, "variable", None)
        if variable is None or getattr(variable, "offset", None) != offset:
            continue
        target_type = stack_type_for_size(size)
        if promote_direct_stack_cvariable(codegen, cvar, size, target_type):
            changed = True
            promoted += 1

    if widths:
        try:
            codegen._inertia_stack_width_instruction_fact_count = int(
                getattr(codegen, "_inertia_stack_width_instruction_fact_count", 0) or 0
            ) + len(widths)
            codegen._inertia_stack_width_instruction_materialized_count = int(
                getattr(codegen, "_inertia_stack_width_instruction_materialized_count", 0) or 0
            ) + promoted
        except Exception:
            pass
    return changed


def _coalesce_direct_ss_local_word_statements(
    project,
    codegen,
    *,
    match_ss_local_plus_const,
    match_shift_right_8_expr,
    stack_slot_identity_can_join,
    same_c_expression,
    unwrap_c_casts,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    match_byte_store_addr_expr,
    addr_exprs_are_byte_pair,
    resolve_stack_cvar_from_addr_expr,
    canonicalize_stack_cvar_expr,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    replacement = None
                    replacement_lhs = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            high_expr = match_shift_right_8_expr(next_stmt.rhs)
                            if (
                                extra_offset == 1
                                and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                                and high_expr is not None
                                and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                            ):
                                replacement_lhs = stmt.lhs

                    if replacement_lhs is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        high_expr = match_shift_right_8_expr(next_stmt.rhs)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and high_expr is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                            and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                        ):
                            resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                            if isinstance(resolved_lhs, structured_c.CVariable):
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)

                    if isinstance(replacement_lhs, structured_c.CVariable):
                        if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, stack_type_for_size(2)):
                            changed = True
                        replacement = structured_c.CAssignment(replacement_lhs, stmt.rhs, codegen=codegen)

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))

    visit(codegen.cfunc.statements)
    return changed


def _coalesce_segmented_word_store_statements(
    project,
    codegen,
    *,
    match_ss_local_plus_const,
    match_word_rhs_from_byte_pair,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    stack_slot_identity_can_join,
    canonicalize_stack_cvar_expr,
    match_byte_store_addr_expr,
    match_shift_right_8_expr,
    addr_exprs_are_byte_pair,
    resolve_stack_cvar_from_addr_expr,
    make_word_dereference_from_addr_expr,
    classify_segmented_addr_expr,
    describe_alias_storage,
    match_byte_load_addr_expr=None,
    same_c_expression=None,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = stack_type_for_size(2)
    debug_widening = os.environ.get("INERTIA_DEBUG_WIDENING", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    def _debug(reason: str, **attrs) -> None:
        if not debug_widening:
            return
        parts = [f"reason={reason}"]
        for key in sorted(attrs):
            value = attrs[key]
            if value is None:
                value = "-"
            parts.append(f"{key}={value}")
        print("[widening.coalesce_word_store] " + " ".join(parts), file=sys.stderr)

    def _same_expr(lhs, rhs) -> bool:
        if callable(same_c_expression):
            return bool(same_c_expression(lhs, rhs))
        return lhs is rhs

    def _node_kind(node) -> str:
        return "-" if node is None else type(node).__name__

    def _node_op(node) -> str:
        return str(getattr(node, "op", "-")) if node is not None else "-"

    def _node_child_kind(node, attr: str) -> str:
        if node is None or not hasattr(node, attr):
            return "-"
        try:
            return _node_kind(getattr(node, attr))
        except Exception:
            return "error"

    def _node_type_bits(node) -> str:
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        return "-" if bits is None else str(bits)

    def _expr_width_bits(node) -> int | None:
        type_ = getattr(node, "type", None)
        try:
            bits = getattr(type_, "size", None)
        except ValueError:
            bits = None
        if isinstance(bits, int):
            return bits
        variable = getattr(node, "variable", None)
        size = getattr(variable, "size", None)
        if isinstance(size, int) and size > 0:
            return size * 8
        return None

    def _unwrap_casts(node):
        while isinstance(node, structured_c.CTypeCast):
            node = node.expr
        return node

    def _match_byte_load_addr_for_assignment(lhs, rhs):
        if callable(match_byte_load_addr_expr):
            matched = match_byte_load_addr_expr(rhs)
            if matched is not None:
                return matched
        if _expr_width_bits(lhs) != 8:
            return None
        rhs = _unwrap_casts(rhs)
        if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Dereference":
            return None
        operand = _unwrap_casts(getattr(rhs, "operand", None))
        return operand

    def _same_c_variable(lhs, rhs) -> bool:
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = getattr(lhs, "variable", None)
        rhs_var = getattr(rhs, "variable", None)
        if lhs_var is rhs_var:
            return True
        lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
        rhs_name = getattr(rhs, "name", None) or getattr(rhs_var, "name", None)
        return isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name

    def _is_byte_cvar(node) -> bool:
        return isinstance(node, structured_c.CVariable) and _expr_width_bits(node) == 8

    def _is_word_or_wider_cvar(node) -> bool:
        return isinstance(node, structured_c.CVariable) and (_expr_width_bits(node) or 0) >= 16

    def _match_loaded_word_pair_expr(expr, low_var, high_var):
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
            return False
        candidates = ((getattr(expr, "lhs", None), getattr(expr, "rhs", None)), (getattr(expr, "rhs", None), getattr(expr, "lhs", None)))
        for low_expr, shifted_high in candidates:
            if not _same_c_variable(low_expr, low_var):
                continue
            if not isinstance(shifted_high, structured_c.CBinaryOp) or shifted_high.op != "Shl":
                continue
            shift_value = getattr(getattr(shifted_high, "rhs", None), "value", None)
            if shift_value == 8 and _same_c_variable(getattr(shifted_high, "lhs", None), high_var):
                return True
        return False

    def _replace_loaded_word_pair_expr(expr, low_var, high_var, replacement):
        if _match_loaded_word_pair_expr(expr, low_var, high_var):
            return replacement, True
        if isinstance(expr, structured_c.CBinaryOp):
            new_lhs, lhs_changed = _replace_loaded_word_pair_expr(expr.lhs, low_var, high_var, replacement)
            new_rhs, rhs_changed = _replace_loaded_word_pair_expr(expr.rhs, low_var, high_var, replacement)
            if lhs_changed or rhs_changed:
                new_expr = copy.copy(expr)
                new_expr.lhs = new_lhs
                new_expr.rhs = new_rhs
                return new_expr, True
            return expr, False
        if isinstance(expr, structured_c.CUnaryOp):
            new_operand, operand_changed = _replace_loaded_word_pair_expr(expr.operand, low_var, high_var, replacement)
            if operand_changed:
                new_expr = copy.copy(expr)
                new_expr.operand = new_operand
                return new_expr, True
            return expr, False
        if isinstance(expr, structured_c.CTypeCast):
            new_inner, inner_changed = _replace_loaded_word_pair_expr(expr.expr, low_var, high_var, replacement)
            if inner_changed:
                new_expr = copy.copy(expr)
                new_expr.expr = new_inner
                return new_expr, True
            return expr, False
        return expr, False

    def _word_lvalue_for_addr(low_addr_expr):
        low_class = classify_segmented_addr_expr(low_addr_expr, project)
        _debug(
            "word_lvalue_class",
            cls_kind=getattr(low_class, "kind", None),
            cls_seg=getattr(low_class, "seg_name", None),
            cls_assoc=getattr(low_class, "assoc_kind", None),
            cls_extra=getattr(low_class, "extra_offset", None),
            cls_base_terms=getattr(getattr(low_class, "assoc_state", None), "base_terms", None),
            cls_other_terms=getattr(getattr(low_class, "assoc_state", None), "other_terms", None),
            cls_stack_slots=len(getattr(getattr(low_class, "assoc_state", None), "stack_slots", ()) or ()),
            has_cvar=int(getattr(low_class, "cvar", None) is not None),
        )
        if low_class is not None and low_class.kind == "stack":
            resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
            if resolved_lhs is None:
                return None
            replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)
            if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                nonlocal_changed[0] = True
            return replacement_lhs
        resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
        if resolved_lhs is not None:
            return canonicalize_stack_cvar_expr(resolved_lhs, codegen)
        return make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

    nonlocal_changed = [False]

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None
                third_stmt = node.statements[i + 2] if i + 2 < len(node.statements) else None
                fourth_stmt = node.statements[i + 3] if i + 3 < len(node.statements) else None

                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(third_stmt, structured_c.CAssignment)
                    and _is_byte_cvar(getattr(stmt, "lhs", None))
                    and _is_byte_cvar(getattr(next_stmt, "lhs", None))
                    and _is_word_or_wider_cvar(getattr(stmt, "rhs", None))
                    and _same_expr(getattr(stmt, "rhs", None), getattr(next_stmt, "rhs", None))
                    and _same_c_variable(getattr(stmt, "rhs", None), getattr(third_stmt, "lhs", None))
                ):
                    rewritten_rhs, rhs_changed = _replace_loaded_word_pair_expr(
                        getattr(third_stmt, "rhs", None),
                        getattr(stmt, "lhs", None),
                        getattr(next_stmt, "lhs", None),
                        getattr(stmt, "rhs", None),
                    )
                    if rhs_changed:
                        new_statements.append(
                            structured_c.CAssignment(
                                getattr(third_stmt, "lhs", None),
                                canonicalize_stack_cvar_expr(rewritten_rhs, codegen),
                                codegen=codegen,
                            )
                        )
                        changed = True
                        i += 3
                        continue

                if (
                    callable(match_byte_load_addr_expr)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(third_stmt, structured_c.CAssignment)
                    and isinstance(fourth_stmt, structured_c.CAssignment)
                    and isinstance(getattr(stmt, "lhs", None), structured_c.CVariable)
                    and isinstance(getattr(next_stmt, "lhs", None), structured_c.CVariable)
                ):
                    low_load_addr = _match_byte_load_addr_for_assignment(
                        getattr(stmt, "lhs", None), getattr(stmt, "rhs", None)
                    )
                    high_load_addr = _match_byte_load_addr_for_assignment(
                        getattr(next_stmt, "lhs", None), getattr(next_stmt, "rhs", None)
                    )
                    low_store_addr = match_byte_store_addr_expr(getattr(third_stmt, "lhs", None))
                    high_store_addr = match_byte_store_addr_expr(getattr(fourth_stmt, "lhs", None))
                    high_store_base = match_shift_right_8_expr(getattr(fourth_stmt, "rhs", None))
                    has_addrs = (
                        low_load_addr is not None
                        and high_load_addr is not None
                        and low_store_addr is not None
                        and high_store_addr is not None
                        and high_store_base is not None
                    )
                    load_pair = (
                        addr_exprs_are_byte_pair(low_load_addr, high_load_addr, project) if has_addrs else False
                    )
                    store_pair = (
                        addr_exprs_are_byte_pair(low_store_addr, high_store_addr, project) if has_addrs else False
                    )
                    same_low = _same_expr(low_load_addr, low_store_addr) if has_addrs else False
                    same_high = _same_expr(high_load_addr, high_store_addr) if has_addrs else False
                    same_rhs = (
                        _same_expr(high_store_base, getattr(third_stmt, "rhs", None)) if has_addrs else False
                    )
                    if debug_widening and any(
                        value is not None
                        for value in (low_load_addr, high_load_addr, low_store_addr, high_store_addr, high_store_base)
                    ):
                        _debug(
                            "four_stmt_probe",
                            low_load=_node_kind(low_load_addr),
                            low_rhs=_node_kind(getattr(stmt, "rhs", None)),
                            low_rhs_op=_node_op(getattr(stmt, "rhs", None)),
                            low_rhs_expr=_node_child_kind(getattr(stmt, "rhs", None), "expr"),
                            low_rhs_operand=_node_child_kind(getattr(stmt, "rhs", None), "operand"),
                            low_rhs_bits=_node_type_bits(getattr(stmt, "rhs", None)),
                            high_load=_node_kind(high_load_addr),
                            high_rhs=_node_kind(getattr(next_stmt, "rhs", None)),
                            high_rhs_op=_node_op(getattr(next_stmt, "rhs", None)),
                            high_rhs_expr=_node_child_kind(getattr(next_stmt, "rhs", None), "expr"),
                            high_rhs_operand=_node_child_kind(getattr(next_stmt, "rhs", None), "operand"),
                            high_rhs_bits=_node_type_bits(getattr(next_stmt, "rhs", None)),
                            low_store=_node_kind(low_store_addr),
                            high_store=_node_kind(high_store_addr),
                            high_base=_node_kind(high_store_base),
                            load_pair=int(load_pair),
                            store_pair=int(store_pair),
                            same_low=int(same_low),
                            same_high=int(same_high),
                            same_rhs=int(same_rhs),
                        )
                    if has_addrs and load_pair and store_pair and same_low and same_high and same_rhs:
                        loaded_word = _word_lvalue_for_addr(low_load_addr)
                        store_lhs = _word_lvalue_for_addr(low_store_addr)
                        if loaded_word is not None and store_lhs is not None:
                            rewritten_rhs, rhs_changed = _replace_loaded_word_pair_expr(
                                getattr(third_stmt, "rhs", None),
                                getattr(stmt, "lhs", None),
                                getattr(next_stmt, "lhs", None),
                                loaded_word,
                            )
                            if rhs_changed:
                                new_statements.append(
                                    structured_c.CAssignment(
                                        store_lhs,
                                        canonicalize_stack_cvar_expr(rewritten_rhs, codegen),
                                        codegen=codegen,
                                    )
                                )
                                changed = True
                                if nonlocal_changed[0]:
                                    changed = True
                                i += 4
                                continue
                            _debug("four_stmt_refused", loaded_word=_node_kind(loaded_word), store_lhs=_node_kind(store_lhs), rhs_changed=0)
                        else:
                            _debug("four_stmt_no_lvalue", loaded_word=_node_kind(loaded_word), store_lhs=_node_kind(store_lhs))

                if isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment):
                    replacement = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                            if (
                                extra_offset == 1
                                and isinstance(target_cvar, structured_c.CVariable)
                                and target_cvar is not None
                                and rhs_word is not None
                                and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                            ):
                                replacement_lhs = canonicalize_stack_cvar_expr(stmt.lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)

                    if replacement is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and rhs_word is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                        ):
                            low_facts = describe_alias_storage(low_addr_expr)
                            high_facts = describe_alias_storage(high_addr_expr)
                            low_class = classify_segmented_addr_expr(low_addr_expr, project)
                            high_class = classify_segmented_addr_expr(high_addr_expr, project)
                            joinable_segment_const_pair = (
                                low_class is not None
                                and high_class is not None
                                and low_class.kind == high_class.kind == "segment_const"
                                and low_class.seg_name == high_class.seg_name
                                and low_class.linear is not None
                                and high_class.linear == low_class.linear + 1
                            )
                            joinable_stack_alias_pair = (
                                low_class is not None and low_class.kind == "stack" and high_class is None
                            )
                            if (
                                (
                                    low_facts.identity is None
                                    or high_facts.identity is None
                                    or not low_facts.can_join(high_facts)
                                )
                                and not joinable_segment_const_pair
                                and not joinable_stack_alias_pair
                            ):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            if low_class is not None and low_class.kind == "stack":
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                if resolved_lhs is None:
                                    visit(stmt)
                                    new_statements.append(stmt)
                                    i += 1
                                    continue
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)
                            else:
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                replacement = structured_c.CAssignment(
                                    resolved_lhs
                                    if resolved_lhs is not None
                                    else make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
                                    rhs_word,
                                    codegen=codegen,
                                )

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))

    visit(codegen.cfunc.statements)
    return changed
