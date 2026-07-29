"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c


class _CFunctionLike(Protocol):
    """Structured C function surface needed by adjacent byte-pair alias seeding."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by adjacent byte-pair alias seeding."""

    cfunc: _CFunctionLike | None


def _seed_adjacent_byte_pair_aliases(
    project: object,
    codegen: _CodegenLike,
    *,
    structured_codegen_node: Callable[[object], bool],
    unwrap_c_casts: Callable[[object], object],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    match_byte_load_addr_expr: Callable[[object], object | None],
    addr_exprs_are_byte_pair: Callable[[object, object, object], bool],
    make_word_dereference_from_addr_expr: Callable[[_CodegenLike, object, object], object],
) -> dict[int, object]:
    cfunc = codegen.cfunc
    if cfunc is None:
        return {}

    statements = cfunc.statements
    if not structured_codegen_node(statements):
        return {}

    aliases: dict[int, object] = {}

    def _count_variable_ids(expr: object, counts: Counter[int]) -> None:
        expr = unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            variable = getattr(expr, "variable", None)
            if variable is not None:
                counts[id(variable)] += 1
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child field names vary across angr C AST nodes.
                value = getattr(expr, attr)
            except Exception:
                continue
            if structured_codegen_node(value):
                _count_variable_ids(value, counts)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child sequence fields vary across angr C AST nodes.
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if structured_codegen_node(item):
                    _count_variable_ids(item, counts)

    dereference_counts: Counter[int] = Counter()
    for node in iter_c_nodes_deep(statements):
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            # Dynamic codegen boundary: CUnaryOp operand is supplied by angr structured codegen.
            _count_variable_ids(getattr(node, "operand", None), dereference_counts)

    def _record_alias(lhs: object, expr: object) -> None:
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(lhs, "variable", None)
        if variable is None:
            return
        aliases[id(variable)] = expr

    def visit(node: object) -> None:
        if isinstance(node, structured_c.CStatements):
            stmt_list = node.statements
            if isinstance(stmt_list, list):
                for index in range(len(stmt_list) - 1):
                    low_stmt = stmt_list[index]
                    high_stmt = stmt_list[index + 1]
                    if not (
                        isinstance(low_stmt, structured_c.CAssignment)
                        and isinstance(high_stmt, structured_c.CAssignment)
                        and isinstance(low_stmt.lhs, structured_c.CVariable)
                        and isinstance(high_stmt.lhs, structured_c.CVariable)
                    ):
                        continue

                    low_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(low_stmt.rhs))
                    high_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(high_stmt.rhs))
                    if low_addr_expr is None or high_addr_expr is None:
                        continue
                    if not addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
                        continue

                    pair_counts: Counter[int] = Counter()
                    _count_variable_ids(low_addr_expr, pair_counts)
                    _count_variable_ids(high_addr_expr, pair_counts)
                    if any(dereference_counts[var_id] > pair_counts[var_id] for var_id in pair_counts):
                        continue

                    word_expr = make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)
                    _record_alias(low_stmt.lhs, word_expr)
                    _record_alias(high_stmt.lhs, word_expr)
            for stmt in node.statements:
                visit(stmt)
            return

        if isinstance(node, structured_c.CIfElse):
            # Dynamic codegen boundary: CIfElse condition/body pairs are angr codegen metadata.
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                visit(cond)
                visit(body)
            # Dynamic codegen boundary: CIfElse else payload is optional.
            else_node = getattr(node, "else_node", None)
            if else_node is not None:
                visit(else_node)
            return

        if isinstance(node, structured_c.CWhileLoop):
            visit(node.condition)
            visit(node.body)
            return

        # Dynamic codegen boundary: older/newer angr versions differ on loop node classes.
        do_while_type = getattr(structured_c, "CDoWhileLoop", None)
        if do_while_type is not None and isinstance(node, do_while_type):
            # Dynamic codegen boundary: loop payload fields vary across angr C AST nodes.
            visit(getattr(node, "condition", None))
            # Dynamic codegen boundary: loop payload fields vary across angr C AST nodes.
            visit(getattr(node, "body", None))
            return

        # Dynamic codegen boundary: older/newer angr versions differ on loop node classes.
        for_loop_type = getattr(structured_c, "CForLoop", None)
        if for_loop_type is not None and isinstance(node, for_loop_type):
            # Dynamic codegen boundary: for-loop payload fields vary across angr C AST nodes.
            visit(getattr(node, "init", None))
            # Dynamic codegen boundary: for-loop payload fields vary across angr C AST nodes.
            visit(getattr(node, "condition", None))
            # Dynamic codegen boundary: for-loop payload fields vary across angr C AST nodes.
            visit(getattr(node, "iteration", None))
            # Dynamic codegen boundary: for-loop payload fields vary across angr C AST nodes.
            visit(getattr(node, "body", None))
            return

    visit(statements)
    return aliases
