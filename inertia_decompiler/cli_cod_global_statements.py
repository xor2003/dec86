from __future__ import annotations

from typing import Any, Callable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort


def _same_expr(left: Any, right: Any) -> bool:
    def _impl():
        if left is right:
            return True
        if type(left) is not type(right):
            return False
        if isinstance(left, structured_c.CConstant):
            return getattr(left, "value", None) == getattr(right, "value", None)
        if isinstance(left, structured_c.CVariable):
            left_var = getattr(left, "variable", None)
            right_var = getattr(right, "variable", None)
            if left_var is right_var:
                return True
            return getattr(left, "name", None) == getattr(right, "name", None) and getattr(
                left_var, "name", None
            ) == getattr(right_var, "name", None)
        if isinstance(left, structured_c.CBinaryOp):
            return (
                getattr(left, "op", None) == getattr(right, "op", None)
                and _same_expr(getattr(left, "lhs", None), getattr(right, "lhs", None))
                and _same_expr(getattr(left, "rhs", None), getattr(right, "rhs", None))
            )
        if isinstance(left, structured_c.CUnaryOp):
            return getattr(left, "op", None) == getattr(right, "op", None) and _same_expr(
                getattr(left, "operand", None),
                getattr(right, "operand", None),
            )
        return False

    return _impl()


def _is_high_byte_projection(high_expr: Any, low_expr: Any) -> bool:
    if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op != "Shr":
        return False
    shift = getattr(getattr(high_expr, "rhs", None), "value", None)
    return shift == 8 and _same_expr(getattr(high_expr, "lhs", None), low_expr)


def _coalesce_cod_word_global_statements(
    project: Any,
    codegen: Any,
    synthetic_globals: Any,
    *,
    global_memory_addr: Callable[[Any], int | None],
    high_byte_store_addr: Callable[[Any, Any], int | None],
    synthetic_word_global_variable: Callable[[Any, Any, int], structured_c.CVariable | None],
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node: Any) -> None:
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
                    base_addr = global_memory_addr(stmt.lhs)
                    next_addr = high_byte_store_addr(next_stmt.lhs, project)
                    word_global = (
                        synthetic_word_global_variable(codegen, synthetic_globals, base_addr)
                        if base_addr is not None
                        else None
                    )

                    if base_addr is not None and next_addr == base_addr + 1 and word_global is not None:
                        if isinstance(stmt.rhs, structured_c.CConstant) and isinstance(
                            next_stmt.rhs, structured_c.CConstant
                        ):
                            value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
                            new_statements.append(
                                structured_c.CAssignment(
                                    word_global,
                                    structured_c.CConstant(value, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                            )
                            changed = True
                            i += 2
                            continue
                        if _is_high_byte_projection(next_stmt.rhs, stmt.rhs):
                            new_statements.append(
                                structured_c.CAssignment(
                                    word_global,
                                    stmt.rhs,
                                    codegen=codegen,
                                )
                            )
                            changed = True
                            i += 2
                            continue
                        changed = True
                        new_statements.append(stmt)
                        new_statements.append(next_stmt)
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed
