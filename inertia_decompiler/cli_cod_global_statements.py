"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort


class _CFunctionLike(Protocol):
    """Structured C function surface needed by COD global statement coalescing."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by COD global statement coalescing."""

    cfunc: _CFunctionLike | None


def _same_expr(left: object, right: object) -> bool:
    def _impl() -> bool:
        if left is right:
            return True
        if type(left) is not type(right):
            return False
        if isinstance(left, structured_c.CConstant) and isinstance(right, structured_c.CConstant):
            return left.value == right.value
        if isinstance(left, structured_c.CVariable) and isinstance(right, structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            left_var = getattr(left, "variable", None)
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            right_var = getattr(right, "variable", None)
            if left_var is right_var:
                return True
            # Dynamic codegen boundary: rendered names and variable names are optional.
            left_name = getattr(left, "name", None)
            # Dynamic codegen boundary: rendered names and variable names are optional.
            right_name = getattr(right, "name", None)
            # Dynamic codegen boundary: rendered codegen variable names are optional.
            left_var_name = getattr(left_var, "name", None)
            # Dynamic codegen boundary: rendered codegen variable names are optional.
            right_var_name = getattr(right_var, "name", None)
            return left_name == right_name and left_var_name == right_var_name
        if isinstance(left, structured_c.CBinaryOp) and isinstance(right, structured_c.CBinaryOp):
            return (
                left.op == right.op
                and _same_expr(left.lhs, right.lhs)
                and _same_expr(left.rhs, right.rhs)
            )
        if isinstance(left, structured_c.CUnaryOp) and isinstance(right, structured_c.CUnaryOp):
            return left.op == right.op and _same_expr(left.operand, right.operand)
        return False

    return _impl()


def _is_high_byte_projection(high_expr: object, low_expr: object) -> bool:
    if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op != "Shr":
        return False
    rhs = high_expr.rhs
    if not isinstance(rhs, structured_c.CConstant):
        return False
    return rhs.value == 8 and _same_expr(high_expr.lhs, low_expr)


def _coalesce_cod_word_global_statements(
    project: object,
    codegen: _CodegenLike,
    synthetic_globals: object,
    *,
    global_memory_addr: Callable[[object], int | None],
    high_byte_store_addr: Callable[[object, object], int | None],
    synthetic_word_global_variable: Callable[[_CodegenLike, object, int], structured_c.CVariable | None],
) -> bool:
    cfunc = codegen.cfunc
    if not synthetic_globals or cfunc is None:
        return False

    changed = False

    def visit(node: object) -> None:
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
                            low_value = stmt.rhs.value
                            high_value = next_stmt.rhs.value
                            if not isinstance(low_value, int) or not isinstance(high_value, int):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            value = (low_value & 0xFF) | ((high_value & 0xFF) << 8)
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

    visit(cfunc.statements)
    return changed
