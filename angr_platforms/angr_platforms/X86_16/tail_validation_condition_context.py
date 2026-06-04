from __future__ import annotations

import os

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDoWhileLoop,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)

from .decompiler_postprocess_flags import (
    _extract_flag_predicate_from_expr_8616,
    _extract_flag_test_info_8616,
)
from .decompiler_postprocess_jcc import _condition_tags_8616, _translate_cmp_jcc_guard_8616
from .decompiler_postprocess_utils import _same_c_expression_8616
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = ["build_x86_16_contextual_condition_fingerprints"]


def _last_assignment_in_stmt(stmt):
    if isinstance(stmt, CAssignment):
        return stmt
    return None


def _iter_stmt_conditions(stmt):
    if isinstance(stmt, CIfElse):
        for cond, _body in getattr(stmt, "condition_and_nodes", ()) or ():
            if cond is not None:
                yield cond
    elif isinstance(stmt, (CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop)):
        cond = getattr(stmt, "condition", None)
        if cond is not None:
            yield cond


def _contextual_condition_fingerprint(assign_stmt, cond, project) -> str | None:
    lhs = getattr(assign_stmt, "lhs", None)
    if not isinstance(lhs, CVariable):
        return None

    info = _extract_flag_test_info_8616(cond)
    if info is None:
        return None
    flag_var, bit, negate_predicate = info
    if not _same_c_expression_8616(lhs, flag_var):
        return None

    predicate = _extract_flag_predicate_from_expr_8616(getattr(assign_stmt, "rhs", None), bit)
    if predicate is None:
        return None
    if negate_predicate:
        predicate = CUnaryOp("Not", predicate, codegen=getattr(cond, "codegen", None))
    return _expr_fingerprint(predicate, project)


def _decoded_jcc_condition_fingerprint(cond, project) -> str | None:
    key = _condition_tags_8616(cond)
    if key is None:
        return None
    ins_addr, block_addr = key
    codegen = getattr(project, "_inertia_tail_validation_active_codegen", None) or getattr(cond, "codegen", None)
    decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
    if decoded is None:
        if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            import sys

            print(
                f"[tv-condition-context] decode_failed block={block_addr:#x} ins={ins_addr:#x} "
                f"active_codegen={getattr(project, '_inertia_tail_validation_active_codegen', None) is not None} "
                f"cond_codegen={getattr(cond, 'codegen', None) is not None}",
                file=sys.stderr,
                flush=True,
            )
        return None
    lhs = _expr_fingerprint(decoded.lhs, project)
    rhs = _expr_fingerprint(decoded.rhs, project)
    if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
        import sys

        print(
            f"[tv-condition-context] decoded block={block_addr:#x} ins={ins_addr:#x} "
            f"op={decoded.op} lhs={lhs} rhs={rhs} expr={type(decoded.expr).__name__ if decoded.expr is not None else 'None'}",
            file=sys.stderr,
            flush=True,
        )
    if lhs == rhs:
        return None
    return f"{decoded.op}({lhs},{rhs})"


def build_x86_16_contextual_condition_fingerprints(root, project) -> dict[int, str]:
    mapping: dict[int, str] = {}

    def visit(node) -> None:
        if isinstance(node, CStatements):
            statements = list(node.statements)
            for index, stmt in enumerate(statements[:-1]):
                assign_stmt = _last_assignment_in_stmt(stmt)
                if assign_stmt is None:
                    continue
                next_stmt = statements[index + 1]
                for cond in _iter_stmt_conditions(next_stmt):
                    fingerprint = _decoded_jcc_condition_fingerprint(cond, project)
                    if fingerprint is None:
                        fingerprint = _contextual_condition_fingerprint(assign_stmt, cond, project)
                    if fingerprint is not None:
                        mapping[id(cond)] = fingerprint
            for stmt in statements:
                for cond in _iter_stmt_conditions(stmt):
                    fingerprint = _decoded_jcc_condition_fingerprint(cond, project)
                    if fingerprint is not None:
                        mapping[id(cond)] = fingerprint
            for stmt in statements:
                visit(stmt)
            return

        if isinstance(node, CIfElse):
            for _cond, body in getattr(node, "condition_and_nodes", ()) or ():
                if body is not None:
                    visit(body)
            else_node = getattr(node, "else_node", None)
            if else_node is not None:
                visit(else_node)
            return

        if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
            body = getattr(node, "body", None)
            if body is not None:
                visit(body)

    if root is not None:
        visit(root)
    return mapping
