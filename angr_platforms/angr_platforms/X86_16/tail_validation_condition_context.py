from __future__ import annotations

import os

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimRegisterVariable

from .decompiler_postprocess_flags import (
    _extract_flag_predicate_from_expr_8616,
    _extract_flag_test_info_8616,
)
from .decompiler_postprocess_jcc import (
    _JCC_COMPARE_OPS_8616,
    _condition_tags_8616,
    _const_8616,
    _decode_block_and_jcc_index_8616,
    _nearest_flag_producer_before_jcc_8616,
    _reg_offset_8616,
    _resolve_cmp_operand_expr_8616,
    _translate_cmp_jcc_guard_8616,
)
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
    if not isinstance(lhs, (CVariable, CDirtyExpression)):
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
    direct_cmp_fingerprint = _direct_cmp_immediate_jcc_fingerprint(cond, project, codegen, block_addr, ins_addr)
    decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
    if decoded is None:
        if direct_cmp_fingerprint is not None:
            return direct_cmp_fingerprint
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
    if direct_cmp_fingerprint is None and (
        _fingerprint_contains_raw_register_8616(lhs) or _fingerprint_contains_raw_register_8616(rhs)
    ):
        if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            import sys

            print(
                f"[tv-condition-context] decoded refuse raw-register block={block_addr:#x} ins={ins_addr:#x} "
                f"lhs={lhs} rhs={rhs}",
                file=sys.stderr,
                flush=True,
            )
        return None
    decoded_fingerprint = f"{decoded.op}({lhs},{rhs})"
    if direct_cmp_fingerprint is not None and direct_cmp_fingerprint != decoded_fingerprint:
        if codegen is not None:
            codegen._inertia_tail_validation_direct_cmp_jcc_overrides_8616 = (
                int(getattr(codegen, "_inertia_tail_validation_direct_cmp_jcc_overrides_8616", 0) or 0) + 1
            )
        if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            import sys

            print(
                f"[tv-condition-context] direct-cmp override block={block_addr:#x} ins={ins_addr:#x} "
                f"decoded={decoded_fingerprint} direct={direct_cmp_fingerprint}",
                file=sys.stderr,
                flush=True,
            )
        return direct_cmp_fingerprint
    if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
        import sys

        print(
            f"[tv-condition-context] decoded block={block_addr:#x} ins={ins_addr:#x} "
            f"op={decoded.op} lhs={lhs} rhs={rhs} "
            f"rhs_node={type(decoded.rhs).__module__}.{type(decoded.rhs).__name__}:"
            f"{getattr(decoded.rhs, 'op', None)!r} "
            f"expr={type(decoded.expr).__name__ if decoded.expr is not None else 'None'}",
            file=sys.stderr,
            flush=True,
        )
    if lhs == rhs:
        return None
    return decoded_fingerprint


def _fingerprint_contains_raw_register_8616(fingerprint: object) -> bool:
    if not isinstance(fingerprint, str):
        return False
    return "reg:" in fingerprint


def _direct_cmp_immediate_jcc_fingerprint(cond, project, codegen, block_addr: int, ins_addr: int) -> str | None:
    """Return instruction-backed cmp-immediate condition evidence for validation.

    This is deliberately narrow: it only handles a direct ``cmp`` whose operand
    is an immediate.  Those branches do not require replayed register state, so
    the validation context should prefer the instruction operand over any stale
    decoded-condition cache.
    """
    _ = cond
    debug = os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}

    def _debug_refuse(reason: str) -> None:
        if not debug:
            return
        import sys

        print(
            f"[tv-condition-context] direct-cmp refuse block={block_addr:#x} ins={ins_addr:#x} reason={reason}",
            file=sys.stderr,
            flush=True,
        )

    if codegen is None:
        _debug_refuse("missing_codegen")
        return None
    insns, jcc_index = _decode_block_and_jcc_index_8616(project, int(block_addr), int(ins_addr), False)
    if insns is None or jcc_index is None:
        _debug_refuse("missing_jcc")
        return None
    jcc_insn = insns[jcc_index]
    op = _JCC_COMPARE_OPS_8616.get(str(getattr(jcc_insn, "mnemonic", "") or "").lower())
    if op is None:
        _debug_refuse("unsupported_jcc")
        return None
    cmp_insn = _nearest_flag_producer_before_jcc_8616(insns, jcc_index)
    if cmp_insn is None or str(getattr(cmp_insn, "mnemonic", "") or "").lower() != "cmp":
        _debug_refuse("not_cmp")
        return None
    operands = tuple(getattr(cmp_insn, "operands", ()) or ())
    if len(operands) != 2:
        _debug_refuse("bad_operand_count")
        return None
    immediate_operands = tuple(
        operand
        for operand in operands
        if int(getattr(operand, "type", -1)) == 2 and isinstance(getattr(operand, "imm", None), int)
    )
    if len(immediate_operands) != 1:
        _debug_refuse(
            "no_immediate:"
            + ",".join(
                f"type={getattr(operand, 'type', None)} imm={getattr(operand, 'imm', None)!r}" for operand in operands
            )
        )
        return None
    if any(int(getattr(operand, "type", -1)) == 1 for operand in operands):
        _debug_refuse("register_operand")
        return None
    ds_offset = _reg_offset_8616(project, "ds")
    ds_var = (
        CVariable(SimRegisterVariable(ds_offset, 2, name="ds"), codegen=codegen) if isinstance(ds_offset, int) else None
    )
    lhs = (
        _const_8616(int(getattr(operands[0], "imm", 0) or 0), codegen)
        if int(getattr(operands[0], "type", -1)) == 2
        else _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            operands[0],
            {},
            ds_var,
            cmp_insn.reg_name,
            {},
            int(getattr(cmp_insn, "address", 0) or 0),
        )
    )
    rhs = (
        _const_8616(int(getattr(operands[1], "imm", 0) or 0), codegen)
        if int(getattr(operands[1], "type", -1)) == 2
        else _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            operands[1],
            {},
            ds_var,
            cmp_insn.reg_name,
            {},
            int(getattr(cmp_insn, "address", 0) or 0),
        )
    )
    if lhs is None or rhs is None:
        _debug_refuse(f"unresolved_operands lhs={lhs!r} rhs={rhs!r}")
        return None
    if not any(isinstance(operand_expr, CConstant) for operand_expr in (lhs, rhs)):
        _debug_refuse("no_constant_expr")
        return None
    fingerprint = f"{op}({_expr_fingerprint(lhs, project)},{_expr_fingerprint(rhs, project)})"
    if debug:
        import sys

        print(
            f"[tv-condition-context] direct-cmp fingerprint block={block_addr:#x} ins={ins_addr:#x} value={fingerprint}",
            file=sys.stderr,
            flush=True,
        )
    return fingerprint


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
