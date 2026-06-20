from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Conservative dead-code elimination.
Only removes plain local/temp assignments proven unread by backward liveness.
Unknown cases are refused and preserved.

Forbidden: semantic recovery, alias decisions beyond liveness, type inference.
"""

import contextlib
import os
import sys
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFakeVariable,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CStructField,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616

__all__ = ["_dead_code_elimination_8616"]


class DceValuePurity8616(Enum):
    LOCAL_VALUE = "local_value"
    GLOBAL_MEMORY_READ = "global_memory_read"
    UNKNOWN = "unknown"


def _dead_code_elimination_8616(codegen) -> bool:
    """Eliminate only definitely-dead assignments within each statement block."""
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None)
    if root is None:
        root = cfunc
    if os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}:
        root_statements = getattr(root, "statements", None)
        cfunc_statements = getattr(cfunc, "statements", None)
        print(
            "[optimization] dce_root "
            f"cfunc={type(cfunc).__name__} "
            f"cfunc_statements={type(cfunc_statements).__name__ if cfunc_statements is not None else 'None'} "
            f"root={type(root).__name__} "
            f"root_len={len(root_statements) if isinstance(root_statements, list) else 'n/a'}",
            file=sys.stderr,
            flush=True,
        )

    for counter in (
        "dce_candidates",
        "dce_deleted",
        "dce_keep_live_use",
        "dce_keep_side_effect",
        "dce_keep_protected",
        "dce_keep_observable",
        "dce_keep_unknown",
        "dce_duplicate_assignment_candidates",
        "dce_duplicate_assignment_deleted",
        "dce_duplicate_assignment_refused",
        "dce_pure_expression_candidates",
        "dce_pure_expression_deleted",
        "dce_pure_expression_refused",
        "dce_dirty_value_candidates",
        "dce_dirty_value_deleted",
        "dce_dirty_value_refused",
        "dce_dead_memory_read_candidates",
        "dce_dead_memory_read_deleted",
        "dce_dead_memory_read_refused",
        "dce_arg_overwrite_artifact_candidates",
        "dce_arg_overwrite_artifact_deleted",
        "dce_arg_overwrite_artifact_refused",
    ):
        if not isinstance(getattr(codegen, counter, None), int):
            setattr(codegen, counter, 0)

    changed = False

    def _safe_attr(node: object, attr: str, default=None):
        try:
            return getattr(node, attr, default)
        except (TypeError, ValueError):
            return default

    def _var_key(node: CVariable) -> tuple[str, int | str]:
        var = getattr(node, "variable", None)
        if var is None:
            return ("node", id(node))
        if isinstance(var, SimStackVariable) and getattr(var, "base", None) == "bp":
            offset = getattr(var, "offset", None)
            if isinstance(offset, int):
                return ("stack", int(offset))
        name = getattr(var, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        node_name = getattr(node, "name", None)
        if isinstance(node_name, str) and node_name:
            return ("name", node_name)
        ident = getattr(var, "ident", None)
        if isinstance(ident, str) and ident:
            return ("ident", ident)
        return ("var", id(var))

    def _dirty_key(node: object) -> tuple[str, int | str] | None:
        if type(node).__name__ != "CDirtyExpression":
            return None
        dirty = _safe_attr(node, "dirty", None)
        dirty_text = ""
        with contextlib.suppress(Exception):
            dirty_text = str(dirty)
        if dirty_text and " object at " not in dirty_text and not dirty_text.startswith("namespace("):
            return ("dirty_text", dirty_text)
        dirty_name = _safe_attr(dirty, "name", None)
        if isinstance(dirty_name, str) and dirty_name:
            return ("dirty_name", dirty_name)
        dirty_varid = _safe_attr(dirty, "varid", None)
        if isinstance(dirty_varid, (int, str)):
            return ("dirty_varid", dirty_varid)
        dirty_idx = _safe_attr(dirty, "idx", None)
        if isinstance(dirty_idx, (int, str)):
            return ("dirty", dirty_idx)
        dirty_oident = _safe_attr(dirty, "oident", None)
        if isinstance(dirty_oident, (int, str)):
            return ("dirty_oident", dirty_oident)
        expr_idx = _safe_attr(node, "idx", None)
        if isinstance(expr_idx, (int, str)):
            return ("dirty_expr", expr_idx)
        return None

    def _dirty_has_storage_provenance_8616(node: object) -> bool:
        if type(node).__name__ != "CDirtyExpression":
            return False
        dirty = _safe_attr(node, "dirty", None)
        for attr in (
            "reg",
            "reg_offset",
            "stack_offset",
            "parameter_reg_offset",
            "parameter_stack_offset",
        ):
            value = _safe_attr(dirty, attr, None)
            if isinstance(value, int):
                return True
        return False

    def _dirty_is_storage_free_temp_8616(node: object) -> bool:
        return (
            type(node).__name__ == "CDirtyExpression"
            and bool(getattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616", False))
            and not _dirty_has_storage_provenance_8616(node)
        )

    def _node_key(node: object) -> tuple[str, int | str] | None:
        if isinstance(node, CVariable):
            return _var_key(node)
        return _dirty_key(node)

    def _iter_with_root(node: object):
        if node is not None:
            yield node
        yield from _iter_c_nodes_deep_8616(node)

    def _lhs_variable_8616(lhs: object) -> CVariable | None:
        if isinstance(lhs, CVariable):
            return lhs
        for child in _iter_c_nodes_deep_8616(lhs):
            if isinstance(child, CVariable):
                return child
        variable = getattr(lhs, "variable", None)
        if variable is not None:
            try:
                return CVariable(None, variable, None)
            except Exception:
                return None
        return None

    def _var_name(node: CVariable) -> str:
        var = getattr(node, "variable", None)
        name = getattr(var, "name", None)
        if isinstance(name, str) and name:
            return name
        node_name = getattr(node, "name", None)
        return node_name if isinstance(node_name, str) else ""

    def _is_observable_lvalue(lhs: object) -> bool:
        if isinstance(lhs, (CUnaryOp, CStructField, CBinaryOp, CIndexedVariable)):
            return True
        if isinstance(lhs, CFunctionCall):
            return True
        if isinstance(lhs, CVariable):
            var = getattr(lhs, "variable", None)
            if isinstance(var, (SimStackVariable, SimRegisterVariable)):
                return False
            if isinstance(var, SimMemoryVariable):
                return True
            region = getattr(var, "region", None)
            if isinstance(region, str) and region.lower() in {"global", "argument", "arg"}:
                return True
        return False

    def _rhs_has_side_effects(rhs: object) -> bool:
        if rhs is None:
            return False
        for node in _iter_c_nodes_deep_8616(rhs):
            if isinstance(node, CFunctionCall) and not _is_pure_generated_helper_call_8616(node):
                return True
        return False

    def _call_name_8616(call: CFunctionCall) -> str | None:
        target = getattr(call, "callee_target", None)
        if isinstance(target, str) and target:
            return target
        target_name = getattr(target, "name", None)
        if isinstance(target_name, str) and target_name:
            return target_name
        callee = getattr(call, "callee", None)
        if isinstance(callee, str) and callee:
            return callee
        callee = getattr(call, "callee_func", None)
        if isinstance(callee, str) and callee:
            return callee
        name = getattr(callee, "name", None)
        return name if isinstance(name, str) and name else None

    def _is_pure_address_helper_call_8616(call: CFunctionCall) -> bool:
        return _call_name_8616(call) in {"MK_FP", "SEG_PTR"}

    def _is_pure_memory_read_helper_call_8616(call: CFunctionCall) -> bool:
        return _call_name_8616(call) in {"MEM_U8", "MEM_U16", "MEM_U32", "SEG_U8", "SEG_U16", "SEG_U32"}

    def _is_pure_generated_helper_call_8616(call: CFunctionCall) -> bool:
        return _is_pure_address_helper_call_8616(call) or _is_pure_memory_read_helper_call_8616(call)

    def _standalone_expression_is_definitely_dead_8616(stmt: object) -> bool:
        if not isinstance(stmt, CUnaryOp) or getattr(stmt, "op", None) != "Dereference":
            return False

        saw_pure_address_helper = False
        for node in _iter_with_root(stmt):
            if isinstance(node, CAssignment):
                return False
            if isinstance(node, CFunctionCall):
                if not _is_pure_address_helper_call_8616(node):
                    return False
                saw_pure_address_helper = True
                continue
            if isinstance(node, CUnaryOp):
                op = getattr(node, "op", None)
                if node is stmt and op == "Dereference":
                    continue
                if op in {"Reference", "AddressOf", "Neg", "Not", "BitNot"}:
                    continue
                return False
            if isinstance(node, CBinaryOp) and getattr(node, "op", None) not in {
                "Add",
                "Sub",
                "Mul",
                "Shl",
                "Shr",
                "And",
                "Or",
                "Xor",
            }:
                return False
        return saw_pure_address_helper

    def _standalone_expression_payload_8616(stmt: object) -> object:
        if isinstance(stmt, CExpressionStatement):
            return getattr(stmt, "expr", None)
        return stmt

    def _expr_is_discardable_dead_value_8616(expr: object) -> bool:
        """True when evaluating expr has no observable effect if its value is unused."""
        if expr is None:
            return False
        saw_discardable_artifact = False
        for node in _iter_with_root(expr):
            if isinstance(node, CAssignment):
                return False
            if isinstance(node, CFunctionCall):
                if not _is_pure_generated_helper_call_8616(node):
                    return False
                saw_discardable_artifact = True
                continue
            if isinstance(node, CStructField):
                return False
            if isinstance(node, CFakeVariable):
                return False
            if type(node).__name__ == "CDirtyExpression":
                if not (
                    _dirty_is_storage_free_temp_8616(node)
                    or bool(getattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616", False))
                ):
                    return False
                saw_discardable_artifact = True
                continue
            if isinstance(node, CTypeCast):
                continue
            if isinstance(node, CUnaryOp):
                if getattr(node, "op", None) in {
                    "Dereference",
                    "Reference",
                    "AddressOf",
                    "Neg",
                    "Not",
                    "BitNot",
                }:
                    if getattr(node, "op", None) == "Dereference":
                        saw_discardable_artifact = True
                    continue
                return False
            if isinstance(node, CBinaryOp) and getattr(node, "op", None) not in {
                "Add",
                "Sub",
                "Mul",
                "Shl",
                "Shr",
                "And",
                "Or",
                "Xor",
            }:
                return False
        return saw_discardable_artifact

    def _is_plain_local_lvalue_8616(lhs: object) -> bool:
        if not isinstance(lhs, CVariable):
            return False
        var = getattr(lhs, "variable", None)
        if isinstance(var, SimStackVariable):
            return True
        if isinstance(var, SimRegisterVariable):
            return True
        return False

    def _expr_is_pure_local_value_8616(expr: object) -> bool:
        if expr is None or _rhs_has_side_effects(expr):
            return False
        for node in _iter_with_root(expr):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CStructField):
                return False
            if isinstance(node, CFakeVariable):
                return False
            if type(node).__name__ == "CDirtyExpression":
                if not (
                    _dirty_is_storage_free_temp_8616(node)
                    or bool(getattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616", False))
                ):
                    return False
                continue
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) in {
                "Dereference",
                "Reference",
                "AddressOf",
            }:
                return False
            if isinstance(node, CVariable):
                var = getattr(node, "variable", None)
                if isinstance(var, (SimStackVariable, SimRegisterVariable)):
                    continue
                if isinstance(var, SimMemoryVariable):
                    return False
        return True

    def _merge_value_purity_8616(*items: DceValuePurity8616) -> DceValuePurity8616:
        if any(item is DceValuePurity8616.UNKNOWN for item in items):
            return DceValuePurity8616.UNKNOWN
        if any(item is DceValuePurity8616.GLOBAL_MEMORY_READ for item in items):
            return DceValuePurity8616.GLOBAL_MEMORY_READ
        return DceValuePurity8616.LOCAL_VALUE

    def _is_direct_memory_variable_8616(node: object) -> bool:
        if not isinstance(node, CVariable):
            return False
        return isinstance(getattr(node, "variable", None), SimMemoryVariable)

    def _is_global_indexed_read_8616(node: object) -> bool:
        if not isinstance(node, CIndexedVariable):
            return False
        base = getattr(node, "variable", None)
        if not _is_direct_memory_variable_8616(base):
            return False
        index = getattr(node, "index", None)
        return _expr_value_purity_8616(index) is DceValuePurity8616.LOCAL_VALUE

    def _address_expr_is_pure_global_read_address_8616(expr: object) -> bool:
        if expr is None:
            return False
        if isinstance(expr, CTypeCast):
            return _address_expr_is_pure_global_read_address_8616(getattr(expr, "expr", None))
        if isinstance(expr, CConstant):
            return True
        if isinstance(expr, CVariable):
            var = getattr(expr, "variable", None)
            return isinstance(var, (SimStackVariable, SimRegisterVariable))
        if isinstance(expr, CIndexedVariable):
            return _is_global_indexed_read_8616(expr)
        if isinstance(expr, CFunctionCall):
            return _is_pure_address_helper_call_8616(expr)
        if isinstance(expr, CUnaryOp):
            op = getattr(expr, "op", None)
            operand = getattr(expr, "operand", None)
            if op in {"Reference", "AddressOf"}:
                return _is_direct_memory_variable_8616(operand) or _is_global_indexed_read_8616(operand)
            if op in {"Neg", "Not", "BitNot"}:
                return _address_expr_is_pure_global_read_address_8616(operand)
            return False
        if isinstance(expr, CBinaryOp) and getattr(expr, "op", None) in {
            "Add",
            "Sub",
            "Mul",
            "Shl",
            "Shr",
            "And",
            "Or",
            "Xor",
        }:
            return _address_expr_is_pure_global_read_address_8616(
                getattr(expr, "lhs", None)
            ) and _address_expr_is_pure_global_read_address_8616(getattr(expr, "rhs", None))
        return False

    def _address_expr_has_global_read_anchor_8616(expr: object) -> bool:
        if expr is None:
            return False
        if isinstance(expr, CTypeCast):
            return _address_expr_has_global_read_anchor_8616(getattr(expr, "expr", None))
        if isinstance(expr, CIndexedVariable):
            return _is_global_indexed_read_8616(expr)
        if isinstance(expr, CFunctionCall):
            return _is_pure_address_helper_call_8616(expr)
        if isinstance(expr, CUnaryOp):
            op = getattr(expr, "op", None)
            operand = getattr(expr, "operand", None)
            if op in {"Reference", "AddressOf"}:
                return _is_direct_memory_variable_8616(operand) or _is_global_indexed_read_8616(operand)
            if op in {"Neg", "Not", "BitNot"}:
                return _address_expr_has_global_read_anchor_8616(operand)
            return False
        if isinstance(expr, CBinaryOp):
            return _address_expr_has_global_read_anchor_8616(
                getattr(expr, "lhs", None)
            ) or _address_expr_has_global_read_anchor_8616(getattr(expr, "rhs", None))
        return False

    def _expr_value_purity_8616(expr: object) -> DceValuePurity8616:
        if expr is None or _rhs_has_side_effects(expr):
            return DceValuePurity8616.UNKNOWN
        if isinstance(expr, CConstant):
            return DceValuePurity8616.LOCAL_VALUE
        if isinstance(expr, CTypeCast):
            return _expr_value_purity_8616(getattr(expr, "expr", None))
        if isinstance(expr, CVariable):
            var = getattr(expr, "variable", None)
            if isinstance(var, (SimStackVariable, SimRegisterVariable)):
                return DceValuePurity8616.LOCAL_VALUE
            if isinstance(var, SimMemoryVariable):
                return DceValuePurity8616.GLOBAL_MEMORY_READ
            return DceValuePurity8616.UNKNOWN
        if isinstance(expr, CIndexedVariable):
            return (
                DceValuePurity8616.GLOBAL_MEMORY_READ
                if _is_global_indexed_read_8616(expr)
                else DceValuePurity8616.UNKNOWN
            )
        if isinstance(expr, CFunctionCall):
            if _is_pure_address_helper_call_8616(expr):
                return DceValuePurity8616.LOCAL_VALUE
            if _is_pure_memory_read_helper_call_8616(expr):
                return DceValuePurity8616.GLOBAL_MEMORY_READ
            return DceValuePurity8616.UNKNOWN
        if isinstance(expr, CUnaryOp):
            op = getattr(expr, "op", None)
            operand = getattr(expr, "operand", None)
            if op == "Dereference":
                return (
                    DceValuePurity8616.GLOBAL_MEMORY_READ
                    if _address_expr_is_pure_global_read_address_8616(operand)
                    and _address_expr_has_global_read_anchor_8616(operand)
                    else DceValuePurity8616.UNKNOWN
                )
            if op in {"Reference", "AddressOf"}:
                return (
                    DceValuePurity8616.LOCAL_VALUE
                    if _address_expr_is_pure_global_read_address_8616(expr)
                    else DceValuePurity8616.UNKNOWN
                )
            if op in {"Neg", "Not", "BitNot"}:
                return _expr_value_purity_8616(operand)
            return DceValuePurity8616.UNKNOWN
        if isinstance(expr, CBinaryOp) and getattr(expr, "op", None) in {
            "Add",
            "Sub",
            "Mul",
            "Shl",
            "Shr",
            "And",
            "Or",
            "Xor",
        }:
            return _merge_value_purity_8616(
                _expr_value_purity_8616(getattr(expr, "lhs", None)),
                _expr_value_purity_8616(getattr(expr, "rhs", None)),
            )
        return DceValuePurity8616.UNKNOWN

    def _expr_is_discardable_value_8616(expr: object) -> bool:
        return _expr_value_purity_8616(expr) in {
            DceValuePurity8616.LOCAL_VALUE,
            DceValuePurity8616.GLOBAL_MEMORY_READ,
        }

    def _expr_contains_memory_read_shape_8616(expr: object) -> bool:
        for node in _iter_with_root(expr):
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return True
            if isinstance(node, CIndexedVariable):
                return True
            if isinstance(node, CFunctionCall) and _is_pure_memory_read_helper_call_8616(node):
                return True
            if _is_direct_memory_variable_8616(node):
                return True
        return False

    def _dirty_lhs_delete_proven_8616(lhs: object, rhs: object) -> bool:
        if _dirty_is_storage_free_temp_8616(lhs):
            return (
                _expr_is_discardable_dead_value_8616(rhs)
                or _rhs_is_pure_stack_base_carrier_8616(rhs)
                or _expr_is_pure_local_value_8616(rhs)
            )
        return (
            _dirty_has_storage_provenance_8616(lhs)
            and _expr_is_discardable_dead_value_8616(rhs)
            and _expr_contains_memory_read_shape_8616(rhs)
        )

    def _transparent_empty_8616(stmt: object) -> bool:
        if not isinstance(stmt, CStatements):
            return False
        return all(_transparent_empty_8616(child) for child in list(getattr(stmt, "statements", ()) or ()))

    def _transparent_single_assignment_8616(stmt: object) -> CAssignment | None:
        if isinstance(stmt, CAssignment):
            return stmt
        if not isinstance(stmt, CStatements):
            return None
        nested = list(getattr(stmt, "statements", ()) or ())
        if len(nested) != 1:
            return None
        return _transparent_single_assignment_8616(nested[0])

    def _transparent_first_assignment_8616(stmt: object) -> CAssignment | None:
        if isinstance(stmt, CAssignment):
            return stmt
        if not isinstance(stmt, CStatements):
            return None
        for child in list(getattr(stmt, "statements", ()) or ()):
            if _transparent_empty_8616(child):
                continue
            return _transparent_first_assignment_8616(child)
        return None

    def _transparent_last_assignment_8616(stmt: object) -> CAssignment | None:
        if isinstance(stmt, CAssignment):
            return stmt
        if not isinstance(stmt, CStatements):
            return None
        for child in reversed(list(getattr(stmt, "statements", ()) or ())):
            if _transparent_empty_8616(child):
                continue
            return _transparent_last_assignment_8616(child)
        return None

    def _duplicate_assignment_pair_is_definitely_dead_8616(
        first_assignment: object,
        second_assignment: object,
    ) -> bool:
        if not isinstance(first_assignment, CAssignment) or not isinstance(second_assignment, CAssignment):
            return False
        if not _same_c_expression_8616(getattr(first_assignment, "lhs", None), getattr(second_assignment, "lhs", None)):
            return False
        if not _same_c_expression_8616(getattr(first_assignment, "rhs", None), getattr(second_assignment, "rhs", None)):
            return False
        lhs = getattr(second_assignment, "lhs", None)
        rhs = getattr(second_assignment, "rhs", None)
        return _is_plain_local_lvalue_8616(lhs) and _expr_is_pure_local_value_8616(rhs)

    def _adjacent_duplicate_assignment_is_definitely_dead_8616(first: object, second: object) -> bool:
        first_assignment = _transparent_last_assignment_8616(first)
        second_assignment = _transparent_first_assignment_8616(second)
        return _duplicate_assignment_pair_is_definitely_dead_8616(first_assignment, second_assignment)

    def _remove_first_transparent_assignment_8616(
        stmt: object,
        assignment: CAssignment,
    ) -> tuple[object | None, bool]:
        if isinstance(stmt, CAssignment):
            if stmt is assignment:
                return None, True
            return stmt, False
        if not isinstance(stmt, CStatements):
            return stmt, False

        nested = list(getattr(stmt, "statements", ()) or ())
        for index, child in enumerate(nested):
            if _transparent_empty_8616(child):
                continue
            first_assignment = _transparent_first_assignment_8616(child)
            if first_assignment is None:
                return stmt, False
            new_child, removed = _remove_first_transparent_assignment_8616(child, assignment)
            if not removed:
                return stmt, False
            if new_child is None or _transparent_empty_8616(new_child):
                del nested[index]
            else:
                nested[index] = new_child
            stmt.statements = nested
            if not nested:
                return None, True
            return stmt, True
        return stmt, False

    def _prune_adjacent_duplicate_assignments_8616(statements) -> bool:
        nonlocal changed
        stmts = list(getattr(statements, "statements", ()) or ())
        if len(stmts) < 2:
            return False
        new_stmts: list[object] = []
        block_changed = False
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            next_stmt = stmts[i + 1] if i + 1 < len(stmts) else None
            stmt_assignment = _transparent_last_assignment_8616(stmt)
            next_assignment = _transparent_first_assignment_8616(next_stmt)
            if isinstance(stmt_assignment, CAssignment) and isinstance(next_assignment, CAssignment):
                same_assignment = _same_c_expression_8616(
                    getattr(stmt_assignment, "lhs", None),
                    getattr(next_assignment, "lhs", None),
                ) and _same_c_expression_8616(
                    getattr(stmt_assignment, "rhs", None),
                    getattr(next_assignment, "rhs", None),
                )
                if same_assignment:
                    setattr(
                        codegen,
                        "dce_duplicate_assignment_candidates",
                        int(getattr(codegen, "dce_duplicate_assignment_candidates", 0)) + 1,
                    )
                    if _adjacent_duplicate_assignment_is_definitely_dead_8616(stmt, next_stmt):
                        pruned_next_stmt, removed = _remove_first_transparent_assignment_8616(
                            next_stmt,
                            next_assignment,
                        )
                        if not removed:
                            setattr(
                                codegen,
                                "dce_duplicate_assignment_refused",
                                int(getattr(codegen, "dce_duplicate_assignment_refused", 0)) + 1,
                            )
                            new_stmts.append(stmt)
                            i += 1
                            continue
                        setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                        setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                        setattr(
                            codegen,
                            "dce_duplicate_assignment_deleted",
                            int(getattr(codegen, "dce_duplicate_assignment_deleted", 0)) + 1,
                        )
                        new_stmts.append(stmt)
                        if pruned_next_stmt is not None:
                            new_stmts.append(pruned_next_stmt)
                        changed = True
                        block_changed = True
                        i += 2
                        continue
                    setattr(
                        codegen,
                        "dce_duplicate_assignment_refused",
                        int(getattr(codegen, "dce_duplicate_assignment_refused", 0)) + 1,
                    )
            new_stmts.append(stmt)
            i += 1
        if block_changed:
            statements.statements = new_stmts
        return block_changed

    def _rhs_is_pure_stack_base_carrier_8616(rhs: object) -> bool:
        if rhs is None or _rhs_has_side_effects(rhs):
            return False
        saw_stack_base = isinstance(rhs, CFakeVariable) and getattr(rhs, "name", None) == "stack_base"
        for node in _iter_with_root(rhs):
            if isinstance(node, CFakeVariable) and getattr(node, "name", None) == "stack_base":
                saw_stack_base = True
                continue
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) not in {"Reference", "AddressOf"}:
                return False
            if isinstance(node, CBinaryOp) and getattr(node, "op", None) not in {"Add", "Sub"}:
                return False
        return saw_stack_base

    def _callsite_materialization_complete_or_no_calls_8616() -> bool:
        if hasattr(codegen, "_inertia_callsite_materialization_stats"):
            try:
                from ...callsite_stack_metadata import _callsite_materialization_complete_8616

                return bool(_callsite_materialization_complete_8616(codegen))
            except Exception:
                return False
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CFunctionCall) and not _is_pure_generated_helper_call_8616(node):
                return False
        return True

    def _callsite_materialization_proven_complete_8616() -> bool:
        if not hasattr(codegen, "_inertia_callsite_materialization_stats"):
            return False
        try:
            from ...callsite_stack_metadata import _callsite_materialization_complete_8616

            return bool(_callsite_materialization_complete_8616(codegen))
        except Exception:
            return False

    def _iter_statement_blocks(root):
        seen: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            if hasattr(node, "statements"):
                yield node
                for stmt in list(getattr(node, "statements", ()) or ()):
                    stack.append(stmt)
            for attr in (
                "condition",
                "cond",
                "body",
                "else_node",
                "iftrue",
                "iffalse",
                "true_node",
                "false_node",
                "expr",
                "retval",
            ):
                child = getattr(node, attr, None)
                if child is not None:
                    stack.append(child)
            for pair in getattr(node, "condition_and_nodes", ()) or ():
                if len(pair) >= 2:
                    stack.append(pair[0])
                    stack.append(pair[1])
            cases = getattr(node, "cases", None)
            if isinstance(cases, dict):
                for body in cases.values():
                    stack.append(body)
            default = getattr(node, "default", None)
            if default is not None:
                stack.append(default)

    def _collect_stmt_reads(stmt: object) -> set[tuple[str, int | str]]:
        reads: set[tuple[str, int | str]] = set()

        def _collect_expr(expr: object) -> None:
            for node in _iter_with_root(expr):
                key = _node_key(node)
                if key is not None:
                    reads.add(key)

        if isinstance(stmt, CAssignment):
            rhs = getattr(stmt, "rhs", None)
            _collect_expr(rhs)
            lhs = getattr(stmt, "lhs", None)
            if (
                isinstance(lhs, CUnaryOp)
                and getattr(lhs, "op", None) in {"Dereference", "Reference"}
                or isinstance(lhs, (CIndexedVariable, CStructField))
            ):
                _collect_expr(lhs)
            return reads

        condition_roots = []
        for attr in ("condition", "cond", "expr", "retval"):
            child = getattr(stmt, attr, None)
            if child is not None:
                condition_roots.append(child)
        condition_and_nodes = getattr(stmt, "condition_and_nodes", None)
        if condition_and_nodes:
            for pair in condition_and_nodes:
                if len(pair) >= 1:
                    condition_roots.append(pair[0])
        if condition_roots:
            for child in condition_roots:
                _collect_expr(child)
            return reads

        # Structured containers own child statement blocks; their parent block
        # only semantically reads the container guard. Counting the whole child
        # body here creates fake "outside" uses for nested dead assignments.
        for attr in (
            "statements",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "true_node",
            "false_node",
            "cases",
            "default",
        ):
            if getattr(stmt, attr, None) is not None:
                return reads

        _collect_expr(stmt)
        return reads

    def _collect_nested_stmt_reads(stmt: object) -> set[tuple[str, int | str]]:
        reads = set(_collect_stmt_reads(stmt))
        work: list[object] = []
        seen: set[int] = set()
        for attr in (
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "true_node",
            "false_node",
            "default",
        ):
            child = getattr(stmt, attr, None)
            if child is not None:
                work.append(child)
        for pair in getattr(stmt, "condition_and_nodes", ()) or ():
            if len(pair) >= 2:
                work.append(pair[1])
        cases = getattr(stmt, "cases", None)
        if isinstance(cases, dict):
            work.extend(cases.values())

        while work:
            node = work.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            if hasattr(node, "statements"):
                for child_stmt in list(getattr(node, "statements", ()) or ()):
                    reads.update(_collect_stmt_reads(child_stmt))
                    work.append(child_stmt)
                continue
            reads.update(_collect_stmt_reads(node))
        return reads

    def _collect_read_counts_by_block(
        root,
    ) -> tuple[dict[tuple[str, int | str], int], dict[int, dict[tuple[str, int | str], int]]]:
        total_reads: dict[tuple[str, int | str], int] = {}
        block_reads: dict[int, dict[tuple[str, int | str], int]] = {}
        for block in _iter_statement_blocks(root):
            local_reads: dict[tuple[str, int | str], int] = {}
            for stmt in list(getattr(block, "statements", ()) or ()):
                for key in _collect_nested_stmt_reads(stmt):
                    total_reads[key] = total_reads.get(key, 0) + 1
                for key in _collect_stmt_reads(stmt):
                    local_reads[key] = local_reads.get(key, 0) + 1
            block_reads[id(block)] = local_reads
        return total_reads, block_reads

    def _is_temp_like_var(var_node: CVariable) -> bool:
        name = _var_name(var_node)
        if not name:
            return False
        return name.startswith("vvar_") or name.startswith("tmp_") or name.startswith("ir_")

    def _lhs_key_and_name_8616(lhs: object) -> tuple[tuple[str, int | str] | None, tuple[str, str] | None, bool]:
        dirty_key = _dirty_key(lhs)
        if dirty_key is not None:
            # Dirty expressions carry VEX/AIL virtual register and flag
            # provenance. They are not ordinary emitted C temporaries, and DCE
            # must not delete them without a stronger typed proof that later
            # materialization no longer needs the carrier.
            if _dirty_is_storage_free_temp_8616(lhs):
                return dirty_key, ("dirty", str(dirty_key[1])), True
            return dirty_key, ("dirty", str(dirty_key[1])), False
        if _is_observable_lvalue(lhs):
            return None, None, False
        lhs_var = _lhs_variable_8616(lhs)
        if lhs_var is None:
            return None, None, False
        return _var_key(lhs_var), ("name", _var_name(lhs_var)), _is_temp_like_var(lhs_var)

    def _argument_keys_8616() -> tuple[set[tuple[str, int | str]], set[tuple[str, str]]]:
        cfunc_obj = getattr(codegen, "cfunc", None)
        keys: set[tuple[str, int | str]] = set()
        name_keys: set[tuple[str, str]] = set()
        for arg in tuple(getattr(cfunc_obj, "arg_list", ()) or ()):
            if not isinstance(arg, CVariable):
                continue
            keys.add(_var_key(arg))
            name = _var_name(arg)
            if name:
                name_keys.add(("name", name))
        prototype = getattr(cfunc_obj, "functy", None) or getattr(cfunc_obj, "prototype", None)
        for name in tuple(getattr(prototype, "arg_names", ()) or ()):
            if isinstance(name, str) and name:
                name_keys.add(("name", name))
        project = getattr(codegen, "project", None)
        func_addr = getattr(cfunc_obj, "addr", None)
        metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
        metadata = (
            metadata_by_addr.get(func_addr)
            if isinstance(metadata_by_addr, dict) and isinstance(func_addr, int)
            else None
        )
        stack_aliases = getattr(metadata, "stack_aliases", None)
        if isinstance(stack_aliases, dict):
            for offset, name in stack_aliases.items():
                if isinstance(offset, int) and offset >= 4 and isinstance(name, str) and name:
                    name_keys.add(("name", name))
        return keys, name_keys

    def _stack_offset_from_plain_lvalue_8616(lhs: object) -> int | None:
        lhs_var = _lhs_variable_8616(lhs)
        if lhs_var is None:
            return None
        variable = getattr(lhs_var, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        offset = getattr(variable, "offset", None)
        return int(offset) if isinstance(offset, int) else None

    def _has_direct_stack_write_evidence_for_offset_8616(offset: int | None) -> bool:
        if not isinstance(offset, int):
            return False
        for attr, offset_key in (
            ("_inertia_direct_stack_move_evidence_8616", "dst_offset"),
            ("_inertia_direct_stack_update_evidence_8616", "offset"),
        ):
            evidence = getattr(codegen, attr, ()) or ()
            for item in evidence:
                pairs = (
                    tuple(item.items())
                    if isinstance(item, dict)
                    else tuple(item)
                    if isinstance(item, (tuple, list))
                    else ()
                )
                for pair in pairs:
                    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                        continue
                    key_item, value = pair
                    if key_item == offset_key and value == offset:
                        return True
        return False

    def _node_has_instruction_evidence_8616(node: object) -> bool:
        for item in _iter_with_root(node):
            tags = getattr(item, "tags", None)
            if isinstance(tags, dict) and isinstance(tags.get("ins_addr"), int):
                return True
        return False

    def _is_function_argument_lvalue_8616(
        lhs: object,
        key: tuple[str, int | str],
        name_key: tuple[str, str] | None,
    ) -> bool:
        argument_keys, argument_name_keys = _argument_keys_8616()
        if key in argument_keys or (name_key is not None and name_key in argument_name_keys):
            return True
        offset = _stack_offset_from_plain_lvalue_8616(lhs)
        return isinstance(offset, int) and offset >= 4

    def _collect_defined_keys_8616(root_node: object) -> set[tuple[str, int | str]]:
        defined: set[tuple[str, int | str]] = set()
        for node in _iter_with_root(root_node):
            if not isinstance(node, CAssignment):
                continue
            lhs_key, _lhs_name_key, _lhs_temp_like = _lhs_key_and_name_8616(getattr(node, "lhs", None))
            if lhs_key is not None:
                defined.add(lhs_key)
        return defined

    def _rhs_is_unproven_dirty_register_carrier_8616(
        rhs: object,
        defined_keys: set[tuple[str, int | str]],
    ) -> bool:
        while isinstance(rhs, CTypeCast):
            rhs = getattr(rhs, "expr", None)
        if type(rhs).__name__ != "CDirtyExpression":
            return False
        key = _dirty_key(rhs)
        if key is None or key in defined_keys:
            return False
        dirty = _safe_attr(rhs, "dirty", None)
        has_register_provenance = any(
            isinstance(_safe_attr(dirty, attr, None), int) for attr in ("reg", "reg_offset", "parameter_reg_offset")
        )
        has_stack_provenance = any(
            isinstance(_safe_attr(dirty, attr, None), int) for attr in ("stack_offset", "parameter_stack_offset")
        )
        return has_register_provenance and not has_stack_provenance

    def _is_dead_argument_overwrite_artifact_8616(
        stmt: object,
        lhs: object,
        rhs: object,
        key: tuple[str, int | str],
        name_key: tuple[str, str] | None,
        defined_keys: set[tuple[str, int | str]],
    ) -> bool:
        if not _is_plain_local_lvalue_8616(lhs):
            return False
        if not _is_function_argument_lvalue_8616(lhs, key, name_key):
            return False
        if _has_direct_stack_write_evidence_for_offset_8616(_stack_offset_from_plain_lvalue_8616(lhs)):
            return False
        if _rhs_has_side_effects(rhs):
            return False
        return _rhs_is_unproven_dirty_register_carrier_8616(rhs, defined_keys)

    def _protected_var_keys() -> set[tuple[str, int | str]]:
        protected: set[tuple[str, int | str]] = set()
        attrs = (
            "_inertia_callsite_arg_sources",
            "_inertia_stack_variable_bindings",
            "_inertia_stack_canonicalization_bridges",
            "_inertia_tail_validation_widened_carriers",
            "_inertia_linear_recurrence_state",
        )
        for attr in attrs:
            obj = getattr(codegen, attr, None)
            if obj is None:
                continue
            work = [obj]
            seen: set[int] = set()
            while work:
                cur = work.pop()
                cur_id = id(cur)
                if cur_id in seen:
                    continue
                seen.add(cur_id)
                if isinstance(cur, CVariable):
                    protected.add(_var_key(cur))
                    continue
                if isinstance(cur, dict):
                    work.extend(cur.values())
                    work.extend(cur.keys())
                    continue
                if isinstance(cur, (list, tuple, set, frozenset)):
                    work.extend(cur)
                    continue
                name = cur if isinstance(cur, str) else getattr(cur, "name", None)
                if isinstance(name, str) and name:
                    protected.add(("name", name))
        for attr, offset_key in (
            ("_inertia_direct_stack_move_evidence_8616", "dst_offset"),
            ("_inertia_direct_stack_update_evidence_8616", "offset"),
        ):
            evidence = getattr(codegen, attr, ()) or ()
            for item in evidence:
                pairs = ()
                if isinstance(item, dict):
                    pairs = tuple(item.items())
                elif isinstance(item, (tuple, list)):
                    pairs = tuple(item)
                for pair in pairs:
                    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                        continue
                    key, value = pair
                    if key == offset_key and isinstance(value, int):
                        protected.add(("stack", int(value)))
        return protected

    protected = _protected_var_keys()
    debug_optimization = os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}
    if debug_optimization:
        block_count = 0
        stmt_count = 0
        assign_count = 0
        class_counts: dict[str, int] = {}
        lhs_counts: dict[str, int] = {}
        lhs_samples: list[str] = []
        for dbg_block in _iter_statement_blocks(root):
            block_count += 1
            for dbg_stmt in list(getattr(dbg_block, "statements", ()) or ()):
                stmt_count += 1
                cls_name = type(dbg_stmt).__name__
                class_counts[cls_name] = class_counts.get(cls_name, 0) + 1
                if isinstance(dbg_stmt, CAssignment):
                    assign_count += 1
                    lhs = getattr(dbg_stmt, "lhs", None)
                    lhs_name = type(lhs).__name__
                    lhs_counts[lhs_name] = lhs_counts.get(lhs_name, 0) + 1
                    if len(lhs_samples) < 6:
                        name = ""
                        with contextlib.suppress(Exception):
                            if isinstance(lhs, CVariable):
                                name = _var_name(lhs)
                            else:
                                attrs = [
                                    attr
                                    for attr in (
                                        "variable",
                                        "expr",
                                        "expression",
                                        "dirty_expr",
                                        "operand",
                                        "operands",
                                        "cvariable",
                                        "variable_node",
                                    )
                                    if hasattr(lhs, attr)
                                ]
                                public = [
                                    attr
                                    for attr in dir(lhs)
                                    if not attr.startswith("_")
                                    and attr
                                    not in {
                                        "c_repr",
                                        "c_repr_chunks",
                                        "c_repr_chunks_annotated",
                                        "c_repr_chunks_with_addr",
                                    }
                                ][:16]
                                dirty = getattr(lhs, "dirty", None)
                                idx = getattr(lhs, "idx", None)
                                dirty_attrs = [
                                    attr
                                    for attr in dir(dirty)
                                    if not attr.startswith("_")
                                    and attr not in {"copy", "likes", "matches", "replace", "tag"}
                                ][:12]
                                name = (
                                    f"attrs={attrs} public={public} idx={idx!r} "
                                    f"dirty={type(dirty).__name__} dirty_public={dirty_attrs}"
                                )
                        lhs_samples.append(f"{lhs_name}:{name}")
        top_classes = ",".join(f"{name}:{count}" for name, count in sorted(class_counts.items())[:8])
        top_lhs = ",".join(f"{name}:{count}" for name, count in sorted(lhs_counts.items())[:8])
        print(
            "[optimization] dce_walk "
            f"blocks={block_count} stmts={stmt_count} assignments={assign_count} "
            f"classes={top_classes} lhs={top_lhs} samples={';'.join(lhs_samples)}",
            file=sys.stderr,
            flush=True,
        )
        if os.environ.get("INERTIA_DEBUG_OPTIMIZATION_PATHS", "").strip().lower() in {"1", "true", "yes", "on"}:

            def _expr_debug_label_8616(expr: object) -> str:
                if isinstance(expr, CVariable):
                    return _var_name(expr)
                if isinstance(expr, CBinaryOp):
                    return f"({_expr_debug_label_8616(getattr(expr, 'lhs', None))} {getattr(expr, 'op', '?')} {_expr_debug_label_8616(getattr(expr, 'rhs', None))})"
                if type(expr).__name__ == "CDirtyExpression":
                    return "dirty"
                value = getattr(expr, "value", None)
                if isinstance(value, (int, str)):
                    return str(value)
                return type(expr).__name__

            def _dump_assignment_paths_8616(node: object, path: str, seen_paths: set[int]) -> None:
                if node is None or id(node) in seen_paths:
                    return
                seen_paths.add(id(node))
                if hasattr(node, "statements"):
                    statements = list(getattr(node, "statements", ()) or ())
                    for index, stmt in enumerate(statements):
                        stmt_path = f"{path}.{index}"
                        if isinstance(stmt, CAssignment):
                            print(
                                "[optimization] dce_path "
                                f"path={stmt_path} parent_len={len(statements)} "
                                f"lhs={_expr_debug_label_8616(getattr(stmt, 'lhs', None))} "
                                f"rhs={_expr_debug_label_8616(getattr(stmt, 'rhs', None))} "
                                f"stmt_type={type(stmt).__name__}",
                                file=sys.stderr,
                                flush=True,
                            )
                        _dump_assignment_paths_8616(stmt, stmt_path, seen_paths)
                for attr in ("body", "else_node", "iftrue", "iffalse", "true_node", "false_node"):
                    child = getattr(node, attr, None)
                    if child is not None:
                        _dump_assignment_paths_8616(child, f"{path}.{attr}", seen_paths)
                for pair_index, pair in enumerate(getattr(node, "condition_and_nodes", ()) or ()):
                    if len(pair) >= 2:
                        _dump_assignment_paths_8616(pair[1], f"{path}.cond{pair_index}", seen_paths)

            _dump_assignment_paths_8616(root, "root", set())

    def walk_statements(
        statements,
        total_reads: dict[tuple[str, int | str], int],
        block_reads,
        defined_keys: set[tuple[str, int | str]],
    ):
        nonlocal changed
        duplicate_changed = _prune_adjacent_duplicate_assignments_8616(statements)
        stmts = list(getattr(statements, "statements", ()) or ())
        if not stmts:
            return duplicate_changed
        local_reads = block_reads.get(id(statements), {})
        live: set[tuple[str, int | str]] = set()
        new_rev: list[object] = []
        block_changed = duplicate_changed

        for stmt in reversed(stmts):
            if not isinstance(stmt, CAssignment):
                expr_stmt = _standalone_expression_payload_8616(stmt)
                if isinstance(expr_stmt, CUnaryOp) and getattr(expr_stmt, "op", None) == "Dereference":
                    setattr(
                        codegen,
                        "dce_pure_expression_candidates",
                        int(getattr(codegen, "dce_pure_expression_candidates", 0)) + 1,
                    )
                    if _standalone_expression_is_definitely_dead_8616(expr_stmt):
                        setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                        setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                        setattr(
                            codegen,
                            "dce_pure_expression_deleted",
                            int(getattr(codegen, "dce_pure_expression_deleted", 0)) + 1,
                        )
                        changed = True
                        block_changed = True
                        continue
                    setattr(
                        codegen,
                        "dce_pure_expression_refused",
                        int(getattr(codegen, "dce_pure_expression_refused", 0)) + 1,
                    )
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            lhs = getattr(stmt, "lhs", None)
            rhs = getattr(stmt, "rhs", None)
            key, name_key, is_temp_like = _lhs_key_and_name_8616(lhs)
            if key is None:
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            if (
                _same_c_expression_8616(lhs, rhs)
                and (_dirty_key(lhs) is None or _dirty_is_storage_free_temp_8616(lhs))
                and not _is_observable_lvalue(lhs)
                and not _rhs_has_side_effects(rhs)
            ):
                if debug_optimization:
                    print(
                        "[optimization] dce_decision "
                        f"reason=delete_self key={key!r} name_key={name_key!r} "
                        f"stmt={stmt!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                changed = True
                block_changed = True
                continue
            outside_reads = (
                0 if key[0] in {"dirty", "dirty_expr"} else int(total_reads.get(key, 0)) - int(local_reads.get(key, 0))
            )
            if _is_function_argument_lvalue_8616(lhs, key, name_key):
                setattr(
                    codegen,
                    "dce_arg_overwrite_artifact_candidates",
                    int(getattr(codegen, "dce_arg_overwrite_artifact_candidates", 0)) + 1,
                )
                if debug_optimization:
                    print(
                        "[optimization] dce_arg_overwrite_probe "
                        f"key={key!r} name_key={name_key!r} "
                        f"tagged={_node_has_instruction_evidence_8616(stmt)} "
                        f"stack_offset={_stack_offset_from_plain_lvalue_8616(lhs)!r} "
                        f"direct_stack_evidence={_has_direct_stack_write_evidence_for_offset_8616(_stack_offset_from_plain_lvalue_8616(lhs))} "
                        f"rhs_dirty={_rhs_is_unproven_dirty_register_carrier_8616(rhs, defined_keys)}",
                        file=sys.stderr,
                        flush=True,
                    )
                if _is_dead_argument_overwrite_artifact_8616(stmt, lhs, rhs, key, name_key, defined_keys):
                    if debug_optimization:
                        print(
                            "[optimization] dce_decision "
                            f"reason=delete_arg_overwrite key={key!r} name_key={name_key!r} "
                            f"stmt={stmt!r}",
                            file=sys.stderr,
                            flush=True,
                        )
                    setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                    setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                    setattr(
                        codegen,
                        "dce_arg_overwrite_artifact_deleted",
                        int(getattr(codegen, "dce_arg_overwrite_artifact_deleted", 0)) + 1,
                    )
                    changed = True
                    block_changed = True
                    continue
                setattr(
                    codegen,
                    "dce_arg_overwrite_artifact_refused",
                    int(getattr(codegen, "dce_arg_overwrite_artifact_refused", 0)) + 1,
                )
            if key[0].startswith("dirty"):
                setattr(
                    codegen,
                    "dce_dirty_value_candidates",
                    int(getattr(codegen, "dce_dirty_value_candidates", 0)) + 1,
                )
                if (
                    key not in live
                    and outside_reads <= 0
                    and key not in protected
                    and (name_key is None or name_key not in protected)
                    and _dirty_lhs_delete_proven_8616(lhs, rhs)
                ):
                    if debug_optimization:
                        print(
                            "[optimization] dce_decision "
                            f"reason=delete_dirty key={key!r} name_key={name_key!r} "
                            f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                            file=sys.stderr,
                            flush=True,
                        )
                    setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                    setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                    setattr(
                        codegen,
                        "dce_dirty_value_deleted",
                        int(getattr(codegen, "dce_dirty_value_deleted", 0)) + 1,
                    )
                    changed = True
                    block_changed = True
                    continue
                setattr(
                    codegen,
                    "dce_dirty_value_refused",
                    int(getattr(codegen, "dce_dirty_value_refused", 0)) + 1,
                )
            if not is_temp_like:
                if key in protected or (name_key is not None and name_key in protected):
                    setattr(codegen, "dce_keep_protected", int(getattr(codegen, "dce_keep_protected", 0)) + 1)
                    live.discard(key)
                    live.update(_collect_stmt_reads(stmt))
                    new_rev.append(stmt)
                    continue
                if (
                    _is_plain_local_lvalue_8616(lhs)
                    and _expr_is_discardable_value_8616(rhs)
                    and key not in live
                    and outside_reads <= 0
                    and key not in protected
                    and (name_key is None or name_key not in protected)
                    and _callsite_materialization_complete_or_no_calls_8616()
                ):
                    if debug_optimization:
                        print(
                            "[optimization] dce_decision "
                            f"reason=delete_non_temp_discardable key={key!r} name_key={name_key!r} "
                            f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                            file=sys.stderr,
                            flush=True,
                        )
                    setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                    setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                    if _expr_value_purity_8616(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
                        setattr(
                            codegen,
                            "dce_dead_memory_read_candidates",
                            int(getattr(codegen, "dce_dead_memory_read_candidates", 0)) + 1,
                        )
                        setattr(
                            codegen,
                            "dce_dead_memory_read_deleted",
                            int(getattr(codegen, "dce_dead_memory_read_deleted", 0)) + 1,
                        )
                    changed = True
                    block_changed = True
                    continue
                if (
                    _is_plain_local_lvalue_8616(lhs)
                    and _expr_is_pure_local_value_8616(rhs)
                    and key not in live
                    and outside_reads <= 0
                    and key not in protected
                    and (name_key is None or name_key not in protected)
                    and (_same_c_expression_8616(lhs, rhs) or _callsite_materialization_proven_complete_8616())
                ):
                    if debug_optimization:
                        print(
                            "[optimization] dce_decision "
                            f"reason=delete_non_temp_pure key={key!r} name_key={name_key!r} "
                            f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                            file=sys.stderr,
                            flush=True,
                        )
                    setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                    setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                    changed = True
                    block_changed = True
                    continue
                if (
                    key[0] in {"dirty", "dirty_expr"}
                    and _rhs_is_pure_stack_base_carrier_8616(rhs)
                    and key not in live
                    and outside_reads <= 0
                    and key not in protected
                    and (name_key is None or name_key not in protected)
                    and _callsite_materialization_complete_or_no_calls_8616()
                ):
                    if debug_optimization:
                        print(
                            "[optimization] dce_decision "
                            f"reason=delete_stack_base key={key!r} name_key={name_key!r} "
                            f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                            file=sys.stderr,
                            flush=True,
                        )
                    setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
                    setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                    changed = True
                    block_changed = True
                    continue
                setattr(codegen, "dce_keep_unknown", int(getattr(codegen, "dce_keep_unknown", 0)) + 1)
                live.discard(key)
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
            removable = False
            lhs_var_for_observable = _lhs_variable_8616(lhs)
            if _is_observable_lvalue(lhs) or (
                lhs_var_for_observable is not None and _is_observable_lvalue(lhs_var_for_observable)
            ):
                setattr(codegen, "dce_keep_observable", int(getattr(codegen, "dce_keep_observable", 0)) + 1)
            elif _rhs_has_side_effects(rhs):
                setattr(codegen, "dce_keep_side_effect", int(getattr(codegen, "dce_keep_side_effect", 0)) + 1)
            elif key in protected or (name_key is not None and name_key in protected):
                setattr(codegen, "dce_keep_protected", int(getattr(codegen, "dce_keep_protected", 0)) + 1)
            elif key in live or outside_reads > 0:
                setattr(codegen, "dce_keep_live_use", int(getattr(codegen, "dce_keep_live_use", 0)) + 1)
                if debug_optimization and key[0] in {"dirty", "dirty_expr"}:
                    print(
                        "[optimization] dce_keep_live "
                        f"key={key!r} live={key in live} outside_reads={outside_reads} stmt={stmt!r}",
                        file=sys.stderr,
                        flush=True,
                    )
            elif not _expr_is_discardable_value_8616(rhs):
                if _expr_contains_memory_read_shape_8616(rhs):
                    setattr(
                        codegen,
                        "dce_dead_memory_read_refused",
                        int(getattr(codegen, "dce_dead_memory_read_refused", 0)) + 1,
                    )
                setattr(codegen, "dce_keep_unknown", int(getattr(codegen, "dce_keep_unknown", 0)) + 1)
            else:
                if _expr_value_purity_8616(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
                    setattr(
                        codegen,
                        "dce_dead_memory_read_candidates",
                        int(getattr(codegen, "dce_dead_memory_read_candidates", 0)) + 1,
                    )
                    setattr(
                        codegen,
                        "dce_dead_memory_read_deleted",
                        int(getattr(codegen, "dce_dead_memory_read_deleted", 0)) + 1,
                    )
                removable = True
            if debug_optimization:
                reason = (
                    "delete"
                    if removable
                    else "keep_observable"
                    if _is_observable_lvalue(lhs)
                    or (lhs_var_for_observable is not None and _is_observable_lvalue(lhs_var_for_observable))
                    else "keep_side_effect"
                    if _rhs_has_side_effects(rhs)
                    else "keep_protected"
                    if key in protected or (name_key is not None and name_key in protected)
                    else "keep_live_use"
                    if key in live or outside_reads > 0
                    else "keep_unknown"
                )
                print(
                    "[optimization] dce_decision "
                    f"reason={reason} key={key!r} name_key={name_key!r} "
                    f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            if removable:
                setattr(codegen, "dce_deleted", int(getattr(codegen, "dce_deleted", 0)) + 1)
                changed = True
                block_changed = True
                continue
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
        new_stmts = list(reversed(new_rev))
        if new_stmts != stmts:
            statements.statements = new_stmts
            block_changed = True
        return block_changed

    # Iterate to a fixed point: once the tail of a pure flag/setup chain is
    # deleted, earlier assignments in the same chain become provably unused.
    for _ in range(128):
        total_reads, block_reads = _collect_read_counts_by_block(root)
        defined_keys = _collect_defined_keys_8616(root)
        pass_changed = False
        for block in _iter_statement_blocks(root):
            pass_changed = walk_statements(block, total_reads, block_reads, defined_keys) or pass_changed
        if not pass_changed:
            break
    if debug_optimization:
        print(
            "[optimization] dce_counters "
            f"dce_candidates={int(getattr(codegen, 'dce_candidates', 0) or 0)} "
            f"dce_deleted={int(getattr(codegen, 'dce_deleted', 0) or 0)} "
            f"dce_keep_live_use={int(getattr(codegen, 'dce_keep_live_use', 0) or 0)} "
            f"dce_keep_side_effect={int(getattr(codegen, 'dce_keep_side_effect', 0) or 0)} "
            f"dce_keep_protected={int(getattr(codegen, 'dce_keep_protected', 0) or 0)} "
            f"dce_keep_observable={int(getattr(codegen, 'dce_keep_observable', 0) or 0)} "
            f"dce_keep_unknown={int(getattr(codegen, 'dce_keep_unknown', 0) or 0)} "
            f"dce_dirty_value_candidates={int(getattr(codegen, 'dce_dirty_value_candidates', 0) or 0)} "
            f"dce_dirty_value_deleted={int(getattr(codegen, 'dce_dirty_value_deleted', 0) or 0)} "
            f"dce_dirty_value_refused={int(getattr(codegen, 'dce_dirty_value_refused', 0) or 0)} "
            f"dce_dead_memory_read_candidates={int(getattr(codegen, 'dce_dead_memory_read_candidates', 0) or 0)} "
            f"dce_dead_memory_read_deleted={int(getattr(codegen, 'dce_dead_memory_read_deleted', 0) or 0)} "
            f"dce_dead_memory_read_refused={int(getattr(codegen, 'dce_dead_memory_read_refused', 0) or 0)} "
            f"dce_pure_expression_candidates={int(getattr(codegen, 'dce_pure_expression_candidates', 0) or 0)} "
            f"dce_pure_expression_deleted={int(getattr(codegen, 'dce_pure_expression_deleted', 0) or 0)} "
            f"dce_pure_expression_refused={int(getattr(codegen, 'dce_pure_expression_refused', 0) or 0)}",
            file=sys.stderr,
            flush=True,
        )
    return changed
