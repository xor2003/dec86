"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.postprocess.optimization.local_liveness import (
    local_liveness_key_8616,
    stack_storage_liveness_key_8616,
)

_PURE_GENERATED_HELPER_CALLEES = frozenset(
    {
        "MEM_U8",
        "MEM_U16",
        "MEM_U32",
        "SEG_U8",
        "SEG_U16",
        "SEG_U32",
        "MK_FP",
        "SEG_PTR",
    }
)


class _CFunctionLike(Protocol):
    """Structured C function surface needed by dead-local pruning."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by dead-local pruning."""

    cfunc: _CFunctionLike | None
    _inertia_dead_local_prune_protected_direct_stack_move_count_8616: int
    _inertia_dead_local_prune_walk_refused_complex_8616: int


class _AliasStorageLike(Protocol):
    """Alias-storage summary used to compare local assignment reads."""

    identity: tuple[object, ...] | None


def _call_name(node: structured_c.CFunctionCall) -> str | None:
    target = node.callee_target
    if isinstance(target, str):
        return target
    # Dynamic codegen boundary: callee targets may be function-like payloads.
    target_name = getattr(target, "name", None)
    if isinstance(target_name, str):
        return target_name
    # Dynamic codegen boundary: older structured codegen call nodes expose callee directly.
    callee = getattr(node, "callee", None)
    if isinstance(callee, str):
        return callee
    callee_func = node.callee_func
    if isinstance(callee_func, str):
        return callee_func
    # Dynamic codegen boundary: callee_func may be a function-like object.
    name = getattr(callee_func, "name", None)
    return name if isinstance(name, str) else None


def _expr_has_side_effects(node: object, *, iter_c_nodes_deep: Callable[[object], Iterable[object]]) -> bool:
    for subnode in iter_c_nodes_deep(node):
        if not isinstance(subnode, structured_c.CFunctionCall):
            continue
        if _call_name(subnode) in _PURE_GENERATED_HELPER_CALLEES:
            continue
        return True
    return False


def _prune_dead_local_assignments(
    codegen: _CodegenLike,
    *,
    structured_codegen_node: Callable[[object], bool],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    root = cfunc.statements
    if not structured_codegen_node(root):
        return False

    def collect_storage_read_keys(
        node: object,
        keys: set[tuple[object, ...]],
        seen: set[int] | None = None,
        *,
        allow_variable_read: bool = True,
    ) -> None:
        if not structured_codegen_node(node):
            return
        if seen is None:
            seen = set()
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        try:
            if isinstance(node, structured_c.CVariable):
                if allow_variable_read:
                    variable = node.variable
                    if variable is not None:
                        keys.add(("var", id(variable)))
                        unified = node.unified_variable
                        if unified is not None:
                            keys.add(("unified", id(unified)))
                        storage_key = describe_alias_storage(node).identity
                        if storage_key is not None:
                            keys.add(("storage", storage_key))
                        liveness_key = local_liveness_key_8616(node)
                        if liveness_key is not None:
                            keys.add(("liveness", liveness_key))
                return

            if isinstance(node, structured_c.CAssignment):
                if structured_codegen_node(node.lhs):
                    collect_storage_read_keys(node.lhs, keys, seen, allow_variable_read=False)
                if structured_codegen_node(node.rhs):
                    collect_storage_read_keys(node.rhs, keys, seen, allow_variable_read=True)
                return

            if node.__class__.__name__ == "CDirtyExpression":
                if allow_variable_read:
                    # Dynamic codegen boundary: dirty expressions are external codegen nodes.
                    dirty = getattr(node, "dirty", None)
                    if dirty is not None:
                        # Dynamic codegen boundary: dirty metadata fields vary by angr expression.
                        varid = getattr(dirty, "varid", None)
                        if isinstance(varid, int):
                            keys.add(("dirty_varid", varid))
                        # Dynamic codegen boundary: dirty metadata fields vary by angr expression.
                        name = getattr(dirty, "name", None)
                        if isinstance(name, str) and name:
                            keys.add(("dirty_name", name))
                return

            for attr in (
                "lhs",
                "rhs",
                "expr",
                "operand",
                "condition",
                "cond",
                "body",
                "iffalse",
                "iftrue",
                "else_node",
                "retval",
            ):
                if not hasattr(node, attr):
                    continue
                try:
                    # Dynamic codegen boundary: child field names vary across angr C AST nodes.
                    value = getattr(node, attr)
                except Exception:
                    continue
                if structured_codegen_node(value):
                    collect_storage_read_keys(value, keys, seen)

            for attr in ("args", "operands", "statements"):
                if not hasattr(node, attr):
                    continue
                try:
                    # Dynamic codegen boundary: child sequence fields vary across angr C AST nodes.
                    items = getattr(node, attr)
                except Exception:
                    continue
                if not items:
                    continue
                for item in items:
                    if structured_codegen_node(item):
                        collect_storage_read_keys(item, keys, seen)

            if hasattr(node, "condition_and_nodes"):
                try:
                    # Dynamic codegen boundary: CIfElse-like nodes may expose condition/body pairs.
                    pairs = node.condition_and_nodes
                except Exception:
                    pairs = None
                if pairs:
                    for cond, body in pairs:
                        if structured_codegen_node(cond):
                            collect_storage_read_keys(cond, keys, seen)
                        if structured_codegen_node(body):
                            collect_storage_read_keys(body, keys, seen)
        finally:
            seen.remove(node_id)

    reads: set[tuple[object, ...]] = set()
    collect_storage_read_keys(root, reads)

    def _direct_stack_move_protected_offsets() -> frozenset[int]:
        protected: set[int] = set()
        # Dynamic codegen compatibility boundary: this counter is attached by the CLI orchestration pass.
        for record in tuple(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()):
            if isinstance(record, Mapping):
                values = record
            else:
                try:
                    values = dict(record)
                except (TypeError, ValueError):
                    continue
            offset = values.get("dst_offset")
            if isinstance(offset, int):
                protected.add(offset)
        return frozenset(protected)

    protected_stack_offsets = _direct_stack_move_protected_offsets()

    def _stack_variable_offset(variable: object) -> int | None:
        if not isinstance(variable, SimStackVariable):
            return None
        return variable.offset if isinstance(variable.offset, int) else None

    def collect_direct_stack_move_protected_keys() -> set[tuple[object, ...]]:
        if not protected_stack_offsets:
            return set()
        protected_keys: set[tuple[object, ...]] = set()
        for node in iter_c_nodes_deep(root):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = node.variable
            if _stack_variable_offset(variable) not in protected_stack_offsets:
                continue
            node_keys: set[tuple[object, ...]] = {("var", id(variable))}
            unified = node.unified_variable
            if unified is not None:
                node_keys.add(("unified", id(unified)))
            storage_key = describe_alias_storage(node).identity
            if storage_key is not None:
                node_keys.add(("storage", storage_key))
            liveness_key = local_liveness_key_8616(node)
            if liveness_key is not None:
                node_keys.add(("liveness", liveness_key))
            if not node_keys.isdisjoint(reads):
                protected_keys.update(node_keys)
                physical_key = stack_storage_liveness_key_8616(node)
                if physical_key is not None:
                    protected_keys.add(("physical", physical_key))
        return protected_keys

    direct_stack_move_protected_keys = collect_direct_stack_move_protected_keys()

    def is_local_variable(variable: object) -> bool:
        return isinstance(variable, (SimRegisterVariable, SimStackVariable))

    def collect_stmt_reads(stmt: object) -> set[tuple[object, ...]]:
        stmt_reads: set[tuple[object, ...]] = set()
        collect_storage_read_keys(stmt, stmt_reads)
        return stmt_reads

    def call_callee_key(call_expr: structured_c.CFunctionCall) -> tuple[str, object] | None:
        callee_target = call_expr.callee_target
        if callee_target is not None:
            return ("target", callee_target)

        callee_func = call_expr.callee_func
        if callee_func is not None:
            # Dynamic codegen boundary: function-like call targets may expose addr.
            callee_addr = getattr(callee_func, "addr", None)
            if callee_addr is not None:
                return ("func_addr", callee_addr)
            # Dynamic codegen boundary: function-like call targets may expose name.
            callee_name = getattr(callee_func, "name", None)
            if callee_name is not None:
                return ("func_name", callee_name)
            return ("func_id", id(callee_func))

        # Dynamic codegen boundary: older structured codegen call nodes expose callee directly.
        callee = getattr(call_expr, "callee", None)
        if isinstance(callee, str):
            return ("callee", callee)
        return None

    def normalized_call_arg_key(expr: object) -> tuple[object, ...]:
        expr = unwrap_c_casts(expr)
        storage_key = describe_alias_storage(expr).identity
        if storage_key is not None:
            return ("storage", storage_key)
        if isinstance(expr, structured_c.CConstant):
            return ("const", expr.value)
        if isinstance(expr, structured_c.CVariable):
            variable = expr.variable
            if isinstance(variable, SimRegisterVariable):
                return ("reg", variable.reg, variable.size)
            if isinstance(variable, SimStackVariable):
                return (
                    "stack",
                    variable.base,
                    variable.offset,
                    variable.size,
                )
            if isinstance(variable, SimMemoryVariable):
                return ("mem", variable.addr, variable.size)
            return ("var", id(variable))
        if isinstance(expr, structured_c.CUnaryOp):
            return ("unary", expr.op, normalized_call_arg_key(expr.operand))
        if isinstance(expr, structured_c.CBinaryOp):
            return ("binary", expr.op, normalized_call_arg_key(expr.lhs), normalized_call_arg_key(expr.rhs))
        if isinstance(expr, structured_c.CFunctionCall):
            return (
                "call",
                call_callee_key(expr),
                tuple(normalized_call_arg_key(arg) for arg in expr.args or ()),
            )
        return ("expr", type(expr).__name__)

    def same_call_signature(lhs: object, rhs: object) -> bool:
        lhs_call = unwrap_c_casts(lhs)
        rhs_call = unwrap_c_casts(rhs)
        if not isinstance(lhs_call, structured_c.CFunctionCall) or not isinstance(rhs_call, structured_c.CFunctionCall):
            return False
        lhs_key = call_callee_key(lhs_call)
        rhs_key = call_callee_key(rhs_call)
        if lhs_key is None or rhs_key is None or lhs_key != rhs_key:
            return False
        lhs_args = tuple(normalized_call_arg_key(arg) for arg in lhs_call.args or ())
        rhs_args = tuple(normalized_call_arg_key(arg) for arg in rhs_call.args or ())
        return lhs_args == rhs_args

    def statement_may_diverge_control_flow(stmt: object) -> bool:
        control_flow_types = (
            structured_c.CBreak,
            structured_c.CContinue,
            structured_c.CDoWhileLoop,
            structured_c.CForLoop,
            structured_c.CGoto,
            structured_c.CIfBreak,
            structured_c.CIfElse,
            structured_c.CReturn,
            structured_c.CWhileLoop,
        )
        return isinstance(stmt, control_flow_types)

    changed = False
    seen_prune_nodes: set[int] = set()
    prune_visit_count = 0
    max_prune_visits = 20000

    def prune(node: object) -> None:
        nonlocal changed, prune_visit_count
        if not structured_codegen_node(node):
            return
        marker = id(node)
        if marker in seen_prune_nodes:
            return
        seen_prune_nodes.add(marker)
        prune_visit_count += 1
        if prune_visit_count > max_prune_visits:
            # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
            codegen._inertia_dead_local_prune_walk_refused_complex_8616 = (
                # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
                int(getattr(codegen, "_inertia_dead_local_prune_walk_refused_complex_8616", 0) or 0) + 1
            )
            return

        if isinstance(node, structured_c.CStatements):
            new_statements: list[object | None] = []
            pending_assignment_indices: dict[tuple[object, ...], int] = {}
            statements = list(node.statements)
            for index, stmt in enumerate(statements):
                # Dynamic codegen boundary: expression statements expose expr in angr structured C.
                call_expr = stmt if isinstance(stmt, structured_c.CFunctionCall) else getattr(stmt, "expr", None)
                if isinstance(call_expr, structured_c.CFunctionCall):
                    next_stmt = statements[index + 1] if index + 1 < len(statements) else None
                    if (
                        isinstance(next_stmt, structured_c.CReturn)
                        and isinstance(next_stmt.retval, structured_c.CFunctionCall)
                        and same_call_signature(call_expr, next_stmt.retval)
                    ):
                        changed = True
                        continue
                stmt_reads = collect_stmt_reads(stmt)
                if stmt_reads:
                    for key in list(pending_assignment_indices):
                        if key in stmt_reads:
                            pending_assignment_indices.pop(key, None)
                if statement_may_diverge_control_flow(stmt):
                    pending_assignment_indices.clear()
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and is_local_variable(stmt.lhs.variable)
                    and not _expr_has_side_effects(stmt.rhs, iter_c_nodes_deep=iter_c_nodes_deep)
                ):
                    lhs_variable = stmt.lhs.variable
                    lhs_unified = stmt.lhs.unified_variable
                    lhs_exact_keys: set[tuple[object, ...]] = set()
                    if lhs_variable is not None:
                        lhs_exact_keys.add(("var", id(lhs_variable)))
                    if lhs_unified is not None:
                        lhs_exact_keys.add(("unified", id(lhs_unified)))
                    lhs_keys = set(lhs_exact_keys)
                    rhs_reads: set[tuple[object, ...]] = set()
                    if structured_codegen_node(stmt.rhs):
                        collect_storage_read_keys(stmt.rhs, rhs_reads)
                    storage_key = describe_alias_storage(stmt.lhs).identity
                    if storage_key is not None:
                        lhs_keys.add(("storage", storage_key))
                    liveness_key = local_liveness_key_8616(stmt.lhs)
                    if liveness_key is not None:
                        lhs_keys.add(("liveness", liveness_key))
                    if _stack_variable_offset(lhs_variable) in protected_stack_offsets:
                        physical_key = stack_storage_liveness_key_8616(stmt.lhs)
                        if physical_key is not None:
                            lhs_keys.add(("physical", physical_key))
                    protected_direct_stack_move_lhs = bool(
                        lhs_keys and not lhs_keys.isdisjoint(direct_stack_move_protected_keys)
                    )
                    self_referential_rhs = bool(lhs_keys) and not lhs_keys.isdisjoint(rhs_reads)
                    if protected_direct_stack_move_lhs:
                        # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
                        codegen._inertia_dead_local_prune_protected_direct_stack_move_count_8616 = (
                            int(
                                # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
                                getattr(
                                    codegen,
                                    "_inertia_dead_local_prune_protected_direct_stack_move_count_8616",
                                    0,
                                )
                                or 0
                            )
                            + 1
                        )
                        for key in lhs_keys:
                            pending_assignment_indices.pop(key, None)
                        prune(stmt)
                        new_statements.append(stmt)
                        continue
                    if lhs_keys.isdisjoint(reads) and not self_referential_rhs:
                        continue
                    for key in lhs_keys:
                        if key in pending_assignment_indices:
                            new_statements[pending_assignment_indices[key]] = None
                            changed = True
                        pending_assignment_indices[key] = len(new_statements)
                elif (
                    isinstance(stmt, structured_c.CAssignment)
                    and stmt.lhs.__class__.__name__ == "CDirtyExpression"
                    and not _expr_has_side_effects(stmt.rhs, iter_c_nodes_deep=iter_c_nodes_deep)
                ):
                    # Dynamic codegen boundary: dirty expressions are external codegen nodes.
                    dirty = getattr(stmt.lhs, "dirty", None)
                    # Dynamic codegen boundary: dirty metadata fields vary by angr expression.
                    dirty_varid = getattr(dirty, "varid", None) if dirty is not None else None
                    # Dynamic codegen boundary: dirty metadata fields vary by angr expression.
                    dirty_name = getattr(dirty, "name", None) if dirty is not None else None
                    lhs_keys = set()
                    if isinstance(dirty_varid, int):
                        lhs_keys.add(("dirty_varid", dirty_varid))
                    if isinstance(dirty_name, str) and dirty_name:
                        lhs_keys.add(("dirty_name", dirty_name))
                    if lhs_keys and lhs_keys.isdisjoint(reads):
                        changed = True
                        continue
                    for key in lhs_keys:
                        if key in pending_assignment_indices:
                            new_statements[pending_assignment_indices[key]] = None
                            changed = True
                        pending_assignment_indices[key] = len(new_statements)
                prune(stmt)
                new_statements.append(stmt)
            if new_statements != list(node.statements):
                node.statements = [stmt for stmt in new_statements if stmt is not None]
                changed = True
            return

        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "else_node",
            "retval",
        ):
            if not hasattr(node, attr):
                continue
            try:
                # Dynamic codegen boundary: child field names vary across angr C AST nodes.
                value = getattr(node, attr)
            except Exception:
                continue
            if structured_codegen_node(value):
                prune(value)

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                # Dynamic codegen boundary: child sequence fields vary across angr C AST nodes.
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            for item in items:
                if structured_codegen_node(item):
                    prune(item)

        if hasattr(node, "condition_and_nodes"):
            try:
                # Dynamic codegen boundary: CIfElse-like nodes may expose condition/body pairs.
                pairs = node.condition_and_nodes
            except Exception:
                pairs = None
            if pairs:
                for cond, body in pairs:
                    if structured_codegen_node(cond):
                        prune(cond)
                    if structured_codegen_node(body):
                        prune(body)

    prune(root)
    return changed
