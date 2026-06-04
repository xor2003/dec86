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

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CFunctionCall,
    CStructField,
    CUnaryOp,
    CVariable,
)

from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = ["_dead_code_elimination_8616"]


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
    ):
        if not isinstance(getattr(codegen, counter, None), int):
            setattr(codegen, counter, 0)

    changed = False

    def _var_key(node: CVariable) -> tuple[str, int | str]:
        var = getattr(node, "variable", None)
        if var is None:
            return ("node", id(node))
        ident = getattr(var, "ident", None)
        if isinstance(ident, str) and ident:
            return ("ident", ident)
        return ("var", id(var))

    def _dirty_key(node: object) -> tuple[str, int | str] | None:
        if type(node).__name__ != "CDirtyExpression":
            return None
        dirty = getattr(node, "dirty", None)
        dirty_idx = getattr(dirty, "idx", None)
        if isinstance(dirty_idx, (int, str)):
            return ("dirty", dirty_idx)
        expr_idx = getattr(node, "idx", None)
        if isinstance(expr_idx, (int, str)):
            return ("dirty_expr", expr_idx)
        return None

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
        if isinstance(lhs, (CUnaryOp, CStructField, CBinaryOp)):
            return True
        if isinstance(lhs, CFunctionCall):
            return True
        if isinstance(lhs, CVariable):
            var = getattr(lhs, "variable", None)
            region = getattr(var, "region", None)
            if isinstance(region, str) and region.lower() in {"global", "argument", "arg"}:
                return True
        return False

    def _rhs_has_side_effects(rhs: object) -> bool:
        if rhs is None:
            return False
        for node in _iter_c_nodes_deep_8616(rhs):
            if isinstance(node, CFunctionCall):
                return True
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
            if isinstance(lhs, CUnaryOp) and getattr(lhs, "op", None) in {"Dereference", "Reference"}:
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

        _collect_expr(stmt)
        return reads

    def _collect_read_counts_by_block(root) -> tuple[dict[tuple[str, int | str], int], dict[int, dict[tuple[str, int | str], int]]]:
        total_reads: dict[tuple[str, int | str], int] = {}
        block_reads: dict[int, dict[tuple[str, int | str], int]] = {}
        for block in _iter_statement_blocks(root):
            local_reads: dict[tuple[str, int | str], int] = {}
            for stmt in list(getattr(block, "statements", ()) or ()):
                for key in _collect_stmt_reads(stmt):
                    total_reads[key] = total_reads.get(key, 0) + 1
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
            return dirty_key, ("dirty", str(dirty_key[1])), True
        lhs_var = _lhs_variable_8616(lhs)
        if lhs_var is None:
            return None, None, False
        return _var_key(lhs_var), ("name", _var_name(lhs_var)), _is_temp_like_var(lhs_var)

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
        return protected

    protected = _protected_var_keys()
    if os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}:
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

    def walk_statements(statements, total_reads: dict[tuple[str, int | str], int], block_reads):
        nonlocal changed
        stmts = list(getattr(statements, "statements", ()) or ())
        if not stmts:
            return False
        local_reads = block_reads.get(id(statements), {})
        live: set[tuple[str, int | str]] = set()
        new_rev: list[object] = []
        block_changed = False

        for stmt in reversed(stmts):
            if not isinstance(stmt, CAssignment):
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
            if not is_temp_like:
                setattr(codegen, "dce_keep_unknown", int(getattr(codegen, "dce_keep_unknown", 0)) + 1)
                live.discard(key)
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            setattr(codegen, "dce_candidates", int(getattr(codegen, "dce_candidates", 0)) + 1)
            outside_reads = 0 if key[0] in {"dirty", "dirty_expr"} else int(total_reads.get(key, 0)) - int(local_reads.get(key, 0))
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
            else:
                removable = True
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
        pass_changed = False
        for block in _iter_statement_blocks(root):
            pass_changed = walk_statements(block, total_reads, block_reads) or pass_changed
        if not pass_changed:
            break
    return changed
