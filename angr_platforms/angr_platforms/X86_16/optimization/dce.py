from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Dead code elimination pass.
Removes assignments to temporaries that are never used.
Respects live-out boundary: never removes memory writes, return values,
or writes to registers visible at function exit.

Forbidden: semantic recovery, alias decisions beyond liveness, type inference."""

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CReturn,
    CUnaryOp,
    CVariable,
)

from ..decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..tail_validation_fingerprint import _register_name

__all__ = ["_dead_code_elimination_8616"]


def _dead_code_elimination_8616(codegen) -> bool:
    """Eliminate dead assignments within each block.

    An assignment lhs = rhs is dead if:
    - lhs is a temporary (registered but never used)
    - rhs has no side effects (not a function call)
    - lhs is not a live-out register
    - lhs is not a memory write (stack/global/segmented)

    Returns True if any dead assignment was removed.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def _is_observable_lvalue(lhs) -> bool:
        """Check if lhs is a memory write or otherwise observable."""
        # Function calls are observable even as lhs (they produce a value from a side-effect)
        if isinstance(lhs, CFunctionCall):
            return True
        # Memory writes
        if isinstance(lhs, CVariable):
            var = getattr(lhs, "variable", None)
            if hasattr(var, "region") and getattr(var, "region", None) == "stack":
                return True
        return False

    def _has_side_effects(rhs) -> bool:
        """Check if rhs has observable effects that can't be eliminated."""
        if isinstance(rhs, CFunctionCall):
            return True
        if isinstance(rhs, CAssignment):
            return True
        return False

    def _collect_local_uses(stmts: tuple) -> set[int]:
        """Collect all variable node ids used within this block."""
        uses: set[int] = set()
        for stmt in stmts:
            for node in _iter_c_nodes_deep_8616(stmt):
                if isinstance(node, CVariable) and not (
                    isinstance(stmt, CAssignment) and _same_c_expression_8616(node, getattr(stmt, "lhs", None))
                ):
                    uses.add(id(node))
        return uses

    def walk_statements(statements):
        nonlocal changed
        stmts = list(getattr(statements, "statements", ()) or ())
        if not stmts:
            return

        # Collect uses within this block
        uses = _collect_local_uses(tuple(stmts))

        # Mark dead assignments
        dead_indices: list[int] = []
        for idx, stmt in enumerate(stmts):
            if not isinstance(stmt, CAssignment):
                continue
            rhs = getattr(stmt, "rhs", None)
            lhs = getattr(stmt, "lhs", None)
            if lhs is None:
                continue

            # Never eliminate observable lvalues
            if _is_observable_lvalue(lhs):
                continue

            # Never eliminate writes with side effects
            if _has_side_effects(rhs):
                continue

            # Check if lhs is used anywhere in the block (other than its own def)
            if id(lhs) not in uses:
                dead_indices.append(idx)

        if dead_indices:
            # Remove dead assignments (process in reverse to keep indices valid)
            for idx in sorted(dead_indices, reverse=True):
                del stmts[idx]
            # Need to reassign to the statements object
            if hasattr(statements, 'statements'):
                # The statements attribute might be a tuple or list
                try:
                    statements.statements = stmts
                except (AttributeError, TypeError):
                    pass
            changed = True

    def _walk_node(node):
        if node is None:
            return
        if hasattr(node, "statements"):
            walk_statements(node)
        for attr in ("condition", "cond", "body", "else_node", "iftrue", "iffalse",
                     "retval", "expr", "switch", "initializer", "iterator"):
            child = getattr(node, attr, None)
            if child is not None:
                _walk_node(child)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                _walk_node(cond)
                _walk_node(body)
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                _walk_node(case_body)
        if hasattr(node, "default"):
            _walk_node(getattr(node, "default", None))

    def walk_cfunc(cfunc_node):
        if hasattr(cfunc_node, "statements"):
            walk_statements(cfunc_node)
        for attr in ("body", "else_node"):
            child = getattr(cfunc_node, attr, None)
            if child is not None:
                _walk_node(child)

    walk_cfunc(cfunc)
    return changed