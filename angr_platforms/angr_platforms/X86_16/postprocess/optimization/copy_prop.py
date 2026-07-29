"""Layer: Rewrite/Postprocess cleanup.

Responsibility: propagate copies only when alias storage facts prove the same storage.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
The codegen and C AST objects cross a dynamic third-party angr boundary; keep
dynamic attribute access limited to traversing already-recovered C AST nodes.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CVariable,
)

from ...semantics.alias_query import _storage_domain_for_expr

__all__ = ["_copy_propagation_8616"]


def _same_storage_domain(lhs: object, rhs: object) -> bool:
    """Prove two expressions refer to the same storage using alias facts."""
    lhs_domain = _storage_domain_for_expr(lhs)
    rhs_domain = _storage_domain_for_expr(rhs)
    if lhs_domain is None or rhs_domain is None:
        return False
    return lhs_domain == rhs_domain


def _copy_propagation_8616(codegen: object) -> bool:
    """Propagate copies: t2 = t1 becomes t2 = original_source when alias-provable.

    The codegen object crosses a dynamic third-party angr boundary; dynamic
    access here is limited to the already-built C AST surface.

    Returns True if any copy was propagated.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def walk_statements(statements: object) -> None:
        """Walk statement blocks across the dynamic third-party angr boundary."""
        nonlocal changed
        stmts = tuple(getattr(statements, "statements", ()) or ())
        # Track last assignment per storage domain within this block
        block_defs: dict[str, object] = {}

        for stmt in stmts:
            if isinstance(stmt, CAssignment):
                rhs = stmt.rhs
                lhs = stmt.lhs
                if isinstance(rhs, CVariable):
                    rhs_domain = _storage_domain_for_expr(rhs)
                    rhs_domain_key = str(rhs_domain) if rhs_domain is not None else None
                    if rhs_domain_key is not None and rhs_domain_key in block_defs:
                        replacement = block_defs[rhs_domain_key]
                        if replacement is not None:
                            stmt.rhs = replacement
                            changed = True

                # Record this definition
                if lhs is not None:
                    lhs_domain = _storage_domain_for_expr(lhs)
                    lhs_domain_key = str(lhs_domain) if lhs_domain is not None else None
                    if lhs_domain_key is not None:
                        block_defs[lhs_domain_key] = rhs
            _walk_node(stmt)

    def _walk_node(node: object) -> None:
        """Walk C AST child links across the dynamic third-party angr boundary."""
        if node is None:
            return
        if hasattr(node, "statements"):
            walk_statements(node)
        for attr in (
            "condition",
            "cond",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "retval",
            "expr",
            "switch",
            "initializer",
            "iterator",
        ):
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

    walk_statements(cfunc)
    return changed
