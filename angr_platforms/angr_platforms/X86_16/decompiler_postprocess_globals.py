"""Late global-load/store cleanup; global identity belongs earlier.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume already-proven adjacent global byte access facts for conservative rendered-C cleanup only.

This module coalesces adjacent byte-shaped global accesses into word-shaped C
globals and updates rendered variable types. That is acceptable only as a
temporary consumer of already-proven adjacent-byte evidence.

Current migration debt:
- word global load/store coalescing still recognizes byte-pair shapes in the C
  AST;
- type repair mutates rendered variables after codegen;
- unused memory declaration pruning depends on late rendered-use inspection.

The permanent home is segmented memory analysis, alias/widening, object/global
recovery, and lowering. Those layers should prove Address(space, offset, width)
and materialize the correct object before structuring/rewrite.

Do not add new global object inference, byte-pair reconstruction, or type
recovery here. If adjacency or width is not proven by structured facts, preserve
the original byte accesses and let validation/reporting show the missing proof.
"""

from __future__ import annotations

import builtins
import typing
from dataclasses import dataclass
from typing import Any

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable

from .decompiler_postprocess_loads import _global_load_addr_8616, _match_global_scaled_high_byte_8616
from .decompiler_postprocess_utils import (
    _global_memory_addr_8616,
    _is_shifted_high_byte_8616,
    _iter_c_nodes_deep_8616,
    _make_word_global_8616,
    _replace_c_children_8616,
)

__all__ = [
    "_coalesce_word_global_loads_8616",
    "WordGlobalStoreCandidate",
    "describe_word_global_constant_store_candidates_8616",
    "_coalesce_word_global_constant_stores_8616",
    "_apply_word_global_types_8616",
    "_prune_unused_unnamed_memory_declarations_8616",
]


def _dynamic_globals_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic third-party angr/codegen global-cleanup boundary."""
    return builtins.getattr(obj, name, default)


@dataclass(frozen=True)
class WordGlobalStoreCandidate:
    """Adjacent byte stores that can be rendered as one validation-gated word store."""

    base_addr: int
    next_addr: int
    kind: str


def _word_global_constant_store_candidate_8616(
    project: object,
    stmt: object,
    next_stmt: object,
) -> WordGlobalStoreCandidate | None:
    if not isinstance(stmt, CAssignment) or not isinstance(next_stmt, CAssignment):
        return None

    base_addr = _global_memory_addr_8616(stmt.lhs)
    if base_addr is None:
        return None

    next_addr = _global_memory_addr_8616(next_stmt.lhs)
    if not isinstance(next_addr, int) or next_addr != base_addr + 1:
        return None

    if isinstance(stmt.rhs, CConstant) and isinstance(next_stmt.rhs, CConstant):
        return WordGlobalStoreCandidate(base_addr, next_addr, "constant")
    if _is_shifted_high_byte_8616(next_stmt.rhs, stmt.rhs):
        return WordGlobalStoreCandidate(base_addr, next_addr, "shifted_high_byte")
    return None


def describe_word_global_constant_store_candidates_8616(
    project: object,
    codegen: object,
) -> tuple[WordGlobalStoreCandidate, ...]:
    """Describe adjacent byte-store shapes without mutating generated code."""
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return ()

    candidates: list[WordGlobalStoreCandidate] = []

    def visit(node: object) -> None:
        if isinstance(node, CStatements):
            for idx in range(len(node.statements) - 1):
                candidate = _word_global_constant_store_candidate_8616(
                    project, node.statements[idx], node.statements[idx + 1]
                )
                if candidate is not None:
                    candidates.append(candidate)
            for stmt in node.statements:
                visit(stmt)
        elif hasattr(node, "condition_and_nodes"):
            for _, body in _dynamic_globals_getattr_8616(node, "condition_and_nodes", ()):
                visit(body)
            else_node = _dynamic_globals_getattr_8616(node, "else_node", None)
            if else_node is not None:
                visit(else_node)

    visit(_dynamic_globals_getattr_8616(cfunc, "statements", None))
    return tuple(candidates)


def _coalesce_word_global_loads_8616(project: object, codegen: object) -> set[int]:
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return set()

    created: dict[int, CVariable] = {}
    changed_addrs: set[int] = set()

    def make_word_global(addr: int) -> CVariable:
        existing = created.get(addr)
        if existing is not None:
            return existing
        cvar = _make_word_global_8616(codegen, addr)
        created[addr] = cvar
        return cvar

    def transform(node: object) -> object:
        if not isinstance(node, CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = _global_load_addr_8616(low_expr)
            if low_addr is None:
                continue
            high_addr = _match_global_scaled_high_byte_8616(high_expr)
            if high_addr != low_addr + 1:
                continue
            changed_addrs.add(low_addr)
            return make_word_global(low_addr)

        return node

    root = _dynamic_globals_getattr_8616(cfunc, "statements", None)
    new_root = transform(root)
    if new_root is not root:
        # Preserve CStatements wrapper — transform() may return a plain list
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(statements=new_root if isinstance(new_root, list) else [new_root], codegen=codegen)
        typing.cast(typing.Any, cfunc).statements = new_root
        root = new_root
    _replace_c_children_8616(root, transform)
    return changed_addrs


def _coalesce_word_global_constant_stores_8616(project: object, codegen: object) -> set[int]:
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return set()

    changed_addrs: set[int] = set()

    def visit(node: object) -> None:
        if isinstance(node, CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, CAssignment)
                    and isinstance(node.statements[i + 1], CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    candidate = _word_global_constant_store_candidate_8616(project, stmt, next_stmt)
                    if candidate is not None:
                        base_addr = candidate.base_addr
                        if candidate.kind == "constant":
                            value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
                            new_statements.append(
                                CAssignment(
                                    _make_word_global_8616(codegen, base_addr),
                                    CConstant(value, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                            )
                            changed_addrs.add(base_addr)
                            i += 2
                            continue

                        if candidate.kind == "shifted_high_byte":
                            new_statements.append(
                                CAssignment(
                                    _make_word_global_8616(codegen, base_addr),
                                    stmt.rhs,
                                    codegen=codegen,
                                )
                            )
                            changed_addrs.add(base_addr)
                            i += 2
                            continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif hasattr(node, "condition_and_nodes"):
            for _, body in _dynamic_globals_getattr_8616(node, "condition_and_nodes", ()):
                visit(body)
            else_node = _dynamic_globals_getattr_8616(node, "else_node", None)
            if else_node is not None:
                visit(else_node)

    visit(_dynamic_globals_getattr_8616(cfunc, "statements", None))
    return changed_addrs


def _apply_word_global_types_8616(codegen: object, addrs: set[int]) -> bool:
    def _impl() -> bool:
        cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
        if not addrs or cfunc is None:
            return False

        changed = False
        target_type = SimTypeShort(False)

        for variable, cvar in _dynamic_globals_getattr_8616(cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimMemoryVariable):
                continue
            if _dynamic_globals_getattr_8616(variable, "addr", None) not in addrs:
                continue
            if _dynamic_globals_getattr_8616(variable, "size", None) != 2:
                variable.size = 2
                changed = True
            if _dynamic_globals_getattr_8616(cvar, "variable_type", None) != target_type:
                cvar.variable_type = target_type
                changed = True
            unified = _dynamic_globals_getattr_8616(cvar, "unified_variable", None)
            if unified is not None and _dynamic_globals_getattr_8616(unified, "size", None) != 2:
                try:
                    unified.size = 2
                    changed = True
                except Exception:
                    pass

        for cextern in _dynamic_globals_getattr_8616(codegen, "cexterns", ()) or ():
            variable = _dynamic_globals_getattr_8616(cextern, "variable", None)
            if not isinstance(variable, SimMemoryVariable):
                continue
            if _dynamic_globals_getattr_8616(variable, "addr", None) not in addrs:
                continue
            if _dynamic_globals_getattr_8616(variable, "size", None) != 2:
                variable.size = 2
                changed = True
            if _dynamic_globals_getattr_8616(cextern, "variable_type", None) != target_type:
                cextern.variable_type = target_type
                changed = True

        unified_locals = _dynamic_globals_getattr_8616(cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                if not isinstance(variable, SimMemoryVariable):
                    continue
                if _dynamic_globals_getattr_8616(variable, "addr", None) not in addrs:
                    continue
                if _dynamic_globals_getattr_8616(variable, "size", None) != 2:
                    variable.size = 2
                    changed = True
                new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
                if new_entries != cvar_and_vartypes:
                    unified_locals[variable] = new_entries
                    changed = True

        return changed

    return _impl()


def _prune_unused_unnamed_memory_declarations_8616(codegen: object) -> bool:
    def _impl() -> bool:
        cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
        if cfunc is None:
            return False

        used_variables: set[int] = set()
        for node in _iter_c_nodes_deep_8616(_dynamic_globals_getattr_8616(cfunc, "statements", None)):
            if not isinstance(node, CVariable):
                continue
            variable = _dynamic_globals_getattr_8616(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
            unified = _dynamic_globals_getattr_8616(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))

        changed = False
        variables_in_use = _dynamic_globals_getattr_8616(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable in list(variables_in_use):
                if not isinstance(variable, SimMemoryVariable):
                    continue
                name = _dynamic_globals_getattr_8616(variable, "name", None)
                if not isinstance(name, str) or not name.startswith("g_"):
                    continue
                if id(variable) in used_variables:
                    continue
                cvar = variables_in_use[variable]
                unified = _dynamic_globals_getattr_8616(cvar, "unified_variable", None)
                if unified is not None and id(unified) in used_variables:
                    continue
                del variables_in_use[variable]
                changed = True

        return changed

    return _impl()
