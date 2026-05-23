from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Typed dead setup/staging carrier pruning.

This pass removes setup/carrier assignments only when they are proven dead:
- no semantic uses
- not referenced by surviving emitted AST
- not tied to observable alias/widening-relevant storage
"""

from dataclasses import dataclass
import re

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CFunctionCall,
    CConstant,
    CUnaryOp,
    CVariable,
)

from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = [
    "_prune_dead_setup_carriers_8616",
    "_count_dead_setup_escaped_8616",
]


_STAGING_NAME_RE = re.compile(
    r"^(?:vvar_\d+|s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|tmp_\d+|ir_\d+|arg_[0-9a-fA-F]+)$"
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    stmt_index: int
    key: tuple[str, int | str]
    lhs: CVariable
    rhs: object


def _setup_counter_defaults(codegen) -> None:
    for name in (
        "dead_setup_candidates",
        "dead_setup_pruned",
        "dead_setup_refused",
        "dead_setup_escaped",
    ):
        if not isinstance(getattr(codegen, name, None), int):
            setattr(codegen, name, 0)


def _var_name(node: CVariable) -> str:
    var = getattr(node, "variable", None)
    name = getattr(var, "name", None)
    if isinstance(name, str) and name:
        return name
    node_name = getattr(node, "name", None)
    if isinstance(node_name, str) and node_name:
        return node_name
    return ""


def _var_key(node: CVariable) -> tuple[str, int | str]:
    var = getattr(node, "variable", None)
    if var is not None:
        ident = getattr(var, "ident", None)
        if isinstance(ident, str) and ident:
            return ("ident", ident)
        return ("varid", id(var))
    return ("nodeid", id(node))


def _is_observable_storage(lhs: CVariable) -> bool:
    var = getattr(lhs, "variable", None)
    region = getattr(var, "region", None)
    # Local stack/register carriers are removable when def-use proves dead.
    # Keep globals/args conservative.
    if isinstance(region, str) and region.lower() in {"global", "argument", "arg"}:
        return True
    return False


def _is_candidate_lhs(lhs: object) -> bool:
    if not isinstance(lhs, CVariable):
        return False
    name = _var_name(lhs)
    return bool(name and _STAGING_NAME_RE.match(name))


def _is_setup_rhs(rhs: object) -> bool:
    if rhs is None:
        return False
    if isinstance(rhs, CUnaryOp) and getattr(rhs, "op", None) in {"Reference", "AddressOf"}:
        return True
    if isinstance(rhs, CBinaryOp):
        op = getattr(rhs, "op", None)
        if op in {"Add", "Sub"}:
            lhs = getattr(rhs, "lhs", None)
            r = getattr(rhs, "rhs", None)
            if isinstance(lhs, CConstant) or isinstance(r, CConstant):
                return True
            if isinstance(lhs, CVariable) or isinstance(r, CVariable):
                return True
    # Deep fallback: if expression tree contains address-taking or simple const offset arithmetic.
    for node in _iter_c_nodes_deep_8616(rhs):
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) in {"Reference", "AddressOf"}:
            return True
        if isinstance(node, CBinaryOp) and getattr(node, "op", None) in {"Add", "Sub"}:
            lhs = getattr(node, "lhs", None)
            r = getattr(node, "rhs", None)
            if isinstance(lhs, CConstant) or isinstance(r, CConstant):
                return True
    return False


def _rhs_has_side_effects(rhs: object) -> bool:
    if rhs is None:
        return False
    for node in _iter_c_nodes_deep_8616(rhs):
        if isinstance(node, CFunctionCall):
            return True
    return False


def _collect_read_counts(root) -> dict[tuple[str, int | str], int]:
    reads: dict[tuple[str, int | str], int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CAssignment):
            lhs = getattr(node, "lhs", None)
            rhs = getattr(node, "rhs", None)
            if isinstance(rhs, CVariable):
                key = _var_key(rhs)
                reads[key] = reads.get(key, 0) + 1
            for rhs_node in _iter_c_nodes_deep_8616(rhs):
                if isinstance(rhs_node, CVariable):
                    key = _var_key(rhs_node)
                    reads[key] = reads.get(key, 0) + 1
            # count nested lvalue uses only for address forms, not direct def lhs
            if isinstance(lhs, CUnaryOp) and getattr(lhs, "op", None) in {"Dereference", "Reference"}:
                for lhs_node in _iter_c_nodes_deep_8616(lhs):
                    if isinstance(lhs_node, CVariable):
                        key = _var_key(lhs_node)
                        reads[key] = reads.get(key, 0) + 1
            continue
        for sub in _iter_c_nodes_deep_8616(node):
            if isinstance(sub, CVariable):
                key = _var_key(sub)
                reads[key] = reads.get(key, 0) + 1
    return reads


def _iter_statement_blocks(root):
    seen: set[int] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None:
            continue
        nid = id(node)
        if nid in seen:
            continue
        seen.add(nid)
        if hasattr(node, "statements"):
            yield node
            for stmt in list(getattr(node, "statements", ()) or ()):
                stack.append(stmt)
        for attr in ("condition", "cond", "body", "else_node", "iftrue", "iffalse", "true_node", "false_node", "expr", "retval"):
            child = getattr(node, attr, None)
            if child is not None:
                stack.append(child)
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            for cond, body in condition_and_nodes:
                stack.append(cond)
                stack.append(body)
        cases = getattr(node, "cases", None)
        if isinstance(cases, dict):
            for body in cases.values():
                stack.append(body)
        default = getattr(node, "default", None)
        if default is not None:
            stack.append(default)


def _gather_candidates(statements) -> list[_Candidate]:
    stmts = list(getattr(statements, "statements", ()) or ())
    out: list[_Candidate] = []
    for idx, stmt in enumerate(stmts):
        if not isinstance(stmt, CAssignment):
            continue
        lhs = getattr(stmt, "lhs", None)
        rhs = getattr(stmt, "rhs", None)
        if not _is_candidate_lhs(lhs):
            continue
        if not _is_setup_rhs(rhs):
            continue
        out.append(_Candidate(idx, _var_key(lhs), lhs, rhs))
    return out


def _prune_dead_setup_carriers_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    statements = getattr(cfunc, "statements", None)
    if statements is None or not hasattr(statements, "statements"):
        return False

    _setup_counter_defaults(codegen)
    changed = False

    while True:
        reads = _collect_read_counts(statements)
        pass_changed = False
        total_refused = 0
        total_candidates = 0
        total_pruned = 0
        for block in _iter_statement_blocks(statements):
            stmts = list(getattr(block, "statements", ()) or ())
            if not stmts:
                continue
            candidates = _gather_candidates(block)
            if not candidates:
                continue
            total_candidates += len(candidates)
            to_remove: set[int] = set()
            refused = 0
            for cand in candidates:
                if _is_observable_storage(cand.lhs):
                    refused += 1
                    continue
                if _rhs_has_side_effects(cand.rhs):
                    refused += 1
                    continue
                if reads.get(cand.key, 0) > 0:
                    refused += 1
                    continue
                to_remove.add(cand.stmt_index)
            total_refused += refused
            if not to_remove:
                continue
            pruned = 0
            for idx in sorted(to_remove, reverse=True):
                if 0 <= idx < len(stmts):
                    del stmts[idx]
                    pruned += 1
            if pruned:
                block.statements = stmts
                total_pruned += pruned
                pass_changed = True

        if total_candidates:
            setattr(codegen, "dead_setup_candidates", int(getattr(codegen, "dead_setup_candidates", 0)) + total_candidates)
        if total_refused:
            setattr(codegen, "dead_setup_refused", int(getattr(codegen, "dead_setup_refused", 0)) + total_refused)
        if total_pruned:
            setattr(codegen, "dead_setup_pruned", int(getattr(codegen, "dead_setup_pruned", 0)) + total_pruned)
            changed = True
        if not pass_changed:
            break

    return changed


def _count_dead_setup_escaped_8616(codegen) -> int:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return 0
    statements = getattr(cfunc, "statements", None)
    if statements is None:
        return 0
    # Count only true escapes: assignments that still satisfy dead-prune criteria
    # after fixpoint, i.e. removable dead setup carriers that leaked past pipeline.
    reads = _collect_read_counts(statements)
    escaped: set[str] = set()
    for block in _iter_statement_blocks(statements):
        for cand in _gather_candidates(block):
            if _is_observable_storage(cand.lhs):
                continue
            if _rhs_has_side_effects(cand.rhs):
                continue
            if reads.get(cand.key, 0) > 0:
                continue
            name = _var_name(cand.lhs)
            if name:
                escaped.add(name)
    return len(escaped)
