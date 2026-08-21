"""Locate exact call-output carriers at the dynamic angr C-AST boundary.

Layer: Types/Lowering.
Responsibility: map an immutable wide call-output Lowering fact to exact
instruction-tagged angr C-AST statements without deriving semantic facts from
AST shape, rendered text, symbols, or source names.
Consumes alias, widening, and typed facts at the dynamic C-AST boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .wide_call_output_assignment_contracts import WideCallOutputAssignmentFact8616


class _TaggedNodeBoundary8616(Protocol):
    """Dynamic tag field exposed by angr C-AST nodes."""

    tags: object


class _FunctionBoundary8616(Protocol):
    """Dynamic address field exposed by angr function objects."""

    addr: int


@dataclass(frozen=True, slots=True)
class WideCallOutputCallSite8616:
    """One exact structured statement carrying the proven machine call."""

    statements: CStatements
    index: int
    statement: object
    call: CFunctionCall


def c_node_instruction_addrs_8616(node: object) -> frozenset[int]:
    """Return instruction tags from one dynamic angr C-AST subtree."""
    addresses: set[int] = set()
    for child in _iter_c_nodes_deep_8616(node):
        try:
            tags = cast(_TaggedNodeBoundary8616, child).tags
        except AttributeError:
            continue
        if not isinstance(tags, dict):
            continue
        address = tags.get("ins_addr")
        if isinstance(address, int):
            addresses.add(address)
    return frozenset(addresses)


def _statement_groups_8616(root: object) -> tuple[CStatements, ...]:
    """Return every mutable statement group once in deterministic tree order."""
    groups: dict[int, CStatements] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CStatements):
            groups.setdefault(id(node), node)
    return tuple(groups.values())


def direct_statement_group_parents_8616(
    root: object,
    child: CStatements,
) -> tuple[tuple[CStatements, int], ...]:
    """Return direct statement-list parents of one exact group by identity."""
    parents: list[tuple[CStatements, int]] = []
    for group in _statement_groups_8616(root):
        parents.extend(
            (group, index)
            for index, statement in enumerate(group.statements)
            if statement is child
        )
    return tuple(parents)


def _standalone_call_8616(statement: object) -> CFunctionCall | None:
    """Return a call carried by one complete statement."""
    if isinstance(statement, CFunctionCall):
        return statement
    if isinstance(statement, CExpressionStatement) and isinstance(
        statement.expr, CFunctionCall
    ):
        return statement.expr
    if isinstance(statement, CAssignment) and isinstance(statement.rhs, CFunctionCall):
        return statement.rhs
    return None


def _call_target_matches_8616(call: CFunctionCall, target_addr: int) -> bool:
    """Match a call only by exact binary target identity, never by name."""
    if isinstance(call.callee_target, int):
        return call.callee_target == target_addr
    if call.callee_func is None:
        return False
    try:
        return cast(_FunctionBoundary8616, call.callee_func).addr == target_addr
    except AttributeError:
        return False


def exact_wide_call_output_call_sites_8616(
    root: object,
    fact: WideCallOutputAssignmentFact8616,
) -> tuple[WideCallOutputCallSite8616, ...]:
    """Collect structured calls matching exact instruction and target identity."""
    matches: list[WideCallOutputCallSite8616] = []
    for group in _statement_groups_8616(root):
        for index, statement in enumerate(group.statements):
            call = _standalone_call_8616(statement)
            if (
                call is not None
                and fact.call_output.callsite_addr
                in c_node_instruction_addrs_8616(statement)
                and _call_target_matches_8616(call, fact.call_output.target_addr)
            ):
                matches.append(
                    WideCallOutputCallSite8616(group, index, statement, call)
                )
    return tuple(matches)


__all__ = [
    "WideCallOutputCallSite8616",
    "c_node_instruction_addrs_8616",
    "direct_statement_group_parents_8616",
    "exact_wide_call_output_call_sites_8616",
]
