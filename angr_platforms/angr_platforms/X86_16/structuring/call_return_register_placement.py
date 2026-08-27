"""Classify an existing register-return call before its structured condition.

Layer: Structuring.
Responsibility: prove whether one exact machine call assignment is the unique
adjacent producer of the register value tested by a structured condition.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
This module does not discover callsites, infer return storage, rewrite C text,
or repair missing call arguments.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import structured_callsite_addr_8616
from ..structured_tags import copy_structured_tags_8616


class CallReturnRegisterPlacementVerdict8616(StrEnum):
    """Typed outcome of one register-return placement proof."""

    MISSING = "missing"
    EXACT = "exact"
    NONADJACENT = "nonadjacent"
    AMBIGUOUS = "ambiguous"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class CallReturnRegisterPlacement8616:
    """One classified register-return assignment and condition relationship."""

    verdict: CallReturnRegisterPlacementVerdict8616
    raw_candidate_count: int
    assignment: CAssignment | None = None
    call: CFunctionCall | None = None
    assignment_container: CStatements | None = None
    assignment_index: int | None = None
    redundant_assignments: tuple[CallReturnRegisterAssignment8616, ...] = ()


@dataclass(frozen=True, slots=True)
class CallReturnRegisterAssignment8616:
    """One same-callsite assignment proven adjacent to the condition."""

    assignment: CAssignment
    call: CFunctionCall
    container: CStatements
    index: int


@dataclass(frozen=True, slots=True)
class _StatementPosition8616:
    """One direct statement position on an exact structured control path."""

    container: CStatements
    index: int
    statement: object
    control_path: tuple[tuple[int, str, int], ...]
    sequence_path: tuple[tuple[CStatements, int], ...]


class _StructuredStatementChildren8616(Protocol):
    """Dynamic third-party C AST body/default child boundary."""

    body: object
    default: object


def _assignment_ins_addr_8616(assignment: CAssignment) -> int | None:
    """Return the exact instruction tag carried by one assignment."""
    tags = copy_structured_tags_8616(assignment.tags)
    if tags is None:
        return None
    ins_addr = tags.get("ins_addr")
    return ins_addr if isinstance(ins_addr, int) else None


def _case_statement_blocks_8616(statement: object) -> tuple[CStatements, ...]:
    """Return switch-case blocks across the dynamic angr AST boundary."""
    cases = getattr(statement, "cases", None)
    if isinstance(cases, dict):
        raw_cases: Iterable[object] = cases.items()
    elif isinstance(cases, Iterable):
        raw_cases = cases
    else:
        return ()
    blocks: list[CStatements] = []
    for item in raw_cases:
        body = item[1] if isinstance(item, (list, tuple)) and len(item) >= 2 else item
        if isinstance(body, CStatements):
            blocks.append(body)
    return tuple(blocks)


def _statement_positions_8616(root: object) -> tuple[_StatementPosition8616, ...]:
    """Index transparent sequence groups while preserving control alternatives."""
    if not isinstance(root, CStatements):
        return ()
    positions: list[_StatementPosition8616] = []
    seen: set[tuple[int, tuple[tuple[int, str, int], ...]]] = set()

    def visit(
        block: CStatements,
        control_path: tuple[tuple[int, str, int], ...],
        sequence_path: tuple[tuple[CStatements, int], ...],
    ) -> None:
        key = (id(block), control_path)
        if key in seen:
            return
        seen.add(key)
        for index, statement in enumerate(tuple(block.statements or ())):
            statement_sequence_path = (*sequence_path, (block, index))
            if isinstance(statement, CStatements):
                visit(statement, control_path, statement_sequence_path)
                continue
            positions.append(
                _StatementPosition8616(
                    block,
                    index,
                    statement,
                    control_path,
                    statement_sequence_path,
                )
            )
            marker = id(statement)
            if isinstance(statement, CIfElse):
                for branch_index, pair in enumerate(tuple(statement.condition_and_nodes or ())):
                    if isinstance(pair, (list, tuple)) and len(pair) >= 2 and isinstance(pair[1], CStatements):
                        visit(pair[1], (*control_path, (marker, "if", branch_index)), ())
                if isinstance(statement.else_node, CStatements):
                    visit(statement.else_node, (*control_path, (marker, "else", 0)), ())
                continue
            for child_index, attr in enumerate(("body", "default")):
                boundary = cast(_StructuredStatementChildren8616, statement)
                try:
                    child = boundary.body if attr == "body" else boundary.default
                except AttributeError:
                    continue
                if isinstance(child, CStatements):
                    visit(child, (*control_path, (marker, attr, child_index)), ())
            for case_index, child in enumerate(_case_statement_blocks_8616(statement)):
                visit(child, (*control_path, (marker, "case", case_index)), ())

    visit(root, (), ())
    return tuple(positions)


def _sequence_paths_are_adjacent_8616(
    assignment: _StatementPosition8616,
    condition: _StatementPosition8616,
) -> bool:
    """Return whether two statements first diverge at adjacent sibling slots."""
    assignment_path = assignment.sequence_path
    condition_path = condition.sequence_path
    shared = 0
    while shared < min(len(assignment_path), len(condition_path)):
        assignment_container, assignment_index = assignment_path[shared]
        condition_container, condition_index = condition_path[shared]
        if assignment_container is not condition_container or assignment_index != condition_index:
            break
        shared += 1
    if shared >= len(assignment_path) or shared >= len(condition_path):
        return False
    assignment_container, assignment_index = assignment_path[shared]
    condition_container, condition_index = condition_path[shared]
    return assignment_container is condition_container and condition_index == assignment_index + 1


def _unique_adjacent_owner_8616(
    root: object,
    assignment: CAssignment,
    condition_owner: object,
) -> tuple[CStatements, int] | None:
    """Return the direct owner after exact same-path adjacency proof."""
    positions = _statement_positions_8616(root)
    assignment_positions = tuple(position for position in positions if position.statement is assignment)
    condition_positions = tuple(position for position in positions if position.statement is condition_owner)
    if len(assignment_positions) != 1 or len(condition_positions) != 1:
        return None
    assignment_position = assignment_positions[0]
    condition_position = condition_positions[0]
    if assignment_position.control_path != condition_position.control_path:
        return None
    if not _sequence_paths_are_adjacent_8616(assignment_position, condition_position):
        return None
    return assignment_position.container, assignment_position.index


def classify_call_return_register_placement_8616(
    root: object,
    condition_owner: object,
    *,
    callsite_addr: int,
    condition_producer_insn: int,
    register_slice: tuple[int, int],
) -> CallReturnRegisterPlacement8616:
    """Classify the unique exact call assignment feeding one condition."""
    candidates: dict[int, tuple[CAssignment, CFunctionCall]] = {}
    bound_assignments: dict[int, tuple[CAssignment, CFunctionCall]] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        lhs = node.lhs
        if not isinstance(lhs, CVariable) or not isinstance(lhs.variable, SimRegisterVariable):
            continue
        variable = lhs.variable
        if (int(variable.reg), int(variable.size)) != register_slice:
            continue
        calls = tuple(
            {id(call): call for call in _iter_c_nodes_deep_8616(node.rhs) if isinstance(call, CFunctionCall)}.values()
        )
        if len(calls) != 1:
            continue
        call = calls[0]
        bound_addr = structured_callsite_addr_8616(call)
        if bound_addr != callsite_addr:
            continue
        bound_assignments[id(node)] = (node, call)
        assignment_addr = _assignment_ins_addr_8616(node)
        if assignment_addr != condition_producer_insn:
            continue
        candidates[id(node)] = (node, call)
    if not candidates:
        return CallReturnRegisterPlacement8616(
            CallReturnRegisterPlacementVerdict8616.MISSING,
            0,
        )
    adjacent: list[tuple[CAssignment, CFunctionCall, CStatements, int]] = []
    for assignment, call in candidates.values():
        owner = _unique_adjacent_owner_8616(root, assignment, condition_owner)
        if owner is not None:
            adjacent.append((assignment, call, owner[0], owner[1]))
    if len(adjacent) == 1:
        assignment, call, owner, index = adjacent[0]
        redundant: list[CallReturnRegisterAssignment8616] = []
        for duplicate, duplicate_call in bound_assignments.values():
            if duplicate is assignment:
                continue
            duplicate_owner = _unique_adjacent_owner_8616(root, duplicate, condition_owner)
            if duplicate_owner is None:
                return CallReturnRegisterPlacement8616(
                    CallReturnRegisterPlacementVerdict8616.CONFLICT,
                    len(candidates),
                )
            redundant.append(
                CallReturnRegisterAssignment8616(
                    duplicate,
                    duplicate_call,
                    duplicate_owner[0],
                    duplicate_owner[1],
                )
            )
        return CallReturnRegisterPlacement8616(
            CallReturnRegisterPlacementVerdict8616.EXACT,
            len(candidates),
            assignment,
            call,
            owner,
            index,
            tuple(redundant),
        )
    if len(candidates) != 1 or adjacent:
        return CallReturnRegisterPlacement8616(
            CallReturnRegisterPlacementVerdict8616.AMBIGUOUS,
            len(candidates),
        )
    assignment, call = next(iter(candidates.values()))
    return CallReturnRegisterPlacement8616(
        CallReturnRegisterPlacementVerdict8616.NONADJACENT,
        1,
        assignment,
        call,
    )


def consume_exact_call_return_register_placement_8616(
    placement: CallReturnRegisterPlacement8616,
) -> bool:
    """Atomically remove every assignment represented by one exact placement."""
    if (
        placement.verdict is not CallReturnRegisterPlacementVerdict8616.EXACT
        or placement.assignment is None
        or placement.call is None
        or placement.assignment_container is None
        or placement.assignment_index is None
    ):
        return False
    records = (
        CallReturnRegisterAssignment8616(
            placement.assignment,
            placement.call,
            placement.assignment_container,
            placement.assignment_index,
        ),
        *placement.redundant_assignments,
    )
    grouped: dict[int, tuple[CStatements, list[tuple[int, CAssignment]]]] = {}
    for record in records:
        snapshot = tuple(record.container.statements or ())
        if not 0 <= record.index < len(snapshot) or snapshot[record.index] is not record.assignment:
            return False
        group = grouped.setdefault(id(record.container), (record.container, []))
        group[1].append((record.index, record.assignment))
    for container, removals in grouped.values():
        mutable_statements: list[object] = list(container.statements or ())
        for index, assignment in sorted(removals, key=lambda item: item[0], reverse=True):
            if not 0 <= index < len(mutable_statements) or mutable_statements[index] is not assignment:
                return False
            del mutable_statements[index]
        container.statements = mutable_statements
    return True


__all__ = (
    "CallReturnRegisterAssignment8616",
    "CallReturnRegisterPlacement8616",
    "CallReturnRegisterPlacementVerdict8616",
    "classify_call_return_register_placement_8616",
    "consume_exact_call_return_register_placement_8616",
)
