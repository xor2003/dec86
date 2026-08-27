"""Structured scope contracts for proven carry/borrow bit placement.

Layer: Types/Lowering.
Responsibility: index exact C-SSA assignments and prove whether multiple
structured definitions are mutually exclusive alternatives reaching one use.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _iter_c_node_occurrences_8616
from ..structuring_cfg_ownership import (
    CFGInstructionReachability8616,
    CFGInstructionSite8616,
    CFGOwnershipArtifact,
)
from .carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616, CarryBorrowBitLoweringFailure8616

type VariableKey8616 = tuple[str, int]
type ControlArm8616 = tuple[int, str, int]
type ControlPath8616 = tuple[ControlArm8616, ...]


@dataclass(frozen=True)
class CarryBitOccurrence8616:
    """One exact high-instruction carry mask and its mutable statement owner."""

    root: object
    container: structured_c.CStatements
    statement_index: int
    node: structured_c.CBinaryOp
    flag_variable: structured_c.CVariable
    mask_depth: int


@dataclass(frozen=True)
class CarryBitDefinitionSelection8616:
    """Definitions proven to reach one use directly or through exclusive arms."""

    definitions: tuple[structured_c.CAssignment, ...]
    joined_alternatives: bool


def variable_key_8616(variable: structured_c.CVariable) -> VariableKey8616 | None:
    """Return stable SSA identity at the third-party C-AST boundary."""
    if isinstance(variable.vvar_id, int):
        return "vvar", variable.vvar_id
    carrier = variable.unified_variable if variable.unified_variable is not None else variable.variable
    return ("variable", id(carrier)) if carrier is not None else None


def node_instruction_site_8616(
    node: object,
    ownership: CFGOwnershipArtifact,
) -> CFGInstructionSite8616 | CFGInstructionReachability8616:
    """Resolve one dynamic C-AST node to a unique pre-join instruction owner."""
    if not hasattr(node, "tags"):
        return CFGInstructionReachability8616.OWNER_MISSING
    tags = cast(dict[str, object], node.tags)
    ins_addr = tags.get("ins_addr")
    if not isinstance(ins_addr, int):
        return CFGInstructionReachability8616.OWNER_MISSING
    block_addr = tags.get("vex_block_addr")
    if isinstance(block_addr, int):
        site = CFGInstructionSite8616(block_addr=block_addr, ins_addr=ins_addr)
    else:
        sites = ownership.instruction_sites(ins_addr)
        if not sites:
            return CFGInstructionReachability8616.OWNER_MISSING
        if len(sites) != 1:
            return CFGInstructionReachability8616.OWNER_AMBIGUOUS
        site = sites[0]
    owner_status = ownership.instruction_reachability(site, site)
    return site if owner_status is CFGInstructionReachability8616.REACHES else owner_status


def node_matches_instruction_site_8616(
    node: object,
    site: CFGInstructionSite8616,
    ownership: CFGOwnershipArtifact,
) -> bool:
    """Return whether one C-AST node has one exact pre-join instruction owner."""
    return node_instruction_site_8616(node, ownership) == site


def statement_containers_8616(root: object) -> tuple[structured_c.CStatements, ...]:
    """Return each unique mutable statement container in deterministic order."""
    containers: list[structured_c.CStatements] = []
    seen: set[int] = set()
    for node in _iter_c_node_occurrences_8616(root):
        if isinstance(node, structured_c.CStatements) and id(node) not in seen:
            seen.add(id(node))
            containers.append(node)
    return tuple(containers)


def assignment_map_8616(
    occurrence: CarryBitOccurrence8616,
) -> dict[VariableKey8616, tuple[structured_c.CAssignment, ...]]:
    """Index exact SSA definitions function-wide and legacy identities locally."""
    grouped: dict[VariableKey8616, list[structured_c.CAssignment]] = {}
    for container in statement_containers_8616(occurrence.root):
        for statement_index, statement in enumerate(container.statements):
            if not isinstance(statement, structured_c.CAssignment) or not isinstance(
                statement.lhs, structured_c.CVariable
            ):
                continue
            if (key := variable_key_8616(statement.lhs)) is None:
                continue
            local_predecessor = container is occurrence.container and statement_index < occurrence.statement_index
            if key[0] == "vvar" or local_predecessor:
                grouped.setdefault(key, []).append(statement)
    return {key: tuple(items) for key, items in grouped.items()}


def read_counts_8616(root: object) -> Counter[VariableKey8616]:
    """Count function-wide C-variable reads, excluding assignment lvalues."""
    counts: Counter[VariableKey8616] = Counter()
    for node in _iter_c_node_occurrences_8616(root):
        if isinstance(node, structured_c.CVariable) and (key := variable_key_8616(node)) is not None:
            counts[key] += 1
        if (
            isinstance(node, structured_c.CAssignment)
            and isinstance(node.lhs, structured_c.CVariable)
            and (lhs_key := variable_key_8616(node.lhs))
        ):
            counts[lhs_key] -= 1
    return counts


def _ifelse_children_8616(
    statement: structured_c.CIfElse,
    path: ControlPath8616,
) -> tuple[tuple[structured_c.CStatements, ControlPath8616], ...]:
    """Return typed branch containers at the dynamic angr C-AST boundary."""
    children: list[tuple[structured_c.CStatements, ControlPath8616]] = []
    marker = id(statement)
    pairs = statement.condition_and_nodes
    if isinstance(pairs, (list, tuple)):
        for branch_index, pair in enumerate(pairs):
            if isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[1], structured_c.CStatements):
                children.append((pair[1], (*path, (marker, "if", branch_index))))
    if isinstance(statement.else_node, structured_c.CStatements):
        children.append((statement.else_node, (*path, (marker, "else", 0))))
    return tuple(children)


def _child_scopes_8616(
    statement: object,
    path: ControlPath8616,
) -> tuple[tuple[structured_c.CStatements, ControlPath8616], ...]:
    """Return child containers, proving exclusivity only for explicit if arms."""
    if isinstance(statement, structured_c.CStatements):
        return ((statement, path),)
    children: list[tuple[structured_c.CStatements, ControlPath8616]] = []
    if isinstance(statement, structured_c.CIfElse):
        children.extend(_ifelse_children_8616(statement, path))
    for attr in ("body", "default"):
        child = getattr(statement, attr, None)  # dynamic third-party C-AST boundary
        if isinstance(child, structured_c.CStatements):
            children.append((child, path))
    cases = getattr(statement, "cases", ())  # dynamic third-party C-AST boundary
    if isinstance(cases, (list, tuple)):
        for case in cases:
            if isinstance(case, tuple) and len(case) == 2 and isinstance(case[1], structured_c.CStatements):
                children.append((case[1], path))  # noqa: PERF401 - narrows dynamic AST tuples
    return tuple(children)


def _structured_control_paths_8616(
    root: object,
) -> tuple[
    dict[int, tuple[ControlPath8616, ...]],
    dict[int, tuple[ControlPath8616, ...]],
]:
    """Index container and direct-statement control paths without flattening arms."""
    if not isinstance(root, structured_c.CStatements):
        return {}, {}
    container_paths: dict[int, list[ControlPath8616]] = {}
    statement_paths: dict[int, list[ControlPath8616]] = {}
    pending: list[tuple[structured_c.CStatements, ControlPath8616]] = [(root, ())]
    visited: set[tuple[int, ControlPath8616]] = set()
    while pending:
        container, path = pending.pop()
        identity = id(container), path
        if identity in visited:
            continue
        visited.add(identity)
        container_paths.setdefault(id(container), []).append(path)
        for statement in container.statements:
            statement_paths.setdefault(id(statement), []).append(path)
            pending.extend(reversed(_child_scopes_8616(statement, path)))
    return (
        {key: tuple(paths) for key, paths in container_paths.items()},
        {key: tuple(paths) for key, paths in statement_paths.items()},
    )


def _paths_exclusive_8616(lhs: ControlPath8616, rhs: ControlPath8616) -> bool:
    """Return whether two paths choose different arms of one control owner."""
    lhs_arms = {owner: (kind, index) for owner, kind, index in lhs}
    return any(owner in lhs_arms and lhs_arms[owner] != (kind, index) for owner, kind, index in rhs)


def select_reaching_definitions_8616(
    occurrence: CarryBitOccurrence8616,
    definitions: tuple[structured_c.CAssignment, ...],
) -> CarryBitDefinitionSelection8616 | None:
    """Select one reaching definition or a complete mutually exclusive join."""
    container_paths, statement_paths = _structured_control_paths_8616(occurrence.root)
    use_paths = container_paths.get(id(occurrence.container), ())
    if len(use_paths) != 1:
        return None
    use_path = use_paths[0]
    compatible: list[structured_c.CAssignment] = []
    definition_paths: dict[int, ControlPath8616] = {}
    for definition in definitions:
        paths = statement_paths.get(id(definition), ())
        if len(paths) != 1:
            return None
        definition_path = paths[0]
        if not _paths_exclusive_8616(definition_path, use_path):
            compatible.append(definition)
            definition_paths[id(definition)] = definition_path
    if len(compatible) == 1:
        return CarryBitDefinitionSelection8616((compatible[0],), False)
    if not compatible or not all(
        _paths_exclusive_8616(definition_paths[id(lhs)], definition_paths[id(rhs)])
        for lhs, rhs in combinations(compatible, 2)
    ):
        return None
    return CarryBitDefinitionSelection8616(tuple(compatible), True)


def _ownership_failure_8616(
    reachability: CFGInstructionReachability8616,
) -> CarryBorrowBitLoweringFailure8616:
    """Map Structuring ownership refusal into the Lowering diagnostic contract."""
    if reachability is CFGInstructionReachability8616.OWNER_MISSING:
        return CarryBorrowBitLoweringFailure8616.EXECUTION_OWNER_MISSING
    if reachability is CFGInstructionReachability8616.ORDER_CONFLICT:
        return CarryBorrowBitLoweringFailure8616.EXECUTION_ORDER_CONFLICT
    return CarryBorrowBitLoweringFailure8616.EXECUTION_OWNER_AMBIGUOUS


def select_cfg_reaching_definitions_8616(
    occurrence: CarryBitOccurrence8616,
    definitions: tuple[structured_c.CAssignment, ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CarryBitDefinitionSelection8616 | CarryBorrowBitLoweringFailure8616:
    """Select exact low-site definitions that can execute before the high use."""
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    high_site = CFGInstructionSite8616(fact.high_block_addr, fact.high_ins_addr)
    candidates: list[structured_c.CAssignment] = []
    for definition in definitions:
        site = node_instruction_site_8616(definition, ownership)
        if isinstance(site, CFGInstructionReachability8616):
            return _ownership_failure_8616(site)
        reachability = ownership.instruction_reachability(site, high_site)
        if reachability is CFGInstructionReachability8616.DOES_NOT_REACH:
            continue
        if reachability is not CFGInstructionReachability8616.REACHES:
            return _ownership_failure_8616(reachability)
        if site != low_site:
            return CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_AMBIGUOUS
        candidates.append(definition)
    if not candidates:
        return CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_MISSING
    selection = select_reaching_definitions_8616(occurrence, tuple(candidates))
    return selection or CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_AMBIGUOUS


__all__ = [
    "CarryBitDefinitionSelection8616",
    "CarryBitOccurrence8616",
    "VariableKey8616",
    "assignment_map_8616",
    "node_instruction_site_8616",
    "node_matches_instruction_site_8616",
    "read_counts_8616",
    "select_cfg_reaching_definitions_8616",
    "select_reaching_definitions_8616",
    "statement_containers_8616",
    "variable_key_8616",
]
