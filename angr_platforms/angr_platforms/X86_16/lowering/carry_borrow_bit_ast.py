"""Bounded C-AST placement for proven numeric carry/borrow values.

Layer: Types/Lowering.
Responsibility: locate an exact instruction-tagged carry use, resolve its C-SSA
slice across structured scopes, and retire only proven-dead pure assignments.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CTypeCast,
    CVariable,
)

from ..c_ast_utils import (
    _iter_c_node_occurrences_8616,
    _iter_c_nodes_deep_8616,
)
from ..structuring_cfg_ownership import CFGInstructionSite8616, CFGOwnershipArtifact
from .carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616, CarryBorrowBitLoweringFailure8616
from .carry_borrow_bit_scope import (
    CarryBitOccurrence8616,
    assignment_map_8616,
    node_matches_instruction_site_8616,
    read_counts_8616,
    select_cfg_reaching_definitions_8616,
    statement_containers_8616,
    variable_key_8616,
)


@dataclass(frozen=True)
class CarryBitCarrierClosure8616:
    """Exact low-instruction definitions reaching one carry mask."""

    assignments: tuple[CAssignment, ...]
    nodes: tuple[object, ...]
    definition_nodes: tuple[tuple[object, ...], ...]


def _constant_int_8616(node: object) -> int | None:
    """Return an integer constant through syntax-only casts."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return int(node.value) if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _direct_masked_variable_8616(node: object) -> CVariable | None:
    """Return the variable in an exact ``value & 1`` expression."""
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or node.op != "And":
        return None
    for value, mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_int_8616(mask) != 1:
            continue
        while isinstance(value, CTypeCast):
            value = value.expr
        if isinstance(value, CBinaryOp) and value.op in {"Shr", "Sar"} and _constant_int_8616(value.rhs) == 0:
            value = value.lhs
            while isinstance(value, CTypeCast):
                value = value.expr
        if isinstance(value, CVariable):
            return value
    return None


def _masked_carry_variable_8616(node: object) -> tuple[CVariable, int] | None:
    """Return the carry variable and canonical mask depth for one C node."""
    direct = _direct_masked_variable_8616(node)
    if direct is not None:
        return direct, 1
    if not isinstance(node, CBinaryOp) or node.op != "And":
        return None
    for value, mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_int_8616(mask) == 1 and (nested := _direct_masked_variable_8616(value)) is not None:
            return nested, 2
    return None


def carry_bit_occurrences_8616(
    root: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> tuple[CarryBitOccurrence8616, ...]:
    """Collect maximal carry masks owned by the proven high instruction."""
    high_site = CFGInstructionSite8616(fact.high_block_addr, fact.high_ins_addr)
    candidates_by_node: dict[int, CarryBitOccurrence8616] = {}
    for container in statement_containers_8616(root):
        for statement_index, statement in enumerate(container.statements):
            for node in _iter_c_node_occurrences_8616(statement):
                if not isinstance(node, CBinaryOp) or not node_matches_instruction_site_8616(
                    node, high_site, ownership
                ):
                    continue
                masked = _masked_carry_variable_8616(node)
                if masked is not None:
                    variable, depth = masked
                    candidates_by_node[id(node)] = CarryBitOccurrence8616(
                        root, container, statement_index, node, variable, depth
                    )
    candidates = tuple(candidates_by_node.values())
    if not candidates:
        return ()
    maximal_depth = max(item.mask_depth for item in candidates)
    return tuple(item for item in candidates if item.mask_depth == maximal_depth)


def carry_bit_carrier_closure_8616(
    occurrence: CarryBitOccurrence8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CarryBitCarrierClosure8616 | CarryBorrowBitLoweringFailure8616:
    """Resolve the exact low-instruction assignment slice reaching carry."""
    seed = variable_key_8616(occurrence.flag_variable)
    if seed is None:
        return CarryBorrowBitLoweringFailure8616.CARRY_VARIABLE_IDENTITY_MISSING
    assignments = assignment_map_8616(occurrence)
    definitions = assignments.get(seed, ())
    if not definitions:
        return CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_MISSING
    selection = select_cfg_reaching_definitions_8616(occurrence, definitions, fact, ownership)
    if isinstance(selection, CarryBorrowBitLoweringFailure8616):
        return selection
    nodes: list[object] = []
    definition_nodes: list[tuple[object, ...]] = []
    for assignment in selection.definitions:
        rhs_nodes = tuple(_iter_c_nodes_deep_8616(assignment.rhs))
        nodes.extend(rhs_nodes)
        definition_nodes.append(rhs_nodes)
    return CarryBitCarrierClosure8616(selection.definitions, tuple(nodes), tuple(definition_nodes))


def _side_effect_free_8616(node: object) -> bool:
    """Return whether deleting one carrier RHS cannot delete an effect."""
    return not any(isinstance(item, (CFunctionCall, CDirtyExpression)) for item in _iter_c_nodes_deep_8616(node))


def prune_dead_carry_bit_carriers_8616(
    occurrence: CarryBitOccurrence8616,
    closure: CarryBitCarrierClosure8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> None:
    """Retire only dead, pure assignments in the proven low carrier slice."""
    owned = {id(assignment) for assignment in closure.assignments}
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    while True:
        reads = read_counts_8616(occurrence.root)
        changed = False
        for container in statement_containers_8616(occurrence.root):
            kept: list[object] = []
            for statement in container.statements:
                removable = False
                if (
                    id(statement) in owned
                    and isinstance(statement, CAssignment)
                    and isinstance(statement.lhs, CVariable)
                    and node_matches_instruction_site_8616(statement, low_site, ownership)
                ):
                    key = variable_key_8616(statement.lhs)
                    removable = key is not None and reads[key] == 0 and _side_effect_free_8616(statement.rhs)
                if removable:
                    changed = True
                else:
                    kept.append(statement)
            container.statements = kept
        if not changed:
            return
