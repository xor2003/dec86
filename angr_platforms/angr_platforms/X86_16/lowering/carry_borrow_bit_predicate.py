"""Materialize explicit C predicates for proven carry/borrow values.

Layer: Types/Lowering.
Responsibility: project one typed carry/borrow operation through exact pre-join
instruction ownership into an explicit unsigned C predicate.
Consumes alias, widening, and typed facts plus pre-join Structuring ownership.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CTypeCast
from angr.sim_type import SimTypeShort

from ..c_ast_utils import _clone_c_ast_tree_8616, _same_c_expression_8616
from ..semantics.carry_borrow_contracts import CarryBorrowKind8616
from ..structuring_cfg_ownership import CFGInstructionSite8616, CFGOwnershipArtifact
from .carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616, CarryBorrowBitLoweringFailure8616
from .carry_borrow_bit_scope import node_matches_instruction_site_8616


def _constant_int_8616(node: object) -> int | None:
    """Return an integer constant through syntax-only casts."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return int(node.value) if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _low_site_8616(fact: CarryBorrowBitLoweringFact8616) -> CFGInstructionSite8616:
    """Return the exact typed low-arithmetic site."""
    return CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)


def _exact_arithmetic_representatives_8616(
    nodes: tuple[object, ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> tuple[CBinaryOp, ...]:
    """Return unique arithmetic projections owned by the proven low site."""
    operation = "Sub" if fact.kind is CarryBorrowKind8616.SUB_WITH_BORROW else "Add"
    low_site = _low_site_8616(fact)
    representatives: list[CBinaryOp] = []
    for node in nodes:
        if (
            isinstance(node, CBinaryOp)
            and node.op == operation
            and node_matches_instruction_site_8616(node, low_site, ownership)
            and not any(_same_c_expression_8616(node, existing) for existing in representatives)
        ):
            representatives.append(node)
    return tuple(representatives)


def _arithmetic_refusal_8616(
    representatives: tuple[CBinaryOp, ...],
) -> CarryBorrowBitLoweringFailure8616:
    """Classify missing versus conflicting exact arithmetic projections."""
    return (
        CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_MISSING
        if not representatives
        else CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_AMBIGUOUS
    )


def _predicate_matches_arithmetic_8616(
    predicate: CBinaryOp,
    nodes: tuple[object, ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> bool:
    """Prove that one C comparison projects the typed low operation."""
    arithmetic = _exact_arithmetic_representatives_8616(nodes, fact, ownership)
    if fact.kind is CarryBorrowKind8616.SUB_WITH_BORROW:
        return any(
            _same_c_expression_8616(predicate.lhs, node.lhs)
            and _same_c_expression_8616(predicate.rhs, node.rhs)
            for node in arithmetic
        )
    return any(
        _same_c_expression_8616(predicate.lhs, node)
        and (
            _same_c_expression_8616(predicate.rhs, node.lhs)
            or _same_c_expression_8616(predicate.rhs, node.rhs)
        )
        for node in arithmetic
    )


def _unsigned_word_operand_8616(expression: object, arithmetic: CBinaryOp) -> CTypeCast:
    """Clone one proven 16-bit operand with explicit unsigned C semantics."""
    return CTypeCast(
        arithmetic.type,
        SimTypeShort(signed=False),
        _clone_c_ast_tree_8616(expression),
        codegen=arithmetic.codegen,
        tags=dict(arithmetic.tags),
    )


def _subtraction_borrow_predicate_8616(
    nodes: tuple[object, ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CBinaryOp | CarryBorrowBitLoweringFailure8616:
    """Project typed SUB_WITH_BORROW as one unsigned low-word comparison."""
    representatives = _exact_arithmetic_representatives_8616(nodes, fact, ownership)
    if len(representatives) != 1:
        return _arithmetic_refusal_8616(representatives)
    subtraction = representatives[0]
    return CBinaryOp(
        "CmpLT",
        _unsigned_word_operand_8616(subtraction.lhs, subtraction),
        _unsigned_word_operand_8616(subtraction.rhs, subtraction),
        codegen=subtraction.codegen,
        tags=dict(subtraction.tags),
    )


def _addition_carry_predicate_8616(
    nodes: tuple[object, ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CBinaryOp | CarryBorrowBitLoweringFailure8616:
    """Project typed ADD_WITH_CARRY as one portable unsigned-16 comparison."""
    low_site = _low_site_8616(fact)
    representatives: list[CBinaryOp] = []
    for node in nodes:
        if not isinstance(node, CBinaryOp) or node.op != "And":
            continue
        for shifted, mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if _constant_int_8616(mask) != 1:
                continue
            while isinstance(shifted, CTypeCast):
                shifted = shifted.expr
            if (
                not isinstance(shifted, CBinaryOp)
                or shifted.op not in {"Shr", "Sar"}
                or _constant_int_8616(shifted.rhs) != 16
            ):
                continue
            addition = shifted.lhs
            if (
                isinstance(addition, CBinaryOp)
                and addition.op == "Add"
                and node_matches_instruction_site_8616(addition, low_site, ownership)
                and not any(_same_c_expression_8616(addition, existing) for existing in representatives)
            ):
                representatives.append(addition)
    if len(representatives) != 1:
        return _arithmetic_refusal_8616(tuple(representatives))
    addition = representatives[0]
    addition_copy = cast(CBinaryOp, _clone_c_ast_tree_8616(addition))
    lhs_copy = _clone_c_ast_tree_8616(addition.lhs)
    wrapped = CTypeCast(
        addition.type,
        SimTypeShort(signed=False),
        addition_copy,
        codegen=addition.codegen,
        tags=dict(addition.tags),
    )
    return CBinaryOp("CmpLT", wrapped, lhs_copy, codegen=addition.codegen, tags=dict(addition.tags))


def _definition_carry_predicate_8616(
    nodes: tuple[object, ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CBinaryOp | CarryBorrowBitLoweringFailure8616:
    """Select one coherent carry predicate from one reaching definition."""
    low_site = _low_site_8616(fact)
    candidates = tuple(
        node
        for node in nodes
        if isinstance(node, CBinaryOp)
        and node.op == "CmpLT"
        and node_matches_instruction_site_8616(node, low_site, ownership)
    )
    if not candidates:
        if fact.kind is CarryBorrowKind8616.ADD_WITH_CARRY:
            return _addition_carry_predicate_8616(nodes, fact, ownership)
        return _subtraction_borrow_predicate_8616(nodes, fact, ownership)
    coherent = tuple(
        node for node in candidates if _predicate_matches_arithmetic_8616(node, nodes, fact, ownership)
    )
    if not coherent:
        return CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_MISMATCH
    representatives: list[CBinaryOp] = []
    for node in coherent:
        if not any(_same_c_expression_8616(node, existing) for existing in representatives):
            representatives.append(node)
    return (
        representatives[0]
        if len(representatives) == 1
        else CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_AMBIGUOUS
    )


def carry_bit_predicate_8616(
    definition_nodes: tuple[tuple[object, ...], ...],
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CBinaryOp | CarryBorrowBitLoweringFailure8616:
    """Require every reaching definition to project one equivalent predicate."""
    predicates: list[CBinaryOp] = []
    for nodes in definition_nodes:
        predicate = _definition_carry_predicate_8616(nodes, fact, ownership)
        if isinstance(predicate, CarryBorrowBitLoweringFailure8616):
            return predicate
        if not any(_same_c_expression_8616(predicate, existing) for existing in predicates):
            predicates.append(predicate)
    return (
        predicates[0]
        if len(predicates) == 1
        else CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_AMBIGUOUS
    )


__all__ = ["carry_bit_predicate_8616"]
