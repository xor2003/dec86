"""Materialize one proven carry/borrow bit at its exact C-AST uses.

Layer: Types/Lowering.
Responsibility: normalize provenance and materialize one closed semantic-use resolution.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

from ..c_ast_utils import (
    _clone_c_ast_tree_8616,
    _iter_c_node_occurrences_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
)
from ..semantics.carry_borrow_contracts import CarryBorrowKind8616
from ..structuring_cfg_ownership import CFGOwnershipArtifact
from ..widening.carry_borrow_values import WideCarryBorrowValue8616
from .carry_borrow_bit_ast import (
    CarryBitCarrierClosure8616,
    carry_bit_carrier_closure_8616,
    carry_bit_occurrences_8616,
    finalize_low_arithmetic_copies_8616,
    inlined_carry_bit_occurrences_8616,
    prune_dead_carry_bit_carriers_8616,
)
from .carry_borrow_bit_contracts import (
    CarryBorrowBitLoweringFact8616,
    CarryBorrowBitLoweringFailure8616,
    CarryBorrowBitLoweringResolution8616,
    CarryBorrowBitLoweringVerdict8616,
    refused_carry_borrow_bit_lowering_8616,
)
from .carry_borrow_bit_predicate import carry_bit_predicate_8616, carry_bit_predicate_from_arithmetic_8616
from .carry_borrow_bit_scope import (
    CarryBitOccurrence8616,
    InlinedCarryBitOccurrence8616,
    assignment_map_8616,
    variable_key_8616,
)

_EVIDENCE_TAG_8616 = "inertia_x86_16_carry_borrow_bit_lowering"


def normalize_carry_borrow_bit_fact_8616(
    function_addr: int,
    source: WideCarryBorrowValue8616,
) -> CarryBorrowBitLoweringFact8616 | CarryBorrowBitLoweringFailure8616:
    """Normalize exact instruction provenance without consulting C-AST shape."""
    if source.kind not in {CarryBorrowKind8616.ADD_WITH_CARRY, CarryBorrowKind8616.SUB_WITH_BORROW}:
        return CarryBorrowBitLoweringFailure8616.UNSUPPORTED_OPERATION
    low_addr = source.provenance.low_arithmetic.instruction.addr
    high_addr = source.provenance.high_final_arithmetic.instruction.addr
    low_block_addr = source.provenance.low_arithmetic.block_addr
    high_block_addr = source.provenance.high_final_arithmetic.block_addr
    if not all(isinstance(value, int) for value in (low_block_addr, low_addr, high_block_addr, high_addr)):
        return CarryBorrowBitLoweringFailure8616.PROVENANCE_MISSING
    return CarryBorrowBitLoweringFact8616(
        function_addr=function_addr,
        kind=source.kind,
        low_block_addr=low_block_addr,
        low_ins_addr=low_addr,
        high_block_addr=high_block_addr,
        high_ins_addr=high_addr,
    )


def _already_materialized_8616(root: object, fact: CarryBorrowBitLoweringFact8616) -> bool:
    """Return whether this exact fact owns a predicate at its high instruction."""
    return any(
        node.tags.get(_EVIDENCE_TAG_8616) == fact and node.tags.get("ins_addr") == fact.high_ins_addr
        for node in _iter_c_node_occurrences_8616(root)
    )


def _one_semantic_carry_use_8616(occurrences: tuple[CarryBitOccurrence8616, ...]) -> bool:
    """Return whether structured copies project one identical carry-variable use."""
    if not occurrences:
        return False
    first = occurrences[0]
    first_key = variable_key_8616(first.flag_variable)
    return first_key is not None and all(
        variable_key_8616(occurrence.flag_variable) == first_key
        and _same_c_expression_8616(occurrence.node, first.node)
        for occurrence in occurrences[1:]
    )


def _one_semantic_inlined_carry_use_8616(
    occurrences: tuple[InlinedCarryBitOccurrence8616, ...],
) -> bool:
    """Return whether structured copies project one identical inlined carry use."""
    return bool(occurrences) and all(
        _same_c_expression_8616(occurrence.node, occurrences[0].node) for occurrence in occurrences[1:]
    )


def _materialize_inlined_carry_use_8616(
    root: object,
    source: WideCarryBorrowValue8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
    occurrences: tuple[InlinedCarryBitOccurrence8616, ...],
) -> CarryBorrowBitLoweringResolution8616:
    """Replace one semantic family of exact inlined carry projections."""
    if not _one_semantic_inlined_carry_use_8616(occurrences):
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.CARRY_USE_AMBIGUOUS,
            fact=fact,
        )
    nodes = tuple(_iter_c_node_occurrences_8616(root))
    predicate = carry_bit_predicate_from_arithmetic_8616(nodes, fact, ownership)
    if isinstance(predicate, CarryBorrowBitLoweringFailure8616):
        return refused_carry_borrow_bit_lowering_8616(
            source,
            predicate,
            fact=fact,
            placement_classified=True,
        )
    predicates = [predicate] * len(occurrences)

    replacements: dict[int, CBinaryOp] = {}
    for occurrence, predicate in zip(occurrences, predicates, strict=True):
        replacement = cast(CBinaryOp, _clone_c_ast_tree_8616(predicate))
        replacement.tags = {**occurrence.high_node.tags, _EVIDENCE_TAG_8616: fact}
        replacements[id(occurrence.node)] = replacement
    replaced_ids: set[int] = set()

    def _replace_occurrence_8616(node: object) -> object:
        """Replace one preclassified inlined projection by identity."""
        replacement = replacements.get(id(node))
        if replacement is None:
            return node
        replaced_ids.add(id(node))
        return replacement

    changed = _replace_c_children_8616(root, _replace_occurrence_8616)
    if not changed or replaced_ids != replacements.keys():
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.REPLACEMENT_FAILED,
            fact=fact,
            placement_classified=True,
        )
    finalize_low_arithmetic_copies_8616(root, fact, ownership)
    return CarryBorrowBitLoweringResolution8616(
        source,
        CarryBorrowBitLoweringVerdict8616.MATERIALIZED,
        fact=fact,
        placement_classified=True,
        changed=True,
    )


def _materialize_orphaned_carry_uses_8616(
    root: object,
    source: WideCarryBorrowValue8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
    occurrences: tuple[CarryBitOccurrence8616, ...],
) -> CarryBorrowBitLoweringResolution8616:
    """Replace exact high-site masks whose numeric definitions were structured away."""
    for occurrence in occurrences:
        key = variable_key_8616(occurrence.flag_variable)
        if key is None or assignment_map_8616(occurrence).get(key, ()):
            return refused_carry_borrow_bit_lowering_8616(
                source,
                CarryBorrowBitLoweringFailure8616.CARRY_USE_AMBIGUOUS,
                fact=fact,
            )
    nodes = tuple(_iter_c_node_occurrences_8616(root))
    predicate = carry_bit_predicate_from_arithmetic_8616(nodes, fact, ownership)
    if isinstance(predicate, CarryBorrowBitLoweringFailure8616):
        return refused_carry_borrow_bit_lowering_8616(
            source,
            predicate,
            fact=fact,
            placement_classified=True,
        )
    replacements: dict[int, CBinaryOp] = {}
    for occurrence in occurrences:
        replacement = cast(CBinaryOp, _clone_c_ast_tree_8616(predicate))
        replacement.tags = {**occurrence.node.tags, _EVIDENCE_TAG_8616: fact}
        replacements[id(occurrence.node)] = replacement
    replaced_ids: set[int] = set()

    def _replace_occurrence_8616(node: object) -> object:
        """Replace one preclassified orphaned numeric mask by identity."""
        replacement = replacements.get(id(node))
        if replacement is None:
            return node
        replaced_ids.add(id(node))
        return replacement

    changed = _replace_c_children_8616(root, _replace_occurrence_8616)
    if not changed or replaced_ids != replacements.keys():
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.REPLACEMENT_FAILED,
            fact=fact,
            placement_classified=True,
        )
    finalize_low_arithmetic_copies_8616(root, fact, ownership)
    return CarryBorrowBitLoweringResolution8616(
        source,
        CarryBorrowBitLoweringVerdict8616.MATERIALIZED,
        fact=fact,
        placement_classified=True,
        changed=True,
    )


def materialize_carry_borrow_bit_value_8616(
    root: object,
    source: WideCarryBorrowValue8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CarryBorrowBitLoweringResolution8616:
    """Materialize one proven carry predicate or return an explicit refusal."""
    occurrences = carry_bit_occurrences_8616(root, fact, ownership)
    if not occurrences:
        inlined_occurrences = inlined_carry_bit_occurrences_8616(root, fact, ownership)
        if inlined_occurrences:
            return _materialize_inlined_carry_use_8616(root, source, fact, ownership, inlined_occurrences)
        if _already_materialized_8616(root, fact):
            return CarryBorrowBitLoweringResolution8616(
                source,
                CarryBorrowBitLoweringVerdict8616.MATERIALIZED,
                fact=fact,
                placement_classified=True,
                already_materialized=True,
            )
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.CARRY_USE_MISSING,
            fact=fact,
        )
    if not _one_semantic_carry_use_8616(occurrences):
        return _materialize_orphaned_carry_uses_8616(root, source, fact, ownership, occurrences)

    closures: list[CarryBitCarrierClosure8616] = []
    for occurrence in occurrences:
        closure = carry_bit_carrier_closure_8616(occurrence, fact, ownership)
        if isinstance(closure, CarryBorrowBitLoweringFailure8616):
            return refused_carry_borrow_bit_lowering_8616(source, closure, fact=fact, placement_classified=True)
        closures.append(closure)
    predicates: list[CBinaryOp] = []
    if len(occurrences) > 1 and fact.kind is CarryBorrowKind8616.SUB_WITH_BORROW:
        nodes = tuple(_iter_c_node_occurrences_8616(root))
        predicate = carry_bit_predicate_from_arithmetic_8616(nodes, fact, ownership)
        if isinstance(predicate, CarryBorrowBitLoweringFailure8616):
            return refused_carry_borrow_bit_lowering_8616(
                source,
                predicate,
                fact=fact,
                placement_classified=True,
            )
        predicates.extend(predicate for _occurrence in occurrences)
    else:
        all_nodes: tuple[object, ...] | None = None
        for closure in closures:
            predicate = carry_bit_predicate_8616(closure.definition_nodes, fact, ownership)
            if predicate is CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_MISSING:
                if all_nodes is None:
                    all_nodes = tuple(_iter_c_node_occurrences_8616(root))
                predicate = carry_bit_predicate_from_arithmetic_8616(all_nodes, fact, ownership)
            if isinstance(predicate, CarryBorrowBitLoweringFailure8616):
                return refused_carry_borrow_bit_lowering_8616(
                    source,
                    predicate,
                    fact=fact,
                    placement_classified=True,
                )
            predicates.append(predicate)
    if any(not _same_c_expression_8616(predicate, predicates[0]) for predicate in predicates[1:]):
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_AMBIGUOUS,
            fact=fact,
            placement_classified=True,
        )

    replacements: dict[int, CBinaryOp] = {}
    for occurrence, predicate in zip(occurrences, predicates, strict=True):
        replacement = cast(CBinaryOp, _clone_c_ast_tree_8616(predicate))
        replacement.tags = {**occurrence.node.tags, _EVIDENCE_TAG_8616: fact}
        replacements[id(occurrence.node)] = replacement
    replaced_ids: set[int] = set()

    def _replace_occurrence_8616(node: object) -> object:
        """Replace one preclassified semantic-use projection by identity."""
        replacement = replacements.get(id(node))
        if replacement is None:
            return node
        replaced_ids.add(id(node))
        return replacement

    changed = _replace_c_children_8616(root, _replace_occurrence_8616)
    if not changed or replaced_ids != replacements.keys():
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.REPLACEMENT_FAILED,
            fact=fact,
            placement_classified=True,
        )
    for occurrence, closure in zip(occurrences, closures, strict=True):
        prune_dead_carry_bit_carriers_8616(occurrence, closure, fact, ownership)
    finalize_low_arithmetic_copies_8616(root, fact, ownership)
    return CarryBorrowBitLoweringResolution8616(
        source,
        CarryBorrowBitLoweringVerdict8616.MATERIALIZED,
        fact=fact,
        placement_classified=True,
        changed=True,
    )


__all__ = ["materialize_carry_borrow_bit_value_8616", "normalize_carry_borrow_bit_fact_8616"]
