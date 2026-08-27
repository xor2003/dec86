"""Materialize one proven carry/borrow bit at its exact C-AST use.

Layer: Types/Lowering.
Responsibility: normalize provenance and materialize one closed resolution.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_node_occurrences_8616, _replace_c_children_8616
from ..semantics.carry_borrow_contracts import CarryBorrowKind8616
from ..structuring_cfg_ownership import CFGOwnershipArtifact
from ..widening.carry_borrow_values import WideCarryBorrowValue8616
from .carry_borrow_bit_ast import (
    carry_bit_carrier_closure_8616,
    carry_bit_occurrences_8616,
    prune_dead_carry_bit_carriers_8616,
)
from .carry_borrow_bit_contracts import (
    CarryBorrowBitLoweringFact8616,
    CarryBorrowBitLoweringFailure8616,
    CarryBorrowBitLoweringResolution8616,
    CarryBorrowBitLoweringVerdict8616,
    refused_carry_borrow_bit_lowering_8616,
)
from .carry_borrow_bit_predicate import carry_bit_predicate_8616

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
    """Return whether this exact typed fact already owns a C predicate."""
    return any(node.tags.get(_EVIDENCE_TAG_8616) == fact for node in _iter_c_node_occurrences_8616(root))


def materialize_carry_borrow_bit_value_8616(
    root: object,
    source: WideCarryBorrowValue8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CarryBorrowBitLoweringResolution8616:
    """Materialize one proven carry predicate or return an explicit refusal."""
    if _already_materialized_8616(root, fact):
        return CarryBorrowBitLoweringResolution8616(
            source,
            CarryBorrowBitLoweringVerdict8616.MATERIALIZED,
            fact=fact,
            placement_classified=True,
            already_materialized=True,
        )
    occurrences = carry_bit_occurrences_8616(root, fact, ownership)
    if len(occurrences) != 1:
        failure = (
            CarryBorrowBitLoweringFailure8616.CARRY_USE_MISSING
            if not occurrences
            else CarryBorrowBitLoweringFailure8616.CARRY_USE_AMBIGUOUS
        )
        return refused_carry_borrow_bit_lowering_8616(source, failure, fact=fact)
    occurrence = occurrences[0]
    closure = carry_bit_carrier_closure_8616(occurrence, fact, ownership)
    if isinstance(closure, CarryBorrowBitLoweringFailure8616):
        return refused_carry_borrow_bit_lowering_8616(source, closure, fact=fact, placement_classified=True)
    predicate = carry_bit_predicate_8616(closure.definition_nodes, fact, ownership)
    if isinstance(predicate, CarryBorrowBitLoweringFailure8616):
        return refused_carry_borrow_bit_lowering_8616(source, predicate, fact=fact, placement_classified=True)
    replacement = cast(CBinaryOp, _clone_c_ast_tree_8616(predicate))
    replacement.tags = {**replacement.tags, _EVIDENCE_TAG_8616: fact}
    changed = _replace_c_children_8616(
        occurrence.container.statements[occurrence.statement_index],
        lambda node: replacement if node is occurrence.node else node,
    )
    if not changed:
        return refused_carry_borrow_bit_lowering_8616(
            source,
            CarryBorrowBitLoweringFailure8616.REPLACEMENT_FAILED,
            fact=fact,
            placement_classified=True,
        )
    prune_dead_carry_bit_carriers_8616(occurrence, closure, fact, ownership)
    return CarryBorrowBitLoweringResolution8616(
        source,
        CarryBorrowBitLoweringVerdict8616.MATERIALIZED,
        fact=fact,
        placement_classified=True,
        changed=True,
    )


__all__ = ["materialize_carry_borrow_bit_value_8616", "normalize_carry_borrow_bit_fact_8616"]
