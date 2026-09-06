"""Consume exact structured-C projections of machine CALL return frames.

Layer: Types/Lowering.
Responsibility: join Semantics-owned VEX CALL-frame effect facts to their exact
structured-C assignments and remove effects represented by the C call itself.
This module does not infer CALL semantics, recover arguments, rewrite rendered
text, or use source/COD metadata.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

Only the full ``(callsite, VEX block, VEX statement)`` identity is accepted.
Instruction-address adjacency, propagated constants, and coincidentally similar
stack expressions are refusal cases rather than ownership evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.core import MemSpace
from ..pipeline.errors import PipelineHardError
from ..semantics.call_return_frame_effects import (
    CallReturnFrameEffectCollection8616,
    CallReturnFrameEffectKey8616,
    CallReturnFrameEffectRole8616,
    collect_call_return_frame_effects_8616,
)
from ..semantics.call_return_frame_projections import (
    CallReturnFrameProjectionFact8616,
    CallReturnFrameProjectionRole8616,
)
from .runtime_segment_access import runtime_segment_access_space_8616

__all__ = [
    "CallReturnFrameCarrierPrune8616",
    "prune_exact_call_return_frame_projections_8616",
]

type StructuredAstValue = Any


@dataclass(frozen=True, slots=True)
class CallReturnFrameCarrierPrune8616:
    """Closed evidence census for consumed CALL-frame C projections."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _CodegenCallReturnFrameSurface8616(Protocol):
    """Owned codegen extensions used by exact CALL-frame lowering."""

    cfunc: StructuredAstValue
    _inertia_call_return_frame_effect_collection_8616: CallReturnFrameEffectCollection8616


def _assignment_effect_key_8616(
    statement: structured_c.CAssignment,
) -> CallReturnFrameEffectKey8616 | None:
    """Read one exact semantic join key from third-party structured-C tags."""
    tags = statement.tags
    if not isinstance(tags, dict):
        return None
    callsite_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    statement_index = tags.get("vex_stmt_idx")
    if not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in (callsite_addr, block_addr, statement_index)
    ):
        return None
    return CallReturnFrameEffectKey8616(
        cast(int, callsite_addr),
        cast(int, block_addr),
        cast(int, statement_index),
    )


def _is_exact_sp_projection_lhs_8616(project: object, lhs: StructuredAstValue) -> bool:
    """Recognize an exact SP register projection at the angr AST boundary."""
    project_dynamic = cast(Any, project)
    try:
        sp_offset = project_dynamic.arch.sp_offset
    except AttributeError:
        return False
    if not isinstance(sp_offset, int):
        return False
    if isinstance(lhs, structured_c.CVariable):
        variable = lhs.variable
        return isinstance(variable, SimRegisterVariable) and variable.reg == sp_offset
    if not isinstance(lhs, structured_c.CDirtyExpression):
        return False
    dirty = cast(Any, lhs.dirty)
    try:
        return dirty.oident == sp_offset and dirty.was_reg is True
    except AttributeError:
        return False


def _is_exact_ss_store_projection_lhs_8616(
    project: object,
    codegen: StructuredAstValue,
    lhs: StructuredAstValue,
) -> bool:
    """Recognize a memory lvalue for one exact Semantics-owned SS store."""
    if isinstance(lhs, structured_c.CVariable):
        variable = lhs.variable
        return isinstance(variable, SimStackVariable) and variable.base == "bp"
    if isinstance(lhs, structured_c.CUnaryOp) and lhs.op == "Dereference":
        # The complete (callsite, VEX block, VEX statement) key already proves
        # this is the CALL-frame SS store. angr may retain its pre-lowering
        # dereference after replacing the address children with stack cvars.
        return True
    return runtime_segment_access_space_8616(project, codegen, lhs) is MemSpace.SS


def _lvalue_matches_role_8616(
    project: object,
    codegen: StructuredAstValue,
    lhs: StructuredAstValue,
    role: CallReturnFrameEffectRole8616,
) -> bool:
    """Require the C lvalue class implied by one exact semantic effect role."""
    if role is CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE:
        return _is_exact_sp_projection_lhs_8616(project, lhs)
    return _is_exact_ss_store_projection_lhs_8616(project, codegen, lhs)


def _is_exact_value_producer_lhs_8616(lhs: StructuredAstValue) -> bool:
    """Recognize a side-effect-free C carrier for one exclusive VEX producer."""
    return isinstance(lhs, (structured_c.CVariable, structured_c.CDirtyExpression))


def _producer_relations_are_exact_8616(
    key: CallReturnFrameEffectKey8616,
    relations: tuple[CallReturnFrameProjectionFact8616, ...],
    effects: Mapping[CallReturnFrameEffectKey8616, CallReturnFrameEffectRole8616],
) -> bool:
    """Require every projection of one producer to belong to exact frame stores."""
    return bool(relations) and all(
        relation.projection_key == key
        and relation.role is CallReturnFrameProjectionRole8616.VALUE_PRODUCER
        and relation.store_key.callsite_addr == key.callsite_addr
        and relation.store_key.vex_block_addr == key.vex_block_addr
        and effects.get(relation.store_key) is CallReturnFrameEffectRole8616.STACK_STORE
        for relation in relations
    )


def prune_exact_call_return_frame_projections_8616(
    project: object,
    codegen: StructuredAstValue,
    function: object,
    return_addr_by_callsite: Mapping[int, int],
) -> CallReturnFrameCarrierPrune8616:
    """Remove only C assignments joined to complete Semantics-owned CALL effects."""
    surface = cast(_CodegenCallReturnFrameSurface8616, codegen)
    collection = collect_call_return_frame_effects_8616(
        project,
        function,
        return_addr_by_callsite,
    )
    surface._inertia_call_return_frame_effect_collection_8616 = collection
    effects = {effect.key: effect.role for effect in collection.effects}
    producer_relations: dict[
        CallReturnFrameEffectKey8616,
        list[CallReturnFrameProjectionFact8616],
    ] = {}
    for relation in collection.projection_collection.projections:
        if relation.role is CallReturnFrameProjectionRole8616.VALUE_PRODUCER:
            producer_relations.setdefault(relation.projection_key, []).append(relation)
    refused_producer_keys = {
        producer_key
        for refusal in collection.projection_collection.refusals
        for producer_key in refusal.producer_keys
    }
    root = surface.cfunc.statements
    if not effects:
        return CallReturnFrameCarrierPrune8616(0, 0, 0, 0, 0)

    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        retained: list[StructuredAstValue] = []
        for statement in tuple(node.statements):
            if not isinstance(statement, structured_c.CAssignment):
                retained.append(statement)
                continue
            key = _assignment_effect_key_8616(statement)
            relations = tuple(producer_relations.get(key, ())) if key is not None else ()
            if key not in effects and not relations and key not in refused_producer_keys:
                retained.append(statement)
                continue
            raw_count += 1
            if key is None or key in refused_producer_keys:
                retained.append(statement)
                continue
            normalized_count += 1
            exact_effect = effects.get(key)
            relation_matches = _producer_relations_are_exact_8616(
                key,
                relations,
                effects,
            )
            if exact_effect is not None:
                lvalue_matches = _lvalue_matches_role_8616(
                    project,
                    codegen,
                    statement.lhs,
                    exact_effect,
                )
            else:
                lvalue_matches = relation_matches and _is_exact_value_producer_lhs_8616(
                    statement.lhs
                )
            if not lvalue_matches:
                retained.append(statement)
                continue
            classified_count += 1
            materialized_count += 1
        node.statements[:] = retained

    result = CallReturnFrameCarrierPrune8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(raw_count - classified_count, 0)
        + max(classified_count - materialized_count, 0),
    )
    if result.classified_fact_count > 0 and result.materialized_count == 0:
        raise PipelineHardError(
            "CALL-frame lowering classified exact C projections without consuming them"
        )
    return result
