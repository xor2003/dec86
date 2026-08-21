"""Materialize Widening-proven redundant stack subview recompositions.

Layer: Widening.
Responsibility: project accepted stack-object byte views into structured C
only after the current Widening artifact proves one unique containing owner.
Consumes Alias-proven storage identity through the typed Widening artifact.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

This pass consumes structured C AST shape as a materialization target, not as
semantic evidence. It refuses missing, stale, incomplete, ambiguous,
cross-region, wrong-offset, wrong-scale, or lvalue projections. Do not move
this work to postprocess or infer it from rendered C or assembly text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from ..c_ast_utils import _clone_c_ast_tree_8616, _replace_c_children_8616
from ..ir.core import IRAddress, MemSpace
from ..pipeline.errors import PipelineHardError
from .stack_memory_objects_contracts import (
    StackMemoryObjectWideningArtifact8616,
    StackMemoryObjectWideningCandidate8616,
)


@dataclass(slots=True)
class StackSubviewProjectionStats8616:
    """Closed evidence counters for contained stack-subview materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class _StackSubviewCandidate8616:
    """One syntax-normalized stack subview recomposition candidate."""

    container: structured_c.CVariable
    subview: structured_c.CVariable
    projection_bits: int | None


class _CodegenBoundary8616(Protocol):
    """Owned proof artifacts carried on the dynamic angr codegen boundary."""

    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616
    _inertia_stack_memory_object_widening_artifact: StackMemoryObjectWideningArtifact8616


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read optional third-party codegen state at the dynamic AST boundary."""
    return getattr(obj, name, default)


def _unwrap_casts_8616(node: object) -> object:
    """Remove syntax-only C casts while matching a structured expression."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_int_8616(node: object) -> int | None:
    """Return an integer C constant value without parsing rendered text."""
    node = _unwrap_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _projection_candidate_8616(node: object) -> tuple[structured_c.CVariable, int | None] | None:
    """Match a byte projection multiplied or shifted into a wider value."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    if node.op == "Shl":
        subview = _unwrap_casts_8616(node.lhs)
        shift = _constant_int_8616(node.rhs)
        if isinstance(subview, structured_c.CVariable) and shift is not None:
            return subview, shift
        return None
    if node.op != "Mul":
        return None
    for subview_node, scale_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        subview = _unwrap_casts_8616(subview_node)
        scale = _constant_int_8616(scale_node)
        if not isinstance(subview, structured_c.CVariable) or scale is None:
            continue
        projection_bits = scale.bit_length() - 1 if scale > 0 and scale & (scale - 1) == 0 else None
        return subview, projection_bits
    return None


def _stack_subview_candidate_8616(node: object) -> _StackSubviewCandidate8616 | None:
    """Match an OR recomposition with one direct container and one projected view."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    for container_node, projection_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        container = _unwrap_casts_8616(container_node)
        projection = _projection_candidate_8616(projection_node)
        if isinstance(container, structured_c.CVariable) and projection is not None:
            subview, projection_bits = projection
            return _StackSubviewCandidate8616(container, subview, projection_bits)
    return None


def _current_object_widening_8616(codegen: object) -> StackMemoryObjectWideningArtifact8616 | None:
    """Return the current complete stack-object proof or reject a layer bypass."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        source = None
    try:
        artifact = boundary._inertia_stack_memory_object_widening_artifact
    except AttributeError:
        artifact = None
    if source is None and artifact is None:
        return None
    if (
        not isinstance(source, StackMemorySSAAliasArtifact8616)
        or not isinstance(artifact, StackMemoryObjectWideningArtifact8616)
        or artifact.source_alias is not source
        or not artifact.complete
    ):
        raise PipelineHardError(
            "stack subview projection does not consume the current complete Widening artifact",
            layer="widening",
        )
    return artifact


def _stack_range_8616(variable: object, function_addr: int) -> tuple[int, int] | None:
    """Return an exact BP-relative range from one third-party stack variable."""
    if not isinstance(variable, SimStackVariable):
        return None
    base = _dynamic_attr_8616(variable, "base", None)
    region = _dynamic_attr_8616(variable, "region", None)
    offset = _dynamic_attr_8616(variable, "offset", None)
    size = _dynamic_attr_8616(variable, "size", None)
    if base != "bp" or region != function_addr or not isinstance(offset, int):
        return None
    if not isinstance(size, int) or size <= 0:
        return None
    return offset, size


def _address_range_8616(address: IRAddress) -> tuple[int, int] | None:
    """Return an exact SS:BP range from one accepted Widening address."""
    if address.space is not MemSpace.SS or address.base != ("bp",) or address.size <= 0:
        return None
    return address.offset, address.size


def _owner_cvariable_8616(
    cfunc: object,
    syntax: _StackSubviewCandidate8616,
    proof: StackMemoryObjectWideningCandidate8616,
    function_addr: int,
) -> structured_c.CVariable | None:
    """Resolve the unique structured-C variable for one proven object owner."""
    owner_range = _address_range_8616(proof.address)
    if owner_range is None:
        return None
    if _stack_range_8616(syntax.container.variable, function_addr) == owner_range:
        return syntax.container
    variables_in_use = _dynamic_attr_8616(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return None
    owners = [
        cvar
        for variable, cvar in variables_in_use.items()
        if _stack_range_8616(variable, function_addr) == owner_range
        and isinstance(cvar, structured_c.CVariable)
    ]
    unique = {id(owner): owner for owner in owners}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _proven_owner_8616(
    cfunc: object,
    artifact: StackMemoryObjectWideningArtifact8616 | None,
    syntax: _StackSubviewCandidate8616,
) -> structured_c.CVariable | None:
    """Match syntax ranges to exactly one accepted Widening object."""
    if artifact is None:
        return None
    function_addr = _dynamic_attr_8616(cfunc, "addr", None)
    if not isinstance(function_addr, int) or function_addr != artifact.function_addr:
        raise PipelineHardError(
            "stack subview projection received a Widening artifact for another function",
            layer="widening",
        )
    container_range = _stack_range_8616(syntax.container.variable, function_addr)
    subview_range = _stack_range_8616(syntax.subview.variable, function_addr)
    if container_range is None or subview_range is None:
        return None
    owners: list[structured_c.CVariable] = []
    for proof in artifact.candidates:
        owner_range = _address_range_8616(proof.address)
        covered_ranges = {
            address_range
            for address in proof.covered_addresses
            if (address_range := _address_range_8616(address)) is not None
        }
        if (
            owner_range is None
            or owner_range[1] != 2
            or container_range not in covered_ranges
            or subview_range not in covered_ranges
            or container_range[0] != owner_range[0]
            or container_range[1] not in {1, owner_range[1]}
            or subview_range != (owner_range[0] + 1, 1)
            or syntax.projection_bits != 8
        ):
            continue
        owner = _owner_cvariable_8616(cfunc, syntax, proof, function_addr)
        if owner is not None:
            owners.append(owner)
    unique = {id(owner): owner for owner in owners}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _increment_codegen_counter_8616(codegen: object, name: str, amount: int) -> None:
    """Accumulate evidence on the dynamic third-party codegen boundary."""
    current = _dynamic_attr_8616(codegen, name, 0)
    current_value = current if isinstance(current, int) else 0
    setattr(cast(Any, codegen), name, current_value + amount)


def materialize_contained_stack_subviews_8616(codegen: object) -> bool:
    """Fold one word recomposition only from the current Widening decision."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    root = _dynamic_attr_8616(cfunc, "statements", None)
    if root is None:
        return False
    artifact = _current_object_widening_8616(codegen)

    stats = StackSubviewProjectionStats8616()

    def transform(node: object) -> object:
        """Materialize one proven contained stack view."""
        candidate = _stack_subview_candidate_8616(node)
        if candidate is None:
            return node
        stats.raw_fact_count += 1
        if candidate.projection_bits != 8:
            stats.failure_count += 1
            return node
        stats.normalized_fact_count += 1
        owner = _proven_owner_8616(cfunc, artifact, candidate)
        if owner is None:
            stats.failure_count += 1
            return node
        stats.classified_fact_count += 1
        stats.materialized_count += 1
        return _clone_c_ast_tree_8616(owner)

    def should_process_child(parent: object, attr: str) -> bool:
        """Keep assignment lvalues outside this rvalue materialization pass."""
        return not (isinstance(parent, structured_c.CAssignment) and attr == "lhs")

    changed = _replace_c_children_8616(root, transform, should_process_child=should_process_child)
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_raw_fact_count",
        stats.raw_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_normalized_fact_count",
        stats.normalized_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_classified_fact_count",
        stats.classified_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_materialized_count",
        stats.materialized_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_failure_count",
        stats.failure_count,
    )
    cast(Any, codegen)._inertia_stack_subview_last_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified contained stack subview was not materialized",
            layer="widening",
        )
    return bool(changed and stats.materialized_count > 0)


__all__ = [
    "StackSubviewProjectionStats8616",
    "materialize_contained_stack_subviews_8616",
]
