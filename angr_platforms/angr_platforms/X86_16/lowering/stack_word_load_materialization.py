"""Materialize Alias-proven stack word-load recompositions in C ASTs.

Layer: Types/Lowering.
Responsibility: replace a structured ``low | (high << 8)`` projection with
the canonical stack CVariable only when instruction provenance, the exact
Alias load range, and the BP-to-entry-SP coordinate registry all agree.
Consumes alias, widening, and typed facts. Unproven candidates are retained and
reported as typed refusals.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasArtifact8616,
)
from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from .instruction_bp_stack_access import (
    InstructionBpStackAccess8616,
    InstructionBpStackAccessIndex8616,
    ensure_instruction_bp_stack_access_index_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_word_load_projection import resolve_stack_word_load_projection_8616
from .stack_word_projection import stack_word_projection_owner_8616

_LOG = logging.getLogger(__name__)


class StackWordLoadRefusalKind8616(StrEnum):
    """Reason one syntactic word projection remained unchanged."""

    SIDE_EFFECTFUL_HIGH = "side_effectful_high"
    ALIAS_ARTIFACT_UNAVAILABLE = "alias_artifact_unavailable"
    NO_INSTRUCTION_PROVENANCE = "no_instruction_provenance"
    ALIAS_LOAD_MISSING = "alias_load_missing"
    ALIAS_LOAD_AMBIGUOUS = "alias_load_ambiguous"
    STACK_PROJECTION_MISMATCH = "stack_projection_mismatch"


@dataclass(frozen=True, slots=True)
class StackWordLoadRefusal8616:
    """One retained word projection and its typed refusal reason."""

    kind: StackWordLoadRefusalKind8616
    instruction_addrs: tuple[int, ...] = ()
    detail: str = ""


@dataclass(frozen=True, slots=True)
class StackWordLoadMaterializationStats8616:
    """Closed evidence accounting for stack word-load materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every candidate was materialized or refused."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class StackWordLoadMaterializationArtifact8616:
    """Result of one AST replay against an exact Alias artifact."""

    source_alias: StackMemorySSAAliasArtifact8616 | None
    refusals: tuple[StackWordLoadRefusal8616, ...]
    stats: StackWordLoadMaterializationStats8616

    @property
    def complete(self) -> bool:
        """Return whether the materialization evidence loop closes."""
        return self.stats.complete and (
            self.source_alias is None or self.source_alias.complete
        )


@dataclass(frozen=True, slots=True)
class StackWordLoadMaterializationResult8616:
    """Possibly replaced AST root plus its durable evidence artifact."""

    root: object
    artifact: StackWordLoadMaterializationArtifact8616

    @property
    def changed(self) -> bool:
        """Return whether at least one proven projection was materialized."""
        return self.artifact.stats.materialized_count > 0


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen extension carrying typed pipeline artifacts."""

    _inertia_stack_memory_ssa_alias_artifact: object
    _inertia_stack_word_load_materialization_artifact_8616: (
        StackWordLoadMaterializationArtifact8616
    )


def _strip_casts_8616(node: object) -> object:
    """Remove syntax-only C casts from one expression boundary."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node: object) -> int | None:
    """Return one exact C integer constant."""
    stripped = _strip_casts_8616(node)
    return (
        stripped.value
        if isinstance(stripped, structured_c.CConstant)
        and isinstance(stripped.value, int)
        else None
    )


def _masked_operand_8616(node: object, mask: int) -> object | None:
    """Return the non-constant operand of one exact bit mask."""
    stripped = _strip_casts_8616(node)
    if not isinstance(stripped, structured_c.CBinaryOp) or stripped.op != "And":
        return None
    if _constant_value_8616(stripped.lhs) == mask:
        return cast(object, stripped.rhs)
    if _constant_value_8616(stripped.rhs) == mask:
        return cast(object, stripped.lhs)
    return None


def _low_stack_cvar_8616(node: object) -> structured_c.CVariable | None:
    """Return the CVariable carrying an exact low-byte projection."""
    stripped = _strip_casts_8616(node)
    if isinstance(stripped, structured_c.CVariable):
        return stripped
    masked = _masked_operand_8616(stripped, 0xFF)
    masked = _strip_casts_8616(masked)
    return masked if isinstance(masked, structured_c.CVariable) else None


def _high_dereference_8616(node: object) -> structured_c.CUnaryOp | None:
    """Return the dereference shifted into the high byte."""
    shifted = _strip_casts_8616(node)
    if (
        not isinstance(shifted, structured_c.CBinaryOp)
        or shifted.op != "Shl"
        or _constant_value_8616(shifted.rhs) != 8
    ):
        return None
    high = _strip_casts_8616(shifted.lhs)
    masked = _masked_operand_8616(high, 0xFF)
    if masked is not None:
        high = _strip_casts_8616(masked)
    return (
        high
        if isinstance(high, structured_c.CUnaryOp) and high.op == "Dereference"
        else None
    )


def _word_projection_parts_8616(
    node: object,
) -> tuple[structured_c.CVariable, structured_c.CUnaryOp] | None:
    """Recognize one syntax-level low/high word recomposition candidate."""
    stripped = _strip_casts_8616(node)
    if not isinstance(stripped, structured_c.CBinaryOp) or stripped.op != "Or":
        return None
    low = _low_stack_cvar_8616(stripped.lhs)
    high = _high_dereference_8616(stripped.rhs)
    if low is None or high is None:
        return None
    return low, high


def _has_side_effect_8616(node: object) -> bool:
    """Reject expression forms that cannot be discarded by materialization."""
    return any(
        isinstance(candidate, structured_c.CFunctionCall)
        or type(candidate).__name__ in {"CAssignment", "CMultiStatementExpression"}
        for candidate in _iter_c_nodes_deep_8616(node)
    )


def _word_load_candidates_8616(
    index: InstructionBpStackAccessIndex8616,
    instruction_addrs: frozenset[int],
) -> tuple[InstructionBpStackAccess8616, ...]:
    """Return deterministic exact two-byte Alias loads in one C subtree."""
    return tuple(sorted({
        fact
        for instruction_addr in instruction_addrs
        for fact in index.by_instruction_addr.get(instruction_addr, ())
        if fact.kind is StackMemoryAliasFactKind8616.LOAD and fact.size == 2
    }, key=lambda fact: (fact.displacement, fact.size, fact.kind.value)))


def materialize_stack_word_load_recompositions_8616(
    codegen: object,
    root: object,
) -> StackWordLoadMaterializationResult8616:
    """Materialize only word projections closed by exact Alias evidence."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        source = None
    source_alias = (
        source if isinstance(source, StackMemorySSAAliasArtifact8616) else None
    )
    index: InstructionBpStackAccessIndex8616 | None = None
    raw_fact_count = 0
    materialized_count = 0
    refusals: list[StackWordLoadRefusal8616] = []

    def _refuse(
        kind: StackWordLoadRefusalKind8616,
        instruction_addrs: frozenset[int] = frozenset(),
        detail: str = "",
    ) -> None:
        """Retain one candidate with deterministic typed diagnostics."""
        refusals.append(
            StackWordLoadRefusal8616(
                kind,
                tuple(sorted(instruction_addrs)),
                detail,
            )
        )

    def transform(node: object) -> object:
        """Replace one proven word projection and retain every refusal."""
        nonlocal index, materialized_count, raw_fact_count
        projected_owner = stack_word_projection_owner_8616(codegen, node)
        if projected_owner is not None:
            raw_fact_count += 1
            materialized_count += 1
            return projected_owner
        parts = _word_projection_parts_8616(node)
        if parts is None:
            return node
        raw_fact_count += 1
        low, high = parts
        if _has_side_effect_8616(high):
            _refuse(StackWordLoadRefusalKind8616.SIDE_EFFECTFUL_HIGH)
            return node
        if source_alias is None:
            _refuse(StackWordLoadRefusalKind8616.ALIAS_ARTIFACT_UNAVAILABLE)
            return node
        instruction_addrs = instruction_addrs_from_node_8616(high)
        if not instruction_addrs:
            instruction_addrs = instruction_addrs_from_node_8616(node)
        if not instruction_addrs:
            _refuse(StackWordLoadRefusalKind8616.NO_INSTRUCTION_PROVENANCE)
            return node
        if index is None:
            index = ensure_instruction_bp_stack_access_index_8616(
                codegen,
                source_alias,
            )
        loads = _word_load_candidates_8616(index, instruction_addrs)
        if len(loads) != 1:
            _refuse(
                StackWordLoadRefusalKind8616.ALIAS_LOAD_MISSING
                if not loads
                else StackWordLoadRefusalKind8616.ALIAS_LOAD_AMBIGUOUS,
                instruction_addrs,
                detail=(
                    f"candidate BP ranges={tuple((load.displacement, load.size) for load in loads)!r}; "
                    f"logical inventory={index.logical_inventory!r}"
                ),
            )
            return node
        load = loads[0]
        variable = low.variable
        if not isinstance(variable, SimStackVariable):
            _refuse(
                StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
                instruction_addrs,
            )
            return node
        resolution = resolve_stack_word_load_projection_8616(
            codegen, variable, bp_offset=load.displacement, size=load.size
        )
        if not resolution.resolved or resolution.cvar is None:
            _refuse(
                StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
                instruction_addrs,
                detail=(
                    f"expected BP range {(load.displacement, load.size)!r}; "
                    f"resolution={resolution.status.value}: {resolution.detail}"
                ),
            )
            return node
        materialized_count += 1
        return resolution.cvar

    replaced_root = transform(root)
    _replace_c_children_8616(replaced_root, transform)
    stats = StackWordLoadMaterializationStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    artifact = StackWordLoadMaterializationArtifact8616(
        source_alias,
        tuple(refusals),
        stats,
    )
    boundary._inertia_stack_word_load_materialization_artifact_8616 = artifact
    if os.environ.get("INERTIA_DEBUG_STACK_FACTS"):
        _LOG.warning(
            "[stack-word-load] function=%s raw=%d classified=%d materialized=%d failures=%d refusals=%r",
            hex(source_alias.function_addr) if source_alias is not None else "unknown",
            stats.raw_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            artifact.refusals,
        )
    return StackWordLoadMaterializationResult8616(replaced_root, artifact)


__all__ = [
    "StackWordLoadMaterializationArtifact8616",
    "StackWordLoadMaterializationResult8616",
    "StackWordLoadMaterializationStats8616",
    "StackWordLoadRefusal8616",
    "StackWordLoadRefusalKind8616",
    "materialize_stack_word_load_recompositions_8616",
]
