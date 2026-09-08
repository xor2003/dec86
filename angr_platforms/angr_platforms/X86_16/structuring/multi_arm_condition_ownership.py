"""Select typed conditions for multi-arm structured CFG nodes.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Recovers condition ownership lost while angr folds a decision
ladder into one ``CIfElse`` node. Selection uses only exact ConditionIR targets
and CFG successors; it does not infer operands or inspect rendered C.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import CExpression

from ..ir.condition_ir import ConditionIR


class MultiArmConditionOwnershipStatus8616(Enum):
    """Typed outcomes for one multi-arm ownership selection."""

    SELECTED = "selected"
    TOO_FEW_ARMS = "too_few_arms"
    MISSING_BODY_TARGET = "missing_body_target"
    DUPLICATE_BODY_TARGET = "duplicate_body_target"
    MISSING_UNIQUE_FACT = "missing_unique_fact"
    ROOT_MISMATCH = "root_mismatch"
    DUPLICATE_FACT = "duplicate_fact"
    CFG_EDGE_MISMATCH = "cfg_edge_mismatch"
    DISCONNECTED_FALLTHROUGH = "disconnected_fallthrough"


@dataclass(frozen=True, slots=True)
class MultiArmConditionOwnershipResult8616:
    """Return selected arm facts or one structured refusal."""

    status: MultiArmConditionOwnershipStatus8616
    facts: tuple[ConditionIR, ...] = ()
    detail: str | None = None

    @property
    def selected(self) -> bool:
        """Return whether every arm has exact CFG-owned condition evidence."""
        return self.status is MultiArmConditionOwnershipStatus8616.SELECTED


@dataclass(frozen=True, slots=True)
class MultiArmConditionMaterializationResult8616[BodyT]:
    """Return replacement predicates with unchanged, precisely typed arm bodies."""

    condition_and_nodes: tuple[tuple[CExpression, BodyT], ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _refuse_8616(
    status: MultiArmConditionOwnershipStatus8616,
    detail: str | None = None,
) -> MultiArmConditionOwnershipResult8616:
    """Build one typed ownership refusal."""
    return MultiArmConditionOwnershipResult8616(status=status, detail=detail)


def select_multi_arm_condition_owners_8616(
    arm_body_targets: tuple[int | None, ...],
    conditions: tuple[ConditionIR, ...],
    *,
    root: ConditionIR,
    successors: Mapping[int, tuple[int, ...]],
) -> MultiArmConditionOwnershipResult8616:
    """Select one exact taken-edge condition for every structured arm."""
    if len(arm_body_targets) < 2:
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.TOO_FEW_ARMS)
    if any(target is None for target in arm_body_targets):
        return _refuse_8616(
            MultiArmConditionOwnershipStatus8616.MISSING_BODY_TARGET
        )
    targets = tuple(int(target) for target in arm_body_targets if target is not None)
    if len(set(targets)) != len(targets):
        return _refuse_8616(
            MultiArmConditionOwnershipStatus8616.DUPLICATE_BODY_TARGET
        )

    selected: list[ConditionIR] = []
    for target in targets:
        candidates = tuple(
            condition
            for condition in conditions
            if condition.taken_target == target
            and isinstance(condition.block_addr, int)
            and isinstance(condition.fallthrough_target, int)
        )
        if len(candidates) != 1:
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.MISSING_UNIQUE_FACT,
                detail=f"target={target:#x}:count={len(candidates)}",
            )
        selected.append(candidates[0])

    if selected[0] != root:
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.ROOT_MISMATCH)
    if len({(fact.block_addr, fact.src_insn) for fact in selected}) != len(
        selected
    ):
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.DUPLICATE_FACT)

    for fact in selected:
        block_addr = fact.block_addr
        if not isinstance(block_addr, int):
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH
            )
        block_successors = successors.get(block_addr, ())
        if (
            fact.taken_target not in block_successors
            or fact.fallthrough_target not in block_successors
        ):
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH,
                detail=f"block={block_addr:#x}",
            )
    for current, following in itertools.pairwise(selected):
        if current.fallthrough_target != following.block_addr:
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH,
                detail=(
                    f"from={current.fallthrough_target!r}:"
                    f"to={following.block_addr!r}"
                ),
            )
    return MultiArmConditionOwnershipResult8616(
        status=MultiArmConditionOwnershipStatus8616.SELECTED,
        facts=tuple(selected),
    )


def materialize_multi_arm_condition_owners_8616[BodyT](
    condition_and_nodes: tuple[tuple[CExpression, BodyT], ...],
    ownership: MultiArmConditionOwnershipResult8616,
    materialize: Callable[[ConditionIR], CExpression | None],
) -> MultiArmConditionMaterializationResult8616[BodyT]:
    """Materialize selected facts while preserving third-party AST tags."""
    raw_count = len(condition_and_nodes)
    if not ownership.selected or len(ownership.facts) != raw_count:
        return MultiArmConditionMaterializationResult8616(
            condition_and_nodes=(),
            raw_fact_count=raw_count,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    replacements: list[tuple[CExpression, BodyT]] = []
    for (condition, body), fact in zip(
        condition_and_nodes,
        ownership.facts,
        strict=True,
    ):
        replacement = materialize(fact)
        if replacement is None:
            return MultiArmConditionMaterializationResult8616(
                condition_and_nodes=(),
                raw_fact_count=raw_count,
                normalized_fact_count=raw_count,
                classified_fact_count=raw_count,
                materialized_count=0,
                failure_count=1,
            )
        tags = dict(condition.tags) if isinstance(condition.tags, dict) else {}
        if isinstance(fact.src_insn, int):
            tags["ins_addr"] = fact.src_insn
        if isinstance(fact.block_addr, int):
            tags["vex_block_addr"] = fact.block_addr
        if isinstance(fact.producer_insn, int):
            tags["condition_producer_insn"] = fact.producer_insn
        tags["inertia_structuring_condition_cfg_materialized_8616"] = True
        tags["inertia_structuring_multi_arm_owner_materialized_8616"] = True
        replacement.tags = tags
        replacements.append((replacement, body))
    return MultiArmConditionMaterializationResult8616(
        condition_and_nodes=tuple(replacements),
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=raw_count,
        materialized_count=raw_count,
        failure_count=0,
    )
