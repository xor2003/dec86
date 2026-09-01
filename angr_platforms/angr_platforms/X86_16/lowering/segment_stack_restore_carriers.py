"""Consume alias-proven segment save/restore stack carriers.

Layer: Types/Lowering.
Responsibility: remove structured stack bookkeeping only when Alias proves an
exact segment-register save and restore pair.
Consumes alias facts. Do not infer pairs from opcodes, assembly, or C text.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.

Dynamic boundary: third-party angr C-AST statements and codegen attachments
expose version-dependent tags and child containers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from ..structured_tags import copy_structured_tags_8616

__all__ = [
    "SegmentStackRestoreCarrierStats8616",
    "prune_proven_segment_stack_restore_carriers_8616",
]


class _SegmentStackRestoreCodegen8616(Protocol):
    """Owned fields consumed and published at the dynamic codegen boundary."""

    cfunc: object
    _inertia_segment_stack_restore_artifact: SegmentStackRestoreArtifact8616
    _inertia_segment_stack_restore_carrier_pairs_8616: frozenset[tuple[int, int, str]]
    _inertia_segment_stack_restore_carrier_stats_8616: SegmentStackRestoreCarrierStats8616


@dataclass(frozen=True, slots=True)
class SegmentStackRestoreCarrierStats8616:
    """Closed accounting for proven restore facts and removed AST carriers."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    already_materialized_count: int
    failure_count: int
    removed_assignment_count: int

    @property
    def closed(self) -> bool:
        """Return whether every proven pair reached one terminal lane."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count + self.failure_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.already_materialized_count
        )


def _statement_instruction_addr_8616(statement: object) -> int | None:
    """Return one exact structured assignment instruction address."""
    tags = copy_structured_tags_8616(getattr(statement, "tags", None))
    if tags is not None:
        instruction_addr = tags.get("ins_addr")
        if isinstance(instruction_addr, int):
            return instruction_addr
    instruction_addr = getattr(statement, "ins_addr", None)
    return instruction_addr if isinstance(instruction_addr, int) else None


def _fact_key_8616(fact: SegmentStackRestoreFact8616) -> tuple[int, int, str] | None:
    """Return one exact proven save/restore pair identity."""
    if (
        fact.verdict is not SegmentStackRestoreVerdict8616.PROVEN
        or not isinstance(fact.saved_instruction_addr, int)
    ):
        return None
    return fact.saved_instruction_addr, fact.restore_instruction_addr, fact.restore_register


def prune_proven_segment_stack_restore_carriers_8616(project: object, codegen: object) -> bool:
    """Remove exact structured carriers for alias-proven segment restores."""
    del project
    boundary = cast(_SegmentStackRestoreCodegen8616, codegen)
    try:
        artifact = boundary._inertia_segment_stack_restore_artifact
        root = boundary.cfunc.statements
    except AttributeError:
        return False
    if not isinstance(artifact, SegmentStackRestoreArtifact8616):
        return False

    facts_by_key = {
        key: fact
        for fact in artifact.facts
        if (key := _fact_key_8616(fact)) is not None
    }
    prior_pairs = getattr(boundary, "_inertia_segment_stack_restore_carrier_pairs_8616", frozenset())
    completed_pairs = set(prior_pairs if isinstance(prior_pairs, frozenset) else ())
    pending_pairs = {key: fact for key, fact in facts_by_key.items() if key not in completed_pairs}
    address_roles: dict[int, set[tuple[tuple[int, int, str], str]]] = {}
    for key, fact in pending_pairs.items():
        assert fact.saved_instruction_addr is not None
        address_roles.setdefault(fact.saved_instruction_addr, set()).add((key, "save"))
        address_roles.setdefault(fact.restore_instruction_addr, set()).add((key, "restore"))

    observed_roles: dict[tuple[int, int, str], set[str]] = {}
    removed_assignment_count = 0

    def rewrite_statement_list(statements: list[object]) -> None:
        """Remove matching assignments recursively while retaining all others."""
        nonlocal removed_assignment_count
        kept: list[object] = []
        for statement in statements:
            instruction_addr = _statement_instruction_addr_8616(statement)
            roles = address_roles.get(instruction_addr, ())
            if isinstance(statement, structured_c.CAssignment) and roles:
                for key, role in roles:
                    observed_roles.setdefault(key, set()).add(role)
                removed_assignment_count += 1
                continue
            kept.append(statement)
        statements[:] = kept
        for statement in tuple(kept):
            for attribute in ("statements", "body", "else_node"):
                child = getattr(statement, attribute, None)
                child_statements = getattr(child, "statements", None)
                if isinstance(child_statements, list):
                    rewrite_statement_list(child_statements)
                elif isinstance(child, list):
                    rewrite_statement_list(child)

    root_statements = getattr(root, "statements", None)
    if isinstance(root_statements, list):
        rewrite_statement_list(root_statements)
    elif isinstance(root, list):
        rewrite_statement_list(root)

    materialized_pairs = {
        key for key, roles in observed_roles.items() if roles == {"save", "restore"}
    }
    completed_pairs.update(materialized_pairs)
    boundary._inertia_segment_stack_restore_carrier_pairs_8616 = frozenset(completed_pairs)
    stats = SegmentStackRestoreCarrierStats8616(
        raw_fact_count=len(facts_by_key),
        normalized_fact_count=len(facts_by_key),
        classified_fact_count=len(facts_by_key),
        materialized_count=len(materialized_pairs),
        already_materialized_count=len(set(facts_by_key) & set(prior_pairs)),
        failure_count=0,
        removed_assignment_count=removed_assignment_count,
    )
    boundary._inertia_segment_stack_restore_carrier_stats_8616 = stats
    return removed_assignment_count > 0
