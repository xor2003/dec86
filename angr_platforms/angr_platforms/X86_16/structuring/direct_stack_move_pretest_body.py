"""Place binary-proven stack definitions inside structured pretest loops.

Layer: Structuring.
Responsibility: join exact pretest-body CFG evidence to one structured loop and
relocate an already-lowered direct stack assignment to its machine-ordered body
position.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Lowering owns assignment values and stack identities. This pass changes only
their structured execution scope and refuses missing or ambiguous evidence.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from ..pipeline.errors import PipelineHardError
from .direct_stack_move_loop_evidence import (
    boundary_tuple_8616,
    comparable_address_8616,
)
from .direct_stack_move_loop_sites import (
    DirectStackMoveAssignmentLocation8616,
    DirectStackMoveLoopEntrySite8616,
    _tree_reads_stack_offset_8616,
    _tree_tag_addresses_8616,
    place_assignment_8616,
    tagged_assignment_locations_8616,
)
from .direct_stack_move_ownership import (
    direct_stack_move_branch_owned_addresses_8616,
)
from .direct_stack_move_pretest_body_evidence import (
    DirectStackMovePretestBodyEvidence8616,
    recover_direct_stack_move_pretest_body_evidence_8616,
)
from .pretest_condition_surface import pretest_condition_surface_8616

__all__ = (
    "DirectStackMovePretestBodyStats8616",
    "materialize_direct_stack_move_pretest_body_ownership_8616",
    "place_direct_stack_move_pretest_body_assignment_8616",
)

log: logging.Logger = logging.getLogger(__name__)

_PRETEST_BODY_SOURCE_KINDS_8616 = frozenset(
    {
        DirectStackMoveSourceKind8616.STACK_SLOT,
        DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
        DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
    }
)


@dataclass(frozen=True, slots=True)
class _DirectStackMovePretestBodySite8616:
    """One structured loop body uniquely matched to exact CFG evidence."""

    statements: list[Any]
    depth: int


@dataclass(frozen=True, slots=True)
class DirectStackMovePretestBodyStats8616:
    """Closed evidence counters for pretest-loop body placement."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    already_materialized_count: int
    refused_no_evidence_count: int
    refused_no_site_count: int
    refused_assignment_count: int
    refused_branch_owner_count: int

    @property
    def closed(self) -> bool:
        """Return whether every raw fact materialized or refused explicitly."""
        counters = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return (
            all(counter >= 0 for counter in counters)
            and self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count >= self.materialized_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
        )


def _ast_field_8616(
    node: object | None,
    name: str,
    default: object | None = None,
) -> object | None:
    """Read one optional field from a heterogeneous angr structured-C node."""
    # Dynamic third-party boundary: structured-codegen node fields vary by type.
    return getattr(node, name, default)


def _pretest_body_sites_8616(
    project: object,
    codegen: object,
    root: object,
    evidence: DirectStackMovePretestBodyEvidence8616,
    dst_offset: int,
) -> tuple[_DirectStackMovePretestBodySite8616, ...]:
    """Find the unique deepest structured loop matching exact block origins."""
    matches: list[_DirectStackMovePretestBodySite8616] = []
    seen: set[int] = set()
    header_addresses = frozenset(evidence.header_instruction_addrs)
    body_entry_addresses = frozenset(evidence.body_entry_instruction_addrs)

    def visit(node: object, depth: int) -> None:
        """Walk owned structured nodes and collect exact pretest-loop matches."""
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        body = _ast_field_8616(node, "body")
        statements = _ast_field_8616(body, "statements")
        if isinstance(node, (structured_c.CForLoop, structured_c.CWhileLoop)) and isinstance(
            statements,
            list,
        ):
            surface = pretest_condition_surface_8616(node)
            condition_tags = frozenset(
                comparable_address_8616(project, address, evidence.move_addr)
                for condition in surface.conditions
                for address in _tree_tag_addresses_8616(condition)
            )
            body_tags = frozenset(
                comparable_address_8616(project, address, evidence.move_addr)
                for address in _tree_tag_addresses_8616(body)
            )
            if (
                condition_tags & header_addresses
                and body_tags & body_entry_addresses
                and _tree_reads_stack_offset_8616(codegen, statements, dst_offset)
            ):
                matches.append(_DirectStackMovePretestBodySite8616(statements, depth))
        statements_value = _ast_field_8616(node, "statements")
        if isinstance(statements_value, list):
            for statement in tuple(statements_value):
                visit(statement, depth + 1)
        for attr in ("body", "else_node"):
            child = _ast_field_8616(node, attr)
            if child is not None:
                visit(child, depth + 1)
        pairs = _ast_field_8616(node, "condition_and_nodes")
        if pairs:
            for _condition, guarded_body in boundary_tuple_8616(pairs):
                visit(guarded_body, depth + 1)

    visit(root, 0)
    if not matches:
        return ()
    deepest = max(site.depth for site in matches)
    return tuple(site for site in matches if site.depth == deepest)


def _place_pretest_body_assignment_8616(
    project: object,
    codegen: object,
    site: _DirectStackMovePretestBodySite8616,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
    location: DirectStackMoveAssignmentLocation8616 | None,
) -> tuple[bool, bool]:
    """Place one assignment in machine/data order within its loop body."""
    result = place_assignment_8616(
        project,
        codegen,
        DirectStackMoveLoopEntrySite8616(site.statements, site.depth),
        move_fact,
        assignment,
        location,
    )
    return bool(result[0]), bool(result[1])


def place_direct_stack_move_pretest_body_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> bool:
    """Place one Lowering-built assignment at its proven loop-body entry."""
    if move_fact.source_kind not in _PRETEST_BODY_SOURCE_KINDS_8616:
        return False
    if move_fact.ins_addr in direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    ):
        return False
    codegen_boundary = cast(Any, codegen)
    try:
        root = codegen_boundary.cfunc.statements
    except AttributeError:
        return False
    evidence = recover_direct_stack_move_pretest_body_evidence_8616(
        project,
        function,
        move_fact.ins_addr,
    )
    sites = (
        _pretest_body_sites_8616(
            project,
            codegen,
            root,
            evidence[0],
            move_fact.dst_offset,
        )
        if root is not None and len(evidence) == 1
        else ()
    )
    locations = (
        tagged_assignment_locations_8616(project, codegen, root, move_fact)
        if root is not None
        else ()
    )
    if len(evidence) != 1 or len(sites) != 1 or len(locations) > 1:
        return False
    location = locations[0] if locations else None
    owned_assignment = location.assignment if location is not None else assignment
    placed, _already = _place_pretest_body_assignment_8616(
        project,
        codegen,
        sites[0],
        move_fact,
        owned_assignment,
        location,
    )
    return placed


def materialize_direct_stack_move_pretest_body_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> bool:
    """Relocate tagged stack assignments to proven pretest-loop body entries."""
    codegen_boundary = cast(Any, codegen)
    try:
        root = codegen_boundary.cfunc.statements
        raw_facts = codegen_boundary._inertia_direct_stack_move_facts_8616
    except AttributeError:
        return False
    facts = tuple(
        fact
        for fact in boundary_tuple_8616(raw_facts or ())
        if isinstance(fact, DirectStackMoveFact8616)
        and fact.source_kind in _PRETEST_BODY_SOURCE_KINDS_8616
    )
    branch_owned = direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    )
    normalized = 0
    classified = 0
    materialized = 0
    already_materialized = 0
    refused_no_evidence = 0
    refused_no_site = 0
    refused_assignment = 0
    refused_branch_owner = 0
    changed = False
    for fact in sorted(facts, key=lambda candidate: candidate.ins_addr):
        if fact.ins_addr in branch_owned:
            refused_branch_owner += 1
            continue
        evidence = recover_direct_stack_move_pretest_body_evidence_8616(
            project,
            function,
            fact.ins_addr,
        )
        if len(evidence) != 1:
            refused_no_evidence += 1
            continue
        normalized += 1
        sites = _pretest_body_sites_8616(
            project,
            codegen,
            root,
            evidence[0],
            fact.dst_offset,
        )
        if len(sites) != 1:
            refused_no_site += 1
            continue
        locations = tagged_assignment_locations_8616(project, codegen, root, fact)
        if len(locations) != 1:
            refused_assignment += 1
            continue
        classified += 1
        placed, already = _place_pretest_body_assignment_8616(
            project,
            codegen,
            sites[0],
            fact,
            locations[0].assignment,
            locations[0],
        )
        if not placed:
            continue
        materialized += 1
        already_materialized += int(already)
        changed = changed or not already
    stats = DirectStackMovePretestBodyStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=len(facts) - materialized,
        already_materialized_count=already_materialized,
        refused_no_evidence_count=refused_no_evidence,
        refused_no_site_count=refused_no_site,
        refused_assignment_count=refused_assignment,
        refused_branch_owner_count=refused_branch_owner,
    )
    codegen_boundary._inertia_direct_stack_move_pretest_body_placement_8616 = stats
    if not stats.closed:
        raise PipelineHardError("direct-stack pretest-body evidence counters did not close")
    if classified > materialized:
        raise PipelineHardError(
            "classified direct-stack pretest-body assignments were not fully materialized"
        )
    if os.environ.get("INERTIA_DEBUG_STACK_PRETEST_BODY") or os.environ.get(
        "INERTIA_DEBUG_STACK_NOISE"
    ):
        log.warning("[direct-stack-move-pretest-body] stats=%r", stats)
    return changed
