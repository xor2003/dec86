"""Place binary-proven stack moves at their owning structured loop entry.

Layer: Structuring.
Responsibility: join typed direct-stack-move facts to exact machine loopback
edges and restore assignments at the unique enclosing posttest-loop entry.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Lowering owns the assignment value and storage identity; this module owns only
structured control-flow placement. It never uses rendered C, symbols, source
text, or variable names as evidence.
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
from .direct_stack_move_loop_evidence import (
    boundary_tuple_8616,
    repeated_sequence_edges_8616,
)
from .direct_stack_move_loop_sites import (
    loop_entry_sites_8616,
    place_assignment_8616,
    tagged_assignment_locations_8616,
)
from .direct_stack_move_ownership import (
    direct_stack_move_branch_claims_8616,
    direct_stack_move_loop_entry_supersedes_branch_claim_8616,
)
from .direct_stack_move_pretest_initializers import (
    materialize_direct_stack_move_pretest_initializers_8616,
    place_direct_stack_move_pretest_initializer_assignment_8616,
)

log: logging.Logger = logging.getLogger(__name__)

_LOOP_ENTRY_SOURCE_KINDS_8616 = frozenset(
    {
        DirectStackMoveSourceKind8616.STACK_SLOT,
        DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
        DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
    }
)


@dataclass(frozen=True, slots=True)
class DirectStackMoveLoopEntryStats8616:
    """Closed evidence counters for loop-entry placement."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    already_materialized_count: int
    refused_no_edge_count: int
    refused_no_site_count: int
    refused_assignment_count: int
    refused_branch_owner_count: int


def place_direct_stack_move_loop_entry_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> bool:
    """Place one Lowering-built assignment at its unique posttest-loop entry."""
    branch_claims = tuple(
        claim
        for claim in direct_stack_move_branch_claims_8616(project, codegen, function)
        if claim.move_ins_addr == move_fact.ins_addr
    )
    codegen_contract = cast(Any, codegen)
    root = codegen_contract.cfunc.statements
    edges = repeated_sequence_edges_8616(project, function, move_fact.ins_addr)
    if branch_claims and not (
        len(branch_claims) == 1
        and len(edges) == 1
        and direct_stack_move_loop_entry_supersedes_branch_claim_8616(
            branch_claims[0],
            edges[0],
        )
    ):
        return False
    sites = (
        loop_entry_sites_8616(
            project,
            root,
            edges[0],
            move_fact.dst_offset,
            function=function,
        )
        if root is not None and len(edges) == 1
        else ()
    )
    locations = (
        tagged_assignment_locations_8616(project, root, move_fact)
        if root is not None
        else ()
    )
    if len(locations) > 1:
        return False
    location = locations[0] if locations else None
    owned_assignment = location.assignment if location is not None else assignment
    materialized, _already = (
        place_assignment_8616(
            project,
            sites[0],
            move_fact,
            owned_assignment,
            location,
        )
        if len(sites) == 1
        else (False, False)
    )
    if materialized:
        return True
    return place_direct_stack_move_pretest_initializer_assignment_8616(
        project,
        codegen,
        function,
        move_fact,
        assignment,
    )


def materialize_direct_stack_move_loop_entry_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> bool:
    """Relocate tagged stack assignments to CFG-proven posttest-loop entries."""
    codegen_contract = cast(Any, codegen)
    try:
        root = codegen_contract.cfunc.statements
        direct_move_facts = codegen_contract._inertia_direct_stack_move_facts_8616
    except AttributeError:
        return False
    move_facts = tuple(
        fact
        for fact in boundary_tuple_8616(direct_move_facts or ())
        if isinstance(fact, DirectStackMoveFact8616)
        and fact.source_kind in _LOOP_ENTRY_SOURCE_KINDS_8616
    )
    normalized = 0
    classified = 0
    materialized = 0
    failures = 0
    already_materialized = 0
    refused_no_edge = 0
    refused_no_site = 0
    refused_assignment = 0
    refused_branch_owner = 0
    changed = False
    branch_claims = direct_stack_move_branch_claims_8616(
        project,
        codegen,
        function,
    )
    for move_fact in sorted(move_facts, key=lambda fact: fact.ins_addr):
        move_branch_claims = tuple(
            claim
            for claim in branch_claims
            if claim.move_ins_addr == move_fact.ins_addr
        )
        edges = repeated_sequence_edges_8616(project, function, move_fact.ins_addr)
        if move_branch_claims and not (
            len(move_branch_claims) == 1
            and len(edges) == 1
            and direct_stack_move_loop_entry_supersedes_branch_claim_8616(
                move_branch_claims[0],
                edges[0],
            )
        ):
            refused_branch_owner += 1
            continue
        debug_loop_entry = os.environ.get("INERTIA_DEBUG_STACK_LOOP_ENTRY") == "1"
        if not edges:
            refused_no_edge += 1
            if debug_loop_entry:
                log.warning("[direct-stack-move-loop-entry] move=%#x no-edge", move_fact.ins_addr)
            continue
        normalized += 1
        if len(edges) != 1 or root is None:
            failures += 1
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x edge-count=%d",
                    move_fact.ins_addr,
                    len(edges),
                )
            continue
        sites = loop_entry_sites_8616(
            project,
            root,
            edges[0],
            move_fact.dst_offset,
            function=function,
        )
        if len(sites) != 1:
            refused_no_site += 1
            failures += int(len(sites) > 1)
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x site-count=%d edge=%r",
                    move_fact.ins_addr,
                    len(sites),
                    edges[0],
                )
            continue
        locations = tagged_assignment_locations_8616(project, root, move_fact)
        if len(locations) != 1:
            refused_assignment += 1
            failures += int(len(locations) > 1)
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x assignment-count=%d",
                    move_fact.ins_addr,
                    len(locations),
                )
            continue
        classified += 1
        placed, already = place_assignment_8616(
            project,
            sites[0],
            move_fact,
            locations[0].assignment,
            locations[0],
        )
        if not placed:
            failures += 1
            continue
        materialized += 1
        already_materialized += int(already)
        changed = changed or not already
    stats = DirectStackMoveLoopEntryStats8616(
        raw_fact_count=len(move_facts),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
        already_materialized_count=already_materialized,
        refused_no_edge_count=refused_no_edge,
        refused_no_site_count=refused_no_site,
        refused_assignment_count=refused_assignment,
        refused_branch_owner_count=refused_branch_owner,
    )
    cast(Any, codegen)._inertia_direct_stack_move_loop_entry_placement_8616 = stats
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE") or os.environ.get(
        "INERTIA_DEBUG_STACK_LOOP_ENTRY"
    ):
        log.warning("[direct-stack-move-loop-entry] stats=%r", stats)
    return (
        materialize_direct_stack_move_pretest_initializers_8616(
            project,
            codegen,
            function,
        )
        or changed
    )
