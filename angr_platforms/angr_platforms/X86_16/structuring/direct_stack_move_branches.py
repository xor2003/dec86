"""Keep binary-proven stack moves inside their owning structured branch.

Layer: Structuring.
Responsibility: join typed direct-stack-move facts to ConditionIR/CFG evidence
and preserve the proven branch owner when angr regenerates the structured C AST.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

Lowering owns the value and destination of a direct stack move. It must not
decide whether that write belongs inside an ``if`` arm. This module owns that
control-flow placement and refuses ambiguous condition, jump-target, AST, or
assignment joins. Rewrite and postprocess may replay this service after AST
regeneration, but they must not infer or alter branch ownership themselves.

Dynamic boundary: angr structured-C nodes, codegen objects, Capstone
instructions, and function block inventories expose version-dependent
attributes. Dynamic access below is restricted to those third-party surfaces.
"""

from __future__ import annotations

import contextlib
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from capstone.x86_const import X86_OP_IMM

from ..ir.condition_ir import ConditionIR
from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from .condition_replay import (
    StructuringConditionReplayFact8616,
    condition_replay_facts_8616,
)

log: logging.Logger = logging.getLogger(__name__)


class DirectStackMoveBranchArm8616(Enum):
    """A structured branch arm proven to execute one direct stack move."""

    TAKEN = "taken"


@dataclass(frozen=True, slots=True)
class DirectStackMoveBranchFact8616:
    """Typed join between one stack move and one machine branch."""

    move_ins_addr: int
    condition_ins_addr: int
    condition_producer_insn: int | None
    arm: DirectStackMoveBranchArm8616
    arm_start: int
    merge_addr: int


@dataclass(frozen=True, slots=True)
class DirectStackMoveBranchStats8616:
    """Closed evidence counters for one branch-placement replay."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    already_materialized_count: int


@dataclass(frozen=True, slots=True)
class _DirectStackMovePlacementSite8616:
    """One mutable statement sequence and its machine-taken suffix start."""

    statements: list[Any]
    start_index: int


_BRANCH_OWNED_SOURCE_KINDS_8616 = frozenset(
    {
        DirectStackMoveSourceKind8616.IMMEDIATE,
        DirectStackMoveSourceKind8616.STACK_SLOT,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
    }
)


def _boundary_tuple_8616(value: object) -> tuple[Any, ...]:
    """Convert one dynamic angr collection to a stable tuple."""
    return tuple(cast(Iterable[Any], value))


def _candidate_addresses_8616(project: object, address: int) -> frozenset[int]:
    """Return current/original address-domain candidates for one instruction."""
    candidates = {address}
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        candidates.update((address + delta, address - delta))
    return frozenset(candidates)


def direct_stack_move_instruction_targets_8616(
    project: object,
    function: object,
    conditions: Iterable[ConditionIR],
) -> dict[int, int]:
    """Return exact immediate targets for decoded function instructions."""
    result: dict[int, int] = {}
    blocks = _boundary_tuple_8616(getattr(function, "blocks", ()) or ())
    local_blocks = getattr(function, "_local_blocks", None)
    if isinstance(local_blocks, dict) and local_blocks:
        blocks = tuple(local_blocks.values())
    for block in blocks:
        capstone = getattr(block, "capstone", None)
        for wrapper in _boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
            insn = getattr(wrapper, "insn", wrapper)
            address = getattr(insn, "address", None)
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            if (
                isinstance(address, int)
                and len(operands) == 1
                and getattr(operands[0], "type", None) == X86_OP_IMM
                and isinstance(getattr(operands[0], "imm", None), int)
            ):
                result[address] = int(operands[0].imm)
    factory = getattr(project, "factory", None)
    for condition in conditions:
        fallthrough = condition.fallthrough_target
        if not isinstance(fallthrough, int) or fallthrough in result or factory is None:
            continue
        with contextlib.suppress(Exception):
            block = factory.block(fallthrough, num_inst=1, opt_level=0)
            wrappers = _boundary_tuple_8616(
                getattr(getattr(block, "capstone", None), "insns", ()) or ()
            )
            if not wrappers:
                continue
            insn = getattr(wrappers[0], "insn", wrappers[0])
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            if (
                getattr(insn, "address", None) == fallthrough
                and len(operands) == 1
                and getattr(operands[0], "type", None) == X86_OP_IMM
                and isinstance(getattr(operands[0], "imm", None), int)
            ):
                result[fallthrough] = int(operands[0].imm)
    return result


def recover_direct_stack_move_branch_facts_8616(
    conditions: Iterable[ConditionIR],
    move_facts: Iterable[DirectStackMoveFact8616],
    instruction_targets: dict[int, int],
) -> tuple[DirectStackMoveBranchFact8616, ...]:
    """Recover unique taken-arm ownership from ConditionIR and exact jumps.

    The accepted machine shape is a conditional jump to the body followed by
    an unconditional jump to the merge. This is sufficient to prove the body
    interval without source, names, rendered C, or address-specific rules.
    """
    recovered: list[DirectStackMoveBranchFact8616] = []
    for move in move_facts:
        if move.source_kind not in _BRANCH_OWNED_SOURCE_KINDS_8616:
            continue
        candidates: list[DirectStackMoveBranchFact8616] = []
        for condition in conditions:
            condition_addr = condition.src_insn
            arm_start = condition.taken_target
            fallthrough = condition.fallthrough_target
            if (
                not isinstance(condition_addr, int)
                or not isinstance(arm_start, int)
                or not isinstance(fallthrough, int)
            ):
                continue
            merge_addr = instruction_targets.get(fallthrough)
            if not isinstance(merge_addr, int):
                continue
            if arm_start <= move.ins_addr < merge_addr:
                candidates.append(
                    DirectStackMoveBranchFact8616(
                        move_ins_addr=move.ins_addr,
                        condition_ins_addr=condition_addr,
                        condition_producer_insn=condition.producer_insn,
                        arm=DirectStackMoveBranchArm8616.TAKEN,
                        arm_start=arm_start,
                        merge_addr=merge_addr,
                    )
                )
        if not candidates:
            continue
        smallest_span = min(candidate.merge_addr - candidate.arm_start for candidate in candidates)
        innermost = tuple(
            candidate
            for candidate in candidates
            if candidate.merge_addr - candidate.arm_start == smallest_span
        )
        if len(innermost) == 1:
            recovered.append(innermost[0])
    return tuple(recovered)


def _node_tag_addresses_8616(node: object) -> frozenset[int]:
    """Return instruction-origin addresses attached to one angr C node."""
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return frozenset()
    return frozenset(
        value
        for value in (
            tags.get("ins_addr"),
            tags.get("inertia_relocated_from_ins_addr"),
        )
        if isinstance(value, int)
    )


def _tree_tag_addresses_8616(root: object) -> frozenset[int]:
    """Collect instruction-origin tags from one structured expression tree."""
    addresses: set[int] = set()
    seen: set[int] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        if isinstance(node, (list, tuple)):
            stack.extend(node)
            continue
        seen.add(id(node))
        addresses.update(_node_tag_addresses_8616(node))
        for attribute in (
            "lhs",
            "rhs",
            "operand",
            "expr",
            "condition",
            "cond",
            "body",
            "else_node",
            "statements",
        ):
            child = getattr(node, attribute, None)
            if child is not None:
                stack.append(child)
        for attribute in ("args", "operands"):
            children = getattr(node, attribute, None)
            if children:
                stack.extend(_boundary_tuple_8616(children))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for condition, body in _boundary_tuple_8616(pairs):
                stack.extend((condition, body))
    return frozenset(addresses)


def _statement_lists_8616(root: object) -> tuple[list[Any], ...]:
    """Return all mutable statement lists below one structured-C root."""
    result: list[list[Any]] = []
    seen: set[int] = set()

    def visit(node: object) -> None:
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            result.append(statements)
            for statement in tuple(statements):
                visit(statement)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in _boundary_tuple_8616(pairs):
                visit(body)
        for attribute in ("body", "else_node"):
            visit(getattr(node, attribute, None))

    visit(root)
    return tuple(result)


def _stack_variable_offset_8616(node: object) -> int | None:
    """Return the canonical BP-relative offset of one typed C variable."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return None
    offset = variable.offset
    if not isinstance(offset, int):
        return None
    return offset - 0x10000 if offset >= 0x8000 else offset


def _assignment_matches_stack_move_fact_8616(
    assignment: object,
    fact: DirectStackMoveBranchFact8616,
    move_fact: DirectStackMoveFact8616,
) -> bool:
    """Join a tagless typed assignment to one exact stack-store fact."""
    if (
        not isinstance(assignment, structured_c.CAssignment)
        or _stack_variable_offset_8616(assignment.lhs) != move_fact.dst_offset
        or fact.move_ins_addr != move_fact.ins_addr
    ):
        return False
    if move_fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT:
        return isinstance(move_fact.source_offset, int) and (
            _stack_variable_offset_8616(assignment.rhs) == move_fact.source_offset
        )
    return bool(
        move_fact.source_kind is DirectStackMoveSourceKind8616.IMMEDIATE
        and isinstance(move_fact.source_value, int)
        and isinstance(assignment.rhs, structured_c.CConstant)
        and isinstance(assignment.rhs.value, int)
        and (assignment.rhs.value & ((1 << (move_fact.width * 8)) - 1)) == move_fact.source_value
    )


def _condition_branch_site_8616(
    root: object,
    project: object,
    fact: DirectStackMoveBranchFact8616,
    replay_facts: tuple[StructuringConditionReplayFact8616, ...],
) -> _DirectStackMovePlacementSite8616 | None:
    """Find the unique rendered arm or guarded fallthrough for a taken range."""
    candidates: list[_DirectStackMovePlacementSite8616] = []
    seen: set[int] = set()
    move_addresses = _candidate_addresses_8616(project, fact.move_ins_addr)

    def has_taken_provenance(nodes: object) -> bool:
        """Return whether nodes own non-target instructions in the taken interval."""
        for address in _tree_tag_addresses_8616(nodes):
            candidates_for_address = _candidate_addresses_8616(project, address)
            if candidates_for_address & move_addresses:
                continue
            if any(
                fact.arm_start <= candidate < fact.merge_addr
                for candidate in candidates_for_address
            ):
                return True
        return False

    def visit(
        node: object,
        owner: list[Any] | None = None,
        owner_index: int | None = None,
    ) -> None:
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for condition, body in _boundary_tuple_8616(pairs):
                addresses = _tree_tag_addresses_8616(condition)
                branch_addresses = set(_candidate_addresses_8616(project, fact.condition_ins_addr))
                if isinstance(fact.condition_producer_insn, int):
                    branch_addresses.update(
                        _candidate_addresses_8616(project, fact.condition_producer_insn)
                    )
                if addresses & branch_addresses:
                    arms = [body]
                    else_node = getattr(node, "else_node", None)
                    if else_node is not None:
                        arms.append(else_node)
                    proven_arms = [arm for arm in arms if has_taken_provenance(arm)]
                    matching_replays = tuple(
                        replay
                        for replay in replay_facts
                        if replay.root_src_insn == fact.condition_ins_addr
                    )
                    if not proven_arms and len(matching_replays) == 1:
                        replay = matching_replays[0]
                        true_is_taken = fact.arm_start <= replay.true_target < fact.merge_addr
                        false_is_taken = fact.arm_start <= replay.false_target < fact.merge_addr
                        if true_is_taken != false_is_taken:
                            replay_arm = body if true_is_taken else else_node
                            if replay_arm is not None:
                                proven_arms = [replay_arm]
                    if len(proven_arms) == 1:
                        arm_statements = getattr(proven_arms[0], "statements", None)
                        if isinstance(arm_statements, list):
                            candidates.append(
                                _DirectStackMovePlacementSite8616(
                                    arm_statements,
                                    0,
                                )
                            )
                    elif (
                        not proven_arms
                        and owner is not None
                        and isinstance(owner_index, int)
                    ):
                        start_index = owner_index + 1
                        if has_taken_provenance(owner[start_index:]):
                            candidates.append(
                                _DirectStackMovePlacementSite8616(
                                    owner,
                                    start_index,
                                )
                            )
                visit(body)
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for index, statement in enumerate(tuple(statements)):
                visit(statement, statements, index)
        for attribute in ("body", "else_node"):
            visit(getattr(node, attribute, None))

    visit(root)
    unique = {
        (id(candidate.statements), candidate.start_index): candidate
        for candidate in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _ordered_arm_insertion_index_8616(
    statements: Iterable[object],
    project: object,
    fact: DirectStackMoveBranchFact8616,
) -> int | None:
    """Return the unique instruction-ordered insertion index within one arm."""
    move_addr = fact.move_ins_addr
    ordered_statements = tuple(statements)
    insertion_index: int | None = None
    saw_after = False
    for index, statement in enumerate(ordered_statements):
        addresses = sorted(
            candidate
            for tagged_addr in _tree_tag_addresses_8616(statement)
            for candidate in _candidate_addresses_8616(project, tagged_addr)
            if fact.arm_start <= candidate < fact.merge_addr
            and candidate != move_addr
        )
        if not addresses:
            return None
        if addresses[0] < move_addr < addresses[-1]:
            return None
        if addresses[-1] < move_addr:
            if saw_after:
                return None
            continue
        if addresses[0] > move_addr:
            saw_after = True
            if insertion_index is None:
                insertion_index = index
            continue
        return None
    return len(ordered_statements) if insertion_index is None else insertion_index


def place_direct_stack_move_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> bool:
    """Place one Lowering-built assignment at its unique CFG-proven site."""
    conditions = tuple(
        condition
        for condition in _boundary_tuple_8616(
            getattr(codegen, "_inertia_typed_conditions", ()) or ()
        )
        if isinstance(condition, ConditionIR)
    )
    branch_facts = recover_direct_stack_move_branch_facts_8616(
        conditions,
        (move_fact,),
        direct_stack_move_instruction_targets_8616(project, function, conditions),
    )
    if len(branch_facts) != 1:
        return False
    fact = branch_facts[0]
    cfunc = getattr(codegen, "cfunc", None)
    placement_site = _condition_branch_site_8616(
        root=getattr(cfunc, "statements", None),
        project=project,
        fact=fact,
        replay_facts=condition_replay_facts_8616(codegen),
    )
    if placement_site is None:
        return False
    target_statements = placement_site.statements
    relative_index = _ordered_arm_insertion_index_8616(
        target_statements[placement_site.start_index :],
        project,
        fact,
    )
    if relative_index is None:
        return False
    target_statements.insert(placement_site.start_index + relative_index, assignment)
    return True


def _transparent_assignment_8616(statement: object) -> structured_c.CAssignment | None:
    """Return an assignment through angr's transparent statement wrapper."""
    if isinstance(statement, structured_c.CExpressionStatement):
        statement = statement.expr
    return statement if isinstance(statement, structured_c.CAssignment) else None


def materialize_direct_stack_move_branch_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> bool:
    """Relocate tagged stack assignments into CFG-proven conditional arms."""
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None)
    conditions = tuple(
        condition
        for condition in _boundary_tuple_8616(
            getattr(codegen, "_inertia_typed_conditions", ()) or ()
        )
        if isinstance(condition, ConditionIR)
    )
    move_facts = tuple(
        fact
        for fact in _boundary_tuple_8616(
            getattr(codegen, "_inertia_direct_stack_move_facts_8616", ()) or ()
        )
        if isinstance(fact, DirectStackMoveFact8616)
        and fact.source_kind in _BRANCH_OWNED_SOURCE_KINDS_8616
    )
    if root is None or not conditions or not move_facts:
        return False
    branch_facts = recover_direct_stack_move_branch_facts_8616(
        conditions,
        move_facts,
        direct_stack_move_instruction_targets_8616(project, function, conditions),
    )
    changed = False
    materialized = 0
    already_materialized = 0
    failures = 0
    for fact in branch_facts:
        matching_move_facts = tuple(
            move_fact
            for move_fact in move_facts
            if move_fact.ins_addr == fact.move_ins_addr
        )
        if len(matching_move_facts) != 1:
            failures += 1
            continue
        move_fact = matching_move_facts[0]
        placement_site = _condition_branch_site_8616(
            root,
            project,
            fact,
            condition_replay_facts_8616(codegen),
        )
        if placement_site is None:
            failures += 1
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[direct-stack-move-branch] no-target move=%#x condition=%#x producer=%r",
                    fact.move_ins_addr,
                    fact.condition_ins_addr,
                    fact.condition_producer_insn,
                )
            continue
        target_statements = placement_site.statements
        candidate_addrs = _candidate_addresses_8616(project, fact.move_ins_addr)
        locations = [
            (statements, index, statement)
            for statements in _statement_lists_8616(root)
            for index, statement in enumerate(tuple(statements))
            if (
                (assignment := _transparent_assignment_8616(statement))
                is not None
                and _assignment_matches_stack_move_fact_8616(
                    assignment,
                    fact,
                    move_fact,
                )
                and bool(_tree_tag_addresses_8616(statement) & candidate_addrs)
            )
        ]
        if not locations:
            locations = [
                (statements, index, statement)
                for statements in _statement_lists_8616(root)
                for index, statement in enumerate(tuple(statements))
                if (
                    (assignment := _transparent_assignment_8616(statement))
                    is not None
                    and _assignment_matches_stack_move_fact_8616(
                        assignment,
                        fact,
                        move_fact,
                    )
                )
            ]
        if len(locations) != 1:
            failures += 1
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[direct-stack-move-branch] assignment-count move=%#x count=%d",
                    fact.move_ins_addr,
                    len(locations),
                )
            continue
        owner, index, assignment = locations[0]
        ordered_target = tuple(
            statement
            for statement in target_statements[placement_site.start_index :]
            if statement is not assignment
        )
        relative_insertion_index = _ordered_arm_insertion_index_8616(
            ordered_target,
            project,
            fact,
        )
        if relative_insertion_index is None:
            failures += 1
            continue
        insertion_index = placement_site.start_index + relative_insertion_index
        if owner is target_statements and index == insertion_index:
            already_materialized += 1
            materialized += 1
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[direct-stack-move-branch] already move=%#x assignment=%r target=%r",
                    fact.move_ins_addr,
                    assignment,
                    target_statements,
                )
            continue
        del owner[index]
        if owner is target_statements and index < insertion_index:
            insertion_index -= 1
        target_statements.insert(insertion_index, assignment)
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-branch] moved move=%#x assignment=%r target=%r",
                fact.move_ins_addr,
                assignment,
                target_statements,
            )
        materialized += 1
        changed = True
    stats = DirectStackMoveBranchStats8616(
        raw_fact_count=len(move_facts),
        normalized_fact_count=len(branch_facts),
        classified_fact_count=len(branch_facts),
        materialized_count=materialized,
        failure_count=failures,
        already_materialized_count=already_materialized,
    )
    cast(Any, codegen)._inertia_direct_stack_move_branch_placement_8616 = stats
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning("[direct-stack-move-branch] stats=%r facts=%r", stats, branch_facts)
    with contextlib.suppress(Exception):
        cfunc.body = root
    with contextlib.suppress(Exception):
        cfunc.statements = root
    with contextlib.suppress(Exception):
        cfunc.stmt = root
    return changed
