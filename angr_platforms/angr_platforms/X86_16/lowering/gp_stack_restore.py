"""Materialize Alias-proven 16-bit GP saves and restores.

Layer: Types/Lowering.
Responsibility: consume exact stack-byte provenance and bind the structured
PUSH stores and POP register write to one coherent architectural GP lane.
Consumes Alias facts. Do not recover pairs from opcodes, assembly, names, or
rendered C text.

Dynamic boundary: angr structured-C nodes and codegen attachments expose
version-dependent child containers and tags.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from ..alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError
from .gp_register_state import runtime_gp_state_expr_8616
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_word_recomposition import recognize_stack_word_recomposition_8616

__all__ = [
    "GPStackRestoreLoweringStats8616",
    "materialize_gp_stack_restores_8616",
]


class _ArchRegisters8616(Protocol):
    """Third-party architecture register map used for physical identity."""

    registers: Mapping[str, tuple[int, int]]


class _Project8616(Protocol):
    """Project boundary required for exact register shapes."""

    arch: _ArchRegisters8616


class _CFunction8616(Protocol):
    """Structured function surface consumed by this lowering owner."""

    addr: int
    statements: object
    unified_local_vars: dict[object, object]
    variables_in_use: dict[object, object]


class _CodegenBoundary8616(Protocol):
    """Owned attachments and third-party fields used by this pass."""

    cfunc: _CFunction8616 | None
    project: _Project8616 | None
    _inertia_stack_register_restore_artifact_8616: SegmentStackRestoreArtifact8616
    _inertia_gp_stack_restore_lowering_stats_8616: GPStackRestoreLoweringStats8616
    _inertia_gp_stack_restore_materialized_pairs_8616: frozenset[tuple[int, int, str]]
    _inertia_gp_stack_restore_snapshots_8616: tuple[structured_c.CVariable, ...]


@dataclass(frozen=True, slots=True)
class GPStackRestoreLoweringStats8616:
    """Closed evidence census for exact GP stack save/restore lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every classified fact reached a terminal lane."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
        )


def _statement_containers_8616(root: object) -> tuple[structured_c.CStatements, ...]:
    """Return deterministic structured statement containers under one root."""
    return tuple(
        {
            id(node): node
            for node in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(node, structured_c.CStatements)
        }.values()
    )


def _snapshot_insertion_point_8616(
    containers: tuple[structured_c.CStatements, ...],
    save_addr: int,
    restore_addr: int,
) -> tuple[structured_c.CStatements, int] | None:
    """Find the unique earliest structured statement following a proven save."""
    candidates: list[tuple[int, int, int, structured_c.CStatements, int]] = []
    for container in containers:
        container_addrs = tuple(
            instruction_addrs_from_node_8616(statement)
            for statement in container.statements
        )
        if not any(restore_addr in addresses for addresses in container_addrs):
            continue
        following_indices: list[tuple[int, int]] = []
        for index, statement in enumerate(container.statements):
            if not isinstance(
                statement,
                (structured_c.CAssignment, structured_c.CFunctionCall),
            ):
                continue
            statement_addrs = container_addrs[index]
            if not statement_addrs or min(statement_addrs) <= save_addr:
                continue
            following = tuple(
                address
                for address in statement_addrs
                if save_addr < address <= restore_addr
            )
            if following:
                following_indices.append((min(following), index))
        if following_indices:
            earliest_addr = min(address for address, _index in following_indices)
            insertion_index = min(
                index for address, index in following_indices if address == earliest_addr
            )
            candidates.append(
                (
                    len(container.statements),
                    len(set().union(*container_addrs)),
                    earliest_addr,
                    container,
                    insertion_index,
                )
            )
    if not candidates:
        return None
    best_score = min(candidate[:3] for candidate in candidates)
    owners = tuple(candidate for candidate in candidates if candidate[:3] == best_score)
    unique = {(id(container), index) for _addr, _span, _size, container, index in owners}
    if len(unique) != 1:
        return None
    _size, _span, _addr, container, index = owners[0]
    return container, index


def _snapshot_variable_8616(
    fact: SegmentStackRestoreFact8616,
    containers: tuple[structured_c.CStatements, ...],
    *,
    codegen: object,
    project: _Project8616,
    function_addr: int,
) -> structured_c.CVariable:
    """Build one exact two-byte stack object for the Alias-proven save range."""
    offset = min(fact.stack_offsets)
    exemplar = next(
        (
            node
            for container in containers
            for node in _iter_c_nodes_deep_8616(container)
            if isinstance(node, structured_c.CVariable)
            and isinstance(node.variable, SimStackVariable)
            and node.variable.offset == offset
        ),
        None,
    )
    base = exemplar.variable.base if exemplar is not None else "bp"
    name = exemplar.variable.name if exemplar is not None else f"local_{abs(offset):x}"
    variable = SimStackVariable(
        offset,
        2,
        base=base,
        name=name,
        region=function_addr,
    )
    value_type = SimTypeShort(False).with_arch(project.arch)
    cvar = structured_c.CVariable(variable, variable_type=value_type, codegen=codegen)
    cfunc = cast(_CodegenBoundary8616, codegen).cfunc
    if cfunc is not None:
        cfunc.unified_local_vars[variable] = {(cvar, value_type)}
        cfunc.variables_in_use[variable] = cvar
    return cvar


def _materialize_fact_8616(
    fact: SegmentStackRestoreFact8616,
    containers: tuple[structured_c.CStatements, ...],
    *,
    codegen: object,
    project: _Project8616,
    function_addr: int,
) -> bool:
    """Materialize one wide stack snapshot and consume its POP recomposition."""
    if fact.saved_instruction_addr is None or fact.saved_register is None:
        return False
    insertion = _snapshot_insertion_point_8616(
        containers,
        fact.saved_instruction_addr,
        fact.restore_instruction_addr,
    )
    source = runtime_gp_state_expr_8616(
        fact.saved_register,
        codegen=codegen,
        function_addr=function_addr,
    )
    if insertion is None or source is None:
        if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
            logging.getLogger(__name__).warning(
                "[gp-stack-restore-refusal] save=%#x restore=%#x insertion=%s source=%s statement_addrs=%s",
                fact.saved_instruction_addr,
                fact.restore_instruction_addr,
                insertion,
                source,
                tuple(
                    tuple(sorted(instruction_addrs_from_node_8616(statement)))
                    for container in containers
                    for statement in container.statements
                ),
            )
        return False
    snapshot = _snapshot_variable_8616(
        fact,
        containers,
        codegen=codegen,
        project=project,
        function_addr=function_addr,
    )
    replacement_count = 0

    def replace_restore(node: object) -> object:
        """Replace the syntax projection only inside the proven POP owner."""
        nonlocal replacement_count
        # Dynamic angr C-AST boundary: tags are the durable typed identity
        # carried through later structured-tree cloning and simplification.
        node_tags = getattr(node, "tags", None)
        restore_identity = (
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
        )
        if (
            isinstance(node, structured_c.CVariable)
            and isinstance(node_tags, dict)
            and node_tags.get("inertia_x86_16_gp_stack_restore") == restore_identity
        ):
            replacement_count += 1
            return node
        if recognize_stack_word_recomposition_8616(node) is None:
            return node
        replacement_count += 1
        replacement = copy.copy(snapshot)
        replacement.tags = {
            **(dict(node_tags) if isinstance(node_tags, dict) else {}),
            "ins_addr": fact.restore_instruction_addr,
            "inertia_x86_16_gp_stack_restore": restore_identity,
        }
        return replacement

    for container in containers:
        for statement in tuple(container.statements):
            if fact.restore_instruction_addr not in instruction_addrs_from_node_8616(statement):
                continue
            _replace_c_children_8616(statement, replace_restore)
    if replacement_count < 1:
        if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
            logging.getLogger(__name__).warning(
                "[gp-stack-restore-refusal] restore=%#x replacement_count=%d",
                fact.restore_instruction_addr,
                replacement_count,
            )
        return False
    target, index = insertion
    assignment = structured_c.CAssignment(
        copy.copy(snapshot),
        source,
        codegen=codegen,
        tags={
            "ins_addr": fact.saved_instruction_addr,
            "inertia_x86_16_gp_stack_save": (
                fact.saved_instruction_addr,
                fact.restore_instruction_addr,
                fact.saved_register,
            ),
        },
    )
    target.statements.insert(index, assignment)
    return True


def materialize_gp_stack_restores_8616(codegen: object) -> bool:
    """Materialize every Alias-proven 16-bit GP stack restoration fact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    empty = GPStackRestoreLoweringStats8616(0, 0, 0, 0, 0)
    try:
        artifact = boundary._inertia_stack_register_restore_artifact_8616
    except AttributeError:
        boundary._inertia_gp_stack_restore_lowering_stats_8616 = empty
        return False
    cfunc = boundary.cfunc
    project = boundary.project
    if (
        not isinstance(artifact, SegmentStackRestoreArtifact8616)
        or cfunc is None
        or project is None
    ):
        boundary._inertia_gp_stack_restore_lowering_stats_8616 = empty
        return False
    facts = tuple(
        fact
        for fact in artifact.facts
        if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    )
    containers = _statement_containers_8616(cfunc.statements)
    live_assignments = tuple(
        statement
        for container in containers
        for statement in container.statements
        if isinstance(statement, structured_c.CAssignment)
        and isinstance(statement.tags, dict)
        and isinstance(statement.tags.get("inertia_x86_16_gp_stack_save"), tuple)
    )
    completed_pairs = {
        statement.tags["inertia_x86_16_gp_stack_save"]
        for statement in live_assignments
    }
    snapshots = [
        statement.lhs
        for statement in live_assignments
        if isinstance(statement.lhs, structured_c.CVariable)
    ]
    newly_materialized = 0
    for fact in facts:
        assert fact.saved_instruction_addr is not None
        key = (
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
        )
        if key in completed_pairs:
            continue
        if _materialize_fact_8616(
            fact,
            containers,
            codegen=codegen,
            project=project,
            function_addr=cfunc.addr,
        ):
            snapshot_offset = min(fact.stack_offsets)
            snapshots.extend(
                node
                for container in containers
                for statement in container.statements
                if isinstance(statement, structured_c.CAssignment)
                and isinstance(statement.tags, dict)
                and statement.tags.get("inertia_x86_16_gp_stack_save")
                == (
                    fact.saved_instruction_addr,
                    fact.restore_instruction_addr,
                    fact.saved_register,
                )
                for node in (statement.lhs,)
                if isinstance(node, structured_c.CVariable)
                and isinstance(node.variable, SimStackVariable)
                and node.variable.offset == snapshot_offset
            )
            completed_pairs.add(key)
            newly_materialized += 1
    materialized = sum(
        fact.saved_instruction_addr is not None
        and (
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
        )
        in completed_pairs
        for fact in facts
    )
    boundary._inertia_gp_stack_restore_materialized_pairs_8616 = frozenset(completed_pairs)
    boundary._inertia_gp_stack_restore_snapshots_8616 = tuple(
        {id(snapshot): snapshot for snapshot in snapshots}.values()
    )
    stats = GPStackRestoreLoweringStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=materialized,
        failure_count=len(facts) - materialized,
    )
    boundary._inertia_gp_stack_restore_lowering_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
        logging.getLogger(__name__).warning(
            "[gp-stack-restore-lowering] function=%#x stats=%s",
            cfunc.addr,
            stats,
        )
    if facts and materialized == 0:
        raise PipelineHardError(
            "GP stack-restore facts were classified but none materialized",
            layer="stack_lowering",
            details={
                "raw_fact_count": stats.raw_fact_count,
                "normalized_fact_count": stats.normalized_fact_count,
                "classified_fact_count": stats.classified_fact_count,
                "materialized_count": stats.materialized_count,
                "failure_count": stats.failure_count,
            },
        )
    return newly_materialized > 0
