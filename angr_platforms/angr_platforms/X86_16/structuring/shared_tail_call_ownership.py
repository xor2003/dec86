"""CFG-proven ownership for duplicated calls at structured shared tails.

Layer: Structuring.
Responsibility: remove synthetic returned-call AST clones only when one exact
machine callsite is retained at its proven common CFG tail.

This pass consumes callsite summaries and CFG topology. It does not infer call
arguments, return types, alias identity, or semantics from rendered C.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _same_c_expression_8616
from ..callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616
from ..pipeline.errors import PipelineHardError
from .shared_tail_cfg_topology import (
    SharedTailCfgTopology8616,
    recover_shared_tail_cfg_topology_8616,
    shared_callsite_tail_is_proven_8616,
)
from .shared_tail_structured_ancestry import (
    SharedTailCallOccurrence8616,
    SharedTailCallOccurrenceKind8616,
    collect_shared_tail_call_occurrences_8616,
    standalone_follows_nested_clone_8616,
)

__all__ = (
    "SharedTailCallOwnershipResult8616",
    "SharedTailCallOwnershipStats8616",
    "SharedTailCallOwnershipStatus8616",
    "materialize_shared_tail_call_ownership_8616",
)


class SharedTailCallOwnershipStatus8616(Enum):
    """Typed outcome for one shared-tail call ownership pass."""

    NO_CANDIDATE = "no_candidate"
    MATERIALIZED = "materialized"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SharedTailCallOwnershipStats8616:
    """Closed evidence counters for shared-tail call ownership."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class SharedTailCallOwnershipResult8616:
    """Immutable pass result retained on the codegen boundary."""

    status: SharedTailCallOwnershipStatus8616
    stats: SharedTailCallOwnershipStats8616
    refusal_reasons: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """Return whether at least one synthetic call clone was removed."""
        return self.stats.materialized_count > 0


class _CFunctionSurface8616(Protocol):
    """Third-party C-function fields consumed by this pass."""

    addr: int
    statements: object


class _CodegenSurface8616(Protocol):
    """Codegen metadata boundary consumed and published by this pass."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_shared_tail_call_ownership_result_8616: SharedTailCallOwnershipResult8616


def _owned_callsite_addr_8616(
    call: structured_c.CFunctionCall,
    summary_map: dict[int, CallsiteSummary8616],
) -> int | None:
    """Resolve one callsite from owned evidence and reject projection drift."""
    raw_tagged_addr = structured_callsite_addr_8616(call)
    if raw_tagged_addr is not None and not isinstance(raw_tagged_addr, int):
        raise TypeError("structured callsite identity must be an integer")
    tagged_addr: int | None = raw_tagged_addr
    summary = summary_map.get(id(call))
    if summary is None:
        return tagged_addr
    if not isinstance(summary, CallsiteSummary8616):
        raise TypeError("shared-tail call identity requires a typed callsite summary")
    summary_addr = summary.callsite_addr
    if not isinstance(summary_addr, int):
        raise TypeError("owned callsite summary identity must be an integer")
    if tagged_addr is not None and tagged_addr != summary_addr:
        raise PipelineHardError("structured callsite tag contradicts its owned callsite summary")
    return summary_addr


def materialize_shared_tail_call_ownership_8616(
    project: object,
    codegen: object,
) -> SharedTailCallOwnershipResult8616:
    """Remove only CFG-proven returned-call clones of one retained shared tail."""
    boundary = cast(_CodegenSurface8616, codegen)
    empty = SharedTailCallOwnershipResult8616(
        SharedTailCallOwnershipStatus8616.NO_CANDIDATE,
        SharedTailCallOwnershipStats8616(),
    )
    try:
        cfunc = boundary.cfunc
        root = cfunc.statements
        summary_map = boundary._inertia_callsite_summaries
        inventory = boundary._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return empty
    if not isinstance(root, structured_c.CStatements):
        return empty
    if not isinstance(summary_map, dict) or not isinstance(inventory, dict):
        raise TypeError("shared-tail call ownership requires typed callsite mappings")
    if any(
        not isinstance(callsite_addr, int)
        or not isinstance(summary, CallsiteSummary8616)
        or summary.callsite_addr != callsite_addr
        for callsite_addr, summary in inventory.items()
    ):
        raise TypeError("shared-tail callsite inventory contains an invalid owned contract")
    topology: SharedTailCfgTopology8616 | None = recover_shared_tail_cfg_topology_8616(
        project,
        cfunc.addr,
    )
    occurrences_by_callsite: dict[int, list[SharedTailCallOccurrence8616]] = {}
    for occurrence in collect_shared_tail_call_occurrences_8616(root):
        callsite_addr = _owned_callsite_addr_8616(occurrence.call, summary_map)
        if isinstance(callsite_addr, int):
            occurrences_by_callsite.setdefault(callsite_addr, []).append(occurrence)

    raw_count = normalized_count = classified_count = materialized_count = failure_count = 0
    refusals: list[str] = []
    removals: list[SharedTailCallOccurrence8616] = []
    for callsite_addr, occurrences in sorted(occurrences_by_callsite.items()):
        returned = tuple(
            item for item in occurrences if item.kind is SharedTailCallOccurrenceKind8616.RETURNED
        )
        standalone = tuple(
            item for item in occurrences if item.kind is SharedTailCallOccurrenceKind8616.STANDALONE
        )
        returned_clone_shape = bool(returned and standalone)
        nested_standalone_shape = not returned and len(standalone) > 1
        if not returned_clone_shape and not nested_standalone_shape:
            continue
        raw_count += 1
        summary = inventory.get(callsite_addr)
        if summary is None or topology is None:
            failure_count += 1
            refusals.append(f"callsite={callsite_addr:#x}:incomplete-census")
            continue
        normalized_count += 1
        if not shared_callsite_tail_is_proven_8616(summary, topology):
            failure_count += 1
            refusals.append(f"callsite={callsite_addr:#x}:not-proven-shared-cfg-tail")
            continue
        retained: SharedTailCallOccurrence8616 | None
        clones: tuple[SharedTailCallOccurrence8616, ...]
        if returned_clone_shape and len(standalone) == 1:
            retained = standalone[0]
            clones = returned
            ownership_proven = all(
                standalone_follows_nested_clone_8616(item, retained) for item in clones
            )
        elif nested_standalone_shape and summary.return_used is False:
            retained_candidates = tuple(
                candidate
                for candidate in standalone
                if all(
                    other is candidate
                    or (
                        standalone_follows_nested_clone_8616(other, candidate)
                        and _same_c_expression_8616(candidate.call, other.call)
                    )
                    for other in standalone
                )
            )
            retained = retained_candidates[0] if len(retained_candidates) == 1 else None
            clones = tuple(item for item in standalone if item is not retained)
            ownership_proven = retained is not None and bool(clones)
        else:
            retained = None
            clones = ()
            ownership_proven = False
        if not ownership_proven:
            failure_count += 1
            refusals.append(f"callsite={callsite_addr:#x}:ast-ownership-conflict")
            continue
        classified_count += len(clones)
        removals.extend(clones)

    for occurrence in sorted(
        removals,
        key=lambda item: (id(item.parent), item.statement_index),
        reverse=True,
    ):
        statements = occurrence.parent.statements
        if (
            not isinstance(statements, list)
            or occurrence.statement_index >= len(statements)
            or statements[occurrence.statement_index] is not occurrence.statement
        ):
            raise PipelineHardError("classified shared-tail call clone lost its AST owner")
        del statements[occurrence.statement_index]
        summary_map.pop(id(occurrence.call), None)
        materialized_count += 1

    stats = SharedTailCallOwnershipStats8616(
        raw_count,
        normalized_count,
        classified_count,
        materialized_count,
        failure_count,
    )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified shared-tail call ownership was not materialized")
    status = (
        SharedTailCallOwnershipStatus8616.MATERIALIZED
        if materialized_count
        else SharedTailCallOwnershipStatus8616.UNKNOWN_REFUSE
        if failure_count
        else SharedTailCallOwnershipStatus8616.NO_CANDIDATE
    )
    result = SharedTailCallOwnershipResult8616(status, stats, tuple(refusals))
    boundary._inertia_shared_tail_call_ownership_result_8616 = result
    return result
