"""Lower binary-proven fixed stack probes into recovered BP-local frame objects.

Layer: Types/Lowering.
Responsibility: remove an unused standalone compiler stack-probe call only when
typed callsite evidence proves a fixed allocation covered by recovered BP locals.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: helper-name matching, source/COD evidence, rendered-C matching, or
removing dynamic probes and used helper return values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616
from ..pipeline.errors import PipelineHardError

__all__ = [
    "FixedStackProbeFrameLoweringStats8616",
    "lower_fixed_stack_probe_frames_8616",
]


@dataclass(frozen=True, slots=True)
class FixedStackProbeFrameLoweringStats8616:
    """Closed evidence census for fixed stack-probe frame lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    refused_fact_count: int
    recovered_frame_extent: int

    @property
    def changed(self) -> bool:
        """Return whether at least one compiler probe statement was removed."""
        return self.materialized_count > 0


def _dynamic_codegen_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read optional metadata across the dynamic third-party angr codegen boundary."""
    return getattr(obj, name, default)


def _structured_root_8616(codegen: object) -> object | None:
    """Return the live structured C root across supported angr codegen shapes."""
    cfunc = _dynamic_codegen_attr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return None
    statements = _dynamic_codegen_attr_8616(cfunc, "statements", None)
    if statements is not None:
        return statements
    return _dynamic_codegen_attr_8616(cfunc, "body", None)


def _recovered_bp_frame_extent_8616(root: object) -> int:
    """Return the deepest live negative BP-local offset represented in the C AST."""
    extent = 0
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, CVariable):
            continue
        variable = node.variable
        if not isinstance(variable, SimStackVariable):
            continue
        offset = variable.offset
        if isinstance(offset, int) and offset < 0:
            extent = max(extent, -offset)
    return extent


def _standalone_call_8616(statement: object) -> CFunctionCall | None:
    """Return a direct standalone call without interpreting its rendered name."""
    if not isinstance(statement, CExpressionStatement):
        return None
    expression = statement.expr
    return expression if isinstance(expression, CFunctionCall) else None


def _statement_containers_8616(root: object) -> tuple[CStatements, ...]:
    """Return each mutable statement container in deterministic tree order."""
    containers: list[CStatements] = []
    seen_ids: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, CStatements) or id(node) in seen_ids:
            continue
        seen_ids.add(id(node))
        containers.append(node)
    return tuple(containers)


def lower_fixed_stack_probe_frames_8616(codegen: object) -> FixedStackProbeFrameLoweringStats8616:
    """Remove only fixed, unused probe calls represented by recovered BP locals."""
    root = _structured_root_8616(codegen)
    summary_map_raw = _dynamic_codegen_attr_8616(codegen, "_inertia_callsite_summaries", None)
    summary_map = (
        {
            node_id: summary
            for node_id, summary in summary_map_raw.items()
            if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
        }
        if isinstance(summary_map_raw, dict)
        else {}
    )
    probe_summaries = {
        node_id: summary
        for node_id, summary in summary_map.items()
        if summary.stack_probe_helper
    }
    raw_fact_count = len(probe_summaries)
    frame_extent = _recovered_bp_frame_extent_8616(root) if root is not None else 0
    standalone_occurrences: dict[int, int] = {}
    live_call_ids: set[int] = set()
    containers = _statement_containers_8616(root) if root is not None else ()
    for container in containers:
        for statement in tuple(container.statements or ()):
            call = _standalone_call_8616(statement)
            if call is not None:
                call_id = id(call)
                live_call_ids.add(call_id)
                standalone_occurrences[call_id] = standalone_occurrences.get(call_id, 0) + 1
        for node in _iter_c_nodes_deep_8616(container):
            if isinstance(node, CFunctionCall):
                live_call_ids.add(id(node))

    normalized_fact_count = sum(node_id in live_call_ids for node_id in probe_summaries)
    classified_ids: set[int] = set()
    for node_id, summary in probe_summaries.items():
        allocation_size = summary.stack_probe_allocation_size
        if standalone_occurrences.get(node_id) != 1:
            continue
        if summary.arg_count != 0 or summary.stack_cleanup not in {None, 0}:
            continue
        if summary.return_used is not False:
            continue
        if not isinstance(allocation_size, int) or allocation_size <= 0:
            continue
        if frame_extent < allocation_size:
            continue
        classified_ids.add(node_id)

    removed_ids: set[int] = set()
    for container in containers:
        statements = list(container.statements or ())
        retained: list[object] = []
        for statement in statements:
            call = _standalone_call_8616(statement)
            if call is not None and id(call) in classified_ids:
                if tuple(call.args or ()):
                    retained.append(statement)
                    continue
                removed_ids.add(id(call))
                continue
            retained.append(statement)
        if len(retained) != len(statements):
            cast(Any, container).statements = retained

    materialized_count = len(classified_ids & removed_ids)
    failure_count = len(classified_ids - removed_ids)
    stats = FixedStackProbeFrameLoweringStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=len(classified_ids),
        materialized_count=materialized_count,
        failure_count=failure_count,
        refused_fact_count=raw_fact_count - len(classified_ids),
        recovered_frame_extent=frame_extent,
    )
    cast(Any, codegen)._inertia_fixed_stack_probe_frame_lowering_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("fixed stack-probe facts were classified but not materialized")
    return stats
