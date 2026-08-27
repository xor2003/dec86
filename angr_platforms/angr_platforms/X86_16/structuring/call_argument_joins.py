"""Bind proven branch-carried register joins to existing call arguments.

Layer: Structuring.
Responsibility: consume Alias-owned predecessor register-join facts by binding
an already structured branch carrier to the matching physical call argument.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Alias supplies register sources, Types/Lowering supplies callsite summaries,
and angr supplies the existing branch. Ambiguous evidence is refused.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpression,
    CFunctionCall,
)
from angr.sim_type import SimTypeShort

from ..alias.callsite_stack_merge import CallsiteRegisterJoin8616
from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..callsite_summary import (
    CallsiteSummary8616,
    callsite_summary_inventory_8616,
    structured_callsite_addr_8616,
)
from ..pipeline.errors import PipelineHardError
from .call_argument_branch_carriers import (
    branch_dominates_call_8616,
    unique_branch_carrier_8616,
)
from .call_argument_join_conditions import (
    conditional_call_argument_join_expression_8616,
    exact_call_argument_immediate_8616,
)
from .call_argument_path_joins import (
    CallArgumentPathJoinDecision8616,
    materialize_call_argument_path_join_8616,
)

__all__ = [
    "CallArgumentJoinDecision8616",
    "CallArgumentJoinStats8616",
    "materialize_call_argument_joins_8616",
]


class _CallArgumentJoinCFunction8616(Protocol):
    """Structured function root consumed across the angr boundary."""

    statements: object


class _CallArgumentJoinCodegen8616(Protocol):
    """Owned evidence fields consumed and produced by this pass."""

    cfunc: _CallArgumentJoinCFunction8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_call_argument_join_stats_8616: CallArgumentJoinStats8616


class CallArgumentJoinDecision8616(StrEnum):
    """Typed result for one branch-carried call-argument fact."""

    MATERIALIZED = "materialized"
    ALREADY_MATERIALIZED = "already-materialized"
    REFUSED_CALL_IDENTITY = "refused-call-identity"
    REFUSED_EVIDENCE = "refused-evidence"
    REFUSED_BRANCH = "refused-branch"
    REFUSED_CONDITION = "refused-condition"
    REFUSED_ORDER = "refused-order"


@dataclass(frozen=True, slots=True)
class CallArgumentJoinStats8616:
    """Closed evidence accounting for branch-carried call arguments."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    decisions: tuple[CallArgumentJoinDecision8616, ...] = ()


@dataclass(frozen=True, slots=True)
class _NormalizedJoin8616:
    """Exact physical call layout accepted from upstream typed evidence."""

    join: CallsiteRegisterJoin8616
    join_lane: int
    immediate_values: tuple[int, ...]


def _normalize_join_8616(summary: CallsiteSummary8616) -> _NormalizedJoin8616 | None:
    """Validate that one summary completely describes a binary register join."""
    merge = summary.predecessor_stack_merge
    if merge is None or merge.register_join is None:
        return None
    join = merge.register_join
    if (
        join.raw_fact_count != 2
        or join.normalized_fact_count != 2
        or join.classified_fact_count != 1
        or join.materialized_count != 1
        or join.failure_count != 0
        or len(join.traces) != 2
    ):
        return None
    trace_values = tuple(exact_call_argument_immediate_8616(trace.source) for trace in join.traces)
    if any(value is None for value in trace_values):
        return None
    immediate_values = cast(tuple[int, ...], trace_values)
    if len(set(immediate_values)) != 2:
        return None
    widths = summary.arg_widths
    sources = summary.push_arg_sources
    addresses = summary.push_arg_instruction_addrs
    if not widths or len(widths) != len(sources) or len(widths) != len(addresses):
        return None
    if any(width != 2 for width in widths):
        return None
    join_lanes = tuple(index for index, address in enumerate(addresses) if address == join.push_instruction_addr)
    if len(join_lanes) != 1:
        return None
    join_lane = join_lanes[0]
    if sources[join_lane] is not None:
        return None
    if any(
        index != join_lane and exact_call_argument_immediate_8616(source) is None
        for index, source in enumerate(sources)
    ):
        return None
    return _NormalizedJoin8616(join, join_lane, immediate_values)


def _expected_arguments_8616(
    summary: CallsiteSummary8616,
    normalized: _NormalizedJoin8616,
    join_expression: CExpression,
    codegen: object,
) -> tuple[object, ...] | None:
    """Build C-order arguments from exact physical PUSH-order evidence."""
    physical: list[object] = []
    for index, source in enumerate(summary.push_arg_sources):
        if index == normalized.join_lane:
            physical.append(join_expression)
            continue
        value = exact_call_argument_immediate_8616(source)
        if value is None:
            return None
        physical.append(CConstant(value, SimTypeShort(False), codegen=codegen))
    return tuple(reversed(physical))


def materialize_call_argument_joins_8616(project: object, codegen: object) -> bool:
    """Bind exact Alias register joins to unique existing structured calls."""
    typed_codegen = cast(_CallArgumentJoinCodegen8616, codegen)
    try:
        root = typed_codegen.cfunc.statements
        summary_map = typed_codegen._inertia_callsite_summaries
    except (AttributeError, TypeError):
        return False
    if not isinstance(summary_map, dict):
        raise TypeError("structured callsite summary map must be a dict")
    summary_inventory = callsite_summary_inventory_8616(typed_codegen)

    grouped: dict[int, list[tuple[CFunctionCall, CallsiteSummary8616]]] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summary_map.get(id(node))
        if not isinstance(summary, CallsiteSummary8616):
            callsite_addr = structured_callsite_addr_8616(node)
            summary = summary_inventory.get(callsite_addr) if callsite_addr is not None else None
        if not isinstance(summary, CallsiteSummary8616):
            continue
        merge = summary.predecessor_stack_merge
        if merge is None or (merge.register_join is None and not merge.traces):
            continue
        grouped.setdefault(summary.callsite_addr, []).append((node, summary))

    raw = normalized_count = classified = materialized = failed = 0
    changed = False
    decisions: list[CallArgumentJoinDecision8616] = []
    for pairs in grouped.values():
        raw += 1
        if len(pairs) != 1:
            failed += 1
            decisions.append(CallArgumentJoinDecision8616.REFUSED_CALL_IDENTITY)
            continue
        call, summary = pairs[0]
        path_result = materialize_call_argument_path_join_8616(
            project,
            codegen,
            call,
            summary,
        )
        if path_result.decision is not CallArgumentPathJoinDecision8616.NOT_APPLICABLE:
            normalized_count += path_result.normalized_fact_count
            classified += path_result.classified_fact_count
            materialized += path_result.materialized_count
            failed += path_result.failure_count
            changed |= path_result.changed
            decisions.append(
                {
                    CallArgumentPathJoinDecision8616.MATERIALIZED: CallArgumentJoinDecision8616.MATERIALIZED,
                    CallArgumentPathJoinDecision8616.ALREADY_MATERIALIZED: CallArgumentJoinDecision8616.ALREADY_MATERIALIZED,
                    CallArgumentPathJoinDecision8616.REFUSED_CONDITION: CallArgumentJoinDecision8616.REFUSED_CONDITION,
                    CallArgumentPathJoinDecision8616.REFUSED_EVIDENCE: CallArgumentJoinDecision8616.REFUSED_EVIDENCE,
                }[path_result.decision]
            )
            continue
        normalized = _normalize_join_8616(summary)
        if normalized is None:
            failed += 1
            decisions.append(CallArgumentJoinDecision8616.REFUSED_EVIDENCE)
            continue
        normalized_count += 1
        values = cast(tuple[int, int], normalized.immediate_values)
        branch_carrier = unique_branch_carrier_8616(root, values)
        join_expression: CExpression | None = None
        refusal = CallArgumentJoinDecision8616.REFUSED_BRANCH
        if branch_carrier is not None:
            branch, carrier = branch_carrier
            if branch_dominates_call_8616(root, branch, carrier, call):
                join_expression = carrier
            else:
                refusal = CallArgumentJoinDecision8616.REFUSED_ORDER
        if join_expression is None:
            join_expression = conditional_call_argument_join_expression_8616(
                project,
                codegen,
                normalized.join,
            )
            if join_expression is None and branch_carrier is None:
                refusal = CallArgumentJoinDecision8616.REFUSED_CONDITION
        if join_expression is None:
            failed += 1
            decisions.append(refusal)
            continue
        expected = _expected_arguments_8616(summary, normalized, join_expression, codegen)
        classified += 1
        if expected is None:
            failed += 1
            decisions.append(CallArgumentJoinDecision8616.REFUSED_EVIDENCE)
            continue
        existing = tuple(call.args or ())
        if len(existing) == len(expected) and all(
            _same_c_expression_8616(lhs, rhs) for lhs, rhs in zip(existing, expected, strict=True)
        ):
            materialized += 1
            decisions.append(CallArgumentJoinDecision8616.ALREADY_MATERIALIZED)
            continue
        call.args = list(expected)
        materialized += 1
        changed = True
        decisions.append(CallArgumentJoinDecision8616.MATERIALIZED)

    stats = CallArgumentJoinStats8616(
        raw,
        normalized_count,
        classified,
        materialized,
        failed,
        tuple(decisions),
    )
    typed_codegen._inertia_call_argument_join_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified branch-carried call arguments were not materialized")
    return changed
