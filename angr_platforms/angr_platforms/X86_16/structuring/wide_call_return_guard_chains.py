"""Consume redundant guards after a proven wide call-return comparison.

Layer: Structuring
Responsibility:
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here

This module collapses a nested exit guard only when typed ConditionIR proves
that the outer predicate already covers the complete DX:AX comparison chain.
This module does not recover call, type, alias, or comparison semantics from
rendered C, assembly text, source files, or helper names.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, TypeAlias

from angr.analyses.decompiler.structured_codegen.c import (
    CExpression,
    CFunctionCall,
    CIfElse,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import ConditionIR
from ..pipeline.errors import PipelineHardError
from .branch_return_expressions import sole_return_statement_8616

DirectInstructionAddress8616: TypeAlias = Callable[[object], int | None]
SameExpression8616: TypeAlias = Callable[[CExpression, CExpression], bool]


class WideCallReturnGuardCollapseStatus8616(str, Enum):
    """Typed outcome of one wide call-return nested-guard inspection."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED = "refused"
    MATERIALIZED = "materialized"


class WideCallReturnGuardCollapseReason8616(str, Enum):
    """Typed reason for accepting, refusing, or ignoring one candidate."""

    ELSE_HAS_NO_STATEMENT = "else_has_no_statement"
    ELSE_STATEMENT_NOT_IF = "else_statement_not_if"
    NESTED_SOURCE_OUTSIDE_CHAIN = "nested_source_outside_chain"
    UNSUPPORTED_BRANCH_SHAPE = "unsupported_branch_shape"
    SIDE_EFFECTING_NESTED_CONDITION = "side_effecting_nested_condition"
    EXIT_BODY_NOT_RETURN = "exit_body_not_return"
    EXIT_RETURNS_DIFFER = "exit_returns_differ"
    IDENTICAL_EXIT_RETURN = "identical_exit_return"


@dataclass(frozen=True, slots=True)
class WideCallReturnGuardCollapseStats8616:
    """Closed evidence counts for nested wide call-return guard collapse."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def merged(
        self,
        other: WideCallReturnGuardCollapseStats8616,
    ) -> WideCallReturnGuardCollapseStats8616:
        """Return the field-wise sum of two evidence reports."""
        return WideCallReturnGuardCollapseStats8616(
            raw_fact_count=self.raw_fact_count + other.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count + other.normalized_fact_count,
            classified_fact_count=self.classified_fact_count + other.classified_fact_count,
            materialized_count=self.materialized_count + other.materialized_count,
            failure_count=self.failure_count + other.failure_count,
        )


@dataclass(frozen=True, slots=True)
class WideCallReturnGuardCollapseResult8616:
    """Outcome and evidence report for one structured guard candidate."""

    status: WideCallReturnGuardCollapseStatus8616
    reason: WideCallReturnGuardCollapseReason8616
    stats: WideCallReturnGuardCollapseStats8616


def _result_8616(
    status: WideCallReturnGuardCollapseStatus8616,
    reason: WideCallReturnGuardCollapseReason8616,
    *,
    normalized: int = 0,
    classified: int = 0,
    materialized: int = 0,
) -> WideCallReturnGuardCollapseResult8616:
    """Build one closed evidence result for an exact typed candidate."""
    raw = int(status is not WideCallReturnGuardCollapseStatus8616.NOT_APPLICABLE)
    stats = WideCallReturnGuardCollapseStats8616(
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=max(0, raw - materialized),
    )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified wide call-return nested guard was not materialized"
        )
    return WideCallReturnGuardCollapseResult8616(
        status=status,
        reason=reason,
        stats=stats,
    )


def collapse_wide_call_return_guard_chain_8616(
    node: CIfElse,
    conditions: tuple[ConditionIR, ConditionIR, ConditionIR],
    direct_instruction_address: DirectInstructionAddress8616,
    same_expression: SameExpression8616,
) -> WideCallReturnGuardCollapseResult8616:
    """Collapse one chain-internal duplicate exit guard after complete proof."""
    else_node = node.else_node
    if not isinstance(else_node, CStatements) or not else_node.statements:
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.NOT_APPLICABLE,
            WideCallReturnGuardCollapseReason8616.ELSE_HAS_NO_STATEMENT,
        )
    else_statements = tuple(else_node.statements)
    nested = else_statements[0]
    if not isinstance(nested, CIfElse):
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.NOT_APPLICABLE,
            WideCallReturnGuardCollapseReason8616.ELSE_STATEMENT_NOT_IF,
        )

    nested_source = direct_instruction_address(nested)
    remainder_sources = frozenset(
        condition.src_insn
        for condition in conditions[1:]
        if isinstance(condition.src_insn, int)
    )
    if nested_source not in remainder_sources:
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.NOT_APPLICABLE,
            WideCallReturnGuardCollapseReason8616.NESTED_SOURCE_OUTSIDE_CHAIN,
        )
    if (
        len(node.condition_and_nodes) != 1
        or len(nested.condition_and_nodes) != 1
    ):
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.REFUSED,
            WideCallReturnGuardCollapseReason8616.UNSUPPORTED_BRANCH_SHAPE,
        )
    if nested.else_node is not None:
        if len(else_statements) != 1:
            return _result_8616(
                WideCallReturnGuardCollapseStatus8616.REFUSED,
                WideCallReturnGuardCollapseReason8616.UNSUPPORTED_BRANCH_SHAPE,
            )
        continuation = nested.else_node
    else:
        if len(else_statements) != 2:
            return _result_8616(
                WideCallReturnGuardCollapseStatus8616.REFUSED,
                WideCallReturnGuardCollapseReason8616.UNSUPPORTED_BRANCH_SHAPE,
            )
        continuation = else_statements[1]

    nested_condition = nested.condition_and_nodes[0][0]
    if any(
        isinstance(child, CFunctionCall)
        for child in _iter_c_nodes_deep_8616(nested_condition)
    ):
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.REFUSED,
            WideCallReturnGuardCollapseReason8616.SIDE_EFFECTING_NESTED_CONDITION,
            normalized=1,
        )

    outer_return = sole_return_statement_8616(node.condition_and_nodes[0][1])
    nested_return = sole_return_statement_8616(nested.condition_and_nodes[0][1])
    if outer_return is None or nested_return is None:
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.REFUSED,
            WideCallReturnGuardCollapseReason8616.EXIT_BODY_NOT_RETURN,
            normalized=1,
        )
    if outer_return.retval is None or nested_return.retval is None:
        returns_match = outer_return.retval is nested_return.retval
    else:
        returns_match = same_expression(outer_return.retval, nested_return.retval)
    if not returns_match:
        return _result_8616(
            WideCallReturnGuardCollapseStatus8616.REFUSED,
            WideCallReturnGuardCollapseReason8616.EXIT_RETURNS_DIFFER,
            normalized=1,
        )

    node.else_node = continuation
    return _result_8616(
        WideCallReturnGuardCollapseStatus8616.MATERIALIZED,
        WideCallReturnGuardCollapseReason8616.IDENTICAL_EXIT_RETURN,
        normalized=1,
        classified=1,
        materialized=1,
    )
