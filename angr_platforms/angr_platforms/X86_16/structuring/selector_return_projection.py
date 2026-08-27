"""Verify selector-return projections on the structured C AST.

Layer: Structuring.
Responsibility: compare CFG-proven selector-return fingerprints with the live
structured AST before Structuring publishes its validation baseline.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This module owns projection integrity only. It does not recover conditions,
return values, aliases, or types, and it never inspects rendered C text.
Dynamic boundary: initialized Inertia metadata and angr C nodes are carried by
third-party codegen objects, so boundary reads are isolated and typed here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CIfElse, CReturn, CStatements

from ..pipeline.errors import PipelineHardError

__all__ = [
    "SelectorReturnProjectionFingerprint8616",
    "SelectorReturnProjectionIntegrity8616",
    "SelectorReturnProjectionVerdict8616",
    "assess_selector_return_projection_8616",
    "collect_selector_return_projection_8616",
    "require_selector_return_projection_8616",
]


class SelectorReturnProjectionVerdict8616(StrEnum):
    """Typed status for one Structuring-owned selector-return projection."""

    NOT_APPLICABLE = "not_applicable"
    PASSED = "passed"
    INCOMPLETE_CODEGEN_BOUNDARY = "incomplete_codegen_boundary"
    MISSING_EXPECTED_FINGERPRINTS = "missing_expected_fingerprints"
    STALE_AST_SHAPE = "stale_ast_shape"
    STALE_FINGERPRINTS = "stale_fingerprints"


@dataclass(frozen=True, slots=True)
class SelectorReturnProjectionFingerprint8616:
    """Ordered condition and return fingerprints for a flat selector chain."""

    conditions: tuple[str, ...] = ()
    returns: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SelectorReturnProjectionIntegrity8616:
    """Closed evidence result for the authoritative selector-return projection."""

    verdict: SelectorReturnProjectionVerdict8616
    expected: SelectorReturnProjectionFingerprint8616 = SelectorReturnProjectionFingerprint8616()
    observed: SelectorReturnProjectionFingerprint8616 = SelectorReturnProjectionFingerprint8616()

    @property
    def accepted(self) -> bool:
        """Return whether no active selector-return projection is stale."""
        return self.verdict in {
            SelectorReturnProjectionVerdict8616.NOT_APPLICABLE,
            SelectorReturnProjectionVerdict8616.PASSED,
        }

    @property
    def active(self) -> bool:
        """Return whether Structuring claims an authoritative selector projection."""
        return self.verdict is not SelectorReturnProjectionVerdict8616.NOT_APPLICABLE

    @property
    def raw_fact_count(self) -> int:
        """Count the materialized-projection marker consumed by this check."""
        return int(self.active)

    @property
    def normalized_fact_count(self) -> int:
        """Count the complete expected fingerprint contract."""
        return int(bool(self.expected.conditions and self.expected.returns))

    @property
    def classified_fact_count(self) -> int:
        """Count projections classified against a live AST surface."""
        return int(
            self.verdict
            in {
                SelectorReturnProjectionVerdict8616.PASSED,
                SelectorReturnProjectionVerdict8616.STALE_AST_SHAPE,
                SelectorReturnProjectionVerdict8616.STALE_FINGERPRINTS,
            }
        )

    @property
    def materialized_count(self) -> int:
        """Count live AST projections matching their authoritative evidence."""
        return int(self.verdict is SelectorReturnProjectionVerdict8616.PASSED)

    @property
    def failure_count(self) -> int:
        """Count active projections that are incomplete or stale."""
        return int(self.active and not self.accepted)

    def diagnostic(self) -> str:
        """Return a stable diagnostic for a Structuring hard failure."""
        return (
            f"selector-return projection={self.verdict.value} "
            f"expected={self.expected!r} observed={self.observed!r}"
        )


class _SelectorReturnCFunctionBoundary8616(Protocol):
    """Minimum third-party angr C-function surface consumed by this guard."""

    statements: object
    addr: int


class _SelectorReturnCodegenBoundary8616(Protocol):
    """Initialized selector-return metadata carried by an angr codegen object."""

    cfunc: _SelectorReturnCFunctionBoundary8616
    _inertia_return_selector_materialized_8616: bool
    _inertia_return_chain_materialized_condition_fingerprints_8616: tuple[str, ...]
    _inertia_return_expr_chain_materialized_return_fingerprints_8616: tuple[str, ...]


def collect_selector_return_projection_8616(
    root: object,
    project: object,
    expr_fingerprint: Callable[[object, object], str],
) -> SelectorReturnProjectionFingerprint8616 | None:
    """Collect one exact flat selector-return projection from an angr C AST."""
    if not isinstance(root, CStatements):
        return None
    statements = tuple(root.statements or ())
    if len(statements) < 2 or not isinstance(statements[-1], CReturn):
        return None
    final_return = statements[-1]
    if final_return.retval is None:
        return None
    conditions: list[str] = []
    returns: list[str] = []
    try:
        for statement in statements[:-1]:
            if not isinstance(statement, CIfElse) or statement.else_node is not None:
                return None
            condition_nodes = tuple(statement.condition_and_nodes or ())
            if len(condition_nodes) != 1:
                return None
            condition, body = condition_nodes[0]
            if not isinstance(body, CStatements):
                return None
            body_statements = tuple(body.statements or ())
            if len(body_statements) != 1 or not isinstance(body_statements[0], CReturn):
                return None
            branch_return = body_statements[0]
            if branch_return.retval is None:
                return None
            conditions.append(expr_fingerprint(condition, project))
            returns.append(expr_fingerprint(branch_return.retval, project))
        returns.append(expr_fingerprint(final_return.retval, project))
    except (AttributeError, TypeError, ValueError):
        return None
    return SelectorReturnProjectionFingerprint8616(tuple(conditions), tuple(returns))


def assess_selector_return_projection_8616(
    codegen: object,
    project: object,
    expr_fingerprint: Callable[[object, object], str],
) -> SelectorReturnProjectionIntegrity8616:
    """Compare the live flat selector-return AST with its exact proof metadata."""
    marker_missing = object()
    marker = getattr(codegen, "_inertia_return_selector_materialized_8616", marker_missing)
    if marker is marker_missing:
        return SelectorReturnProjectionIntegrity8616(
            SelectorReturnProjectionVerdict8616.NOT_APPLICABLE
        )
    if not bool(marker):
        return SelectorReturnProjectionIntegrity8616(
            SelectorReturnProjectionVerdict8616.NOT_APPLICABLE
        )
    try:
        typed_codegen = cast(_SelectorReturnCodegenBoundary8616, codegen)
        expected = SelectorReturnProjectionFingerprint8616(
            tuple(typed_codegen._inertia_return_chain_materialized_condition_fingerprints_8616),
            tuple(typed_codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616),
        )
        root = typed_codegen.cfunc.statements
    except (AttributeError, TypeError):
        return SelectorReturnProjectionIntegrity8616(
            SelectorReturnProjectionVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    if not expected.conditions or not expected.returns:
        return SelectorReturnProjectionIntegrity8616(
            SelectorReturnProjectionVerdict8616.MISSING_EXPECTED_FINGERPRINTS,
            expected=expected,
        )
    observed = collect_selector_return_projection_8616(root, project, expr_fingerprint)
    if observed is None:
        return SelectorReturnProjectionIntegrity8616(
            SelectorReturnProjectionVerdict8616.STALE_AST_SHAPE,
            expected=expected,
        )
    verdict = (
        SelectorReturnProjectionVerdict8616.PASSED
        if observed == expected
        else SelectorReturnProjectionVerdict8616.STALE_FINGERPRINTS
    )
    return SelectorReturnProjectionIntegrity8616(verdict, expected=expected, observed=observed)


def require_selector_return_projection_8616(
    codegen: object,
    project: object,
    expr_fingerprint: Callable[[object, object], str],
    *,
    context: str,
) -> SelectorReturnProjectionIntegrity8616:
    """Hard-fail when a claimed selector-return projection is not live."""
    integrity = assess_selector_return_projection_8616(codegen, project, expr_fingerprint)
    if integrity.accepted:
        return integrity
    typed_codegen = cast(_SelectorReturnCodegenBoundary8616, codegen)
    function_addr = typed_codegen.cfunc.addr
    raise PipelineHardError(
        "authoritative C AST lost CFG-proven selector-return projection",
        layer="structuring",
        function_addr=function_addr if isinstance(function_addr, int) else None,
        details={
            "verdict": integrity.verdict.value,
            "expected": integrity.expected,
            "observed": integrity.observed,
            "raw_fact_count": integrity.raw_fact_count,
            "normalized_fact_count": integrity.normalized_fact_count,
            "classified_fact_count": integrity.classified_fact_count,
            "materialized_count": integrity.materialized_count,
            "failure_count": integrity.failure_count,
            "context": context,
        },
    )
