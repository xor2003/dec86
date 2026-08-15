"""Render casts whose conversion is part of proven machine semantics.

Layer: Types/Lowering.
Responsibility: distinguish required width/signedness conversions from angr's
optional cosmetic casts so generated C preserves binary value semantics.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _iter_c_nodes_deep_8616


class CSemanticCast8616(
    structured_c.CTypeCast,  # type: ignore[misc]  # dynamic angr codegen base
):
    """Structured-C cast that remains visible when cosmetic casts are hidden."""

    def c_repr_chunks(
        self,
        indent: int = 0,
        asexpr: bool = False,
    ) -> Iterator[tuple[str, object]]:
        """Render the required C conversion independently of ``show_casts``."""
        del indent, asexpr
        if self.collapsed:
            yield "...", self
            return
        parenthesis = structured_c.CClosingObject("(")
        yield "(", parenthesis
        yield self.dst_type.c_repr(name=None), self.dst_type
        yield ")", parenthesis
        wrap_expression = isinstance(self.expr, structured_c.CBinaryOp)
        if wrap_expression:
            yield "(", parenthesis
        yield from structured_c.CExpression._try_c_repr_chunks(self.expr)
        if wrap_expression:
            yield ")", parenthesis


class RequiredAssignmentCastReconcileStatus8616(StrEnum):
    """Typed outcome for evidence-backed assignment-cast reconciliation."""

    NOT_REQUIRED = "not_required"
    ALREADY_PRESENT = "already_present"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    APPLIED = "applied"


@dataclass(frozen=True, slots=True)
class RequiredAssignmentCastReconcileResult8616:
    """Closed evidence result for one required assignment cast."""

    status: RequiredAssignmentCastReconcileStatus8616
    assignment_count: int
    destination_count: int
    candidate_count: int

    @property
    def changed(self) -> bool:
        """Return whether the required cast was applied."""
        return self.status is RequiredAssignmentCastReconcileStatus8616.APPLIED


def reconcile_required_assignment_cast_8616(
    root: object,
    expected: structured_c.CAssignment,
    *,
    same_destination: Callable[[object, object], bool],
    same_source: Callable[[object, object], bool],
) -> RequiredAssignmentCastReconcileResult8616:
    """Restore one evidence-backed cast onto a unique stale assignment."""
    expected_rhs = expected.rhs
    if not isinstance(expected_rhs, CSemanticCast8616):
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.NOT_REQUIRED,
            0,
            0,
            0,
        )
    assignments = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CAssignment)
    )
    destinations = tuple(
        node for node in assignments if same_destination(node.lhs, expected.lhs)
    )
    already_present = tuple(
        node
        for node in destinations
        if isinstance(node.rhs, CSemanticCast8616)
        and node.rhs.dst_type == expected_rhs.dst_type
        and same_source(node.rhs.expr, expected_rhs.expr)
    )
    if len(already_present) == 1:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.ALREADY_PRESENT,
            len(assignments),
            len(destinations),
            1,
        )
    if len(already_present) > 1:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.AMBIGUOUS,
            len(assignments),
            len(destinations),
            len(already_present),
        )
    candidates = tuple(
        node
        for node in destinations
        if not isinstance(node.rhs, CSemanticCast8616)
        and same_source(node.rhs, expected_rhs.expr)
    )
    if not candidates:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.NO_MATCH,
            len(assignments),
            len(destinations),
            0,
        )
    if len(candidates) != 1:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.AMBIGUOUS,
            len(assignments),
            len(destinations),
            len(candidates),
        )
    candidates[0].rhs = expected_rhs
    return RequiredAssignmentCastReconcileResult8616(
        RequiredAssignmentCastReconcileStatus8616.APPLIED,
        len(assignments),
        len(destinations),
        1,
    )
