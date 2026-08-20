"""Validate exact callsite multiplicity in the final structured C AST.

Layer: Tail validation.
Responsibility: compare binary-required callsite identities with the number of
final C call nodes carrying each exact instruction address.
Forbidden: target-name inference, rendered-C/assembly inspection, AST repair,
or treating an untagged call as evidence for or against multiplicity.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from .c_ast_utils import _iter_c_nodes_deep_8616
from .callsite_summary import CallsiteSummary8616

__all__ = [
    "CallsiteMultiplicityIssue8616",
    "CallsiteMultiplicityIssueKind8616",
    "CallsiteMultiplicityValidationReport8616",
    "validate_required_callsite_multiplicity_8616",
]


class _CodegenCallsiteSurface8616(Protocol):
    """Dynamic angr codegen metadata consumed by final call validation."""

    _inertia_callsite_summaries: object


class CallsiteMultiplicityIssueKind8616(StrEnum):
    """Typed contradictions between one machine callsite and final C calls."""

    DUPLICATE_FINAL_CALLSITE = "duplicate-final-callsite"


@dataclass(frozen=True, order=True, slots=True)
class CallsiteMultiplicityIssue8616:
    """One binary callsite projected more than once into final structured C."""

    kind: CallsiteMultiplicityIssueKind8616
    callsite_addr: int
    target_addr: int | None
    actual_count: int

    def token(self) -> str:
        """Return a deterministic token for tail-validation diagnostics."""
        target = "unknown" if self.target_addr is None else f"{self.target_addr:#x}"
        return (
            f"callsite-multiplicity:{self.kind}:callsite={self.callsite_addr:#x}:"
            f"target={target}:expected=1:actual={self.actual_count}"
        )


@dataclass(frozen=True, slots=True)
class CallsiteMultiplicityValidationReport8616:
    """Closed evidence-loop counters for exact final callsite multiplicity."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[CallsiteMultiplicityIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every observed required callsite appears exactly once."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for canonical tail snapshots."""
        return tuple(issue.token() for issue in self.issues)


def _required_targets_by_callsite_8616(codegen: object) -> dict[int, tuple[int, ...]]:
    """Return exact binary target evidence grouped by required callsite address."""
    try:
        raw_summaries = cast(_CodegenCallsiteSurface8616, codegen)._inertia_callsite_summaries
    except AttributeError:
        return {}
    if not isinstance(raw_summaries, Mapping):
        return {}
    targets: defaultdict[int, set[int]] = defaultdict(set)
    for summary in raw_summaries.values():
        if (
            isinstance(summary, CallsiteSummary8616)
            and not summary.stack_probe_helper
            and isinstance(summary.target_addr, int)
        ):
            targets[summary.callsite_addr].add(summary.target_addr)
    return {
        callsite_addr: tuple(sorted(callsite_targets))
        for callsite_addr, callsite_targets in targets.items()
    }


def _callsite_addr_8616(call: CFunctionCall) -> int | None:
    """Return exact instruction identity retained on a third-party C call."""
    tags = call.tags
    if not isinstance(tags, Mapping):
        return None
    for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
        value = tags.get(key)
        if isinstance(value, int):
            return value
    return None


def validate_required_callsite_multiplicity_8616(
    codegen: object,
    root: object,
) -> CallsiteMultiplicityValidationReport8616:
    """Reject duplicate final calls proven to represent one machine callsite."""
    targets_by_callsite = _required_targets_by_callsite_8616(codegen)
    if not targets_by_callsite:
        return CallsiteMultiplicityValidationReport8616()

    observed: Counter[int] = Counter()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        callsite_addr = _callsite_addr_8616(node)
        if callsite_addr in targets_by_callsite:
            observed[callsite_addr] += 1

    issues = tuple(
        CallsiteMultiplicityIssue8616(
            kind=CallsiteMultiplicityIssueKind8616.DUPLICATE_FINAL_CALLSITE,
            callsite_addr=callsite_addr,
            target_addr=(targets[0] if len(targets) == 1 else None),
            actual_count=count,
        )
        for callsite_addr, count in sorted(observed.items())
        if count > 1
        for targets in (targets_by_callsite[callsite_addr],)
    )
    return CallsiteMultiplicityValidationReport8616(
        raw_fact_count=sum(observed.values()),
        normalized_fact_count=len(observed),
        classified_fact_count=len(observed),
        materialized_count=sum(count == 1 for count in observed.values()),
        failure_count=len(issues),
        issues=issues,
    )
