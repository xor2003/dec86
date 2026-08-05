"""Validate binary-proven software-interrupt inputs on final C calls.

Layer: Tail Validation.
Responsibility: independently compare Semantics-owned interrupt input facts
with the exact final structured C callsite. This module reports only; it never
repairs calls or derives facts from rendered text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, Sequence, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from .c_ast_utils import _iter_c_nodes_deep_8616
from .ir.core import IRFunctionArtifact
from .semantics.software_interrupt_inputs import (
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
    build_software_interrupt_input_artifact_8616,
    software_interrupt_value_fingerprint_8616,
)

__all__ = [
    "SoftwareInterruptValidationIssue8616",
    "SoftwareInterruptValidationIssueKind8616",
    "SoftwareInterruptValidationReport8616",
    "validate_software_interrupt_inputs_8616",
]


class SoftwareInterruptValidationIssueKind8616(StrEnum):
    """Typed final-C failures for required interrupt inputs."""

    INPUT_RECOVERY_REFUSED = "input-recovery-refused"
    MISSING_CALL = "missing-call"
    ARGUMENT_SURFACE_UNAVAILABLE = "argument-surface-unavailable"
    ARGUMENT_COUNT_MISMATCH = "argument-count-mismatch"
    ARGUMENT_VALUE_MISMATCH = "argument-value-mismatch"
    STALE_RESULT_SELECTOR = "stale-result-selector"


@dataclass(frozen=True, order=True, slots=True)
class SoftwareInterruptValidationIssue8616:
    """One contradiction between interrupt input facts and final C."""

    kind: SoftwareInterruptValidationIssueKind8616
    callsite_addr: int
    vector: int
    argument_index: int | None = None
    expected: str | None = None
    actual: str | None = None

    def token(self) -> str:
        """Return a deterministic canonical validation token."""
        token = (
            f"software-interrupt:{self.kind}:callsite={self.callsite_addr:#x}:"
            f"vector={self.vector:#x}"
        )
        if self.argument_index is not None:
            token += f":arg={self.argument_index}"
        if self.expected is not None:
            token += f":expected={self.expected}"
        if self.actual is not None:
            token += f":actual={self.actual}"
        return token


@dataclass(frozen=True, slots=True)
class SoftwareInterruptValidationReport8616:
    """Closed evidence-loop report for final interrupt call inputs."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[SoftwareInterruptValidationIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every classified interrupt input survived."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for the final tail snapshot."""
        return tuple(issue.token() for issue in self.issues)


class _CodegenInterruptSurface8616(Protocol):
    """Owned typed artifacts attached to a third-party codegen object."""

    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616
    _inertia_vex_ir_artifact: IRFunctionArtifact


class _TaggedCallSurface8616(Protocol):
    """Third-party structured call fields read during validation."""

    tags: object
    args: object


class _CVariableSurface8616(Protocol):
    """Third-party C variable storage field read during validation."""

    variable: object


def _artifact_8616(codegen: object) -> SoftwareInterruptInputArtifact8616 | None:
    """Read or rebuild the Semantics-owned interrupt input artifact."""
    surface = cast(_CodegenInterruptSurface8616, codegen)
    try:
        return surface._inertia_software_interrupt_input_artifact_8616
    except AttributeError:
        pass
    try:
        return build_software_interrupt_input_artifact_8616(surface._inertia_vex_ir_artifact)
    except AttributeError:
        return None


def _callsite_addr_8616(call: structured_c.CFunctionCall) -> int | None:
    """Read the exact instruction address from a final C call."""
    try:
        tags = cast(_TaggedCallSurface8616, call).tags
    except AttributeError:
        return None
    if not isinstance(tags, dict):
        return None
    addr = tags.get("ins_addr")
    return addr if isinstance(addr, int) else None


def _actual_value_fingerprint_8616(node: object) -> str | None:
    """Fingerprint the final C subset permitted by interrupt lowering."""
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return f"const:{node.value:#x}:size2"
    if isinstance(node, structured_c.CVariable):
        try:
            variable = cast(_CVariableSurface8616, node).variable
        except AttributeError:
            return None
        if isinstance(variable, SimStackVariable):
            return f"stack:SS:BP{variable.offset:+#x}:size{variable.size}"
        return None
    if isinstance(node, structured_c.CBinaryOp):
        lhs = _actual_value_fingerprint_8616(node.lhs)
        rhs = _actual_value_fingerprint_8616(node.rhs)
        if lhs is None or rhs is None:
            return None
        return f"{node.op}({lhs},{rhs}):size2"
    return None


def _validate_fact_8616(
    fact: SoftwareInterruptInputFact8616,
    calls: tuple[structured_c.CFunctionCall, ...],
    root: object,
) -> tuple[bool, list[SoftwareInterruptValidationIssue8616]]:
    """Validate one fact against one exact final callsite."""
    matches = tuple(call for call in calls if _callsite_addr_8616(call) == fact.callsite_addr)
    if len(matches) != 1:
        return False, [
            SoftwareInterruptValidationIssue8616(
                SoftwareInterruptValidationIssueKind8616.MISSING_CALL,
                fact.callsite_addr,
                fact.vector,
            )
        ]
    args = cast(_TaggedCallSurface8616, matches[0]).args
    if not isinstance(args, Sequence) or isinstance(args, (str, bytes)):
        return False, [
            SoftwareInterruptValidationIssue8616(
                SoftwareInterruptValidationIssueKind8616.ARGUMENT_SURFACE_UNAVAILABLE,
                fact.callsite_addr,
                fact.vector,
            )
        ]
    if len(args) != len(fact.argument_values):
        return False, [
            SoftwareInterruptValidationIssue8616(
                SoftwareInterruptValidationIssueKind8616.ARGUMENT_COUNT_MISMATCH,
                fact.callsite_addr,
                fact.vector,
                expected=str(len(fact.argument_values)),
                actual=str(len(args)),
            )
        ]
    issues: list[SoftwareInterruptValidationIssue8616] = []
    for index, (expected_value, actual_value) in enumerate(
        zip(fact.argument_values, args, strict=True)
    ):
        expected = software_interrupt_value_fingerprint_8616(expected_value)
        actual = _actual_value_fingerprint_8616(actual_value)
        if actual != expected:
            issues.append(
                SoftwareInterruptValidationIssue8616(
                    SoftwareInterruptValidationIssueKind8616.ARGUMENT_VALUE_MISMATCH,
                    fact.callsite_addr,
                    fact.vector,
                    argument_index=index,
                    expected=expected,
                    actual=actual or "unavailable",
                )
            )
    if fact.result_register is not None and _has_stale_selector_return_8616(
        root,
        fact,
        matches[0],
    ):
        issues.append(
            SoftwareInterruptValidationIssue8616(
                SoftwareInterruptValidationIssueKind8616.STALE_RESULT_SELECTOR,
                fact.callsite_addr,
                fact.vector,
                expected=f"return:{fact.result_register}",
                actual=f"selector:{fact.selector_value:#x}",
            )
        )
    return not issues, issues


def _has_stale_selector_return_8616(
    root: object,
    fact: SoftwareInterruptInputFact8616,
    call: structured_c.CFunctionCall,
) -> bool:
    """Detect a call result discarded for its pre-call selector constant."""
    assigned = any(
        isinstance(node, structured_c.CAssignment) and node.rhs is call
        for node in _iter_c_nodes_deep_8616(root)
    )
    if not assigned:
        return False
    return any(
        isinstance(node, structured_c.CReturn)
        and isinstance(node.retval, structured_c.CConstant)
        and node.retval.value == fact.selector_value
        for node in _iter_c_nodes_deep_8616(root)
    )


def validate_software_interrupt_inputs_8616(
    codegen: object,
    root: object,
) -> SoftwareInterruptValidationReport8616:
    """Require every known binary-proven interrupt input on final C calls."""
    artifact = _artifact_8616(codegen)
    if artifact is None:
        return SoftwareInterruptValidationReport8616()
    issues: list[SoftwareInterruptValidationIssue8616] = [
        SoftwareInterruptValidationIssue8616(
            SoftwareInterruptValidationIssueKind8616.INPUT_RECOVERY_REFUSED,
            callsite_addr,
            0,
            expected=f"{kind}:{detail}",
        )
        for callsite_addr, kind, detail in artifact.refusals
    ]
    calls = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
    )
    materialized_count = 0
    for fact in artifact.facts:
        materialized, fact_issues = _validate_fact_8616(fact, calls, root)
        materialized_count += int(materialized)
        issues.extend(fact_issues)
    return SoftwareInterruptValidationReport8616(
        raw_fact_count=artifact.stats.raw_fact_count,
        normalized_fact_count=artifact.stats.normalized_fact_count,
        classified_fact_count=artifact.stats.classified_fact_count,
        materialized_count=materialized_count,
        failure_count=len(issues),
        issues=tuple(issues),
    )
