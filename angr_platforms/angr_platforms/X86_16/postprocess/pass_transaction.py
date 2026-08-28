"""Own typed state and preflight policy for guarded postprocess passes.

Layer: Rewrite/Postprocess cleanup.
Responsibility: hold request-local guarded-pass state and decide whether one
already-selected cleanup pass must probe local evidence, execute, or be refused.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
This module does not execute passes, inspect the C AST, or publish metadata at
the dynamic angr boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .pass_validation_policy import (
    FORCE_PER_PASS_VALIDATION_NAMES_8616,
    LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616,
    MANDATORY_VALIDATION_PASS_NAMES_8616,
    OPTIMIZATION_VALIDATION_PASS_NAMES_8616,
    PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616,
)

__all__ = [
    "PostprocessMutationGeneration8616",
    "PostprocessPassPreflightAction8616",
    "PostprocessPassPreflightDecision8616",
    "PostprocessPassPreflightInput8616",
    "PostprocessPassTransactionState8616",
    "decide_postprocess_pass_preflight_8616",
]


class PostprocessPassPreflightAction8616(Enum):
    """Describe the next guarded-pass action selected by static policy."""

    PROBE_LOCAL_EVIDENCE = "probe_local_evidence"
    EXECUTE = "execute"
    REFUSE_LOCAL_PROOF = "refuse_local_proof"
    SKIP_REJECT_BUDGET = "skip_reject_budget"


@dataclass(frozen=True, slots=True)
class PostprocessPassPreflightInput8616:
    """Collect immutable inputs used to select one guarded-pass action."""

    pass_name: str
    validation_enabled: bool
    per_pass_validation_enabled: bool
    large_function_skip: bool
    force_per_pass_requested: bool
    optional_reject_budget: int
    optional_reject_count: int
    local_evidence_present: bool | None = None

    def with_local_evidence(self, present: bool) -> PostprocessPassPreflightInput8616:
        """Return the same preflight request with its lazy evidence probe closed."""
        return PostprocessPassPreflightInput8616(
            pass_name=self.pass_name,
            validation_enabled=self.validation_enabled,
            per_pass_validation_enabled=self.per_pass_validation_enabled,
            large_function_skip=self.large_function_skip,
            force_per_pass_requested=self.force_per_pass_requested,
            optional_reject_budget=self.optional_reject_budget,
            optional_reject_count=self.optional_reject_count,
            local_evidence_present=present,
        )


@dataclass(frozen=True, slots=True)
class PostprocessPassPreflightDecision8616:
    """Return one action and the validation obligations for an executable pass."""

    action: PostprocessPassPreflightAction8616
    is_optimization_pass: bool
    force_pass_validation: bool
    requires_snapshot: bool
    enforce_pass_validation: bool


@dataclass(frozen=True, slots=True)
class PostprocessMutationGeneration8616:
    """Accepted AST mutation generation published by one guarded transaction."""

    value: int
    last_changed_pass: str | None

    def __post_init__(self) -> None:
        """Reject an invalid monotonic generation at its owning boundary."""
        if self.value < 0:
            raise ValueError("postprocess mutation generation must be non-negative")


@dataclass(slots=True)
class PostprocessPassTransactionState8616:
    """Own mutable state shared by all guarded passes in one rewrite request."""

    baseline_summary: object | None
    known_cycle_path: tuple[str, ...] | None
    accepted_changed: bool = False
    last_changed_pass: str | None = None
    accepted_mutation_count: int = 0

    def accept_change(self, pass_name: str) -> None:
        """Record one accepted mutation and its deterministic pass identity."""
        self.accepted_changed = True
        self.last_changed_pass = pass_name
        self.accepted_mutation_count += 1

    def mutation_generation(self) -> PostprocessMutationGeneration8616:
        """Return the immutable accepted generation for downstream consumers."""
        return PostprocessMutationGeneration8616(
            value=self.accepted_mutation_count,
            last_changed_pass=self.last_changed_pass,
        )

    def replace_baseline(self, summary: object) -> None:
        """Advance validation baseline after an explicitly accepted delta."""
        self.baseline_summary = summary

    def record_cycle_path(self, cycle_path: tuple[str, ...] | None) -> None:
        """Publish the cycle witness for the current accepted AST state."""
        self.known_cycle_path = cycle_path


def decide_postprocess_pass_preflight_8616(
    request: PostprocessPassPreflightInput8616,
) -> PostprocessPassPreflightDecision8616:
    """Select a fail-closed guarded-pass action without inspecting runtime AST state."""
    pass_name = request.pass_name
    is_optimization_pass = pass_name in OPTIMIZATION_VALIDATION_PASS_NAMES_8616
    force_pass_validation = request.force_per_pass_requested and (
        pass_name in FORCE_PER_PASS_VALIDATION_NAMES_8616
        or pass_name in MANDATORY_VALIDATION_PASS_NAMES_8616
    )
    force_pass_validation = force_pass_validation or (
        request.validation_enabled
        and not request.large_function_skip
        and pass_name in MANDATORY_VALIDATION_PASS_NAMES_8616
    )
    requires_snapshot = request.validation_enabled and (
        request.per_pass_validation_enabled
        or force_pass_validation
        or is_optimization_pass
    )
    enforce_pass_validation = (
        request.per_pass_validation_enabled
        or force_pass_validation
        or is_optimization_pass
    )
    if (
        request.large_function_skip
        and not request.force_per_pass_requested
        and not force_pass_validation
        and not is_optimization_pass
    ):
        enforce_pass_validation = False

    refuse_without_local_proof = bool(
        request.validation_enabled
        and request.large_function_skip
        and not request.per_pass_validation_enabled
        and not force_pass_validation
        and not is_optimization_pass
        and pass_name in LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
    )
    reject_budget_reached = bool(
        request.validation_enabled
        and not request.per_pass_validation_enabled
        and request.optional_reject_budget > 0
        and request.optional_reject_count >= request.optional_reject_budget
        and pass_name in PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616
    )
    if (
        (refuse_without_local_proof or reject_budget_reached)
        and request.local_evidence_present is None
    ):
        action = PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE
    elif refuse_without_local_proof and not request.local_evidence_present:
        action = PostprocessPassPreflightAction8616.REFUSE_LOCAL_PROOF
    elif reject_budget_reached and not request.local_evidence_present:
        action = PostprocessPassPreflightAction8616.SKIP_REJECT_BUDGET
    else:
        action = PostprocessPassPreflightAction8616.EXECUTE
    return PostprocessPassPreflightDecision8616(
        action=action,
        is_optimization_pass=is_optimization_pass,
        force_pass_validation=force_pass_validation,
        requires_snapshot=requires_snapshot,
        enforce_pass_validation=enforce_pass_validation,
    )
