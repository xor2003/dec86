"""Typed contracts for direct segmented-memory live-out collection.

Layer: Types/Lowering.
Responsibility: retain exact caller-use outcomes, refusals, and closed counters
when Semantics-proven DS/ES outputs cross a call boundary. This module owns no
CFG traversal, Alias inference, C type projection, prototype mutation, or codegen.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir.condition_ir import ConditionIR
from ..ir.function_ssa_registry import FunctionSSAArtifactFailure8616
from ..semantics.terminal_memory_output_contracts import (
    MemoryOutputKey8616,
    TerminalMemoryOutputFailure8616,
)
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageTrial8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_return_defs import CallOutputDefinitionFailure8616


class MemoryLiveOutCollectionVerdict8616(StrEnum):
    """Outcome of collecting one function's bounded direct-memory live-outs."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class MemoryLiveOutUseDisposition8616(StrEnum):
    """Reachability outcome for one exact caller storage-use candidate."""

    NOT_REACHED = "not_reached"
    USED = "used"


class MemoryLiveOutFailureKind8616(StrEnum):
    """Stable reasons one bounded memory live-out candidate cannot close."""

    CALLEE_SSA_UNAVAILABLE = "callee_ssa_unavailable"
    TERMINAL_EVIDENCE_REFUSED = "terminal_evidence_refused"
    CALLER_SSA_UNAVAILABLE = "caller_ssa_unavailable"
    CALL_OUTPUT_DEFINITION_REFUSED = "call_output_definition_refused"
    CALL_OUTPUT_DEFINITION_CONFLICT = "call_output_definition_conflict"
    CFG_INCOMPLETE = "cfg_incomplete"
    CFG_CYCLE = "cfg_cycle"
    INTERVENING_ALIAS = "intervening_alias"
    INTERVENING_CALL = "intervening_call"
    USE_OVERLAP = "use_overlap"
    CONDITION_NOT_FOUND = "condition_not_found"
    CONDITION_CONFLICT = "condition_conflict"
    CONDITION_UNSUPPORTED = "condition_unsupported"
    SIGNEDNESS_CONFLICT = "signedness_conflict"
    CONDITIONAL_WRITE = "conditional_write"


@dataclass(frozen=True, slots=True)
class MemoryLiveOutUseFact8616:
    """One exact storage candidate and its bounded caller-use outcome."""

    storage: StorageIdentity8616
    disposition: MemoryLiveOutUseDisposition8616
    use: StorageUseEvidence8616 | None = None
    signedness: StorageTrialSignedness8616 | None = None
    condition: ConditionIR | None = None

    @property
    def complete(self) -> bool:
        """Return whether this fact retains every field required by its verdict."""
        if self.disposition is MemoryLiveOutUseDisposition8616.NOT_REACHED:
            return self.storage.is_exact and all(
                item is None for item in (self.use, self.signedness, self.condition)
            )
        return bool(
            self.storage.is_exact
            and self.use is not None
            and self.use.is_complete
            and self.signedness is not None
            and self.condition is not None
        )


@dataclass(frozen=True, slots=True)
class MemoryLiveOutCandidateResult8616:
    """Inactive candidate, closed use fact/trial, or one typed refusal."""

    activated: bool
    fact: MemoryLiveOutUseFact8616 | None = None
    trial: StorageTrial8616 | None = None
    failure: MemoryLiveOutFailureKind8616 | None = None
    definition_failure: CallOutputDefinitionFailure8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this activated candidate has one durable outcome."""
        if not self.activated:
            return (self.fact, self.trial, self.failure, self.definition_failure) == (None,) * 4
        if self.failure is not None:
            return self.fact is None and self.trial is None
        return self.fact is not None and self.fact.complete and (
            self.trial is None or self.trial.is_complete
        )


@dataclass(frozen=True, slots=True)
class CallsiteMemoryLiveOutEvidence8616:
    """Closed direct-memory facts and materialized trials for one callsite."""

    caller_addr: int
    callee_addr: int
    callsite_addr: int
    facts: tuple[MemoryLiveOutUseFact8616, ...] = ()
    trials: tuple[StorageTrial8616, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryLiveOutFailure8616:
    """One exact refusal retaining all available upstream typed evidence."""

    kind: MemoryLiveOutFailureKind8616
    callee_addr: int
    caller_addr: int | None = None
    callsite_addr: int | None = None
    storage_key: MemoryOutputKey8616 | None = None
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None
    terminal_failure: TerminalMemoryOutputFailure8616 | None = None
    definition_failure: CallOutputDefinitionFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionMemoryLiveOutCollection8616:
    """Function-wide direct-memory live-outs or atomic typed refusals."""

    verdict: MemoryLiveOutCollectionVerdict8616
    callsites: tuple[CallsiteMemoryLiveOutEvidence8616, ...]
    failures: tuple[MemoryLiveOutFailure8616, ...]
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
        """Return whether every activated candidate has one retained outcome."""
        return (
            self.verdict is MemoryLiveOutCollectionVerdict8616.PROVEN
            and not self.failures
            and self.stats.complete
            and all(fact.complete for site in self.callsites for fact in site.facts)
            and all(trial.is_complete for site in self.callsites for trial in site.trials)
        )


__all__ = [
    "CallsiteMemoryLiveOutEvidence8616",
    "FunctionMemoryLiveOutCollection8616",
    "MemoryLiveOutCollectionVerdict8616",
    "MemoryLiveOutCandidateResult8616",
    "MemoryLiveOutFailure8616",
    "MemoryLiveOutFailureKind8616",
    "MemoryLiveOutUseDisposition8616",
    "MemoryLiveOutUseFact8616",
]
