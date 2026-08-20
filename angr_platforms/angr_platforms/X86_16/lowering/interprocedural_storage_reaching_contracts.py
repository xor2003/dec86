"""Typed outcomes for call-argument SSA reaching-definition lookup.

Layer: Types/Lowering.
Responsibility: retain exact source pieces, call use, refusal reason, and closed
evidence counters for one logical call argument.
Consumes alias, widening, and typed facts. This module does not inspect binary
boundaries or mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir import IRInstr
from ..ir.ssa import SSABlock
from .interprocedural_storage_contracts import (
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
)

__all__ = [
    "CallArgumentDefinitionFailure8616",
    "CallArgumentDefinitionResolution8616",
    "CallArgumentDefinitionStats8616",
    "CallArgumentDefinitionVerdict8616",
    "PhysicalCallArgument8616",
    "SSAInstructionSite8616",
]


class CallArgumentDefinitionVerdict8616(StrEnum):
    """Typed result of matching one logical argument to caller SSA."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class CallArgumentDefinitionFailure8616(StrEnum):
    """Stable reasons why one call argument lacks exact SSA proof."""

    INVALID_ARGUMENT_INDEX = "invalid_argument_index"
    INCOMPLETE_PHYSICAL_ARGUMENT = "incomplete_physical_argument"
    CALLSITE_NOT_FOUND = "callsite_not_found"
    CALLSITE_CONFLICT = "callsite_conflict"
    CALL_TARGET_CONFLICT = "call_target_conflict"
    SOURCE_SHAPE_CONFLICT = "source_shape_conflict"
    SOURCE_WIDTH_CONFLICT = "source_width_conflict"
    SOURCE_DEFINITION_NOT_FOUND = "source_definition_not_found"
    SOURCE_DEFINITION_CONFLICT = "source_definition_conflict"
    UNMODELED_CALL_OUTPUT = "unmodeled_call_output"
    UNSUPPORTED_SOURCE_KIND = "unsupported_source_kind"


@dataclass(frozen=True, slots=True)
class CallArgumentDefinitionStats8616:
    """Closed evidence accounting for one logical argument lookup."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether the argument became one proof-bearing binding."""
        return (
            self.raw_fact_count == 1
            and self.normalized_fact_count == 1
            and self.classified_fact_count == 1
            and self.materialized_count == 1
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class CallArgumentDefinitionResolution8616:
    """Exact source pieces and call use, or one typed refusal."""

    verdict: CallArgumentDefinitionVerdict8616
    definitions: tuple[StorageReachingDefinition8616, ...]
    use: StorageUseEvidence8616 | None
    failure: CallArgumentDefinitionFailure8616 | None
    stats: CallArgumentDefinitionStats8616


@dataclass(frozen=True, slots=True)
class SSAInstructionSite8616:
    """One typed SSA instruction with stable block/index coordinates."""

    block: SSABlock
    instr_index: int
    instr: IRInstr


@dataclass(frozen=True, slots=True)
class PhysicalCallArgument8616:
    """One source-order argument projected to its physical push fact."""

    width: int
    source: tuple[object, ...]
    push_addr: int
