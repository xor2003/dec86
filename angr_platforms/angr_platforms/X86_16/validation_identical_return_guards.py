"""Validate one exact identical-return guard collapse delta.

Layer: Tail validation.
Responsibility: consume only the condition and control-flow observations
removed by a closed typed Structuring identical-return result.

This compatibility boundary checks field ownership and cardinality in the
existing fingerprint delta. It does not parse condition text or infer return
semantics from fingerprints; Structuring must already have proved purity and
return-expression identity.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from enum import StrEnum

from .structuring.identical_return_guards import (
    IdenticalReturnGuardCollapseResult8616,
    IdenticalReturnGuardShape8616,
)


class IdenticalReturnGuardValidationStatus8616(StrEnum):
    """Typed outcome for one attempted validation-delta consumption."""

    ACCEPTED = "accepted"
    REFUSED_NO_RESULT = "refused_no_result"
    REFUSED_UNCLOSED_EVIDENCE = "refused_unclosed_evidence"
    REFUSED_MALFORMED_DELTA = "refused_malformed_delta"
    REFUSED_UNEXPECTED_EFFECT = "refused_unexpected_effect"


@dataclass(frozen=True, slots=True)
class IdenticalReturnGuardValidationResult8616:
    """Validation outcome and consumed observation counts."""

    status: IdenticalReturnGuardValidationStatus8616
    consumed_condition_count: int = 0
    consumed_control_effect_count: int = 0

    @property
    def accepted(self) -> bool:
        """Return whether the exact typed delta was consumed."""
        return self.status is IdenticalReturnGuardValidationStatus8616.ACCEPTED


def _tokens_8616(field_delta: object, direction: str) -> tuple[object, ...] | None:
    """Read one established tail-validation delta channel."""
    if not isinstance(field_delta, Mapping):
        return None
    value = field_delta.get(direction, ())
    return tuple(value) if isinstance(value, (tuple, list, set, frozenset)) else None


def _evidence_is_closed_8616(result: IdenticalReturnGuardCollapseResult8616) -> bool:
    """Require one fully classified identical-return collapse."""
    stats = result.stats
    return bool(
        stats.complete
        and result.collapsed_guard_count == 1
        and stats.materialized_count == 1
        and len(result.materializations) == 1
        and result.materializations[0].shape
        in {
            IdenticalReturnGuardShape8616.ELSE_RETURN,
            IdenticalReturnGuardShape8616.FALLTHROUGH_RETURN,
        }
        and len(result.refusals) == stats.failure_count
    )


def consume_identical_return_guard_validation_delta_8616(
    result: IdenticalReturnGuardCollapseResult8616 | None,
    validation: MutableMapping[str, object],
) -> IdenticalReturnGuardValidationResult8616:
    """Consume only the exact no-effect delta for one proved guard collapse."""
    if result is None:
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_NO_RESULT
        )
    if not _evidence_is_closed_8616(result):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNCLOSED_EVIDENCE
        )
    delta = validation.get("delta")
    if not isinstance(delta, MutableMapping):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_MALFORMED_DELTA
        )
    channels: dict[str, tuple[object, ...]] = {}
    for field_name, field_delta in delta.items():
        added = _tokens_8616(field_delta, "added")
        removed = _tokens_8616(field_delta, "removed")
        if added is None or removed is None:
            return IdenticalReturnGuardValidationResult8616(
                IdenticalReturnGuardValidationStatus8616.REFUSED_MALFORMED_DELTA
            )
        if added:
            return IdenticalReturnGuardValidationResult8616(
                IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
            )
        if removed:
            channels[str(field_name)] = removed
    if set(channels) != {"conditions", "control_flow_effects"}:
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )
    conditions = channels["conditions"]
    control = channels["control_flow_effects"]
    if (
        len(conditions) != 1
        or not isinstance(conditions[0], str)
        or len(control) not in {1, 2, 3}
        or any(not isinstance(item, str) for item in control)
    ):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )
    if validation.get("semantic_failures", ()):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )

    validation["changed"] = False
    validation["status"] = "stable"
    validation["summary_text"] = "no observable whole-tail changes"
    validation.pop("delta", None)
    return IdenticalReturnGuardValidationResult8616(
        IdenticalReturnGuardValidationStatus8616.ACCEPTED,
        consumed_condition_count=1,
        consumed_control_effect_count=len(control),
    )
