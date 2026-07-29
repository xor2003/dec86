"""Typed value contracts for identified runtime calls.

Layer: Semantics.
Responsibility: describe value effects of already identified runtime calls.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Forbidden: discovering call targets from names, materializing C expressions,
performing lowering/structuring, or accepting rendered-C text as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "IntegerValueRange8616",
    "RuntimeCallReturnContract8616",
    "RuntimeCallSemanticId8616",
    "runtime_call_return_contract_8616",
]


class RuntimeCallSemanticId8616(Enum):
    """Runtime-call identities with semantics used by the x86-16 pipeline."""

    C_RAND = "c_rand"


@dataclass(frozen=True, slots=True)
class IntegerValueRange8616:
    """Inclusive integer range proven for one semantic value."""

    minimum: int
    maximum: int | None

    @property
    def is_nonnegative(self) -> bool:
        """Return whether every value in this range is nonnegative."""
        return self.minimum >= 0


@dataclass(frozen=True, slots=True)
class RuntimeCallReturnContract8616:
    """Typed return-value contract for an already identified runtime call."""

    semantic_id: RuntimeCallSemanticId8616
    value_range: IntegerValueRange8616
    preserves_caller_storage: bool


_RUNTIME_RETURN_CONTRACTS_8616 = {
    "rand": RuntimeCallReturnContract8616(
        semantic_id=RuntimeCallSemanticId8616.C_RAND,
        value_range=IntegerValueRange8616(minimum=0, maximum=None),
        preserves_caller_storage=True,
    ),
}


def runtime_call_return_contract_8616(
    canonical_name: str | None,
) -> RuntimeCallReturnContract8616 | None:
    """Return semantics for a call identity resolved by binary/runtime evidence.

    This lookup does not identify a call target. Callers must first resolve the
    binary target to a canonical runtime identity. Unknown identities remain
    unproved.
    """
    if not isinstance(canonical_name, str):
        return None
    normalized = canonical_name.strip().lower().lstrip("_")
    if not normalized:
        return None
    return _RUNTIME_RETURN_CONTRACTS_8616.get(normalized)
