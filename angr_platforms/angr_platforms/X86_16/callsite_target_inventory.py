"""Layer: Recovery metadata.

Responsibility: collect immutable CFG-derived call targets once per summary request.
"""

from __future__ import annotations

from dataclasses import dataclass

from .analysis_helpers import CallTargetSeed, collect_neighbor_call_targets

__all__ = ["CallsiteTargetInventory8616"]


@dataclass(frozen=True, slots=True)
class CallsiteTargetInventory8616:
    """Immutable direct-call and tail-jump targets for one recovered function."""

    seeds: tuple[CallTargetSeed, ...]

    @classmethod
    def collect(cls, function: object) -> CallsiteTargetInventory8616:
        """Collect the function's CFG-derived target facts exactly once."""
        return cls(tuple(collect_neighbor_call_targets(function)))

    def seed_for_callsite(self, callsite_addr: int) -> CallTargetSeed | None:
        """Return the first recovered target fact for an exact callsite."""
        return next((seed for seed in self.seeds if seed.callsite_addr == callsite_addr), None)
