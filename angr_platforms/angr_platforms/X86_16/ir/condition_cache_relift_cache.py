"""Bounded cache for immutable exact-byte condition-relift artifacts.

Layer: IR.
Responsibility: reuse complete relift artifacts only when architecture identity
and every exact input byte and request field are unchanged.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = (
    "ConditionReliftArtifactCache8616",
    "ConditionReliftCacheRequest8616",
)

@dataclass(frozen=True, slots=True)
class ConditionReliftCacheRequest8616:
    """Exact immutable inputs that determine one condition-relift artifact."""

    block_bytes: tuple[tuple[int, int, bytes], ...]
    expected_condition_blocks: frozenset[int]


@dataclass(frozen=True, slots=True)
class _ConditionReliftCacheEntry8616[ArtifactT]:
    """One architecture-scoped immutable cache entry."""

    architecture: object
    request: ConditionReliftCacheRequest8616
    artifact: ArtifactT


class ConditionReliftArtifactCache8616[ArtifactT]:
    """Keep a fixed number of most-recent complete relift artifacts."""

    def __init__(self, *, max_entries: int) -> None:
        """Create a bounded cache with an explicit positive capacity."""
        if max_entries <= 0:
            msg = "condition relift cache capacity must be positive"
            raise ValueError(msg)
        self._max_entries = max_entries
        self._entries: list[_ConditionReliftCacheEntry8616[ArtifactT]] = []

    def lookup(self, architecture: object, request: ConditionReliftCacheRequest8616) -> ArtifactT | None:
        """Return and promote an exact architecture-identity cache hit."""
        for index, entry in enumerate(self._entries):
            if entry.architecture is architecture and entry.request == request:
                if index != len(self._entries) - 1:
                    self._entries.append(self._entries.pop(index))
                return entry.artifact
        return None

    def publish(
        self,
        architecture: object,
        request: ConditionReliftCacheRequest8616,
        artifact: ArtifactT,
    ) -> None:
        """Publish one complete artifact and evict the oldest excess entry."""
        self._entries = [
            entry
            for entry in self._entries
            if not (entry.architecture is architecture and entry.request == request)
        ]
        self._entries.append(_ConditionReliftCacheEntry8616(architecture, request, artifact))
        del self._entries[: max(0, len(self._entries) - self._max_entries)]
