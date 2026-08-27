"""Typed runtime eligibility for semantic decompiler caches.

Layer: CLI/fallback/reporting.
Responsibility: refuse semantic cache reuse unless Python hash ordering is deterministic.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class CacheRuntimeVerdict8616(StrEnum):
    """Typed reason why semantic cache reuse is allowed or refused."""

    DETERMINISTIC = "deterministic"
    HASH_SEED_UNSET = "hash_seed_unset"
    HASH_SEED_NONZERO = "hash_seed_nonzero"


@dataclass(frozen=True, slots=True)
class CacheRuntimeContract8616:
    """Determinism evidence required before semantic cache reuse."""

    verdict: CacheRuntimeVerdict8616
    python_hash_seed: str | None

    @property
    def allows_semantic_cache(self) -> bool:
        """Return whether this process may read or write semantic cache entries."""
        return self.verdict is CacheRuntimeVerdict8616.DETERMINISTIC


def cache_runtime_contract_8616(
    environment: Mapping[str, str] | None = None,
) -> CacheRuntimeContract8616:
    """Classify the current process from explicit hash-seed evidence."""
    source = os.environ if environment is None else environment
    raw_seed = source.get("PYTHONHASHSEED")
    if raw_seed is None or not raw_seed.strip():
        verdict = CacheRuntimeVerdict8616.HASH_SEED_UNSET
    elif raw_seed.strip() == "0":
        verdict = CacheRuntimeVerdict8616.DETERMINISTIC
    else:
        verdict = CacheRuntimeVerdict8616.HASH_SEED_NONZERO
    return CacheRuntimeContract8616(verdict=verdict, python_hash_seed=raw_seed)
