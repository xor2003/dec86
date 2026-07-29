"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import sys


def _default_recovery_timeout(configured_timeout: int, *, explicit_timeout: bool) -> int:
    if configured_timeout <= 0:
        return 5
    if not explicit_timeout:
        return max(5, configured_timeout)
    return configured_timeout


class _AdaptivePerByteTimeoutModel:
    def __init__(self, configured_timeout: int, *, explicit_timeout: bool, margin: float = 1.5) -> None:
        self.configured_timeout = max(1, configured_timeout)
        self.explicit_timeout = explicit_timeout
        self.margin = max(1.0, float(margin))
        self._samples: list[tuple[int, float]] = []

    def observe_success(self, byte_count: int, elapsed: float) -> None:
        """Record one successful recovery timing sample."""
        if byte_count <= 0 or elapsed <= 0:
            return
        self._samples.append((byte_count, float(elapsed)))
        if len(self._samples) > 64:
            self._samples = self._samples[-64:]

    def _seed_rate(self) -> tuple[float, float]:
        if not self._samples:
            return (0.05, 0.5)
        rates = [elapsed / max(1, byte_count) for byte_count, elapsed in self._samples]
        overheads = [
            max(0.0, elapsed - (rate * byte_count)) for (byte_count, elapsed), rate in zip(self._samples, rates)
        ]
        rate = sum(rates) / len(rates)
        overhead = sum(overheads) / len(overheads) if overheads else 0.5
        return max(0.005, rate), max(0.0, overhead)

    def timeout_for_byte_count(self, byte_count: int) -> int:
        """Return the timeout budget for a function with the given byte count."""
        base = max(1, int(self.configured_timeout))
        if self.explicit_timeout:
            return base
        # Adaptive default budgets for larger functions in serial file sweeps.
        # Keeps deterministic behavior while avoiding frequent 86_16 timeout
        # churn on medium/large procedures (e.g. menu/render loops).
        if byte_count >= 520:
            return max(base, 120)
        if byte_count >= 380:
            return max(base, 90)
        if byte_count >= 280:
            return max(base, 60)
        return base


def _stdout_is_interactive() -> bool:
    stream = sys.stdout
    try:
        return bool(stream is not None and hasattr(stream, "isatty") and stream.isatty())
    except Exception:
        return False
