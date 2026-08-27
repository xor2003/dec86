from __future__ import annotations  # noqa: D100

import math
import re
from dataclasses import dataclass

DEFAULT_ESTIMATED_ROUNDS = 1


@dataclass(frozen=True)
class StuckDecision:  # noqa: D101
    category: str
    playbook: str
    estimated_rounds: int
    stuck_after_rounds: int
    is_stuck: bool


def estimated_rounds(item_text: str) -> int:  # noqa: D103
    def _impl():  # noqa: ANN202
        """Extract the item round budget from an execution specification."""
        match = re.search(r"Estimated rounds:\s*(\d+)", item_text, re.IGNORECASE)
        if not match:
            return DEFAULT_ESTIMATED_ROUNDS
        return max(1, int(match.group(1)))

    return _impl()


def stuck_after_rounds(item_text: str) -> int:  # noqa: D103
    def _impl():  # noqa: ANN202
        """Return the deterministic 1.5x stuck threshold for a plan item."""
        return max(2, math.ceil(estimated_rounds(item_text) * 1.5))

    return _impl()


def classify_stuck_reason(item_text: str, runtime_context: str = "") -> str:  # noqa: D103
    def _impl() -> str:
        """Classify the likely stuck family from structured item and runtime clues."""
        text = f"{item_text}\n{runtime_context}".lower()
        if "timeout" in text or "hang" in text or "no-output" in text or "no output" in text:
            return "timeout-or-silent-agent"
        if "failed " in text or "traceback" in text or "error:" in text:
            return "test-or-runtime-failure"
        if "unknown" in text or "uncollected" in text or "missing evidence" in text:
            return "evidence-gap"
        if len(item_text) > 1200 or item_text.count("`") > 18:
            return "plan-item-too-broad"
        return "worker-no-progress"

    return _impl()


def stuck_playbook(category: str) -> str:  # noqa: D103
    def _impl():  # noqa: ANN202
        """Map a stuck category to the next deterministic harness action."""
        return {
            "timeout-or-silent-agent": "restart fresh context, capture smallest repro/profile, then split timeout work before implementation",
            "test-or-runtime-failure": "keep the failing command fixed, change code or hypothesis before rerun, then route to reviewer if repeated",
            "evidence-gap": "add a diagnostic/data-collection PLAN step before more implementation",
            "plan-item-too-broad": "rewrite into smaller Execution Specification items with separate DoD and round budgets",
            "worker-no-progress": "route to planner for a narrower task packet and explicit stop conditions",
        }.get(category, "route to planner for classification before retry")

    return _impl()


def decide_stuck(item_text: str, completed_rounds: int, runtime_context: str = "") -> StuckDecision:  # noqa: D103
    def _impl():  # noqa: ANN202
        """Decide whether a task exceeded its 1.5x round budget and choose playbook."""
        threshold = stuck_after_rounds(item_text)
        category = classify_stuck_reason(item_text, runtime_context)
        return StuckDecision(
            category=category,
            playbook=stuck_playbook(category),
            estimated_rounds=estimated_rounds(item_text),
            stuck_after_rounds=threshold,
            is_stuck=completed_rounds >= threshold,
        )

    return _impl()
