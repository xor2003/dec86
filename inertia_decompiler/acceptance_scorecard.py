"""Report generated-C acceptance markers without defining semantic truth.

Layer: CLI/fallback/reporting.
Responsibility: summarize generated-output quality markers without deciding semantic correctness.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

__all__ = [
    "AcceptanceScorecard",
    "build_acceptance_scorecard",
]


_FLAGS_RE = re.compile(r"\bflags(?:_[A-Za-z0-9]+)?\b")
_VVAR_RE = re.compile(r"\bvvar_[A-Za-z0-9]+\b")
_SUB_RE = re.compile(r"\bsub_[0-9a-fA-F]+\b")
_TAIL_VALIDATION_METADATA_RE = re.compile(r"@@INERTIA_TAIL_VALIDATION@@\s+(\{.*\})")
_DS_HELPER_LINEAR_RE = re.compile(r"\b(?:SEG_PTR|MK_FP|SEG_U8|SEG_U16|SEG_U32)\s*\(\s*ds\s*,")
_SS_LINEAR_RE = re.compile(r"\bss\s*\*\s*16\b")


@dataclass(frozen=True, slots=True)
class AcceptanceScorecard:
    """Generated-output quality counters for one recovered function."""

    function_name: str
    raw_flags_count: int
    raw_ss_linear_count: int
    raw_ds_linear_count: int
    vvar_count: int
    anonymous_sub_count: int
    recovery_mode: str
    validation_verdict: str
    source_present: bool

    def to_row(self) -> dict[str, object]:
        """Return a stable JSON-serializable scorecard row."""
        return {
            "function_name": self.function_name,
            "raw_flags_count": self.raw_flags_count,
            "raw_ss_linear_count": self.raw_ss_linear_count,
            "raw_ds_linear_count": self.raw_ds_linear_count,
            "vvar_count": self.vvar_count,
            "anonymous_sub_count": self.anonymous_sub_count,
            "recovery_mode": self.recovery_mode,
            "validation_verdict": self.validation_verdict,
            "source_present": self.source_present,
        }


def _recovery_mode_from_output(output: str) -> str:
    lowered = output.lower()
    if "/* == asm fallback == */" in lowered:
        return "asm_fallback"
    if "/* -- c (non-optimized fallback) -- */" in lowered or "/* non-optimized fallback" in lowered:
        return "asm_fallback"
    if "/* == c == */" in lowered or "/* -- c -- */" in lowered:
        return "decompiled"
    return "unknown"


def _validation_verdict_from_output(output: str) -> str:
    def _impl() -> str:
        lowered = output.lower()
        metadata_match = _TAIL_VALIDATION_METADATA_RE.search(output)
        if metadata_match is not None:
            with_context = metadata_match.group(1)
            try:
                payload = json.loads(with_context)
            except Exception:
                payload = None
            if isinstance(payload, dict):
                surface = payload.get("surface", {})
                severity = surface.get("severity")
                if isinstance(severity, str) and severity:
                    if severity == "changed":
                        return "failed"
                    return severity
        for verdict in ("failed", "unknown", "uncollected", "stable", "changed"):
            if f"tail-validation:{verdict}" in lowered or f"validation={verdict}" in lowered:
                if verdict == "changed":
                    return "failed"
                return verdict
        if "[tail-validation] whole-tail validation changed" in lowered:
            return "failed"
        if "[tail-validation] whole-tail validation failed" in lowered:
            return "failed"
        if "[tail-validation] whole-tail validation clean" in lowered:
            return "stable"
        if "[tail-validation] whole-tail validation unknown" in lowered:
            return "unknown"
        if "[tail-validation] whole-tail validation uncollected" in lowered:
            return "uncollected"
        return "uncollected"

    return _impl()


def build_acceptance_scorecard(
    function_name: str,
    recovered_output: str,
    *,
    source_text: str | None = None,
) -> AcceptanceScorecard:
    """Build reporting-only quality counters for one recovered output."""
    recovery_mode = _recovery_mode_from_output(recovered_output)
    validation_verdict = _validation_verdict_from_output(recovered_output)
    if recovery_mode == "asm_fallback" and validation_verdict == "failed":
        # Scorecards track fallback degradation separately from strict CLI
        # validation printing ("failed").
        validation_verdict = "changed"
    return AcceptanceScorecard(
        function_name=function_name,
        raw_flags_count=len(_FLAGS_RE.findall(recovered_output)),
        raw_ss_linear_count=recovered_output.count("ss << 4") + len(_SS_LINEAR_RE.findall(recovered_output)),
        raw_ds_linear_count=recovered_output.count("ds << 4") + len(_DS_HELPER_LINEAR_RE.findall(recovered_output)),
        vvar_count=len(_VVAR_RE.findall(recovered_output)),
        anonymous_sub_count=len(_SUB_RE.findall(recovered_output)),
        recovery_mode=recovery_mode,
        validation_verdict=validation_verdict,
        source_present=bool(source_text),
    )
