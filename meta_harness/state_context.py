from __future__ import annotations


def merge_step_extra(*parts: str | None) -> str:
    """Join step-status context without dropping earlier facts."""

    cleaned = [part.strip() for part in parts if part and part.strip()]
    return "; ".join(cleaned)
