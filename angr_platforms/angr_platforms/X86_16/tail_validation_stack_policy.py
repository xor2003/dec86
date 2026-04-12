from __future__ import annotations

__all__ = ["include_x86_16_tail_validation_stack_write"]


def include_x86_16_tail_validation_stack_write(
    location: str,
    *,
    mode: str,
    observed_locations: set[str],
) -> bool:
    if mode == "coarse":
        return True
    if not location.startswith("stack:"):
        return False
    if location.startswith("stack:-"):
        return False
    return location in observed_locations
