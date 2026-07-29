"""Layer: Tail Validation.

Responsibility: decide which recovered stack writes are observable validation effects.
Forbidden: stack variable recovery, alias ownership, or rewrite-stage stack repair.
"""

from __future__ import annotations

__all__ = ["include_x86_16_tail_validation_stack_write"]


def include_x86_16_tail_validation_stack_write(
    location: str,
    *,
    mode: str,
    observed_locations: set[str],
) -> bool:
    """Return whether a recovered stack write is observable for tail validation."""
    if mode == "coarse":
        return True
    if not location.startswith(("stack:", "stack_slot:")):
        return False
    # [bp+0] is not a stable user-visible stack slot in the 16-bit frame model.
    # Postprocess can transiently synthesize carrier writes there while recovering
    # arguments; treating it as a live-out observable produces false deltas.
    if location == "stack:+0x0":
        return False
    if location.startswith("stack_slot:SS:BP+0x0"):
        return False
    if location.startswith("stack:+"):
        return False
    if location.startswith("stack_slot:SS:BP+"):
        return False
    if location.startswith("stack:-"):
        return location in observed_locations
    if location.startswith("stack_slot:SS:BP-"):
        return location in observed_locations
    return location in observed_locations
