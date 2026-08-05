"""Normalize exact BP-relative value sources from callsite summaries.

Layer: Semantics/Callsite summary.
Responsibility: convert structured callsite push-source records into typed
stack value evidence without selecting or mutating structured-C arguments.
Forbidden: instruction discovery, rendered-text matching, AST mutation, or
prototype-based width guessing.
"""

from __future__ import annotations

from dataclasses import dataclass

from .callsite_summary import CallsitePushSourceKind8616

__all__ = [
    "CallArgumentStackValueSource8616",
    "call_argument_stack_value_source_8616",
]


@dataclass(frozen=True, slots=True)
class CallArgumentStackValueSource8616:
    """Exact BP-relative storage read that feeds one physical argument PUSH."""

    offset: int
    width: int


def call_argument_stack_value_source_8616(
    source: object,
) -> CallArgumentStackValueSource8616 | None:
    """Return typed evidence only for an exact width-bearing BP value source."""
    if not isinstance(source, tuple) or len(source) != 3:
        return None
    source_kind, offset, width = source
    if (
        source_kind != CallsitePushSourceKind8616.BP_VALUE.value
        or type(offset) is not int
        or type(width) is not int
        or width not in {1, 2, 4}
    ):
        return None
    return CallArgumentStackValueSource8616(offset=offset, width=width)
