"""Project immutable entry-address tags from one structured-C subtree.

Layer: Structuring.
Responsibility: collect instruction and VEX-block entry tags in one read-only
walk so Structuring consumers do not independently traverse the same subtree.
Dynamic boundary: angr structured-C nodes expose version-dependent tag fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..structured_tags import copy_structured_tags_8616


class _TaggedStructuredNode8616(Protocol):
    """Minimal third-party structured-C tag surface."""

    tags: object


@dataclass(frozen=True, slots=True)
class StructuredSubtreeEntryTags8616:
    """Immutable instruction and block entry tags for one subtree."""

    first_instruction_addr: int | None
    block_addrs: tuple[int, ...]

    @property
    def first_block_addr(self) -> int | None:
        """Return the lowest represented VEX block address."""
        return self.block_addrs[0] if self.block_addrs else None


def collect_structured_subtree_entry_tags_8616(
    node: object,
) -> StructuredSubtreeEntryTags8616:
    """Collect instruction and block tags in one deterministic subtree walk."""
    first_instruction_addr: int | None = None
    block_addrs: set[int] = set()
    for current in _iter_c_nodes_deep_8616(node):
        boundary = cast(_TaggedStructuredNode8616, current)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        copied_tags = copy_structured_tags_8616(tags)
        if copied_tags is None:
            continue
        instruction_addr = copied_tags.get("ins_addr")
        if isinstance(instruction_addr, int) and (
            first_instruction_addr is None
            or instruction_addr < first_instruction_addr
        ):
            first_instruction_addr = instruction_addr
        block_addr = copied_tags.get("vex_block_addr")
        if isinstance(block_addr, int):
            block_addrs.add(block_addr)
    return StructuredSubtreeEntryTags8616(
        first_instruction_addr=first_instruction_addr,
        block_addrs=tuple(sorted(block_addrs)),
    )


__all__ = [
    "StructuredSubtreeEntryTags8616",
    "collect_structured_subtree_entry_tags_8616",
]
