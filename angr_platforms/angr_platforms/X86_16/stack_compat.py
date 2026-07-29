"""Layer: Frontend/angr compatibility.

Responsibility: patch angr stack address translation for 16-bit x86 stack facts.
Forbidden: stack variable recovery, alias ownership, or rewrite-stage stack repair.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast

from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

__all__ = ["apply_x86_16_stack_compatibility"]

_PATCHED_STACK_OFFSET_TO_ADDR_NAME = "_stack_offset_to_stack_addr_8616"
_StackOffsetToAddr = Callable[["_LiveDefinitionsLike", int], int]


class _StackArch(Protocol):
    @property
    def bits(self) -> int:
        """Return the angr architecture bit width."""
        ...


class _LiveDefinitionsLike(Protocol):
    @property
    def arch(self) -> _StackArch:
        """Return the angr architecture object attached to live definitions."""
        ...


class _NamedStackOffsetToAddr(Protocol):
    __name__: str

    def __call__(self, _: _LiveDefinitionsLike, offset: int) -> int: ...


def apply_x86_16_stack_compatibility() -> None:
    """Patch angr stack offsets so 16-bit stack addresses stay word-sized."""
    original_stack_offset_to_stack_addr = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)

    def _stack_offset_to_stack_addr_8616(self: _LiveDefinitionsLike, offset: int) -> int:
        if self.arch.bits == 16:
            return (0x7FFE + offset) & 0xFFFF
        return original_stack_offset_to_stack_addr(self, offset)

    current_stack_offset_to_stack_addr = cast(_NamedStackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)
    if current_stack_offset_to_stack_addr.__name__ != _PATCHED_STACK_OFFSET_TO_ADDR_NAME:
        LiveDefinitions.stack_offset_to_stack_addr = _stack_offset_to_stack_addr_8616
