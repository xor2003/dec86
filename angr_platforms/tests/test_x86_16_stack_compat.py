from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr_platforms.X86_16.stack_compat import apply_x86_16_stack_compatibility


class _StackOffsetToAddr(Protocol):
    __name__: str

    def __call__(self, self_obj: _LiveDefinitionsStub, offset: int) -> int: ...


@dataclass(frozen=True, slots=True)
class _ArchStub:
    bits: int


@dataclass(frozen=True, slots=True)
class _LiveDefinitionsStub:
    arch: _ArchStub


def test_x86_16_stack_compat_patches_16bit_stack_offsets() -> None:
    original = LiveDefinitions.stack_offset_to_stack_addr
    try:
        LiveDefinitions.stack_offset_to_stack_addr = original

        apply_x86_16_stack_compatibility()

        patched = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)
        assert patched.__name__ == "_stack_offset_to_stack_addr_8616"
        assert patched(_LiveDefinitionsStub(_ArchStub(bits=16)), 2) == 0x8000
        assert patched(_LiveDefinitionsStub(_ArchStub(bits=16)), -2) == 0x7FFC
    finally:
        LiveDefinitions.stack_offset_to_stack_addr = original


def test_x86_16_stack_compat_delegates_non_16bit_offsets() -> None:
    previous = LiveDefinitions.stack_offset_to_stack_addr

    def original(self_obj: _LiveDefinitionsStub, offset: int) -> int:
        return 0xABC000 + self_obj.arch.bits + offset

    try:
        LiveDefinitions.stack_offset_to_stack_addr = original

        apply_x86_16_stack_compatibility()

        patched = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)
        assert patched(_LiveDefinitionsStub(_ArchStub(bits=32)), 5) == 0xABC025
    finally:
        LiveDefinitions.stack_offset_to_stack_addr = previous


def test_x86_16_stack_compat_patch_is_idempotent() -> None:
    original = LiveDefinitions.stack_offset_to_stack_addr
    try:
        LiveDefinitions.stack_offset_to_stack_addr = original

        apply_x86_16_stack_compatibility()
        first = LiveDefinitions.stack_offset_to_stack_addr
        apply_x86_16_stack_compatibility()

        assert LiveDefinitions.stack_offset_to_stack_addr is first
    finally:
        LiveDefinitions.stack_offset_to_stack_addr = original
