from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.expression import Convert, StackBaseOffset, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.analyses.s_propagator import SPropagator
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr_platforms.X86_16.stack_compat import (
    StackPointerPropagationVerdict8616,
    apply_x86_16_stack_compatibility,
    normalize_stack_pointer_replacement_8616,
)


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


def test_x86_16_stack_compat_patch_installs_propagator_normalization_once() -> None:
    apply_x86_16_stack_compatibility()
    first = SPropagator._analyze

    apply_x86_16_stack_compatibility()

    assert first.__name__ == "_analyze_8616"
    assert SPropagator._analyze is first


def test_x86_16_stack_pointer_replacement_narrows_loader_address_width() -> None:
    manager = Manager()
    stack_pointer = VirtualVariable(
        manager.next_atom(),
        1,
        16,
        VirtualVariableCategory.REGISTER,
        oident=16,
    )
    stack_address = StackBaseOffset(manager.next_atom(), 32, -14)

    result = normalize_stack_pointer_replacement_8616(
        stack_pointer,
        stack_address,
        stack_register_offsets=frozenset((16, 20)),
        ail_manager=manager,
    )

    assert result.verdict is StackPointerPropagationVerdict8616.MATERIALIZED_NARROWING
    assert isinstance(result.replacement, Convert)
    assert result.replacement.from_bits == 32
    assert result.replacement.to_bits == 16
    assert result.replacement.operand == stack_address
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_x86_16_stack_pointer_replacement_refuses_unproven_upper_bits() -> None:
    manager = Manager()
    stack_pointer = VirtualVariable(
        manager.next_atom(),
        1,
        32,
        VirtualVariableCategory.REGISTER,
        oident=16,
    )
    stack_address = StackBaseOffset(manager.next_atom(), 16, 0)

    result = normalize_stack_pointer_replacement_8616(
        stack_pointer,
        stack_address,
        stack_register_offsets=frozenset((16, 20)),
        ail_manager=manager,
    )

    assert result.verdict is StackPointerPropagationVerdict8616.REFUSED_WIDENING
    assert result.replacement is stack_address
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
