"""Tests for the request-owned decoded direct-call index."""

from __future__ import annotations

from dataclasses import dataclass

from angr_platforms.X86_16.frontend_direct_callsite_index import (
    build_decoded_direct_callsite_index_8616,
)


@dataclass(frozen=True, slots=True)
class _Instruction:
    target: int | None
    address: int | None


def test_direct_callsite_index_scans_once_and_normalizes_16_bit_targets() -> None:
    resolver_calls: list[_Instruction] = []
    address_calls: list[_Instruction] = []
    first = _Instruction(0x12345, 0x1010)
    invalid = _Instruction(0x2345, None)
    non_call = _Instruction(None, 0x1012)
    second = _Instruction(0x2345, 0x2010)
    decoded_ranges = {
        (0x2000, 0x2020): (second,),
        (0x1000, 0x1020): (first, invalid, non_call),
    }

    def resolve_target(instruction: object) -> int | None:
        typed = instruction
        assert isinstance(typed, _Instruction)
        resolver_calls.append(typed)
        return typed.target

    def resolve_address(instruction: object) -> int | None:
        typed = instruction
        assert isinstance(typed, _Instruction)
        address_calls.append(typed)
        return typed.address

    index = build_decoded_direct_callsite_index_8616(
        decoded_ranges,
        direct_target_resolver=resolve_target,
        instruction_address_resolver=resolve_address,
    )

    assert resolver_calls == [first, invalid, non_call, second]
    assert address_calls == [first, invalid, second]
    assert index.for_target(0x2345) == index.for_target(0x12345)
    assert tuple(callsite.callsite_addr for callsite in index.for_target(0x2345)) == (
        0x1010,
        0x2010,
    )
    assert index.stats.raw_fact_count == 3
    assert index.stats.normalized_fact_count == 3
    assert index.stats.classified_fact_count == 2
    assert index.stats.materialized_count == 2
    assert index.stats.failure_count == 1
    assert index.stats.closed is True


def test_direct_callsite_index_returns_empty_for_unknown_target() -> None:
    index = build_decoded_direct_callsite_index_8616(
        {},
        direct_target_resolver=lambda _instruction: None,
        instruction_address_resolver=lambda _instruction: None,
    )

    assert index.for_target(0xBEEF) == ()
    assert index.stats.closed is True
