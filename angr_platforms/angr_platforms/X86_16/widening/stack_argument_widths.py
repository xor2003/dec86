"""Prove logical wide stack arguments from typed word-operation facts.

Layer: Widening.
Responsibility: join adjacent BP word operands only when carry-linked arithmetic
or register-linked high-word comparison proves one logical parameter.
Consumes alias-proven storage identity and typed frontend instruction facts.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum

__all__ = [
    "StackWordArithmeticFact8616",
    "StackWordRegisterRole8616",
    "WideStackArgumentWidthEvidence8616",
    "analyze_wide_stack_argument_widths_8616",
]


class StackWordRegisterRole8616(Enum):
    """Semantic ABI role of one instruction destination register."""

    OTHER = "other"
    AX_LOW_RETURN = "ax_low_return"
    DX_HIGH_RETURN = "dx_high_return"


@dataclass(frozen=True, slots=True)
class StackWordArithmeticFact8616:
    """Typed frontend fact for one instruction operating on a BP word."""

    mnemonic: str
    destination_register: int | None
    source_bp_offset: int | None
    compared_register: int | None = None
    destination_role: StackWordRegisterRole8616 = StackWordRegisterRole8616.OTHER


@dataclass(frozen=True, slots=True)
class WideStackArgumentWidthEvidence8616:
    """Closed evidence census for proven logical wide stack arguments."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_offsets: tuple[int, ...]
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def classified_fact_count(self) -> int:
        """Return the number of distinct proven wide argument offsets."""
        return len(self.classified_offsets)

    def with_materialized_count(self, count: int) -> WideStackArgumentWidthEvidence8616:
        """Return this evidence with its lowering materialization count."""
        return replace(self, materialized_count=count)


def analyze_wide_stack_argument_widths_8616(
    instruction_groups: Iterable[Iterable[StackWordArithmeticFact8616]],
) -> WideStackArgumentWidthEvidence8616:
    """Classify adjacent BP words joined by carry or high-word comparison."""
    raw_fact_count = 0
    normalized_fact_count = 0
    failure_count = 0
    classified_offsets: set[int] = set()
    carry_mnemonic = {"add": "adc", "sub": "sbb"}
    for instruction_group in instruction_groups:
        instructions = tuple(instruction_group)
        for index, (low, high) in enumerate(zip(instructions, instructions[1:])):
            if (
                low.mnemonic.lower() != "mov"
                or high.mnemonic.lower() != "mov"
                or low.destination_role is not StackWordRegisterRole8616.AX_LOW_RETURN
                or high.destination_role is not StackWordRegisterRole8616.DX_HIGH_RETURN
            ):
                continue
            raw_fact_count += 1
            if low.source_bp_offset is None or high.source_bp_offset is None:
                failure_count += 1
                continue
            normalized_fact_count += 1
            later_return_write = any(
                fact.destination_role
                in {
                    StackWordRegisterRole8616.AX_LOW_RETURN,
                    StackWordRegisterRole8616.DX_HIGH_RETURN,
                }
                for fact in instructions[index + 2 :]
            )
            if high.source_bp_offset != low.source_bp_offset + 2 or later_return_write:
                failure_count += 1
                continue
            classified_offsets.add(low.source_bp_offset)
        for index, (low, high) in enumerate(zip(instructions, instructions[1:])):
            if carry_mnemonic.get(low.mnemonic.lower()) != high.mnemonic.lower():
                continue
            raw_fact_count += 1
            if low.source_bp_offset is None or high.source_bp_offset is None:
                failure_count += 1
                continue
            normalized_fact_count += 1
            if (
                high.source_bp_offset != low.source_bp_offset + 2
                or low.destination_register is None
                or high.destination_register is None
                or low.destination_register == high.destination_register
            ):
                failure_count += 1
                continue
            classified_offsets.add(low.source_bp_offset)
            if index < 2:
                continue
            seed_low, seed_high = instructions[index - 2 : index]
            if seed_low.mnemonic.lower() != "mov" or seed_high.mnemonic.lower() != "mov":
                continue
            raw_fact_count += 1
            if seed_low.source_bp_offset is None or seed_high.source_bp_offset is None:
                failure_count += 1
                continue
            normalized_fact_count += 1
            if (
                seed_high.source_bp_offset != seed_low.source_bp_offset + 2
                or seed_low.destination_register != low.destination_register
                or seed_high.destination_register != high.destination_register
            ):
                failure_count += 1
                continue
            classified_offsets.add(seed_low.source_bp_offset)

        for seed_low, seed_high, high_compare in zip(
            instructions,
            instructions[1:],
            instructions[2:],
        ):
            if (
                seed_low.mnemonic.lower() != "mov"
                or seed_high.mnemonic.lower() != "mov"
                or high_compare.mnemonic.lower() != "cmp"
            ):
                continue
            raw_fact_count += 1
            if (
                seed_low.source_bp_offset is None
                or seed_high.source_bp_offset is None
                or high_compare.source_bp_offset is None
            ):
                failure_count += 1
                continue
            normalized_fact_count += 1
            compared_low_offset = high_compare.source_bp_offset - 2
            if (
                seed_high.source_bp_offset != seed_low.source_bp_offset + 2
                or compared_low_offset < 4
                or seed_low.destination_register is None
                or seed_high.destination_register is None
                or seed_low.destination_register == seed_high.destination_register
                or high_compare.compared_register != seed_high.destination_register
            ):
                failure_count += 1
                continue
            classified_offsets.add(seed_low.source_bp_offset)
            classified_offsets.add(compared_low_offset)
    return WideStackArgumentWidthEvidence8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_offsets=tuple(sorted(classified_offsets)),
        failure_count=failure_count,
    )
