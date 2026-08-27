"""Propagate exact segment-byte identities through stack-backed IR values.

Layer: Alias.
Responsibility: track byte provenance through typed values and exact SS:SP
storage. Owns storage identity. This module does not classify segment-register
writes or update IR segment state. Do not perform lowering, structuring,
rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..ir.core import AddressStatus, IRAddress, IRAtom, IRInstr, IRValue, MemSpace
from ..ir.segment_state_transfer import SEGMENT_REGISTERS

__all__ = [
    "SegmentStackByteOrigin8616",
    "SegmentStackFragments8616",
    "complete_segment_restore_8616",
    "computed_segment_fragments_8616",
    "segment_value_fragments_8616",
    "stack_load_fragments_8616",
    "store_stack_fragments_8616",
]


@dataclass(frozen=True, slots=True)
class SegmentStackByteOrigin8616:
    """One byte of a segment read as it moves through stack storage."""

    saved_register: str
    saved_instruction_addr: int
    origin_byte: int
    value_byte: int
    stack_offset: int | None = None


type SegmentStackFragments8616 = frozenset[SegmentStackByteOrigin8616]


def _expr_narrows_to_byte(value: IRValue) -> bool:
    """Return whether typed conversion metadata keeps only value byte zero."""
    return any(token.endswith("to8") for token in (value.expr or ()))


def segment_value_fragments_8616(
    value: IRAtom | None,
    instruction_addr: int,
    values: dict[str, SegmentStackFragments8616],
) -> SegmentStackFragments8616:
    """Read symbolic segment-byte provenance for one typed value."""
    if not isinstance(value, IRValue):
        return frozenset()
    if value.space is MemSpace.REG and value.name in SEGMENT_REGISTERS:
        fragments = frozenset(
            SegmentStackByteOrigin8616(value.name, instruction_addr, byte, byte)
            for byte in range(2)
        )
    elif value.name is not None:
        fragments = values.get(value.name, frozenset())
    else:
        fragments = frozenset()
    if _expr_narrows_to_byte(value):
        return frozenset(fragment for fragment in fragments if fragment.value_byte == 0)
    return fragments


def _shift_fragments(
    fragments: SegmentStackFragments8616,
    bits: int,
    *,
    left: bool,
) -> SegmentStackFragments8616:
    """Shift byte-aligned symbolic fragments without inventing partial bytes."""
    if bits < 0 or bits % 8:
        return frozenset()
    byte_delta = bits // 8
    shifted: set[SegmentStackByteOrigin8616] = set()
    for fragment in fragments:
        value_byte = fragment.value_byte + byte_delta if left else fragment.value_byte - byte_delta
        if 0 <= value_byte < 2:
            shifted.add(replace(fragment, value_byte=value_byte))
    return frozenset(shifted)


def _merge_fragments(
    lhs: SegmentStackFragments8616,
    rhs: SegmentStackFragments8616,
) -> SegmentStackFragments8616:
    """Union non-conflicting byte positions for a typed OR composition."""
    merged = lhs | rhs
    positions: dict[int, SegmentStackByteOrigin8616] = {}
    for fragment in merged:
        existing = positions.get(fragment.value_byte)
        if existing is not None and existing != fragment:
            return frozenset()
        positions[fragment.value_byte] = fragment
    return merged


def _stack_offset(address: IRAddress, sp_delta: int | None) -> int | None:
    """Resolve an exact same-block SS:SP byte offset from entry SP."""
    if (
        sp_delta is None
        or address.space is not MemSpace.SS
        or address.status is not AddressStatus.STABLE
        or address.base != ("sp",)
    ):
        return None
    return sp_delta + address.offset


def stack_load_fragments_8616(
    address: IRAddress,
    width: int,
    sp_delta: int | None,
    stack_bytes: dict[int, SegmentStackByteOrigin8616],
) -> SegmentStackFragments8616:
    """Load only when every requested stack byte has proven identity."""
    offset = _stack_offset(address, sp_delta)
    if offset is None or width <= 0:
        return frozenset()
    loaded: set[SegmentStackByteOrigin8616] = set()
    for value_byte in range(width):
        fragment = stack_bytes.get(offset + value_byte)
        if fragment is None:
            return frozenset()
        loaded.add(replace(fragment, value_byte=value_byte))
    return frozenset(loaded)


def store_stack_fragments_8616(
    address: IRAddress,
    value: IRValue,
    fragments: SegmentStackFragments8616,
    sp_delta: int | None,
    stack_bytes: dict[int, SegmentStackByteOrigin8616],
) -> None:
    """Overwrite exact stack bytes, retaining only fully proved fragments."""
    offset = _stack_offset(address, sp_delta)
    if offset is None:
        if address.space in {MemSpace.SS, MemSpace.UNKNOWN}:
            stack_bytes.clear()
        return
    fragment_width = max((fragment.value_byte + 1 for fragment in fragments), default=1)
    width = max(1, value.size, fragment_width)
    for byte in range(width):
        stack_bytes.pop(offset + byte, None)
    for fragment in fragments:
        slot = offset + fragment.value_byte
        stack_bytes[slot] = replace(fragment, stack_offset=slot)


def _constant_arg(instruction: IRInstr, index: int) -> int | None:
    """Read one exact integer operand from a typed IR instruction."""
    if index >= len(instruction.args):
        return None
    value = instruction.args[index]
    return value.const if isinstance(value, IRValue) and value.space is MemSpace.CONST else None


def computed_segment_fragments_8616(
    instruction: IRInstr,
    values: dict[str, SegmentStackFragments8616],
) -> SegmentStackFragments8616:
    """Transfer byte provenance through lossless MOV, shift, and OR operations."""
    if instruction.addr is None or not instruction.args:
        return frozenset()
    lhs = segment_value_fragments_8616(instruction.args[0], instruction.addr, values)
    if instruction.op == "MOV":
        return lhs
    if "Shr" in instruction.op:
        bits = _constant_arg(instruction, 1)
        return frozenset() if bits is None else _shift_fragments(lhs, bits, left=False)
    if "Shl" in instruction.op:
        bits = _constant_arg(instruction, 1)
        return frozenset() if bits is None else _shift_fragments(lhs, bits, left=True)
    if "Or" in instruction.op and len(instruction.args) == 2:
        rhs = segment_value_fragments_8616(instruction.args[1], instruction.addr, values)
        return _merge_fragments(lhs, rhs)
    return frozenset()


def complete_segment_restore_8616(
    fragments: SegmentStackFragments8616,
) -> tuple[str, int, tuple[int, ...]] | None:
    """Return one complete two-byte source only when every identity agrees."""
    if len(fragments) != 2:
        return None
    registers = {fragment.saved_register for fragment in fragments}
    save_sites = {fragment.saved_instruction_addr for fragment in fragments}
    origin_bytes = {fragment.origin_byte for fragment in fragments}
    value_bytes = {fragment.value_byte for fragment in fragments}
    stack_offsets = sorted(
        fragment.stack_offset
        for fragment in fragments
        if fragment.stack_offset is not None
    )
    if (
        len(registers) != 1
        or len(save_sites) != 1
        or origin_bytes != {0, 1}
        or value_bytes != {0, 1}
        or len(stack_offsets) != 2
        or stack_offsets[1] - stack_offsets[0] != 1
    ):
        return None
    return next(iter(registers)), next(iter(save_sites)), tuple(stack_offsets)
