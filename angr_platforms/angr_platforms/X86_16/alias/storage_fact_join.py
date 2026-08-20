"""Join already-proven adjacent Alias storage facts.

Layer: Alias.
Responsibility: own construction of a canonical combined Alias identity after a
consumer has selected exact adjacent views. Segmented joins retain every
original IR address because the legacy generic memory identity alone does not
distinguish DS from ES. This module does not discover candidates, infer widths,
mutate codegen, or inspect rendered text. Owns storage identity and exact
Alias-domain joins.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .alias_model_impl import AliasStorageFacts, _StackSlotIdentity


@dataclass(frozen=True, slots=True)
class SegmentedAliasRange8616:
    """Canonical Alias storage derived from exact adjacent segmented addresses."""

    space: MemSpace
    addresses: tuple[IRAddress, ...]
    source_facts: tuple[AliasStorageFacts, ...]
    storage: AliasStorageFacts

    @property
    def size(self) -> int:
        """Return the proven byte width of this segmented range."""
        return sum(address.size for address in self.addresses)

    @property
    def offset(self) -> int:
        """Return the first byte offset of this segmented range."""
        return int(self.addresses[0].offset)


def join_adjacent_stack_alias_facts_8616(
    low: AliasStorageFacts,
    high: AliasStorageFacts,
) -> AliasStorageFacts | None:
    """Return one canonical stack Alias fact for a proven adjacent pair."""
    if not low.can_join(high):
        return None
    low_identity = low.identity
    high_identity = high.identity
    if (
        low_identity is None
        or high_identity is None
        or low_identity[0] != "stack"
        or high_identity[0] != "stack"
        or not isinstance(low_identity[1], _StackSlotIdentity)
        or not isinstance(high_identity[1], _StackSlotIdentity)
    ):
        return None
    domain = low.domain.join(high.domain)
    slot = low_identity[1].join(high_identity[1])
    if domain is None or slot is None:
        return None
    return AliasStorageFacts(domain=domain, identity=("stack", slot))


def _memory_fact_matches_address_8616(
    address: IRAddress,
    fact: AliasStorageFacts,
) -> bool:
    view = fact.domain.view
    return (
        fact.domain.space == "memory"
        and fact.domain.width == address.size
        and fact.identity == ("memory", address.offset)
        and view is not None
        and view.bit_offset == address.offset * 8
        and view.bit_width == address.size * 8
        and not fact.needs_synthesis()
    )


def _stack_fact_matches_address_8616(
    address: IRAddress,
    fact: AliasStorageFacts,
) -> bool:
    identity = fact.identity
    view = fact.domain.view
    return (
        address.base in {("bp",), ("sp",)}
        and fact.domain.space == "stack"
        and fact.domain.width == address.size
        and identity is not None
        and identity[0] == "stack"
        and isinstance(identity[1], _StackSlotIdentity)
        and identity[1].base == address.base[0]
        and identity[1].offset == address.offset
        and identity[1].width == address.size
        and view is not None
        and view.bit_width == address.size * 8
        and not fact.needs_synthesis()
    )


def build_segmented_alias_range_8616(
    addresses: tuple[IRAddress, ...],
    facts: tuple[AliasStorageFacts, ...],
) -> SegmentedAliasRange8616 | None:
    """Build a range from one or more original adjacent segmented Alias facts."""
    if not addresses or len(addresses) != len(facts):
        return None
    first = addresses[0]
    if (
        first.space not in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        or first.status is not AddressStatus.STABLE
        or first.segment_origin is not SegmentOrigin.PROVEN
        or first.size <= 0
        or first.offset < 0
    ):
        return None
    for previous, current in zip(addresses[:-1], addresses[1:], strict=True):
        if (
            current.space is not first.space
            or current.base != first.base
            or current.status is not first.status
            or current.segment_origin is not first.segment_origin
            or current.expr != first.expr
            or current.version != first.version
            or current.size <= 0
            or current.offset != previous.offset + previous.size
        ):
            return None
    if addresses[-1].offset + addresses[-1].size > 0x10000:
        return None

    if first.space is MemSpace.SS:
        if not all(
            _stack_fact_matches_address_8616(address, fact)
            for address, fact in zip(addresses, facts, strict=True)
        ):
            return None
        combined = facts[0]
        for fact in facts[1:]:
            joined = join_adjacent_stack_alias_facts_8616(combined, fact)
            if joined is None:
                return None
            combined = joined
    else:
        if not all(
            _memory_fact_matches_address_8616(address, fact)
            for address, fact in zip(addresses, facts, strict=True)
        ):
            return None
        domain = facts[0].domain
        for fact in facts[1:]:
            joined_domain = domain.join(fact.domain)
            if joined_domain is None:
                return None
            domain = joined_domain
        combined = AliasStorageFacts(
            domain=domain,
            identity=(
                "memory",
                (first.space.value, first.offset, sum(address.size for address in addresses)),
            ),
        )
    return SegmentedAliasRange8616(
        space=first.space,
        addresses=addresses,
        source_facts=facts,
        storage=combined,
    )


def join_adjacent_segmented_alias_facts_8616(
    addresses: tuple[IRAddress, ...],
    facts: tuple[AliasStorageFacts, ...],
) -> SegmentedAliasRange8616 | None:
    """Join at least two original adjacent segmented Alias facts."""
    if len(addresses) < 2:
        return None
    return build_segmented_alias_range_8616(addresses, facts)


__all__ = [
    "SegmentedAliasRange8616",
    "build_segmented_alias_range_8616",
    "join_adjacent_segmented_alias_facts_8616",
    "join_adjacent_stack_alias_facts_8616",
]
