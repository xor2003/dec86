from __future__ import annotations

from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
from angr_platforms.X86_16.lowering.segment_access_policy import (
    SegmentAccessLoweringDecision8616,
    SegmentAccessLoweringResult8616,
    classify_local_segment_access_8616,
)


def _byte_fact(
    offset: int,
    *,
    instruction_addr: int = 0x1010,
    kind: SegmentAccessKind = SegmentAccessKind.READ,
    source: str | None = "ds",
    verdict: SegmentFactVerdict = SegmentFactVerdict.PROVEN,
) -> SegmentAccessFact:
    return SegmentAccessFact(
        block_addr=0x1000,
        instruction_addr=instruction_addr,
        kind=kind,
        address=IRAddress(
            space=MemSpace.DS,
            base=("bx",),
            offset=offset,
            size=1,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
            expr=("segmented_linear", "ds", "bx"),
        ),
        segment_register="ds",
        physical_source=source,
        verdict=verdict,
    )


def _classify(
    *facts: SegmentAccessFact,
    instruction_addrs: frozenset[int] = frozenset({0x1010}),
    offset: int | None = None,
) -> SegmentAccessLoweringResult8616:
    contract = SegmentFunctionContract(function_addr=0x1000, accesses=facts)
    return classify_local_segment_access_8616(
        contract,
        instruction_addrs=instruction_addrs,
        segment_register="ds",
        offset=offset,
        width=2,
    )


def test_segment_access_policy_joins_exact_proven_byte_pair() -> None:
    result = _classify(_byte_fact(0), _byte_fact(1))

    assert result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert result.stats.raw_fact_count == 2
    assert result.stats.normalized_fact_count == 2
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_segment_access_policy_joins_unique_byte_pair_without_instruction_provenance() -> None:
    result = _classify(
        _byte_fact(68),
        _byte_fact(69),
        instruction_addrs=frozenset(),
        offset=68,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert tuple(fact.address.offset for fact in result.facts) == (68, 69)


def test_segment_access_policy_refuses_ambiguous_byte_pairs_without_instruction_provenance() -> None:
    result = _classify(
        _byte_fact(68),
        _byte_fact(69),
        _byte_fact(68, instruction_addr=0x1020),
        _byte_fact(69, instruction_addr=0x1020),
        instruction_addrs=frozenset(),
        offset=68,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
    assert result.stats.raw_fact_count == 4
    assert result.stats.normalized_fact_count == 0
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_segment_access_policy_refuses_incomplete_or_incoherent_byte_pair() -> None:
    cases = (
        (_byte_fact(0),),
        (_byte_fact(0), _byte_fact(1, source=None, verdict=SegmentFactVerdict.UNKNOWN_REFUSE)),
        (_byte_fact(0), _byte_fact(1, kind=SegmentAccessKind.WRITE)),
    )
    for facts in cases:
        assert _classify(*facts).decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
