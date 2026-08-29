from __future__ import annotations

from angr_platforms.X86_16.alias.register_reaching_source import (
    RegisterReachingSourceResult8616,
    RegisterReachingSourceVerdict8616,
)
from angr_platforms.X86_16.alias.terminal_pointer_output_contracts import (
    TerminalPointerAliasEvidence8616,
    TerminalPointerAliasFact8616,
    TerminalPointerAliasStats8616,
)
from angr_platforms.X86_16.callsite_summary import CallsitePushSourceKind8616
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
    TerminalPointerOutputEvidence8616,
    TerminalPointerOutputFact8616,
    TerminalPointerOutputStats8616,
    TerminalPointerStoreSite8616,
)
from angr_platforms.X86_16.widening.terminal_pointer_output_contracts import (
    TerminalPointerOutputViewFailure8616,
)
from angr_platforms.X86_16.widening.terminal_pointer_output_views import (
    widen_terminal_pointer_output_views_8616,
)

FUNCTION = 0x1000
BP_VALUE = CallsitePushSourceKind8616.BP_VALUE.value


def _alias_fact(
    parameter_offset: int,
    relative_offset: int,
    width: int,
    *,
    base_version: int = 1,
    disposition: TerminalPointerOutputDisposition8616 = (
        TerminalPointerOutputDisposition8616.MUST_WRITE
    ),
    terminals: tuple[int, ...] = (FUNCTION,),
    definite: tuple[int, ...] = (FUNCTION,),
) -> TerminalPointerAliasFact8616:
    base = IRValue(MemSpace.REG, name="bx", size=2, version=base_version)
    address = IRAddress(
        MemSpace.DS,
        base=("bx",),
        offset=relative_offset,
        size=width,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(base,),
    )
    output = TerminalPointerOutputFact8616(
        address,
        base,
        disposition,
        (TerminalPointerStoreSite8616(FUNCTION, 0, FUNCTION),),
        terminals,
        definite,
    )
    parameter = IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=parameter_offset,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    source = RegisterReachingSourceResult8616(
        RegisterReachingSourceVerdict8616.PROVEN,
        (BP_VALUE, parameter_offset, 2),
        1,
        1,
        1,
        1,
        0,
    )
    return TerminalPointerAliasFact8616(output, parameter, (source,))


def _evidence(
    *facts: TerminalPointerAliasFact8616,
) -> TerminalPointerAliasEvidence8616:
    count = len(facts)
    terminal = TerminalPointerOutputEvidence8616(
        FUNCTION,
        tuple(fact.terminal_output for fact in facts),
        None,
        TerminalPointerOutputStats8616(count, count, count, count),
    )
    return TerminalPointerAliasEvidence8616(
        FUNCTION,
        facts,
        None,
        TerminalPointerAliasStats8616(count, count, count, count),
        terminal,
    )


def test_contiguous_byte_lanes_form_one_word_view() -> None:
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(_alias_fact(4, 0, 1), _alias_fact(4, 1, 1, base_version=2))
    )

    assert evidence.complete
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.materialized_count == 1
    assert len(evidence.facts) == 1
    assert (evidence.facts[0].relative_offset, evidence.facts[0].width) == (0, 2)
    assert len(evidence.facts[0].alias_outputs) == 2


def test_gap_and_distinct_parameters_remain_separate_views() -> None:
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(
            _alias_fact(4, 0, 1),
            _alias_fact(4, 2, 1, base_version=2),
            _alias_fact(6, 0, 1, base_version=3),
        )
    )

    assert evidence.complete
    assert len(evidence.facts) == 3
    assert {
        (fact.parameter_storage.offset, fact.relative_offset, fact.width)
        for fact in evidence.facts
    } == {(4, 0, 1), (4, 2, 1), (6, 0, 1)}


def test_adjacent_lanes_with_distinct_path_coverage_remain_separate() -> None:
    conditional = _alias_fact(
        4,
        1,
        1,
        base_version=2,
        disposition=TerminalPointerOutputDisposition8616.CONDITIONAL,
        terminals=(0x1010, 0x1020),
        definite=(0x1010,),
    )
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(_alias_fact(4, 0, 1), conditional)
    )

    assert evidence.complete
    assert len(evidence.facts) == 2


def test_overlapping_ranges_with_distinct_path_coverage_refuse_atomically() -> None:
    conditional = _alias_fact(
        4,
        1,
        1,
        base_version=2,
        disposition=TerminalPointerOutputDisposition8616.CONDITIONAL,
        terminals=(0x1010, 0x1020),
        definite=(0x1010,),
    )
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(_alias_fact(4, 0, 2), conditional)
    )

    assert not evidence.complete
    assert evidence.facts == ()
    assert (
        evidence.failure
        is TerminalPointerOutputViewFailure8616.OVERLAPPING_PATH_CONFLICT
    )


def test_duplicate_exact_output_refuses_atomically() -> None:
    fact = _alias_fact(4, 0, 1)
    evidence = widen_terminal_pointer_output_views_8616(_evidence(fact, fact))

    assert not evidence.complete
    assert evidence.facts == ()
    assert evidence.failure is TerminalPointerOutputViewFailure8616.DUPLICATE_OUTPUT
