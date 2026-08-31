from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
)
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.callsite_summary_program import (
    program_callsite_summary_evidence_8616,
)
from angr_platforms.X86_16.callsite_target_inventory import (
    CallsiteTargetInventory8616,
)
from angr_platforms.X86_16.lowering import callee_callsite_census
from angr_platforms.X86_16.lowering import project_callee_callsite_collection as collection
from angr_platforms.X86_16.lowering.callee_callsite_codec import (
    callee_callsite_census_map_from_record_8616,
    callee_callsite_census_map_record_8616,
)
from angr_platforms.X86_16.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)


def _summary(callsite_addr: int, target_addr: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=callsite_addr + 3,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("imm", 7),),
        push_arg_instruction_addrs=(callsite_addr - 2,),
    )


def _census(project: object, target_addr: int = 0x2200) -> CalleeCallsiteCensus8616:
    fact = CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=SimpleNamespace(addr=0x1100),
        evidence_target_addr=target_addr,
        caller_addr=0x1100,
        callsite_addr=0x1110,
        summary=_summary(0x1110, target_addr),
    )
    return CalleeCallsiteCensus8616(target_addr, (fact,), 1, 1, 0)


def test_callee_callsite_codec_round_trips_and_rebinds_owner() -> None:
    source = SimpleNamespace()
    attach_callee_callsite_censuses_8616(source, {0x2200: _census(source)})
    record = callee_callsite_census_map_record_8616(source)
    decoded_json = json.loads(json.dumps(record, sort_keys=True))
    destination = SimpleNamespace()

    restored = callee_callsite_census_map_from_record_8616(
        destination,
        decoded_json,
    )

    fact = restored[0x2200].facts[0]
    assert fact.evidence_project is destination
    assert fact.caller_function is None
    assert fact.summary == _summary(0x1110, 0x2200)


def test_callee_callsite_codec_rejects_duplicate_targets() -> None:
    source = SimpleNamespace()
    attach_callee_callsite_censuses_8616(source, {0x2200: _census(source)})
    record = callee_callsite_census_map_record_8616(source)

    with pytest.raises(ValueError, match="duplicate targets"):
        callee_callsite_census_map_from_record_8616(
            SimpleNamespace(),
            [record[0], record[0]],
        )


def test_complete_project_collection_scans_each_function_once_and_publishes_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = SimpleNamespace()
    functions = (SimpleNamespace(addr=0x1100, size=0x30),)
    targets = (
        CallTargetSeed(
            0x1110,
            0x2200,
            0x1113,
            CallTargetKind8616.DIRECT_NEAR_CALL,
        ),
        CallTargetSeed(
            0x1120,
            0x2200,
            0x1123,
            CallTargetKind8616.DIRECT_NEAR_CALL,
        ),
    )
    calls = {"neighbors": 0, "summaries": 0, "ranges": 0}

    def neighbors(_function: object) -> list[CallTargetSeed]:
        calls["neighbors"] += 1
        return list(targets)

    def summarize(
        _function: object,
        callsite_addr: int,
        *,
        target_inventory: CallsiteTargetInventory8616,
    ) -> CallsiteSummary8616:
        calls["summaries"] += 1
        assert target_inventory.seeds == targets
        return _summary(callsite_addr, 0x2200)

    def range_facts(
        _project: object,
        _ranges: tuple[tuple[int, int], ...],
        *,
        excluded_fact_keys: frozenset[tuple[int, int]],
    ) -> tuple[CalleeCallsiteFact8616, ...]:
        calls["ranges"] += 1
        assert excluded_fact_keys == frozenset(
            {(0x2200, 0x1110), (0x2200, 0x1120)}
        )
        return ()

    monkeypatch.setattr(collection, "collect_neighbor_call_targets", neighbors)
    monkeypatch.setattr(collection, "summarize_x86_16_callsite", summarize)
    monkeypatch.setattr(collection, "collect_range_callsite_facts_8616", range_facts)

    result = collection.collect_complete_project_callee_callsites_8616(
        project,
        functions,
    )

    assert result.target_addrs == (0x2200,)
    assert result.raw_fact_count == result.materialized_count == 2
    assert result.failure_count == 0
    assert calls == {"neighbors": 1, "summaries": 2, "ranges": 1}
    program_summaries = program_callsite_summary_evidence_8616(project)
    assert program_summaries is not None
    assert program_summaries.materialized_count == 2
    assert program_summaries.facts[0].caller_addr == 0x1100
    assert program_summaries.facts[0].callsite_addr == 0x1110
    monkeypatch.setattr(
        callee_callsite_census,
        "collect_neighbor_call_targets",
        lambda _function: pytest.fail("cached census must not rescan functions"),
    )
    assert callee_callsite_census.collect_callee_callsite_census_8616(
        project,
        0x2200,
    ) == callee_callsite_censuses_by_addr_8616(project)[0x2200]
