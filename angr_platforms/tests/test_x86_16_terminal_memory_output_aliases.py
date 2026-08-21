from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.alias.terminal_memory_outputs import (
    TerminalMemoryAliasDisposition8616,
    TerminalMemoryAliasFailure8616,
    classify_terminal_memory_output_aliases_8616,
)
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.lowering import interprocedural_storage_live_out
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_live_out import (
    collect_function_memory_live_out_trials_8616,
)
from angr_platforms.X86_16.semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputEvidence8616,
    TerminalMemoryOutputFact8616,
    TerminalMemoryOutputStats8616,
    TerminalMemoryStoreSite8616,
)
from pytest import MonkeyPatch

FUNCTION = 0x1000
CALLER = 0x2000
CALLSITE = CALLER
LOAD = CALLER + 3


def _output(
    offset: int,
    size: int,
    *,
    space: MemSpace = MemSpace.DS,
    segment_origin: SegmentOrigin = SegmentOrigin.PROVEN,
) -> TerminalMemoryOutputFact8616:
    address = IRAddress(
        space,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=segment_origin,
    )
    return TerminalMemoryOutputFact8616(
        address,
        TerminalMemoryOutputDisposition8616.MUST_WRITE,
        (TerminalMemoryStoreSite8616(FUNCTION, 0, FUNCTION),),
        (FUNCTION,),
        (FUNCTION,),
    )


def _evidence(
    *outputs: TerminalMemoryOutputFact8616,
) -> TerminalMemoryOutputEvidence8616:
    count = len(outputs)
    return TerminalMemoryOutputEvidence8616(
        FUNCTION,
        outputs,
        None,
        TerminalMemoryOutputStats8616(count, count, count, count),
    )


def test_nested_views_retain_one_unique_maximal_alias_owner() -> None:
    evidence = classify_terminal_memory_output_aliases_8616(
        _evidence(_output(0x1200, 2), _output(0x1201, 1))
    )

    assert evidence.complete is True
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 2
    assert tuple(fact.key for fact in evidence.canonical_facts) == (
        (MemSpace.DS, 0x1200, 2),
    )
    subview = next(fact for fact in evidence.facts if fact.key[1] == 0x1201)
    assert subview.disposition is TerminalMemoryAliasDisposition8616.SUBVIEW
    assert subview.owner_range == evidence.canonical_facts[0].storage_range


def test_crossing_views_refuse_without_partial_alias_facts() -> None:
    evidence = classify_terminal_memory_output_aliases_8616(
        _evidence(_output(0x1200, 2), _output(0x1201, 2))
    )

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalMemoryAliasFailure8616.CROSSING_OVERLAP
    assert evidence.stats.raw_fact_count == evidence.stats.normalized_fact_count == 2
    assert evidence.stats.failure_count == 1


def test_equal_offsets_in_ds_and_es_remain_distinct_alias_owners() -> None:
    evidence = classify_terminal_memory_output_aliases_8616(
        _evidence(
            _output(0x1200, 2),
            _output(0x1200, 2, space=MemSpace.ES),
        )
    )

    assert evidence.complete is True
    assert {fact.storage_range.space for fact in evidence.canonical_facts} == {
        MemSpace.DS,
        MemSpace.ES,
    }


def test_unproven_segment_origin_refuses_alias_range() -> None:
    evidence = classify_terminal_memory_output_aliases_8616(
        _evidence(_output(0x1200, 2, segment_origin=SegmentOrigin.DEFAULTED))
    )

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalMemoryAliasFailure8616.RANGE_BUILD_REFUSED


def test_lowering_consumes_unique_alias_owner_for_nested_stores(
    monkeypatch: MonkeyPatch,
) -> None:
    owner_address = _output(0x1200, 2).address
    call = IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=FUNCTION, size=2),),
        size=2,
        addr=CALLSITE,
    )
    load = IRInstr(
        "LOAD",
        IRValue(MemSpace.TMP, name="t0", size=2),
        (owner_address,),
        size=2,
        addr=LOAD,
    )
    caller = SSAFunctionArtifact(
        function_addr=CALLER,
        blocks=(SSABlock(CALLER, (call, load), ()),),
        predecessor_map={CALLER: ()},
    )
    callee = SSAFunctionArtifact(
        function_addr=FUNCTION,
        blocks=(SSABlock(FUNCTION, (), ()),),
        predecessor_map={FUNCTION: ()},
    )
    project = SimpleNamespace(
        _inertia_function_ssa_artifacts_8616={CALLER: caller, FUNCTION: callee},
        _inertia_function_ssa_stages_8616={
            CALLER: FunctionSSAArtifactStage8616.SEMANTIC,
            FUNCTION: FunctionSSAArtifactStage8616.SEMANTIC,
        },
    )
    terminal = _evidence(_output(0x1200, 2), _output(0x1201, 1))
    condition = ConditionIR(
        "ne",
        IRValue(
            MemSpace.DS,
            offset=0x1200,
            size=2,
            memory_access_size=2,
            memory_access_insn=LOAD,
        ),
        IRValue(MemSpace.CONST, const=0, size=2),
        width_bits=16,
        producer_insn=LOAD,
    )
    monkeypatch.setattr(
        interprocedural_storage_live_out,
        "collect_terminal_memory_output_evidence_8616",
        lambda _project, _artifact: terminal,
    )
    monkeypatch.setattr(
        interprocedural_storage_live_out,
        "collect_typed_condition_artifacts_8616",
        lambda _project, _address: ([condition], ()),
    )

    collection = collect_function_memory_live_out_trials_8616(
        project,
        FUNCTION,
        (CallsiteStorageTrials8616(CALLER, FUNCTION, CALLSITE, stack_delta=0),),
        (FUNCTION,),
    )

    assert collection.complete is True
    assert collection.stats.raw_fact_count == collection.stats.materialized_count == 1
    effect = collection.callsites[0].facts[0]
    assert effect.alias_output.is_owner is True
    assert effect.storage.width == 2
    assert len(collection.callsites[0].trials) == 1
