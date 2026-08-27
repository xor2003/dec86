from __future__ import annotations

from types import SimpleNamespace

import angr_platforms.X86_16.segment_function_summary as segment_summary
from angr_platforms.X86_16.analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
    collect_direct_far_call_targets,
    collect_neighbor_call_targets,
    resolve_direct_call_target_from_block,
)
from angr_platforms.X86_16.ir.segment_contract import SegmentFactVerdict, SegmentFunctionContract
from angr_platforms.X86_16.segment_function_summary import (
    SegmentControlTransferDistance8616,
    SegmentControlTransferFact8616,
    SegmentControlTransferKind8616,
    apply_x86_16_segment_function_summary,
    build_x86_16_segment_control_transfers,
    join_x86_16_segment_function_summaries,
)


def _local_contract(function_addr: int, *clobbers: str) -> SegmentFunctionContract:
    return SegmentFunctionContract(
        function_addr=function_addr,
        clobbered_registers=clobbers,
        summary={
            "raw_fact_count": 0,
            "normalized_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "failure_count": 0,
        },
    )


def _transfer(site: int, target: int) -> SegmentControlTransferFact8616:
    return SegmentControlTransferFact8616(
        instruction_addr=site,
        kind=SegmentControlTransferKind8616.CALL,
        distance=SegmentControlTransferDistance8616.NEAR,
        target_addr=target,
        return_addr=site + 3,
        verdict=SegmentFactVerdict.PROVEN,
    )


def test_control_transfers_preserve_near_far_and_unresolved_calls(monkeypatch) -> None:
    function = SimpleNamespace(get_call_sites=lambda: (0x10, 0x20, 0x30))
    monkeypatch.setattr(
        segment_summary,
        "collect_neighbor_call_targets",
        lambda _function: (
            CallTargetSeed(0x10, 0x110, 0x13, CallTargetKind8616.DIRECT_NEAR_CALL),
            CallTargetSeed(0x20, 0x220, 0x25, CallTargetKind8616.DIRECT_FAR_CALL),
            CallTargetSeed(0x40, 0x440, None, CallTargetKind8616.DIRECT_FAR_TAIL_JUMP),
        ),
    )

    facts = build_x86_16_segment_control_transfers(function)

    assert tuple(fact.distance for fact in facts) == (
        SegmentControlTransferDistance8616.NEAR,
        SegmentControlTransferDistance8616.FAR,
        SegmentControlTransferDistance8616.UNKNOWN,
        SegmentControlTransferDistance8616.FAR,
    )
    assert facts[2].target_addr is None
    assert facts[2].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert facts[3].kind is SegmentControlTransferKind8616.TAIL_JUMP


def test_function_summary_propagates_transitive_callee_clobbers() -> None:
    contracts = {
        0x100: _local_contract(0x100),
        0x200: _local_contract(0x200),
        0x300: _local_contract(0x300, "es"),
    }
    transfers = {0x100: (_transfer(0x110, 0x200),), 0x200: (_transfer(0x210, 0x300),)}

    summaries = join_x86_16_segment_function_summaries(contracts, transfers)

    assert summaries[0x100].effective_clobbered_registers == ("es",)
    assert summaries[0x100].callee_effects[0].clobbered_registers == ("es",)
    assert summaries[0x100].callee_effects[0].verdict is SegmentFactVerdict.PROVEN
    assert summaries[0x100].unresolved_effect_sites == ()


def test_function_summary_refuses_missing_or_transitively_unknown_callee() -> None:
    contracts = {0x100: _local_contract(0x100, "ds"), 0x200: _local_contract(0x200)}
    transfers = {0x100: (_transfer(0x110, 0x200),), 0x200: (_transfer(0x210, 0x999),)}

    summaries = join_x86_16_segment_function_summaries(contracts, transfers)

    assert summaries[0x100].effective_clobbered_registers == ("ds",)
    assert summaries[0x100].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert summaries[0x100].unresolved_effect_sites == (0x110,)
    assert summaries[0x200].unresolved_effect_sites == (0x210,)


def test_apply_function_summary_registers_current_project_contract(monkeypatch) -> None:
    function = SimpleNamespace(addr=0x100, get_call_sites=lambda: ())
    project = SimpleNamespace(_inertia_active_structuring_function_8616=function)
    codegen = SimpleNamespace(_inertia_segment_function_contract=_local_contract(0x100))
    monkeypatch.setattr(segment_summary, "collect_neighbor_call_targets", lambda _function: ())

    changed = apply_x86_16_segment_function_summary(project, codegen)

    assert changed is False
    assert codegen._inertia_segment_function_summary_8616.function_addr == 0x100
    assert project._inertia_segment_function_summaries_8616[0x100].summary["failure_count"] == 0


def test_apply_function_summary_accepts_slotted_angr_function_surface(monkeypatch) -> None:
    class SlottedFunction:
        __slots__ = ("addr",)

        def __init__(self) -> None:
            self.addr = 0x100

        def get_call_sites(self) -> tuple[int, ...]:
            return ()

    function = SlottedFunction()
    project = SimpleNamespace(_inertia_active_structuring_function_8616=function)
    codegen = SimpleNamespace(_inertia_segment_function_contract=_local_contract(0x100))
    monkeypatch.setattr(segment_summary, "collect_neighbor_call_targets", lambda _function: ())

    changed = apply_x86_16_segment_function_summary(project, codegen)

    assert changed is False
    assert codegen._inertia_segment_function_summary_8616.function_addr == 0x100
    assert project._inertia_segment_function_summaries_8616[0x100].function_addr == 0x100


def test_neighbor_collection_distinguishes_direct_far_call() -> None:
    def operand(immediate: int) -> SimpleNamespace:
        return SimpleNamespace(type=2, imm=immediate)

    instruction = SimpleNamespace(
        address=0x10010,
        mnemonic="lcall",
        size=5,
        insn=SimpleNamespace(operands=(operand(0x1000), operand(0x20)), size=5),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)), size=5)
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x1000)),
        factory=SimpleNamespace(block=lambda _addr, opt_level=0: block),
    )
    function = SimpleNamespace(
        project=project,
        get_call_sites=lambda: (0x10010,),
        get_call_target=lambda _addr: None,
        get_call_return=lambda _addr: 0x10015,
        block_addrs_set={0x10010},
    )

    seeds = collect_neighbor_call_targets(function)

    assert len(seeds) == 1
    assert seeds[0].target_addr == 0x10020
    assert seeds[0].kind is CallTargetKind8616.DIRECT_FAR_CALL

    instruction.mnemonic = "call"
    instruction.insn.operands = (operand(0x10020),)
    assert collect_direct_far_call_targets(function) == []
    assert collect_neighbor_call_targets(function)[0].kind is CallTargetKind8616.DIRECT_NEAR_CALL

    instruction.mnemonic = "lcall"
    instruction.insn.operands = (operand(0), operand(0))
    assert resolve_direct_call_target_from_block(project, 0x10010) == 0
    assert collect_neighbor_call_targets(function) == []
