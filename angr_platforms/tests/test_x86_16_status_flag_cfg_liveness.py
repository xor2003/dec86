from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir.status_flag_binary_cfg import (
    summarize_binary_status_flag_entry_reads_8616,
)
from angr_platforms.X86_16.semantics.status_flag_cfg_liveness import (
    StatusFlagCFGBlock8616,
    StatusFlagCFGInstruction8616,
    analyze_status_flag_cfg_liveness_8616,
    summarize_status_flag_cfg_effect_8616,
)
from angr_platforms.X86_16.semantics.status_flag_contracts import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    STATUS_FLAGS_8616,
    StatusFlag8616,
    StatusFlagEffect8616,
)


def _instruction(
    address: int,
    *,
    reads: StatusFlag8616 = StatusFlag8616.NONE,
    overwrites: StatusFlag8616 = StatusFlag8616.NONE,
) -> StatusFlagCFGInstruction8616:
    return StatusFlagCFGInstruction8616(
        address=address,
        effect=StatusFlagEffect8616(reads=reads, overwrites=overwrites),
    )


def _decision_by_address(
    artifact: object,
) -> dict[int, object]:
    return {decision.instruction_address: decision for decision in artifact.decisions}


def test_cfg_liveness_suppresses_definition_overwritten_in_successor() -> None:
    blocks = (
        StatusFlagCFGBlock8616(
            address=0x1000,
            instructions=(_instruction(0x1000, overwrites=STATUS_FLAGS_8616),),
            successor_addresses=(0x1010,),
        ),
        StatusFlagCFGBlock8616(
            address=0x1010,
            instructions=(_instruction(0x1010, overwrites=STATUS_FLAGS_8616),),
        ),
    )

    artifact = analyze_status_flag_cfg_liveness_8616(blocks, entry_address=0x1000)

    decisions = _decision_by_address(artifact)
    assert decisions[0x1000].suppresses_write
    assert not decisions[0x1010].suppresses_write
    assert artifact.stats.complete


def test_cfg_liveness_keeps_bit_read_on_one_branch() -> None:
    blocks = (
        StatusFlagCFGBlock8616(
            address=0x1000,
            instructions=(_instruction(0x1000, overwrites=STATUS_FLAGS_8616),),
            successor_addresses=(0x1010, 0x1020),
        ),
        StatusFlagCFGBlock8616(
            address=0x1010,
            instructions=(_instruction(0x1010, reads=StatusFlag8616.CARRY),),
        ),
        StatusFlagCFGBlock8616(address=0x1020, instructions=()),
    )

    artifact = analyze_status_flag_cfg_liveness_8616(
        blocks,
        entry_address=0x1000,
        exit_live=StatusFlag8616.NONE,
    )

    producer = _decision_by_address(artifact)[0x1000]
    assert not producer.suppresses_write
    assert producer.live_after == StatusFlag8616.CARRY
    assert producer.dead_writes == STATUS_FLAGS_8616 & ~StatusFlag8616.CARRY


def test_cfg_liveness_converges_through_loop_backedge() -> None:
    blocks = (
        StatusFlagCFGBlock8616(
            address=0x1000,
            instructions=(_instruction(0x1000, overwrites=STATUS_FLAGS_8616),),
            successor_addresses=(0x1010,),
        ),
        StatusFlagCFGBlock8616(
            address=0x1010,
            instructions=(_instruction(0x1010, overwrites=STATUS_FLAGS_8616),),
            successor_addresses=(0x1010, 0x1020),
        ),
        StatusFlagCFGBlock8616(address=0x1020, instructions=()),
    )

    artifact = analyze_status_flag_cfg_liveness_8616(
        blocks,
        entry_address=0x1000,
        exit_live=StatusFlag8616.NONE,
    )

    decisions = _decision_by_address(artifact)
    assert decisions[0x1000].suppresses_write
    assert decisions[0x1010].suppresses_write


def test_cfg_liveness_unknown_instruction_and_missing_edge_refuse_suppression() -> None:
    blocks = (
        StatusFlagCFGBlock8616(
            address=0x1000,
            instructions=(
                _instruction(0x1000, overwrites=STATUS_FLAGS_8616),
                StatusFlagCFGInstruction8616(address=0x1001, effect=None),
            ),
            successor_addresses=(0x2000,),
        ),
    )

    artifact = analyze_status_flag_cfg_liveness_8616(
        blocks,
        entry_address=0x1000,
        exit_live=StatusFlag8616.NONE,
    )

    assert not _decision_by_address(artifact)[0x1000].suppresses_write
    assert artifact.stats.closed
    assert artifact.stats.failure_count == 2


def test_callee_summary_composes_reads_and_definite_overwrites() -> None:
    no_read_callee = (
        StatusFlagCFGBlock8616(
            address=0x2000,
            instructions=(
                _instruction(0x2000, overwrites=INCDEC_STATUS_FLAG_WRITES_8616),
                _instruction(0x2001, overwrites=STATUS_FLAGS_8616),
            ),
        ),
    )
    carry_read_callee = (
        StatusFlagCFGBlock8616(
            address=0x3000,
            instructions=(
                _instruction(
                    0x3000,
                    reads=StatusFlag8616.CARRY,
                    overwrites=STATUS_FLAGS_8616,
                ),
            ),
        ),
    )

    no_read = summarize_status_flag_cfg_effect_8616(no_read_callee, entry_address=0x2000)
    carry_read = summarize_status_flag_cfg_effect_8616(carry_read_callee, entry_address=0x3000)

    assert no_read.reads == StatusFlag8616.NONE
    assert no_read.overwrites == STATUS_FLAGS_8616
    assert carry_read.reads == StatusFlag8616.CARRY
    assert carry_read.overwrites == STATUS_FLAGS_8616


def test_binary_callee_summary_stops_after_incoming_flags_are_overwritten() -> None:
    seen: list[str] = []
    instructions = (
        SimpleNamespace(mnemonic="cmp"),
        SimpleNamespace(mnemonic="unsupported"),
    )
    block = SimpleNamespace(
        addr=0x2000,
        size=2,
        capstone=SimpleNamespace(insns=instructions),
    )
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda address, opt_level=0: block),
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x2FFF)),
    )

    def instruction_effect(instruction: object) -> StatusFlagEffect8616 | None:
        mnemonic = instruction.mnemonic
        seen.append(mnemonic)
        return (
            StatusFlagEffect8616(overwrites=STATUS_FLAGS_8616)
            if mnemonic == "cmp"
            else None
        )

    summary = summarize_binary_status_flag_entry_reads_8616(
        project,
        entry_address=0x2000,
        instruction_effect=instruction_effect,
    )

    assert summary.reads == StatusFlag8616.NONE
    assert summary.complete
    assert summary.materialized_count == summary.classified_fact_count == 1
    assert seen == ["cmp"]


def test_binary_callee_summary_refuses_unknown_before_overwrite() -> None:
    instruction = SimpleNamespace(mnemonic="unsupported")
    block = SimpleNamespace(
        addr=0x2000,
        size=1,
        capstone=SimpleNamespace(insns=(instruction,)),
    )
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda address, opt_level=0: block),
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x2FFF)),
    )

    summary = summarize_binary_status_flag_entry_reads_8616(
        project,
        entry_address=0x2000,
        instruction_effect=lambda _instruction: None,
    )

    assert summary.reads == STATUS_FLAGS_8616
    assert not summary.complete
    assert summary.failure_count == 1
    assert summary.materialized_count == 0
