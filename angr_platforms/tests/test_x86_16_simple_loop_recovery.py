from __future__ import annotations

from angr_platforms.X86_16.structuring.simple_loop_recovery import (
    InsnSummary8616,
    recover_counted_stack_loop_from_summaries_8616,
)


def test_recover_counted_stack_loop_from_bp_operand_evidence():
    summaries = [
        InsnSummary8616("mov", "bp_mem", -2, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("mov", "bp_mem", -4, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("inc", "bp_mem", -4, op0_size=2),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", 4, op0_size=2, op1_size=2),
        InsnSummary8616("cmp", "bp_mem", -4, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("test", "bp_mem", -4, "imm", 1, op0_size=1, op1_size=1),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", -4, op0_size=2, op1_size=2),
        InsnSummary8616("add", "bp_mem", -2, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("dec", "bp_mem", -2, op0_size=2),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", -2, op0_size=2, op1_size=2),
    ]

    recovered = recover_counted_stack_loop_from_summaries_8616(summaries)

    assert recovered is not None
    assert recovered.induction_disp == -4
    assert recovered.accumulator_disp == -2
    assert recovered.limit_disp == 4
    assert recovered.parity_mask == 1


def test_recover_counted_stack_loop_refuses_without_accumulator_return_load():
    summaries = [
        InsnSummary8616("mov", "bp_mem", -2, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("mov", "bp_mem", -4, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("inc", "bp_mem", -4, op0_size=2),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", 4, op0_size=2, op1_size=2),
        InsnSummary8616("cmp", "bp_mem", -4, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("test", "bp_mem", -4, "imm", 1, op0_size=1, op1_size=1),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", -4, op0_size=2, op1_size=2),
        InsnSummary8616("add", "bp_mem", -2, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("dec", "bp_mem", -2, op0_size=2),
    ]

    assert recover_counted_stack_loop_from_summaries_8616(summaries) is None
