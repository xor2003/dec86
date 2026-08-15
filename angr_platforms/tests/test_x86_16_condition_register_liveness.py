"""Tests for typed Alias liveness across condition-only CFG edges."""

from angr_platforms.X86_16.alias.condition_register_liveness import (
    ConditionRegisterTopology8616,
    normalize_condition_register_liveness_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace


def _condition(
    block_addr: int,
    *,
    producer_insn: int,
    src_insn: int,
    taken_target: int,
    fallthrough_target: int,
    lhs: IRValue,
    rhs: IRValue,
    semantics: tuple[object, ...],
) -> ConditionIR:
    return ConditionIR(
        op="sgt",
        lhs=lhs,
        rhs=rhs,
        source=("cmp", "jg"),
        src_insn=src_insn,
        block_addr=block_addr,
        producer_insn=producer_insn,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
        producer_semantics=semantics,
    )


def test_register_identity_survives_complete_condition_only_chain() -> None:
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    high_upper = IRValue(MemSpace.SS, name="bp", offset=22, size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    first = _condition(
        0x1000,
        producer_insn=0x1009,
        src_insn=0x100C,
        taken_target=0x1045,
        fallthrough_target=0x100E,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    shared_flags = _condition(
        0x100E,
        producer_insn=0x1009,
        src_insn=0x100E,
        taken_target=0x1015,
        fallthrough_target=0x1010,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    upper = _condition(
        0x1015,
        producer_insn=0x1015,
        src_insn=0x1018,
        taken_target=0x1045,
        fallthrough_target=0x101A,
        lhs=dx,
        rhs=high_upper,
        semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
    )
    topology = ConditionRegisterTopology8616(
        {
            0x1000: frozenset(),
            0x100E: frozenset({0x1000}),
            0x1015: frozenset({0x100E}),
        },
        frozenset({0x1000, 0x100E, 0x1015}),
    )

    result = normalize_condition_register_liveness_8616(
        (first, shared_flags, upper), topology
    )

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1015].lhs == high_x
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_register_identity_refuses_incomplete_predecessor_join() -> None:
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    high_upper = IRValue(MemSpace.SS, name="bp", offset=22, size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    first = _condition(
        0x1000,
        producer_insn=0x1009,
        src_insn=0x100C,
        taken_target=0x1015,
        fallthrough_target=0x100E,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    upper = _condition(
        0x1015,
        producer_insn=0x1015,
        src_insn=0x1018,
        taken_target=0x1045,
        fallthrough_target=0x101A,
        lhs=dx,
        rhs=high_upper,
        semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
    )
    topology = ConditionRegisterTopology8616(
        {
            0x1000: frozenset(),
            0x1015: frozenset({0x1000, 0x1008}),
        },
        frozenset({0x1000, 0x1015}),
    )

    result = normalize_condition_register_liveness_8616((first, upper), topology)

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1015].lhs == dx
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0


def test_register_identity_refuses_an_intervening_instruction_gap() -> None:
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    high_upper = IRValue(MemSpace.SS, name="bp", offset=22, size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    first = _condition(
        0x1000,
        producer_insn=0x1009,
        src_insn=0x100C,
        taken_target=0x1015,
        fallthrough_target=0x100E,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    upper = _condition(
        0x1015,
        producer_insn=0x1017,
        src_insn=0x101A,
        taken_target=0x1045,
        fallthrough_target=0x101C,
        lhs=dx,
        rhs=high_upper,
        semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
    )
    topology = ConditionRegisterTopology8616(
        {0x1000: frozenset(), 0x1015: frozenset({0x1000})},
        frozenset({0x1000}),
    )

    result = normalize_condition_register_liveness_8616((first, upper), topology)

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1015].lhs == dx
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
