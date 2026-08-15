"""Tests for typed alias propagation across decrement dispatch chains."""

from angr_platforms.X86_16.alias.condition_register_carriers import (
    normalize_condition_register_carriers_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace


def _root_condition(lhs: IRValue) -> ConditionIR:
    return ConditionIR(
        op="zero",
        lhs=lhs,
        source=("test", "je"),
        src_insn=0x1012,
        block_addr=0x1010,
        producer_insn=0x1010,
        taken_target=0x1100,
        fallthrough_target=0x1020,
    )


def _dec_condition(
    block_addr: int,
    *,
    fallthrough_target: int,
    register_name: str = "ax",
) -> ConditionIR:
    return ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.REG, name=register_name, size=2),
        rhs=IRValue(MemSpace.CONST, const=1, size=2),
        source=("cmp", "je"),
        src_insn=block_addr + 1,
        block_addr=block_addr,
        producer_insn=block_addr,
        taken_target=block_addr + 0x100,
        fallthrough_target=fallthrough_target,
        producer_semantics=("dec_reg16", register_name, 1),
    )


def test_decrement_dispatch_binds_cases_to_proven_stack_carrier() -> None:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    first = _dec_condition(0x1020, fallthrough_target=0x1030)
    second = _dec_condition(0x1030, fallthrough_target=0x1040)

    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), first, second)
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021].lhs == argument
    assert by_source[0x1021].rhs == IRValue(MemSpace.CONST, const=1, size=2)
    assert by_source[0x1031].lhs == argument
    assert by_source[0x1031].rhs == IRValue(MemSpace.CONST, const=2, size=2)
    assert result.stats.raw_fact_count == 4
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 0


def test_decrement_dispatch_refuses_ambiguous_storage_identity() -> None:
    stack_argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    global_value = IRValue(MemSpace.DS, offset=0x2200, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    branch = _dec_condition(0x1020, fallthrough_target=0x1030)

    result = normalize_condition_register_carriers_8616(
        (
            _root_condition(stack_argument),
            _root_condition(global_value),
            _root_condition(register),
            branch,
        )
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021] == branch
    assert result.stats.normalized_fact_count == 0
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_decrement_dispatch_refuses_a_different_register() -> None:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    branch = _dec_condition(
        0x1020,
        fallthrough_target=0x1030,
        register_name="bx",
    )

    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), branch)
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021] == branch
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
