from __future__ import annotations

from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring.wide_stack_condition_chains import (
    recover_wide_stack_condition_chain_8616,
)
from angr_platforms.X86_16.structuring.wide_stack_single_branches import (
    recover_wide_stack_single_body_condition_8616,
)


def _word(offset: int) -> IRValue:
    return IRValue(space=MemSpace.SS, name="bp", offset=offset, size=2)


def _condition(
    op: str,
    lhs: int,
    rhs: int,
    block: int,
    taken: int,
    fallthrough: int,
) -> ConditionIR:
    return ConditionIR(
        op=op,
        lhs=_word(lhs),
        rhs=_word(rhs),
        width_bits=16,
        source=("cmp", "jcc"),
        src_insn=block + 2,
        block_addr=block,
        taken_target=taken,
        fallthrough_target=fallthrough,
    )


def _adjacent(high: IRValue, low: IRValue) -> bool:
    return high.offset == low.offset + 2


def test_wide_stack_condition_chain_recovers_signed_less_equal() -> None:
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("sle", 10, 6, 0x1000, 0x1010, false_target)
    equal_or_less = _condition("sge", 10, 6, 0x1010, 0x1020, true_target)
    low = _condition("ule", 8, 4, 0x1020, true_target, false_target)

    result = recover_wide_stack_condition_chain_8616(
        root,
        {0x1000: root, 0x1010: equal_or_less, 0x1020: low},
        {},
        true_target,
        false_target,
        _adjacent,
    )

    assert result.condition is not None
    assert result.condition.op == "sle"
    assert result.condition.width_bits == 32
    assert result.condition.lhs == IRValue(space=MemSpace.SS, name="bp", offset=8, size=4)
    assert result.condition.rhs == IRValue(space=MemSpace.SS, name="bp", offset=4, size=4)
    assert result.stats.materialized_count == 1


def test_wide_stack_condition_chain_refuses_missing_low_word_decision() -> None:
    root = _condition("sle", 10, 6, 0x1000, 0x1030, 0x1040)

    result = recover_wide_stack_condition_chain_8616(
        root,
        {0x1000: root},
        {},
        0x1030,
        0x1040,
        _adjacent,
    )

    assert result.condition is None
    assert result.stats.materialized_count == 0


def test_wide_stack_single_body_recovers_signed_less_than() -> None:
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("slt", 10, 6, 0x1000, true_target, 0x1010)
    high_equal = _condition("eq", 10, 6, 0x1010, 0x1020, false_target)
    low = _condition("ult", 8, 4, 0x1020, true_target, false_target)

    result = recover_wide_stack_single_body_condition_8616(
        root,
        {0x1000: root, 0x1010: high_equal, 0x1020: low},
        {},
        _adjacent,
        lambda target: True if target == true_target else False if target == false_target else None,
    )

    assert result.condition is not None
    assert result.condition.op == "slt"
    assert result.condition.width_bits == 32


def test_wide_stack_single_body_recovers_low_then_high_equality() -> None:
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("eq", 8, 4, 0x1000, 0x1010, false_target)
    high = _condition("eq", 10, 6, 0x1010, true_target, false_target)

    result = recover_wide_stack_single_body_condition_8616(
        root,
        {0x1000: root, 0x1010: high},
        {},
        _adjacent,
        lambda target: True if target == true_target else False if target == false_target else None,
    )

    assert result.condition is not None
    assert result.condition.op == "eq"
    assert result.condition.lhs.size == 4
    assert result.condition.rhs.size == 4


def test_wide_stack_single_body_refuses_unclassified_exit() -> None:
    root = _condition("slt", 10, 6, 0x1000, 0x1030, 0x1010)
    high_equal = _condition("eq", 10, 6, 0x1010, 0x1020, 0x1040)
    low = _condition("ult", 8, 4, 0x1020, 0x1030, 0x1040)

    result = recover_wide_stack_single_body_condition_8616(
        root,
        {0x1000: root, 0x1010: high_equal, 0x1020: low},
        {},
        _adjacent,
        lambda _target: None,
    )

    assert result.condition is None
    assert result.stats.failure_count == 1
