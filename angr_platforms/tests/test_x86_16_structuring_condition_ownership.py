from __future__ import annotations

from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring.condition_ownership import (
    structured_node_owns_condition_fact_8616,
)


def _condition(block_addr: int = 0x1009) -> ConditionIR:
    return ConditionIR(
        op="sle",
        lhs="left",
        rhs="right",
        src_insn=0x1014,
        block_addr=block_addr,
        taken_target=0x1019,
        fallthrough_target=0x1016,
    )


def test_structuring_condition_owner_accepts_linear_preheader() -> None:
    assert structured_node_owns_condition_fact_8616(
        0x1000,
        _condition(),
        {0x1000: (0x1009,), 0x1009: (0x1016, 0x1019)},
        frozenset({0x1009}),
    )


def test_structuring_condition_owner_refuses_branching_preheader() -> None:
    assert not structured_node_owns_condition_fact_8616(
        0x1000,
        _condition(),
        {0x1000: (0x1009, 0x1010)},
        frozenset({0x1009}),
    )


def test_structuring_condition_owner_refuses_crossing_other_condition() -> None:
    assert not structured_node_owns_condition_fact_8616(
        0x1000,
        _condition(block_addr=0x1019),
        {0x1000: (0x1009,), 0x1009: (0x1019,)},
        frozenset({0x1009, 0x1019}),
    )
