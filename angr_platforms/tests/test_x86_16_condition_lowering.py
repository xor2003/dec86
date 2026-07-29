from __future__ import annotations

from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.structuring.condition_lowering import condition_origin_tags_8616


def test_condition_origin_tags_preserve_branch_provenance():
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x100F,
        block_addr=0x1009,
        producer_insn=0x100B,
    )

    assert condition_origin_tags_8616(condition) == {
        "typed_condition": True,
        "ins_addr": 0x100F,
        "vex_block_addr": 0x1009,
        "condition_producer_insn": 0x100B,
    }


def test_condition_origin_tags_keep_ircondition_fallback_minimal():
    condition = IRCondition(
        op="ne",
        args=(
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
        ),
    )

    assert condition_origin_tags_8616(condition) == {"typed_condition": True}
