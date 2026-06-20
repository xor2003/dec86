from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir.condition_ir import ConditionIR, ConditionSource
from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.lowering.condition_transfer import (
    collect_typed_conditions_from_emulator_8616,
    transfer_typed_conditions_to_codegen_8616,
)


class _Emu:
    def __init__(self, condition=None):
        self._last_condition = condition

    def set_last_condition(self, condition):
        self._last_condition = condition

    def get_last_condition(self):
        return self._last_condition

    def clear_last_condition(self):
        self._last_condition = None


def test_collect_typed_conditions_relifts_blocks_when_cache_is_empty(monkeypatch):
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    condition = ConditionIR("sgt", "ax", "bx")
    lifted_blocks: list[int] = []

    def _lift_block(block_addr: int, opt_level: int = 0):
        lifted_blocks.append(block_addr)
        Instruction_ANY._inertia_module_condition_cache[block_addr] = [condition]
        return None

    Instruction_ANY._inertia_module_condition_cache = {}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(block_addrs_set={addr, addr + 4})
            )
        ),
        factory=SimpleNamespace(block=_lift_block),
    )

    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x4010)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache

    assert lifted_blocks == [0x4010, 0x4014]
    assert conditions == [condition]


def test_direct_jcc_preserves_condition_for_back_to_back_jcc(monkeypatch):
    from angr_platforms.X86_16 import lift_86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    condition = IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=69, size=2),
        ),
    )
    prev_emu = _Emu(condition)
    current_emu = _Emu()
    instr = SimpleNamespace(
        _past_instructions=[SimpleNamespace(emu=prev_emu, addr=0x423)],
        _future_instructions=[SimpleNamespace(simple_semantics=("jle",))],
        emu=current_emu,
        _next_instruction_is_simple_jcc=lambda: True,
    )

    monkeypatch.setattr(lift_86_16, "_direct_jcc_condition_from_last_condition_8616", lambda *_args: object())

    assert Instruction_ANY._direct_jcc_condition(instr, "jne") is not None
    assert prev_emu.get_last_condition() is condition
    assert current_emu.get_last_condition() is condition


def test_emit_simple_jcc_propagates_condition_source_for_following_jcc():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, addr=0x423, block_addr=0x423)
    prev_emu = _Emu()
    prev_emu._inertia_last_condition_source = source
    current_emu = _Emu()
    recorded: list[ConditionIR] = []
    instr = SimpleNamespace(
        _past_instructions=[SimpleNamespace(emu=prev_emu, addr=0x423)],
        simple_semantics=("jne",),
        addr=0x426,
        cs=SimpleNamespace(size=2),
        emu=current_emu,
        _condition_operands_from_cmp_semantics_8616=lambda _semantics: None,
        _record_typed_condition_8616=recorded.append,
        jump=lambda *_args: None,
    )

    try:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
        Instruction_ANY._emit_simple_jcc(instr, object(), 0x430)

        assert current_emu._inertia_last_condition_source is source
        pending = Instruction_ANY._inertia_pending_condition_sources_by_addr[0x428]
        assert pending is not source
        assert pending.lhs is lhs
        assert pending.rhs is rhs
        assert pending.fallthrough_from_jcc == "jne"
        assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in recorded] == [
            (0x426, 0x423, 0x423, "ne")
        ]
    finally:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending


def test_emit_simple_jcc_consumes_pending_fallthrough_condition_source():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, addr=0x423, block_addr=0x423)
    current_emu = _Emu()
    recorded: list[ConditionIR] = []
    instr = SimpleNamespace(
        _past_instructions=[],
        simple_semantics=("jle",),
        addr=0x428,
        cs=SimpleNamespace(size=2),
        emu=current_emu,
        _condition_operands_from_cmp_semantics_8616=lambda _semantics: None,
        _record_typed_condition_8616=recorded.append,
        jump=lambda *_args: None,
    )

    try:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x428: source}
        Instruction_ANY._emit_simple_jcc(instr, object(), 0x452)

        assert current_emu._inertia_last_condition_source is source
        assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in recorded] == [
            (0x428, 0x423, 0x423, "sle")
        ]
    finally:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending


def test_collect_typed_conditions_materializes_pending_fallthrough_jcc():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, width_bits=16, addr=0x1153, block_addr=0x1153)
    first_condition = ConditionIR(
        "ne",
        lhs,
        rhs,
        src_insn=0x1153,
        block_addr=0x1153,
        producer_insn=0x114E,
        source=("cmp", "jne"),
    )
    decoded_addrs: list[int] = []

    def _lift_block(block_addr: int, **_kwargs):
        decoded_addrs.append(block_addr)
        return SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="jle"),)))

    Instruction_ANY._inertia_module_condition_cache = {0x1153: [first_condition]}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x1158: source}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: SimpleNamespace(block_addrs_set={0x1153, 0x1158}))
        ),
        factory=SimpleNamespace(block=_lift_block),
    )

    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x1100)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert decoded_addrs == [0x1158]
    assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in conditions] == [
        (0x1153, 0x1153, 0x114E, "ne"),
        (0x1158, 0x1158, 0x1153, "sle"),
    ]


def test_transfer_records_pending_fallthrough_jmp_as_edge_evidence_not_guard_condition():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(
        kind="cmp",
        lhs=lhs,
        rhs=rhs,
        fallthrough_from_jcc="jne",
        width_bits=16,
        addr=0x1153,
        block_addr=0x1153,
    )
    first_condition = ConditionIR(
        "ne",
        lhs,
        rhs,
        src_insn=0x1153,
        block_addr=0x1153,
        producer_insn=0x114E,
        source=("cmp", "jne"),
    )

    def _lift_block(_block_addr: int, **_kwargs):
        operand = SimpleNamespace(type=2, imm=0x109C)
        insn = SimpleNamespace(mnemonic="jmp", operands=(operand,))
        return SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))

    Instruction_ANY._inertia_module_condition_cache = {0x1153: [first_condition]}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x1158: source}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: SimpleNamespace(block_addrs_set={0x1153, 0x1158}))
        ),
        factory=SimpleNamespace(block=_lift_block),
    )
    codegen = SimpleNamespace()

    try:
        transferred = transfer_typed_conditions_to_codegen_8616(project, 0x1100, codegen)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert transferred == 1
    assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in codegen._inertia_typed_conditions] == [
        (0x1153, 0x1153, 0x114E, "ne")
    ]
    edge_evidence = codegen._inertia_condition_edge_evidence
    assert len(edge_evidence) == 1
    edge = edge_evidence[0]
    assert (edge.edge_block_addr, edge.edge_kind, edge.source_jcc, edge.producer_insn) == (
        0x1158,
        "fallthrough_jmp",
        "jne",
        0x1153,
    )
    assert (edge.condition.src_insn, edge.condition.block_addr, edge.condition.op) == (0x1158, 0x1158, "eq")
