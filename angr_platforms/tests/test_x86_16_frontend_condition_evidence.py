"""Regression tests for typed branch evidence emitted by the x86-16 frontend."""

from __future__ import annotations

from types import SimpleNamespace

import bitstring
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR, ConditionSource
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY
from angr_platforms.X86_16.lowering.condition_transfer import collect_typed_conditions_from_emulator_8616


class _ConditionEmulator:
    """Minimal owned test double for the lifter's typed-condition state."""

    def __init__(self) -> None:
        self._inertia_current_block_addr = 0x4000
        self._inertia_last_condition_source: ConditionSource | None = None
        self._last_condition: IRCondition | None = None

    def set_last_condition(self, condition: IRCondition) -> None:
        """Store the latest typed condition."""
        self._last_condition = condition


def test_direct_byte_test_mask_is_classified_before_a_jcc() -> None:
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=b"\xf6\x06\x34\x12\x01\x74\x02"),
        Arch86_16(),
        0x4000,
    )

    assert instruction.simple_semantics == ("test_abs_imm8", 0x1234, 1)


def test_inc_ax_before_jne_emits_exact_zero_boundary_condition(monkeypatch) -> None:
    """The simple frontend path must retain INC-produced branch evidence."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex("83c40440750190c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    conditions = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert len(conditions) == 1
    condition = conditions[0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "ne"
    assert condition.lhs == IRValue(
        MemSpace.REG,
        name="ax",
        offset=0,
        size=2,
        expr=("cmp-reg",),
    )
    assert condition.rhs == IRValue(
        MemSpace.CONST,
        const=0xFFFF,
        size=2,
        expr=("cmp-imm",),
    )
    assert condition.producer_insn == 0x4003
    assert condition.src_insn == 0x4004
    assert condition.producer_semantics == ("inc_reg16", "ax", 1)


@pytest.mark.parametrize(
    ("machine_code", "producer_semantics", "expected_boundary"),
    (
        ("4040750190c3", ("inc_reg16", "ax", 2), 0xFFFE),
        ("4848750190c3", ("dec_reg16", "ax", 2), 2),
    ),
    ids=("two-increments", "two-decrements"),
)
def test_repeated_inc_dec_before_jne_uses_original_value_boundary(
    monkeypatch,
    machine_code: str,
    producer_semantics: tuple[str, str, int],
    expected_boundary: int,
) -> None:
    """Repeated unary updates compare the pre-chain value with the exact boundary."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex(machine_code),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    condition = Instruction_ANY._inertia_module_condition_cache[0x4000][0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "ne"
    assert isinstance(condition.rhs, IRValue)
    assert condition.rhs.space is MemSpace.CONST
    assert condition.rhs.const == expected_boundary
    assert condition.producer_insn == 0x4001
    assert condition.src_insn == 0x4002
    assert condition.producer_semantics == producer_semantics


def test_byte_register_copy_preserves_direct_load_condition_evidence(monkeypatch) -> None:
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex("a0341288c380fb00750190c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    conditions = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert len(conditions) == 1
    condition = conditions[0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "ne"
    assert condition.width_bits == 8
    assert condition.producer_insn == 0x4005
    assert condition.producer_semantics == ("cmp_reg_imm8", "bl", 0)
    assert condition.lhs == IRValue(
        MemSpace.DS,
        offset=0x1234,
        size=1,
        expr=("cmp-ds",),
        memory_access_size=1,
        memory_access_insn=0x4000,
    )
    assert condition.rhs == IRValue(
        MemSpace.CONST,
        const=0,
        size=1,
        expr=("cmp-imm",),
    )


@pytest.mark.parametrize(
    "machine_code",
    (
        bytes.fromhex("a0341288c3fec380fb00750190c3"),
        bytes.fromhex("a0341288e380fb00750190c3"),
    ),
    ids=("incremented-copy", "unknown-high-byte-copy"),
)
def test_byte_register_transform_clears_direct_load_condition_evidence(
    monkeypatch,
    machine_code: bytes,
) -> None:
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        machine_code,
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    condition = Instruction_ANY._inertia_module_condition_cache[0x4000][0]
    assert isinstance(condition, ConditionIR)
    assert isinstance(condition.lhs, IRValue)
    assert condition.lhs.space is MemSpace.REG
    assert condition.lhs.name == "bl"
    assert condition.lhs.size == 1
    assert condition.lhs.memory_access_insn is None


def test_direct_byte_test_mask_emits_exact_typed_access_evidence() -> None:
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4000
    instruction.emu = _ConditionEmulator()
    instruction.simple_semantics = ("test_abs_imm8", 0x1234, 1)
    instruction._load_abs8 = lambda _offset: 5
    instruction.constant = lambda value, _type: value
    instruction._update_logical_flags8 = lambda _result: None

    assert instruction._lift_simple_test_8616("test_abs_imm8")
    source = instruction.emu._inertia_last_condition_source
    assert isinstance(source, ConditionSource)
    assert source.width_bits == 8
    assert source.normalized_lhs == IRBinaryValue(
        op="and",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x1234,
            size=1,
            expr=("cmp-ds",),
            memory_access_size=1,
            memory_access_insn=0x4000,
        ),
        rhs=IRValue(MemSpace.CONST, const=1, size=1, expr=("cmp-imm",)),
        size=1,
    )
    assert instruction.emu._last_condition == IRCondition(
        op="masked_zero",
        args=(source.normalized_lhs.lhs, source.normalized_lhs.rhs),
        expr=("test_abs_imm8",),
    )


def test_dec_jcc_does_not_mutate_disabled_affine_state(monkeypatch) -> None:
    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4000
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)
    instruction.simple_semantics = ("dec_reg16", "ax")
    instruction._restore_condition_reg_affine_snapshot_8616 = lambda: None
    instruction._reset_condition_reg_value_state_at_block_entry_8616 = lambda: None
    instruction._lift_simple_cmp_8616 = lambda _kind: False
    instruction._lift_simple_test_8616 = lambda _kind: False
    instruction._lift_simple_jcc_8616 = lambda _kind: False
    instruction._get_reg16 = lambda _name: 4
    instruction._const16 = lambda value: value
    instruction._next_instruction_is_simple_jcc = lambda: True
    instruction._same_preceding_incdec_reg16_count_8616 = lambda _name, mnemonic: 1
    instruction._condition_proven_reg_value_8616 = lambda _name, width_bits: None
    instruction._normalized_reg_imm_condition_operands_8616 = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("disabled affine state was read")
    )
    recorded: list[tuple[object, object]] = []
    instruction._record_cmp_condition_source = lambda lhs, rhs, **_kwargs: recorded.append((lhs, rhs))
    instruction.put = lambda _value, _name: None
    instruction._update_condition_reg_affine_offset_8616 = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("disabled affine state was mutated")
    )
    instruction._clear_condition_index_reg_state_8616 = lambda _name: None
    instruction._clear_condition_reg_value_state_8616 = lambda _name: None

    instruction._lift_simple()

    assert recorded == [(4, 1)]


def test_dec_jcc_semantics_keep_typed_register_operands_without_affine_state() -> None:
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x4001
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)

    operands = instruction._condition_operands_from_cmp_semantics_8616(
        ("dec_reg16", "ax", 1)
    )

    assert operands == (
        IRValue(MemSpace.REG, name="ax", offset=0, size=2, expr=("cmp-reg",)),
        IRValue(MemSpace.CONST, const=1, size=2, expr=("cmp-imm",)),
    )


def test_conditionless_blocks_do_not_force_repeated_condition_relifts() -> None:
    original_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr
    original_affine = Instruction_ANY._inertia_condition_reg_affine_state_8616
    original_snapshots = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616
    original_index = Instruction_ANY._inertia_condition_index_reg_state_8616
    original_values = Instruction_ANY._inertia_condition_reg_value_state_8616
    fresh = ConditionIR(
        "eq",
        "ax",
        1,
        source=("cmp", "je"),
        src_insn=0x4011,
        block_addr=0x4010,
        taken_target=0x4020,
        fallthrough_target=0x4013,
    )

    def lift_block(block_addr: int, opt_level: int = 0) -> None:
        raise AssertionError(f"unexpected relift of {block_addr:#x} at opt_level={opt_level}")

    terminal = SimpleNamespace(
        address=0x4011,
        size=2,
        mnemonic="je",
        operands=(SimpleNamespace(imm=0x4020),),
    )
    conditional_block = SimpleNamespace(
        addr=0x4010,
        capstone=SimpleNamespace(insns=(SimpleNamespace(insn=terminal),)),
    )
    conditionless_block = SimpleNamespace(
        addr=0x4014,
        capstone=SimpleNamespace(
            insns=(SimpleNamespace(insn=SimpleNamespace(address=0x4014, size=1, mnemonic="ret")),)
        ),
    )
    function = SimpleNamespace(
        block_addrs_set={0x4010, 0x4014},
        blocks=(conditional_block, conditionless_block),
    )
    Instruction_ANY._inertia_module_condition_cache = {0x4010: [fresh]}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
    Instruction_ANY._inertia_condition_reg_affine_state_8616 = {}
    Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = {}
    Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
    Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function)
        ),
        factory=SimpleNamespace(block=lift_block),
    )
    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x4010)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending
        Instruction_ANY._inertia_condition_reg_affine_state_8616 = original_affine
        Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = original_snapshots
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index
        Instruction_ANY._inertia_condition_reg_value_state_8616 = original_values

    assert conditions == [fresh]
