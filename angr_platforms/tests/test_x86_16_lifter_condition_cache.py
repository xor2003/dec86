"""Regress typed condition caching at the pyvex ownership boundary."""

from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY


class _OwnedOperand:
    """Model a pyvex value whose equality is invalid across IRSB owners."""

    def __eq__(self, _other: object) -> bool:
        """Refuse direct equality, as pyvex does for cross-IRSB values."""
        raise AssertionError("cross-owner operand equality")

    def __str__(self) -> str:
        """Return the stable rendering used by the typed condition key."""
        return "owned-operand"


def test_lifter_condition_cache_deduplicates_without_operand_equality() -> None:
    """Use the IR key instead of comparing pyvex-owned operand objects."""
    original_cache = Instruction_ANY._inertia_module_condition_cache
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4014
    instruction.emu = SimpleNamespace(
        _inertia_current_block_addr=0x4010,
        _inertia_typed_conditions=[],
    )
    conditions = (
        ConditionIR("ne", _OwnedOperand(), 0, src_insn=0x4014, block_addr=0x4010),
        ConditionIR("ne", _OwnedOperand(), 0, src_insn=0x4014, block_addr=0x4010),
    )
    Instruction_ANY._inertia_module_condition_cache = {}

    try:
        for condition in conditions:
            instruction._record_typed_condition_8616(condition)
        cached = Instruction_ANY._inertia_module_condition_cache[0x4010]
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache

    assert len(cached) == 1
    assert cached[0] is conditions[0]
    assert instruction.emu._inertia_typed_conditions == list(conditions)
