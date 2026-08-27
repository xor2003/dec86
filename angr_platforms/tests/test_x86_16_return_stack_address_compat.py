"""Tests for BP provenance on current angr AIL stack-address nodes."""

from types import SimpleNamespace

from angr.ailment.expression import StackBaseOffset
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.decompiler_return_compat import (
    _bp_offset_from_linear_stack_addr_8616,
    _terminal_ax_stack_load_from_instructions_8616,
)


def test_stack_base_offset_retains_typed_bp_provenance() -> None:
    """A current AIL stack node is BP-relative only when its variable proves it."""
    variable = SimStackVariable(6, 2, base="bp", region=0x1000)
    expression = StackBaseOffset(1, 16, 6, variable=variable)

    assert _bp_offset_from_linear_stack_addr_8616(SimpleNamespace(), expression) == 6


def test_stack_base_offset_without_bp_variable_is_not_reclassified() -> None:
    """A generic stack-base node must not be guessed to be BP-relative."""
    expression = StackBaseOffset(1, 16, 6)

    assert _bp_offset_from_linear_stack_addr_8616(SimpleNamespace(), expression) is None


def _instruction(mnemonic: str, operands: tuple[object, ...] = ()) -> SimpleNamespace:
    names = {1: "ax", 2: "bp"}
    return SimpleNamespace(mnemonic=mnemonic, operands=operands, reg_name=lambda reg: names.get(reg, ""))


def test_terminal_ax_stack_load_uses_typed_instruction_effect() -> None:
    destination = SimpleNamespace(type=1, reg=1)
    source = SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=2, index=0, disp=-2))
    block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_instruction("mov", (destination, source)), _instruction("ret")))
    )

    assert _terminal_ax_stack_load_from_instructions_8616(SimpleNamespace(blocks=(block,))) == (-2, 2)


def test_terminal_ax_stack_load_refuses_later_ax_overwrite() -> None:
    destination = SimpleNamespace(type=1, reg=1)
    stack_source = SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=2, index=0, disp=-2))
    immediate = SimpleNamespace(type=2, imm=7)
    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _instruction("mov", (destination, stack_source)),
                _instruction("mov", (destination, immediate)),
                _instruction("ret"),
            )
        )
    )

    assert _terminal_ax_stack_load_from_instructions_8616(SimpleNamespace(blocks=(block,))) is None
