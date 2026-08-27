from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.callsite_summary import (
    CallsiteReturnUseKind8616,
    _return_use_after_call,
)
from angr_platforms.X86_16.semantics.register_value_preservation import (
    decoded_instruction_self_clears_register_8616,
)
from capstone.x86_const import X86_OP_IMM, X86_OP_REG


class _Operand:
    def __init__(self, operand_type: int, *, reg: int = 0, imm: int = 0) -> None:
        self.type = operand_type
        self.reg = reg
        self.imm = imm


class _Instruction:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        operands: tuple[_Operand, ...] = (),
        *,
        reg_names: dict[int, str] | None = None,
        size: int = 1,
    ) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.size = size
        self.insn = SimpleNamespace(
            operands=operands,
            reg_name=lambda reg: (reg_names or {}).get(reg, ""),
        )


@pytest.mark.parametrize("mnemonic", ("sub", "xor"))
def test_exact_same_register_zero_idiom_self_clears_ax(mnemonic: str) -> None:
    instruction = _Instruction(
        0x1000,
        mnemonic,
        (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=2)),
        reg_names={2: "ax"},
    )

    assert decoded_instruction_self_clears_register_8616(instruction, "ax") is True


def test_different_register_subtraction_does_not_self_clear_ax() -> None:
    instruction = _Instruction(
        0x1000,
        "sub",
        (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=3)),
        reg_names={2: "ax", 3: "dx"},
    )

    assert decoded_instruction_self_clears_register_8616(instruction, "ax") is False


def test_post_call_sub_ax_ax_is_clobber_not_return_value_use() -> None:
    reg_names = {1: "sp", 2: "ax"}
    instructions = (
        _Instruction(0x1000, "call", size=5),
        _Instruction(
            0x1005,
            "add",
            (_Operand(X86_OP_REG, reg=1), _Operand(X86_OP_IMM, imm=0x10)),
            reg_names=reg_names,
            size=3,
        ),
        _Instruction(
            0x1008,
            "sub",
            (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=2)),
            reg_names=reg_names,
            size=2,
        ),
        _Instruction(
            0x100A,
            "push",
            (_Operand(X86_OP_REG, reg=2),),
            reg_names=reg_names,
        ),
    )

    return_register, return_used, return_use_kind = _return_use_after_call(
        SimpleNamespace(),
        instructions,
        0,
        0x1000,
    )

    assert return_register == "ax"
    assert return_used is False
    assert return_use_kind is CallsiteReturnUseKind8616.CLOBBERED
