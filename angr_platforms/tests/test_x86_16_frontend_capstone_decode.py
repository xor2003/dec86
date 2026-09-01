from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.frontend_capstone_decode import (
    DirectCapstoneInstruction8616,
    decode_exact_capstone_block_8616,
)


class _Instruction:
    address = 0x1000
    size = 2
    mnemonic = "cmp"
    op_str = "ax, bx"
    groups: tuple[int, ...] = ()
    operands: tuple[str, ...] = ("ax", "bx")

    def reg_name(self, register_id: int) -> str:
        return f"reg_{register_id}"


class _Decoder:
    def disasm(self, _code: bytes, _address: int) -> tuple[_Instruction, ...]:
        return (_Instruction(),)


def test_direct_instruction_preserves_capstone_detail_contract() -> None:
    project = SimpleNamespace(arch=SimpleNamespace(capstone=_Decoder()))

    artifact = decode_exact_capstone_block_8616(project, 0x1000, b"\x39\xd8")

    assert artifact.complete is True
    assert artifact.block is not None
    instruction = artifact.block.instructions[0]
    assert isinstance(instruction, DirectCapstoneInstruction8616)
    assert instruction.operands == ("ax", "bx")
    assert instruction.reg_name(7) == "reg_7"
