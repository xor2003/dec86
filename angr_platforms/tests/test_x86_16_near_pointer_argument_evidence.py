"""Binary-only distinction between pointer dereferences and scalar indexes."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.lowering.near_pointer_argument import (
    collect_near_pointer_argument_facts_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import _capstone_memory_view_8616
from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_MEM, X86_REG_DS, X86_REG_SS


def _facts(hex_bytes):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instructions = tuple(
        SimpleNamespace(insn=instruction)
        for instruction in decoder.disasm(bytes.fromhex(hex_bytes), 0x2000)
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(addr=0x2000, capstone=SimpleNamespace(insns=instructions)),),
    )
    return collect_near_pointer_argument_facts_8616(function)


def test_direct_argument_dereference_proves_near_pointer():
    # mov si,[bp+8]; mov byte ptr [si],0xbb
    facts = _facts("8b7608 c604bb")
    assert len(facts) == 1
    assert facts[0].stack_offset == 8
    assert facts[0].dereference_ins_addr == 0x2003
    assert facts[0].access_width_bytes == 1


@pytest.mark.parametrize("hex_bytes", [
    "8b7608 c642afbb",  # mov si,[bp+8]; mov byte ptr [bp+si-81],0xbb
    "8b7608 8d4404",  # mov si,[bp+8]; lea ax,[si+4]
])
def test_scalar_stack_index_or_lea_is_not_pointer_dereference(hex_bytes):
    assert _facts(hex_bytes) == ()


@pytest.mark.parametrize(("hex_bytes", "segment"), [
    ("c642afbb", X86_REG_SS),  # default SS:[bp+si-81]
    ("3ec642afbb", X86_REG_DS),  # explicit DS overrides the BP default
    ("c604bb", X86_REG_DS),  # default DS:[si]
    ("36c604bb", X86_REG_SS),  # explicit SS:[si]
    ("67c60428bb", X86_REG_DS),  # EBP as SIB index does not select SS
    ("67c6440500bb", X86_REG_SS),  # EBP as SIB base selects SS
])
def test_decoded_memory_view_preserves_effective_segment(hex_bytes, segment):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instruction = next(decoder.disasm(bytes.fromhex(hex_bytes), 0x2000))
    operand = next(operand for operand in instruction.operands if operand.type == X86_OP_MEM)
    assert _capstone_memory_view_8616(operand.mem).segment == segment
