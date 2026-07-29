import inspect
from types import SimpleNamespace

from angr_platforms.X86_16.instr_base import InstrBase
from angr_platforms.X86_16.instruction import CHK_IMM8, CHK_MODRM, MAX_OPCODE
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY


def _dummy_handler() -> None:
    return None


def test_instruction_any_implements_gymrat_decoder_contract():
    assert Instruction_ANY.bin_format == "xxxxxxxx"
    assert Instruction_ANY.name == "nop"
    assert not inspect.isabstract(Instruction_ANY)


def _table_host():
    return SimpleNamespace(instrfuncs=[None] * MAX_OPCODE, chk=[0] * MAX_OPCODE)


def test_set_funcflag_maps_0f_prefixed_opcode_into_two_byte_table_slot():
    host = _table_host()

    InstrBase.set_funcflag(host, 0x0F90, _dummy_handler, CHK_MODRM)

    assert host.instrfuncs[0x190] is _dummy_handler
    assert host.chk[0x190] == CHK_MODRM


def test_set_funcflag_maps_single_byte_opcode_into_direct_slot():
    host = _table_host()

    InstrBase.set_funcflag(host, 0x8A, _dummy_handler, CHK_IMM8)

    assert host.instrfuncs[0x8A] is _dummy_handler
    assert host.chk[0x8A] == CHK_IMM8


def test_register_opcode_range_fills_all_slots_with_same_handler_and_flags():
    host = _table_host()

    InstrBase._register_opcode_range(host, 0x40, 0x47, _dummy_handler, CHK_MODRM)

    for opcode in range(0x40, 0x48):
        assert host.instrfuncs[opcode] is _dummy_handler
        assert host.chk[opcode] == CHK_MODRM
