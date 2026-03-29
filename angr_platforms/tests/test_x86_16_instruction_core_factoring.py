from angr_platforms.X86_16 import instr16
from angr_platforms.X86_16.instr_base import GROUP2_BYTE_SHIFT_ROTATE_HANDLERS, InstrBase


def test_x86_16_instruction_core_registration_tables_cover_hot_ranges():
    assert instr16.X86_16_OPCODE_HELPERS == (
        (0x40, 0x47, "inc_r16", 0),
        (0x48, 0x4F, "dec_r16", 0),
        (0x50, 0x57, "push_r16", 0),
        (0x58, 0x5F, "pop_r16", 0),
        (0x91, 0x97, "xchg_r16_ax", 0),
        (0xB8, 0xBF, "mov_r16_imm16", 4),
    )
    assert GROUP2_BYTE_SHIFT_ROTATE_HANDLERS[4] == "shl_rm8"
    assert GROUP2_BYTE_SHIFT_ROTATE_HANDLERS[6] == "shl_rm8"


def test_x86_16_instruction_core_base_exposes_registration_helper():
    assert hasattr(InstrBase, "_register_opcode_range")


def test_x86_16_instruction_core_base_groups_ax_immediates_under_shared_helpers():
    assert hasattr(instr16.Instr16, "_ax_imm16")
    assert hasattr(instr16.Instr16, "_binary_ax_imm16")
    assert hasattr(instr16.Instr16, "_binary_ax_imm16_with_carry")
    assert hasattr(instr16.Instr16, "_compare_ax_imm16")
