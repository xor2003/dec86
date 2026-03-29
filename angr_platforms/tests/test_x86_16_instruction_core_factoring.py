import inspect

from angr_platforms.X86_16 import instr16
from angr_platforms.X86_16 import instr32
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


def test_x86_16_instruction_core_base_reuses_resolved_memory_operands_for_byte_memory_paths():
    source = inspect.getsource(InstrBase.xchg_r8_rm8) + inspect.getsource(InstrBase.esc)

    assert "_resolved_rm_operand(8)" in source
    assert "select_segment()" not in source
    assert "get_m()" not in source


def test_x86_16_exec_resolved_memory_operands_use_effective_address_width():
    source = inspect.getsource(InstrBase._resolved_rm_operand) + inspect.getsource(InstrBase._resolved_moffs_operand)

    assert "address_width_bits(" in source


def test_x86_16_instruction_core_uses_addressing_helpers_for_xlat_and_bound_pairs():
    source = inspect.getsource(instr16.Instr16.xlat) + inspect.getsource(instr16.Instr16.bound_r16_m16)

    assert "resolve_linear_operand(" in source
    assert "load_resolved_operand(" in source
    assert "load_word_pair16(" in source


def test_x86_16_instruction_core_uses_shared_rm8_access_for_movzx_and_movsx():
    source = inspect.getsource(instr16.Instr16.movzx_r16_rm8) + inspect.getsource(instr16.Instr16.movsx_r16_rm8)

    assert "self.get_rm8()" in source
    assert "calc_modrm()" not in source
    assert "self.emu.get_data8(" not in source


def test_x86_16_instruction_core_uses_string_helpers_for_string_memory_access():
    source = (
        inspect.getsource(instr16.Instr16.movsb_m8_m8)
        + inspect.getsource(instr16.Instr16.movsw_m16_m16)
        + inspect.getsource(instr16.Instr16.lodsb_al_m8)
        + inspect.getsource(instr16.Instr16.lodsw_ax_m16)
        + inspect.getsource(instr16.Instr16.scasb_al_m8)
        + inspect.getsource(instr16.Instr16.scasw_ax_m16)
        + inspect.getsource(instr16.Instr16.cmps_m8_m8)
        + inspect.getsource(instr16.Instr16.cmps_m16_m16)
        + inspect.getsource(instr16.Instr16.insb_m8_dx)
        + inspect.getsource(instr16.Instr16.insw_m16_dx)
        + inspect.getsource(instr16.Instr16.outsb_dx_m8)
        + inspect.getsource(instr16.Instr16.outsw_dx_m16)
    )

    assert "string_load(" in source
    assert "string_store(" in source


def test_x86_16_instruction_core_uses_string_helpers_for_32bit_string_compare_access():
    source = inspect.getsource(instr32.Instr32.cmps_m8_m8) + inspect.getsource(instr32.Instr32.cmps_m32_m32)

    assert "string_load(" in source
    assert "self.emu.get_data8(" not in source
    assert "self.emu.get_data32(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_pusha_and_popa():
    source = inspect.getsource(instr16.Instr16.pusha) + inspect.getsource(instr16.Instr16.popa)

    assert "push_all16(" in source
    assert "pop_all16(" in source
    assert "self.emu.push16(" not in source
    assert "self.emu.pop16(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_near_returns():
    source = inspect.getsource(instr16.Instr16.ret) + inspect.getsource(instr16.Instr16.ret_imm16)

    assert "return_near16(" in source
    assert "self.emu.pop16(" not in source
    assert "self.emu.irsb.jumpkind" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_32bit_stack_families():
    source = (
        inspect.getsource(instr32.Instr32.push_es)
        + inspect.getsource(instr32.Instr32.pop_es)
        + inspect.getsource(instr32.Instr32.push_ss)
        + inspect.getsource(instr32.Instr32.pop_ss)
        + inspect.getsource(instr32.Instr32.push_ds)
        + inspect.getsource(instr32.Instr32.pop_ds)
        + inspect.getsource(instr32.Instr32.pushad)
        + inspect.getsource(instr32.Instr32.popad)
        + inspect.getsource(instr32.Instr32.ret)
    )

    assert "push_segment32(" in source
    assert "pop_segment32(" in source
    assert "push_all32(" in source
    assert "pop_all32(" in source
    assert "return_near32(" in source


def test_x86_16_instruction_core_uses_byte_alu_immediate_helper_families():
    source = (
        inspect.getsource(InstrBase.add_al_imm8)
        + inspect.getsource(InstrBase.or_al_imm8)
        + inspect.getsource(InstrBase.and_al_imm8)
        + inspect.getsource(InstrBase.sub_al_imm8)
        + inspect.getsource(InstrBase.xor_al_imm8)
        + inspect.getsource(InstrBase.adc_al_imm8)
        + inspect.getsource(InstrBase.sbb_al_imm8)
        + inspect.getsource(InstrBase.cmp_al_imm8)
        + inspect.getsource(InstrBase.add_rm8_imm8)
        + inspect.getsource(InstrBase.or_rm8_imm8)
        + inspect.getsource(InstrBase.and_rm8_imm8)
        + inspect.getsource(InstrBase.sub_rm8_imm8)
        + inspect.getsource(InstrBase.xor_rm8_imm8)
        + inspect.getsource(InstrBase.adc_rm8_imm8)
        + inspect.getsource(InstrBase.sbb_rm8_imm8)
        + inspect.getsource(InstrBase.cmp_rm8_imm8)
    )

    assert "_binary_al_imm8(" in source
    assert "_binary_al_imm8_with_carry(" in source
    assert "_compare_al_imm8(" in source
    assert "_binary_rm8_imm8(" in source
    assert "_binary_rm8_imm8_with_carry(" in source
    assert "_compare_rm8_imm8(" in source


def test_x86_16_instruction_core_uses_resolved_operand_load_store_helpers():
    source = (
        inspect.getsource(instr16.Instr16.xchg_r16_rm16)
        + inspect.getsource(InstrBase.xchg_r8_rm8)
        + inspect.getsource(InstrBase.esc)
    )

    assert "load_resolved_operand(" in source
    assert "store_resolved_operand(" in source
