from angr_platforms.X86_16.regs import reg16_t, sgreg_t
from angr_platforms.X86_16.stack_helpers import (
    enter16,
    leave16,
    near_return_ip16,
    pop16,
    pop_far_return_frame16,
    pop_interrupt_frame16,
    push16,
    push16_register,
    push_far_return_frame16,
)


class _StackEmu:
    def __init__(self):
        self.gpregs = {
            reg16_t.SP: 0x1000,
            reg16_t.BP: 0x2222,
            reg16_t.IP: 0x0100,
        }
        self.sgregs = {sgreg_t.CS: 0x1234, sgreg_t.SS: 0x2000}
        self.memory = {}

    def update_gpreg(self, reg, delta):
        self.gpregs[reg] = self.gpregs[reg] + delta

    def get_gpreg(self, reg):
        return self.gpregs[reg]

    def set_gpreg(self, reg, value):
        self.gpregs[reg] = value

    def get_sgreg(self, reg):
        return self.sgregs[reg]

    def set_sgreg(self, reg, value):
        self.sgregs[reg] = value

    def write_mem16_seg(self, seg, addr, value):
        self.memory[(seg, addr)] = value

    def read_mem16_seg(self, seg, addr):
        return self.memory[(seg, addr)]

    def constant(self, value, _ty):
        return value


def test_stack_helpers_push_and_pop_16_bit_values():
    emu = _StackEmu()

    push16(emu, 0xABCD)
    assert emu.get_gpreg(reg16_t.SP) == 0x0FFE
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0xABCD
    assert pop16(emu) == 0xABCD
    assert emu.get_gpreg(reg16_t.SP) == 0x1000


def test_stack_helpers_push16_register_preserves_original_sp_value():
    emu = _StackEmu()

    push16_register(emu, reg16_t.SP)

    assert emu.get_gpreg(reg16_t.SP) == 0x0FFE
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1000


def test_stack_helpers_form_far_call_frames_in_cs_ip_order():
    emu = _StackEmu()

    push_far_return_frame16(emu, 0x0105)

    assert emu.get_gpreg(reg16_t.SP) == 0x0FFC
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1234
    assert emu.memory[(sgreg_t.SS, 0x0FFC)] == 0x0105
    assert pop_far_return_frame16(emu) == (0x0105, 0x1234)


def test_stack_helpers_pop_interrupt_frames_in_ip_cs_flags_order():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x0FF8
    emu.memory[(sgreg_t.SS, 0x0FF8)] = 0xAAAA
    emu.memory[(sgreg_t.SS, 0x0FFA)] = 0xBBBB
    emu.memory[(sgreg_t.SS, 0x0FFC)] = 0xCCCC

    assert pop_interrupt_frame16(emu) == (0xAAAA, 0xBBBB, 0xCCCC)


def test_stack_helpers_enter_and_leave_manage_the_frame_pointer():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x1000
    emu.gpregs[reg16_t.BP] = 0x1111

    enter16(emu, 4, 0)

    assert emu.get_gpreg(reg16_t.BP) == 0x0FFE
    assert emu.get_gpreg(reg16_t.SP) == 0x0FFA
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1111

    leave16(emu)

    assert emu.get_gpreg(reg16_t.BP) == 0x1111
    assert emu.get_gpreg(reg16_t.SP) == 0x1000


def test_stack_helpers_compute_near_return_ip_from_instruction_size():
    emu = _StackEmu()

    assert near_return_ip16(emu, 3) == 0x0103
