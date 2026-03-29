from __future__ import annotations

from pyvex.lifting.util.vex_helper import Type

from .regs import reg16_t, reg32_t, sgreg_t


def push16(emu, value):
    emu.update_gpreg(reg16_t.SP, -2)
    sp = emu.get_gpreg(reg16_t.SP)
    emu.write_mem16_seg(sgreg_t.SS, sp, value)


def pop16(emu):
    sp = emu.get_gpreg(reg16_t.SP)
    value = emu.read_mem16_seg(sgreg_t.SS, sp)
    emu.update_gpreg(reg16_t.SP, 2)
    return value


def push32(emu, value):
    emu.update_gpreg(reg32_t.ESP, -4)
    sp = emu.get_gpreg(reg32_t.ESP)
    emu.write_mem32_seg(sgreg_t.SS, sp, value)


def pop32(emu):
    sp = emu.get_gpreg(reg32_t.ESP)
    value = emu.read_mem32_seg(sgreg_t.SS, sp)
    emu.update_gpreg(reg32_t.ESP, 4)
    return value


def near_return_ip16(emu, instruction_size: int):
    return emu.get_gpreg(reg16_t.IP) + emu.constant(instruction_size, Type.int_16)


def near_return_eip32(emu):
    return emu.get_eip()


def push_far_return_frame16(emu, return_ip=None):
    push16(emu, emu.get_sgreg(sgreg_t.CS))
    if return_ip is None:
        return_ip = emu.get_gpreg(reg16_t.IP)
    push16(emu, return_ip)
    return return_ip


def pop_far_return_frame16(emu):
    ip = pop16(emu)
    seg = pop16(emu)
    return ip, seg


def pop_interrupt_frame16(emu):
    ip = pop16(emu)
    cs = pop16(emu)
    flags = pop16(emu)
    return ip, cs, flags


def enter16(emu, frame_size: int, nesting_level: int) -> None:
    push16(emu, emu.get_gpreg(reg16_t.BP))
    ss = emu.get_sgreg(sgreg_t.SS)
    frame_temp = emu.get_gpreg(reg16_t.SP)
    sp = frame_temp
    if nesting_level:
        bp = emu.get_gpreg(reg16_t.BP)
        for _ in range(1, nesting_level):
            bp -= 2
            sp -= 2
            emu.put_data16(ss, sp, emu.get_data16(ss, bp))
        sp -= 2
        emu.put_data16(ss, sp, frame_temp)
    emu.set_gpreg(reg16_t.BP, frame_temp)
    sp -= frame_size
    emu.set_gpreg(reg16_t.SP, sp)


def leave16(emu) -> None:
    ebp = emu.get_gpreg(reg16_t.BP)
    emu.set_gpreg(reg16_t.SP, ebp)
    emu.set_gpreg(reg16_t.BP, pop16(emu))


def leave32(emu) -> None:
    ebp = emu.get_gpreg(reg32_t.EBP)
    emu.set_gpreg(reg32_t.ESP, ebp)
    emu.set_gpreg(reg32_t.EBP, pop32(emu))
