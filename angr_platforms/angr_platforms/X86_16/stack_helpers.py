from __future__ import annotations

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .regs import reg16_t, reg32_t, sgreg_t


def push16(emu, value):
    emu.update_gpreg(reg16_t.SP, -2)
    sp = emu.get_gpreg(reg16_t.SP)
    emu.write_mem16_seg(sgreg_t.SS, sp, value)


def push16_register(emu, reg: reg16_t):
    if reg == reg16_t.SP:
        sp = emu.get_gpreg(reg16_t.SP)
        push16(emu, sp)
        return
    push16(emu, emu.get_gpreg(reg))


def pop16(emu):
    sp = emu.get_gpreg(reg16_t.SP)
    value = emu.read_mem16_seg(sgreg_t.SS, sp)
    emu.update_gpreg(reg16_t.SP, 2)
    return value


def push_segment16(emu, segment: sgreg_t) -> None:
    push16(emu, emu.get_segment(segment))


def pop_segment16(emu, segment: sgreg_t) -> None:
    emu.set_segment(segment, pop16(emu))


def push_flags16(emu) -> None:
    push16(emu, emu.get_flags())


def pop_flags16(emu, writable_mask: int = 0x0FD5, fixed_mask: int = 0x0002):
    flags = pop16(emu)
    masked = (flags & emu.constant(writable_mask, Type.int_16)) | emu.constant(fixed_mask, Type.int_16)
    emu.set_flags(masked)
    return masked


def push_all16(emu) -> None:
    sp = emu.get_gpreg(reg16_t.SP)
    push16(emu, emu.get_gpreg(reg16_t.AX))
    push16(emu, emu.get_gpreg(reg16_t.CX))
    push16(emu, emu.get_gpreg(reg16_t.DX))
    push16(emu, emu.get_gpreg(reg16_t.BX))
    push16(emu, sp)
    push16(emu, emu.get_gpreg(reg16_t.BP))
    push16(emu, emu.get_gpreg(reg16_t.SI))
    push16(emu, emu.get_gpreg(reg16_t.DI))


def pop_all16(emu) -> None:
    emu.set_gpreg(reg16_t.DI, pop16(emu))
    emu.set_gpreg(reg16_t.SI, pop16(emu))
    emu.set_gpreg(reg16_t.BP, pop16(emu))
    pop16(emu)
    emu.set_gpreg(reg16_t.BX, pop16(emu))
    emu.set_gpreg(reg16_t.DX, pop16(emu))
    emu.set_gpreg(reg16_t.CX, pop16(emu))
    emu.set_gpreg(reg16_t.AX, pop16(emu))


def push32(emu, value):
    emu.update_gpreg(reg32_t.ESP, -4)
    sp = emu.get_gpreg(reg32_t.ESP)
    emu.write_mem32_seg(sgreg_t.SS, sp, value)


def pop32(emu):
    sp = emu.get_gpreg(reg32_t.ESP)
    value = emu.read_mem32_seg(sgreg_t.SS, sp)
    emu.update_gpreg(reg32_t.ESP, 4)
    return value


def push_all32(emu) -> None:
    esp = emu.get_gpreg(reg32_t.ESP)
    push32(emu, emu.get_gpreg(reg32_t.EAX))
    push32(emu, emu.get_gpreg(reg32_t.ECX))
    push32(emu, emu.get_gpreg(reg32_t.EDX))
    push32(emu, emu.get_gpreg(reg32_t.EBX))
    push32(emu, esp)
    push32(emu, emu.get_gpreg(reg32_t.EBP))
    push32(emu, emu.get_gpreg(reg32_t.ESI))
    push32(emu, emu.get_gpreg(reg32_t.EDI))


def pop_all32(emu) -> None:
    emu.set_gpreg(reg32_t.EDI, pop32(emu))
    emu.set_gpreg(reg32_t.ESI, pop32(emu))
    emu.set_gpreg(reg32_t.EBP, pop32(emu))
    esp = pop32(emu)
    emu.set_gpreg(reg32_t.EBX, pop32(emu))
    emu.set_gpreg(reg32_t.EDX, pop32(emu))
    emu.set_gpreg(reg32_t.ECX, pop32(emu))
    emu.set_gpreg(reg32_t.EAX, pop32(emu))
    emu.set_gpreg(reg32_t.ESP, esp)


def push_segment32(emu, segment: sgreg_t) -> None:
    push32(emu, emu.get_segment(segment))


def pop_segment32(emu, segment: sgreg_t) -> None:
    emu.set_segment(segment, pop32(emu))


def near_return_ip16(emu, instruction_size: int):
    return emu.get_gpreg(reg16_t.IP) + emu.constant(instruction_size, Type.int_16)


def near_return_eip32(emu):
    return emu.get_eip()


def near_relative_target16(emu, displacement, instruction_size: int):
    return near_return_ip16(emu, instruction_size) + emu.constant(displacement, Type.int_16)


def near_relative_target32(emu, displacement, instruction_size: int):
    return emu.get_eip() + emu.constant(instruction_size, Type.int_32) + emu.constant(displacement, Type.int_32)


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


def return_near16(emu, stack_adjust=0):
    ip = pop16(emu)
    if stack_adjust:
        emu.set_gpreg(reg16_t.SP, emu.get_gpreg(reg16_t.SP) + emu.constant(stack_adjust, Type.int_16))
    emu.set_gpreg(reg16_t.IP, ip)
    emu.irsb.next = ip
    emu.irsb.jumpkind = "Ijk_Ret"
    return ip


def return_near32(emu, stack_adjust=0):
    eip = pop32(emu)
    if stack_adjust:
        emu.set_gpreg(reg32_t.ESP, emu.get_gpreg(reg32_t.ESP) + emu.constant(stack_adjust, Type.int_32))
    emu.set_eip(eip)
    emu.irsb.next = eip
    emu.irsb.jumpkind = "Ijk_Ret"
    return eip


def emit_near_call16(emu, target, return_ip=None, instruction_size: int | None = None):
    if return_ip is None:
        if instruction_size is None:
            raise ValueError("instruction_size is required when return_ip is not provided")
        return_ip = near_return_ip16(emu, instruction_size)
    push16(emu, return_ip)
    emu.set_gpreg(reg16_t.IP, target)
    emu.lifter_instruction.jump(None, target, JumpKind.Call)
    return return_ip


def emit_near_jump16(emu, target):
    emu.set_gpreg(reg16_t.IP, target)
    emu.lifter_instruction.jump(None, target, JumpKind.Boring)
    return target


def emit_near_call32(emu, target, return_ip=None):
    if return_ip is None:
        return_ip = near_return_eip32(emu)
    push32(emu, return_ip)
    emu.set_eip(target)
    emu.lifter_instruction.jump(None, target, JumpKind.Call)
    return return_ip


def emit_near_jump32(emu, target):
    emu.set_eip(target)
    emu.lifter_instruction.jump(None, target, JumpKind.Boring)
    return target


def branch_rel32(emu, condition, displacement):
    if hasattr(condition, "cast_to"):
        condition = condition.cast_to(Type.int_1)
    target = emu.get_eip() + emu.constant(displacement, Type.int_32)
    if isinstance(condition, bool):
        if not condition:
            return None
        return emit_near_jump32(emu, target)
    if getattr(condition, "rdt", None) is False:
        return None
    return emit_near_jump32(emu, target)


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
