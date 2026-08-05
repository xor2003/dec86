"""Layer: Helper boundary.

Responsibility: execute x86 stack and flag stack effects through the segmented SS memory model.
Forbidden: converting stack offsets into locals/args or inferring variable identity here.
"""

from __future__ import annotations

import builtins
from collections.abc import Callable
from typing import Protocol, TypeAlias, cast

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .addressing_helpers import linear_address
from .regs import reg16_t, reg32_t, sgreg_t


class StackExpr(Protocol):
    """Structural value protocol for PyVEX stack and control-flow expressions."""

    rdt: object

    def __add__(self, other: object) -> StackExpr:
        """Return a PyVEX addition expression."""
        ...

    def __sub__(self, other: object) -> StackExpr:
        """Return a PyVEX subtraction expression."""
        ...

    def __and__(self, other: object) -> StackExpr:
        """Return a PyVEX bitwise-and expression."""
        ...

    def __or__(self, other: object) -> StackExpr:
        """Return a PyVEX bitwise-or expression."""
        ...

    def __ne__(self, other: object) -> StackExpr:  # type: ignore[override]
        """Return a PyVEX inequality expression."""
        ...

    def cast_to(self, ty: object) -> StackExpr:
        """Cast the expression to a PyVEX type."""
        ...


class StackIrsb(Protocol):
    """Writable IRSB surface used by return helpers."""

    next: object
    jumpkind: str


class StackLifterInstruction(Protocol):
    """Control-flow jump surface exposed by the x86 lifter instruction."""

    def jump(
        self,
        condition: object,
        target: object,
        jumpkind: object | None = None,  # noqa: V107 - PyVEX keyword contract
    ) -> None:
        """Emit a VEX control-flow edge."""
        ...


class StackEmulator(Protocol):
    """Minimal emulator protocol consumed by stack helper effects."""

    irsb: StackIrsb
    lifter_instruction: StackLifterInstruction

    def update_gpreg(self, reg: object, delta: object) -> None:
        """Apply a relative update to a general-purpose register."""
        ...

    def get_gpreg(self, reg: object) -> StackExpr:
        """Return a general-purpose register expression."""
        ...

    def set_gpreg(self, reg: object, value: object) -> None:
        """Write a general-purpose register expression."""
        ...

    def read_mem16_seg(self, segment: object, offset: object) -> StackExpr:
        """Read a 16-bit segmented stack value."""
        ...

    def write_mem16_seg(self, segment: object, offset: object, value: object) -> None:
        """Write a 16-bit segmented stack value."""
        ...

    def read_mem32_seg(self, segment: object, offset: object) -> StackExpr:
        """Read a 32-bit segmented stack value."""
        ...

    def write_mem32_seg(self, segment: object, offset: object, value: object) -> None:
        """Write a 32-bit segmented stack value."""
        ...

    def get_segment(self, segment: object) -> StackExpr:
        """Return a segment register expression."""
        ...

    def set_segment(self, segment: object, value: object) -> None:
        """Write a segment register expression."""
        ...

    def get_sgreg(self, segment: object) -> StackExpr:
        """Return a segment register expression by enum id."""
        ...

    def set_sgreg(self, segment: object, value: object) -> None:
        """Write a segment register expression by enum id."""
        ...

    def get_flags(self) -> StackExpr:
        """Return FLAGS."""
        ...

    def set_flags(self, value: object) -> None:
        """Write FLAGS."""
        ...

    def get_eflags(self) -> StackExpr:
        """Return EFLAGS."""
        ...

    def set_eflags(self, value: object) -> None:
        """Write EFLAGS."""
        ...

    def constant(self, value: object, ty: object) -> StackExpr:
        """Return a typed PyVEX constant expression."""
        ...

    def get_eip(self) -> StackExpr:
        """Return EIP."""
        ...

    def set_eip(self, value: object) -> None:
        """Write EIP."""
        ...

    def put_data16(self, segment: object, offset: object, value: object) -> None:
        """Write a 16-bit segmented data value."""
        ...

    def get_data16(self, segment: object, offset: object) -> StackExpr:
        """Read a 16-bit segmented data value."""
        ...

    def callf(self, segment: object, offset: object, *, return_ip: object) -> None:
        """Emit a far call through the emulator."""
        ...

    def jmpf(self, segment: object, offset: object) -> None:
        """Emit a far jump through the emulator."""
        ...


StackPair: TypeAlias = tuple[StackExpr, StackExpr]
StackTriple: TypeAlias = tuple[StackExpr, StackExpr, StackExpr]


def _dynamic_pyvex_expr_getattr_8616(obj: object, name: str, default: object = None) -> object:
    """Read an attribute across the dynamic third-party PyVEX expression boundary."""
    return builtins.getattr(obj, name, default)


def push16(emu: StackEmulator, value: object) -> None:
    """Push a 16-bit value through SS:SP without inferring variable identity."""
    emu.update_gpreg(reg16_t.SP, -2)
    sp = emu.get_gpreg(reg16_t.SP)
    emu.write_mem16_seg(sgreg_t.SS, sp, value)


def push16_register(emu: StackEmulator, reg: reg16_t) -> None:
    """Push a 16-bit register value, preserving PUSH SP original-value semantics."""
    if reg == reg16_t.SP:
        sp = emu.get_gpreg(reg16_t.SP)
        push16(emu, sp)
        return
    push16(emu, emu.get_gpreg(reg))


def pop16_register(emu: StackEmulator, reg: reg16_t) -> None:
    """Pop a 16-bit SS:SP value into a general-purpose register."""
    emu.set_gpreg(reg, pop16(emu))


def push32_register(emu: StackEmulator, reg: reg32_t) -> None:
    """Push a 32-bit register value through SS:ESP."""
    push32(emu, emu.get_gpreg(reg))


def pop32_register(emu: StackEmulator, reg: reg32_t) -> None:
    """Pop a 32-bit SS:ESP value into a general-purpose register."""
    emu.set_gpreg(reg, pop32(emu))


def pop16(emu: StackEmulator) -> StackExpr:
    """Pop and return a 16-bit value from the segmented SS stack."""
    sp = emu.get_gpreg(reg16_t.SP)
    value = emu.read_mem16_seg(sgreg_t.SS, sp)
    emu.update_gpreg(reg16_t.SP, 2)
    return value


def push_segment16(emu: StackEmulator, segment: sgreg_t) -> None:
    """Push a 16-bit segment register value through SS:SP."""
    push16(emu, emu.get_segment(segment))


def pop_segment16(emu: StackEmulator, segment: sgreg_t) -> None:
    """Pop a 16-bit value into a segment register."""
    emu.set_segment(segment, pop16(emu))


def push_flags16(emu: StackEmulator) -> None:
    """Push FLAGS through the 16-bit segmented stack."""
    push16(emu, emu.get_flags())


def pop_flags16(emu: StackEmulator, writable_mask: int = 0x0FD5, fixed_mask: int = 0x0002) -> StackExpr:
    """Pop FLAGS and apply the 16-bit writable/fixed flag mask contract."""
    flags = pop16(emu)
    masked = (flags & emu.constant(writable_mask, Type.int_16)) | emu.constant(fixed_mask, Type.int_16)
    emu.set_flags(masked)
    return masked


def push_flags32(emu: StackEmulator) -> None:
    """Push EFLAGS through the 32-bit segmented stack."""
    push32(emu, emu.get_eflags())


def pop_flags32(emu: StackEmulator) -> StackExpr:
    """Pop EFLAGS from SS:ESP and install the resulting value."""
    flags = pop32(emu)
    emu.set_eflags(flags)
    return flags


def push_immediate16(emu: StackEmulator, value: object) -> None:
    """Push a decoded 16-bit immediate through SS:SP."""
    push16(emu, value)


def push_immediate32(emu: StackEmulator, value: object) -> None:
    """Push a decoded 32-bit immediate through SS:ESP."""
    push32(emu, value)


def push_all16(emu: StackEmulator) -> None:
    """Push all 16-bit general registers in x86 PUSHA order."""
    sp = emu.get_gpreg(reg16_t.SP)
    push16(emu, emu.get_gpreg(reg16_t.AX))
    push16(emu, emu.get_gpreg(reg16_t.CX))
    push16(emu, emu.get_gpreg(reg16_t.DX))
    push16(emu, emu.get_gpreg(reg16_t.BX))
    push16(emu, sp)
    push16(emu, emu.get_gpreg(reg16_t.BP))
    push16(emu, emu.get_gpreg(reg16_t.SI))
    push16(emu, emu.get_gpreg(reg16_t.DI))


def pop_all16(emu: StackEmulator) -> None:
    """Pop all 16-bit general registers in x86 POPA order, skipping saved SP."""
    emu.set_gpreg(reg16_t.DI, pop16(emu))
    emu.set_gpreg(reg16_t.SI, pop16(emu))
    emu.set_gpreg(reg16_t.BP, pop16(emu))
    pop16(emu)
    emu.set_gpreg(reg16_t.BX, pop16(emu))
    emu.set_gpreg(reg16_t.DX, pop16(emu))
    emu.set_gpreg(reg16_t.CX, pop16(emu))
    emu.set_gpreg(reg16_t.AX, pop16(emu))


def push32(emu: StackEmulator, value: object) -> None:
    """Push a 32-bit value through SS:ESP."""
    emu.update_gpreg(reg32_t.ESP, -4)
    sp = emu.get_gpreg(reg32_t.ESP)
    emu.write_mem32_seg(sgreg_t.SS, sp, value)


def pop32(emu: StackEmulator) -> StackExpr:
    """Pop and return a 32-bit value from the segmented SS stack."""
    sp = emu.get_gpreg(reg32_t.ESP)
    value = emu.read_mem32_seg(sgreg_t.SS, sp)
    emu.update_gpreg(reg32_t.ESP, 4)
    return value


def push_all32(emu: StackEmulator) -> None:
    """Push all 32-bit general registers in x86 PUSHAD order."""
    esp = emu.get_gpreg(reg32_t.ESP)
    push32(emu, emu.get_gpreg(reg32_t.EAX))
    push32(emu, emu.get_gpreg(reg32_t.ECX))
    push32(emu, emu.get_gpreg(reg32_t.EDX))
    push32(emu, emu.get_gpreg(reg32_t.EBX))
    push32(emu, esp)
    push32(emu, emu.get_gpreg(reg32_t.EBP))
    push32(emu, emu.get_gpreg(reg32_t.ESI))
    push32(emu, emu.get_gpreg(reg32_t.EDI))


def pop_all32(emu: StackEmulator) -> None:
    """Pop all 32-bit general registers in x86 POPAD order."""
    emu.set_gpreg(reg32_t.EDI, pop32(emu))
    emu.set_gpreg(reg32_t.ESI, pop32(emu))
    emu.set_gpreg(reg32_t.EBP, pop32(emu))
    esp = pop32(emu)
    emu.set_gpreg(reg32_t.EBX, pop32(emu))
    emu.set_gpreg(reg32_t.EDX, pop32(emu))
    emu.set_gpreg(reg32_t.ECX, pop32(emu))
    emu.set_gpreg(reg32_t.EAX, pop32(emu))
    emu.set_gpreg(reg32_t.ESP, esp)


def push_segment32(emu: StackEmulator, segment: sgreg_t) -> None:
    """Push a 32-bit segment value through SS:ESP."""
    push32(emu, emu.get_segment(segment))


def pop_segment32(emu: StackEmulator, segment: sgreg_t) -> None:
    """Pop a 32-bit stack value into a segment register."""
    emu.set_segment(segment, pop32(emu))


def near_return_ip16(emu: StackEmulator, instruction_size: int) -> StackExpr:
    """Compute the 16-bit near return IP from the current instruction size."""
    return emu.get_gpreg(reg16_t.IP) + emu.constant(instruction_size, Type.int_16)


def near_return_eip32(emu: StackEmulator) -> StackExpr:
    """Return the current 32-bit EIP used as a near-call return target."""
    return emu.get_eip()


def near_relative_target16(emu: StackEmulator, displacement: object, instruction_size: int) -> StackExpr:
    """Compute a 16-bit relative branch target from IP, displacement, and size."""
    return near_return_ip16(emu, instruction_size) + emu.constant(displacement, Type.int_16)


def near_relative_target32(emu: StackEmulator, displacement: object, instruction_size: int = 0) -> StackExpr:
    """Compute a 32-bit relative branch target from EIP, displacement, and size."""
    return emu.get_eip() + emu.constant(instruction_size, Type.int_32) + emu.constant(displacement, Type.int_32)


def push_far_return_frame16(emu: StackEmulator, return_ip: object | None = None) -> object:
    """Push the 16-bit far-call return frame and return the pushed IP."""
    push16(emu, emu.get_sgreg(sgreg_t.CS))
    if return_ip is None:
        return_ip = emu.get_gpreg(reg16_t.IP)
    push16(emu, return_ip)
    return return_ip


def push_far_return_frame32(emu: StackEmulator, return_ip: object | None = None) -> object:
    """Push the 32-bit far-call return frame and return the pushed EIP."""
    push32(emu, emu.get_segment(sgreg_t.CS))
    if return_ip is None:
        return_ip = emu.get_eip()
    push32(emu, return_ip)
    return return_ip


def push_privilege_stack32(emu: StackEmulator) -> StackPair:
    """Push the current SS:ESP pair for a 32-bit privilege transition."""
    saved_ss = emu.get_segment(sgreg_t.SS)
    saved_esp = emu.get_gpreg(reg32_t.ESP)
    push32(emu, saved_ss)
    push32(emu, saved_esp)
    return saved_ss, saved_esp


def pop_far_return_frame16(emu: StackEmulator) -> StackPair:
    """Pop a 16-bit far-return IP:CS frame from SS:SP."""
    ip = pop16(emu)
    seg = pop16(emu)
    return ip, seg


def pop_far_return_frame32(emu: StackEmulator) -> StackPair:
    """Pop a 32-bit far-return EIP:CS frame from SS:ESP."""
    eip = pop32(emu)
    seg = pop32(emu)
    return eip, seg


def pop_interrupt_frame16(emu: StackEmulator) -> StackTriple:
    """Pop a 16-bit interrupt return frame in IP, CS, FLAGS order."""
    ip = pop16(emu)
    cs = pop16(emu)
    flags = pop16(emu)
    return ip, cs, flags


def pop_interrupt_frame32(emu: StackEmulator) -> StackTriple:
    """Pop a 32-bit interrupt return frame in EIP, CS, EFLAGS order."""
    eip = pop32(emu)
    cs = pop32(emu)
    flags = pop32(emu)
    return eip, cs, flags


def return_near16(emu: StackEmulator, stack_adjust: int = 0) -> StackExpr:
    """Emit a 16-bit near return and apply an optional stack adjustment."""
    ip = pop16(emu)
    if stack_adjust:
        emu.set_gpreg(reg16_t.SP, emu.get_gpreg(reg16_t.SP) + emu.constant(stack_adjust, Type.int_16))
    emu.set_gpreg(reg16_t.IP, ip)
    emu.irsb.next = ip
    emu.irsb.jumpkind = "Ijk_Ret"
    return ip


def return_near32(emu: StackEmulator, stack_adjust: int = 0) -> StackExpr:
    """Emit a 32-bit near return and apply an optional stack adjustment."""
    eip = pop32(emu)
    if stack_adjust:
        emu.set_gpreg(reg32_t.ESP, emu.get_gpreg(reg32_t.ESP) + emu.constant(stack_adjust, Type.int_32))
    emu.set_eip(eip)
    emu.irsb.next = eip
    emu.irsb.jumpkind = "Ijk_Ret"
    return eip


def emit_near_call16(
    emu: StackEmulator,
    target: object,
    return_ip: object | None = None,
    instruction_size: int | None = None,
) -> object:
    """Emit a 16-bit near call edge after pushing the return IP."""
    if return_ip is None:
        if instruction_size is None:
            raise ValueError("instruction_size is required when return_ip is not provided")
        return_ip = near_return_ip16(emu, instruction_size)
    push16(emu, return_ip)
    emu.set_gpreg(reg16_t.IP, target)
    emu.lifter_instruction.jump(None, target, JumpKind.Call)
    return return_ip


def emit_near_jump16(emu: StackEmulator, target: object) -> object:
    """Emit a 16-bit near jump edge."""
    emu.set_gpreg(reg16_t.IP, target)
    emu.lifter_instruction.jump(None, target, JumpKind.Boring)
    return target


def emit_near_call32(emu: StackEmulator, target: object, return_ip: object | None = None) -> object:
    """Emit a 32-bit near call edge after pushing the return EIP."""
    if return_ip is None:
        return_ip = near_return_eip32(emu)
    push32(emu, return_ip)
    emu.set_eip(target)
    emu.lifter_instruction.jump(None, target, JumpKind.Call)
    return return_ip


def emit_near_jump32(emu: StackEmulator, target: object) -> object:
    """Emit a 32-bit near jump edge."""
    emu.set_eip(target)
    emu.lifter_instruction.jump(None, target, JumpKind.Boring)
    return target


def far_return_ip16(emu: StackEmulator, instruction_size: int) -> StackExpr:
    """Compute the 16-bit far-call return IP from instruction size."""
    return near_return_ip16(emu, instruction_size)


def far_return_ip32(emu: StackEmulator, instruction_size: int) -> StackExpr:
    """Compute the 32-bit far-call return EIP from instruction size."""
    return emu.get_eip() + emu.constant(instruction_size, Type.int_32)


def emit_far_call16(emu: StackEmulator, segment: object, offset: object, return_ip: object) -> object:
    """Emit a 16-bit far call through the emulator boundary."""
    emu.callf(segment, offset, return_ip=return_ip)
    return return_ip


def emit_far_jump16(emu: StackEmulator, segment: object, offset: object) -> object:
    """Emit a 16-bit far jump through the emulator boundary."""
    emu.jmpf(segment, offset)
    return offset


def emit_far_call32(emu: StackEmulator, segment: object, offset: object, return_ip: object) -> object:
    """Emit a 32-bit far call through the emulator boundary."""
    emu.callf(segment, offset, return_ip=return_ip)
    return return_ip


def emit_far_jump32(emu: StackEmulator, segment: object, offset: object) -> object:
    """Emit a 32-bit far jump through the emulator boundary."""
    emu.jmpf(segment, offset)
    return offset


def return_far16(emu: StackEmulator, stack_adjust: int = 0) -> StackPair:
    """Emit a 16-bit far return and restore CS:IP."""
    ip, seg = pop_far_return_frame16(emu)
    if stack_adjust:
        emu.set_gpreg(reg16_t.SP, emu.get_gpreg(reg16_t.SP) + emu.constant(stack_adjust, Type.int_16))
    emu.set_sgreg(sgreg_t.CS, seg)
    emu.set_gpreg(reg16_t.IP, ip)
    addr = linear_address(emu, seg, ip)
    emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)
    return ip, seg


def return_interrupt16(emu: StackEmulator) -> StackTriple:
    """Emit a 16-bit interrupt return and restore CS:IP plus FLAGS."""
    ip, cs, flags = pop_interrupt_frame16(emu)
    emu.set_gpreg(reg16_t.FLAGS, flags)
    emu.set_sgreg(sgreg_t.CS, cs)
    emu.set_gpreg(reg16_t.IP, ip)
    addr = linear_address(emu, cs, ip)
    emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)
    return ip, cs, flags


def return_far32(emu: StackEmulator, stack_adjust: int = 0) -> StackPair:
    """Emit a 32-bit far return and restore CS:EIP."""
    eip, seg = pop_far_return_frame32(emu)
    if stack_adjust:
        emu.set_gpreg(reg32_t.ESP, emu.get_gpreg(reg32_t.ESP) + emu.constant(stack_adjust, Type.int_32))
    emu.set_segment(sgreg_t.CS.name, seg)
    emu.set_eip(eip)
    addr = linear_address(emu, seg, eip)
    emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)
    return eip, seg


def return_interrupt32(emu: StackEmulator) -> StackTriple:
    """Emit a 32-bit interrupt return and restore CS:EIP plus EFLAGS."""
    eip, cs, flags = pop_interrupt_frame32(emu)
    emu.set_eflags(flags)
    emu.set_segment(sgreg_t.CS.name, cs)
    emu.set_eip(eip)
    addr = linear_address(emu, cs, eip)
    emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)
    return eip, cs, flags


def _branch_rel(
    emu: StackEmulator,
    condition: object,
    displacement: object,
    instruction_size: int,
    target_width_bits: int,
    emit_jump: Callable[[StackEmulator, object], object],
) -> object | None:
    if hasattr(condition, "cast_to"):
        condition = cast(StackExpr, condition).cast_to(Type.int_1)
    target = (
        (emu.get_gpreg(reg16_t.IP) if target_width_bits == 16 else emu.get_eip())
        + emu.constant(displacement, Type.int_16 if target_width_bits == 16 else Type.int_32)
        + emu.constant(instruction_size, Type.int_16 if target_width_bits == 16 else Type.int_32)
    )
    if isinstance(condition, bool):
        if not condition:
            return None
        return emit_jump(emu, target)
    if _dynamic_pyvex_expr_getattr_8616(condition, "rdt", None) is False:
        return None
    target_expr = target.rdt if hasattr(target, "rdt") else target
    emu.lifter_instruction.jump(condition, target_expr, JumpKind.Boring)
    return target


def branch_rel8(emu: StackEmulator, condition: object, displacement: object) -> object | None:
    """Emit or compute an 8-bit relative branch target from a 16-bit IP."""
    return _branch_rel(emu, condition, displacement, 2, 16, emit_near_jump16)


def branch_rel16(
    emu: StackEmulator,
    condition: object,
    displacement: object,
    instruction_size: int = 3,
) -> object | None:
    """Emit or compute a 16-bit relative branch target from a 16-bit IP."""
    return _branch_rel(emu, condition, displacement, instruction_size, 16, emit_near_jump16)


def branch_rel32(emu: StackEmulator, condition: object, displacement: object) -> object | None:
    """Emit or compute a 32-bit relative branch target from EIP."""
    return _branch_rel(emu, condition, displacement, 0, 32, emit_near_jump32)


def loop_rel8(emu: StackEmulator, condition: StackExpr, displacement: object) -> object | None:
    """Decrement CX and emit an 8-bit LOOP-style branch when the condition holds."""
    cx = emu.get_gpreg(reg16_t.CX) - emu.constant(1, Type.int_16)
    emu.set_gpreg(reg16_t.CX, cx)
    loop_continue = (cx != emu.constant(0, Type.int_16)).cast_to(Type.int_1)
    return branch_rel8(emu, condition.cast_to(Type.int_1) & loop_continue, displacement)


def enter16(emu: StackEmulator, frame_size: int, nesting_level: int) -> None:
    """Execute ENTER for a 16-bit frame without naming locals or arguments."""
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


def leave16(emu: StackEmulator) -> None:
    """Execute LEAVE for a 16-bit frame through SS:BP/SP state."""
    ebp = emu.get_gpreg(reg16_t.BP)
    emu.set_gpreg(reg16_t.SP, ebp)
    emu.set_gpreg(reg16_t.BP, pop16(emu))


def leave32(emu: StackEmulator) -> None:
    """Execute LEAVE for a 32-bit frame through SS:EBP/ESP state."""
    ebp = emu.get_gpreg(reg32_t.EBP)
    emu.set_gpreg(reg32_t.ESP, ebp)
    emu.set_gpreg(reg32_t.EBP, pop32(emu))
