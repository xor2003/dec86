import logging
import re
import sys

import angr
import claripy
import pyvex
from archinfo import ArchX86

from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa

logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel('ERROR')
logging.getLogger('pyvex.expr').setLevel('DEBUG')
logging.getLogger('angr_platforms.X86_16.parse').setLevel('DEBUG')

FLAGS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "DF": 10, "OF": 11}


def assembler(lines, bitness=0) -> bytes:
    import keystone as ks
    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, count = ks_.asm(lines, as_bytes=True)
    print(data)
    return data


def step(simgr, insn_bytes):
    # Step to the next instruction (execute the current block)
    simgr.step(num_inst=1, insn_bytes=insn_bytes)
    # Get the new state after execution
    new_state = simgr.active[0]
    return new_state


def prepare(arch, data):
    # Create an Angr project
    addr = 0  # 0x400000
    project = angr.load_shellcode(data, arch=arch, start_offset=0, load_address=addr, selfmodifying_code=False,
                                  rebase_granularity=0x1000)
    # Lift the instruction to VEX
    block = pyvex.lift(data, addr, arch, max_inst=1)
    #print(block.pp())
    state = project.factory.blank_state()
    # Execute the instruction
    block = project.factory.block(state.addr, len(data))
    block.vex.pp()  # Print the VEX IR for inspection
    block.pp()  # Print the block for inspection
    # Create a simulation manager
    simgr = project.factory.simgr(state)
    return simgr


def compare_states(instruction, state32, state16):
    differencies = []

    skip_regs = {"eflags"}
    if not instruction.startswith("j") and not instruction.startswith("l"):
        skip_regs.add("eip")
    # Compare registers
    for reg in state16.arch.register_list:
        reg_name = reg.name
        if reg_name in skip_regs:
            continue
        val32 = repr(getattr(state32.regs, reg_name))
        val32 = filter_symbolic(val32)
        try:
            val16 = repr(getattr(state16.regs, reg_name))
            val16 = filter_symbolic(val16)
            #print(f"Register {reg_name}: state32={val32}, state16={val16}")
            if val32 != val16:
                print(f"Register {reg_name} differs: state32={val32}\n                 state16={val16}")
                differencies.append((reg_name, val32, val16))
        except KeyError as ex:
            pass
            # print(f"Register {reg_name} not found in state")
    #return differencies
    # To handle lazy flag calculation, print individual flags
    flags32 = {key: state32.regs.flags[bit] for key, bit in FLAGS.items()}
    flags16 = {key: state16.regs.flags[bit] for key, bit in FLAGS.items()}
    for flag, value32 in flags32.items():
        if flag not in {"CF", "ZF", "SF", "OF", "DF"}:
            continue
        value32 = repr(flags32[flag])
        value32 = filter_symbolic(value32)
        value16 = repr(flags16[flag])
        value16 = filter_symbolic(value16)
        #print(f"Flag {flag} differs: state32={value32}, state16={value16}")

        if repr(value32) != repr(value16):
            print(f"Flag {flag} differs: state32={value32}\n                 state16={value16}")
            differencies.append((flag, value32, value16))
    return differencies


def filter_symbolic(value32):
    value32 = value32.replace("{UNINITIALIZED}", "").replace("reg_", "")
    value32 = re.sub(r"_\d_32", "", value32)
    value32 = re.sub(r"\[(\d+):\1\]", "[\g<1>]", value32)
    return value32




def compare_instructions_impact(instruction: str):
    arch_16 = Arch86_16()  # get architecture
    arch_32 = ArchX86()  # get architecture
    print("~~32~~")
    bytes32 = assembler(instruction, 32)
    simgr32 = prepare(arch_32, bytes32)
    print("~~16~~")
    bytes16 = assembler(instruction, 16)
    #bytes16=b"\xcd\x21"
    simgr16 = prepare(arch_16, bytes16)
    current_state32 = simgr32.active[0]
    current_state16 = simgr16.active[0]
    current_state16.regs.eflags = claripy.BVV(0, 32)
    current_state16.regs.eip = claripy.BVV(0, 32)
    current_state16.regs.eax = claripy.BVV(0, 32)
    current_state16.regs.ecx = claripy.BVV(0, 32)
    for reg in current_state16.arch.register_list:
        # if reg.name in {"op_cc_op", "op_cc_dep1", "op_cc_dep2", "op_cc_ndep", "eflags"}:
        #    continue
        val16 = getattr(current_state16.regs, reg.name)
        try:
            pass
            setattr(current_state32.regs, reg.name, val16)
        except Exception as ex:
            print(f"Register {reg.name} failed to set %s", ex)
    print("~~will step 32~~")
    state32 = step(simgr32, bytes32)
    print("~~will step 16~")
    state16 = step(simgr16, bytes16)
    # state32 =current_state32
    # state16 =current_state16
    print("~~compare~~")
    return compare_states(instruction, state32, state16)

"""
add ax,cx
add bx,0x10
add bx,dx
add cx,2
add sp,2
and al,3
and ax,0xf
and bx,0xfff0
cdq 
cld
cli
cmp bp,di
cmp al,1
cmp ax,0x15
cmp ax,8
cmp cx,ax
cmp di,0x200
dec cx
mov bx,0x1234
"""

LIST="""
imul ax,ax,0x6
imul si,si,0x3
imul si,si,0x1234
inc bx
je 0x25
jnz 6
ja 0xc
jae 0x109
jb 0x106
jbe 0x109
jcxz 0x7b
jg 2
jge 0x2e
jl 0x11
jle 5
jmp 5
jmp 0x1ea
jmp 0xffffff35
mov ah,0x0
mov ax,0x1a
mov ax,0x2500
mov ax,di
mov bp,sp
mov bx,0x0
mov bx,ax
mov bx,si
mov ch,al
mov cl,0x4
mov cl,4
mov cx,0x7fff
mov cx,0x96
mov cx,ax
mov di,0x200
mov di,ax
mov ds,dx
mov dx,0x171
mov dx,bx
mov dx,cs
mov dx,di
mov dx,ss
mov es,ax
mov es,di
mov si,0x452e
mov si,ax
mov sp,bp
mov sp,di
mov ss,dx
neg cx
nop
or al,al
or ax,ax
or ch,0x80
pop bp
pop di
push ax
push cs
push si
ret
retf
shl ax,1
shl bx,1
shl bx,cl
shl si,cl
shr di,cl
sti
sub ah,ah
sub al,0x4a
sub ax,ax
sub bp,dx
sub cl,cl
sub sp,0x34
xchg bx,ax
xor ah,ah
xor bp,bp
call 0x17a
call 0xfd92
callf [0x2e0:0xb38]
int 0x21out dx,al

"""

CODE = """
jz 5
movsw
idiv cx
sbb ax,ax
sbb cx,cx
"""
for line in filter(None, LIST.splitlines()):
    result = compare_instructions_impact(line)
    if result:
        sys.exit()
