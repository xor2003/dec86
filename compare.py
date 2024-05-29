import angr
import pyvex
from archinfo import ArchX86

from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa

import logging

logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel('ERROR')
logging.getLogger('pyvex.expr').setLevel('DEBUG')
#logging.getLogger('angr').setLevel('DEBUG')
#logging.getLogger('angr.calling_conventions').setLevel('DEBUG')
#logging.getLogger('pyvex.lifting.util').setLevel('DEBUG')
#logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('DEBUG')
FLAGS={"OF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "DF":10, "OF":11}
def assembler(lines, bitness=0) -> bytes:
    import keystone as ks
    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, count = ks_.asm(lines, as_bytes=True)
    return data


def step(simgr):
    # Step to the next instruction (execute the current block)
    simgr.step()
    # Get the new state after execution
    new_state = simgr.active[0]
    return new_state


def prepare(arch, data):
    # Create an Angr project
    addr = 0  # 0x400000
    project = angr.load_shellcode(data, arch=arch, start_offset=0, load_address=addr, selfmodifying_code=False,
                                  rebase_granularity=0x1000)
    # Lift the instruction to VEX
    block = pyvex.lift(data, addr, arch)
    print(block.pp())
    state = project.factory.blank_state()
    # Execute the instruction
    block = project.factory.block(state.addr, len(data))
    block.vex.pp()  # Print the VEX IR for inspection
    block.pp()  # Print the block for inspection
    # Create a simulation manager
    simgr = project.factory.simgr(state)
    return simgr


def compare_states(state1, state2):
    # Helper function to concretize values

    # Compare registers
    for reg in state2.arch.register_list:
        reg_name = reg.name
        if reg_name in ("eip", "eflags"):
            continue
        val1 = getattr(state1.regs, reg_name)
        try:
            val2 = getattr(state2.regs, reg_name)
            #print(f"Register {reg_name}: state1={val1}, state2={val2}")
            if repr(val1) != repr(val2):
                print(f"Register {reg_name} differs: state1={val1}, state2={val2}")
        except KeyError as ex:
            pass
            #print(f"Register {reg_name} not found in state")
    # To handle lazy flag calculation, print individual flags
    flags1 = {key: state1.regs.eflags[bit] for key, bit in FLAGS.items()}
    flags2 = {key: state2.regs.eflags[bit] for key, bit in FLAGS.items()}
    for flag, value1 in flags1.items():
        value2 = flags2[flag]
        if repr(value1) != repr(value2):
            print(f"Flag {flag} differs: state1={value1}, state2={value2}")



CODE = """
add ax,dx
"""
"""
pushf
pop bx
ret
"""

arch_16 = Arch86_16()  # get architecture
arch_32 = ArchX86()  # get architecture

print("~~32~~")
bytes32 = assembler(CODE, 32)
simgr32 = prepare(arch_32, bytes32)

print("~~16~~")
bytes16 = assembler(CODE, 16)
simgr16 = prepare(arch_16, bytes16)

current_state32 = simgr32.active[0]
current_state16 = simgr16.active[0]
for reg in current_state16.arch.register_list:
    val1 = getattr(current_state32.regs, reg.name)
    try:
        setattr(current_state16.regs, reg.name, val1)
    except Exception:
        pass

state32 = step(simgr32)
state16 = step(simgr16)
#state16 = simgr16.active[0]

print("~~compare~~")
compare_states(state32, state16)

