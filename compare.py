import logging
import re
from copy import deepcopy

import angr
import pyvex
from archinfo import ArchX86

from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa

logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel('ERROR')
logging.getLogger('pyvex.expr').setLevel('DEBUG')
# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr.calling_conventions').setLevel('DEBUG')
# logging.getLogger('pyvex.lifting.util').setLevel('DEBUG')
# logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('DEBUG')
FLAGS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "DF": 10, "OF": 11}
# LOHF SF:ZF:0:AF:0:PF:1:CF
LAHF = {"SF": 7, "ZF": 6, "AF": 4, "PF": 2, "CF": 0}


def assembler(lines, bitness=0) -> bytes:
    import keystone as ks
    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, count = ks_.asm(lines, as_bytes=True)
    return data


def step(simgr):
    # Step to the next instruction (execute the current block)
    simgr.step(num_inst=1)
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
    print(block.pp())
    state = project.factory.blank_state()
    # Execute the instruction
    block = project.factory.block(state.addr, len(data))
    block.vex.pp()  # Print the VEX IR for inspection
    block.pp()  # Print the block for inspection
    # Create a simulation manager
    simgr = project.factory.simgr(state)
    return simgr


def compare_states(state32, state16):
    # Helper function to concretize values

    # Compare registers
    for reg in state16.arch.register_list:
        reg_name = reg.name
        if reg_name in ("eax", "eip", "eflags"):
            continue
        val32 = repr(getattr(state32.regs, reg_name))
        val32 = filter_symbolic(val32)
        try:
            val16 = repr(getattr(state16.regs, reg_name))
            val16 = filter_symbolic(val16)
            #print(f"Register {reg_name}: state32={val32}, state16={val16}")
            if val32 != val16:
                print(f"Register {reg_name} differs: state32={val32}\n                 state16={val16}")
        except KeyError as ex:
            pass
            # print(f"Register {reg_name} not found in state")
    # To handle lazy flag calculation, print individual flags
    # flags2_ = calculate_flags(state2)
    flags32 = {key: state32.regs.flags[bit] for key, bit in FLAGS.items()}
    flags16 = {key: state16.regs.flags[bit] for key, bit in FLAGS.items()}
    for flag, value32 in flags32.items():
        if flag in {"PF", "DF", "AF"}:
            continue
        value32 = repr(flags32[flag])
        value32 = filter_symbolic(value32)
        value16 = repr(flags16[flag])
        value16 = filter_symbolic(value16)
        #print(f"Flag {flag} differs: state32={value32}, state16={value16}")

        if repr(value32) != repr(value16):
            print(f"Flag {flag} differs: state32={value32}\n                 state16={value16}")


def filter_symbolic(value32):
    value32 = value32.replace("{UNINITIALIZED}", "").replace("reg_", "")
    value32 = re.sub(r"_\d_32", "", value32)
    value32 = re.sub(r"\[(\d+):\1\]", "[\g<1>]", value32)
    return value32


CODE = """
idiv bl
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
    #if reg.name in {"op_cc_op", "op_cc_dep1", "op_cc_dep2", "op_cc_ndep", "eflags"}:
    #    continue
    val16 = getattr(current_state16.regs, reg.name)
    try:
        pass
        setattr(current_state32.regs, reg.name, val16)
    except Exception as ex:
        print(f"Register {reg.name} failed to set %s", ex)

state32 = step(simgr32)
state16 = step(simgr16)
#state32 =current_state32
#state16 =current_state16

print("~~compare~~")
compare_states(state32, state16)
