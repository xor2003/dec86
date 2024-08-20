#!/usr/bin/env python3
import sys

import angr
from angr.analyses import CFGFast, VariableRecoveryFast, CallingConventionAnalysis, Decompiler
from angr.calling_conventions import register_default_cc, SimCC, SimStackArg, SimRegArg

from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa

import logging

class SimCC8616MSC(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = SimRegArg("dx", 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True

register_default_cc("x8616", SimCC8616MSC)

#logging.getLogger('angr').setLevel('DEBUG')
#logging.getLogger('angr.calling_conventions').setLevel('DEBUG')
#logging.getLogger('pyvex.lifting.util').setLevel('DEBUG')
logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('DEBUG')


arch_16 = Arch86_16()  # get architecture archinfo.ArchPcode('x86:LE:16:Real Mode')
byte_string = b'\xb8\x00\x4f\xcd\x21\xc3'
#with open("/home/xor/vextest/4093.bin", "rb") as f:
#with open("/home/xor/vextest/1f44.bin", "rb") as f:
#with open("/home/xor/inertia_player/snake.com", "rb") as f:
#with open("/home/xor/masm2c/asmTests/addsub.com", "rb") as f:
#with open("/home/xor/vextest/22ec.bin", "rb") as f:
with open(sys.argv[1], "rb") as f:
        byte_string = f.read()[:0x51]
addr = 0x100
project = angr.load_shellcode(byte_string, arch=arch_16, start_offset=addr, load_address=addr, selfmodifying_code=False, rebase_granularity=0x1000)
print("After load")

#block = project.factory.block(project.entry, max_size=len(byte_string))

print("After disasm")
# force_complete_scan=False - because it is mix of code and data
cfg = project.analyses[CFGFast].prep()(force_complete_scan=False, data_references=True, normalize=True)

for node in cfg.graph.nodes():
    block = project.factory.block(node.addr, size=node.size)
    if block.size == 0:
        continue
    print(f"Block at {hex(node.addr)}, size: {block.size}")

    block.pp()
    block.vex.pp()
    print()

for addr, func in cfg.functions.items():
        _ = project.analyses[VariableRecoveryFast].prep()(func)
        cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype
        
        dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
        print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
