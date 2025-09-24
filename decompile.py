#!/usr/bin/env python3

import angr
from angr import SimProcedure
from angr.analyses import CFGFast, VariableRecoveryFast, CallingConventionAnalysis, Decompiler
from capstone import *
from angr.calling_conventions import register_default_cc, SimCC, SimStackArg, SimRegArg

import sys

from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSCmedium, SimCC8616MSCsmall  # noqa

import logging
logging.getLogger().setLevel('ERROR')

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('angr.analyses.decompiler').setLevel('ERROR')

# Monkey-patch VariableRecoveryFast to skip for 16-bit architectures
class PatchedVariableRecoveryFast(VariableRecoveryFast):
    def run(self):
        if self.function.arch.bits == 16:
            self.variables = {}
            return self
        return super().run()

VariableRecoveryFast = PatchedVariableRecoveryFast

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
logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('ERROR')
logging.getLogger('angr_platforms.angr_platforms.X86_16.parse').setLevel('ERROR')

arch_16 = Arch86_16()



# Check if a file argument is provided
if len(sys.argv) < 2:
    print("Usage: ./decompile.py <file.bin>")
    sys.exit(1)

# Read the binary file

with open(sys.argv[1], 'rb') as f:
    byte_string = f.read()

addr = 0x100

try:
    project = angr.load_shellcode(byte_string, arch=arch_16, load_address=addr, start_offset=0, selfmodifying_code=False, rebase_granularity=0x1000)
    project.entry = addr

    # Hook DOS int 21h at IVT 0x84 for syscall resolution in decomp
    class HookInt21(SimProcedure):
        def run(self):
            return 0  # Stub return; minimal for decomp

    # Temporarily comment hook to avoid unmapped memory error; re-enable if needed
    # project.hook(0x84, HookInt21())
except Exception as e:
    print(f"Failed to load project: {e}")
    sys.exit(1)


print("After disasm")
print("Arch bits:", project.arch.bits)
binary_len = len(byte_string)
regions = [(addr, addr + binary_len)]
cfg = project.analyses.CFGFast(start=addr, regions=regions, force_complete_scan=True, data_references=False, normalize=False, resolve_indirect_jumps=False, symbols=False)

functions = project.kb.functions

if len(functions) == 0 or (addr in functions and not functions[addr].block_addrs):
    try:
        if addr not in functions:
            func = functions.function(addr, create=True)
        else:
            func = functions[addr]
        block = project.factory.block(addr)
        func.add_block(block)
    except:
        pass

print(f"Detected {len(functions)} functions")
print(f"Functions at: {list(functions.keys())}")


for func_addr in list(functions):
    func = functions[func_addr]
    print(f"Function {hex(func_addr)}: {len(func.block_addrs)} blocks")
    if not func.block_addrs:
        print("No blocks, using fallback disassembly:")
        cd = Cs(CS_ARCH_X86, CS_MODE_16)
        for i in cd.disasm(byte_string, func_addr):
            print(f"  {hex(i.address)}: {i.mnemonic} {i.op_str}")
        continue

    # Print function info
    total_size = sum(project.factory.block(ba).size for ba in func.block_addrs)
    print(f" total size {total_size} bytes")

    try:
        _ = project.analyses[VariableRecoveryFast].prep()(func)
    except:
        pass
    try:
        cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype
    except:
        pass
    try:
        dec = project.analyses.Decompiler(func, cfg=cfg, simplify_literals=True)
        if dec.codegen:
            print(f"Decompiled function {hex(func.addr)}:")
            print(dec.codegen.text)
        else:
            print(f"No codegen for {hex(func.addr)}, fallback disassembly:")
            if func.blocks:
                for b in func.blocks:
                    for insn in b.capstone.insns:
                        print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                    print()
            else:
                cd = Cs(CS_ARCH_X86, CS_MODE_16)
                cd.syntax = CS_OPT_SYNTAX_INTEL
                for i in cd.disasm(byte_string, func.addr):
                    print(f"{hex(i.address)}: {i.mnemonic} {i.op_str}")
                print()
    except Exception as e:
        print(f"Decomp failed for {hex(func.addr)}: {e}")
        print("Fallback disassembly:")
        if func.blocks:
            for b in func.blocks:
                for insn in b.capstone.insns:
                    print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                print()
        else:
            cd = Cs(CS_ARCH_X86, CS_MODE_16)
            cd.syntax = CS_OPT_SYNTAX_INTEL
            for i in cd.disasm(byte_string, func.addr):
                print(f"{hex(i.address)}: {i.mnemonic} {i.op_str}")
            print()
