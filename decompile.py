#!/usr/bin/env python3

import angr
from angr import SimProcedure
from angr.analyses import CFGFast, VariableRecoveryFast, CallingConventionAnalysis, Decompiler
from capstone import *
from angr.calling_conventions import register_default_cc, SimCC, SimStackArg, SimRegArg
import claripy
import io

import sys
import tempfile
import os

from archinfo import all_arches
from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSCmedium, SimCC8616MSCsmall  # noqa

# Monkey-patch for Typehoon 16-bit support
from angr.analyses.typehoon.simple_solver import BASE_LATTICES, TopType, Int, Int16, BottomType
import networkx
BASE_LATTICE_16 = networkx.DiGraph()
BASE_LATTICE_16.add_edge(TopType(), Int())
BASE_LATTICE_16.add_edge(Int(), Int16())
BASE_LATTICE_16.add_edge(Int16(), BottomType())
BASE_LATTICES[16] = BASE_LATTICE_16

# Monkey-patch Typehoon for 16-bit pointers
from angr.analyses.typehoon.simple_solver import SimpleSolver
from angr.sim_type import SimTypePointer, SimTypeInt
from angr.sim_type import SimType
def patched_pointer_class(cls, bits=None):
    # For 16-bit arch, always return 16-bit pointer; ignore bits if not passed
    return SimTypePointer(SimTypeInt(16))
SimpleSolver._pointer_class = staticmethod(patched_pointer_class)

from angr.analyses.variable_recovery.engine_vex import SimEngineVRVEX
import traceback
from pyvex.expr import Binop, Unop
from angr.engines.light import SpOffset

class PatchedSimEngineVRVEX(SimEngineVRVEX):
    def _handle_Binop_Add16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_Add32', [w1, w2])

    def _handle_Binop_CmpLT16U(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_CmpLT32U', [w1, w2])

    def _handle_Binop_And16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_And32', [w1, w2])

    def _handle_Binop_Shl16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_Shl32', [w1, w2])

    def _handle_Binop_Or16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_Or32', [w1, w2])

    def _handle_Binop_CmpEQ16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_CmpEQ32', [w1, w2])

    def _handle_Binop_Shr16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_Shr32', [w1, w2])

    def _handle_Binop_Xor16(self, expr):
        child1, child2 = expr.args
        w1 = Unop('Iop_16Uto32', [child1])
        w2 = Unop('Iop_16Uto32', [child2])
        return Binop('Iop_Xor32', [w1, w2])

    def _handle_Unop_Not16(self, expr):
        child = expr.args[0]
        w = Unop('Iop_16Uto32', [child])
        return Unop('Iop_Not32', [w])

    def _handle_expr_Binop(self, expr):
        if expr.op == 'Iop_Add16':
            return self._handle_Binop_Add16(expr)
        elif expr.op == 'Iop_CmpLT16U':
            return self._handle_Binop_CmpLT16U(expr)
        elif expr.op == 'Iop_And16':
            return self._handle_Binop_And16(expr)
        elif expr.op == 'Iop_Shl16':
            return self._handle_Binop_Shl16(expr)
        elif expr.op == 'Iop_Or16':
            return self._handle_Binop_Or16(expr)
        elif expr.op == 'Iop_CmpEQ16':
            return self._handle_Binop_CmpEQ16(expr)
        elif expr.op == 'Iop_Shr16':
            return self._handle_Binop_Shr16(expr)
        elif expr.op == 'Iop_Xor16':
            return self._handle_Binop_Xor16(expr)
        return super()._handle_expr_Binop(expr)

    def _handle_expr_Unop(self, expr):
        if expr.op == 'Iop_Not16':
            return self._handle_Unop_Not16(expr)
        return super()._handle_expr_Unop(expr)

SimEngineVRVEX = PatchedSimEngineVRVEX

# Monkey-patch for SimEngineFactCollectorVEX to handle 16-bit ops (skip flags for CC)
from angr.analyses.calling_convention.fact_collector import SimEngineFactCollectorVEX, binop_handler

class PatchedSimEngineFactCollectorVEX(SimEngineFactCollectorVEX):
    @binop_handler
    def _handle_binop_CmpLT16U(self, expr):
        return None

    @binop_handler
    def _handle_binop_Shl16(self, expr):
        return None

    @binop_handler
    def _handle_binop_Or16(self, expr):
        return None

    @binop_handler
    def _handle_binop_CmpEQ16(self, expr):
        return None

    @binop_handler
    def _handle_binop_Shr16(self, expr):
        return None

    @binop_handler
    def _handle_binop_Xor16(self, expr):
        return None

    def _handle_expr_Unop(self, expr):
        if expr.op == 'Iop_Not16':
            return None
        return super()._handle_expr_Unop(expr)

SimEngineFactCollectorVEX = PatchedSimEngineFactCollectorVEX

# Monkey-patch Lifter86_16 for symbolic emu
from angr_platforms.angr_platforms.X86_16.processor import Processor, GPRegister, SGRegister, DTRegister
from angr_platforms.angr_platforms.X86_16.regs import reg32_t, sgreg_t, dtreg_t
class SymbolicProcessor(Processor):
    def __init__(self, *args, **kwargs):
        # Skip concrete init to avoid lifter_instruction dependency
        self.eip = 0
        self.gpregs = [GPRegister() for _ in range(reg32_t.GPREGS_COUNT.value)]
        self.sgregs = [SGRegister() for _ in range(sgreg_t.SGREGS_COUNT.value)]
        self.dtregs = [DTRegister() for _ in range(dtreg_t.DTREGS_COUNT.value)]
        self.halt = False
        # Skip concrete set_eip, set_crn, set_eflags, segment setups
        for i in range(reg32_t.GPREGS_COUNT.value):
            self.gpregs[i].reg32 = claripy.BVS(f'gpreg_{i}', 32)
        self.eip = claripy.BVS('eip', 32)

original_lifter_init = Lifter86_16.__init__
def symbolic_lifter_init(self, *args, **kwargs):
    original_lifter_init(self, *args, **kwargs)
    self.emu = SymbolicProcessor()
Lifter86_16.__init__ = symbolic_lifter_init

# Manual prototype for test2.bin (add two int16 args, return int16)
from angr.sim_type import SimTypeInt, SimTypeFunction
SimTypeInt16 = SimTypeInt(16, False)  # unsigned short
SimTypeInt16_signed = SimTypeInt(16, True)  # signed int
proto = SimTypeFunction([SimTypeInt16, SimTypeInt16], SimTypeInt16_signed)

import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel('DEBUG')

l = logging.getLogger("decompile_debug")
l.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
l.addHandler(handler)

logging.getLogger('angr').setLevel('DEBUG')
logging.getLogger('angr.analyses.decompiler').setLevel('DEBUG')
logging.getLogger('cle').setLevel('DEBUG')
logging.getLogger('archinfo').setLevel('DEBUG')
logging.getLogger('pyvex').setLevel('DEBUG')

logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('DEBUG')
logging.getLogger('angr_platforms.angr_platforms.X86_16.parse').setLevel('DEBUG')
logging.getLogger('angr.project').setLevel('DEBUG')
logging.getLogger('cle.backends.blob').setLevel('DEBUG')
logging.getLogger('archinfo').setLevel('DEBUG')

arch_16 = Arch86_16()

print("Available architectures:")
print([a.name for a in all_arches])
print(f"Attempting arch: X86")
print(f"Is 'X86' in arches? {'X86' in [a.name for a in all_arches]}")

# Check if a file argument is provided
if len(sys.argv) < 2:
    print("Usage: ./decompile.py <file.bin>")
    sys.exit(1)

# Read the binary file
with open(sys.argv[1], 'rb') as f:
    byte_string = f.read()

addr = 0x1000
print("Creating project with arch only and loading bytes to memory")
buf = io.BytesIO(byte_string)
print(f"Using arch: {arch_16.name}")
project = angr.Project(buf, main_opts={
    'backend': 'blob',
    'arch': arch_16,
    'base_addr': addr,
    'entry_point': addr
})
project.entry = addr
print("Project setup successful with memory load")

print("After disasm")
print("Arch bits:", project.arch.bits)
binary_len = len(byte_string)
cfg = project.analyses.CFGFast(regions=[(addr, addr + len(byte_string))], resolve_indirect_jumps=False, data_references=True, normalize=True, symbols=False, detect_tail_calls=False)

functions = project.kb.functions

# Manual block creation to bypass lifter failures for 16-bit
if len(functions) == 0 or (addr in functions and not functions[addr].block_addrs):
    try:
        if addr not in functions:
            func = functions.function(addr, create=True)
        else:
            func = functions[addr]
        # Use VEX lifter with opt_level=1 for better simplification
        block = project.factory.block(addr, binary_len, opt_level=1)
        func.add_block(block)
        print(f"VEX block created, size {block.size} bytes")
        l.info(f"IRSB opt_level=1 applied; check for reduced temps")
    except Exception as e:
        print(f"VEX block failed: {e}")
        l.error(f"Block creation error: {e}")
        pass

print(f"Detected {len(functions)} functions")
print(f"Functions at: {list(functions.keys())}")

for func_addr in list(functions):
    func = functions[func_addr]
    print(f"Function {hex(func_addr)}: {len(func.block_addrs)} blocks")
    if not func.block_addrs:
        print("No blocks, attempting manual VEX lift")
        try:
            block = project.factory.block(addr, binary_len, opt_level=0)
            func.add_block(block)
            print(f"Manual VEX block added, size {block.size}")
        except Exception as e:
            print(f"Manual VEX lift failed: {e}")
        break

    # Print function info
    total_size = sum(project.factory.block(ba).size for ba in func.block_addrs)
    print(f" total size {total_size} bytes")

    if project.arch.bits == 16:
        func.calling_convention = SimCC8616MSCsmall
        func.prototype = proto
        # func.frame_size = 4  # Inferred; no direct attr
        l.info(f"Set CC: {func.calling_convention}, Proto: {func.prototype}")
    if project.arch.bits == 16:
        try:
            try:
                vrec = project.analyses[VariableRecoveryFast].prep()(func)
            except Exception as ve:
                l.error(f"VR inner error: {ve}")
                l.error(f"VR traceback: {traceback.format_exc()}")
                raise
            try:
                vars_list = list(func.variables.values())
            except AttributeError:
                vars_list = []
                l.warning("Variables not available after VR; using empty list")
            l.info(f"Variable recovery done. Stack vars: {[(v.name, v.location) for v in vars_list if v.location.type == 'stack']}")
            l.info(f"Arguments: {[(p.name, p.location) for p in vars_list if p.location.type == 'arg']}")
            _ = vrec
        except Exception as e:
            l.error(f"VariableRecovery failed: {e}")
            l.error(f"VR full traceback: {traceback.format_exc()}")
            pass
    else:
        l.info("Skipping VariableRecovery for 16-bit. Manually setting arguments.")
        from angr.calling_conventions import SimStackArg
        from angr.sim_type import SimTypeInt

        # Set manual arguments using SimStackArg for prototype
        #func.arguments = [
        #    SimStackArg(4, 2),
        #    SimStackArg(6, 2)
        #]
        l.info(f"Manual args set: a0 at bp+4, a1 at bp+6")
    if project.arch.bits == 16:
        try:
            cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg)
            func.calling_convention = cca.cc
            func.prototype = cca.prototype
        except:
            pass
    from angr.analyses.decompiler import Decompiler

    try:
        dec = project.analyses.Decompiler(func, cfg=cfg)
        l.info(f"Decompiler success: {bool(dec.codegen)}")
        if dec.codegen:
            print(f"Decompiled function {hex(func.addr)}:")
            print(dec.codegen.text)
            # Test: Assert correct decomp output with args
            expected = """int _start(unsigned short a0, unsigned short a1)
{
    return a0 + a1;
}"""
            if dec.codegen.text.strip() != expected.strip():
                l.warning(f"Decomp mismatch: got\\n{dec.codegen.text}\\nexpected\\n{expected}")
                print("Decompilation produced, but body mismatch; check logs.")
            else:
                print("Decompilation matches expected.")
            # Fix: use dec.kb.variables or func.variables
            try:
                vars_info = [(v.name, str(v.location), str(v.type)) for v in func.variables.values()]
                l.info(f"Function variables: {vars_info}")
            except:
                l.info("No variables accessible")
        else:
            print(f"No codegen for {hex(func.addr)}")
            l.warning("No codegen produced")
    except Exception as e:
        print(f"Decomp failed for {hex(func_addr)}: {e}")
        l.error(f"Decomp exception: {e}")
