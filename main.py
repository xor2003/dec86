import re

import pyvex
# pip install keystone-engine
from archinfo.arch_x86 import ArchX86
import angr
from angr.analyses import (
    VariableRecoveryFast,
    CallingConventionAnalysis,
    CompleteCallingConventionsAnalysis,
    CFGFast,
    Decompiler,
)
#from keystone import Ks

def resolver(symbol, value):
    if symbol == b'abcd':
        value.contents.value = 0x42
        return True
    return False


def vexer(instruction):
    global arch_32
    arch_16 = ArchX86()  # get architecture
    # arch_16.bits=16
    arch_16.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    arch_16.ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
    arch_16.keystone  # init keystone assembler
    arch_16._ks.sym_resolver = resolver  # set resolver
    arch_16._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
    length = len(arch_16.asm(instruction))

    arch_32 = ArchX86()  # get architecture
    # a.bits=16
    #arch_32.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    arch_32.keystone  # init keystone assembler
    arch_32._ks.sym_resolver = resolver  # set resolver
    # a._ks_x86_syntax = 'masm'
    # a._configure_keystone()
    arch_32._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
    addr = 1
    instruction = re.sub(r'\b[cdefgs]s:','',instruction)
    bytes = arch_32.asm(instruction)
    vex = pyvex.lift(bytes, addr, arch_32)
    assert vex.statements
    vex._size = length
    vex.statements[0].len = length

    vex.default_exit_target = addr + length
    vex.next = pyvex.expr.Const(pyvex.const.U32(addr + length))
    return vex


if __name__ == '__main__':
    try:
        import capstone as _capstone
    except ImportError:
        _capstone = None

    try:
        import keystone as _keystone
    except ImportError:
        _keystone = None

    # print(pyvex.lift(a.asm('je 3'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,5\nmul ax'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,abcd'), 0, a).pp())
    #instruction = 'add ax,abcd'
    instruction = 'mov word ptr es:[di],0x42'
    #instruction = 'inc eax'
    vex = vexer(instruction)
    print(vex.pp())
    #exit(0)

    #print(pyvex.lift(a.asm('jp abcd'), 0, a).pp())
    #print(pyvex.lift(a.asm('clc')+a.asm('add ax,3')+a.asm('adc ax,5')+a.asm('mul ax')+a.asm('clc'), 0, a).pp())
    #a.bits=32

    #bytes = a.asm('push ebp')+a.asm('mov ebp,esp')+a.asm('mov eax,[ebp+8]')+a.asm('mov ebx,[ebp+0xc]')+a.asm('add ax,bx')+a.asm('pop ebp')+a.asm('ret')
    bytes = arch_32.asm(
'''
        push    ebp
        mov     ebp, esp
        mov     edx, DWORD PTR [ebp+8]
        mov     eax, DWORD PTR [ebp+0xC]
add ax,abcd
adc ax,dx
        pop     ebp
        ret
''')
    project = angr.load_shellcode(bytes, arch_32, start_offset=0, load_address=0, support_selfmodifying_code=False)
    cfg = project.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0]

    _ = project.analyses[VariableRecoveryFast].prep()(func)
    cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
    func.calling_convention = cca.cc
    func.prototype = cca.prototype

    dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
    assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
    print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
