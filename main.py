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

if __name__ == '__main__':
    try:
        import capstone as _capstone
    except ImportError:
        _capstone = None

    try:
        import keystone as _keystone
    except ImportError:
        _keystone = None

    a = ArchX86()  # get architecture
    #a.bits=16
    a.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    a.keystone  # init keystone assembler
    a._ks.sym_resolver = resolver  # set resolver
    #a._ks_x86_syntax = 'masm'
    #a._configure_keystone()
    a._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax

    #a.ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
    #print(pyvex.lift(a.asm('je 3'), 0, a).pp())
    #print(pyvex.lift(a.asm('adc ax,5\nmul ax'), 0, a).pp())
    print(pyvex.lift(a.asm('adc ax,abcd'), 0, a).pp())
    #print(pyvex.lift(a.asm('jp abcd'), 0, a).pp())
    #print(pyvex.lift(a.asm('clc')+a.asm('add ax,3')+a.asm('adc ax,5')+a.asm('mul ax')+a.asm('clc'), 0, a).pp())
    #a.bits=32

    #bytes = a.asm('push ebp')+a.asm('mov ebp,esp')+a.asm('mov eax,[ebp+8]')+a.asm('mov ebx,[ebp+0xc]')+a.asm('add ax,bx')+a.asm('pop ebp')+a.asm('ret')
    bytes = a.asm('add ax,bx')+a.asm('ret')
    p = angr.load_shellcode(bytes, a, start_offset=0, load_address=0,support_selfmodifying_code=False)
    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0]

    _ = p.analyses[VariableRecoveryFast].prep()(func)
    cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
    func.calling_convention = cca.cc
    func.prototype = cca.prototype

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
    print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
