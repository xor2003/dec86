import angr
from angr.analyses import CFGFast, VariableRecoveryFast, CallingConventionAnalysis, Decompiler
from angr_platforms.angr_platforms.X86_16.arch_X86_16 import Arch86_16

import logging
logging.getLogger('angr').setLevel('DEBUG')

arch_16 = Arch86_16()  # get architecture
"""
bytes = arch_32.asm('''

        mov     eax, dword ptr [esp + 4]
        mov     ebx, dword ptr [esp + 0xc]
        mov     ecx, dword ptr [esp + 8]
        sub ax,abcd
        ja second
        sub ax,cx
    second:
        movzx eax,ax
        ret
''')

bytes = arch_32.asm('''
        mov     eax, dword ptr [esp + 4]
        mov     ecx, dword ptr [esp + 8]
        shl     ecx, 4
        mov     eax, dword ptr [eax + ecx]
        ret
''')

bytes = arch_32.asm('''

        mov     eax, dword ptr [esp + 4]
        mov     ebx, dword ptr [esp + 0xc]
        mov     ecx, dword ptr [esp + 8]
        sub ax,abcd
        sub ax,cx
        movzx eax,ax
        ret
''')
"""

CODE = '''
    movzx     eax, word ptr [esp + 4]
    movzx     ecx, word ptr [esp + 8]
    shl     ecx, 4
    movzx  ecx,cx
    mov     ax, word ptr [eax + ecx]
    movzx eax,ax
    ret
    '''
CODE = '''
        imul bx
        movzx     eax, word ptr [esp + 4]
        movzx     ecx, word ptr [esp + 8]
        sub ax,42
        sub ax,cx
        movzx eax,ax
        ret
'''

byte_string = b'\xb8\x01\x00\xc3'
project = angr.load_shellcode(byte_string, arch=arch_16, start_offset=0, load_address=0, selfmodifying_code=False, rebase_granularity=0x1000)
print("After load")

block = project.factory.block(project.entry, byte_string=byte_string)
print("Created block")
block.pp()

print("After disasm")
cfg = project.analyses[CFGFast].prep()(data_references=True, normalize=True)

func = cfg.functions[0]

_ = project.analyses[VariableRecoveryFast].prep()(func)
cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
func.calling_convention = cca.cc
func.prototype = cca.prototype

dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
