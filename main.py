import angr
from angr.analyses import CFGFast, VariableRecoveryFast, CallingConventionAnalysis, Decompiler
from archinfo import ArchX86

from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa

import logging

#from angr_platforms.angr_platforms.msp430.arch_msp430 import ArchMSP430

logging.getLogger('angr').setLevel('DEBUG')
logging.getLogger('angr.calling_conventions').setLevel('DEBUG')
logging.getLogger('pyvex.lifting.util').setLevel('DEBUG')
logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('DEBUG')

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

arch_16 = Arch86_16()  # get architecture
#arch_16 = ArchX86()  # get architecture
byte_string = b'\xb8\x03\x04\xc3'
#byte_string = b'\xb8\x03\x04\x00\x00\xc3'
#with open("/home/xor/masm2c/asmTests/t.com", "rb") as f:
#with open("/home/xor/vextest/4093.bin", "rb") as f:
#with open("/home/xor/vextest/1f44.bin", "rb") as f:
#with open("/home/xor/inertia_player/snake.com", "rb") as f:
with open("/home/xor/vextest/22ec.bin", "rb") as f:
        byte_string = f.read()
#byte_string = b"\x8B\x44\x24\x08\x03\x44\x24\x04\xC3" # 32+ return value
#byte_string = b'\x0e\x1f\x83\x06\x11\x022\x83>\x11\x022u~\x83.\x11\x02\x19\x83>\x11\x02\x19ur\x83>\x0f\x02\x00ukf\xb8\x03\x00\x00\x00f\xbb\x02\x00\x00\x00f+\xd8wZf\xb8\x02\x00\x00\x00f\xbb\x03\x00\x00\x00f+\xd8rIf\x83\xfb\x01uCf\x83\xfb\x02w=f\x83\xfb\x00r7f\x83\xfb\x01r1w/f\xb8\xfe\xff\xff\xfff\x83\xf8\xfeu#f\xbb\x02\x00\x00\x00f;\xc3r\x18\xb2c\x80\xeaa\x80\xfa\x02u\x0ef3\xfff\x81\xc7\x80\x11\x00\x00\xb0\x00\xeb\x02\xb0\x01\xb4L\xcd!\x02\x05\x06\x04\x00\x06\x00\t\x00\x0b\x00\x00\x00\xf5\xff\xff\xff\x02\x00\x00\x00\x04\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
project = angr.load_shellcode(byte_string, arch=arch_16, start_offset=0, load_address=0, selfmodifying_code=False, rebase_granularity=0x1000)
print("After load")

block = project.factory.block(project.entry, byte_string=byte_string)
print("Created block")
block.pp()

print("After disasm")
# force_complete_scan=False - because it is mix of code and data
cfg = project.analyses[CFGFast].prep()(force_complete_scan=False, data_references=True, normalize=True)

func = cfg.functions[0]

_ = project.analyses[VariableRecoveryFast].prep()(func)
cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
func.calling_convention = cca.cc
func.prototype = cca.prototype

dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
