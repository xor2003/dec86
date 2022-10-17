import pprint
import re
from abc import abstractmethod
from copy import deepcopy, copy

import angr
import pyvex
# pip install keystone-engine
# from capstone import *
from archinfo import arch
from pyvex import IRSB, IRTypeEnv
from pyvex.const import U32, U1, U8, U16
from pyvex.data_ref import DataRef
from pyvex.expr import Binop, RdTmp, Const, Get, Unop, IRExpr, Binder, VECRET, GSPTR, GetI, Qop, Triop, Load, ITE, CCall
from pyvex.stmt import IRStmt, NoOp, IMark, AbiHint, Put, PutI, Store, CAS, LLSC, MBE, Dirty, Exit, LoadG, StoreG, WrTmp

from pyvex.lifting import LibVEXLifter, lifters
from cffi import FFI as ffi
import jsonpickle

from archinfo.arch_x86 import ArchX86
from vextest.reprmixin import ReprMixin

arch = ArchX86()
# Serialization
IMark.__repr__ = lambda self: "IMark(addr=self.v.addr, length=self.v._size, delta=0)"
WrTmp.__repr__ = lambda self: f"WrTmp(t{self.tmp},{repr(self.data)})"
RdTmp.__repr__ = lambda self: "RdTmp(t%d)" % self.tmp
Binop.__repr__ = lambda self: f"Binop({repr(self.op)},{repr(self.args)})"
Const.__repr__ = lambda self: "Const(%s)" % repr(self._con)
U1.__repr__ = lambda self: "U1(%d)" % self.value
U8.__repr__ = lambda self: "U8(%d)" % self.value
U16.__repr__ = lambda self: "U16(%d)" % self.value
U32.__repr__ = lambda self: "U32(%d)" % self.value
IRTypeEnv.__repr__ = lambda self: f"IRTypeEnv(self.arch, types={self.types})"
Get.__repr__ = lambda self: f"self.get('{arch.translate_register_name(self.offset)}')"
Put.__repr__ = lambda self: f"self.put('{arch.translate_register_name(self.offset)}',{repr(self.data)})"
IRSB.__repr__ = lambda \
    self: f"IRSB(None, {repr(self.addr)}, self.arch)\nv.statements={repr(self.statements)}\nv.next={repr(self.next)}\n" + \
          f"v.jumpkind={repr(self.jumpkind)}\nv.default_exit_target={repr(self.default_exit_target)}\n" + \
          f"v.data_refs={repr(self.data_refs)}\nv._tyenv={repr(self._tyenv)}\n" + \
          f"v._instructions={repr(self._instructions)}\n" + \
          f"v._instruction_addresses={repr(self._instruction_addresses)}"
for Class in [Unop, IRExpr, Binder, VECRET, GSPTR, GetI, Qop, Triop, Load, ITE, CCall, IRStmt, NoOp, IMark, AbiHint,
              Put, PutI, Store, CAS, LLSC, MBE, Dirty, Exit, LoadG, StoreG]:
    Class.__bases__ += (ReprMixin,)



def assembler(lines, bitness=0) -> bytes:
    import keystone as ks
    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, count = ks_.asm(lines, as_bytes=True)
    return data



class Lifter16:


    @staticmethod
    def render_vex_to_json(vex):
        vexx = copy(vex)
        vexx.arch = None
        json = jsonpickle.encode(vexx, indent=2)
        return json



class MyVex(IRSB):

    def __init__(self, addr=0):
        self.addr = addr
        self.arch = ArchX86()
        self.v = IRSB(None, self.addr, self.arch)
        self.v._tyenv = IRTypeEnv(self.arch)

    def add_tmp(self, size):
        return self.v._tyenv.add(pyvex.expr.int_type_for_size(size))

    def get(self, register):
        ty = pyvex.expr.int_type_for_size(8 * self.v.arch.registers[register][1])
        # ty_int = pyvex.enums.get_int_from_enum(ty)
        return Get(self.v.arch.get_register_offset(register), ty)

    def conv16Uto32(self, source):
        return Unop("Iop_16Uto32", [source])

    def put(self, register, source):
        return Put(source, self.v.arch.get_register_offset(register))

    def load_byte(self, addr):
        return Load("Iend_LE", "Ity_I8", addr)

    def load_word(self, addr):
        return Load("Iend_LE", "Ity_I16", addr)

    def load_dword(self, addr):
        return Load("Iend_LE", "Ity_I32", addr)

    def add(self, size, *args):
        if size not in [8, 16, 32]:
            raise ValueError('Invalid op size %d' % size)
        if len(args) == 1:
            return Unop("Iop_Add%d" % size, args)
        elif len(args) == 2:
            return Binop("Iop_Add%d" % size, args)
        elif len(args) == 3:
            return Triop("Iop_Add%d" % size, args)
        else:
            raise ValueError('Invalid number of args %s' % args)

    def mov(self):
        self.v._size = 5
        '''
        self.v.statements = [
            IMark(self.addr, self.v._size, 0),
            WrTmp(t2, self.get('esp')),
            WrTmp(t1, self.add(32, RdTmp(t2), Const(U32(4)))),
            WrTmp(t4, self.load_word(RdTmp(t1))),
            WrTmp(t3, self.conv16Uto32(RdTmp(t4))),
            self.put('eax', RdTmp(t3))
        ]
        '''
        # self.v=IRSB(None, 0, self.arch)
        t0 = self.add_tmp(32)
        t1 = self.add_tmp(32)
        t2 = self.add_tmp(16)
        t3 = self.add_tmp(32)
        t4 = self.add_tmp(32)  # movzx     eax, word ptr [esp + 4]
        t5 = self.add_tmp(16)  # movzx     eax, word ptr [esp + 4]
        self.v.statements = [IMark(addr=self.v.addr, length=self.v._size, delta=0),
                             WrTmp(t2, self.get('es')),
                             WrTmp(t3, Unop(op='Iop_16Uto32', args=[RdTmp(t2)])),
                             WrTmp(t4, Binop('Iop_Shl32', [RdTmp(t3), Const(U8(4))])),
                             WrTmp(t1, Binop('Iop_Add32', [RdTmp(t4), Const(U32(0x2000))])),
                             WrTmp(t5, Load(end='Iend_LE', ty='Ity_I16', addr=RdTmp(t1))),
                             WrTmp(t0, Unop(op='Iop_16Uto32', args=[RdTmp(t5)])),
                             self.put('eax', RdTmp(t0))]

        self.v.next = Const(U32(self.v.addr + self.v._size))
        self.v.jumpkind = "Ijk_Boring"
        self.v._instructions = 1
        self.v.default_exit_target = self.v.addr + self.v._size
        self.v._instruction_addresses = (self.v.addr,)
        # self.v.data_refs = [DataRef(4, 0, 36864, 2, 0)]

        print(self.v)
        print(repr(self.v))
        # print(Lifter16.render_vex_to_json(self.v))
        return self.v

    def make_temp(self):
        pass


# from keystone import Ks

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
    _16bit_length = len(arch_16.asm(instruction))

    arch_32 = ArchX86()  # get architecture
    # a.bits=16
    # arch_32.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    arch_32.keystone  # init keystone assembler
    arch_32._ks.sym_resolver = resolver  # set resolver
    # a._ks_x86_syntax = 'masm'
    # a._configure_keystone()
    arch_32._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
    addr = 1
    instruction = re.sub(r'\b[cdefgs]s:', '', instruction)
    bytes = arch_32.asm(instruction)
    vex = pyvex.lift(bytes, addr, arch_32)
    assert vex.statements
    vex._size = _16bit_length
    vex.statements[0].len = _16bit_length

    vex.default_exit_target = addr + _16bit_length
    vex.next = pyvex.expr.Const(pyvex.const.U32(addr + _16bit_length))
    return vex

if __name__ == '__main__':

    try:
        import keystone as _keystone
    except ImportError:
        _keystone = None

    # angr.block.DEFAULT_VEX_ENGINE = Lifter16(None)

    # print(pyvex.lift(a.asm('je 3'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,5\nmul ax'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,abcd'), 0, a).pp())
    instruction = 'add ax,abcd'
    instruction = input()
    # instruction = 'mov word ptr es:[di],0x42'
    # instruction = 'inc eax'

    #########
    vex = vexer(instruction)
    print(vex.pp())
    print(repr(vex))

    # print(pyvex.lift(a.asm('jp abcd'), 0, a).pp())
    # print(pyvex.lift(a.asm('clc')+a.asm('add ax,3')+a.asm('adc ax,5')+a.asm('mul ax')+a.asm('clc'), 0, a).pp())
    arch_32 = ArchX86()  # get architecture

    """
    print(1)
    vex1 = pyvex.lift(arch_32.asm('add     eax, dword ptr [esp + 4]'), 0, arch_32)
    #vex1 = pyvex.lift(arch_32.asm('jmp 4'), 0, arch_32)
    print(vex1.pp())

    # print(Lifter16.render_vex_to_json(vex))

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
