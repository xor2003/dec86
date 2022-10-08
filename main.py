import re
from abc import abstractmethod
from copy import deepcopy, copy

import angr
import pyvex
# pip install keystone-engine
# from capstone import *
from pyvex import IRSB
from pyvex.expr import Binop, Triop, Unop, RdTmp

from pyvex.lifting import LibVEXLifter, lifters
from cffi import FFI as ffi
import jsonpickle

from pyvex.stmt import WrTmp, Put


def disasm(CODE: bytes, bitness=0, addr: int = 0) -> str:
    import capstone as cs

    md = cs.Cs(cs.CS_ARCH_X86, {16: cs.CS_MODE_16, 32: cs.CS_MODE_32}[bitness])
    for instr in md.disasm(CODE, addr):
        yield instr
    # "0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str))


def asm32(line) -> bytes:
    import keystone as ks
    if line:
        ks_ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        data, count = ks_.asm(line, as_bytes=True)
        if count == 0:
            raise Exception(f"Could not assemble {line}")
        # if count != 1:
        #    raise Exception(f"Could not assemble {line}")
        return data


def assembler(lines, bitness=0) -> bytes:
    import keystone as ks
    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, count = ks_.asm(lines, as_bytes=True)
    return data


data = bytes()
sizes_16bit = []
sizes_32bit = []


class Lifter16(LibVEXLifter):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        """
        self.arch_16 = ArchX86()  # get architecture
        # arch_16.bits=16
        self.arch_16.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
        self.arch_16.ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
        self.arch_16.keystone  # init keystone assembler
        self.arch_16._ks.sym_resolver = resolver  # set resolver
        self.arch_16._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
        """

    def _lift(self,
              data,
              bytes_offset=None,
              max_bytes=None,
              max_inst=None,
              opt_level=1,
              traceflags=None,
              allow_arch_optimizations=None,
              strict_block_end=None,
              skip_stmts=False,
              collect_data_refs=False,
              cross_insn_opt=True,
              load_from_ro_regions=False):
        print(f'Input: {locals()}')

        # asm = asm32()
        # next(asm)

        addr16bit = 0
        addr32bit = 0
        i = 0
        try:
            bytes16 = ffi().unpack(data, len(data))
            raise Exception()
        except:
            vex = super()._lift(data,
                                bytes_offset=bytes_offset,
                                max_bytes=max_bytes,
                                max_inst=max_inst,
                                opt_level=opt_level,
                                traceflags=traceflags,
                                allow_arch_optimizations=allow_arch_optimizations,
                                strict_block_end=strict_block_end,
                                skip_stmts=skip_stmts,
                                collect_data_refs=collect_data_refs,
                                cross_insn_opt=cross_insn_opt,
                                load_from_ro_regions=load_from_ro_regions)
            print(f"As is: {vex}")
            # self.render_vex_to_json(vex)
            return vex

        print("Trying to convert:")
        print(f"bytes: {bytes16}")

        vex = None
        statements = []
        for instr16 in disasm(bytes16, addr=addr16bit, bitness=16):
            print(f"intr16: {instr16.size} {instr16.mnemonic} {instr16.op_str}")
            instr16_size = instr16.size

            bytes32 = asm32(f"{instr16.mnemonic} {instr16.op_str}")
            instr32_size = len(bytes32)
            d = disasm(bytes32, addr=addr32bit, bitness=32)
            instr32 = next(d)
            print(f"intr32: {instr32.size} {instr32.mnemonic} {instr32.op_str}")

            instr32_cdata = ffi().from_buffer(bytearray(bytes32))
            vex = super()._lift(instr32_cdata,
                                bytes_offset=bytes_offset,
                                max_bytes=max_bytes,  # instr32_size,
                                max_inst=1,
                                opt_level=opt_level,
                                traceflags=traceflags,
                                allow_arch_optimizations=allow_arch_optimizations,
                                strict_block_end=strict_block_end,
                                skip_stmts=False,
                                collect_data_refs=collect_data_refs,
                                cross_insn_opt=cross_insn_opt,
                                load_from_ro_regions=load_from_ro_regions)
            assert vex.statements
            print(vex)
            # self.render_vex_to_json(vex)

            addr32bit += instr32_size

            vex._size = instr16_size
            vex.statements[0].len = instr16_size
            vex.default_exit_target = addr16bit + instr16_size
            vex.next = pyvex.expr.Const(pyvex.const.U32(addr16bit + instr16_size))
            # print(vex)
            # self.render_vex_to_json(vex)
            addr16bit += sizes_16bit[i]
            statements.append(vex.statements)
        vex.statements = statements
        vex._size = len(bytes16)
        Lifter16.render_vex_to_json(vex)

        print(f'Output: {vex}')
        return vex

    @staticmethod
    def render_vex_to_json(vex):
        vexx = copy(vex)
        vexx.arch = None
        json = jsonpickle.encode(vexx, indent=2)
        return json


# lifters['X86'] = [Lifter16]

from archinfo.arch_x86 import ArchX86
from angr.analyses import (
    VariableRecoveryFast,
    CallingConventionAnalysis,
    CompleteCallingConventionsAnalysis,
    CFGFast,
    Decompiler,
)


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


def get_instructions_sizes(CODE):
    from keystone import Ks, KS_ARCH_X86, KS_MODE_16, KS_MODE_32, KsError
    sizes16 = []
    sizes32 = []
    for line in CODE.splitlines():
        if line:
            try:
                ks16 = Ks(KS_ARCH_X86, KS_MODE_16)
                # ks16.syntax = KS_OPT_SYNTAX_MASM
                data16, count16 = ks16.asm(line, as_bytes=True)
                if not data16:
                    continue
                assert count16 == 1
                data16_size = len(data16)

                ks32 = Ks(KS_ARCH_X86, KS_MODE_32)
                # ks32.syntax = KS_OPT_SYNTAX_MASM
                data32, count32 = ks32.asm(line, as_bytes=True)
                assert data32
                assert count32 == 1
                data32_size = len(data32)

                if data16_size == 0:
                    continue
                print(f"{CODE} = {data16} (number of statements: {count16})")
                sizes16.append(data16_size)
                sizes32.append(data32_size)
            except KsError as e:
                print("ERROR: %s" % e)
                exit(1)
    return sizes16, sizes32


def merge_vexes(vex1, vex2):
    #c1 = myContext()
    #statement_walker(vex1, 'get_temp', c1)
    #print(c1.results)
    max_temp = len(vex1._tyenv.types) # max(c1.results)

    c2 = myContext()
    statement_walker(vex1, 'get_temp', c2)
    #print(c2.results)

    for i in range(len(c2.results)):
        c2.results[i] += max_temp
    statement_walker(vex2, 'set_temp', c2)
    #vex2._tyenv.types[0:0] = ['Ity_I0'] * (max_temp + 1)
    vex1._tyenv.types += vex1._tyenv.types

    vex1.statements += vex2.statements
    vex1._instructions += vex2._instructions
    vex1.default_exit_target = vex2.default_exit_target
    vex1._instruction_addresses = tuple(list(vex1._instruction_addresses) + [vex1._size + ins_addr  for ins_addr in vex2._instruction_addresses])
    vex1._size += vex2._size
    return vex1



if __name__ == '__main__':
    try:
        import capstone as _capstone
    except ImportError:
        _capstone = None

    try:
        import keystone as _keystone
    except ImportError:
        _keystone = None

    # angr.block.DEFAULT_VEX_ENGINE = Lifter16(None)

    # print(pyvex.lift(a.asm('je 3'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,5\nmul ax'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,abcd'), 0, a).pp())
    instruction = 'add ax,abcd'
    # instruction = 'mov word ptr es:[di],0x42'
    # instruction = 'inc eax'

    #########
    # vex = vexer(instruction)
    # print(vex.pp())
    #########
    # exit(0)

    # print(pyvex.lift(a.asm('jp abcd'), 0, a).pp())
    # print(pyvex.lift(a.asm('clc')+a.asm('add ax,3')+a.asm('adc ax,5')+a.asm('mul ax')+a.asm('clc'), 0, a).pp())
    arch_32 = ArchX86()  # get architecture
    print(1)
    vex1 = pyvex.lift(arch_32.asm('add     eax, dword ptr [esp + 4]'), 0, arch_32)
    print(vex1.pp())


    # print(Lifter16.render_vex_to_json(vex))

    # with open("1.txt", "w") as text_file:
    #    text_file.write(Lifter16.render_vex_to_json(vex))

    class myContext:
        def __init__(self, ):
            self.results = []

    class myRdTmp:
        @staticmethod
        def get_temp(obj, context):
            context.results.append(obj._tmp)

        @staticmethod
        def set_temp(obj, context):
            obj._tmp = context.results.pop(0)


    class myWrTmp:
        @staticmethod
        def get_temp(obj, context):
            context.results.append(obj.tmp)

        @staticmethod
        def set_temp(obj, context):
            obj.tmp = context.results.pop(0)


    def arg_walker(args: IRSB, op, context: myContext):
        if isinstance(args, RdTmp):
            getattr(myRdTmp, op)(args, context)
        if isinstance(args, (Unop, Binop, Triop)):
            for arg in args.args:
                arg_walker(arg, op, context)


    def statement_walker(vex: IRSB, op, context: myContext):
        for stmt in vex.statements:
            if isinstance(stmt, WrTmp):
                getattr(myWrTmp, op)(stmt, context)
                arg_walker(stmt.data, op, context)
            elif isinstance(stmt, Put):
                arg_walker(stmt.data, op, context)


    print(2)
    vex2 = pyvex.lift(arch_32.asm('sub     ebx, dword ptr [esp + 0xc]'), 0, arch_32)
    print(vex2.pp())
    #print(Lifter16.render_vex_to_json(vex2))
    # with open("2.txt", "w") as text_file:
    #    text_file.write(Lifter16.render_vex_to_json(vex))

    vex = merge_vexes(vex1, vex2)
    '''
    c.results = []
    statement_walker(vex, 'get_temp', c)
    print(c.results)
    '''
    print(vex.pp())

    exit(0)

    print(12)
    vex = pyvex.lift(arch_32.asm('''add     eax, dword ptr [esp + 4]
            sub     ebx, dword ptr [esp + 0xc]'''), 0, arch_32)
    # print(vex.pp())
    print(Lifter16.render_vex_to_json(vex))
    # with open("12.txt", "w") as text_file:
    #    text_file.write(Lifter16.render_vex_to_json(vex))
    exit(0)

    # Lifter16.render_vex_to_json(vex)
    # a.bits=32

    # bytes = a.asm('push ebp')+a.asm('mov ebp,esp')+a.asm('mov eax,[ebp+8]')+a.asm('mov ebx,[ebp+0xc]')+a.asm('add ax,bx')+a.asm('pop ebp')+a.asm('ret')
    # ;push     ebp
    # ;mov     ebp, esp

    arch_32 = ArchX86()  # get architecture
    # arch_32.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    arch_32.keystone  # init keystone assembler
    arch_32._ks.sym_resolver = resolver  # set resolver
    arch_32._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax

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
            mov     eax, dword ptr [esp + 4]
            mov     ecx, dword ptr [esp + 8]
            sub ax,42
            sub ax,cx
            movzx eax,ax
            ret
    '''

    CODE = '''
            mov     eax, dword ptr [esp + 4]
        mov     ecx, dword ptr [esp + 8]
        shl     ecx, 4
        mov     eax, dword ptr [eax + ecx]
        ret
        '''

    CODE = '''
            add     ax, word ptr [esi + 4]
        sbb     ax, word ptr [edi + 8]
        '''

    sizes_16bit, sizes_32bit = get_instructions_sizes(CODE)
    bytes_ = assembler(CODE, 32)

    print(bytes_)

    project = angr.load_shellcode(bytes_, arch_32, start_offset=0, load_address=0, support_selfmodifying_code=False)
    cfg = project.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0]

    _ = project.analyses[VariableRecoveryFast].prep()(func)
    cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
    func.calling_convention = cca.cc
    func.prototype = cca.prototype

    dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
    assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
    print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
