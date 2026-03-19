from .interrupt import Interrupt
from .processor import Processor
from .regs import reg16_t, sgreg_t
from pyvex.expr import Const, Binop
from pyvex.stmt import Store, Put
from pyvex import IRSB
from pyvex.stmt import WrTmp
from pyvex.expr import RdTmp, Load
from pyvex.lifting.util.vex_helper import Type


class Emulator(Interrupt):
    def __init__(self, arch, lifter=None):
        Processor.__init__(self)
        Interrupt.__init__(self)
        self.arch = arch
        self.lifter = lifter
        self.irsb = lifter.irsb if lifter else None
        self.vex_offsets = {r.name.lower(): r.vex_offset for r in arch.register_list if hasattr(r, 'vex_offset')}
        self.regs = {}
        self.tmp_counter = 0

    def push16(self, val):
        sp = self.get_gpreg(reg16_t.SP)
        two = self.constant(2, Type.int_16)
        new_sp = Binop('Iop_Sub16', sp, two)
        self.set_gpreg(reg16_t.SP, new_sp)
        ss = self.get_sgreg(sgreg_t.SS)
        ss32 = Binop('Iop_Zext16to32', ss)
        four = self.constant(4, Type.int_8)
        base = Binop('Iop_Shl32', ss32, four)
        sp32 = Binop('Iop_Zext16to32', new_sp)
        addr = Binop('Iop_Add32', base, sp32)
        if self.irsb:
            self.irsb._append_stmt(Store(self.arch.memory_endness, addr, val))

    def pop16(self):
        sp = self.get_gpreg(reg16_t.SP)
        ss = self.get_sgreg(sgreg_t.SS)
        ss32 = Binop('Iop_Zext16to32', ss)
        four = self.constant(4, Type.int_8)
        base = Binop('Iop_Shl32', ss32, four)
        sp32 = Binop('Iop_Zext16to32', sp)
        addr = Binop('Iop_Add32', base, sp32)
        if self.irsb:
            tmp_id = self.tmp_counter
            self.tmp_counter += 1
            self.irsb._append_stmt(WrTmp(tmp_id, Load(self.arch.memory_endness, addr, 3)))
            val = RdTmp(tmp_id)
        else:
            val = 0  # concrete fallback
        two = self.constant(2, Type.int_16)
        new_sp = Binop('Iop_Add16', sp, two)
        self.set_gpreg(reg16_t.SP, new_sp)
        return val

    def get_data16(self, seg, addr):
        ss = self.get_sgreg(seg)
        ss32 = Binop('Iop_Zext16to32', ss)
        four = self.constant(4, Type.int_8)
        base = Binop('Iop_Shl32', ss32, four)
        addr32 = Binop('Iop_Zext16to32', addr)
        full_addr = Binop('Iop_Add32', base, addr32)
        if self.irsb:
            tmp_id = self.tmp_counter
            self.tmp_counter += 1
            self.irsb._append_stmt(WrTmp(tmp_id, Load(self.arch.memory_endness, full_addr, 3)))
            return RdTmp(tmp_id)
        else:
            return 0  # concrete fallback

    def put_data16(self, seg, addr, val):
        ss = self.get_sgreg(seg)
        ss32 = Binop('Iop_Zext16to32', ss)
        four = self.constant(4, Type.int_8)
        base = Binop('Iop_Shl32', ss32, four)
        addr32 = Binop('Iop_Zext16to32', addr)
        full_addr = Binop('Iop_Add32', base, addr32)
        if self.irsb:
            self.irsb._append_stmt(Store(self.arch.memory_endness, full_addr, val))
