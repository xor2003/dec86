from .interrupt import Interrupt
from .processor import Processor
from .regs import reg16_t, sgreg_t
from pyvex.expr import Const, Binop
from pyvex.stmt import Store, Put
from pyvex import IRSB
from pyvex.stmt import WrTmp
from pyvex.expr import RdTmp, Load
from pyvex.lifting.util.vex_helper import Type
from pyvex.lifting.util.syntax_wrapper import VexValue


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

    def _vv(self, value, ty=None):
        if isinstance(value, VexValue):
            return value
        if isinstance(value, int):
            if ty is None:
                raise ValueError("type is required to wrap an integer into a VEX value")
            return self.constant(value, ty)
        return VexValue(self.lifter_instruction, value)

    def push16(self, val):
        sp = self.get_gpreg(reg16_t.SP)
        two = self.constant(2, Type.int_16)
        new_sp = sp - two
        self.set_gpreg(reg16_t.SP, new_sp)
        ss = self.get_sgreg(sgreg_t.SS)
        ss32 = ss.cast_to(Type.int_32)
        four = self.constant(4, Type.int_8)
        base = ss32 << four
        sp32 = new_sp.cast_to(Type.int_32)
        addr = base + sp32
        if isinstance(val, int):
            val = self.constant(val, Type.int_16)
        if self.irsb:
            self.irsb._append_stmt(Store(addr.rdt, val.rdt, self.arch.memory_endness))

    def pop16(self):
        sp = self.get_gpreg(reg16_t.SP)
        ss = self.get_sgreg(sgreg_t.SS)
        ss32 = ss.cast_to(Type.int_32)
        four = self.constant(4, Type.int_8)
        base = ss32 << four
        sp32 = sp.cast_to(Type.int_32)
        addr = base + sp32
        if self.irsb:
            tmp_id = self.tmp_counter
            self.tmp_counter += 1
            self.irsb._append_stmt(WrTmp(tmp_id, Load(self.arch.memory_endness, Type.int_16, addr.rdt)))
            val = VexValue(self.lifter_instruction, RdTmp.get_instance(tmp_id))
        else:
            val = 0  # concrete fallback
        two = self.constant(2, Type.int_16)
        new_sp = sp + two
        self.set_gpreg(reg16_t.SP, new_sp)
        return val

    def get_data16(self, seg, addr):
        ss = self._vv(self.get_sgreg(seg), Type.int_16)
        addr = self._vv(addr, Type.int_16)
        ss32 = ss.cast_to(Type.int_32)
        four = self.constant(4, Type.int_8)
        base = ss32 << four
        addr32 = addr.cast_to(Type.int_32)
        full_addr = base + addr32
        if self.irsb:
            tmp_id = self.tmp_counter
            self.tmp_counter += 1
            self.irsb._append_stmt(WrTmp(tmp_id, Load(self.arch.memory_endness, Type.int_16, full_addr.rdt)))
            return VexValue(self.lifter_instruction, RdTmp.get_instance(tmp_id))
        else:
            return 0  # concrete fallback

    def put_data16(self, seg, addr, val):
        ss = self._vv(self.get_sgreg(seg), Type.int_16)
        addr = self._vv(addr, Type.int_16)
        ss32 = ss.cast_to(Type.int_32)
        four = self.constant(4, Type.int_8)
        base = ss32 << four
        addr32 = addr.cast_to(Type.int_32)
        full_addr = base + addr32
        val = self._vv(val, Type.int_16)
        if self.irsb:
            self.irsb._append_stmt(Store(full_addr.rdt, val.rdt, self.arch.memory_endness))
