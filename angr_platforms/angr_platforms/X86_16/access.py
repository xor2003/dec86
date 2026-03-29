from pyvex.lifting.util.vex_helper import Type
from pyvex.lifting.util import JumpKind

ITY_I8 = Type.int_8
ITY_I16 = Type.int_16
ITY_I32 = Type.int_32

from .hardware import Hardware
from .addressing_helpers import linear_address
from .stack_helpers import pop16, pop32, push16, push32, push_far_return_frame16
from .regs import reg16_t, reg32_t, sgreg_t

# Constants for access modes
MODE_READ = 0
MODE_WRITE = 1
MODE_EXEC = 2


class DataAccess(Hardware):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tlb = []  # Translation Lookaside Buffer

    def set_segment(self, reg, sel):
        self.set_gpreg(reg, sel)

    def get_segment(self, reg):
        return self.get_sgreg(reg)

    #def trans_v2p(self, mode, seg, vaddr):
    #    laddr = self.trans_v2l(mode, seg, vaddr)
    #
    #    paddr = laddr
    #    return paddr


    def convert_ss_vaddr(self, vaddr):
        _, off = self.convert_segoff2vexv(sgreg_t.SS, vaddr)
        ss = self.get_sgreg(sgreg_t.SS).cast_to(ITY_I32)
        return (ss << 4) + off

    def v2p(self, seg, off):
        sg, vaddr = self.convert_segoff2vexv(seg, off)
        return (sg << 4) + vaddr

    def convert_segoff2vexv(self, seg, vaddr):
        if isinstance(seg, sgreg_t):
            sg = self.get_sgreg(seg)
        elif isinstance(seg, int):
            sg = self.constant(seg, ITY_I16)
        else:
            sg = seg
        if not isinstance(vaddr, int):
            vaddr = vaddr.cast_to(ITY_I32)
        sg = sg.cast_to(ITY_I32)
        return sg, vaddr

    def search_tlb(self, vpn):
        if vpn + 1 > len(self.tlb) or self.tlb[vpn] is None:
            return None
        return self.tlb[vpn]

    def cache_tlb(self, vpn, pte):
        if vpn + 1 > len(self.tlb):
            self.tlb.extend([None] * (vpn + 1 - len(self.tlb)))
        self.tlb[vpn] = pte

    def push32(self, value):
        push32(self, value)

    def pop32(self):
        return pop32(self)

    def push16(self, value):
        push16(self, value)

    def pop16(self):
        return pop16(self)

    def read_mem32_seg(self, seg, addr):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            paddr = self.convert_ss_vaddr(addr)
            return self.read_mem32(paddr)
        paddr = self.v2p(seg, addr)
        return self.read_mem32(paddr)

    def read_mem16_seg(self, seg, addr):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            paddr = self.convert_ss_vaddr(addr)
            return self.read_mem16(paddr)
        paddr = self.v2p(seg, addr)
        return self.read_mem16(paddr)

    def read_mem8_seg(self, seg, addr):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            paddr = self.convert_ss_vaddr(addr)
            return self.read_mem8(paddr)
        paddr = self.v2p(seg, addr)
        return self.read_mem8(paddr)

    def write_mem32_seg(self, seg, addr, value):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            paddr = self.convert_ss_vaddr(addr)
            return self.write_mem32(paddr, value)
        paddr = self.v2p(seg, addr)
        self.write_mem32(paddr, value)

    def write_mem16_seg(self, seg, addr, value):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            paddr = self.convert_ss_vaddr(addr)
            return self.write_mem16(paddr, value)
        paddr = self.v2p(seg, addr)
        self.write_mem16(paddr, value)

    def write_mem8_seg(self, seg, addr, value):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            paddr = self.convert_ss_vaddr(addr)
            return self.write_mem8(paddr, value)
        paddr = self.v2p(seg, addr)
        self.write_mem8(paddr, value)

    def get_code8(self, offset):
        assert offset == 0
        return self.bitstream.read("uint:8")

    def get_code16(self, offset):
        assert offset == 0
        return self.bitstream.read("uintle:16")

    def get_code32(self, offset):
        assert offset == 0
        return self.bitstream.read("uintle:32")

    def get_data16(self, seg, addr):
        return self.read_mem16_seg(seg, addr)

    def get_data32(self, seg, addr):
        return self.read_mem32_seg(seg, addr)

    def get_data8(self, seg, addr):
        return self.read_mem8_seg(seg, addr)

    def put_data8(self, seg, addr, value):
        self.write_mem8_seg(seg, addr, value)

    def put_data16(self, seg, addr, value):
        self.write_mem16_seg(seg, addr, value)

    def put_data32(self, seg, addr, value):
        self.write_mem32_seg(seg, addr, value)

    def callf(self, seg, ip, return_ip=None):
        push_far_return_frame16(self, return_ip)
        self.set_sgreg(sgreg_t.CS, seg)
        self.set_gpreg(reg16_t.IP, ip)
        laddr = linear_address(self, seg, ip)
        self.lifter_instruction.jump(None, laddr, jumpkind=JumpKind.Call)

    def jmpf(self, seg, ip):
        self.set_sgreg(sgreg_t.CS, seg)
        self.set_gpreg(reg16_t.IP, ip)
        laddr = linear_address(self, seg, ip)
        self.lifter_instruction.jump(None, laddr, jumpkind=JumpKind.Boring)
