import sys

from pyvex.lifting.util.vex_helper import Type
from pyvex.expr import Const, Binop, Unop
from pyvex import IRConst

from .addressing_helpers import (
    ResolvedMemoryOperand,
    address_width_bits,
    default_segment_for_modrm16,
    default_segment_for_modrm32,
    resolve_linear_operand,
    signed_displacement,
)
from .regs import reg8_t, reg16_t, reg32_t, sgreg_t

from .instruction import X86Instruction


class ExecInstr(X86Instruction):
    def __init__(self, emu):
        self.instrfuncs = [None] * 0x200  # Initialize with None for all opcodes
        #self.chsz_ad = False

    def exec(self):
        opcode = self.instr.opcode

        if opcode >> 8 == 0x0f:
            opcode = (opcode & 0xff) | 0x0100

        if self.instrfuncs[opcode] is None:
            print(f"not implemented OPCODE 0x{opcode:02x}", file=sys.stderr)
            return False

        self.instrfuncs[opcode]()
        return True

    def set_rm32(self, value):
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(reg32_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(32)
        self.emu.put_data32(operand.segment, operand.offset, value)


    def get_rm32(self):
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(reg32_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(32)
        return self.emu.get_data32(operand.segment, operand.offset)

    def set_r32(self, value):
        self.emu.set_gpreg(reg32_t(self.instr.modrm.reg), value)

    def get_r32(self):
        return self.emu.get_gpreg(reg32_t(self.instr.modrm.reg))

    def set_moffs32(self, value):
        operand = self._resolved_moffs_operand(32)
        self.emu.put_data32(operand.segment, operand.offset, value)

    def get_moffs32(self):
        operand = self._resolved_moffs_operand(32)
        return self.emu.get_data32(operand.segment, operand.offset)

    def set_rm16(self, value):
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(reg16_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(16)
        self.emu.put_data16(operand.segment, operand.offset, value)

    def get_rm16(self):
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(reg16_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(16)
        return self.emu.get_data16(operand.segment, operand.offset)

    def set_r16(self, value):
        self.emu.set_gpreg(reg16_t(self.instr.modrm.reg), value)

    def get_r16(self):
        return self.emu.get_gpreg(reg16_t(self.instr.modrm.reg))

    def set_moffs16(self, value):
        operand = self._resolved_moffs_operand(16)
        self.emu.put_data16(operand.segment, operand.offset, value)

    def get_moffs16(self):
        operand = self._resolved_moffs_operand(16)
        return self.emu.get_data16(operand.segment, operand.offset)

    def set_rm8(self, value):
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(reg8_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(8)
        self.emu.put_data8(operand.segment, operand.offset, value)

    def get_rm8(self):
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(reg8_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(8)
        return self.emu.get_data8(operand.segment, operand.offset)

    def set_r8(self, value):
        self.emu.set_gpreg(reg8_t(self.instr.modrm.reg), value)

    def get_r8(self):
        return self.emu.get_gpreg(reg8_t(self.instr.modrm.reg))

    def set_moffs8(self, value):
        operand = self._resolved_moffs_operand(8)
        self.emu.put_data8(operand.segment, operand.offset, value)

    def get_moffs8(self):
        operand = self._resolved_moffs_operand(8)
        return self.emu.get_data8(operand.segment, operand.offset)

    def get_m(self):
        return self.calc_modrm()

    def _resolved_rm_operand(self, width_bits: int) -> ResolvedMemoryOperand:
        seg, addr = self._resolved_rm_address()
        address_bits = self.instr.address_bits or address_width_bits(self.emu.is_mode32(), self.chsz_ad)
        return resolve_linear_operand(
            self.emu,
            seg,
            addr,
            width_bits,
            address_bits,
        )

    def _resolved_rm_address(self):
        addr = self.calc_modrm()
        seg = self.select_segment()
        return seg, addr

    def _resolved_moffs_operand(self, width_bits: int) -> ResolvedMemoryOperand:
        self.instr.segment = sgreg_t.DS.value
        seg = self.select_segment()
        offset = self.instr.moffs
        address_bits = self.instr.address_bits or address_width_bits(self.emu.is_mode32(), self.chsz_ad)
        return resolve_linear_operand(
            self.emu,
            seg,
            offset,
            width_bits,
            address_bits,
        )

    def set_sreg(self, value):
        self.emu.set_segment(sgreg_t(self.instr.modrm.reg), value)

    def get_sreg(self):
        return self.emu.get_segment(sgreg_t(self.instr.modrm.reg))

    def set_crn(self, value):
        print(f"set CR{self.instr.modrm.reg} = {value:x}")
        self.emu.set_crn(self.instr.modrm.reg, value)

    def get_crn(self):
        return self.emu.get_crn(self.instr.modrm.reg)

    def calc_modrm(self):
        assert self.instr.modrm.mod != 3

        self.instr.segment = sgreg_t.DS.value
        if (self.instr.address_bits or address_width_bits(self.emu.is_mode32(), self.chsz_ad)) == 32:
            return self.calc_modrm32()
        else:
            return self.calc_modrm16()

    def calc_modrm16(self):
        addr = self.emu.constant(0, Type.int_16)
        self.instr.segment = default_segment_for_modrm16(self.instr.modrm.mod, self.instr.modrm.rm).value

        if self.instr.modrm.mod == 1:
            disp8 = signed_displacement(self.instr.disp8, 8)
            addr = addr + self.emu.constant(disp8 & 0xFFFF, Type.int_16)
        elif self.instr.modrm.mod == 2:
            addr = addr + self.emu.constant(self.instr.disp16, Type.int_16)

        rm = self.instr.modrm.rm
        if rm in (0, 1, 7):
            bx = self.emu.get_gpreg(reg16_t.BX)
            addr = addr + bx
        elif rm in (2, 3, 6):
            if self.instr.modrm.mod == 0 and rm == 6:
                addr = addr + self.emu.constant(self.instr.disp16, Type.int_16)
            else:
                bp = self.emu.get_gpreg(reg16_t.BP)
                addr = addr + bp

        if rm < 6:
            if rm % 2:
                di = self.emu.get_gpreg(reg16_t.DI)
                addr = addr + di
            else:
                si = self.emu.get_gpreg(reg16_t.SI)
                addr = addr + si

        return addr

    def calc_modrm32(self):
        addr = 0
        self.instr.segment = default_segment_for_modrm32(self.instr.modrm.mod, self.instr.modrm.rm).value

        if self.instr.modrm.mod == 1:
            addr += self.instr.disp8
        elif self.instr.modrm.mod == 2:
            addr += self.instr.disp32

        rm = self.instr.modrm.rm
        if rm == 4:
            addr += self.calc_sib()
        elif rm == 5:
            if self.instr.modrm.mod == 0:
                addr += self.instr.disp32
            else:
                addr += self.emu.get_gpreg(reg32_t(rm))
        else:
            addr += self.emu.get_gpreg(reg32_t(rm))

        return addr

    def calc_sib(self):
        base = 0

        if self.instr.sib.base == 5 and self.instr.modrm.mod == 0:
            base = self.instr.disp32
        elif self.instr.sib.base == 4:
            if self.instr.sib.scale == 0:
                self.instr.segment = sgreg_t.SS.value
            else:
                print(
                    f"not implemented SIB (base = {self.instr.sib.base}, index = {self.instr.sib.index}, scale = {self.instr.sib.scale})\n",
                    file=sys.stderr,
                )
        else:
            self.instr.segment = default_segment_for_modrm32(self.instr.modrm.mod, self.instr.modrm.rm, self.instr.sib.base).value
            base = self.emu.get_gpreg(reg32_t(self.instr.sib.base))

        return base + self.emu.get_gpreg(reg32_t(self.instr.sib.index)) * (1 << self.instr.sib.scale)
