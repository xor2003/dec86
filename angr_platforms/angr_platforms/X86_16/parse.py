import logging
import struct
from typing import TYPE_CHECKING

from pyvex.lifting.util.vex_helper import Type
from pyvex.lifting.util import ParseError

if TYPE_CHECKING:
    from .emulator import Emulator
from .instruction import *

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2

logger = logging.getLogger(__name__)

class ParseInstr(X86Instruction):
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        super().__init__(emu, instr, mode32)
        self.emu: Emulator = emu
        self.chk = [InstrFlags()] * MAX_OPCODE
        self.chsz_ad = False

    def parse_prefix(self) -> int:
        chsz = 0
        prefix_len = 0

        while True:
            #code = self.emu.get_code8_(bitstream)
            code = self.emu.bitstream.peek("uint:8")
            match code:
                case 0x26:
                    self.instr.pre_segment = sgreg_t.ES
                case 0x2E:
                    self.instr.pre_segment = sgreg_t.CS
                case 0x36:
                    self.instr.pre_segment = sgreg_t.SS
                case 0x3E:
                    self.instr.pre_segment = sgreg_t.DS
                case 0x64:
                    self.instr.pre_segment = sgreg_t.FS
                case 0x65:
                    self.instr.pre_segment = sgreg_t.GS
                case 0x66:
                    chsz |= CHSZ_OP
                case 0x67:
                    chsz |= CHSZ_AD
                case 0xF2:
                    self.instr.pre_repeat = REPNZ
                case 0xF3:
                    self.instr.pre_repeat = REPZ
                case 0xF0:
                    # LOCK is a valid real-mode prefix. For our current single-core
                    # verifier path it does not change architectural results, so we
                    # keep it as a consumed prefix and let the following opcode lift.
                    pass
                case _:
                    self.instr.prefix_len = prefix_len
                    return chsz

            self.emu.bitstream.read("uint:8")
            self.instr.prefix = code
            prefix_len += 1
            #self.emu.update_eip(1)

    def parse(self) -> None:
        start = self.emu.bitstream.bytepos
        self.parse_opcode()

        opcode = self.instr.opcode
        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100

        if opcode not in self.chk:
            logger.error(
                "Unknown opcode at %08x: %02x, next bytes: %08x",
                self.emu.bitstream.bytepos,
                opcode,
                self.emu.bitstream.peek("uint:32"),
            )
            raise ParseError(f"Unknown opcode {self.emu.bitstream.bytepos:08x}: {opcode:02x}{self.emu.bitstream.peek('uint:32'):08x}")
            #sys.exit(1)
        if self.chk[opcode] & CHK_MODRM:
            self.parse_modrm_sib_disp()

        if self.chk[opcode] & CHK_IMM32:
            self.instr.imm32 = self.emu.get_code32(0)
            #self.emu.update_eip(4)
        if self.chk[opcode] & CHK_IMM16:
            self.instr.imm16 = self.emu.get_code16(0)
            #self.emu.update_eip(2)
        if self.chk[opcode] & CHK_IMM8:
            self.instr.imm8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            #self.emu.update_eip(1)
        if self.chk[opcode] & CHK_PTR16:
            self.instr.ptr16 = self.emu.get_code16(0)
            #self.emu.update_eip(2)

        if self.chk[opcode] & CHK_MOFFS:
            self.parse_moffs()

        if opcode == 0xF6 and self.instr.modrm.reg in (0, 1):  # test
            self.instr.imm8 = self.emu.get_code8(0)
        if opcode == 0xF7 and self.instr.modrm.reg in (0, 1):  # test
            self.instr.imm16 = self.emu.get_code16(0)

        self.instr.size = self.instr.prefix_len + (self.emu.bitstream.bytepos - start)


    def parse_opcode(self) -> None:
        self.instr.opcode = self.emu.get_code8(0)
        #self.emu.update_eip(1)

        # two byte opcode
        if self.instr.opcode == 0x0F:
            self.instr.opcode = (self.instr.opcode << 8) + self.emu.get_code8(0)
            #self.emu.update_eip(1)
        logger.debug(f"opcode: {self.instr.opcode:0x}")

    def parse_modrm_sib_disp(self) -> None:
        modrm = self.emu.get_code8(0)
        self.instr.modrm.mod = modrm >> 6
        self.instr.modrm.reg = (modrm >> 3) & 0b111
        self.instr.modrm.rm = modrm & 0b111
        #self.emu.update_eip(1)

        if self.emu.is_mode32() ^ self.chsz_ad:
            self.parse_modrm32()
        else:
            self.parse_modrm16()

    def parse_modrm32(self) -> None:
        if self.instr.modrm.mod != 3 and self.instr.modrm.rm == 4:
            sib = self.emu.get_code8(0)
            self.instr.sib.scale = sib >> 6
            self.instr.sib.index = (sib >> 3) & 0b111
            self.instr.sib.base = sib & 0b111
            #self.emu.update_eip(1)

        if (
            self.instr.modrm.mod == 2
            or (self.instr.modrm.mod == 0 and self.instr.modrm.rm == 5)
            or (self.instr.modrm.mod == 0 and self.instr.sib.base == 5)
        ):
            self.instr.disp32 = self.emu.get_code32(0)
            #self.emu.update_eip(4)
        elif self.instr.modrm.mod == 1:
            self.instr.disp8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            #self.emu.update_eip(1)

    def parse_modrm16(self) -> None:
        if (self.instr.modrm.mod == 0 and self.instr.modrm.rm == 6) or self.instr.modrm.mod == 2:
            self.instr.disp16 = self.emu.constant(self.emu.get_code16(0), Type.int_16)
            #self.emu.update_eip(2)
        elif self.instr.modrm.mod == 1:
            self.instr.disp8 = self.emu.constant(struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0], Type.int_8)
            #self.emu.update_eip(1)

    def parse_moffs(self) -> None:
        if self.emu.is_mode32() ^ self.chsz_ad:
            self.instr.moffs = self.emu.get_code32(0)
            #self.emu.update_eip(4)
        else:
            self.instr.moffs = self.emu.get_code16(0)
            #self.emu.update_eip(2)
