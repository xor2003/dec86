from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, cast

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .emu import EmuInstr
from .exec import ExecInstr
from .instruction import *
from .parse import ParseInstr
from .regs import reg8_t, reg16_t, sgreg_t

if TYPE_CHECKING:
    from .emulator import Emulator

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2


import logging

logger = logging.getLogger(__name__)

OpcodeHandler = Callable[..., None]

class InstrBase(ExecInstr, ParseInstr, EmuInstr):
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        super().__init__(emu)
        super(ExecInstr, self).__init__(emu, instr, mode32)  # ParseInstr
        super(ParseInstr, self).__init__(emu, instr, mode32)  # EmuInstr
        self.emu = emu
        self.instrfuncs: dict[int, OpcodeHandler] = {}
        self.chk: dict[int, int] = {}
        self.chsz_ad = False

        self.set_funcflag(0x00, self.add_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x02, self.add_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x04, self.add_al_imm8, CHK_IMM8)
        self.set_funcflag(0x08, self.or_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x0A, self.or_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x0C, self.or_al_imm8, CHK_IMM8)
        self.set_funcflag(0x10, self.adc_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x12, self.adc_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x20, self.and_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x22, self.and_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x24, self.and_al_imm8, CHK_IMM8)
        self.set_funcflag(0x27, self.daa, 0)
        self.set_funcflag(0x28, self.sub_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x2A, self.sub_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x2C, self.sub_al_imm8, CHK_IMM8)
        self.set_funcflag(0x2F, self.das, 0)
        self.set_funcflag(0x30, self.xor_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x32, self.xor_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x34, self.xor_al_imm8, CHK_IMM8)
        self.set_funcflag(0x37, self.aaa, 0)
        self.set_funcflag(0x38, self.cmp_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x3A, self.cmp_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x3C, self.cmp_al_imm8, CHK_IMM8)
        self.set_funcflag(0x3F, self.aas, 0)
        self.set_funcflag(0x70, self.jo_rel8, CHK_IMM8)
        self.set_funcflag(0x71, self.jno_rel8, CHK_IMM8)
        self.set_funcflag(0x72, self.jb_rel8, CHK_IMM8)
        self.set_funcflag(0x73, self.jnb_rel8, CHK_IMM8)
        self.set_funcflag(0x74, self.jz_rel8, CHK_IMM8)
        self.set_funcflag(0x75, self.jnz_rel8, CHK_IMM8)
        self.set_funcflag(0x76, self.jbe_rel8, CHK_IMM8)
        self.set_funcflag(0x77, self.ja_rel8, CHK_IMM8)
        self.set_funcflag(0x78, self.js_rel8, CHK_IMM8)
        self.set_funcflag(0x79, self.jns_rel8, CHK_IMM8)
        self.set_funcflag(0x7A, self.jp_rel8, CHK_IMM8)
        self.set_funcflag(0x7B, self.jnp_rel8, CHK_IMM8)
        self.set_funcflag(0x7C, self.jl_rel8, CHK_IMM8)
        self.set_funcflag(0x7D, self.jnl_rel8, CHK_IMM8)
        self.set_funcflag(0x7E, self.jle_rel8, CHK_IMM8)
        self.set_funcflag(0x7F, self.jnle_rel8, CHK_IMM8)
        self.set_funcflag(0x84, self.test_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x86, self.xchg_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x88, self.mov_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x8A, self.mov_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x8E, self.mov_sreg_rm16, CHK_MODRM)
        self.set_funcflag(0x90, self.nop, 0)
        self.set_funcflag(0x9B, self.wait, 0)
        self.set_funcflag(0x9E, self.sahf, 0)
        self.set_funcflag(0x9F, self.lahf, 0)
        self.set_funcflag(0xA0, self.mov_al_moffs8, CHK_MOFFS)
        self.set_funcflag(0xA2, self.mov_moffs8_al, CHK_MOFFS)
        self.set_funcflag(0xA8, self.test_al_imm8, CHK_IMM8)
        for i in range(8):
            self.set_funcflag(0xB0 + i, self.mov_r8_imm8, CHK_IMM8)
        self.set_funcflag(0xC6, self.mov_rm8_imm8, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xCA, self.retf_imm16, CHK_IMM16)
        self.set_funcflag(0xCB, self.retf, 0)
        self.set_funcflag(0xCC, self.int3, 0)
        self.set_funcflag(0xCD, self.int_imm8, CHK_IMM8)
        self.set_funcflag(0xCF, self.iret, 0)
        self.set_funcflag(0xD0, self.code_d0_d2, CHK_MODRM)
        self.set_funcflag(0xD2, self.code_d0_d2, CHK_MODRM)
        self.set_funcflag(0xD4, self.aam, CHK_IMM8)
        self.set_funcflag(0xD5, self.aad, CHK_IMM8)
        self.set_funcflag(0xD6, self.salc, 0)
        self.set_funcflag(0xD8, self.esc, CHK_MODRM)
        self.set_funcflag(0xD9, self.esc, CHK_MODRM)
        self.set_funcflag(0xDA, self.esc, CHK_MODRM)
        self.set_funcflag(0xDB, self.esc, CHK_MODRM)
        self.set_funcflag(0xDC, self.esc, CHK_MODRM)
        self.set_funcflag(0xDD, self.esc, CHK_MODRM)
        self.set_funcflag(0xDE, self.esc, CHK_MODRM)
        self.set_funcflag(0xDF, self.esc, CHK_MODRM)
        self.set_funcflag(0xE4, self.in_al_imm8, CHK_IMM8)
        self.set_funcflag(0xE6, self.out_imm8_al, CHK_IMM8)
        self.set_funcflag(0xEB, self.jmp, CHK_IMM8)
        self.set_funcflag(0xEC, self.in_al_dx, 0)
        self.set_funcflag(0xEE, self.out_dx_al, 0)
        self.set_funcflag(0xF5, self.cmc, 0)
        self.set_funcflag(0xF8, self.clc, 0)
        self.set_funcflag(0xF9, self.stc, 0)
        self.set_funcflag(0xFA, self.cli, 0)
        self.set_funcflag(0xFB, self.sti, 0)
        self.set_funcflag(0xFC, self.cld, 0)
        self.set_funcflag(0xFD, self.std, 0)
        self.set_funcflag(0xF4, self.hlt, 0)

        self.set_funcflag(0x0F20, self.mov_r32_crn, CHK_MODRM)
        self.set_funcflag(0x0F22, self.mov_crn_r32, CHK_MODRM)
        self.set_funcflag(0x0F90, self.seto_rm8, CHK_MODRM)
        self.set_funcflag(0x0F91, self.setno_rm8, CHK_MODRM)
        self.set_funcflag(0x0F92, self.setb_rm8, CHK_MODRM)
        self.set_funcflag(0x0F93, self.setnb_rm8, CHK_MODRM)
        self.set_funcflag(0x0F94, self.setz_rm8, CHK_MODRM)
        self.set_funcflag(0x0F95, self.setnz_rm8, CHK_MODRM)
        self.set_funcflag(0x0F96, self.setbe_rm8, CHK_MODRM)
        self.set_funcflag(0x0F97, self.seta_rm8, CHK_MODRM)
        self.set_funcflag(0x0F98, self.sets_rm8, CHK_MODRM)
        self.set_funcflag(0x0F99, self.setns_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9A, self.setp_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9B, self.setnp_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9C, self.setl_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9D, self.setnl_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9E, self.setle_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9F, self.setnle_rm8, CHK_MODRM)

        self.set_funcflag(0x80, self.code_80, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0x82, self.code_82, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xC0, self.code_c0, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xF6, self.code_f6, CHK_MODRM)
        self.set_funcflag(0xFE, self.code_fe, CHK_MODRM)

    def _ite_value(self, cond, when_true, when_false):
        expr = self.emu.lifter_instruction.irsb_c.ite(
            cond.cast_to(Type.int_1).rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self.emu._vv(expr)


    def code_d0_d2(self) -> None:
        """
        Handle the x86 Group-2 byte shifts/rotates used by opcodes 0xD0 and 0xD2.

        Keeping this as an explicit dispatch table makes it easier to audit when
        a real sample trips over one of the rarely used `/digit` encodings.
        """

        group2_handler_names = {
            0: "rol_rm8",
            1: "ror_rm8",
            2: "rcl_rm8",
            3: "rcr_rm8",
            4: "shl_rm8",  # SHL
            5: "shr_rm8",
            6: "shl_rm8",  # SAL aliases SHL on x86
            7: "sar_rm8",
        }
        reg = self.instr.modrm.reg
        handler_name = group2_handler_names.get(reg)
        if handler_name is None:
            raise RuntimeError(f"not implemented: 0xd0_d2 /{reg}")
        cast(OpcodeHandler, getattr(self, handler_name))()

    def set_funcflag(self, opcode: int, func: OpcodeHandler, flags: int) -> None:
        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100
        assert opcode < 0x200
        self.instrfuncs[opcode] = func
        self.chk[opcode] = flags

    def add_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 + r8)
        self.emu.update_eflags_add(rm8, r8)

    def adc_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.set_rm8(rm8 + r8 + carry)
        self.emu.update_eflags_adc(rm8, r8, carry)

    def add_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 + rm8)
        self.emu.update_eflags_add(r8, rm8)

    def adc_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.set_r8(r8 + rm8 + carry)
        self.emu.update_eflags_adc(r8, rm8, carry)

    def adc_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, al + self.instr.imm8 + carry)
        self.emu.update_eflags_adc(al, self.instr.imm8, carry)

    def add_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al + self.instr.imm8)
        self.emu.update_eflags_add(al, self.instr.imm8)

    def or_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 | r8)
        self.emu.update_eflags_or(rm8, r8)

    def or_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 | rm8)
        self.emu.update_eflags_or(r8, rm8)

    def or_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al | self.instr.imm8)
        self.emu.update_eflags_or(al, self.instr.imm8)

    def and_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 & r8)
        self.emu.update_eflags_and(rm8, r8)

    def and_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 & rm8)
        self.emu.update_eflags_and(r8, rm8)

    def and_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al & self.instr.imm8)
        self.emu.update_eflags_and(al, self.instr.imm8)

    def sub_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 - r8)
        self.emu.update_eflags_sub(rm8, r8)

    def sub_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 - rm8)
        self.emu.update_eflags_sub(r8, rm8)

    def sub_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al - self.instr.imm8)
        self.emu.update_eflags_sub(al, self.instr.imm8)

    def sbb_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.set_rm8(rm8 - r8 - carry)
        self.emu.update_eflags_sbb(rm8, r8, carry)

    def sbb_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.set_r8(r8 - rm8 - carry)
        self.emu.update_eflags_sbb(r8, rm8, carry)

    def sbb_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, al - self.instr.imm8 - carry)
        self.emu.update_eflags_sbb(al, self.instr.imm8, carry)

    def xor_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 ^ r8)
        self.emu.update_eflags_xor(rm8, r8)

    def xor_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 ^ rm8)
        self.emu.update_eflags_xor(rm8, r8)

    def xor_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al ^ self.instr.imm8)
        self.emu.update_eflags_xor(al, self.instr.imm8)

    def cmp_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.emu.update_eflags_sub(rm8, r8)

    def cmp_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.emu.update_eflags_sub(r8, rm8)

    def cmp_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.update_eflags_sub(al, self.instr.imm8)

    def _rel8_target(self):
        rel = self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16)
        return self.emu.get_gpreg(reg16_t.IP) + rel + self.emu.constant(2, Type.int_16)

    def jo_rel8(self) -> None:
        result = self.emu.is_overflow()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jno_rel8(self) -> None:
        result = self.emu.is_overflow()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~result, ip, JumpKind.Boring)

    def jb_rel8(self) -> None:
        result = self.emu.is_carry()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jnb_rel8(self) -> None:  # jae
        result = self.emu.is_carry()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~result, ip, JumpKind.Boring)

    def jz_rel8(self) -> None:
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(self.emu.is_zero(), ip)

    def jnz_rel8(self) -> None:
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~self.emu.is_zero(), ip)

    def jbe_rel8(self) -> None:
        result = self.emu.is_carry() | self.emu.is_zero()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def ja_rel8(self) -> None:
        result = self.emu.is_carry() | self.emu.is_zero()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~result, ip, JumpKind.Boring)

    def js_rel8(self) -> None:
        result = self.emu.is_sign()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jns_rel8(self) -> None:
        result = self.emu.is_sign()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~result, ip, JumpKind.Boring)

    def jp_rel8(self) -> None:
        result = self.emu.is_parity()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jnp_rel8(self) -> None:
        result = self.emu.is_parity()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~result, ip, JumpKind.Boring)

    def jl_rel8(self) -> None:
        result = self.emu.is_sign() != self.emu.is_overflow()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jnl_rel8(self) -> None:  # jge
        result = self.emu.is_sign() != self.emu.is_overflow()
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(~result, ip, JumpKind.Boring)

    def jle_rel8(self) -> None:
        ip = self._rel8_target()
        cond = self.emu.is_zero() | (self.emu.is_sign() != self.emu.is_overflow())
        self.emu.lifter_instruction.jump(cond, ip)

    def jnle_rel8(self) -> None:
        result = ~self.emu.is_zero() & (self.emu.is_sign() == self.emu.is_overflow())
        ip = self._rel8_target()
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def test_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.emu.update_eflags_and(rm8, r8)

    def xchg_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        if self.instr.modrm.mod == 3:
            self.set_r8(rm8)
            self.set_rm8(r8)
            return

        addr = self.get_m()
        seg = self.select_segment()
        self.set_r8(rm8)
        self.emu.put_data8(seg, addr, r8)

    def mov_rm8_r8(self) -> None:
        r8 = self.get_r8()
        self.set_rm8(r8)

    def mov_r8_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_r8(rm8)

    def mov_sreg_rm16(self) -> None:
        rm16 = self.get_rm16()
        self.set_sreg(rm16)

    def nop(self) -> None:
        pass

    def wait(self) -> None:
        # WAIT only stalls until TEST is asserted; architecturally it is a no-op
        # for the real-mode concrete verifier we are using here.
        self.nop()

    def lahf(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS).cast_to(Type.int_8)
        flags_low = flags & self.emu.constant(0xD5, Type.int_8)
        self.emu.set_gpreg(reg8_t.AH, flags_low | self.emu.constant(0x02, Type.int_8))

    def lohf(self) -> None:
        self.lahf()

    def sahf(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        ah = self.emu.get_gpreg(reg8_t.AH).cast_to(Type.int_16)
        preserved = flags & self.emu.constant(0xFF2A, Type.int_16)
        new_bits = ah & self.emu.constant(0x00D5, Type.int_16)
        self.emu.set_gpreg(reg16_t.FLAGS, preserved | new_bits | self.emu.constant(0x0002, Type.int_16))

    def mov_al_moffs8(self) -> None:
        self.emu.set_gpreg(reg8_t.AL, self.get_moffs8())

    def mov_moffs8_al(self) -> None:
        self.set_moffs8(self.emu.get_gpreg(reg8_t.AL))

    def test_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.update_eflags_and(al, self.instr.imm8)

    def salc(self) -> None:
        value = self._ite_value(
            self.emu.is_carry().cast_to(Type.int_1),
            self.emu.constant(0xFF, Type.int_8),
            self.emu.constant(0x00, Type.int_8),
        )
        self.emu.set_gpreg(reg8_t.AL, value)

    def esc(self) -> None:
        if self.instr.modrm.mod != 3:
            addr = self.get_m()
            seg = self.select_segment()
            self.emu.get_data8(seg, addr)

    def mov_r8_imm8(self) -> None:
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(reg8_t(reg), self.instr.imm8)

    def mov_rm8_imm8(self) -> None:
        self.set_rm8(self.emu.lifter_instruction.constant(self.instr.imm8, Type.int_8))

    def _update_adjust_flags(self, result, *, af=None, cf=None, of=None):
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        low = result.cast_to(Type.int_8)
        if af is not None:
            flags = self.emu.set_flag(flags, 4, af)
        if cf is not None:
            flags = self.emu.set_carry(flags, cf)
        if of is not None:
            flags = self.emu.set_overflow(flags, of)
        flags = self.emu.set_parity(flags, self.emu.chk_parity(low))
        flags = self.emu.set_zero(flags, low == self.emu.constant(0, Type.int_8))
        flags = self.emu.set_sign(flags, low[7])
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def daa(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        cf = self.emu.is_carry()
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1) | af
        high_adjust = (al > self.emu.constant(0x99, Type.int_8)).cast_to(Type.int_1) | cf

        overflow = self._ite_value(
            cf.cast_to(Type.int_1),
            ((al >= self.emu.constant(0x1A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(Type.int_1),
            ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(Type.int_1),
        )

        result = al
        low_added = result + self.emu.constant(0x06, Type.int_8)
        result = self._ite_value(low_adjust.cast_to(Type.int_1), low_added, result)

        high_added = result + self.emu.constant(0x60, Type.int_8)
        result = self._ite_value(high_adjust.cast_to(Type.int_1), high_added, result)
        self.emu.set_gpreg(reg8_t.AL, result)
        self._update_adjust_flags(
            result,
            af=low_adjust.cast_to(Type.int_1),
            cf=high_adjust.cast_to(Type.int_1),
            of=overflow,
        )

    def das(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        cf = self.emu.is_carry()
        old_sign = al[7]

        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1) | af
        high_adjust = (al > self.emu.constant(0x99, Type.int_8)).cast_to(Type.int_1) | cf

        cf_after_low = self._ite_value(
            high_adjust,
            self.emu.constant(1, Type.int_1),
            (al <= self.emu.constant(0x05, Type.int_8)).cast_to(Type.int_1),
        )
        cf_final = self._ite_value(
            low_adjust.cast_to(Type.int_1),
            cf_after_low,
            high_adjust.cast_to(Type.int_1),
        )

        result = al
        result = self._ite_value(high_adjust, result - self.emu.constant(0x60, Type.int_8), result)
        result = self._ite_value(low_adjust, result - self.emu.constant(0x06, Type.int_8), result)
        self.emu.set_gpreg(reg8_t.AL, result)
        overflow = old_sign.cast_to(Type.int_1) & (result[7].cast_to(Type.int_1) ^ self.emu.constant(1, Type.int_1))
        self._update_adjust_flags(
            result,
            af=low_adjust.cast_to(Type.int_1),
            cf=cf_final,
            of=overflow,
        )

    def aaa(self) -> None:
        ax = self.emu.get_gpreg(reg16_t.AX)
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1)
        adjust = low_adjust | af

        result_ax = self._ite_value(adjust, ax + self.emu.constant(0x0106, Type.int_16), ax)
        self.emu.set_gpreg(reg16_t.AX, result_ax)
        new_al = self._ite_value(adjust, al + self.emu.constant(6, Type.int_8), al)
        masked_al = new_al & self.emu.constant(0x0F, Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, masked_al)

        overflow = ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(Type.int_1)
        sign = ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0xF9, Type.int_8))).cast_to(Type.int_1)
        zero = (new_al == self.emu.constant(0, Type.int_8)).cast_to(Type.int_1)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_flag(flags, 4, adjust)
        flags = self.emu.set_carry(flags, adjust)
        flags = self.emu.set_overflow(flags, overflow)
        flags = self.emu.set_sign(flags, sign)
        flags = self.emu.set_zero(flags, zero)
        flags = self.emu.set_parity(flags, self.emu.chk_parity(new_al))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def aas(self) -> None:
        ax = self.emu.get_gpreg(reg16_t.AX)
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1)
        adjust = low_adjust | af

        result_ax = self._ite_value(adjust, ax - self.emu.constant(0x0106, Type.int_16), ax)
        self.emu.set_gpreg(reg16_t.AX, result_ax)
        pre_mask_al = result_ax.cast_to(Type.int_8)
        masked_al = pre_mask_al & self.emu.constant(0x0F, Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, masked_al)

        overflow = self._ite_value(
            low_adjust,
            self.emu.constant(0, Type.int_1),
            self._ite_value(
                af,
                ((al >= self.emu.constant(0x80, Type.int_8)) & (al <= self.emu.constant(0x85, Type.int_8))).cast_to(Type.int_1),
                self.emu.constant(0, Type.int_1),
            ),
        )
        sign = self._ite_value(
            low_adjust,
            (al > self.emu.constant(0x85, Type.int_8)).cast_to(Type.int_1),
            self._ite_value(
                af,
                ((al < self.emu.constant(0x06, Type.int_8)) | (al > self.emu.constant(0x85, Type.int_8))).cast_to(Type.int_1),
                (al >= self.emu.constant(0x80, Type.int_8)).cast_to(Type.int_1),
            ),
        )
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_flag(flags, 4, adjust)
        flags = self.emu.set_carry(flags, adjust)
        flags = self.emu.set_overflow(flags, overflow)
        flags = self.emu.set_sign(flags, sign)
        flags = self.emu.set_zero(flags, (pre_mask_al == self.emu.constant(0, Type.int_8)).cast_to(Type.int_1))
        flags = self.emu.set_parity(flags, self.emu.chk_parity(pre_mask_al))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def aam(self) -> None:
        base = self.emu.constant(self.instr.imm8 & 0xFF, Type.int_8)
        al = self.emu.get_gpreg(reg8_t.AL)
        ah = al // base
        new_al = al % base
        self.emu.set_gpreg(reg8_t.AH, ah)
        self.emu.set_gpreg(reg8_t.AL, new_al)
        self._update_adjust_flags(
            new_al,
            af=self.emu.constant(0, Type.int_1),
            cf=self.emu.constant(0, Type.int_1),
            of=self.emu.constant(0, Type.int_1),
        )

    def aad(self) -> None:
        base = self.emu.constant(self.instr.imm8 & 0xFF, Type.int_8)
        ah = self.emu.get_gpreg(reg8_t.AH)
        al = self.emu.get_gpreg(reg8_t.AL)
        ax = ah.cast_to(Type.int_16) * base.cast_to(Type.int_16) + al.cast_to(Type.int_16)
        new_al = ax.cast_to(Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, new_al)
        self.emu.set_gpreg(reg8_t.AH, self.emu.constant(0, Type.int_8))
        self._update_adjust_flags(
            new_al,
            af=self.emu.constant(0, Type.int_1),
            cf=self.emu.constant(0, Type.int_1),
            of=self.emu.constant(0, Type.int_1),
        )

    def retf_imm16(self) -> None:
        ip = self.emu.pop16()
        seg = self.emu.pop16()
        self.emu.set_gpreg(
            reg16_t.SP,
            self.emu.get_gpreg(reg16_t.SP) + self.emu.constant(self.instr.imm16, Type.int_16),
        )
        self.emu.set_sgreg(sgreg_t.CS, seg)
        self.emu.set_gpreg(reg16_t.IP, ip)
        addr = self.emu.v2p(seg, ip)
        self.emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)

    def retf(self) -> None:
        ip = self.emu.pop16()
        seg = self.emu.pop16()
        self.emu.set_sgreg(sgreg_t.CS, seg)
        self.emu.set_gpreg(reg16_t.IP, ip)
        addr = self.emu.v2p(seg, ip)
        self.emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)


    def int3(self) -> None:
        self.instr.imm8 = 3
        self.int_imm8()

    def int_imm8(self) -> None:
        #self.emu.lifter_instruction.put(self.emu.constant(self.instr.imm8), "ip_at_syscall")
        # Model real-mode interrupts as synthetic call targets so CFG/decompilation
        # can treat them like normal helper functions.
        self.emu.set_gpreg(reg16_t.IP, self.emu.constant(self.instr.imm8, Type.int_16))
        self.emu.lifter_instruction.jump(None, 0xFF000 + self.instr.imm8, JumpKind.Call)

    def iret(self) -> None:
        ip = self.emu.pop16()
        cs = self.emu.pop16()
        flags = self.emu.pop16()
        self.emu.set_gpreg(reg16_t.FLAGS, flags)
        self.emu.set_sgreg(sgreg_t.CS, cs)
        self.emu.set_gpreg(reg16_t.IP, ip)
        addr = self.emu.v2p(cs, ip)
        self.emu.lifter_instruction.jump(None, addr, jumpkind=JumpKind.Ret)

    def in_al_imm8(self) -> None:
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(self.instr.imm8))

    def out_imm8_al(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.out_io8(self.instr.imm8, al)

    def jmp(self) -> None:
        size = self.emu.constant(self.instr.size, Type.int_16)
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16) + size
        self.emu.set_gpreg(reg16_t.IP, ip)
        self.emu.lifter_instruction.jump(None, ip, JumpKind.Boring)

    def in_al_dx(self) -> None:
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(dx))

    def out_dx_al(self) -> None:
        dx = self.emu.get_gpreg(reg16_t.DX)
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.out_io8(dx, al)

    def cmc(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, flags ^ self.emu.constant(0x0001, Type.int_16))

    def clc(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, flags & self.emu.constant(0xFFFE, Type.int_16))

    def stc(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, flags | self.emu.constant(0x0001, Type.int_16))

    def cli(self) -> None:
        self.emu.set_interrupt(False)

    def sti(self) -> None:
        self.emu.set_interrupt(True)

    def cld(self) -> None:
        self.emu.set_direction(False)

    def std(self) -> None:
        self.emu.set_direction(True)

    def hlt(self) -> None:
        if not self.emu.chk_ring(0):
            raise Exception(self.emu.EXP_GP)
        self.emu.do_halt(True)

    def ltr_rm16(self) -> None:
        if not self.emu.chk_ring(0):
            raise Exception(self.emu.EXP_GP)
        rm16 = self.get_rm16()
        self.emu.set_tr(rm16)

    def mov_r32_crn(self) -> None:
        crn = self.get_crn()
        self.emu.set_gpreg(self.instr.modrm.rm, crn)

    def mov_crn_r32(self) -> None:
        if not self.emu.chk_ring(0):
            raise Exception(self.emu.EXP_GP)
        r32 = self.emu.get_gpreg(self.instr.modrm.rm)
        self.set_crn(r32)

    def seto_rm8(self) -> None:
        self.set_rm8(self.emu.is_overflow())

    def setno_rm8(self) -> None:
        self.set_rm8(not self.emu.is_overflow())

    def setb_rm8(self) -> None:
        self.set_rm8(self.emu.is_carry())

    def setnb_rm8(self) -> None:
        self.set_rm8(not self.emu.is_carry())

    def setz_rm8(self) -> None:
        self.set_rm8(self.emu.is_zero())

    def setnz_rm8(self) -> None:
        self.set_rm8(not self.emu.is_zero())

    def setbe_rm8(self) -> None:
        self.set_rm8(self.emu.is_carry() or self.emu.is_zero())

    def seta_rm8(self) -> None:
        self.set_rm8(not (self.emu.is_carry() or self.emu.is_zero()))

    def sets_rm8(self) -> None:
        self.set_rm8(self.emu.is_sign())

    def setns_rm8(self) -> None:
        self.set_rm8(not self.emu.is_sign())

    def setp_rm8(self) -> None:
        self.set_rm8(self.emu.is_parity())

    def setnp_rm8(self) -> None:
        self.set_rm8(not self.emu.is_parity())

    def setl_rm8(self) -> None:
        self.set_rm8(self.emu.is_sign() != self.emu.is_overflow())

    def setnl_rm8(self) -> None:
        self.set_rm8(self.emu.is_sign() == self.emu.is_overflow())

    def setle_rm8(self) -> None:
        self.set_rm8(self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow()))

    def setnle_rm8(self) -> None:
        self.set_rm8(
            self.instr, not self.emu.is_zero() and (self.emu.is_sign() == self.emu.is_overflow()),
        )

    def code_80(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 0:
            self.add_rm8_imm8()
        elif reg == 1:
            self.or_rm8_imm8()
        elif reg == 2:
            self.adc_rm8_imm8()
        elif reg == 3:
            self.sbb_rm8_imm8()
        elif reg == 4:
            self.and_rm8_imm8()
        elif reg == 5:
            self.sub_rm8_imm8()
        elif reg == 6:
            self.xor_rm8_imm8()
        elif reg == 7:
            self.cmp_rm8_imm8()
        else:
            raise RuntimeError(f"not implemented: 0x80 /{reg}")

    def code_82(self) -> None:
        self.code_80()

    def code_c0(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 0:
            self.rol_rm8_imm8()
        elif reg == 1:
            self.ror_rm8_imm8()
        elif reg == 2:
            self.rcl_rm8_imm8()
        elif reg == 3:
            self.rcr_rm8_imm8()
        elif reg == 4:
            self.shl_rm8_imm8()
        elif reg == 5:
            self.shr_rm8_imm8()
        elif reg == 6:
            self.sal_rm8_imm8()
        elif reg == 7:
            self.sar_rm8_imm8()
        else:
            raise RuntimeError(f"not implemented: 0xc0 /{reg}")

    def code_f6(self) -> None:
        reg = self.instr.modrm.reg
        if reg in (0, 1):
            self.test_rm8_imm8()
        elif reg == 2:
            self.not_rm8()
        elif reg == 3:
            self.neg_rm8()
        elif reg == 4:
            self.mul_ax_al_rm8()
        elif reg == 5:
            self.imul_ax_al_rm8()
        elif reg == 6:
            self.div_al_ah_rm8()
        elif reg == 7:
            self.idiv_al_ah_rm8()
        else:
            raise RuntimeError(f"not implemented: 0xf6 /{reg}")

    def code_fe(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 0:
            self.inc_rm8()
        elif reg == 1:
            self.dec_rm8()
        else:
            raise RuntimeError(f"not implemented: 0xf6 /{reg}")

    def _group2_rm8_count(self):
        """
        Resolve the implicit shift/rotate count for opcodes 0xD0 and 0xD2.

        0xD0 uses a fixed count of 1, while 0xD2 uses CL.
        """

        if self.instr.opcode == 0xD2:
            return self.emu.get_gpreg(reg8_t.CL)
        return self.emu.constant(1, Type.int_8)

    def _masked_shift_count8(self, count):
        count_v = self.emu.constant(count, Type.int_8) if isinstance(count, int) else count.cast_to(Type.int_8)
        return count_v & self.emu.constant(0x1F, Type.int_8)

    def _rotate_count8(self, count, modulo):
        return self._masked_shift_count8(count) % self.emu.constant(modulo, Type.int_8)

    def shl_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._masked_shift_count8(self._group2_rm8_count())
        self.set_rm8(rm8 << count)
        self.emu.update_eflags_shl(rm8, count)

    def rol_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._rotate_count8(self._group2_rm8_count(), 8)
        width = self.emu.constant(8, Type.int_8)
        self.set_rm8((rm8 << count) | (rm8 >> (width - count)))
        self.emu.update_eflags_rol(rm8, count)

    def ror_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._rotate_count8(self._group2_rm8_count(), 8)
        width = self.emu.constant(8, Type.int_8)
        self.set_rm8((rm8 >> count) | (rm8 << (width - count)))
        self.emu.update_eflags_ror(rm8, count)

    def rcl_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._group2_rm8_count()
        self._rcl_rm8(rm8, count)

    def rcr_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._group2_rm8_count()
        self._rcr_rm8(rm8, count)

    def shr_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._masked_shift_count8(self._group2_rm8_count())
        self.set_rm8(rm8 >> count)
        self.emu.update_eflags_shr(rm8, count)

    def sar_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._masked_shift_count8(self._group2_rm8_count())
        self.set_rm8(rm8.sar(count))
        self.emu.update_eflags_sar(rm8, count)

    def inc_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 + 1)
        self.emu.update_eflags_inc(rm8)

    def dec_rm8(self) -> None:
        rm8 = self.get_rm8() - 1
        self.set_rm8(rm8)
        self.emu.update_eflags_dec(rm8)

    def add_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 + self.instr.imm8)
        self.emu.update_eflags_add(rm8, self.instr.imm8)

    def or_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 | self.instr.imm8)
        self.emu.update_eflags_or(rm8, self.instr.imm8)

    def adc_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        cf = self.emu.is_carry().cast_to(Type.int_8)
        self.set_rm8(rm8 + self.instr.imm8 + cf)
        self.emu.update_eflags_adc(rm8, self.instr.imm8, cf)

    def sbb_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        cf = self.emu.is_carry().cast_to(Type.int_8)
        self.set_rm8(rm8 - self.instr.imm8 - cf)
        self.emu.update_eflags_sbb(rm8, self.instr.imm8, cf)


    def and_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 & self.instr.imm8)
        self.emu.update_eflags_and(rm8, self.instr.imm8)


    def sub_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 - self.instr.imm8)
        self.emu.update_eflags_sub(rm8, self.instr.imm8)


    def xor_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 ^ self.instr.imm8)
        self.emu.update_eflags_xor(rm8, self.instr.imm8)


    def cmp_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.emu.update_eflags_sub(rm8, self.emu.constant(self.instr.imm8, Type.int_8))


    def shl_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._masked_shift_count8(self.instr.imm8)
        self.set_rm8(rm8 << count)
        self.emu.update_eflags_shl(rm8, count)

    def rol_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._rotate_count8(self.instr.imm8, 8)
        width = self.emu.constant(8, Type.int_8)
        self.set_rm8((rm8 << count) | (rm8 >> (width - count)))
        self.emu.update_eflags_rol(rm8, count)

    def ror_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._rotate_count8(self.instr.imm8, 8)
        width = self.emu.constant(8, Type.int_8)
        self.set_rm8((rm8 >> count) | (rm8 << (width - count)))
        self.emu.update_eflags_ror(rm8, count)

    def rcl_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self.emu.constant(self.instr.imm8, Type.int_8)
        self._rcl_rm8(rm8, count)

    def rcr_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self.emu.constant(self.instr.imm8, Type.int_8)
        self._rcr_rm8(rm8, count)


    def shr_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._masked_shift_count8(self.instr.imm8)
        self.set_rm8(rm8 >> count)
        self.emu.update_eflags_shr(rm8, count)


    def sal_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._masked_shift_count8(self.instr.imm8)
        self.set_rm8(rm8 << count)
        self.emu.update_eflags_shl(rm8, count)


    def sar_rm8_imm8(self) -> None:
        rm8_s = self.get_rm8()
        count = self._masked_shift_count8(self.instr.imm8)
        self.set_rm8(rm8_s.sar(count))
        self.emu.update_eflags_sar(rm8_s, count)

    def _rcl_rm8(self, value, count) -> None:
        size = 8
        count_v = self._masked_shift_count8(count)
        steps = count_v % self.emu.constant(size + 1, Type.int_8)
        result = value
        cf = self.emu.get_carry()

        for step in range(1, size + 1):
            cand_result = value
            cand_cf = self.emu.get_carry()
            for _ in range(step):
                new_cf = (cand_result >> (size - 1)) & 1
                cand_result = ((cand_result << 1) | cand_cf.cast_to(Type.int_8)) & self.emu.constant((1 << size) - 1, Type.int_8)
                cand_cf = new_cf
            use_step = steps == self.emu.constant(step, Type.int_8)
            result = self._ite_value(use_step, cand_result, result)
            cf = self._ite_value(use_step, cand_cf.cast_to(Type.int_1), cf.cast_to(Type.int_1))

        self.set_rm8(result)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, cf)
        one_step = steps == self.emu.constant(1, Type.int_8)
        of = ((result >> (size - 1)) & 1) ^ cf.cast_to(Type.int_8)
        flags = self.emu.set_overflow(flags, self._ite_value(one_step, of.cast_to(Type.int_1), self.emu.get_flag(11)))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def _rcr_rm8(self, value, count) -> None:
        size = 8
        count_v = self._masked_shift_count8(count)
        steps = count_v % self.emu.constant(size + 1, Type.int_8)
        result = value
        cf = self.emu.get_carry()

        for step in range(1, size + 1):
            cand_result = value
            cand_cf = self.emu.get_carry()
            for _ in range(step):
                new_cf = cand_result & 1
                cand_result = (cand_result >> 1) | (cand_cf.cast_to(Type.int_8) << (size - 1))
                cand_cf = new_cf
            use_step = steps == self.emu.constant(step, Type.int_8)
            result = self._ite_value(use_step, cand_result, result)
            cf = self._ite_value(use_step, cand_cf.cast_to(Type.int_1), cf.cast_to(Type.int_1))

        self.set_rm8(result)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, cf)
        one_step = steps == self.emu.constant(1, Type.int_8)
        of = ((result >> (size - 1)) & 1) ^ ((result >> (size - 2)) & 1)
        flags = self.emu.set_overflow(flags, self._ite_value(one_step, of.cast_to(Type.int_1), self.emu.get_flag(11)))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)


    def test_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        imm8 = self.instr.imm8  #self.emu.get_code8(0)
        #self.emu.update_eip(1)
        self.emu.update_eflags_and(rm8, imm8)


    def not_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(~rm8)


    def neg_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(self.emu.constant(0, Type.int_8) - rm8)
        self.emu.update_eflags_sub(self.emu.constant(0, Type.int_8), rm8)


    def mul_ax_al_rm8(self) -> None:
        rm8 = self.get_rm8()
        al = self.emu.get_gpreg(reg8_t.AL)
        val = al.cast_to(Type.int_16) * rm8.cast_to(Type.int_16)
        self.emu.set_gpreg(reg16_t.AX, val)
        self.emu.update_eflags_mul(al, rm8)


    def imul_ax_al_rm8(self) -> None:
        rm8_s = self.get_rm8().signed
        al_s = self.emu.get_gpreg(reg8_t.AL).signed
        val_s = al_s * rm8_s
        self.emu.set_gpreg(reg16_t.AX, val_s)
        self.emu.update_eflags_imul(al_s, rm8_s)


    def div_al_ah_rm8(self) -> None:
        rm8 = self.get_rm8().cast_to(Type.int_16)
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg8_t.AL, ax // rm8)
        self.emu.set_gpreg(reg8_t.AH, ax % rm8)


    def idiv_al_ah_rm8(self) -> None:
        rm8_s = self.get_rm8().cast_to(Type.int_16, signed=True)
        ax_s = self.emu.get_gpreg(reg16_t.AX).signed
        self.emu.set_gpreg(reg8_t.AL, ax_s // rm8_s)
        self.emu.set_gpreg(reg8_t.AH, ax_s % rm8_s)

    def set_chsz_ad(self, ad):
        self.chsz_ad = ad
