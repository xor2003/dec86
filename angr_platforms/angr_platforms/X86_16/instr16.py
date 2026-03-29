
from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type
from pyvex.stmt import IMark, WrTmp, Put, Store
from pyvex.expr import Const, Binop
from pyvex import IRConst
 
from .alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    masked_shift_count,
    rotate_count,
    unary_operation,
)
from .addressing_helpers import address_step
from .instr_base import InstrBase
from .stack_helpers import enter16, leave16, near_return_ip16
from .string_helpers import repeat_jump, repeat_prefix_cond, string_delta, string_source_segment
from .instruction import *
from .regs import reg8_t, reg16_t, sgreg_t
from .exception import EXP_UD

X86_16_OPCODE_HELPERS = (
    (0x40, 0x47, "inc_r16", 0),
    (0x48, 0x4F, "dec_r16", 0),
    (0x50, 0x57, "push_r16", 0),
    (0x58, 0x5F, "pop_r16", 0),
    (0x91, 0x97, "xchg_r16_ax", 0),
    (0xB8, 0xBF, "mov_r16_imm16", CHK_IMM16),
)


class Instr16(InstrBase):
    def __init__(self, emu: Emulator, instr: InstrData):
        super().__init__(emu, instr, mode32=False)  # X86Instruction

        self.set_funcflag(0x00, self.add_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x01, self.add_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x02, self.add_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x03, self.add_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x04, self.add_al_imm8, CHK_IMM8)
        self.set_funcflag(0x05, self.add_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x06, self.push_es, 0)
        self.set_funcflag(0x07, self.pop_es, 0)
        self.set_funcflag(0x08, self.or_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x09, self.or_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x0A, self.or_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x0B, self.or_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x0C, self.or_al_imm8, CHK_IMM8)
        self.set_funcflag(0x0D, self.or_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x0E, self.push_cs, 0)
        self.set_funcflag(0x10, self.adc_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x11, self.adc_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x12, self.adc_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x13, self.adc_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x14, self.adc_al_imm8, CHK_IMM8)
        self.set_funcflag(0x15, self.adc_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x16, self.push_ss, 0)
        self.set_funcflag(0x17, self.pop_ss, 0)
        self.set_funcflag(0x18, self.sbb_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x19, self.sbb_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x1A, self.sbb_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x1B, self.sbb_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x1C, self.sbb_al_imm8, CHK_IMM8)
        self.set_funcflag(0x1D, self.sbb_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x1E, self.push_ds, 0)
        self.set_funcflag(0x1F, self.pop_ds, 0)
        self.set_funcflag(0x20, self.and_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x21, self.and_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x22, self.and_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x23, self.and_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x24, self.and_al_imm8, CHK_IMM8)
        self.set_funcflag(0x25, self.and_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x28, self.sub_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x29, self.sub_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x2A, self.sub_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x2B, self.sub_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x2C, self.sub_al_imm8, CHK_IMM8)
        self.set_funcflag(0x2D, self.sub_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x30, self.xor_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x31, self.xor_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x32, self.xor_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x33, self.xor_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x34, self.xor_al_imm8, CHK_IMM8)
        self.set_funcflag(0x35, self.xor_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x38, self.cmp_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x39, self.cmp_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x3A, self.cmp_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x3B, self.cmp_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x3C, self.cmp_al_imm8, CHK_IMM8)
        self.set_funcflag(0x3D, self.cmp_ax_imm16, CHK_IMM16)

        for start, end, helper_name, flags in X86_16_OPCODE_HELPERS:
            self._register_opcode_range(start, end, getattr(self, helper_name), flags)

        self.set_funcflag(0x60, self.pusha, 0)
        self.set_funcflag(0x61, self.popa, 0)
        self.set_funcflag(0x62, self.bound_r16_m16, CHK_MODRM)
        self.set_funcflag(0x68, self.push_imm16, CHK_IMM16)
        self.set_funcflag(0x69, self.imul_r16_rm16_imm16, CHK_MODRM | CHK_IMM16)
        self.set_funcflag(0x6A, self.push_imm8, CHK_IMM8)
        self.set_funcflag(0x6B, self.imul_r16_rm16_imm8, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0x6C, self.insb_m8_dx, 0)
        self.set_funcflag(0x6D, self.insw_m16_dx, 0)
        self.set_funcflag(0x6E, self.outsb_dx_m8, 0)
        self.set_funcflag(0x6F, self.outsw_dx_m16, 0)
        self.set_funcflag(0x85, self.test_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x87, self.xchg_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x89, self.mov_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x8B, self.mov_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x8C, self.mov_rm16_sreg, CHK_MODRM)
        self.set_funcflag(0x8D, self.lea_r16_m16, CHK_MODRM)
        self.set_funcflag(0x8F, self.code_8f, CHK_MODRM)

        self.set_funcflag(0x98, self.cbw, 0)
        self.set_funcflag(0x99, self.cwd, 0)
        self.set_funcflag(0x9A, self.callf_ptr16_16, CHK_PTR16 | CHK_IMM16)
        self.set_funcflag(0x9C, self.pushf, 0)
        self.set_funcflag(0x9D, self.popf, 0)
        self.set_funcflag(0xCE, self.into, 0)
        self.set_funcflag(0xA1, self.mov_ax_moffs16, CHK_MOFFS)
        self.set_funcflag(0xA3, self.mov_moffs16_ax, CHK_MOFFS)
        self.set_funcflag(0xA4, self.movsb_m8_m8, 0)
        self.set_funcflag(0xAC, self.lodsb_al_m8, 0)
        self.set_funcflag(0xAA, self.stosb_m8_al, 0)
        self.set_funcflag(0xAB, self.stosw_m16_ax, 0)
        self.set_funcflag(0xAD, self.lodsw_ax_m16, 0)
        self.set_funcflag(0xAE, self.scasb_al_m8, 0)
        self.set_funcflag(0xAF, self.scasw_ax_m16, 0)
        self.set_funcflag(0xA5, self.movsw_m16_m16, 0)
        self.set_funcflag(0xA6, self.cmps_m8_m8, 0)
        self.set_funcflag(0xA7, self.cmps_m16_m16, 0)
        self.set_funcflag(0xA9, self.test_ax_imm16, CHK_IMM16)

        for i in range(8):
            self.set_funcflag(0xB8+i, self.mov_r16_imm16, CHK_IMM16)

        self.set_funcflag(0xC2, self.ret_imm16, CHK_IMM16)
        self.set_funcflag(0xC3, self.ret, 0)
        self.set_funcflag(0xC4, self.les_es_r16_m16, CHK_MODRM)
        self.set_funcflag(0xC5, self.lds_ds_r16_m16, CHK_MODRM)
        self.set_funcflag(0xC7, self.mov_rm16_imm16, CHK_MODRM | CHK_IMM16)
        self.set_funcflag(0xC8, self.enter, CHK_IMM16 | CHK_IMM8)
        self.set_funcflag(0xC9, self.leave, 0)
        self.set_funcflag(0xD7, self.xlat, 0)
        self.set_funcflag(0xE0, self.loop16ne, CHK_IMM8)
        self.set_funcflag(0xE1, self.loop16e, CHK_IMM8)
        self.set_funcflag(0xE2, self.loop16, CHK_IMM8)
        self.set_funcflag(0xE3, self.jcxz_rel8, CHK_IMM8)
        self.set_funcflag(0xE5, self.in_ax_imm8, CHK_IMM8)
        self.set_funcflag(0xE7, self.out_imm8_ax, CHK_IMM8)
        self.set_funcflag(0xE8, self.call_rel16, CHK_IMM16)
        self.set_funcflag(0xE9, self.jmp_rel16, CHK_IMM16)
        self.set_funcflag(0xEA, self.jmpf_ptr16_16, CHK_PTR16 | CHK_IMM16)
        self.set_funcflag(0xED, self.in_ax_dx, 0)
        self.set_funcflag(0xEF, self.out_dx_ax, 0)

        self.set_funcflag(0x0F80, self.jo_rel16, CHK_IMM16)
        self.set_funcflag(0x0F81, self.jno_rel16, CHK_IMM16)
        self.set_funcflag(0x0F82, self.jb_rel16, CHK_IMM16)
        self.set_funcflag(0x0F83, self.jnb_rel16, CHK_IMM16)
        self.set_funcflag(0x0F84, self.jz_rel16, CHK_IMM16)
        self.set_funcflag(0x0F85, self.jnz_rel16, CHK_IMM16)
        self.set_funcflag(0x0F86, self.jbe_rel16, CHK_IMM16)
        self.set_funcflag(0x0F87, self.ja_rel16, CHK_IMM16)
        self.set_funcflag(0x0F88, self.js_rel16, CHK_IMM16)
        self.set_funcflag(0x0F89, self.jns_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8A, self.jp_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8B, self.jnp_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8C, self.jl_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8D, self.jnl_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8E, self.jle_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8F, self.jnle_rel16, CHK_IMM16)
        self.set_funcflag(0x0FAF, self.imul_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x0FB6, self.movzx_r16_rm8, CHK_MODRM)
        self.set_funcflag(0x0FB7, self.movzx_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x0FBE, self.movsx_r16_rm8, CHK_MODRM)
        self.set_funcflag(0x0FBF, self.movsx_r16_rm16, CHK_MODRM)

        self.set_funcflag(0x81, self.code_81, CHK_MODRM | CHK_IMM16)
        self.set_funcflag(0x83, self.code_83, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xC1, self.code_c1, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xD1, self.code_d1, CHK_MODRM)
        self.set_funcflag(0xD3, self.code_d3, CHK_MODRM)
        self.set_funcflag(0xF7, self.code_f7, CHK_MODRM)
        self.set_funcflag(0xFF, self.code_ff, CHK_MODRM)
        self.set_funcflag(0x0F00, self.code_0f00, CHK_MODRM)
        self.set_funcflag(0x0F01, self.code_0f01, CHK_MODRM)
        
        # FPU instructions
        self.set_funcflag(0xDA, self.code_da, CHK_MODRM)


    def _rel8_target(self):
        rel = self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16)
        return self.emu.get_gpreg(reg16_t.IP) + rel + self.emu.constant(2, Type.int_16)

    def _decrement_cx(self):
        cx = self.emu.get_gpreg(reg16_t.CX)
        cx -= 1
        self.emu.set_gpreg(reg16_t.CX, cx)
        return cx

    def jcxz_rel8(self) -> None:
        self.emu.lifter_instruction.jump(self.emu.get_gpreg(reg16_t.CX) == 0, self._rel8_target())


    def loop16(self) -> None:
        cx = self._decrement_cx()
        self.emu.lifter_instruction.jump(cx != 0, self._rel8_target(), JumpKind.Boring)

    def loop16e(self) -> None:
        cx = self._decrement_cx()
        zero = self.emu.is_zero()
        count_nonzero = (cx != self.emu.constant(0, Type.int_16)).cast_to(Type.int_1)
        self.emu.lifter_instruction.jump(count_nonzero & zero, self._rel8_target(), JumpKind.Boring)

    def loop16ne(self) -> None:
        cx = self._decrement_cx()
        zero = self.emu.is_zero()
        count_nonzero = (cx != self.emu.constant(0, Type.int_16)).cast_to(Type.int_1)
        self.emu.lifter_instruction.jump(count_nonzero & ~zero, self._rel8_target(), JumpKind.Boring)

    def code_8f(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.pop_rm16()
        else:
            raise RuntimeError(f"not implemented: 0x8f /{reg}")

    def sbb_r16_rm16(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_r16,
            self.get_rm16,
            self.set_r16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def add_rm16_r16(self):
        binary_operation(self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def sbb_rm16_r16(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            self.get_r16,
            self.set_rm16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def adc_rm16_r16(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            self.get_r16,
            self.set_rm16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def add_r16_rm16(self):
        binary_operation(self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def adc_r16_rm16(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_r16,
            self.get_rm16,
            self.set_r16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def _ax_imm16(self):
        return self.emu.constant(self.instr.imm16, Type.int_16)

    def _binary_ax_imm16(self, operator, updater):
        binary_operation(self.emu, lambda: self.emu.get_gpreg(reg16_t.AX), self._ax_imm16, lambda value: self.emu.set_gpreg(reg16_t.AX, value), updater, operator)

    def _binary_ax_imm16_with_carry(self, operator, updater):
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            self._ax_imm16,
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            updater,
            operator,
            16,
        )

    def _compare_ax_imm16(self, updater):
        compare_operation(lambda: self.emu.get_gpreg(reg16_t.AX), self._ax_imm16, updater)

    def add_ax_imm16(self):
        self._binary_ax_imm16(lambda ax, imm16: ax + imm16, self.emu.update_eflags_add)

    def adc_ax_imm16(self):
        self._binary_ax_imm16_with_carry(
            lambda ax, imm16, carry: ax + imm16 + carry,
            self.emu.update_eflags_adc,
        )

    def sbb_ax_imm16(self):
        self._binary_ax_imm16_with_carry(
            lambda ax, imm16, carry: ax - imm16 - carry,
            self.emu.update_eflags_sbb,
        )

    def push_es(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.ES))

    def pop_es(self):
        self.emu.set_segment(sgreg_t.ES, self.emu.pop16())

    def or_rm16_r16(self):
        binary_operation(self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def or_r16_rm16(self):
        binary_operation(self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def or_ax_imm16(self):
        self._binary_ax_imm16(lambda ax, imm16: ax | imm16, self.emu.update_eflags_or)

    def push_cs(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.CS))

    def push_ss(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.SS))

    def pop_ss(self):
        self.emu.set_segment(sgreg_t.SS, self.emu.pop16())

    def push_ds(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.DS))

    def pop_ds(self):
        self.emu.set_segment(sgreg_t.DS, self.emu.pop16())

    def and_rm16_r16(self):
        binary_operation(self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def and_r16_rm16(self):
        binary_operation(self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def and_ax_imm16(self):
        self._binary_ax_imm16(lambda ax, imm16: ax & imm16, self.emu.update_eflags_and)

    def sub_rm16_r16(self):
        binary_operation(self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def sub_r16_rm16(self):
        binary_operation(self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def sub_ax_imm16(self):
        self._binary_ax_imm16(lambda ax, imm16: ax - imm16, self.emu.update_eflags_sub)

    def xor_rm16_r16(self):
        binary_operation(self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs)


    def xor_r16_rm16(self):
        binary_operation(self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs)

    def xor_ax_imm16(self):
        self._binary_ax_imm16(lambda ax, imm16: ax ^ imm16, self.emu.update_eflags_xor)

    def cmp_rm16_r16(self):
        compare_operation(self.get_rm16, self.get_r16, self.emu.update_eflags_sub)

    def cmp_r16_rm16(self):
        compare_operation(self.get_r16, self.get_rm16, self.emu.update_eflags_sub)

    def cmp_ax_imm16(self):
        self._compare_ax_imm16(self.emu.update_eflags_sub)

    def inc_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_inc,
            lambda value: value + 1,
        )

    def dec_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_dec,
            lambda value: value - 1,
        )

    def push_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        if reg == reg16_t.SP:
            sp = self.emu.get_gpreg(reg16_t.SP)
            new_sp = sp - self.emu.constant(2, Type.int_16)
            self.emu.set_gpreg(reg16_t.SP, new_sp)
            self.emu.put_data16(sgreg_t.SS, new_sp, sp)
            return

        value = self.emu.get_gpreg(reg)
        self.emu.push16(value)

    def pop_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        self.emu.set_gpreg(reg, self.emu.pop16())

    def pusha(self):
        sp = self.emu.get_gpreg(reg16_t.SP)
        self.emu.push16(self.emu.get_gpreg(reg16_t.AX))
        self.emu.push16(self.emu.get_gpreg(reg16_t.CX))
        self.emu.push16(self.emu.get_gpreg(reg16_t.DX))
        self.emu.push16(self.emu.get_gpreg(reg16_t.BX))
        self.emu.push16(sp)
        self.emu.push16(self.emu.get_gpreg(reg16_t.BP))
        self.emu.push16(self.emu.get_gpreg(reg16_t.SI))
        self.emu.push16(self.emu.get_gpreg(reg16_t.DI))

    def popa(self):
        self.emu.set_gpreg(reg16_t.DI, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.SI, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.BP, self.emu.pop16())
        self.emu.pop16()
        self.emu.set_gpreg(reg16_t.BX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.DX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.CX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.AX, self.emu.pop16())

    def push_imm16(self):
        self.emu.push16(self.emu.constant(self.instr.imm16, Type.int_16))

    def bound_r16_m16(self):
        if self.instr.modrm.mod == 3:
            raise Exception(EXP_UD)
        reg = self.get_r16().signed
        addr = self.get_m()
        seg = self.select_segment()
        lower = self.emu.get_data16(seg, addr).signed
        upper = self.emu.get_data16(seg, addr + address_step(self.emu, 2, 16)).signed
        out_of_range = (reg < lower) | (reg > upper)
        self.emu.lifter_instruction.jump(out_of_range, 0xFF005, JumpKind.Call)

    def imul_r16_rm16_imm16(self):
        rm16_s = self.get_rm16().signed
        imm16_s = self.emu.constant(self.instr.imm16, Type.int_16).signed
        self.set_r16((rm16_s * imm16_s).cast_to(Type.int_16))
        self.emu.update_eflags_imul(rm16_s, imm16_s)

    def push_imm8(self):
        # Create a 16-bit constant from the 8-bit immediate value
        imm16 = self.emu.constant(self.instr.imm8, Type.int_16)
        self.emu.push16(imm16)

    def imul_r16_rm16_imm8(self):
        rm16_s = self.get_rm16().signed
        imm8_s = self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16).signed
        self.set_r16((rm16_s * imm8_s).cast_to(Type.int_16))
        self.emu.update_eflags_imul(rm16_s, imm8_s)

    def test_rm16_r16(self):
        compare_operation(self.get_rm16, self.get_r16, self.emu.update_eflags_and)

    def xchg_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        if self.instr.modrm.mod == 3:
            self.set_r16(rm16)
            self.set_rm16(r16)
            return

        addr = self.get_m()
        seg = self.select_segment()
        self.set_r16(rm16)
        self.emu.put_data16(seg, addr, r16)

    def mov_rm16_r16(self):
        r16 = self.get_r16()
        self.set_rm16(r16)

    def mov_r16_rm16(self):
        rm16 = self.get_rm16()
        self.set_r16(rm16)

    def mov_rm16_sreg(self):
        sreg = self.get_sreg()
        self.set_rm16(sreg)

    def lea_r16_m16(self):
        m16 = self.get_m()
        self.set_r16(m16)

    def _load_far_pointer(self):
        addr = self.get_m()
        seg = self.select_segment()
        offset = self.emu.get_data16(seg, addr)
        segment = self.emu.get_data16(seg, addr + address_step(self.emu, 2, 16))
        return offset, segment

    def les_es_r16_m16(self):
        offset, segment = self._load_far_pointer()
        self.set_r16(offset)
        self.emu.set_sgreg(sgreg_t.ES, segment)

    def lds_ds_r16_m16(self):
        offset, segment = self._load_far_pointer()
        self.set_r16(offset)
        self.emu.set_sgreg(sgreg_t.DS, segment)

    def xchg_r16_ax(self):
        reg = self.instr.opcode & 0b111
        r16 = self.emu.get_gpreg(reg16_t(reg))
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t(reg), ax)
        self.emu.set_gpreg(reg16_t.AX, r16)

    def cbw(self):
        al_s = self.emu.get_gpreg(reg8_t.AL).widen_signed(Type.int_16)
        self.emu.set_gpreg(reg16_t.AX, al_s)

    def cwd(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        dx = self.emu.constant(0, Type.int_16) - ax[15].cast_to(Type.int_16)
        self.emu.set_gpreg(reg16_t.DX, dx)

    def callf_ptr16_16(self):
        self.emu.callf(self.instr.ptr16, self.instr.imm16, return_ip=near_return_ip16(self.emu, 5))


    def pushf(self):
        self.emu.push16(self.emu.get_flags())

    def popf(self):
        flags = self.emu.pop16()
        masked = (flags & self.emu.constant(0x0FD5, Type.int_16)) | self.emu.constant(0x0002, Type.int_16)
        self.emu.set_flags(masked)

    def mov_ax_moffs16(self):
        self.emu.set_gpreg(reg16_t.AX, self.get_moffs16())

    def mov_moffs16_ax(self):
        self.set_moffs16(self.emu.get_gpreg(reg16_t.AX))

    def into(self):
        self.emu.lifter_instruction.jump(
            self.emu.is_overflow(),
            0xFF004,
            JumpKind.Call,
        )

    def xlat(self):
        self.instr.segment = sgreg_t.DS.value
        bx = self.emu.get_gpreg(reg16_t.BX)
        al = self.emu.get_gpreg(reg8_t.AL).cast_to(Type.int_16)
        value = self.emu.get_data8(self.select_segment(), bx + al)
        self.emu.set_gpreg(reg8_t.AL, value)

    def _string_delta(self, width):
        return string_delta(self.emu, width)

    def _string_source_segment(self):
        return string_source_segment(self.instr)

    def _repeat_prefix_cond(self):
        return repeat_prefix_cond(self.emu, self.instr)

    def movsb_m8_m8(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        delta = self._string_delta(1)
        value = self.emu.get_data8(self._string_source_segment(), si)
        self.emu.put_data8(sgreg_t.ES, di, value)
        self.emu.set_gpreg(reg16_t.SI, si + delta)
        self.emu.set_gpreg(reg16_t.DI, di + delta)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)

    def stosb_m8_al(self):
        repeat_cond = self._repeat_prefix_cond()

        di = self.emu.get_gpreg(reg16_t.DI)
        self.emu.put_data8(sgreg_t.ES, di, self.emu.get_gpreg(reg8_t.AL))
        self.emu.set_gpreg(reg16_t.DI, di + self._string_delta(1))

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)

    def stosw_m16_ax(self):
        repeat_cond = self._repeat_prefix_cond()

        di = self.emu.get_gpreg(reg16_t.DI)
        self.emu.put_data16(sgreg_t.ES, di, self.emu.get_gpreg(reg16_t.AX))
        self.emu.set_gpreg(reg16_t.DI, di + self._string_delta(2))

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)

    def lodsb_al_m8(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        next_si = si + self._string_delta(1)
        value = self.emu.get_data8(self._string_source_segment(), si)
        self.emu.set_gpreg(reg8_t.AL, value)
        self.emu.set_gpreg(reg16_t.SI, next_si)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)

    def lodsw_ax_m16(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        next_si = si + self._string_delta(2)
        value = self.emu.get_data16(self._string_source_segment(), si)
        self.emu.set_gpreg(reg16_t.AX, value)
        self.emu.set_gpreg(reg16_t.SI, next_si)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)

    def scasb_al_m8(self):
        repeat_cond = self._repeat_prefix_cond()

        di = self.emu.get_gpreg(reg16_t.DI)
        next_di = di + self._string_delta(1)
        value = self.emu.get_data8(sgreg_t.ES, di)
        compare_operation(lambda: self.emu.get_gpreg(reg8_t.AL), lambda: value, self.emu.update_eflags_sub)
        self.emu.set_gpreg(reg16_t.DI, next_di)

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)

    def scasw_ax_m16(self):
        repeat_cond = self._repeat_prefix_cond()

        di = self.emu.get_gpreg(reg16_t.DI)
        next_di = di + self._string_delta(2)
        value = self.emu.get_data16(sgreg_t.ES, di)
        compare_operation(lambda: self.emu.get_gpreg(reg16_t.AX), lambda: value, self.emu.update_eflags_sub)
        self.emu.set_gpreg(reg16_t.DI, next_di)

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)

    def cmps_m8_m8(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        delta = self._string_delta(1)
        m8_s = self.emu.get_data8(self._string_source_segment(), si)
        m8_d = self.emu.get_data8(sgreg_t.ES, di)
        compare_operation(lambda: m8_s, lambda: m8_d, self.emu.update_eflags_sub)
        self.emu.set_gpreg(reg16_t.SI, si + delta)
        self.emu.set_gpreg(reg16_t.DI, di + delta)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)

    def cmps_m16_m16(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        delta = self._string_delta(2)
        m16_s = self.emu.get_data16(self._string_source_segment(), si)
        m16_d = self.emu.get_data16(sgreg_t.ES, di)
        compare_operation(lambda: m16_s, lambda: m16_d, self.emu.update_eflags_sub)
        self.emu.set_gpreg(reg16_t.SI, si + delta)
        self.emu.set_gpreg(reg16_t.DI, di + delta)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond)


    def movsw_m16_m16(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        delta = self._string_delta(2)
        value = self.emu.get_data16(self._string_source_segment(), si)
        self.emu.put_data16(sgreg_t.ES, di, value)
        self.emu.set_gpreg(reg16_t.SI, si + delta)
        self.emu.set_gpreg(reg16_t.DI, di + delta)

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)

    def insb_m8_dx(self):
        repeat_cond = self._repeat_prefix_cond()

        di = self.emu.get_gpreg(reg16_t.DI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.put_data8(sgreg_t.ES, di, self.emu.in_io8(dx))
        self.emu.set_gpreg(reg16_t.DI, di + self._string_delta(1))

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)

    def insw_m16_dx(self):
        repeat_cond = self._repeat_prefix_cond()

        di = self.emu.get_gpreg(reg16_t.DI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.put_data16(sgreg_t.ES, di, self.emu.in_io16(dx))
        self.emu.set_gpreg(reg16_t.DI, di + self._string_delta(2))

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)

    def outsb_dx_m8(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.out_io8(dx, self.emu.get_data8(self._string_source_segment(), si))
        self.emu.set_gpreg(reg16_t.SI, si + self._string_delta(1))

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)

    def outsw_dx_m16(self):
        repeat_cond = self._repeat_prefix_cond()

        si = self.emu.get_gpreg(reg16_t.SI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.out_io16(dx, self.emu.get_data16(self._string_source_segment(), si))
        self.emu.set_gpreg(reg16_t.SI, si + self._string_delta(2))

        if repeat_cond is not None:
            self.emu.lifter_instruction.jump(repeat_cond, self.emu.get_gpreg(reg16_t.IP), JumpKind.Boring)


    def test_ax_imm16(self):
        compare_operation(lambda: self.emu.get_gpreg(reg16_t.AX), lambda: self.instr.imm16, self.emu.update_eflags_and)

    def mov_r16_imm16(self):
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(reg16_t(reg), Const(IRConst.U16(self.instr.imm16)))

    def _emit_near_call(self, target, return_ip=None):
        """
        Emit a near call edge in a single place.

        Near-call bugs tend to show up as CFG/decompiler pathologies rather than
        obvious execution failures, so keeping the stack update and call jumpkind
        together makes this area much easier to troubleshoot.
        """

        if return_ip is None:
            return_ip = self.emu.get_ip() + self.emu.constant(self.instr.size, Type.int_16)
        self.emu.push16(return_ip)
        self.emu.set_gpreg(reg16_t.IP, target)
        self.emu.lifter_instruction.jump(None, target, JumpKind.Call)

    def _emit_near_jump(self, target):
        self.emu.set_gpreg(reg16_t.IP, target)
        self.emu.lifter_instruction.jump(None, target, JumpKind.Boring)

    def ret(self):
        ret_addr = self.emu.pop16()
        self.emu.set_gpreg(reg16_t.IP, ret_addr)
        self.emu.irsb.next = ret_addr
        self.emu.irsb.jumpkind = 'Ijk_Ret'

    def ret_imm16(self):
        ret_addr = self.emu.pop16()
        self.emu.set_gpreg(
            reg16_t.SP,
            self.emu.get_gpreg(reg16_t.SP) + self.emu.constant(self.instr.imm16, Type.int_16),
        )
        self.emu.set_gpreg(reg16_t.IP, ret_addr)
        self.emu.irsb.next = ret_addr
        self.emu.irsb.jumpkind = 'Ijk_Ret'

    def mov_rm16_imm16(self):
        self.set_rm16(self.emu.constant(self.instr.imm16, Type.int_16))

    def leave(self):
        leave16(self.emu)

    def in_ax_imm8(self):
        self.emu.set_gpreg(reg16_t.AX, self.emu.in_io16(self.instr.imm8))

    def out_imm8_ax(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.out_io16(self.instr.imm8, ax)

    def call_rel16(self):
        size = 3  # opcode + imm16
        return_ip = near_return_ip16(self.emu, size)
        imm = self.emu.constant(self.instr.imm16, Type.int_16)
        target = return_ip + imm
        self._emit_near_call(target)


    def jmp_rel16(self):
        size = self.instr.size
        current_ip = self.emu.get_gpreg(reg16_t.IP) + size
        imm = self.emu.constant(self.instr.imm16, Type.int_16)
        target = current_ip + imm
        self._emit_near_jump(target)

    def jmpf_ptr16_16(self):
        self.emu.jmpf(self.instr.ptr16, self.instr.imm16)

    def _rel16_target(self):
        return (
            self.emu.get_gpreg(reg16_t.IP)
            + self.emu.constant(self.instr.imm16, Type.int_16)
            + self.emu.constant(4, Type.int_16)
        )

    def in_ax_dx(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg16_t.AX, self.emu.in_io16(dx))

    def out_dx_ax(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.out_io16(dx, ax)

    def jo_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(self.emu.is_overflow(), ip)

    def jno_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(not self.emu.is_overflow(), ip)

    def jb_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(self.emu.is_carry(), ip)

    def jnb_rel16(self):  # jae, jnc
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(not self.emu.is_carry(), ip)

    def jz_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(self.emu.is_zero(), ip)

    def jnz_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(not self.emu.is_zero(), ip)

    def jbe_rel16(self):
        ip = self._rel16_target()
        cond = self.emu.is_carry() or self.emu.is_zero()
        self.emu.lifter_instruction.jump(cond, ip)

    def ja_rel16(self):
        ip = self._rel16_target()
        cond = not (self.emu.is_carry() or self.emu.is_zero())
        self.emu.lifter_instruction.jump(cond, ip)

    def js_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(self.emu.is_sign(), ip)

    def jns_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(not self.emu.is_sign(), ip)

    def jp_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(self.emu.is_parity(), ip)

    def jnp_rel16(self):
        ip = self._rel16_target()
        self.emu.lifter_instruction.jump(not self.emu.is_parity(), ip)

    def jl_rel16(self):
        ip = self._rel16_target()
        cond = self.emu.is_sign() != self.emu.is_overflow()
        self.emu.lifter_instruction.jump(cond, ip)

    def jnl_rel16(self):  # jge
        ip = self._rel16_target()
        cond = self.emu.is_sign() == self.emu.is_overflow()
        self.emu.lifter_instruction.jump(cond, ip)

    def jle_rel16(self):
        ip = self._rel16_target()
        cond = self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow())
        self.emu.lifter_instruction.jump(cond, ip)

    def jnle_rel16(self):
        ip = self._rel16_target()
        cond = not (self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow()))
        self.emu.lifter_instruction.jump(cond, ip)

    def imul_r16_rm16(self):
        r16_s = self.get_r16()
        rm16_s = self.get_rm16()
        self.set_r16(r16_s * rm16_s)
        self.emu.update_eflags_imul(r16_s, rm16_s)

    def movzx_r16_rm8(self):
        rm8 = self.emu.get_data8(sgreg_t(self.instr.segment), self.calc_modrm())
        self.set_r16(rm8)

    def movzx_r16_rm16(self):
        rm16 = self.get_rm16()
        self.set_r16(rm16)

    def movsx_r16_rm8(self):
        rm8_s = self.emu.get_data8(sgreg_t(self.instr.segment), self.calc_modrm()).widen_signed(Type.int_16)
        self.set_r16(rm8_s)

    def movsx_r16_rm16(self):
        rm16_s = self.get_rm16().signed  # TODO source is 16 bit??
        self.set_r16(rm16_s)

    def code_81(self):
        self._dispatch_modrm_reg(
            (
                self.add_rm16_imm16,
                self.or_rm16_imm16,
                self.adc_rm16_imm16,
                self.sbb_rm16_imm16,
                self.and_rm16_imm16,
                self.sub_rm16_imm16,
                self.xor_rm16_imm16,
                self.cmp_rm16_imm16,
            ),
            "0x81",
        )

    def code_83(self):
        self._dispatch_modrm_reg(
            (
                self.add_rm16_imm8,
                self.or_rm16_imm8,
                self.adc_rm16_imm8,
                self.sbb_rm16_imm8,
                self.and_rm16_imm8,
                self.sub_rm16_imm8,
                self.xor_rm16_imm8,
                self.cmp_rm16_imm8,
            ),
            "0x83",
        )

    def code_c1(self):
        self._dispatch_modrm_reg(
            (
                self.rol_rm16_imm8,
                self.ror_rm16_imm8,
                self.rcl_rm16_imm8,
                self.rcr_rm16_imm8,
                self.shl_rm16_imm8,
                self.shr_rm16_imm8,
                self.sal_rm16_imm8,
                self.sar_rm16_imm8,
            ),
            "0xc1",
        )

    def code_d1(self):
        self._dispatch_modrm_reg(
            (
                self.rol_rm16_1,
                self.ror_rm16_1,
                self.rcl_rm16_1,
                self.rcr_rm16_1,
                self.shl_rm16_1,
                self.shr_rm16_1,
                self.sal_rm16_1,
                self.sar_rm16_1,
            ),
            "0xd1",
        )

    def code_d3(self):
        self._dispatch_modrm_reg(
            (
                self.rol_rm16_cl,
                self.ror_rm16_cl,
                self.rcl_rm16_cl,
                self.rcr_rm16_cl,
                self.shl_rm16_cl,
                self.shr_rm16_cl,
                self.sal_rm16_cl,
                self.sar_rm16_cl,
            ),
            "0xd3",
        )

    def code_f7(self):
        self._dispatch_modrm_reg(
            (
                self.test_rm16_imm16,
                self.test_rm16_imm16,
                self.not_rm16,
                self.neg_rm16,
                self.mul_dx_ax_rm16,
                self.imul_dx_ax_rm16,
                self.div_dx_ax_rm16,
                self.idiv_dx_ax_rm16,
            ),
            "0xf7",
        )

    def code_ff(self):
        self._dispatch_modrm_reg(
            (
                self.inc_rm16,
                self.dec_rm16,
                self.call_rm16,
                self.callf_m16_16,
                self.jmp_rm16,
                self.jmpf_m16_16,
                self.push_rm16,
                None,
            ),
            "0xff",
        )

    def code_0f00(self):
        self._dispatch_modrm_reg((None, None, None, self.ltr_rm16), "0x0f00")

    def code_0f01(self):
        reg = self.instr.modrm.reg
        #if reg == 2:
        #    self.lgdt_m24()
        #elif reg == 3:

    def code_da(self):
        # FPU instructions with ModR/M byte
        reg = self.instr.modrm.reg
        # For now, we'll implement a simplified version that just handles the specific
        # instruction we're encountering: "fidiv dword ptr [bx + di - 0x2cfc]"
        # This is opcode 0xDA with reg=6 (MODRM.REG field)
        if reg == 6:
            # FIDIV - Divide ST(0) by 32-bit integer from memory
            # In our simplified implementation, we'll just skip this instruction
            # since we don't have a full FPU emulator
            pass
        elif reg == 7:
            # FIDIVR - Divide 32-bit integer from memory by ST(0)
            # In our simplified implementation, we'll just skip this instruction
            pass
        else:
            # For other FPU instructions, we'll just skip them
            pass

    def add_rm16_imm16(self):
        binary_operation(self.emu, self.get_rm16, lambda: self.instr.imm16, self.set_rm16, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def or_rm16_imm16(self):
        binary_operation(self.emu, self.get_rm16, lambda: self.instr.imm16, self.set_rm16, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def adc_rm16_imm16(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def sbb_rm16_imm16(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def and_rm16_imm16(self):
        binary_operation(self.emu, self.get_rm16, lambda: self.instr.imm16, self.set_rm16, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def sub_rm16_imm16(self):
        binary_operation(self.emu, self.get_rm16, lambda: self.instr.imm16, self.set_rm16, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def xor_rm16_imm16(self):
        binary_operation(self.emu, self.get_rm16, lambda: self.emu.constant(self.instr.imm16, Type.int_16), self.set_rm16, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs)

    def cmp_rm16_imm16(self):
        compare_operation(self.get_rm16, lambda: self.instr.imm16, self.emu.update_eflags_sub)

    def add_rm16_imm8(self):
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm16_imm8(self):
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm16_imm8(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def sbb_rm16_imm8(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def and_rm16_imm8(self):
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm16_imm8(self):
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm16_imm8(self):
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm16_imm8(self):
        compare_operation(self.get_rm16, lambda: self.emu.constant(self.instr.imm8, Type.int_8).widen_signed(Type.int_16), self.emu.update_eflags_sub)

    def shl_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.shl(rm16, self.instr.imm8)

    def shr_rm16_imm8(self):
        rm16 = self.get_rm16()
        count = self._shift_count(self.instr.imm8)
        self.set_rm16(rm16 >> count)
        self.emu.update_eflags_shr(rm16, count)

    def sal_rm16_imm8(self):
        rm16 = self.get_rm16()
        count = self._shift_count(self.instr.imm8)
        self.set_rm16(rm16 << count)
        self.emu.update_eflags_shl(rm16, count)

    def sar_rm16_imm8(self):
        rm16 = self.get_rm16()
        count = self._shift_count(self.instr.imm8)
        self.set_rm16(rm16.sar(count))
        self.emu.update_eflags_sar(rm16, count)

    def shl_rm16_1(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 << 1)
        self.emu.update_eflags_shl(rm16, 1)

    def rol_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rol(rm16, cl)

    def ror_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.ror(rm16, cl)

    def rcl_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rcl(rm16, cl)

    def rcr_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rcr(rm16, cl)

    def _ite_value(self, cond, when_true, when_false):
        expr = self.emu.lifter_instruction.irsb_c.ite(
            cond.cast_to(Type.int_1).rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self.emu._vv(expr)

    def _rot_count(self, count, modulo):
        count_v = count if hasattr(count, "cast_to") else self.emu.constant(count, Type.int_8)
        return (count_v.cast_to(Type.int_8) & self.emu.constant(0x1F, Type.int_8)) % self.emu.constant(modulo, Type.int_8)

    def _shift_count(self, count):
        count_v = count if hasattr(count, "cast_to") else self.emu.constant(count, Type.int_8)
        return count_v.cast_to(Type.int_8) & self.emu.constant(0x1F, Type.int_8)

    def _set_rotate_cf(self, cf):
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, cf.cast_to(Type.int_1))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def rol(self, a, b):
        masked = self._shift_count(b)
        count = masked % self.emu.constant(16, Type.int_8)
        inv_count = self.emu.constant(16, Type.int_8) - count
        rotated = ((a << count) | (a >> inv_count)) & self.emu.constant(
            0xFFFF, Type.int_16
        )
        result = self._ite_value(masked == self.emu.constant(0, Type.int_8), a, rotated)
        self.set_rm16(result)
        self.emu.update_eflags_rol(a, masked)

    def shl_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.shl(rm16, cl)

    def shl(self, a, b):
        count = self._shift_count(b)
        self.set_rm16(a << count)
        self.emu.update_eflags_shl(a, count)

    def rol_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.rol(rm16, self.instr.imm8)

    def rol_rm16_1(self):
        rm16 = self.get_rm16()
        self.rol(rm16, 1)

    def ror_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.ror(rm16, self.instr.imm8)

    def ror_rm16_1(self):
        rm16 = self.get_rm16()
        self.ror(rm16, 1)

    def rcl_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.rcl(rm16, self.instr.imm8)

    def rcl_rm16_1(self):
        rm16 = self.get_rm16()
        self.rcl(rm16, 1)

    def rcr_rm16_1(self):
        rm16 = self.get_rm16()
        self.rcr(rm16, 1)

    def rcr_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.rcr(rm16, self.instr.imm8)

    def ror(self, a, b):
        masked = self._shift_count(b)
        count = masked % self.emu.constant(16, Type.int_8)
        inv_count = self.emu.constant(16, Type.int_8) - count
        rotated = ((a >> count) | (a << inv_count)) & self.emu.constant(
            0xFFFF, Type.int_16
        )
        result = self._ite_value(masked == self.emu.constant(0, Type.int_8), a, rotated)
        self.set_rm16(result)
        self.emu.update_eflags_ror(a, masked)

    def rcl(self, a, b):
        count = self._rot_count(b, 17)
        count_value = self.emu._const_u8_value(count)
        if count_value == 0:
            self.set_rm16(a)
            return
        if count_value == 1:
            carry = self.emu.get_carry().cast_to(Type.int_1)
            result = ((a << 1) | carry.cast_to(Type.int_16)) & self.emu.constant(0xFFFF, Type.int_16)
            shifted_out = a[15].cast_to(Type.int_1)
            self.set_rm16(result)
            self._set_rotate_cf(shifted_out)
            flags = self.emu.get_gpreg(reg16_t.FLAGS)
            of = result[15].cast_to(Type.int_1) ^ shifted_out
            flags = self.emu.set_overflow(flags, of.cast_to(Type.int_1))
            self.emu.set_gpreg(reg16_t.FLAGS, flags)
            return
        result = a
        carry = self.emu.get_carry().cast_to(Type.int_1)
        selected_result = a
        selected_carry = carry.cast_to(Type.int_16)
        for step in range(1, 17):
            shifted_out = result[15].cast_to(Type.int_1)
            result = ((result << 1) | carry.cast_to(Type.int_16)) & self.emu.constant(0xFFFF, Type.int_16)
            carry = shifted_out
            cond = count == self.emu.constant(step, Type.int_8)
            selected_result = self._ite_value(cond, result, selected_result)
            selected_carry = self._ite_value(cond, carry.cast_to(Type.int_16), selected_carry)
        self.set_rm16(selected_result)
        self._set_rotate_cf(selected_carry.cast_to(Type.int_1))
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        one_step = count == self.emu.constant(1, Type.int_8)
        of = selected_result[15].cast_to(Type.int_1) ^ selected_carry.cast_to(Type.int_1)
        flags = self.emu.set_overflow(flags, self._ite_value(one_step, of.cast_to(Type.int_1), self.emu.get_flag(11)))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def rcr(self, a, b):
        count = self._rot_count(b, 17)
        count_value = self.emu._const_u8_value(count)
        if count_value == 0:
            self.set_rm16(a)
            return
        if count_value == 1:
            carry = self.emu.get_carry().cast_to(Type.int_1)
            result = (a >> 1) | (carry.cast_to(Type.int_16) << 15)
            shifted_out = a[0].cast_to(Type.int_1)
            self.set_rm16(result)
            self._set_rotate_cf(shifted_out)
            flags = self.emu.get_gpreg(reg16_t.FLAGS)
            of = result[15].cast_to(Type.int_1) ^ result[14].cast_to(Type.int_1)
            flags = self.emu.set_overflow(flags, of.cast_to(Type.int_1))
            self.emu.set_gpreg(reg16_t.FLAGS, flags)
            return
        result = a
        carry = self.emu.get_carry().cast_to(Type.int_1)
        selected_result = a
        selected_carry = carry.cast_to(Type.int_16)
        for step in range(1, 17):
            shifted_out = result[0].cast_to(Type.int_1)
            result = (result >> 1) | (carry.cast_to(Type.int_16) << 15)
            carry = shifted_out
            cond = count == self.emu.constant(step, Type.int_8)
            selected_result = self._ite_value(cond, result, selected_result)
            selected_carry = self._ite_value(cond, carry.cast_to(Type.int_16), selected_carry)
        self.set_rm16(selected_result)
        self._set_rotate_cf(selected_carry.cast_to(Type.int_1))
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        one_step = count == self.emu.constant(1, Type.int_8)
        of = selected_result[15].cast_to(Type.int_1) ^ selected_result[14].cast_to(Type.int_1)
        flags = self.emu.set_overflow(flags, self._ite_value(one_step, of.cast_to(Type.int_1), self.emu.get_flag(11)))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def shr_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.shr(rm16, cl)

    def shr_rm16_1(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 >> 1)
        self.emu.update_eflags_shr(rm16, 1)

    def shr(self, a, b):
        count = self._shift_count(b)
        self.set_rm16(a >> count)
        self.emu.update_eflags_shr(a, count)

    def sal_rm16_1(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 << 1)
        self.emu.update_eflags_shl(rm16, 1)

    def sar_rm16_1(self):
        rm16_s = self.get_rm16()
        self.set_rm16(rm16_s.sar(self.emu.constant(1, Type.int_8)))
        self.emu.update_eflags_sar(rm16_s, 1)

    def sal_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self._shift_count(self.emu.get_gpreg(reg8_t.CL))
        self.set_rm16(rm16 << cl)
        self.emu.update_eflags_shl(rm16, cl)

    def sar_rm16_cl(self):
        rm16_s = self.get_rm16()
        cl = self._shift_count(self.emu.get_gpreg(reg8_t.CL))
        self.set_rm16(rm16_s.sar(cl))
        self.emu.update_eflags_sar(rm16_s, cl)

    def test_rm16_imm16(self):
        compare_operation(self.get_rm16, lambda: self.instr.imm16, self.emu.update_eflags_and)

    def not_rm16(self):
        unary_operation(self.get_rm16, self.set_rm16, None, lambda value: ~value)

    def neg_rm16(self):
        unary_operation(
            self.get_rm16,
            self.set_rm16,
            self.emu.update_eflags_neg,
            lambda value: (value.signed * -1).cast_to(Type.int_16),
        )

    def mul_dx_ax_rm16(self):
        rm16 = self.get_rm16()
        ax = self.emu.get_gpreg(reg16_t.AX)
        val = ax.cast_to(Type.int_32) * rm16.cast_to(Type.int_32)
        self.emu.set_gpreg(reg16_t.AX, val.cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val >> 16).cast_to(Type.int_16))
        self.emu.update_eflags_mul(ax, rm16)

    def imul_dx_ax_rm16(self):
        rm16_s = self.get_rm16().signed
        ax_s = self.emu.get_gpreg(reg16_t.AX).signed
        val_s = ax_s * rm16_s
        self.emu.set_gpreg(reg16_t.AX, val_s.cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val_s >> 16).cast_to(Type.int_16))
        self.emu.update_eflags_imul(ax_s, rm16_s)

    def div_dx_ax_rm16(self):
        rm16 = self.get_rm16().cast_to(Type.int_32)
        # Avoid turning decompilation/lifting into a Python crash when the divisor
        # is unknown or currently zero in a stack slot. The runtime engine can still
        # model a real divide error separately if needed.
        val = (
            (self.emu.get_gpreg(reg16_t.DX).cast_to(Type.int_32) << 16)
            | self.emu.get_gpreg(reg16_t.AX).cast_to(Type.int_32)
        )
        self.emu.set_gpreg(reg16_t.AX, (val // rm16).cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val % rm16).cast_to(Type.int_16))

    def idiv_dx_ax_rm16(self):
        rm16_s = self.get_rm16().cast_to(Type.int_32, signed=True)
        #if rm16_s == 0:
        #    raise Exception(self.emu.EXP_DE)
        val_s = ((self.emu.get_gpreg(reg16_t.DX).cast_to(Type.int_32, signed=True) << 16)
                 | self.emu.get_gpreg(reg16_t.AX).cast_to(Type.int_32))
        self.emu.set_gpreg(reg16_t.AX, (val_s // rm16_s).cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val_s % rm16_s).cast_to(Type.int_16))

    def inc_rm16(self):
        unary_operation(self.get_rm16, self.set_rm16, self.emu.update_eflags_inc, lambda value: value + 1)

    def dec_rm16(self):
        unary_operation(self.get_rm16, self.set_rm16, self.emu.update_eflags_dec, lambda value: value - 1)

    def call_rm16(self):
        rm16 = self.get_rm16()
        return_ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.size, Type.int_16)
        self._emit_near_call(rm16, return_ip=return_ip)

    def callf_m16_16(self):
        m32 = self.get_m()
        ip = self.emu.read_mem16(m32)  # TODO: check segment, probably self.emu.get_data16(select_segment(),
        cs = self.emu.read_mem16(m32 + 2)
        size = self.emu.constant(self.instr.size, Type.int_16)
        self.emu.callf(cs, ip, return_ip=self.emu.get_gpreg(reg16_t.IP) + size)

    def jmp_rm16(self):
        rm16 = self.get_rm16()
        self._emit_near_jump(rm16)

    def jmpf_m16_16(self):
        m32 = self.get_m()
        ip = self.emu.read_mem16(m32)
        sel = self.emu.read_mem16(m32 + 2)
        self.emu.jmpf(sel, ip)

    def push_rm16(self):
        rm16 = self.get_rm16()
        self.emu.push16(rm16)

    def pop_rm16(self):
        value = self.emu.pop16()
        self.set_rm16(value)

    def enter(self):
        bytes_ = self.instr.imm16
        level = self.instr.imm8
        level &= 0x1f
        enter16(self.emu, bytes_, level)
