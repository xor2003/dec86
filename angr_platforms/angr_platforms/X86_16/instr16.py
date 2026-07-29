"""Layer: Frontend/runtime.

Responsibility: implement 16-bit opcode lifting and emulator-side instruction behavior.
Forbidden: decompiler postprocess repair, source/COD-backed semantics, or validation gating.
"""

from __future__ import annotations

from pyvex import IRConst
from pyvex.expr import Const
from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .addressing_helpers import (
    load_far_pointer,
    load_resolved_operand,
    load_word_pair16,
    resolve_linear_operand,
    store_resolved_operand,
)
from .alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    rotate_through_carry_left_state,
    rotate_through_carry_right_state,
    unary_operation,
)
from .emulator import Emulator
from .exception import EXP_UD
from .exec import OpcodeExecHandler
from .instr_base import InstrBase, VexExpr, _vex_expr
from .instruction import CHK_IMM8, CHK_IMM16, CHK_MODRM, CHK_MOFFS, CHK_PTR16, InstrData, InstrFlags
from .jcc_condition import _consume_last_condition_branch_8616
from .regs import coerce_reg16_t, reg8_t, reg16_t, sgreg_t
from .stack_helpers import (
    branch_rel8,
    branch_rel16,
    emit_far_call16,
    emit_far_jump16,
    emit_near_call16,
    emit_near_jump16,
    enter16,
    far_return_ip16,
    leave16,
    loop_rel8,
    near_relative_target16,
    pop16,
    pop16_register,
    pop_all16,
    pop_flags16,
    pop_segment16,
    push16_register,
    push_all16,
    push_flags16,
    push_immediate16,
    push_segment16,
    return_near16,
)
from .string_helpers import (
    repeat_jump,
    repeat_prefix_cond,
    string_advance_indices,
    string_compare_values,
    string_load,
    string_source_segment,
    string_store,
)

X86_16_OPCODE_HELPERS: tuple[tuple[int, int, str, int], ...] = (
    (0x40, 0x47, "inc_r16", 0),
    (0x48, 0x4F, "dec_r16", 0),
    (0x50, 0x57, "push_r16", 0),
    (0x58, 0x5F, "pop_r16", 0),
    (0x91, 0x97, "xchg_r16_ax", 0),
    (0xB8, 0xBF, "mov_r16_imm16", CHK_IMM16),
)


class Instr16(InstrBase):
    """Implement operand-size-16 instruction effects for the x86 frontend."""

    _opcode_template_instrfuncs: list[OpcodeExecHandler | None] | None = None
    _opcode_template_chk: list[int | InstrFlags] | None = None

    def __init__(self, emu: Emulator, instr: InstrData) -> None:
        """Initialize 16-bit opcode handlers for one decoded instruction."""
        super().__init__(emu, instr, mode32=False)  # X86Instruction
        cls = type(self)
        template_funcs = cls._opcode_template_instrfuncs
        template_chk = cls._opcode_template_chk
        if template_funcs is not None and template_chk is not None:
            self.instrfuncs = template_funcs.copy()
            self.chk = template_chk.copy()
            return
        sf = self.set_funcflag

        sf(0x00, self.add_rm8_r8, CHK_MODRM)
        sf(0x01, self.add_rm16_r16, CHK_MODRM)
        sf(0x02, self.add_r8_rm8, CHK_MODRM)
        sf(0x03, self.add_r16_rm16, CHK_MODRM)
        sf(0x04, self.add_al_imm8, CHK_IMM8)
        sf(0x05, self.add_ax_imm16, CHK_IMM16)
        sf(0x06, self.push_es, 0)
        sf(0x07, self.pop_es, 0)
        sf(0x08, self.or_rm8_r8, CHK_MODRM)
        sf(0x09, self.or_rm16_r16, CHK_MODRM)
        sf(0x0A, self.or_r8_rm8, CHK_MODRM)
        sf(0x0B, self.or_r16_rm16, CHK_MODRM)
        sf(0x0C, self.or_al_imm8, CHK_IMM8)
        sf(0x0D, self.or_ax_imm16, CHK_IMM16)
        sf(0x0E, self.push_cs, 0)
        sf(0x10, self.adc_rm8_r8, CHK_MODRM)
        sf(0x11, self.adc_rm16_r16, CHK_MODRM)
        sf(0x12, self.adc_r8_rm8, CHK_MODRM)
        sf(0x13, self.adc_r16_rm16, CHK_MODRM)
        sf(0x14, self.adc_al_imm8, CHK_IMM8)
        sf(0x15, self.adc_ax_imm16, CHK_IMM16)
        sf(0x16, self.push_ss, 0)
        sf(0x17, self.pop_ss, 0)
        sf(0x18, self.sbb_rm8_r8, CHK_MODRM)
        sf(0x19, self.sbb_rm16_r16, CHK_MODRM)
        sf(0x1A, self.sbb_r8_rm8, CHK_MODRM)
        sf(0x1B, self.sbb_r16_rm16, CHK_MODRM)
        sf(0x1C, self.sbb_al_imm8, CHK_IMM8)
        sf(0x1D, self.sbb_ax_imm16, CHK_IMM16)
        sf(0x1E, self.push_ds, 0)
        sf(0x1F, self.pop_ds, 0)
        sf(0x20, self.and_rm8_r8, CHK_MODRM)
        sf(0x21, self.and_rm16_r16, CHK_MODRM)
        sf(0x22, self.and_r8_rm8, CHK_MODRM)
        sf(0x23, self.and_r16_rm16, CHK_MODRM)
        sf(0x24, self.and_al_imm8, CHK_IMM8)
        sf(0x25, self.and_ax_imm16, CHK_IMM16)
        sf(0x28, self.sub_rm8_r8, CHK_MODRM)
        sf(0x29, self.sub_rm16_r16, CHK_MODRM)
        sf(0x2A, self.sub_r8_rm8, CHK_MODRM)
        sf(0x2B, self.sub_r16_rm16, CHK_MODRM)
        sf(0x2C, self.sub_al_imm8, CHK_IMM8)
        sf(0x2D, self.sub_ax_imm16, CHK_IMM16)
        sf(0x30, self.xor_rm8_r8, CHK_MODRM)
        sf(0x31, self.xor_rm16_r16, CHK_MODRM)
        sf(0x32, self.xor_r8_rm8, CHK_MODRM)
        sf(0x33, self.xor_r16_rm16, CHK_MODRM)
        sf(0x34, self.xor_al_imm8, CHK_IMM8)
        sf(0x35, self.xor_ax_imm16, CHK_IMM16)
        sf(0x38, self.cmp_rm8_r8, CHK_MODRM)
        sf(0x39, self.cmp_rm16_r16, CHK_MODRM)
        sf(0x3A, self.cmp_r8_rm8, CHK_MODRM)
        sf(0x3B, self.cmp_r16_rm16, CHK_MODRM)
        sf(0x3C, self.cmp_al_imm8, CHK_IMM8)
        sf(0x3D, self.cmp_ax_imm16, CHK_IMM16)

        opcode_handlers = (
            self.inc_r16,
            self.dec_r16,
            self.push_r16,
            self.pop_r16,
            self.xchg_r16_ax,
            self.mov_r16_imm16,
        )
        for (start, end, _name, flags), handler in zip(X86_16_OPCODE_HELPERS, opcode_handlers, strict=True):
            self._register_opcode_range(start, end, handler, flags)

        sf(0x60, self.pusha, 0)
        sf(0x61, self.popa, 0)
        sf(0x62, self.bound_r16_m16, CHK_MODRM)
        sf(0x68, self.push_imm16, CHK_IMM16)
        sf(0x69, self.imul_r16_rm16_imm16, CHK_MODRM | CHK_IMM16)
        sf(0x6A, self.push_imm8, CHK_IMM8)
        sf(0x6B, self.imul_r16_rm16_imm8, CHK_MODRM | CHK_IMM8)
        sf(0x6C, self.insb_m8_dx, 0)
        sf(0x6D, self.insw_m16_dx, 0)
        sf(0x6E, self.outsb_dx_m8, 0)
        sf(0x6F, self.outsw_dx_m16, 0)
        sf(0x85, self.test_rm16_r16, CHK_MODRM)
        sf(0x87, self.xchg_r16_rm16, CHK_MODRM)
        sf(0x89, self.mov_rm16_r16, CHK_MODRM)
        sf(0x8B, self.mov_r16_rm16, CHK_MODRM)
        sf(0x8C, self.mov_rm16_sreg, CHK_MODRM)
        sf(0x8D, self.lea_r16_m16, CHK_MODRM)
        sf(0x8F, self.code_8f, CHK_MODRM)

        sf(0x98, self.cbw, 0)
        sf(0x99, self.cwd, 0)
        sf(0x9A, self.callf_ptr16_16, CHK_PTR16 | CHK_IMM16)
        sf(0x9C, self.pushf, 0)
        sf(0x9D, self.popf, 0)
        sf(0xCE, self.into, 0)
        sf(0xA1, self.mov_ax_moffs16, CHK_MOFFS)
        sf(0xA3, self.mov_moffs16_ax, CHK_MOFFS)
        sf(0xA4, self.movsb_m8_m8, 0)
        sf(0xAC, self.lodsb_al_m8, 0)
        sf(0xAA, self.stosb_m8_al, 0)
        sf(0xAB, self.stosw_m16_ax, 0)
        sf(0xAD, self.lodsw_ax_m16, 0)
        sf(0xAE, self.scasb_al_m8, 0)
        sf(0xAF, self.scasw_ax_m16, 0)
        sf(0xA5, self.movsw_m16_m16, 0)
        sf(0xA6, self.cmps_m8_m8, 0)
        sf(0xA7, self.cmps_m16_m16, 0)
        sf(0xA9, self.test_ax_imm16, CHK_IMM16)

        for i in range(8):
            sf(0xB8 + i, self.mov_r16_imm16, CHK_IMM16)

        sf(0xC2, self.ret_imm16, CHK_IMM16)
        sf(0xC3, self.ret, 0)
        sf(0xC4, self.les_es_r16_m16, CHK_MODRM)
        sf(0xC5, self.lds_ds_r16_m16, CHK_MODRM)
        sf(0xC7, self.mov_rm16_imm16, CHK_MODRM | CHK_IMM16)
        sf(0xC8, self.enter, CHK_IMM16 | CHK_IMM8)
        sf(0xC9, self.leave, 0)
        sf(0xD7, self.xlat, 0)
        sf(0xE0, self.loop16ne, CHK_IMM8)
        sf(0xE1, self.loop16e, CHK_IMM8)
        sf(0xE2, self.loop16, CHK_IMM8)
        sf(0xE3, self.jcxz_rel8, CHK_IMM8)
        sf(0xE5, self.in_ax_imm8, CHK_IMM8)
        sf(0xE7, self.out_imm8_ax, CHK_IMM8)
        sf(0xE8, self.call_rel16, CHK_IMM16)
        sf(0xE9, self.jmp_rel16, CHK_IMM16)
        sf(0xEA, self.jmpf_ptr16_16, CHK_PTR16 | CHK_IMM16)
        sf(0xED, self.in_ax_dx, 0)
        sf(0xEF, self.out_dx_ax, 0)

        sf(0x0F80, self.jo_rel16, CHK_IMM16)
        sf(0x0F81, self.jno_rel16, CHK_IMM16)
        sf(0x0F82, self.jb_rel16, CHK_IMM16)
        sf(0x0F83, self.jnb_rel16, CHK_IMM16)
        sf(0x0F84, self.jz_rel16, CHK_IMM16)
        sf(0x0F85, self.jnz_rel16, CHK_IMM16)
        sf(0x0F86, self.jbe_rel16, CHK_IMM16)
        sf(0x0F87, self.ja_rel16, CHK_IMM16)
        sf(0x0F88, self.js_rel16, CHK_IMM16)
        sf(0x0F89, self.jns_rel16, CHK_IMM16)
        sf(0x0F8A, self.jp_rel16, CHK_IMM16)
        sf(0x0F8B, self.jnp_rel16, CHK_IMM16)
        sf(0x0F8C, self.jl_rel16, CHK_IMM16)
        sf(0x0F8D, self.jnl_rel16, CHK_IMM16)
        sf(0x0F8E, self.jle_rel16, CHK_IMM16)
        sf(0x0F8F, self.jnle_rel16, CHK_IMM16)
        sf(0x0FAF, self.imul_r16_rm16, CHK_MODRM)
        sf(0x0FB6, self.movzx_r16_rm8, CHK_MODRM)
        sf(0x0FB7, self.movzx_r16_rm16, CHK_MODRM)
        sf(0x0FBE, self.movsx_r16_rm8, CHK_MODRM)
        sf(0x0FBF, self.movsx_r16_rm16, CHK_MODRM)

        sf(0x81, self.code_81, CHK_MODRM | CHK_IMM16)
        sf(0x83, self.code_83, CHK_MODRM | CHK_IMM8)
        sf(0xC1, self.code_c1, CHK_MODRM | CHK_IMM8)
        sf(0xD1, self.code_d1, CHK_MODRM)
        sf(0xD3, self.code_d3, CHK_MODRM)
        sf(0xF7, self.code_f7, CHK_MODRM)
        sf(0xFF, self.code_ff, CHK_MODRM)
        sf(0x0F00, self.code_0f00, CHK_MODRM)
        sf(0x0F01, self.code_0f01, CHK_MODRM)

        # FPU instructions
        sf(0xDA, self.code_da, CHK_MODRM)
        cls._opcode_template_instrfuncs = self.instrfuncs.copy()
        cls._opcode_template_chk = self.chk.copy()

    def jcxz_rel8(self) -> None:
        """Execute decoded ``JCXZ_REL8`` semantics through frontend emulator effects."""
        branch_rel8(self._active_stack_emulator(), self.emu.get_gpreg(reg16_t.CX) == 0, self.instr.imm8)

    def loop16(self) -> None:
        """Execute decoded ``LOOP16`` semantics through frontend emulator effects."""
        loop_rel8(self._active_stack_emulator(), _vex_expr(self.emu.constant(1, Type.int_1)), self.instr.imm8)

    def loop16e(self) -> None:
        """Execute decoded ``LOOP16E`` semantics through frontend emulator effects."""
        loop_rel8(self._active_stack_emulator(), _vex_expr(self.emu.is_zero()), self.instr.imm8)

    def loop16ne(self) -> None:
        """Execute decoded ``LOOP16NE`` semantics through frontend emulator effects."""
        loop_rel8(self._active_stack_emulator(), _vex_expr(~self.emu.is_zero()), self.instr.imm8)

    def code_8f(self) -> None:
        """Dispatch decoded opcode group ``8F`` through owned handlers."""
        reg = self.instr.modrm.reg
        if reg == 0:
            self.pop_rm16()
        else:
            raise RuntimeError(f"not implemented: 0x8f /{reg}")

    def sbb_r16_rm16(self) -> None:
        """Execute decoded ``SBB_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_r16,
            self.get_rm16,
            self.set_r16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def add_rm16_r16(self) -> None:
        """Execute decoded ``ADD_RM16_R16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs
        )

    def sbb_rm16_r16(self) -> None:
        """Execute decoded ``SBB_RM16_R16`` semantics through frontend emulator effects."""
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
        """Execute decoded ``ADC_RM16_R16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            self.get_r16,
            self.set_rm16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def add_r16_rm16(self) -> None:
        """Execute decoded ``ADD_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs
        )

    def adc_r16_rm16(self) -> None:
        """Execute decoded ``ADC_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_r16,
            self.get_rm16,
            self.set_r16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def add_ax_imm16(self) -> None:
        """Execute decoded ``ADD_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_add,
            lambda ax, imm16: ax + imm16,
        )

    def adc_ax_imm16(self) -> None:
        """Execute decoded ``ADC_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_adc,
            lambda ax, imm16, carry: ax + imm16 + carry,
            16,
        )

    def sbb_ax_imm16(self) -> None:
        """Execute decoded ``SBB_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_sbb,
            lambda ax, imm16, carry: ax - imm16 - carry,
            16,
        )

    def push_es(self) -> None:
        """Execute decoded ``PUSH_ES`` semantics through frontend emulator effects."""
        push_segment16(self._active_stack_emulator(), sgreg_t.ES)

    def pop_es(self) -> None:
        """Execute decoded ``POP_ES`` semantics through frontend emulator effects."""
        pop_segment16(self._active_stack_emulator(), sgreg_t.ES)

    def or_rm16_r16(self) -> None:
        """Execute decoded ``OR_RM16_R16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs
        )

    def or_r16_rm16(self) -> None:
        """Execute decoded ``OR_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs
        )

    def or_ax_imm16(self) -> None:
        """Execute decoded ``OR_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_or,
            lambda ax, imm16: ax | imm16,
        )

    def push_cs(self) -> None:
        """Execute decoded ``PUSH_CS`` semantics through frontend emulator effects."""
        push_segment16(self._active_stack_emulator(), sgreg_t.CS)

    def push_ss(self) -> None:
        """Execute decoded ``PUSH_SS`` semantics through frontend emulator effects."""
        push_segment16(self._active_stack_emulator(), sgreg_t.SS)

    def pop_ss(self) -> None:
        """Execute decoded ``POP_SS`` semantics through frontend emulator effects."""
        pop_segment16(self._active_stack_emulator(), sgreg_t.SS)

    def push_ds(self) -> None:
        """Execute decoded ``PUSH_DS`` semantics through frontend emulator effects."""
        push_segment16(self._active_stack_emulator(), sgreg_t.DS)

    def pop_ds(self) -> None:
        """Execute decoded ``POP_DS`` semantics through frontend emulator effects."""
        pop_segment16(self._active_stack_emulator(), sgreg_t.DS)

    def and_rm16_r16(self) -> None:
        """Execute decoded ``AND_RM16_R16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs
        )

    def and_r16_rm16(self) -> None:
        """Execute decoded ``AND_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs
        )

    def and_ax_imm16(self) -> None:
        """Execute decoded ``AND_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_and,
            lambda ax, imm16: ax & imm16,
        )

    def sub_rm16_r16(self) -> None:
        """Execute decoded ``SUB_RM16_R16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs
        )

    def sub_r16_rm16(self) -> None:
        """Execute decoded ``SUB_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs
        )

    def sub_ax_imm16(self) -> None:
        """Execute decoded ``SUB_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_sub,
            lambda ax, imm16: ax - imm16,
        )

    def xor_rm16_r16(self) -> None:
        """Execute decoded ``XOR_RM16_R16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm16, self.get_r16, self.set_rm16, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs
        )

    def xor_r16_rm16(self) -> None:
        """Execute decoded ``XOR_R16_RM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r16, self.get_rm16, self.set_r16, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs
        )

    def xor_ax_imm16(self) -> None:
        """Execute decoded ``XOR_AX_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            lambda value: self.emu.set_gpreg(reg16_t.AX, value),
            self.emu.update_eflags_xor,
            lambda ax, imm16: ax ^ imm16,
        )

    def cmp_rm16_r16(self) -> None:
        """Execute decoded ``CMP_RM16_R16`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm16, self.get_r16, self.emu.update_eflags_sub)

    def cmp_r16_rm16(self) -> None:
        """Execute decoded ``CMP_R16_RM16`` semantics through frontend emulator effects."""
        compare_operation(self.get_r16, self.get_rm16, self.emu.update_eflags_sub)

    def cmp_ax_imm16(self) -> None:
        """Execute decoded ``CMP_AX_IMM16`` semantics through frontend emulator effects."""
        compare_operation(
            lambda: self.emu.get_gpreg(reg16_t.AX),
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            self.emu.update_eflags_sub,
        )

    def inc_r16(self) -> None:
        """Execute decoded ``INC_R16`` semantics through frontend emulator effects."""
        reg = reg16_t(self.instr.opcode & 0b111)
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_inc,
            lambda value: value + 1,
        )

    def dec_r16(self) -> None:
        """Execute decoded ``DEC_R16`` semantics through frontend emulator effects."""
        reg = reg16_t(self.instr.opcode & 0b111)
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_dec,
            lambda value: value - 1,
        )

    def push_r16(self) -> None:
        """Execute decoded ``PUSH_R16`` semantics through frontend emulator effects."""
        reg = reg16_t(self.instr.opcode & 0b111)
        push16_register(self._active_stack_emulator(), reg)

    def pop_r16(self) -> None:
        """Execute decoded ``POP_R16`` semantics through frontend emulator effects."""
        reg = reg16_t(self.instr.opcode & 0b111)
        pop16_register(self._active_stack_emulator(), reg)

    def pusha(self) -> None:
        """Execute decoded ``PUSHA`` semantics through frontend emulator effects."""
        push_all16(self._active_stack_emulator())

    def popa(self) -> None:
        """Execute decoded ``POPA`` semantics through frontend emulator effects."""
        pop_all16(self._active_stack_emulator())

    def push_imm16(self) -> None:
        """Execute decoded ``PUSH_IMM16`` semantics through frontend emulator effects."""
        push_immediate16(self._active_stack_emulator(), self.emu.constant(self.instr.imm16, Type.int_16))

    def bound_r16_m16(self) -> None:
        """Execute decoded ``BOUND_R16_M16`` semantics through frontend emulator effects."""
        if self.instr.modrm.mod == 3:
            raise Exception(EXP_UD)
        reg = _vex_expr(self.get_r16()).signed
        seg, addr = self._resolved_rm_address()
        lower, upper = load_word_pair16(self.emu, seg, addr, address_bits=self.effective_address_bits())
        lower = _vex_expr(lower).signed
        upper = _vex_expr(upper).signed
        out_of_range = (reg < lower) | (reg > upper)
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("BOUND exception emission requires an active lifter instruction")
        lifter_instruction.jump(out_of_range, 0xFF005, JumpKind.Call)

    def imul_r16_rm16_imm16(self) -> None:
        """Execute decoded ``IMUL_R16_RM16_IMM16`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16()).signed
        imm16_s = _vex_expr(self.emu.constant(self.instr.imm16, Type.int_16)).signed
        self.set_r16((rm16_s * imm16_s).cast_to(Type.int_16))
        self.emu.update_eflags_imul(rm16_s, imm16_s)

    def push_imm8(self) -> None:
        """Execute decoded ``PUSH_IMM8`` semantics through frontend emulator effects."""
        # Create a 16-bit constant from the 8-bit immediate value
        push_immediate16(self._active_stack_emulator(), self.emu.constant(self.instr.imm8, Type.int_16))

    def imul_r16_rm16_imm8(self) -> None:
        """Execute decoded ``IMUL_R16_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16()).signed
        imm8_s = _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16).signed
        self.set_r16((rm16_s * imm8_s).cast_to(Type.int_16))
        self.emu.update_eflags_imul(rm16_s, imm8_s)

    def test_rm16_r16(self) -> None:
        """Execute decoded ``TEST_RM16_R16`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm16, self.get_r16, self.emu.update_eflags_and)

    def xchg_r16_rm16(self) -> None:
        """Execute decoded ``XCHG_R16_RM16`` semantics through frontend emulator effects."""
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        if self.instr.modrm.mod == 3:
            self.set_r16(rm16)
            self.set_rm16(r16)
            return

        seg, addr = self._resolved_rm_address()
        self.set_r16(rm16)
        store_resolved_operand(self.emu, resolve_linear_operand(self.emu, seg, addr, 16, 16), r16)

    def mov_rm16_r16(self) -> None:
        """Execute decoded ``MOV_RM16_R16`` semantics through frontend emulator effects."""
        r16 = self.get_r16()
        self.set_rm16(r16)

    def mov_r16_rm16(self) -> None:
        """Execute decoded ``MOV_R16_RM16`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.set_r16(rm16)

    def mov_rm16_sreg(self) -> None:
        """Execute decoded ``MOV_RM16_SREG`` semantics through frontend emulator effects."""
        sreg = self.get_sreg()
        self.set_rm16(sreg)

    def lea_r16_m16(self) -> None:
        """Execute decoded ``LEA_R16_M16`` semantics through frontend emulator effects."""
        _, addr = self._resolved_rm_address()
        self.set_r16(addr)

    def _load_far_pointer(self) -> tuple[object, object]:
        """Load the decoded far pointer through segmented operand helpers."""
        seg, addr = self._resolved_rm_address()
        return load_far_pointer(self.emu, seg, addr, 16, address_bits=self.effective_address_bits())

    def les_es_r16_m16(self) -> None:
        """Execute decoded ``LES_ES_R16_M16`` semantics through frontend emulator effects."""
        offset, segment = self._load_far_pointer()
        self.set_r16(offset)
        self.emu.set_sgreg(sgreg_t.ES, segment)

    def lds_ds_r16_m16(self) -> None:
        """Execute decoded ``LDS_DS_R16_M16`` semantics through frontend emulator effects."""
        offset, segment = self._load_far_pointer()
        self.set_r16(offset)
        self.emu.set_sgreg(sgreg_t.DS, segment)

    def xchg_r16_ax(self) -> None:
        """Execute decoded ``XCHG_R16_AX`` semantics through frontend emulator effects."""
        reg = self.instr.opcode & 0b111
        r16 = self.emu.get_gpreg(coerce_reg16_t(reg))
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(coerce_reg16_t(reg), ax)
        self.emu.set_gpreg(reg16_t.AX, r16)

    def cbw(self) -> None:
        """Execute decoded ``CBW`` semantics through frontend emulator effects."""
        al_s = _vex_expr(self.emu.get_gpreg(reg8_t.AL)).widen_signed(Type.int_16)
        self.emu.set_gpreg(reg16_t.AX, al_s)

    def cwd(self) -> None:
        """Execute decoded ``CWD`` semantics through frontend emulator effects."""
        ax = _vex_expr(self.emu.get_gpreg(reg16_t.AX))
        dx = _vex_expr(self.emu.constant(0, Type.int_16)) - ax[15].cast_to(Type.int_16)
        self.emu.set_gpreg(reg16_t.DX, dx)

    def callf_ptr16_16(self) -> None:
        """Execute decoded ``CALLF_PTR16_16`` semantics through frontend emulator effects."""
        emit_far_call16(
            self._active_stack_emulator(),
            self.instr.ptr16,
            self.instr.imm16,
            far_return_ip16(self._active_stack_emulator(), self.instr.size),
        )

    def pushf(self) -> None:
        """Execute decoded ``PUSHF`` semantics through frontend emulator effects."""
        push_flags16(self._active_stack_emulator())

    def popf(self) -> None:
        """Execute decoded ``POPF`` semantics through frontend emulator effects."""
        pop_flags16(self._active_stack_emulator())

    def mov_ax_moffs16(self) -> None:
        """Execute decoded ``MOV_AX_MOFFS16`` semantics through frontend emulator effects."""
        self.emu.set_gpreg(reg16_t.AX, self.get_moffs16())

    def mov_moffs16_ax(self) -> None:
        """Execute decoded ``MOV_MOFFS16_AX`` semantics through frontend emulator effects."""
        self.set_moffs16(self.emu.get_gpreg(reg16_t.AX))

    def into(self) -> None:
        """Execute decoded ``INTO`` semantics through frontend emulator effects."""
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("INTO exception emission requires an active lifter instruction")
        lifter_instruction.jump(
            self.emu.is_overflow(),
            0xFF004,
            JumpKind.Call,
        )

    def xlat(self) -> None:
        """Execute decoded ``XLAT`` semantics through frontend emulator effects."""
        self.instr.segment = sgreg_t.DS.value
        bx = _vex_expr(self.emu.get_gpreg(reg16_t.BX))
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL)).cast_to(Type.int_16)
        operand = resolve_linear_operand(self.emu, self.select_segment(), bx + al, 8, self.effective_address_bits())
        value = load_resolved_operand(self.emu, operand)
        self.emu.set_gpreg(reg8_t.AL, value)

    def movsb_m8_m8(self) -> None:
        """Execute decoded ``MOVSB_M8_M8`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        value = string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 1)
        string_store(self._active_string_emulator(), sgreg_t.ES, di, value, 1)
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.SI, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def stosb_m8_al(self) -> None:
        """Execute decoded ``STOSB_M8_AL`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        di = self.emu.get_gpreg(reg16_t.DI)
        string_store(self._active_string_emulator(), sgreg_t.ES, di, self.emu.get_gpreg(reg8_t.AL), 1)
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def stosw_m16_ax(self) -> None:
        """Execute decoded ``STOSW_M16_AX`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        di = self.emu.get_gpreg(reg16_t.DI)
        string_store(self._active_string_emulator(), sgreg_t.ES, di, self.emu.get_gpreg(reg16_t.AX), 2)
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def lodsb_al_m8(self) -> None:
        """Execute decoded ``LODSB_AL_M8`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        value = string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 1)
        self.emu.set_gpreg(reg8_t.AL, value)
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.SI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def lodsw_ax_m16(self) -> None:
        """Execute decoded ``LODSW_AX_M16`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        value = string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 2)
        self.emu.set_gpreg(reg16_t.AX, value)
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.SI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def scasb_al_m8(self) -> None:
        """Execute decoded ``SCASB_AL_M8`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        di = self.emu.get_gpreg(reg16_t.DI)
        value = string_load(self._active_string_emulator(), sgreg_t.ES, di, 1)
        string_compare_values(self.emu.get_gpreg(reg8_t.AL), value, self.emu.update_eflags_sub)
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond, zf_sensitive=True)

    def scasw_ax_m16(self) -> None:
        """Execute decoded ``SCASW_AX_M16`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        di = self.emu.get_gpreg(reg16_t.DI)
        value = string_load(self._active_string_emulator(), sgreg_t.ES, di, 2)
        string_compare_values(self.emu.get_gpreg(reg16_t.AX), value, self.emu.update_eflags_sub)
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond, zf_sensitive=True)

    def cmps_m8_m8(self) -> None:
        """Execute decoded ``CMPS_M8_M8`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        m8_s = string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 1)
        m8_d = string_load(self._active_string_emulator(), sgreg_t.ES, di, 1)
        string_compare_values(m8_s, m8_d, self.emu.update_eflags_sub)
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.SI, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def cmps_m16_m16(self) -> None:
        """Execute decoded ``CMPS_M16_M16`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        m16_s = string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 2)
        m16_d = string_load(self._active_string_emulator(), sgreg_t.ES, di, 2)
        string_compare_values(m16_s, m16_d, self.emu.update_eflags_sub)
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.SI, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def movsw_m16_m16(self) -> None:
        """Execute decoded ``MOVSW_M16_M16`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        di = self.emu.get_gpreg(reg16_t.DI)
        value = string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 2)
        string_store(self._active_string_emulator(), sgreg_t.ES, di, value, 2)
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.SI, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def insb_m8_dx(self) -> None:
        """Execute decoded ``INSB_M8_DX`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        di = self.emu.get_gpreg(reg16_t.DI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        string_store(self._active_string_emulator(), sgreg_t.ES, di, self.emu.in_io8(_vex_expr(dx)), 1)
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def insw_m16_dx(self) -> None:
        """Execute decoded ``INSW_M16_DX`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        di = self.emu.get_gpreg(reg16_t.DI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        string_store(self._active_string_emulator(), sgreg_t.ES, di, self.emu.in_io16(_vex_expr(dx)), 2)
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.DI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def outsb_dx_m8(self) -> None:
        """Execute decoded ``OUTSB_DX_M8`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.out_io8(
            _vex_expr(dx), string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 1)
        )
        string_advance_indices(self._active_string_emulator(), 1, reg16_t.SI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def outsw_dx_m16(self) -> None:
        """Execute decoded ``OUTSW_DX_M16`` semantics through frontend emulator effects."""
        repeat_cond = repeat_prefix_cond(self._active_string_emulator(), self.instr)

        si = self.emu.get_gpreg(reg16_t.SI)
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.out_io16(
            _vex_expr(dx), string_load(self._active_string_emulator(), string_source_segment(self.instr), si, 2)
        )
        string_advance_indices(self._active_string_emulator(), 2, reg16_t.SI)

        if repeat_cond is not None:
            repeat_jump(self._active_string_emulator(), self.instr, repeat_cond)

    def test_ax_imm16(self) -> None:
        """Execute decoded ``TEST_AX_IMM16`` semantics through frontend emulator effects."""
        compare_operation(lambda: self.emu.get_gpreg(reg16_t.AX), lambda: self.instr.imm16, self.emu.update_eflags_and)

    def mov_r16_imm16(self) -> None:
        """Execute decoded ``MOV_R16_IMM16`` semantics through frontend emulator effects."""
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(coerce_reg16_t(reg), Const(IRConst.U16(self.instr.imm16)))

    def ret(self) -> None:
        """Execute decoded ``RET`` semantics through frontend emulator effects."""
        return_near16(self._active_stack_emulator())

    def ret_imm16(self) -> None:
        """Execute decoded ``RET_IMM16`` semantics through frontend emulator effects."""
        return_near16(self._active_stack_emulator(), stack_adjust=self.instr.imm16)

    def mov_rm16_imm16(self) -> None:
        """Execute decoded ``MOV_RM16_IMM16`` semantics through frontend emulator effects."""
        self.set_rm16(self.emu.constant(self.instr.imm16, Type.int_16))

    def leave(self) -> None:
        """Execute decoded ``LEAVE`` semantics through frontend emulator effects."""
        leave16(self._active_stack_emulator())

    def in_ax_imm8(self) -> None:
        """Execute decoded ``IN_AX_IMM8`` semantics through frontend emulator effects."""
        self.emu.set_gpreg(reg16_t.AX, self.emu.in_io16(self.instr.imm8))

    def out_imm8_ax(self) -> None:
        """Execute decoded ``OUT_IMM8_AX`` semantics through frontend emulator effects."""
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.out_io16(self.instr.imm8, ax)

    def call_rel16(self) -> None:
        """Execute decoded ``CALL_REL16`` semantics through frontend emulator effects."""
        target = near_relative_target16(self._active_stack_emulator(), self.instr.imm16, self.instr.size)
        emit_near_call16(self._active_stack_emulator(), target, instruction_size=self.instr.size)

    def jmp_rel16(self) -> None:
        """Execute decoded ``JMP_REL16`` semantics through frontend emulator effects."""
        target = near_relative_target16(self._active_stack_emulator(), self.instr.imm16, self.instr.size)
        emit_near_jump16(self._active_stack_emulator(), target)

    def jmpf_ptr16_16(self) -> None:
        """Execute decoded ``JMPF_PTR16_16`` semantics through frontend emulator effects."""
        emit_far_jump16(self._active_stack_emulator(), self.instr.ptr16, self.instr.imm16)

    def in_ax_dx(self) -> None:
        """Execute decoded ``IN_AX_DX`` semantics through frontend emulator effects."""
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg16_t.AX, self.emu.in_io16(_vex_expr(dx)))

    def out_dx_ax(self) -> None:
        """Execute decoded ``OUT_DX_AX`` semantics through frontend emulator effects."""
        dx = self.emu.get_gpreg(reg16_t.DX)
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.out_io16(_vex_expr(dx), ax)

    def jo_rel16(self) -> None:
        """Execute decoded ``JO_REL16`` semantics through frontend emulator effects."""
        branch_rel16(self._active_stack_emulator(), self.emu.is_overflow(), self.instr.imm16, self.instr.size)

    def jno_rel16(self) -> None:
        """Execute decoded ``JNO_REL16`` semantics through frontend emulator effects."""
        branch_rel16(self._active_stack_emulator(), not self.emu.is_overflow(), self.instr.imm16, self.instr.size)

    def jb_rel16(self) -> None:
        """Execute decoded ``JB_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jb", self.emu.is_carry()),
            self.instr.imm16,
            self.instr.size,
        )

    def jnb_rel16(self) -> None:  # jae, jnc
        """Execute decoded ``JNB_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jnb", ~self.emu.is_carry()),
            self.instr.imm16,
            self.instr.size,
        )

    def jz_rel16(self) -> None:
        """Execute decoded ``JZ_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jz", self.emu.is_zero()),
            self.instr.imm16,
            self.instr.size,
        )

    def jnz_rel16(self) -> None:
        """Execute decoded ``JNZ_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jnz", not self.emu.is_zero()),
            self.instr.imm16,
            self.instr.size,
        )

    def jbe_rel16(self) -> None:
        """Execute decoded ``JBE_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jbe", self.emu.is_carry() or self.emu.is_zero()),
            self.instr.imm16,
            self.instr.size,
        )

    def ja_rel16(self) -> None:
        """Execute decoded ``JA_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("ja", not (self.emu.is_carry() or self.emu.is_zero())),
            self.instr.imm16,
            self.instr.size,
        )

    def js_rel16(self) -> None:
        """Execute decoded ``JS_REL16`` semantics through frontend emulator effects."""
        branch_rel16(self._active_stack_emulator(), self.emu.is_sign(), self.instr.imm16, self.instr.size)

    def jns_rel16(self) -> None:
        """Execute decoded ``JNS_REL16`` semantics through frontend emulator effects."""
        branch_rel16(self._active_stack_emulator(), not self.emu.is_sign(), self.instr.imm16, self.instr.size)

    def jp_rel16(self) -> None:
        """Execute decoded ``JP_REL16`` semantics through frontend emulator effects."""
        branch_rel16(self._active_stack_emulator(), self.emu.is_parity(), self.instr.imm16, self.instr.size)

    def jnp_rel16(self) -> None:
        """Execute decoded ``JNP_REL16`` semantics through frontend emulator effects."""
        branch_rel16(self._active_stack_emulator(), not self.emu.is_parity(), self.instr.imm16, self.instr.size)

    def jl_rel16(self) -> None:
        """Execute decoded ``JL_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jl", self.emu.is_sign() != self.emu.is_overflow()),
            self.instr.imm16,
            self.instr.size,
        )

    def jnl_rel16(self) -> None:  # jge
        """Execute decoded ``JNL_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jge", self.emu.is_sign() == self.emu.is_overflow()),
            self.instr.imm16,
            self.instr.size,
        )

    def jle_rel16(self) -> None:
        """Execute decoded ``JLE_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jle", self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow())),
            self.instr.imm16,
            self.instr.size,
        )

    def jnle_rel16(self) -> None:
        """Execute decoded ``JNLE_REL16`` semantics through frontend emulator effects."""
        branch_rel16(
            self._active_stack_emulator(),
            self._branch_cond_8616("jg", not (self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow()))),
            self.instr.imm16,
            self.instr.size,
        )

    def imul_r16_rm16(self) -> None:
        """Execute decoded ``IMUL_R16_RM16`` semantics through frontend emulator effects."""
        r16_s = _vex_expr(self.get_r16())
        rm16_s = _vex_expr(self.get_rm16())
        self.set_r16(r16_s * rm16_s)
        self.emu.update_eflags_imul(r16_s, rm16_s)

    def movzx_r16_rm8(self) -> None:
        """Execute decoded ``MOVZX_R16_RM8`` semantics through frontend emulator effects."""
        rm8 = self.get_rm8()
        self.set_r16(rm8)

    def movzx_r16_rm16(self) -> None:
        """Execute decoded ``MOVZX_R16_RM16`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.set_r16(rm16)

    def movsx_r16_rm8(self) -> None:
        """Execute decoded ``MOVSX_R16_RM8`` semantics through frontend emulator effects."""
        rm8_s = _vex_expr(self.get_rm8()).widen_signed(Type.int_16)
        self.set_r16(rm8_s)

    def movsx_r16_rm16(self) -> None:
        """Execute decoded ``MOVSX_R16_RM16`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16()).signed  # TODO source is 16 bit??
        self.set_r16(rm16_s)

    def code_81(self) -> None:
        """Dispatch decoded opcode group ``81`` through owned handlers."""
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

    def code_83(self) -> None:
        """Dispatch decoded opcode group ``83`` through owned handlers."""
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

    def code_c1(self) -> None:
        """Dispatch decoded opcode group ``C1`` through owned handlers."""
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

    def code_d1(self) -> None:
        """Dispatch decoded opcode group ``D1`` through owned handlers."""
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

    def code_d3(self) -> None:
        """Dispatch decoded opcode group ``D3`` through owned handlers."""
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

    def code_f7(self) -> None:
        """Dispatch decoded opcode group ``F7`` through owned handlers."""
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

    def code_ff(self) -> None:
        """Dispatch decoded opcode group ``FF`` through owned handlers."""
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

    def code_0f00(self) -> None:
        """Dispatch decoded opcode group ``0F00`` through owned handlers."""
        self._dispatch_modrm_reg((None, None, None, self.ltr_rm16), "0x0f00")

    def code_0f01(self) -> None:
        """Dispatch decoded opcode group ``0F01`` through owned handlers."""
        # if reg == 2:
        #    self.lgdt_m24()
        # elif reg == 3:
        pass

    def code_da(self) -> None:
        """Dispatch decoded opcode group ``DA`` through owned handlers."""
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

    def add_rm16_imm16(self) -> None:
        """Execute decoded ``ADD_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.instr.imm16,
            self.set_rm16,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm16_imm16(self) -> None:
        """Execute decoded ``OR_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.instr.imm16,
            self.set_rm16,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm16_imm16(self) -> None:
        """Execute decoded ``ADC_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def sbb_rm16_imm16(self) -> None:
        """Execute decoded ``SBB_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def and_rm16_imm16(self) -> None:
        """Execute decoded ``AND_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.instr.imm16,
            self.set_rm16,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm16_imm16(self) -> None:
        """Execute decoded ``SUB_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.instr.imm16,
            self.set_rm16,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm16_imm16(self) -> None:
        """Execute decoded ``XOR_RM16_IMM16`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: self.emu.constant(self.instr.imm16, Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm16_imm16(self) -> None:
        """Execute decoded ``CMP_RM16_IMM16`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm16, lambda: self.instr.imm16, self.emu.update_eflags_sub)

    def add_rm16_imm8(self) -> None:
        """Execute decoded ``ADD_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm16_imm8(self) -> None:
        """Execute decoded ``OR_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm16_imm8(self) -> None:
        """Execute decoded ``ADC_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            16,
        )

    def sbb_rm16_imm8(self) -> None:
        """Execute decoded ``SBB_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            16,
        )

    def and_rm16_imm8(self) -> None:
        """Execute decoded ``AND_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm16_imm8(self) -> None:
        """Execute decoded ``SUB_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm16_imm8(self) -> None:
        """Execute decoded ``XOR_RM16_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.set_rm16,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm16_imm8(self) -> None:
        """Execute decoded ``CMP_RM16_IMM8`` semantics through frontend emulator effects."""
        compare_operation(
            self.get_rm16,
            lambda: _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).widen_signed(Type.int_16),
            self.emu.update_eflags_sub,
        )

    def shl_rm16_imm8(self) -> None:
        """Execute decoded ``SHL_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.shl(rm16, self.instr.imm8)

    def shr_rm16_imm8(self) -> None:
        """Execute decoded ``SHR_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        count = self._shift_count(self.instr.imm8)
        self.set_rm16(rm16 >> count)
        self.emu.update_eflags_shr(rm16, count)

    def sal_rm16_imm8(self) -> None:
        """Execute decoded ``SAL_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        count = self._shift_count(self.instr.imm8)
        self.set_rm16(rm16 << count)
        self.emu.update_eflags_shl(rm16, count)

    def sar_rm16_imm8(self) -> None:
        """Execute decoded ``SAR_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        count = self._shift_count(self.instr.imm8)
        self.set_rm16(rm16.sar(count))
        self.emu.update_eflags_sar(rm16, count)

    def shl_rm16_1(self) -> None:
        """Execute decoded ``SHL_RM16_1`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        self.set_rm16(rm16 << 1)
        self.emu.update_eflags_shl(rm16, 1)

    def rol_rm16_cl(self) -> None:
        """Execute decoded ``ROL_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rol(rm16, cl)

    def ror_rm16_cl(self) -> None:
        """Execute decoded ``ROR_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.ror(rm16, cl)

    def rcl_rm16_cl(self) -> None:
        """Execute decoded ``RCL_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rcl(rm16, cl)

    def rcr_rm16_cl(self) -> None:
        """Execute decoded ``RCR_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rcr(rm16, cl)

    def _rot_count(self, count: VexExpr | int, modulo: int) -> VexExpr:
        """Normalize a rotate count at the PyVEX expression boundary."""
        count_v = _vex_expr(self.emu.constant(count, Type.int_8)) if isinstance(count, int) else count
        return (count_v.cast_to(Type.int_8) & _vex_expr(self.emu.constant(0x1F, Type.int_8))) % _vex_expr(
            self.emu.constant(modulo, Type.int_8)
        )

    def _shift_count(self, count: VexExpr | int) -> VexExpr:
        """Normalize a shift count at the PyVEX expression boundary."""
        count_v = _vex_expr(self.emu.constant(count, Type.int_8)) if isinstance(count, int) else count
        return count_v.cast_to(Type.int_8) & _vex_expr(self.emu.constant(0x1F, Type.int_8))

    def _set_rotate_cf(self, cf: VexExpr) -> None:
        """Write the carry result produced by a rotate operation."""
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, cf.cast_to(Type.int_1))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def rol(self, a: VexExpr, b: VexExpr | int) -> None:
        """Execute decoded ``ROL`` semantics through frontend emulator effects."""
        masked = self._shift_count(b)
        count = masked % self.emu.constant(16, Type.int_8)
        inv_count = self.emu.constant(16, Type.int_8) - count
        rotated = ((a << count) | (a >> inv_count)) & self.emu.constant(0xFFFF, Type.int_16)
        result = self._ite_value(masked == self.emu.constant(0, Type.int_8), a, rotated)
        self.set_rm16(result)
        self.emu.update_eflags_rol(a, masked)

    def shl_rm16_cl(self) -> None:
        """Execute decoded ``SHL_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.shl(rm16, cl)

    def shl(self, a: VexExpr, b: VexExpr | int) -> None:
        """Execute decoded ``SHL`` semantics through frontend emulator effects."""
        count = self._shift_count(b)
        self.set_rm16(a << count)
        self.emu.update_eflags_shl(a, count)

    def rol_rm16_imm8(self) -> None:
        """Execute decoded ``ROL_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.rol(rm16, self.instr.imm8)

    def rol_rm16_1(self) -> None:
        """Execute decoded ``ROL_RM16_1`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.rol(rm16, 1)

    def ror_rm16_imm8(self) -> None:
        """Execute decoded ``ROR_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.ror(rm16, self.instr.imm8)

    def ror_rm16_1(self) -> None:
        """Execute decoded ``ROR_RM16_1`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.ror(rm16, 1)

    def rcl_rm16_imm8(self) -> None:
        """Execute decoded ``RCL_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.rcl(rm16, self.instr.imm8)

    def rcl_rm16_1(self) -> None:
        """Execute decoded ``RCL_RM16_1`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.rcl(rm16, 1)

    def rcr_rm16_1(self) -> None:
        """Execute decoded ``RCR_RM16_1`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.rcr(rm16, 1)

    def rcr_rm16_imm8(self) -> None:
        """Execute decoded ``RCR_RM16_IMM8`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.rcr(rm16, self.instr.imm8)

    def ror(self, a: VexExpr, b: VexExpr | int) -> None:
        """Execute decoded ``ROR`` semantics through frontend emulator effects."""
        masked = self._shift_count(b)
        count = masked % self.emu.constant(16, Type.int_8)
        inv_count = self.emu.constant(16, Type.int_8) - count
        rotated = ((a >> count) | (a << inv_count)) & self.emu.constant(0xFFFF, Type.int_16)
        result = self._ite_value(masked == self.emu.constant(0, Type.int_8), a, rotated)
        self.set_rm16(result)
        self.emu.update_eflags_ror(a, masked)

    def rcl(self, a: VexExpr, b: VexExpr | int) -> None:
        """Execute decoded ``RCL`` semantics through frontend emulator effects."""
        masked = self._shift_count(b)
        count_value = self.emu._const_u8_value(masked)
        result, carry, overflow = rotate_through_carry_left_state(self.emu, a, masked, 16, self._ite_value)
        if carry is None:
            self.set_rm16(a)
            return
        self.set_rm16(result)
        self._set_rotate_cf(carry)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        if count_value == 1:
            flags = self.emu.set_overflow(flags, overflow)
        else:
            flags = self.emu.set_overflow(
                flags,
                self._ite_value(masked == self.emu.constant(1, Type.int_8), overflow, self.emu.get_flag(11)),
            )
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def rcr(self, a: VexExpr, b: VexExpr | int) -> None:
        """Execute decoded ``RCR`` semantics through frontend emulator effects."""
        masked = self._shift_count(b)
        count_value = self.emu._const_u8_value(masked)
        result, carry, overflow = rotate_through_carry_right_state(self.emu, a, masked, 16, self._ite_value)
        if carry is None:
            self.set_rm16(a)
            return
        self.set_rm16(result)
        self._set_rotate_cf(carry)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        if count_value == 1:
            flags = self.emu.set_overflow(flags, overflow)
        else:
            flags = self.emu.set_overflow(
                flags,
                self._ite_value(masked == self.emu.constant(1, Type.int_8), overflow, self.emu.get_flag(11)),
            )
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def shr_rm16_cl(self) -> None:
        """Execute decoded ``SHR_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.shr(rm16, cl)

    def shr_rm16_1(self) -> None:
        """Execute decoded ``SHR_RM16_1`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        self.set_rm16(rm16 >> 1)
        self.emu.update_eflags_shr(rm16, 1)

    def shr(self, a: VexExpr, b: VexExpr | int) -> None:
        """Execute decoded ``SHR`` semantics through frontend emulator effects."""
        count = self._shift_count(b)
        self.set_rm16(a >> count)
        self.emu.update_eflags_shr(a, count)

    def sal_rm16_1(self) -> None:
        """Execute decoded ``SAL_RM16_1`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        self.set_rm16(rm16 << 1)
        self.emu.update_eflags_shl(rm16, 1)

    def sar_rm16_1(self) -> None:
        """Execute decoded ``SAR_RM16_1`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16())
        self.set_rm16(rm16_s.sar(self.emu.constant(1, Type.int_8)))
        self.emu.update_eflags_sar(rm16_s, 1)

    def sal_rm16_cl(self) -> None:
        """Execute decoded ``SAL_RM16_CL`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        cl = self._shift_count(self.emu.get_gpreg(reg8_t.CL))
        self.set_rm16(rm16 << cl)
        self.emu.update_eflags_shl(rm16, cl)

    def sar_rm16_cl(self) -> None:
        """Execute decoded ``SAR_RM16_CL`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16())
        cl = self._shift_count(self.emu.get_gpreg(reg8_t.CL))
        self.set_rm16(rm16_s.sar(cl))
        self.emu.update_eflags_sar(rm16_s, cl)

    def test_rm16_imm16(self) -> None:
        """Execute decoded ``TEST_RM16_IMM16`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm16, lambda: self.instr.imm16, self.emu.update_eflags_and)

    def not_rm16(self) -> None:
        """Execute decoded ``NOT_RM16`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm16, self.set_rm16, None, lambda value: ~value)

    def neg_rm16(self) -> None:
        """Execute decoded ``NEG_RM16`` semantics through frontend emulator effects."""
        unary_operation(
            self.get_rm16,
            self.set_rm16,
            self.emu.update_eflags_neg,
            lambda value: (_vex_expr(value).signed * -1).cast_to(Type.int_16),
        )

    def mul_dx_ax_rm16(self) -> None:
        """Execute decoded ``MUL_DX_AX_RM16`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16())
        ax = _vex_expr(self.emu.get_gpreg(reg16_t.AX))
        val = ax.cast_to(Type.int_32) * rm16.cast_to(Type.int_32)
        self.emu.set_gpreg(reg16_t.AX, val.cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val >> 16).cast_to(Type.int_16))
        self.emu.update_eflags_mul(ax, rm16)

    def imul_dx_ax_rm16(self) -> None:
        """Execute decoded ``IMUL_DX_AX_RM16`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16()).signed
        ax_s = _vex_expr(self.emu.get_gpreg(reg16_t.AX)).signed
        val_s = ax_s * rm16_s
        self.emu.set_gpreg(reg16_t.AX, val_s.cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val_s >> 16).cast_to(Type.int_16))
        self.emu.update_eflags_imul(ax_s, rm16_s)

    def div_dx_ax_rm16(self) -> None:
        """Execute decoded ``DIV_DX_AX_RM16`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16()).cast_to(Type.int_32)
        # Avoid turning decompilation/lifting into a Python crash when the divisor
        # is unknown or currently zero in a stack slot. The runtime engine can still
        # model a real divide error separately if needed.
        val = (_vex_expr(self.emu.get_gpreg(reg16_t.DX)).cast_to(Type.int_32) << 16) | _vex_expr(
            self.emu.get_gpreg(reg16_t.AX)
        ).cast_to(Type.int_32)
        self.emu.set_gpreg(reg16_t.AX, (val // rm16).cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val % rm16).cast_to(Type.int_16))

    def idiv_dx_ax_rm16(self) -> None:
        """Execute decoded ``IDIV_DX_AX_RM16`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16()).cast_to(Type.int_32, signed=True)
        # if rm16_s == 0:
        #    raise Exception(self.emu.EXP_DE)
        val_s = (_vex_expr(self.emu.get_gpreg(reg16_t.DX)).cast_to(Type.int_32, signed=True) << 16) | _vex_expr(
            self.emu.get_gpreg(reg16_t.AX)
        ).cast_to(Type.int_32)
        self.emu.set_gpreg(reg16_t.AX, (val_s // rm16_s).cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val_s % rm16_s).cast_to(Type.int_16))

    def inc_rm16(self) -> None:
        """Execute decoded ``INC_RM16`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm16, self.set_rm16, self.emu.update_eflags_inc, lambda value: value + 1)

    def dec_rm16(self) -> None:
        """Execute decoded ``DEC_RM16`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm16, self.set_rm16, self.emu.update_eflags_dec, lambda value: value - 1)

    def call_rm16(self) -> None:
        """Execute decoded ``CALL_RM16`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        return_ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.size, Type.int_16)
        emit_near_call16(self._active_stack_emulator(), rm16, return_ip=return_ip)

    def callf_m16_16(self) -> None:
        """Execute decoded ``CALLF_M16_16`` semantics through frontend emulator effects."""
        ip, cs = self._load_far_pointer()
        emit_far_call16(
            self._active_stack_emulator(), cs, ip, far_return_ip16(self._active_stack_emulator(), self.instr.size)
        )

    def jmp_rm16(self) -> None:
        """Execute decoded ``JMP_RM16`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        emit_near_jump16(self._active_stack_emulator(), rm16)

    def jmpf_m16_16(self) -> None:
        """Execute decoded ``JMPF_M16_16`` semantics through frontend emulator effects."""
        ip, sel = self._load_far_pointer()
        emit_far_jump16(self._active_stack_emulator(), sel, ip)

    def push_rm16(self) -> None:
        """Execute decoded ``PUSH_RM16`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        push_immediate16(self._active_stack_emulator(), rm16)

    def pop_rm16(self) -> None:
        """Execute decoded ``POP_RM16`` semantics through frontend emulator effects."""
        value = pop16(self._active_stack_emulator())
        self.set_rm16(value)

    def enter(self) -> None:
        """Execute decoded ``ENTER`` semantics through frontend emulator effects."""
        bytes_ = self.instr.imm16
        level = self.instr.imm8
        level &= 0x1F
        enter16(self._active_stack_emulator(), bytes_, level)

    def _branch_cond_8616(self, kind: str, fallback: VexExpr) -> VexExpr:
        """Prefer a transferred typed branch condition over the flag fallback."""
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("conditional branch recovery requires an active lifter instruction")
        direct = _consume_last_condition_branch_8616(lifter_instruction, self.emu, kind)
        return fallback if direct is None else direct
