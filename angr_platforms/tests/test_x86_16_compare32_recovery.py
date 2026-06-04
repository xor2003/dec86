from __future__ import annotations

from angr_platforms.X86_16.structuring.compare32_recovery import (
    Instruction8616,
    Operand8616,
    recover_32bit_compare_c_from_instructions_8616,
)


def _reg(name: str) -> Operand8616:
    return Operand8616("reg", name, 2)


def _bp(disp: int) -> Operand8616:
    return Operand8616("bp_mem", disp, 2)


def _imm(value: int) -> Operand8616:
    return Operand8616("imm", value, 2)


def _insn(mnemonic: str, op0: Operand8616, op1: Operand8616 | None = None) -> Instruction8616:
    return Instruction8616(0, mnemonic, op0, op1 or Operand8616(None, None, None))


def test_recover_signed_32bit_constant_compare_from_high_low_word_evidence():
    insns = [
        _insn("mov", _reg("ax"), _bp(4)),
        _insn("mov", _reg("dx"), _bp(6)),
        _insn("cmp", _bp(10), _reg("dx")),
        _insn("jge", Operand8616(None, None)),
        _insn("cmp", _bp(8), _reg("ax")),
        _insn("ja", Operand8616(None, None)),
        _insn("mov", _reg("ax"), _imm(0xFFFF)),
        _insn("mov", _reg("ax"), _imm(1)),
        _insn("mov", _reg("ax"), _imm(0)),
        _insn("mov", _reg("ax"), _imm(2)),
    ]

    recovered = recover_32bit_compare_c_from_instructions_8616(insns, function_name="compare_signed")

    assert recovered is not None
    assert "int compare_signed(long a, long b)" in recovered
    assert "if (a < b)" in recovered
    assert "return -1;" in recovered


def test_recover_unsigned_32bit_constant_compare_from_unsigned_jcc_evidence():
    insns = [
        _insn("mov", _reg("ax"), _bp(8)),
        _insn("mov", _reg("dx"), _bp(10)),
        _insn("cmp", _bp(6), _reg("dx")),
        _insn("jbe", Operand8616(None, None)),
        _insn("cmp", _bp(4), _reg("ax")),
        _insn("jb", Operand8616(None, None)),
        _insn("mov", _reg("ax"), _imm(0xFFFF)),
        _insn("mov", _reg("ax"), _imm(1)),
        _insn("mov", _reg("ax"), _imm(0)),
        _insn("mov", _reg("ax"), _imm(2)),
    ]

    recovered = recover_32bit_compare_c_from_instructions_8616(insns, function_name="compare_unsigned")

    assert recovered is not None
    assert "int compare_unsigned(unsigned long a, unsigned long b)" in recovered


def test_recover_32bit_compare_refuses_without_low_word_compare_evidence():
    insns = [
        _insn("mov", _reg("ax"), _bp(4)),
        _insn("mov", _reg("dx"), _bp(6)),
        _insn("cmp", _bp(10), _reg("dx")),
        _insn("jge", Operand8616(None, None)),
        _insn("mov", _reg("ax"), _imm(0xFFFF)),
        _insn("mov", _reg("ax"), _imm(1)),
        _insn("mov", _reg("ax"), _imm(0)),
        _insn("mov", _reg("ax"), _imm(2)),
    ]

    assert recover_32bit_compare_c_from_instructions_8616(insns, function_name="bad") is None
