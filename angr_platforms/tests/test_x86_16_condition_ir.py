from __future__ import annotations

from angr_platforms.X86_16.condition_ir import (
    build_condition_ir_8616,
    condition_compare_symbol_8616,
    is_signed_condition_8616,
    is_condition_compare_family_8616,
    is_condition_truth_test_8616,
    is_unsigned_condition_8616,
    normalize_condition_op_8616,
)
from angr_platforms.X86_16.ir.vex_condition_lifting import build_condition_from_binop
from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace


def test_condition_ir_builder_keeps_typed_ops_and_args():
    condition = build_condition_ir_8616(
        "eq",
        IRValue(MemSpace.REG, name="ax", size=2, expr=("reg",)),
        IRValue(MemSpace.CONST, const=0, size=2, expr=("int",)),
        expr=("cmp",),
    )

    assert condition == IRCondition(
        op="eq",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2, expr=("reg",)),
            IRValue(MemSpace.CONST, const=0, size=2, expr=("int",)),
        ),
        expr=("cmp",),
    )


def test_condition_ir_normalizes_legacy_nonzero_aliases():
    assert normalize_condition_op_8616("masked_nonzero") == "nonzero"
    assert normalize_condition_op_8616("zero") == "zero"
    assert normalize_condition_op_8616("lt") == "slt"
    assert normalize_condition_op_8616("lt_u") == "ult"
    assert normalize_condition_op_8616("bogus") == "compare"


def test_condition_ir_classifies_compare_vs_truth_families():
    assert is_condition_truth_test_8616("masked_nonzero") is True
    assert is_condition_truth_test_8616("zero") is True
    assert is_condition_truth_test_8616("eq") is False
    assert is_condition_compare_family_8616("compare") is True
    assert is_condition_compare_family_8616("ugt") is True
    assert is_condition_compare_family_8616("nonzero") is False


def test_condition_ir_exposes_compare_symbol_and_signedness():
    assert condition_compare_symbol_8616("slt") == "<"
    assert condition_compare_symbol_8616("uge") == ">="
    assert condition_compare_symbol_8616("compare") is None
    assert is_signed_condition_8616("slt") is True
    assert is_signed_condition_8616("ult") is False
    assert is_unsigned_condition_8616("ult") is True
    assert is_unsigned_condition_8616("slt") is False


def test_vex_condition_lifting_uses_typed_condition_ops():
    left = IRValue(MemSpace.REG, name="ax", size=2, expr=("reg",))
    right = IRValue(MemSpace.REG, name="bx", size=2, expr=("reg",))

    assert build_condition_from_binop("Iop_CmpEQ16", left, right).op == "eq"
    assert build_condition_from_binop("Iop_CmpLT16S", left, right).op == "slt"
    assert build_condition_from_binop("Iop_CmpLT16U", left, right).op == "ult"
    assert build_condition_from_binop("Iop_CmpNE16", left, IRValue(MemSpace.CONST, const=0, size=2, expr=("int",))).op == "nonzero"
