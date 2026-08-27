from __future__ import annotations

"""Regressions for width-proven identity masks in Condition IR."""

from unittest.mock import MagicMock

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimVariable
from angr_platforms.X86_16.ir.condition_fingerprint_masks import (
    normalize_condition_full_width_masks_8616,
)
from angr_platforms.X86_16.ir.condition_ir import normalize_condition_fingerprint_algebraic_8616
from angr_platforms.X86_16.ir.ir_canonicalize_8616 import canonicalize_expr_8616


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size2,const:65535),const:0)",
            "CmpNE(stack_slot:SS:BP-0xc:size2,const:0)",
        ),
        (
            "if:CmpEQ(And(const:0xffff,stack_arg:value:size2:bp+0x4),const:0)",
            "if:CmpEQ(stack_arg:value:size2:bp+0x4,const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size2,const:255),const:0)",
            "CmpNE(And(stack_slot:SS:BP-0xc:size2,const:255),const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size4,const:65535),const:0)",
            "CmpNE(And(stack_slot:SS:BP-0xc:size4,const:65535),const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size4,const:0xffffffff),const:0)",
            "CmpNE(stack_slot:SS:BP-0xc:size4,const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc,const:65535),const:0)",
            "CmpNE(And(stack_slot:SS:BP-0xc,const:65535),const:0)",
        ),
    ),
)
def test_condition_mask_normalization_requires_exact_width(raw: str, expected: str) -> None:
    assert normalize_condition_full_width_masks_8616(raw) == expected
    assert normalize_condition_fingerprint_algebraic_8616(raw) == expected


def _variable(size: int) -> CVariable:
    codegen = MagicMock()
    codegen.next_idx.return_value = 0
    return CVariable(SimVariable(size, None, f"value_{size}", None, None), codegen=codegen)


def _masked(variable: CVariable, mask: int) -> CBinaryOp:
    codegen = variable.codegen
    constant = CConstant(mask, SimTypeInt(signed=False), codegen=codegen)
    return CBinaryOp("And", variable, constant, codegen=codegen)


def test_local_value_canonicalizer_removes_proven_word_identity_mask() -> None:
    variable = _variable(2)

    assert canonicalize_expr_8616(_masked(variable, 0xFFFF)) is variable


def test_local_value_canonicalizer_keeps_partial_dword_mask() -> None:
    variable = _variable(4)

    assert isinstance(canonicalize_expr_8616(_masked(variable, 0xFFFF)), CBinaryOp)


def test_local_value_canonicalizer_removes_proven_dword_identity_mask() -> None:
    variable = _variable(4)

    assert canonicalize_expr_8616(_masked(variable, 0xFFFFFFFF)) is variable
