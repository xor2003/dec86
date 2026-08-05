"""Materialize proven terminal register-lane values as structured C.

Layer: Structuring.
Responsibility: shape semantic register-lane effects into typed return expressions.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CExpression
from angr.sim_type import SimTypeShort

from ..c_ast_utils import _clone_c_ast_tree_8616

__all__ = ["compose_ax_byte_lanes_8616"]


def compose_ax_byte_lanes_8616(
    codegen: object,
    low_value: CExpression,
    high_value: CExpression,
) -> CBinaryOp:
    """Build AX from independently proven AL and AH values."""
    word_type = SimTypeShort(False)
    low_lane = CBinaryOp(
        "And",
        cast(CExpression, _clone_c_ast_tree_8616(low_value)),
        CConstant(0xFF, word_type, codegen=codegen),
        codegen=codegen,
    )
    high_lane = CBinaryOp(
        "And",
        cast(CExpression, _clone_c_ast_tree_8616(high_value)),
        CConstant(0xFF, word_type, codegen=codegen),
        codegen=codegen,
    )
    shifted_high_lane = CBinaryOp(
        "Shl",
        high_lane,
        CConstant(8, word_type, codegen=codegen),
        codegen=codegen,
    )
    return CBinaryOp("Or", low_lane, shifted_high_lane, codegen=codegen)
