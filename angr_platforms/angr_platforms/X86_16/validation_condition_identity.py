"""Typed condition identity bridge for final semantic validation.

Layer: Tail validation.
Responsibility: compare proven ConditionIR storage with its final lowered C AST
identity without recovering or rewriting semantics.
Forbidden: semantic recovery, AST mutation, or source/COD/assembly/rendered-C
inspection.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

from .ir.condition_ir import ConditionIR
from .ir.core import IRBinaryValue, IRValue, MemSpace
from .structuring.condition_materialization import materialize_condition_ir_expression_8616
from .tail_validation_fingerprint import _expr_fingerprint


def _typed_operand_fingerprint_8616(
    operand: object,
    expression: object,
    project: object,
) -> str:
    """Fingerprint one typed operand through final lowering evidence."""
    if isinstance(operand, IRBinaryValue) and isinstance(expression, CBinaryOp):
        lhs = _typed_operand_fingerprint_8616(operand.lhs, expression.lhs, project)
        rhs = _typed_operand_fingerprint_8616(operand.rhs, expression.rhs, project)
        return f"{expression.op}({lhs},{rhs})"
    if (
        isinstance(operand, IRValue)
        and operand.space is MemSpace.DS
        and operand.expr is None
        and operand.index is None
        and operand.name is None
        and operand.offset >= 0
    ):
        return f"global:{operand.offset:#x}"
    if isinstance(operand, IRValue) and operand.space is not MemSpace.CONST:
        return _expr_fingerprint(expression, project)
    return _expr_fingerprint(expression, project)


def condition_ir_semantic_fingerprint_8616(
    project: object,
    codegen: object,
    condition: ConditionIR,
) -> str | None:
    """Fingerprint proven ConditionIR in the final lowered storage domain."""
    expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    if not isinstance(expression, CBinaryOp):
        return None
    lhs = _typed_operand_fingerprint_8616(condition.lhs, expression.lhs, project)
    rhs = _typed_operand_fingerprint_8616(condition.rhs, expression.rhs, project)
    return f"{expression.op}({lhs},{rhs})"
