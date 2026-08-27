from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsitePushExprOp8616
from angr_platforms.X86_16.lowering.call_argument_expression import (
    materialize_call_argument_operations_8616,
)


def _materialize(
    operations: tuple[object, ...],
) -> structured_c.CExpression | None:
    word_type = SimTypeShort(signed=False)
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    return materialize_call_argument_operations_8616(
        structured_c.CConstant(42, word_type, codegen=codegen),
        operations,
        resolve_source=lambda source: (
            structured_c.CConstant(int(source[1]), word_type, codegen=codegen)
            if len(source) == 2 and source[0] == "imm" and isinstance(source[1], int)
            else None
        ),
        bind_type=lambda expression: expression,
        word_type=word_type,
        signed_word_type=SimTypeShort(signed=True),
        codegen=codegen,
    )


def test_call_argument_expression_materializes_signed_shift_and_negation() -> None:
    expression = _materialize(
        (
            (CallsitePushExprOp8616.SAR.value, 1),
            (CallsitePushExprOp8616.SUB.value, 160),
            (CallsitePushExprOp8616.NEG.value, 0),
        )
    )

    assert isinstance(expression, structured_c.CBinaryOp)
    assert expression.op == "Sub"
    assert isinstance(expression.lhs, structured_c.CConstant)
    assert expression.lhs.value == 0
    subtract = expression.rhs
    assert isinstance(subtract, structured_c.CBinaryOp)
    assert subtract.op == "Sub"
    shift = subtract.lhs
    assert isinstance(shift, structured_c.CBinaryOp)
    assert shift.op == "Shr"
    assert isinstance(shift.lhs, structured_c.CTypeCast)
    assert shift.lhs.dst_type.signed is True


def test_call_argument_expression_materializes_nested_source_operation() -> None:
    expression = _materialize(
        ((CallsitePushExprOp8616.SUB_SOURCE.value, ("imm", 7)),)
    )

    assert isinstance(expression, structured_c.CBinaryOp)
    assert expression.op == "Sub"
    assert isinstance(expression.rhs, structured_c.CConstant)
    assert expression.rhs.value == 7


def test_call_argument_expression_refuses_unknown_operation() -> None:
    assert _materialize((("invented", 1),)) is None
