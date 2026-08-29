from __future__ import annotations

from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    ScalarAffineFailure8616,
    SegmentOrigin,
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    trace_scalar_affine_expression_8616,
)


def _artifact(operation: str = "Iop_Add16") -> SSAFunctionArtifact:
    source = IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    loaded = IRValue(MemSpace.TMP, name="loaded", size=2)
    shifted = IRValue(MemSpace.TMP, name="shifted", size=2)
    result = IRValue(MemSpace.TMP, name="result", size=2)
    return build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    (
                        IRInstr("LOAD", loaded, (source,), 2, 0x1000),
                        IRInstr(
                            "Iop_Shl16",
                            shifted,
                            (loaded, IRValue(MemSpace.CONST, const=1, size=2)),
                            2,
                            0x1002,
                        ),
                        IRInstr(
                            operation,
                            result,
                            (shifted, IRValue(MemSpace.CONST, const=0x0B4C, size=2)),
                            2,
                            0x1004,
                        ),
                    ),
                ),
            ),
        )
    )


def test_affine_trace_retains_stack_term_scale_constant_and_path() -> None:
    artifact = _artifact()
    block = artifact.blocks[0]
    root = block.instrs[-1].dst
    assert root is not None

    trace = trace_scalar_affine_expression_8616(
        artifact,
        root,
        block_addr=block.addr,
        before_index=len(block.instrs),
    )

    assert trace.complete
    assert trace.failure is None
    expression = trace.expression
    assert expression is not None
    assert expression.constant == 0x0B4C
    assert len(expression.terms) == 1
    assert expression.terms[0].source.offset == -2
    assert expression.terms[0].coefficient == 2
    assert tuple(site.op for site in expression.definition_path) == (
        "Iop_Add16",
        "Iop_Shl16",
        "LOAD",
    )


def test_non_affine_operation_refuses_without_partial_expression() -> None:
    artifact = _artifact("Iop_Xor16")
    block = artifact.blocks[0]
    root = block.instrs[-1].dst
    assert root is not None

    trace = trace_scalar_affine_expression_8616(
        artifact,
        root,
        block_addr=block.addr,
        before_index=len(block.instrs),
    )

    assert not trace.complete
    assert trace.expression is None
    assert trace.failure is ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED
