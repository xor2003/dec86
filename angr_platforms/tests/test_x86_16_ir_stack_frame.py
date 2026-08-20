from angr_platforms.X86_16.analysis.stack_frame_ir import (
    FrameCoordinateStatus8616,
    build_x86_16_ir_frame_access_artifact,
)
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)


def test_ir_stack_frame_artifact_classifies_bp_args_and_locals():
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.REG, name="ax", size=2),
                        (IRAddress(MemSpace.SS, base=("bp",), offset=4, size=2, status=AddressStatus.PROVISIONAL),),
                        size=2,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (
                            IRAddress(MemSpace.SS, base=("bp",), offset=-2, size=2, status=AddressStatus.PROVISIONAL),
                            IRValue(MemSpace.CONST, const=1),
                        ),
                        size=2,
                    ),
                ),
            ),
        ),
    )

    frame = build_x86_16_ir_frame_access_artifact(artifact)

    assert [(slot.offset, slot.role) for slot in frame.slots] == [(-2, "local"), (4, "arg")]
    assert frame.bp_coordinate.status is FrameCoordinateStatus8616.UNKNOWN


def test_ir_stack_frame_artifact_proves_bp_entry_sp_coordinate() -> None:
    """Typed SP and BP effects prove the coordinate used by Lowering."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="sp", size=2),
                        (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
                        size=2,
                        addr=0x1000,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="bp", size=2),
                        (IRValue(MemSpace.REG, name="sp", size=2),),
                        size=2,
                        addr=0x1001,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (
                            IRAddress(MemSpace.SS, base=("bp",), offset=-2, size=2),
                            IRValue(MemSpace.REG, name="ax", size=2),
                        ),
                        size=2,
                        addr=0x1003,
                    ),
                ),
            ),
        ),
    )

    frame = build_x86_16_ir_frame_access_artifact(artifact)

    assert frame.bp_coordinate.status is FrameCoordinateStatus8616.PROVEN
    assert frame.bp_coordinate.bp_entry_sp_delta == -2
    assert frame.bp_coordinate.complete is True
    assert frame.bp_coordinate.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
