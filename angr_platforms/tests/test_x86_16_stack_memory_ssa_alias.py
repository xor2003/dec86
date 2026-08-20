from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.alias.stack_memory_ssa import (
    StackMemoryAliasFactKind8616,
    StackMemoryAliasRefusalKind8616,
    apply_x86_16_stack_memory_ssa_alias_artifact,
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from angr_platforms.X86_16.ir.ssa_memory_contracts import (
    SSAMemoryIncomingValue8616,
    SSAMemoryPhiNode8616,
    SSAMemoryStats8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


def _bp_slot(offset: int, size: int, *, version: int | None = None) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
        version=version,
    )


def _branching_stack_artifact() -> IRFunctionArtifact:
    slot = _bp_slot(-2, 2)
    return IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
            IRBlock(
                addr=0x1010,
                successor_addrs=(0x1030,),
                instrs=(IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),),
            ),
            IRBlock(
                addr=0x1020,
                successor_addrs=(0x1030,),
                instrs=(IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=2, size=2)), size=2),),
            ),
            IRBlock(
                addr=0x1030,
                instrs=(IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),),
            ),
        ),
    )


def test_stack_memory_ssa_alias_projects_accesses_and_phi_exactly() -> None:
    function_ssa = build_x86_16_function_ssa(_branching_stack_artifact())

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.stats.raw_fact_count == 4
    assert artifact.stats.materialized_count == 4
    assert artifact.stats.failure_count == 0
    assert [fact.kind for fact in artifact.facts] == [
        StackMemoryAliasFactKind8616.STORE,
        StackMemoryAliasFactKind8616.STORE,
        StackMemoryAliasFactKind8616.LOAD,
        StackMemoryAliasFactKind8616.PHI,
    ]
    assert [fact.address.version for fact in artifact.facts] == [1, 2, 3, 3]
    assert artifact.facts[-1].incoming_versions == (1, 2)
    assert all(fact.storage == artifact.facts[0].storage for fact in artifact.facts)


def test_stack_memory_ssa_alias_preserves_upstream_range_refusals() -> None:
    word = _bp_slot(-4, 2)
    overlap = _bp_slot(-3, 2)
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=(
                        IRInstr("STORE", None, (word, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                        IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (overlap,), size=2),
                    ),
                ),
            ),
        )
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.facts == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 2
    assert len(artifact.source_refusals) == 2
    assert {refusal.kind for refusal in artifact.refusals} == {
        StackMemoryAliasRefusalKind8616.UPSTREAM_MEMORY_REFUSAL
    }


def test_stack_memory_ssa_alias_refuses_phi_with_mixed_storage_identity() -> None:
    target = _bp_slot(-2, 2, version=3)
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        memory_phi_nodes=(
            SSAMemoryPhiNode8616(
                block_addr=0x1030,
                key=("ss", ("bp",), -2, 2),
                target=target,
                incoming=(
                    SSAMemoryIncomingValue8616(0x1010, _bp_slot(-2, 2, version=1)),
                    SSAMemoryIncomingValue8616(0x1020, _bp_slot(-4, 2, version=2)),
                ),
            ),
        ),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.facts == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert artifact.refusals[0].kind is StackMemoryAliasRefusalKind8616.INCONSISTENT_PHI_STORAGE


def test_stack_memory_ssa_alias_refuses_all_inputs_when_upstream_is_incomplete() -> None:
    slot = _bp_slot(-2, 2, version=1)
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            SSABlock(
                addr=0x1000,
                instrs=(IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),),
                bindings=(),
            ),
        ),
        memory_stats=SSAMemoryStats8616(raw_fact_count=1),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is False
    assert artifact.facts == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert artifact.refusals[0].kind is StackMemoryAliasRefusalKind8616.UPSTREAM_INCOMPLETE


def test_stack_memory_ssa_alias_apply_attaches_typed_artifact() -> None:
    function_ssa = build_x86_16_function_ssa(_branching_stack_artifact())
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=function_ssa)

    assert apply_x86_16_stack_memory_ssa_alias_artifact(SimpleNamespace(), codegen) is False
    assert codegen._inertia_stack_memory_ssa_alias_artifact.complete is True
    assert apply_x86_16_stack_memory_ssa_alias_artifact(SimpleNamespace(), SimpleNamespace()) is False


def test_stack_memory_ssa_alias_apply_hard_fails_open_upstream_accounting() -> None:
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        memory_stats=SSAMemoryStats8616(raw_fact_count=1),
    )

    with pytest.raises(PipelineHardError, match="incomplete evidence accounting"):
        apply_x86_16_stack_memory_ssa_alias_artifact(
            SimpleNamespace(),
            SimpleNamespace(_inertia_vex_ir_function_ssa=function_ssa),
        )


def test_structuring_stage_runs_stack_memory_alias_immediately_after_vex_ir() -> None:
    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)

    vex_index = names.index("_vex_ir_artifact_8616")
    memory_alias_index = names.index("_stack_memory_ssa_alias_artifact_8616")
    restoration_index = names.index("_segment_stack_restore_artifact_8616")
    assert vex_index < memory_alias_index < restoration_index
