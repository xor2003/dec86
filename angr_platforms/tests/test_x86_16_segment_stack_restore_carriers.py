"""Tests for lowering alias-proven segment stack restore carriers."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.segment_stack_restore_carriers import (
    prune_proven_segment_stack_restore_carriers_8616,
)


def _assignment(codegen: object, instruction_addr: int) -> CAssignment:
    """Build one tagged assignment carrier."""
    value_type = SimTypeShort(False)
    return CAssignment(
        CConstant(0, value_type, codegen=codegen),
        CConstant(1, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": instruction_addr},
    )


def test_proven_segment_restore_removes_only_save_and_restore_assignments() -> None:
    """A proven pair consumes all tagged bookkeeping and keeps unrelated code."""
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    save = _assignment(codegen, 0x1000)
    restore = _assignment(codegen, 0x1006)
    unrelated = _assignment(codegen, 0x1004)
    codegen.cfunc = SimpleNamespace(statements=CStatements([save, unrelated, restore], codegen=codegen))
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=(
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1006,
                restore_register="es",
                saved_instruction_addr=0x1000,
                saved_register="es",
                stack_offsets=(-2, -1),
                verdict=SegmentStackRestoreVerdict8616.PROVEN,
            ),
        ),
    )

    assert prune_proven_segment_stack_restore_carriers_8616(object(), codegen) is True
    assert codegen.cfunc.statements.statements == [unrelated]
    assert codegen._inertia_segment_stack_restore_carrier_stats_8616.closed


def test_unknown_segment_restore_keeps_every_assignment() -> None:
    """Unknown restore provenance is an explicit refusal, never deletion."""
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    restore = _assignment(codegen, 0x1006)
    codegen.cfunc = SimpleNamespace(statements=CStatements([restore], codegen=codegen))
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=(
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1006,
                restore_register="es",
                saved_instruction_addr=None,
                saved_register=None,
                stack_offsets=(),
                verdict=SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
            ),
        ),
    )

    assert prune_proven_segment_stack_restore_carriers_8616(object(), codegen) is False
    assert codegen.cfunc.statements.statements == [restore]
