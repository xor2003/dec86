from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from angr_platforms.X86_16.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
)
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
from angr_platforms.X86_16.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.lowering.instruction_bp_stack_access import (
    InstructionBpStackAccess8616,
    InstructionBpStackAccessEvidence8616,
    ensure_instruction_bp_stack_access_index_8616,
    select_instruction_bp_stack_access_8616,
)
from angr_platforms.X86_16.lowering.stack_storage_evidence import (
    alias_excludes_stack_range_8616,
    alias_proves_stack_range_8616,
)


def _alias_artifact():
    address = IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(
        build_x86_16_function_ssa(
            IRFunctionArtifact(
                function_addr=0x1000,
                blocks=(
                    IRBlock(
                        addr=0x1000,
                        instrs=(
                            IRInstr(
                                "LOAD",
                                IRValue(MemSpace.REG, name="ax", size=2),
                                (address,),
                                size=2,
                                addr=0x1010,
                            ),
                        ),
                    ),
                ),
            )
        )
    )


def _byte_split_logical_alias_artifact():
    addresses = tuple(
        IRAddress(
            MemSpace.SS,
            base=("bp",),
            offset=offset,
            size=1,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.DEFAULTED,
        )
        for offset in (-2, -1)
    )
    source_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=tuple(
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.REG, name=f"byte_{index}", size=1),
                            (address,),
                            size=1,
                            addr=0x1010,
                        )
                        for index, address in enumerate(addresses)
                    ),
                ),
            ),
        )
    )
    block = source_ssa.blocks[0]
    execution_addresses = tuple(instruction.args[0] for instruction in block.instrs)
    assert all(isinstance(address, IRAddress) for address in execution_addresses)
    logical_access = IRLogicalMemoryAccess8616(
        IRLogicalMemoryAccessKey8616(0x1000, 0x1000, 0x1010, 0),
        IRMemoryAccessKind8616.READ,
        replace(execution_addresses[0], size=2),
        16,
        tuple(
            IRMemoryExecutionSlice8616(
                0x1000,
                index,
                0x1010,
                index,
                address,
            )
            for index, address in enumerate(execution_addresses)
            if isinstance(address, IRAddress)
        ),
    )
    logical_memory = IRLogicalMemoryArtifact8616(
        0x1000,
        (logical_access,),
        (),
        IRLogicalMemoryStats8616(1, 1, 1, 1, 0),
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(
        replace(source_ssa, logical_memory=logical_memory)
    )


def test_instruction_bp_stack_index_reuses_exact_alias_artifact() -> None:
    source = _alias_artifact()
    codegen = SimpleNamespace()

    first = ensure_instruction_bp_stack_access_index_8616(codegen, source)
    replay = ensure_instruction_bp_stack_access_index_8616(codegen, source)

    assert replay is first
    assert first.source_alias is source
    assert first.complete is True
    assert first.stats.raw_fact_count == first.stats.materialized_count == 1
    assert first.by_instruction_addr[0x1010] == (
        InstructionBpStackAccess8616(
            -2,
            2,
            StackMemoryAliasFactKind8616.LOAD,
            InstructionBpStackAccessEvidence8616.EXECUTION_SLICE,
        ),
    )


def test_instruction_bp_stack_index_preserves_logical_word_over_byte_execution() -> None:
    source = _byte_split_logical_alias_artifact()

    index = ensure_instruction_bp_stack_access_index_8616(SimpleNamespace(), source)

    assert source.logical_complete is True
    assert index.complete is True
    assert InstructionBpStackAccess8616(
        -2,
        2,
        StackMemoryAliasFactKind8616.LOAD,
        InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS,
    ) in index.by_instruction_addr[0x1010]


def test_instruction_bp_stack_index_selects_exact_byte_among_sibling_views() -> None:
    index = ensure_instruction_bp_stack_access_index_8616(
        SimpleNamespace(),
        _byte_split_logical_alias_artifact(),
    )

    selected = select_instruction_bp_stack_access_8616(
        index,
        frozenset({0x1010}),
        displacement=-1,
        size=1,
    )

    assert selected == InstructionBpStackAccess8616(
        -1,
        1,
        StackMemoryAliasFactKind8616.LOAD,
        InstructionBpStackAccessEvidence8616.EXECUTION_SLICE,
    )


def test_instruction_bp_stack_index_prefers_same_base_logical_word_owner() -> None:
    index = ensure_instruction_bp_stack_access_index_8616(
        SimpleNamespace(),
        _byte_split_logical_alias_artifact(),
    )

    selected = select_instruction_bp_stack_access_8616(
        index,
        frozenset({0x1010}),
        displacement=-2,
        size=1,
    )

    assert selected == InstructionBpStackAccess8616(
        -2,
        2,
        StackMemoryAliasFactKind8616.LOAD,
        InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS,
    )


def test_instruction_bp_stack_index_uses_sole_range_to_correct_shaped_offset() -> None:
    index = ensure_instruction_bp_stack_access_index_8616(
        SimpleNamespace(),
        _alias_artifact(),
    )

    selected = select_instruction_bp_stack_access_8616(
        index,
        frozenset({0x1010}),
        displacement=-4,
        size=2,
    )

    assert selected == InstructionBpStackAccess8616(
        -2,
        2,
        StackMemoryAliasFactKind8616.LOAD,
        InstructionBpStackAccessEvidence8616.EXECUTION_SLICE,
    )


def test_complete_alias_artifact_proves_contained_execution_byte_range() -> None:
    artifact = _byte_split_logical_alias_artifact()
    codegen = SimpleNamespace(_inertia_stack_memory_ssa_alias_artifact=artifact)

    assert alias_proves_stack_range_8616(codegen, -1, 1) is True
    assert alias_proves_stack_range_8616(codegen, -1, 2) is False
    assert alias_excludes_stack_range_8616(codegen, -4, 2) is True
    assert alias_excludes_stack_range_8616(codegen, -2, 2) is False
