from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.carry_borrow_destinations import (
    CarryBorrowDestinationAliasFailure8616,
    CarryBorrowDestinationAliasVerdict8616,
)
from angr_platforms.X86_16.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.carry_borrow_stack_storage import (
    WideCarryBorrowStackFailure8616,
)
from angr_platforms.X86_16.lowering.stack_memory_ssa import (
    StackMemoryObjectKind8616,
    lower_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.widening.carry_borrow_pipeline import (
    CarryBorrowWideningPipeline8616,
    build_carry_borrow_widening_pipeline_8616,
)
from angr_platforms.X86_16.widening.carry_borrow_storage import (
    WideCarryBorrowStorageFailure8616,
    WideCarryBorrowStorageVerdict8616,
)

_ADJACENT_STORES = bytes.fromhex("01 d8 11 ca 89 46 fc 89 56 fe c3")
_NONADJACENT_STORES = bytes.fromhex("01 d8 11 ca 89 46 fc 89 56 fa c3")


def _lift_with_stack_alias(
    code: bytes,
) -> tuple[SSAFunctionArtifact, StackMemorySSAAliasArtifact8616]:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    function_ssa = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    return function_ssa, build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)


def _pipeline(
    code: bytes,
) -> tuple[StackMemorySSAAliasArtifact8616, CarryBorrowWideningPipeline8616]:
    function_ssa, stack_alias = _lift_with_stack_alias(code)
    return stack_alias, build_carry_borrow_widening_pipeline_8616(function_ssa, stack_alias)


class _FakeCodegen:
    def __init__(
        self,
        stack_alias: StackMemorySSAAliasArtifact8616,
        pipeline: CarryBorrowWideningPipeline8616,
    ) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(
            addr=stack_alias.function_addr,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            sort_local_vars=lambda: None,
        )
        self._inertia_stack_memory_ssa_alias_artifact = stack_alias
        self._inertia_carry_borrow_widening_pipeline_8616 = pipeline
        self._inertia_vex_ir_frame = FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                detail="test fixture",
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        )
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def test_exact_result_stores_widen_to_one_alias_proven_stack_range() -> None:
    stack_alias, pipeline = _pipeline(_ADJACENT_STORES)

    assert pipeline.complete
    assert pipeline.source_stack_alias is stack_alias
    assert pipeline.destination_aliases.stats.materialized_count == 1
    destination = pipeline.destination_aliases.resolutions[0]
    assert destination.verdict is CarryBorrowDestinationAliasVerdict8616.PROVEN
    assert destination.fact is not None
    assert destination.fact.low_store.instr_index == 159
    assert destination.fact.high_store.instr_index == 168

    assert pipeline.storage_widening.stats.materialized_count == 1
    resolution = pipeline.storage_widening.resolutions[0]
    assert resolution.verdict is WideCarryBorrowStorageVerdict8616.PROVEN
    assert resolution.value is not None
    wide = resolution.value
    assert (wide.address.space, wide.address.base, wide.address.offset, wide.address.size) == (
        MemSpace.SS,
        ("bp",),
        -4,
        4,
    )
    assert wide.address.version is None
    assert wide.source_versions == (1, 2)
    assert wide.storage.contains(destination.fact.low_store.storage)
    assert wide.storage.contains(destination.fact.high_store.storage)


def test_nonadjacent_result_stores_retain_typed_refusals() -> None:
    _stack_alias, pipeline = _pipeline(_NONADJACENT_STORES)

    assert pipeline.complete
    destination = pipeline.destination_aliases.resolutions[0]
    assert destination.verdict is CarryBorrowDestinationAliasVerdict8616.UNKNOWN_REFUSE
    assert destination.failure is CarryBorrowDestinationAliasFailure8616.DESTINATION_RANGE_MISMATCH
    storage = pipeline.storage_widening.resolutions[0]
    assert storage.verdict is WideCarryBorrowStorageVerdict8616.UNKNOWN_REFUSE
    assert storage.failure is WideCarryBorrowStorageFailure8616.ALIAS_REFUSED
    assert pipeline.destination_aliases.stats.failure_count == 1
    assert pipeline.storage_widening.stats.failure_count == 1


def test_lowering_materializes_exact_wide_stack_local() -> None:
    stack_alias, pipeline = _pipeline(_ADJACENT_STORES)
    codegen = _FakeCodegen(stack_alias, pipeline)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete
    assert len(artifact.candidates) == 1
    candidate = artifact.candidates[0]
    assert candidate.role is StackMemoryObjectKind8616.LOCAL
    assert (candidate.address.offset, candidate.address.size) == (-4, 4)
    assert candidate.entry_sp_offset == -6
    assert candidate.versions == (1, 2)
    wide_stack = codegen._inertia_wide_carry_borrow_stack_artifact
    assert wide_stack.complete and len(wide_stack.candidates) == 1

    variables = {
        variable: cvar
        for variable, cvar in codegen.cfunc.variables_in_use.items()
        if isinstance(variable, SimStackVariable)
    }
    assert len(variables) == 1
    variable, cvar = next(iter(variables.items()))
    assert (variable.offset, variable.size) == (-4, 4)
    assert isinstance(cvar.variable_type, SimTypeLong)


def test_refused_widening_preserves_both_narrow_stack_locals() -> None:
    stack_alias, pipeline = _pipeline(_NONADJACENT_STORES)
    codegen = _FakeCodegen(stack_alias, pipeline)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete
    assert {(item.address.offset, item.address.size) for item in artifact.candidates} == {
        (-6, 2),
        (-4, 2),
    }
    wide_stack = codegen._inertia_wide_carry_borrow_stack_artifact
    assert wide_stack.candidates == ()
    assert wide_stack.refusals[0].kind is WideCarryBorrowStackFailure8616.SOURCE_WIDENING_REFUSAL
    variables = {
        variable: cvar
        for variable, cvar in codegen.cfunc.variables_in_use.items()
        if isinstance(variable, SimStackVariable)
    }
    assert {(variable.offset, variable.size) for variable in variables} == {(-6, 2), (-4, 2)}
    assert all(isinstance(cvar.variable_type, SimTypeShort) for cvar in variables.values())
