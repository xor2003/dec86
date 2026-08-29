"""Real IR/SSA tests for exact interprocedural call-output producers."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from angr_platforms.X86_16.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_defs import (
    CallOutputDefinitionFailure8616,
    CallOutputDefinitionVerdict8616,
    resolve_call_output_definitions_8616,
)


def _lift_ssa(code: bytes) -> SSAFunctionArtifact:
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
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    return build_x86_16_function_ssa(artifact)


def _fact(
    verdict: CallerReturnUseVerdict8616 = CallerReturnUseVerdict8616.USED,
    *,
    callsite_addr: int = 0x1000,
) -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=0x1000,
        callsite_addr=callsite_addr,
        verdict=verdict,
        kind=(
            CallsiteReturnUseKind8616.CONDITION
            if verdict is CallerReturnUseVerdict8616.USED
            else CallsiteReturnUseKind8616.CLOBBERED
        ),
        witness_instruction_addr=0x1003,
    )


def _register(name: str, width: int = 2) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=width,
        register=name,
    )


def test_exact_call_output_is_versionless_and_provenance_bound() -> None:
    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(),
        0x1003,
        (0x1003,),
        (_register("ax"),),
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.PROVEN
    assert result.complete
    assert result.stats.complete
    definition = result.definitions[0]
    assert definition.definition_kind is StorageDefinitionKind8616.CALL_OUTPUT
    assert definition.instr_addr == 0x1000
    assert definition.value.name == "ax"
    assert definition.value.version is None
    assert definition.value.const is None
    assert result.provenance is not None
    assert result.provenance.function_addr == 0x1003
    assert result.provenance.definition_addr == 0x1000


def test_split_output_pieces_share_one_call_provenance() -> None:
    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(),
        0x1003,
        (0x1003,),
        (_register("ax"), _register("dx")),
    )

    assert result.complete
    assert tuple(item.value.name for item in result.definitions) == ("ax", "dx")
    assert all(item.instr_addr == 0x1000 for item in result.definitions)
    assert result.stats.raw_fact_count == result.stats.materialized_count == 2


def test_target_comparison_does_not_flatten_to_low_16_bits() -> None:
    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(),
        0x11003,
        (0x11003,),
        (_register("ax"),),
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.CONFLICT
    assert result.failure is CallOutputDefinitionFailure8616.CALL_TARGET_CONFLICT
    assert not result.definitions
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_real_mode_offset_target_matches_linked_target_with_project_evidence() -> None:
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xFFFF)
        )
    )

    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(),
        0x11003,
        (0x11003,),
        (_register("ax"),),
        project=project,
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.PROVEN
    assert result.complete


def test_unknown_return_use_refuses_before_call_materialization() -> None:
    fact = CallerReturnUseFact8616(
        caller_addr=0x1000,
        callsite_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.UNKNOWN,
        kind=None,
        witness_instruction_addr=None,
    )

    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        fact,
        0x1003,
        (0x1003,),
        (_register("ax"),),
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallOutputDefinitionFailure8616.RETURN_USE_UNKNOWN
    assert not result.definitions


def test_unused_return_refuses_output_definition() -> None:
    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(CallerReturnUseVerdict8616.UNUSED),
        0x1003,
        (0x1003,),
        (_register("ax"),),
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallOutputDefinitionFailure8616.RETURN_NOT_OBSERVED


def test_missing_callsite_refuses_without_fabricating_definition() -> None:
    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(callsite_addr=0x1001),
        0x1003,
        (0x1003,),
        (_register("ax"),),
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallOutputDefinitionFailure8616.CALLSITE_NOT_FOUND
    assert not result.definitions


def test_duplicate_output_storage_is_a_typed_conflict() -> None:
    result = resolve_call_output_definitions_8616(
        _lift_ssa(bytes.fromhex("e80000")),
        _fact(),
        0x1003,
        (0x1003,),
        (_register("ax"), _register("ax")),
    )

    assert result.verdict is CallOutputDefinitionVerdict8616.CONFLICT
    assert result.failure is CallOutputDefinitionFailure8616.OUTPUT_STORAGE_CONFLICT
    assert not result.definitions
