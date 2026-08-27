"""Real IR/SSA tests for interprocedural call-argument definition proof."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from angr_platforms.X86_16.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageIdentityKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_reaching_defs import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionVerdict8616,
    resolve_call_argument_reaching_definition_8616,
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
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        info={},
    )
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    return build_x86_16_function_ssa(artifact)


def _summary(
    *,
    callsite_addr: int,
    target_addr: int,
    push_addr: int,
    source: tuple[object, ...],
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=target_addr,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=None,
        return_register=None,
        return_used=None,
        push_arg_sources=(source,),
        push_arg_instruction_addrs=(push_addr,),
    )


def test_immediate_argument_resolves_exact_store_and_call_use() -> None:
    ssa = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.failure is None
    assert result.stats.complete
    assert len(result.definitions) == 2
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1)
    assert result.definitions[0].value.const == 5
    assert tuple(definition.instr_addr for definition in result.definitions) == (0x1000, 0x1000)
    assert result.use is not None
    assert result.use.callsite_addr == 0x1002


def test_wide_logical_argument_resolves_two_physical_push_definitions() -> None:
    ssa = _lift_ssa(bytes.fromhex("6a026a01e80000"))
    summary = CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=0x1007,
        return_addr=0x1007,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=None,
        push_arg_sources=(
            (CallsitePushSourceKind8616.IMMEDIATE.value, 2),
            (CallsitePushSourceKind8616.IMMEDIATE.value, 1),
        ),
        push_arg_instruction_addrs=(0x1000, 0x1002),
        logical_arg_widths=(4,),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.failure is None
    assert result.stats.complete
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1, 1, 1)
    assert tuple(definition.value.const for definition in result.definitions) == (1, None, 2, None)
    assert tuple(definition.instr_addr for definition in result.definitions) == (
        0x1002,
        0x1002,
        0x1000,
        0x1000,
    )


def test_bp_value_argument_resolves_exact_stack_load() -> None:
    ssa = _lift_ssa(bytes.fromhex("ff7604e80000"))
    summary = _summary(
        callsite_addr=0x1003,
        target_addr=0x1006,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.BP_VALUE.value, 4),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert len(result.definitions) == 2
    storages = tuple(definition.source_storage for definition in result.definitions)
    assert all(storage is not None for storage in storages)
    assert all(storage.kind is StorageIdentityKind8616.STACK for storage in storages if storage)
    assert tuple(storage.address.offset for storage in storages if storage and storage.address) == (4, 5)
    assert all(storage.address.space is MemSpace.SS for storage in storages if storage and storage.address)


def test_bp_value_without_authoritative_logical_access_refuses() -> None:
    ssa = replace(_lift_ssa(bytes.fromhex("ff7604e80000")), logical_memory=None)
    summary = _summary(
        callsite_addr=0x1003,
        target_addr=0x1006,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.BP_VALUE.value, 4),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.raw_fact_count == result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_global_word_argument_retains_two_exact_memory_pieces() -> None:
    ssa = _lift_ssa(bytes.fromhex("ff360012e80000"))
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.GLOBAL_VALUE.value, 0x1200, 2),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert len(result.definitions) == 2
    storages = tuple(definition.source_storage for definition in result.definitions)
    assert all(storage is not None for storage in storages)
    assert all(storage.kind is StorageIdentityKind8616.MEMORY for storage in storages if storage)
    assert tuple(storage.address.offset for storage in storages if storage and storage.address) == (
        0x1200,
        0x1201,
    )
    assert all(storage.address.space is MemSpace.DS for storage in storages if storage and storage.address)


def test_bp_address_argument_requires_matching_ssa_origin() -> None:
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1003,
        source=(CallsitePushSourceKind8616.BP_ADDRESS.value, -4),
    )

    proven = resolve_call_argument_reaching_definition_8616(
        _lift_ssa(bytes.fromhex("8d46fc50e80000")),
        summary,
        0,
    )
    contradicted = resolve_call_argument_reaching_definition_8616(
        _lift_ssa(bytes.fromhex("b8341250e80000")),
        summary,
        0,
    )

    assert proven.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert tuple(
        definition.source_storage.address.offset
        for definition in proven.definitions
        if definition.source_storage is not None
        and definition.source_storage.address is not None
    ) == (-4, -3)
    assert contradicted.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert contradicted.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert contradicted.stats.classified_fact_count == 0
    assert contradicted.stats.materialized_count == 0


def test_signed_immediate_retains_two_byte_definitions_as_one_logical_fact() -> None:
    ssa = _lift_ssa(bytes.fromhex("6affe80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, -1),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1)
    assert result.definitions[0].value.const == 0xFFFF


def test_immediate_source_mismatch_refuses_all_physical_pieces() -> None:
    ssa = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 6),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.raw_fact_count == result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_missing_push_definition_refuses_after_normalization() -> None:
    ssa = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1001,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_call_output_source_refuses_until_output_ssa_is_modeled() -> None:
    ssa = _lift_ssa(bytes.fromhex("50e80000"))
    summary = _summary(
        callsite_addr=0x1001,
        target_addr=0x1004,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.RETURN_REGISTER.value, "ax"),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.UNMODELED_CALL_OUTPUT
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_call_target_conflict_refuses_before_source_classification() -> None:
    ssa = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x2222,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.CONFLICT
    assert result.failure is CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT
    assert result.stats.normalized_fact_count == 0
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
