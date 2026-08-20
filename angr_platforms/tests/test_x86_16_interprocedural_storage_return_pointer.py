"""Real IR/SSA tests for exact near-pointer return-use proof."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.ir import AddressStatus, IRAddress
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_defs import (
    resolve_call_output_definitions_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_pointer import (
    classify_pointer_return_storage_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeVerdict8616,
)

CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1000
WITNESS_ADDR = 0x1003
CALLEE_ADDR = 0x1013


def _fact(
    *,
    witness: int = WITNESS_ADDR,
    kind: CallsiteReturnUseKind8616 = CallsiteReturnUseKind8616.VALUE,
) -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=kind,
        witness_instruction_addr=witness,
    )


def _register(name: str = "ax", width: int = 2) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=width,
        register=name,
    )


def _lift_ssa(code_after_call: bytes) -> SSAFunctionArtifact:
    code = bytes.fromhex("e81000") + code_after_call
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": CALLER_ADDR,
            "entry_point": CALLER_ADDR,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=CALLER_ADDR,
        block_addrs_set={CALLER_ADDR, WITNESS_ADDR},
        info={},
    )
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    return build_x86_16_function_ssa(artifact)


def _definition(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
) -> StorageReachingDefinition8616:
    result = resolve_call_output_definitions_8616(
        artifact,
        fact,
        CALLEE_ADDR,
        (CALLEE_ADDR,),
        (_register(),),
    )
    assert result.complete
    return result.definitions[0]


def _with_address_status(
    artifact: SSAFunctionArtifact,
    status: AddressStatus,
) -> SSAFunctionArtifact:
    changed = False
    blocks = []
    for block in artifact.blocks:
        instructions = []
        for instruction in block.instrs:
            arguments = tuple(
                replace(argument, status=status) if isinstance(argument, IRAddress) else argument
                for argument in instruction.args
            )
            changed = changed or arguments != instruction.args
            instructions.append(replace(instruction, args=arguments))
        blocks.append(replace(block, instrs=tuple(instructions)))
    assert changed
    return replace(artifact, blocks=tuple(blocks))


def test_ax_copy_to_bx_then_ds_load_proves_pointer_return() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.PROVEN
    assert result.complete
    assert result.signedness is StorageTrialSignedness8616.NOT_APPLICABLE
    assert result.value_class is StorageTrialValueClass8616.POINTER
    assert result.pointer_use is not None
    assert result.pointer_use.carrier_register == "bx"
    assert result.pointer_use.address.space.value == "ds"
    assert result.pointer_use.dereference_instruction_addr == 0x1005
    assert any(step.target.name == "bx" for step in result.pointer_use.aliases)


def test_ax_copy_to_si_then_ds_store_proves_pointer_return() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c6890cc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact),
    )

    assert result.complete
    assert result.pointer_use is not None
    assert result.pointer_use.carrier_register == "si"
    assert result.pointer_use.dereference_instruction_addr == 0x1005


def test_mixed_base_address_refuses_pointer_class() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b08c3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_ADDRESS_AMBIGUOUS
    assert result.pointer_use is None


def test_clobbered_alias_refuses_later_dereference() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c331db8b0fc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_ALIAS_CLOBBERED


def test_scalar_copy_without_dereference_does_not_prove_pointer() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c389d9c3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact),
    )

    assert result.failure is ReturnStorageTypeFailure8616.POINTER_DEREFERENCE_NOT_FOUND
    assert result.value_class is None


def test_wrong_witness_and_non_value_use_refuse_before_alias_scan() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    definition = _definition(artifact, fact)

    wrong_witness = classify_pointer_return_storage_8616(
        artifact,
        _fact(witness=0x1004),
        definition,
    )
    wrong_kind = classify_pointer_return_storage_8616(
        artifact,
        _fact(kind=CallsiteReturnUseKind8616.CONDITION),
        definition,
    )

    assert wrong_witness.failure is ReturnStorageTypeFailure8616.POINTER_WITNESS_NOT_FOUND
    assert wrong_kind.failure is ReturnStorageTypeFailure8616.RETURN_USE_NOT_VALUE


def test_call_output_identity_conflict_refuses_pointer_proof() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    definition = _definition(artifact, fact)

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        replace(definition, instr_addr=0x1001),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.CALL_OUTPUT_DEFINITION_CONFLICT


def test_versioned_call_output_refuses_pointer_proof() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    definition = _definition(artifact, fact)

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        replace(definition, value=replace(definition.value, version=0)),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.CALL_OUTPUT_DEFINITION_UNKNOWN


def test_provisional_segmented_address_refuses_pointer_proof() -> None:
    artifact = _with_address_status(
        _lift_ssa(bytes.fromhex("89c38b0fc3")),
        AddressStatus.PROVISIONAL,
    )
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_ADDRESS_UNKNOWN


def test_duplicate_witness_blocks_are_a_typed_conflict() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    conflicting = replace(artifact, blocks=artifact.blocks + artifact.blocks)

    result = classify_pointer_return_storage_8616(
        conflicting,
        fact,
        _definition(artifact, fact),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_WITNESS_CONFLICT


def test_caller_identity_mismatch_is_a_typed_conflict() -> None:
    artifact = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        replace(artifact, function_addr=0x2000),
        fact,
        _definition(artifact, fact),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.CALLER_IDENTITY_CONFLICT
