"""Tests for atomic storage-contract function prototype application."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import (
    SimStruct,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.lowering.callsite_prototype_declarations import (
    _joined_return_type_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    FunctionStorageContract8616,
    FunctionStorageResolution8616,
    FunctionStorageTrials8616,
    ProgramStorageResolution8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageSlotContract8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageTrialVerdict8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_prototype_application import (
    FunctionStoragePrototypeApplicationVerdict8616,
    apply_accepted_function_storage_prototype_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_simtypes import (
    StorageSimTypeFailureKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_transaction import (
    apply_program_storage_resolution_8616,
)
from angr_platforms.X86_16.lowering.near_pointer_type import near_pointer_type_8616


class _Codegen:
    def __init__(self, project: object) -> None:
        self.project = project
        self.cfunc: object | None = None
        self._next_index = 0
        self._inertia_codegen_decl_refresh_required_8616 = False

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _identity(
    width: int,
    *,
    offset: int | None = None,
    register: str | None = None,
) -> StorageIdentity8616:
    if offset is None:
        return StorageIdentity8616(
            kind=StorageIdentityKind8616.REGISTER,
            width=width,
            register=register,
        )
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.STACK,
        width=width,
        address=IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )


def _slot(
    role: StorageTrialRole8616,
    logical_index: int,
    width: int,
    signedness: StorageTrialSignedness8616,
    value_class: StorageTrialValueClass8616,
    *,
    offset: int | None = None,
    register: str | None = None,
) -> StorageSlotContract8616:
    return StorageSlotContract8616(
        role=role,
        logical_index=logical_index,
        pieces=(_identity(width, offset=offset, register=register),),
        signedness=signedness,
        value_class=value_class,
    )


def _contract(
    *,
    inputs: tuple[StorageSlotContract8616, ...] = (),
    outputs: tuple[StorageSlotContract8616, ...] = (),
) -> FunctionStorageContract8616:
    return FunctionStorageContract8616(
        function_addr=0x2000,
        inputs=inputs,
        outputs=outputs,
        stack_delta=sum(slot.width for slot in inputs),
        callsites=(),
    )


def _publish(project: object, contract: FunctionStorageContract8616) -> None:
    stats = StorageTrialStats8616(1, 1, 1, 1)
    trials = FunctionStorageTrials8616(contract.function_addr, True, (), ())
    resolution = ProgramStorageResolution8616(
        function_trials=(trials,),
        resolutions=(
            FunctionStorageResolution8616(
                contract.function_addr,
                StorageTrialVerdict8616.ACCEPTED,
                contract,
                (),
                stats,
            ),
        ),
        sccs=((contract.function_addr,),),
        iterations_by_scc=(1,),
        stats=stats,
    )
    assert apply_program_storage_resolution_8616(project, resolution)


def test_application_updates_callee_and_callsite_from_same_contract() -> None:
    arch = Arch86_16()
    struct_type = SimStruct({}, name="Item").with_arch(arch)
    pointer_type = near_pointer_type_8616(struct_type, arch)
    wide = SimTypeLong(False).with_arch(arch)
    old_prototype = SimTypeFunction(
        [wide, pointer_type],
        wide,
        arg_names=("count", "item"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=old_prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: function if addr == 0x2000 else None,
            )
        ),
    )
    contract = _contract(
        inputs=(
            _slot(
                StorageTrialRole8616.INPUT,
                0,
                2,
                StorageTrialSignedness8616.SIGNED,
                StorageTrialValueClass8616.VALUE,
                offset=4,
            ),
            _slot(
                StorageTrialRole8616.INPUT,
                1,
                2,
                StorageTrialSignedness8616.NOT_APPLICABLE,
                StorageTrialValueClass8616.POINTER,
                offset=6,
            ),
        ),
        outputs=(
            _slot(
                StorageTrialRole8616.RETURN,
                0,
                2,
                StorageTrialSignedness8616.UNSIGNED,
                StorageTrialValueClass8616.VALUE,
                register="ax",
            ),
        ),
    )
    _publish(project, contract)
    codegen = _Codegen(project)
    arguments = [
        CVariable(
            SimStackVariable(offset, 4, base="bp", name=name, region=0x2000),
            variable_type=variable_type,
            codegen=codegen,
        )
        for offset, name, variable_type in (
            (4, "count", wide),
            (6, "item", pointer_type),
        )
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x2000,
        arg_list=arguments,
        functy=old_prototype,
    )

    result = apply_accepted_function_storage_prototype_8616(project, codegen)

    assert result.verdict is FunctionStoragePrototypeApplicationVerdict8616.APPLIED
    assert isinstance(codegen.cfunc.functy.args[0], SimTypeShort)
    assert codegen.cfunc.functy.args[0].signed is True
    assert isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert codegen.cfunc.functy.args[1].pts_to == struct_type
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert codegen.cfunc.functy.returnty.signed is False
    assert function.prototype == codegen.cfunc.functy
    assert [argument.variable.size for argument in arguments] == [2, 2]
    assert _joined_return_type_8616(
        project,
        CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
        ),
        (),
    ) == "unsigned short"


def test_unsupported_output_refuses_without_partial_mutation() -> None:
    arch = Arch86_16()
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda *, addr, create=False: function)
        ),
    )
    contract = _contract(
        outputs=(
            _slot(
                StorageTrialRole8616.RETURN,
                0,
                3,
                StorageTrialSignedness8616.UNSIGNED,
                StorageTrialValueClass8616.VALUE,
                register="ax",
            ),
        ),
    )
    _publish(project, contract)
    codegen = _Codegen(project)
    codegen.cfunc = SimpleNamespace(addr=0x2000, arg_list=[], functy=prototype)

    result = apply_accepted_function_storage_prototype_8616(project, codegen)

    assert result.verdict is FunctionStoragePrototypeApplicationVerdict8616.TYPE_REFUSED
    assert result.type_failures == (StorageSimTypeFailureKind8616.UNSUPPORTED_WIDTH,)
    assert codegen.cfunc.functy is prototype
    assert function.prototype is prototype
    assert function.is_prototype_guessed is True
