from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.function_pointer_parameters import (
    FunctionPointerParameterFailure8616,
    collect_function_pointer_parameter_evidence_8616,
    materialize_function_pointer_parameters_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


class _VariableManager:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.types: dict[SimStackVariable, object] = {}

    def set_variable_type(
        self,
        variable: object,
        type_: object,
        *,
        name: str | None = None,
        override_bot: bool = True,
        all_unified: bool = False,
    ) -> None:
        del name, override_bot, all_unified
        if self.reject:
            raise ValueError("rejected")
        assert isinstance(variable, SimStackVariable)
        self.types[variable] = type_


def _summary(callsite_addr: int, *, arg_widths: tuple[int, ...] = (2,)) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=None,
        return_addr=callsite_addr + 3,
        kind="near-indirect",
        arg_count=len(arg_widths),
        arg_widths=arg_widths,
        stack_cleanup=sum(arg_widths),
        return_register="ax",
        return_used=True,
        return_shape="ax",
        target_source=("bp", 4),
        push_arg_sources=(("bp", 6),) if len(arg_widths) == 1 else (("bp", 6), ("bp", 8)),
    )


def _fixture(
    *,
    reject_manager: bool = False,
    bp_entry_sp_delta: int = 0,
    analysis_address_bits: int = 16,
) -> tuple[object, object, object, _VariableManager, CVariable]:
    arch = Arch86_16()
    arch.bits = analysis_address_bits
    word = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([word, word], word, arg_names=("fn", "value")).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        _inertia_vex_ir_frame=FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta,
                "test",
                FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        ),
    )
    fn_variable = SimStackVariable(
        4 + bp_entry_sp_delta,
        2,
        base="bp",
        name="fn",
        region=0x1000,
    )
    value_variable = SimStackVariable(
        6 + bp_entry_sp_delta,
        2,
        base="bp",
        name="value",
        region=0x1000,
    )
    fn_argument = CVariable(fn_variable, variable_type=word, codegen=codegen)
    value_argument = CVariable(value_variable, variable_type=word, codegen=codegen)
    fn_use = CVariable(fn_variable, variable_type=word, codegen=codegen)
    manager = _VariableManager(reject=reject_manager)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[fn_argument, value_argument],
        functy=prototype,
        variable_manager=manager,
        body=fn_use,
        statements=None,
    )
    codegen._inertia_callsite_summaries = {0x100E: _summary(0x100E), 0x101A: _summary(0x101A)}
    return project, codegen, function, manager, fn_use


def test_materializes_and_replays_binary_proven_function_pointer_parameter() -> None:
    project, codegen, function, manager, fn_use = _fixture()

    assert materialize_function_pointer_parameters_8616(project, codegen) is True

    fn_type = codegen.cfunc.arg_list[0].variable_type
    assert isinstance(fn_type, SimTypePointer)
    assert isinstance(fn_type.pts_to, SimTypeFunction)
    assert len(fn_type.pts_to.args) == 1
    assert isinstance(codegen.cfunc.functy.args[0], SimTypePointer)
    assert isinstance(function.prototype.args[0], SimTypePointer)
    assert isinstance(fn_use.variable_type, SimTypePointer)
    assert manager.types[codegen.cfunc.arg_list[0].variable] == fn_type
    evidence = codegen._inertia_function_pointer_parameter_evidence_8616
    assert (evidence.raw_fact_count, evidence.normalized_fact_count) == (2, 2)
    assert (evidence.classified_fact_count, evidence.materialized_count, evidence.failure_count) == (1, 1, 0)

    word = SimTypeShort(False).with_arch(project.arch)
    scalar_prototype = SimTypeFunction([word, word], word, arg_names=("fn", "value")).with_arch(project.arch)
    codegen.cfunc.arg_list[0].variable_type = word
    codegen.cfunc.functy = scalar_prototype
    function.prototype = scalar_prototype
    fn_use.variable_type = word
    manager.types.clear()

    assert materialize_function_pointer_parameters_8616(project, codegen) is True
    assert isinstance(codegen.cfunc.arg_list[0].variable_type, SimTypePointer)
    assert isinstance(function.prototype.args[0], SimTypePointer)
    assert isinstance(fn_use.variable_type, SimTypePointer)


def test_function_pointer_parameter_refuses_misordered_codegen_arguments() -> None:
    project, codegen, function, _manager, _fn_use = _fixture()
    codegen.cfunc.arg_list.reverse()

    with pytest.raises(PipelineHardError, match="classified but not materialized"):
        materialize_function_pointer_parameters_8616(project, codegen)

    assert isinstance(codegen.cfunc.functy.args[0], SimTypeShort)
    assert isinstance(codegen.cfunc.functy.args[1], SimTypeShort)
    assert isinstance(function.prototype.args[0], SimTypeShort)
    assert isinstance(function.prototype.args[1], SimTypeShort)


def test_function_pointer_parameter_uses_proven_machine_bp_coordinate() -> None:
    project, codegen, function, _manager, fn_use = _fixture(
        bp_entry_sp_delta=-2,
        analysis_address_bits=32,
    )

    assert materialize_function_pointer_parameters_8616(project, codegen) is True

    assert codegen.cfunc.arg_list[0].variable.offset == 2
    assert isinstance(codegen.cfunc.arg_list[0].variable_type, SimTypePointer)
    assert codegen.cfunc.arg_list[0].variable_type.size == 16
    assert isinstance(codegen.cfunc.arg_list[1].variable_type, SimTypeShort)
    assert isinstance(codegen.cfunc.functy.args[0], SimTypePointer)
    assert isinstance(codegen.cfunc.functy.args[1], SimTypeShort)
    assert isinstance(function.prototype.args[0], SimTypePointer)
    assert isinstance(function.prototype.args[1], SimTypeShort)
    assert isinstance(fn_use.variable_type, SimTypePointer)


def test_refuses_conflicting_indirect_call_signatures() -> None:
    evidence = collect_function_pointer_parameter_evidence_8616(
        (_summary(0x100E), _summary(0x101A, arg_widths=(2, 2)))
    )

    assert evidence.raw_fact_count == 2
    assert evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == 0
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 2
    assert evidence.failures == (
        FunctionPointerParameterFailure8616.CONFLICTING_CALL_SIGNATURES,
        FunctionPointerParameterFailure8616.CONFLICTING_CALL_SIGNATURES,
    )


def test_classified_function_pointer_fact_must_reach_variable_manager() -> None:
    project, codegen, _function, _manager, _fn_use = _fixture(reject_manager=True)

    with pytest.raises(PipelineHardError, match="classified but not materialized"):
        materialize_function_pointer_parameters_8616(project, codegen)

    evidence = codegen._inertia_function_pointer_parameter_evidence_8616
    assert evidence.classified_fact_count == 1
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 1
    assert evidence.failures == (FunctionPointerParameterFailure8616.VARIABLE_MANAGER_REJECTED,)
