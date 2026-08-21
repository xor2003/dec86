from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.condition_ir import ConditionIR, ConditionOp
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.lowering import interprocedural_storage_live_out
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_live_out import (
    collect_function_memory_live_out_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_live_out_contracts import (
    MemoryLiveOutCandidateResult8616,
    MemoryLiveOutFailureKind8616,
    MemoryLiveOutUseDisposition8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_live_out_flow import (
    materialize_memory_live_out_candidate_8616,
)
from angr_platforms.X86_16.semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputFact8616,
)

CALLER = 0x1000
CALLEE = 0x1020
CALLSITE = 0x1000
LOAD_ADDR = 0x1003


def _address(*, size: int = 1, base: tuple[str, ...] = ()) -> IRAddress:
    return IRAddress(
        MemSpace.DS,
        base=base,
        offset=0x1234,
        size=size,
        status=AddressStatus.STABLE,
    )


def _call(address: int = CALLSITE, target: int = CALLEE) -> IRInstr:
    return IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=target, size=2),),
        size=2,
        addr=address,
    )


def _load(address: int = LOAD_ADDR, *, size: int = 1) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.TMP, name="t0", size=size),
        (_address(size=size),),
        size=size,
        addr=address,
    )


def _store(address: int = 0x1002, *, base: tuple[str, ...] = ()) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (_address(base=base), IRValue(MemSpace.REG, name="al", size=1)),
        size=1,
        addr=address,
    )


def _artifact(*instructions: IRInstr) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(
        function_addr=CALLER,
        blocks=(SSABlock(CALLER, instructions, ()),),
        predecessor_map={CALLER: ()},
    )


def _output(
    disposition: TerminalMemoryOutputDisposition8616 = TerminalMemoryOutputDisposition8616.MUST_WRITE,
) -> TerminalMemoryOutputFact8616:
    return TerminalMemoryOutputFact8616(_address(), disposition, (), (CALLEE,))


def _condition(
    op: ConditionOp = "ne",
    *,
    load_addr: int = LOAD_ADDR,
) -> ConditionIR:
    return ConditionIR(
        op=op,
        lhs=IRValue(
            MemSpace.DS,
            offset=0x1234,
            size=1,
            memory_access_size=1,
            memory_access_insn=load_addr,
        ),
        rhs=IRValue(MemSpace.CONST, const=0, size=1),
        width_bits=8,
        producer_insn=load_addr,
    )


def _materialize(
    artifact: SSAFunctionArtifact,
    output: TerminalMemoryOutputFact8616 | None = None,
    conditions: tuple[ConditionIR, ...] | None = None,
) -> MemoryLiveOutCandidateResult8616:
    return materialize_memory_live_out_candidate_8616(
        artifact,
        output or _output(),
        CALLER,
        CALLEE,
        CALLSITE,
        (CALLEE,),
        conditions if conditions is not None else (_condition(),),
    )


def test_exact_direct_condition_use_materializes_live_out_trial() -> None:
    result = _materialize(_artifact(_call(), _load()))

    assert result.complete is True
    assert result.failure is None
    assert result.fact is not None
    assert result.fact.disposition is MemoryLiveOutUseDisposition8616.USED
    assert result.fact.signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert result.trial is not None
    assert result.trial.is_complete is True
    assert result.trial.role is StorageTrialRole8616.LIVE_OUT
    assert result.trial.reaching_definition.value.space is MemSpace.DS


def test_absent_direct_load_does_not_create_unused_fact() -> None:
    result = _materialize(_artifact(_call()))

    assert result.complete is True
    assert result.activated is False
    assert result.fact is result.trial is result.failure is None


def test_direct_load_without_condition_provenance_does_not_activate() -> None:
    result = _materialize(_artifact(_call(), _load()), conditions=())

    assert result.complete is True
    assert result.activated is False
    assert result.fact is result.trial is result.failure is None


def test_exact_store_before_load_closes_as_not_reached() -> None:
    result = _materialize(_artifact(_call(), _store(), _load()))

    assert result.complete is True
    assert result.fact is not None
    assert result.fact.disposition is MemoryLiveOutUseDisposition8616.NOT_REACHED
    assert result.trial is None


def test_indirect_alias_and_intervening_call_refuse_attribution() -> None:
    alias = _materialize(_artifact(_call(), _store(base=("bx",)), _load()))
    second_call = _materialize(_artifact(_call(), _call(0x1002, 0x1100), _load()))

    assert alias.failure is MemoryLiveOutFailureKind8616.INTERVENING_ALIAS
    assert second_call.failure is MemoryLiveOutFailureKind8616.INTERVENING_CALL


def test_overlapping_load_and_conditional_write_refuse() -> None:
    overlap = _materialize(_artifact(_call(), _load(size=2)))
    conditional = _materialize(
        _artifact(_call(), _load()),
        _output(TerminalMemoryOutputDisposition8616.CONDITIONAL),
    )

    assert overlap.failure is MemoryLiveOutFailureKind8616.USE_OVERLAP
    assert conditional.failure is MemoryLiveOutFailureKind8616.CONDITIONAL_WRITE


def test_conflicting_condition_signedness_refuses() -> None:
    second_load = 0x1005
    result = _materialize(
        _artifact(_call(), _load(), _load(second_load)),
        conditions=(_condition("slt"), _condition("ult", load_addr=second_load)),
    )

    assert result.failure is MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT


def test_call_target_mismatch_is_typed_conflict() -> None:
    result = _materialize(_artifact(_call(target=0x1200), _load()))

    assert result.failure is MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT
    assert result.definition_failure is not None


def test_function_collection_connects_terminal_store_to_caller_live_out(monkeypatch) -> None:
    caller = _artifact(_call(), _load())
    callee = SSAFunctionArtifact(
        function_addr=CALLEE,
        blocks=(SSABlock(CALLEE, (_store(CALLEE),), ()),),
        predecessor_map={CALLEE: ()},
    )

    class _Factory:
        def block(self, address: int, *, opt_level: int) -> object:
            assert address == CALLEE
            assert opt_level == 0
            instruction = SimpleNamespace(mnemonic="ret")
            return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))

    project = SimpleNamespace(
        factory=_Factory(),
        _inertia_function_ssa_artifacts_8616={CALLER: caller, CALLEE: callee},
        _inertia_function_ssa_stages_8616={
            CALLER: FunctionSSAArtifactStage8616.SEMANTIC,
            CALLEE: FunctionSSAArtifactStage8616.SEMANTIC,
        },
    )
    monkeypatch.setattr(
        interprocedural_storage_live_out,
        "collect_typed_condition_artifacts_8616",
        lambda _project, _address: ([_condition()], ()),
    )
    callsites = (CallsiteStorageTrials8616(CALLER, CALLEE, CALLSITE, stack_delta=0),)

    collection = collect_function_memory_live_out_trials_8616(
        project, CALLEE, callsites, (CALLEE,)
    )

    assert collection.complete is True
    assert collection.stats.raw_fact_count == collection.stats.materialized_count == 1
    assert len(collection.callsites) == 1
    assert collection.callsites[0].trials[0].role is StorageTrialRole8616.LIVE_OUT
