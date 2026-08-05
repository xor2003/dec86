from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from angr_platforms.X86_16.lowering.call_execution_frame_carriers import (
    CallExecutionFrameCarrierStatus8616,
    prune_consumed_call_execution_frame_carriers_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_node_idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(statements=None)

    def next_idx(self, _kind: str) -> int:
        self._next_node_idx += 1
        return self._next_node_idx


def _dirty(
    codegen: _Codegen,
    varid: int,
    *,
    register_name: str = "sp",
) -> CDirtyExpression:
    register_offset, register_size = codegen.project.arch.registers[register_name]
    return CDirtyExpression(
        SimpleNamespace(
            varid=varid,
            reg_offset=register_offset,
            bits=register_size * 8,
        ),
        codegen=codegen,
    )


def _fixture(
    *,
    register_name: str = "sp",
    decrement: int = 2,
    attach_call: bool = True,
    extra_use: bool = False,
) -> tuple[_Codegen, CFunctionCall, CAssignment, CAssignment]:
    codegen = _Codegen()
    base = _dirty(codegen, 1, register_name=register_name)
    decremented = _dirty(codegen, 23, register_name=register_name)
    pre = CAssignment(
        decremented,
        CBinaryOp(
            "Sub",
            _dirty(codegen, 1, register_name=register_name),
            CConstant(decrement, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        tags={"ins_addr": 0x1052},
        codegen=codegen,
    )
    call = CFunctionCall("clock", None, [], codegen=codegen)
    middle = (
        CIfElse(
            [(call, CStatements([], codegen=codegen))],
            codegen=codegen,
        )
        if attach_call
        else CStatements([], codegen=codegen)
    )
    restore = CAssignment(
        base,
        _dirty(codegen, 23, register_name=register_name),
        tags={"dephi": True},
        codegen=codegen,
    )
    statements: list[object] = [pre, middle, restore]
    if extra_use:
        statements.append(
            CAssignment(
                _dirty(codegen, 99, register_name=register_name),
                _dirty(codegen, 23, register_name=register_name),
                codegen=codegen,
            )
        )
    codegen.cfunc.statements = CStatements(statements, codegen=codegen)
    return codegen, call, pre, restore


def test_consumed_call_execution_frame_prunes_exact_sp_pair() -> None:
    codegen, call, pre, restore = _fixture()

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.MATERIALIZED
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert result.stats.removed_statement_count == 2
    assert pre not in codegen.cfunc.statements.statements
    assert restore not in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_external_carrier_use() -> None:
    codegen, call, pre, restore = _fixture(extra_use=True)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert result.stats.failure_count == 1
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_non_sp_pair() -> None:
    codegen, call, pre, restore = _fixture(register_name="ax")

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_frame_width_mismatch() -> None:
    codegen, call, pre, restore = _fixture(decrement=4)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_unattached_call() -> None:
    codegen, call, pre, restore = _fixture(attach_call=False)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_callsite_machine_frame_kind_normalizes_legacy_spellings() -> None:
    def summary(kind: str | None) -> CallsiteSummary8616:
        return CallsiteSummary8616(
            callsite_addr=0x1052,
            target_addr=0x2000,
            return_addr=0x1055,
            kind=kind,
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
        )

    assert (
        callsite_machine_frame_kind_8616(summary("direct_near"))
        is CallsiteMachineFrameKind8616.NEAR
    )
    assert (
        callsite_machine_frame_kind_8616(summary("direct_far"))
        is CallsiteMachineFrameKind8616.FAR
    )
    assert callsite_machine_frame_kind_8616(summary(None)) is None
    assert CallsiteMachineFrameKind8616.NEAR.return_frame_width == 2
    assert CallsiteMachineFrameKind8616.FAR.return_frame_width == 4
