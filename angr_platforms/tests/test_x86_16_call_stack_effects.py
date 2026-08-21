"""Tests for exact Semantics-owned caller-frame effects."""

from __future__ import annotations

from angr_platforms.X86_16.callsite_summary import (
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import (
    CallStackEffectFailure8616,
    CallStackEffectVerdict8616,
)
from angr_platforms.X86_16.semantics.call_stack_effects import (
    materialize_call_stack_effects_8616,
)


def _slot() -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _artifact(*, duplicate_call: bool = False) -> IRFunctionArtifact:
    slot = _slot()
    calls = (
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1003),
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1003),
    ) if duplicate_call else (
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1003),
    )
    return IRFunctionArtifact(
        0x1000,
        (
            IRBlock(
                0x1000,
                (
                    IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                    *calls,
                    IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),
                ),
            ),
        ),
    )


def _summary(
    *,
    arg_widths: tuple[int, ...] = (),
    logical_arg_classes: tuple[CallsiteArgumentClass8616, ...] = (),
    cleanup: int | None = 0,
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1003,
        target_addr=0x2000,
        return_addr=0x1006,
        kind="direct_near",
        arg_count=len(arg_widths),
        arg_widths=arg_widths,
        stack_cleanup=cleanup,
        return_register="ax",
        return_used=True,
        logical_arg_widths=arg_widths,
        logical_arg_classes=logical_arg_classes,
        stack_cleanup_instruction_addr=0x1006 if cleanup else None,
    )


def test_zero_argument_call_preserves_exact_bp_range_for_memory_ssa() -> None:
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: _summary()})

    assert result.complete is True
    assert result.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    assert result.facts[0].verdict is CallStackEffectVerdict8616.PROVEN
    assert result.facts[0].effect.preserved_ranges == (_slot(),)
    function_ssa = build_x86_16_function_ssa(result.function)
    assert function_ssa.memory_stats.failure_count == 0
    assert len(function_ssa.memory_bindings) == 1


def test_zero_argument_call_proves_zero_cleanup_when_summary_omits_it() -> None:
    """No argument bytes means there is no caller/callee cleanup ambiguity."""
    result = materialize_call_stack_effects_8616(
        _artifact(),
        {0x1003: _summary(cleanup=None)},
    )

    assert result.complete is True
    assert result.facts[0].verdict is CallStackEffectVerdict8616.PROVEN
    assert result.facts[0].effect.net_stack_delta == 0
    assert result.facts[0].effect.preserved_ranges == (_slot(),)


def test_missing_call_summary_materializes_typed_refusal() -> None:
    result = materialize_call_stack_effects_8616(_artifact(), {})

    assert result.stats.closed is True
    assert result.complete is False
    assert result.facts[0].failure is CallStackEffectFailure8616.SUMMARY_MISSING
    assert result.facts[0].effect.complete is False
    function_ssa = build_x86_16_function_ssa(result.function)
    assert {item.kind for item in function_ssa.memory_refusals} == {"unknown_call_stack_effect"}


def test_pointer_argument_refuses_caller_frame_preservation() -> None:
    summary = _summary(
        arg_widths=(2,),
        logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
        cleanup=2,
    )
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: summary})

    assert result.facts[0].failure is CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE
    assert result.facts[0].effect.escaped_ranges == (_slot(),)


def test_duplicate_machine_call_address_refuses_both_producers() -> None:
    result = materialize_call_stack_effects_8616(
        _artifact(duplicate_call=True),
        {0x1003: _summary()},
    )

    assert result.stats.raw_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 2
    assert {fact.failure for fact in result.facts} == {
        CallStackEffectFailure8616.DUPLICATE_CALL_ADDRESS
    }
