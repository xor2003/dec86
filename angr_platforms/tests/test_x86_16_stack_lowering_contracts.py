from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.alias_model_impl import AliasStorageFacts, _StackSlotIdentity, _StorageDomainSignature
from angr_platforms.X86_16.analysis.stack_frame_ir import FrameAccessArtifact, StackFrameSlot
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.ir.core import AddressStatus, MemSpace, SegmentOrigin
from angr_platforms.X86_16.lowering.real_mode_linear import _known_bp_stack_offsets_8616, _ss_probe_enabled_8616
from angr_platforms.X86_16.lowering.ss_bp_substitution import substitute_ss_bp_dereferences_with_variables
from angr_platforms.X86_16.lowering.stack_lowering import run_stack_lowering_pass_8616
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import (
    _unbound_typed_frame_slots_8616,
    build_stack_variable_bindings_from_alias_facts_8616,
    lower_stack_accesses_from_alias_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering_impl import (
    _sole_bound_stack_cvar_8616,
    _typed_alias_fact_bp_offsets_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering_result import (
    StackLoweringResult,
    StackLoweringStatus,
    StackSlotFailure,
    materialization_diagnostics_8616,
)
from angr_platforms.X86_16.lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_binding import (
    StackVariableBinding,
    stable_ss_offset_to_ir_address_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


def test_stack_lowering_result_uses_typed_status_values() -> None:
    result = StackLoweringResult(
        status=StackLoweringStatus.PARTIAL,
        failures=[StackSlotFailure(offset=-2, size=2, reason="not materialized")],
    )

    assert result.status is StackLoweringStatus.PARTIAL
    assert result.is_ok is False
    assert result.is_failed is False
    assert result.failure_count == 1
    assert result.to_dict()["status"] == "partial"
    assert "Stack lowering: partial" in materialization_diagnostics_8616(result)


def test_stack_variable_binding_preserves_stable_ss_address_contract() -> None:
    binding = StackVariableBinding(-4, 2, var_name="local_4")
    address = stable_ss_offset_to_ir_address_8616(binding.bp_offset, binding.size)

    assert binding.to_dict() == {
        "bp_offset": -4,
        "size": 2,
        "var_name": "local_4",
        "is_stable": True,
    }
    assert address.space is MemSpace.SS
    assert address.offset == -4
    assert address.size == 2
    assert address.status is AddressStatus.STABLE
    assert address.segment_origin is SegmentOrigin.PROVEN


def test_typed_frame_slot_reconciliation_uses_byte_range_coverage() -> None:
    bindings = (
        StackVariableBinding(-2, 2, var_name="local_2"),
        StackVariableBinding(6, 2, var_name="arg_6"),
    )
    slots = (
        StackFrameSlot(base="bp", offset=-2, role="local", size=2),
        StackFrameSlot(base="bp", offset=7, role="arg", size=1),
    )

    assert _unbound_typed_frame_slots_8616(bindings, slots) == ()


def test_stack_binding_builder_refuses_non_bp_alias_facts() -> None:
    non_bp_fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("si", -2, 2)),
    )

    assert build_stack_variable_bindings_from_alias_facts_8616([non_bp_fact]) == []


def test_stack_lowering_fails_when_typed_bp_slot_has_no_alias_binding() -> None:
    class FakeCodegen:
        def __init__(self) -> None:
            self._inertia_vex_ir_frame = FrameAccessArtifact(
                slots=(StackFrameSlot(base="bp", offset=-8, role="local", size=2),)
            )

    codegen = FakeCodegen()

    with pytest.raises(PipelineHardError, match="typed BP frame slots"):
        lower_stack_accesses_from_alias_facts_8616(codegen, [])

    assert codegen._inertia_stack_lowering_debug == {
        "stable_stack_fact_count": 0,
        "stable_bp_fact_count": 0,
        "stack_binding_count": 0,
        "stack_slot_candidates": 0,
        "stack_slot_bindings": 0,
        "stack_slot_materialized": 0,
        "stack_slot_failed": 0,
        "typed_frame_raw_fact_count": 1,
        "typed_frame_normalized_fact_count": 1,
        "typed_frame_classified_fact_count": 1,
        "typed_frame_bound_count": 0,
        "typed_frame_failure_count": 1,
    }


def test_bound_stack_cvar_resolution_uses_binding_bp_offset() -> None:
    class FakeCodegen:
        def __init__(self) -> None:
            self.project = SimpleNamespace(arch=Arch86_16())
            self._inertia_stack_variable_bindings = (StackVariableBinding(-6, 2),)
            self._idx = 0

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx

    codegen = FakeCodegen()
    variable = SimStackVariable(-6, 2, base="bp", name="local_6")
    cvar = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    seen_offsets: list[int] = []

    def resolve_stack_cvar_at_offset(_codegen: object, offset: int) -> structured_c.CVariable:
        seen_offsets.append(offset)
        return cvar

    assert _sole_bound_stack_cvar_8616(codegen, resolve_stack_cvar_at_offset) is cvar
    assert seen_offsets == [-6]


def test_known_bp_stack_offsets_uses_typed_stack_bindings() -> None:
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, variables_in_use={}, arg_list=()),
        _inertia_semantic_alias_facts=[],
        _inertia_stack_variable_bindings=(object(), StackVariableBinding(-8, 2)),
    )

    assert _known_bp_stack_offsets_8616(codegen) == {-8}


def test_known_bp_stack_offsets_uses_typed_alias_facts() -> None:
    stack_fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("bp", -10, 2)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, variables_in_use={}, arg_list=()),
        _inertia_semantic_alias_facts=[object(), stack_fact],
        _inertia_stack_variable_bindings=(),
    )

    assert _known_bp_stack_offsets_8616(codegen) == {-10}


def test_stack_lowering_impl_uses_typed_alias_fact_fields() -> None:
    stack_fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("bp", 0xFFF4, 2)),
    )

    assert _typed_alias_fact_bp_offsets_8616([object(), stack_fact]) == {-12}


def test_ss_probe_enabled_uses_typed_stack_probe_facts() -> None:
    codegen = SimpleNamespace(
        _inertia_typed_stack_probe_return_facts={
            1: object(),
            2: TypedStackProbeReturnFact8616(call_node_id=2, segment_space="ss", width=2, carrier_keys=()),
        }
    )

    assert _ss_probe_enabled_8616(codegen) is True


def test_stack_lowering_coordinator_runs_typed_lowering_before_rewrite_cleanup() -> None:
    calls: list[str] = []

    def lower_stable_ss_stack_accesses() -> bool:
        calls.append("typed-ss")
        return True

    def rewrite_ss_stack_byte_offsets() -> bool:
        calls.append("rewrite")
        return False

    def canonicalize_stack_cvars() -> bool:
        calls.append("canonicalize")
        return False

    changed = run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
        rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
        canonicalize_stack_cvars=canonicalize_stack_cvars,
        max_rounds=1,
    )

    assert changed is True
    assert calls == ["typed-ss", "rewrite", "canonicalize"]


def test_stack_probe_return_facts_use_typed_callsite_summary_fields() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1234,
        target_addr=0x2000,
        return_addr=0x1237,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register="ax",
        return_used=True,
        stack_probe_helper=True,
        helper_return_state="stack_address",
        helper_return_space="ss",
        helper_return_width=2,
        helper_return_address_kind="stack",
    )
    codegen = SimpleNamespace(_inertia_callsite_summaries={1: object(), 2: summary})

    facts = build_typed_stack_probe_return_facts_8616(codegen)

    assert facts == {
        2: TypedStackProbeReturnFact8616(call_node_id=2, segment_space="ss", width=2, carrier_keys=())
    }
    assert codegen._inertia_typed_stack_probe_return_facts == facts


def test_ss_bp_substitution_uses_typed_stack_binding_fields() -> None:
    c_text = "x = *((ss << 4) + BP) - 0x4; y = ((ss << 4) + BP) - 4;"
    bindings = (StackVariableBinding(-4, 2, var_name="local_4"),)

    result = substitute_ss_bp_dereferences_with_variables(c_text, bindings)

    assert "x = local_4;" in result
    assert "y = &local_4;" in result
