from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering import callee_argument_count_evidence as evidence_module
from angr_platforms.X86_16.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountVerdict8616,
    collect_callee_argument_count_evidence_8616,
)


def _summary(callsite_addr: int, target_addr: int, argument_count: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=callsite_addr + 3,
        kind="near",
        arg_count=argument_count,
        arg_widths=(2,) * argument_count,
        stack_cleanup=argument_count * 2,
        return_register=None,
        return_used=False,
        push_arg_sources=tuple(("imm", index) for index in range(argument_count)),
    )


def _project() -> SimpleNamespace:
    functions = [SimpleNamespace(name="caller_a"), SimpleNamespace(name="caller_b")]
    return SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(values=lambda: functions)),
    )


def test_callee_argument_count_evidence_proves_zero_from_all_callers(monkeypatch) -> None:
    project = _project()
    targets = {
        "caller_a": [SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")],
        "caller_b": [SimpleNamespace(callsite_addr=0x120, target_addr=0x200, return_addr=0x123, kind="near")],
    }
    summaries = {0x110: _summary(0x110, 0x200, 0), 0x120: _summary(0x120, 0x200, 0)}
    monkeypatch.setattr(evidence_module, "collect_neighbor_call_targets", lambda function: targets[function.name])
    monkeypatch.setattr(evidence_module, "summarize_x86_16_callsite", lambda _function, addr: summaries[addr])

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 0
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == evidence.materialized_count == 2
    assert evidence.failure_count == 0


def test_callee_argument_count_evidence_preserves_one_push_per_logical_argument(monkeypatch) -> None:
    project = _project()
    target = SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")
    monkeypatch.setattr(evidence_module, "collect_neighbor_call_targets", lambda _function: [target])
    monkeypatch.setattr(
        evidence_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x200, 2),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 2


def test_callee_argument_count_evidence_uses_active_project_entry_aliases(monkeypatch) -> None:
    project = _project()
    project._inertia_caller_target_aliases_8616 = (0x200, 0x1F0)
    alias_target = SimpleNamespace(callsite_addr=0x110, target_addr=0x1F0, return_addr=0x113, kind="near")
    monkeypatch.setattr(evidence_module, "collect_neighbor_call_targets", lambda _function: [alias_target])
    monkeypatch.setattr(
        evidence_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x1F0, 0),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 0
    assert evidence.callsite_addrs == (0x110,)


def test_callee_argument_count_evidence_refuses_unrelated_entry_aliases(monkeypatch) -> None:
    project = _project()
    project._inertia_caller_target_aliases_8616 = (0x200, 0x1F0)
    alias_target = SimpleNamespace(
        callsite_addr=0x110,
        target_addr=0x1F0,
        return_addr=0x113,
        kind="near",
    )
    monkeypatch.setattr(
        evidence_module,
        "collect_neighbor_call_targets",
        lambda _function: [alias_target],
    )
    monkeypatch.setattr(
        evidence_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x1F0, 0),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x300)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.UNKNOWN
    assert evidence.raw_fact_count == 0
    assert evidence.callsite_addrs == ()


def test_callee_argument_count_evidence_reports_conflicting_callers(monkeypatch) -> None:
    project = _project()
    targets = {
        "caller_a": [SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")],
        "caller_b": [SimpleNamespace(callsite_addr=0x120, target_addr=0x200, return_addr=0x123, kind="near")],
    }
    summaries = {0x110: _summary(0x110, 0x200, 0), 0x120: _summary(0x120, 0x200, 1)}
    monkeypatch.setattr(evidence_module, "collect_neighbor_call_targets", lambda function: targets[function.name])
    monkeypatch.setattr(evidence_module, "summarize_x86_16_callsite", lambda _function, addr: summaries[addr])

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONFLICT
    assert evidence.argument_count is None
    assert evidence.failure_count == 1


def test_range_census_canonicalizes_padding_target_before_matching(monkeypatch) -> None:
    instruction = SimpleNamespace(address=0x110, mnemonic="call", operands=())
    disassembler = SimpleNamespace(
        detail=False,
        disasm=lambda _code, _address: (instruction,),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(capstone=disassembler),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: bytes(size))),
    )
    monkeypatch.setattr(
        evidence_module,
        "_direct_call_target_8616",
        lambda _instruction: 0x1F0,
    )
    monkeypatch.setattr(
        evidence_module,
        "canonicalize_x86_16_padding_call_target_8616",
        lambda _project, target: 0x200 if target == 0x1F0 else target,
    )
    monkeypatch.setattr(
        evidence_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x200, 2),
    )

    summaries = evidence_module._range_callsite_summaries_8616(
        project,
        0x200,
        ((0x100, 0x120),),
    )

    assert tuple(summary.callsite_addr for summary in summaries) == (0x110,)
