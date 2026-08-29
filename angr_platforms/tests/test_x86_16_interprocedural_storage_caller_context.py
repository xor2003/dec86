"""Exact caller SSA context joins for interprocedural return trials."""

from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering import callee_callsite_census
from angr_platforms.X86_16.lowering.callee_callsite_census import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    collect_callee_callsite_census_8616,
)
from angr_platforms.X86_16.lowering.callee_callsite_contracts import (
    callee_callsite_censuses_by_addr_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_caller_context import (
    CallerSSAContextVerdict8616,
    caller_ssa_context_for_return_use_8616,
)

CALLEE_ADDR = 0x1100
CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1010


def _return_use() -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.VALUE,
        witness_instruction_addr=0x1013,
    )


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=CALLSITE_ADDR,
        target_addr=CALLEE_ADDR,
        return_addr=0x1013,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
    )


def _caller_fact(project: object, boundary: object) -> CalleeCallsiteFact8616:
    return CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=boundary,
        evidence_target_addr=CALLEE_ADDR,
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        summary=_summary(),
    )


def _project_with_facts(
    facts: tuple[CalleeCallsiteFact8616, ...],
) -> SimpleNamespace:
    census = CalleeCallsiteCensus8616(
        target_addr=CALLEE_ADDR,
        facts=facts,
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        failure_count=0,
    )
    return SimpleNamespace(_inertia_callee_callsite_census_8616={CALLEE_ADDR: census})


def test_return_use_selects_census_owned_project_and_boundary() -> None:
    evidence_project = SimpleNamespace(name="original")
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})
    project = _project_with_facts((_caller_fact(evidence_project, boundary),))

    result = caller_ssa_context_for_return_use_8616(
        project,
        CALLEE_ADDR,
        _return_use(),
    )

    assert result.verdict is CallerSSAContextVerdict8616.PROVEN
    assert result.complete
    assert result.evidence_project is evidence_project
    assert result.caller_function is boundary


def test_missing_return_use_context_is_typed_unavailable() -> None:
    result = caller_ssa_context_for_return_use_8616(
        _project_with_facts(()),
        CALLEE_ADDR,
        _return_use(),
    )

    assert result.verdict is CallerSSAContextVerdict8616.UNAVAILABLE
    assert not result.complete


def test_duplicate_return_use_context_is_typed_conflict() -> None:
    project_a = SimpleNamespace(name="a")
    project_b = SimpleNamespace(name="b")
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})
    project = _project_with_facts(
        (
            _caller_fact(project_a, boundary),
            _caller_fact(project_b, boundary),
        )
    )

    result = caller_ssa_context_for_return_use_8616(
        project,
        CALLEE_ADDR,
        _return_use(),
    )

    assert result.verdict is CallerSSAContextVerdict8616.CONFLICT
    assert not result.complete


def test_empty_census_before_fact_materialization_is_not_cached(monkeypatch) -> None:
    """Late exact caller facts must replace provisional early absence."""
    functions = SimpleNamespace(values=lambda: ())
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=functions),
        _inertia_caller_function_ranges_8616=((CALLER_ADDR, CALLER_ADDR + 0x20),),
    )
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})

    early = collect_callee_callsite_census_8616(project, CALLEE_ADDR)

    assert early.raw_fact_count == 0
    assert CALLEE_ADDR not in callee_callsite_censuses_by_addr_8616(project)

    monkeypatch.setattr(
        callee_callsite_census,
        "collect_range_callsite_facts_for_target_8616",
        lambda _project, _target, _ranges: (_caller_fact(project, boundary),),
    )

    rebuilt = collect_callee_callsite_census_8616(project, CALLEE_ADDR)

    assert rebuilt.complete
    assert rebuilt.facts[0].callsite_addr == CALLSITE_ADDR
