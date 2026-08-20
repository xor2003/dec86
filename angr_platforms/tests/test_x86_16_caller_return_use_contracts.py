from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.callsite_summary import (
    collect_caller_return_use_evidence_8616,
)


class _Memory:
    def __init__(self, regions: dict[int, bytes]) -> None:
        self._regions = regions

    def load(self, addr: int, size: int) -> bytes:
        for base, data in self._regions.items():
            offset = addr - base
            if 0 <= offset and offset + size <= len(data):
                return data[offset : offset + size]
        raise KeyError(addr)


def _project(regions: dict[int, bytes]) -> SimpleNamespace:
    return SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory(regions)),
    )


def test_condition_use_retains_exact_caller_callsite_and_witness() -> None:
    # call 0x1020; add sp, 2; test ax, ax
    project = _project({0x1000: bytes.fromhex("e81d0083c40285c0")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1008),),
    )

    assert evidence.fact_census_complete
    assert len(evidence.facts) == 1
    fact = evidence.facts[0]
    assert fact.caller_addr == 0x1000
    assert fact.callsite_addr == 0x1000
    assert fact.verdict is CallerReturnUseVerdict8616.USED
    assert fact.kind is CallsiteReturnUseKind8616.CONDITION
    assert fact.witness_instruction_addr == 0x1006
    assert fact.classified


def test_clobber_retains_exact_unused_witness() -> None:
    # call 0x1020; mov ax, 0
    project = _project({0x1000: bytes.fromhex("e81d00b80000")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1006),),
    )

    assert evidence.fact_census_complete
    fact = evidence.facts[0]
    assert fact.verdict is CallerReturnUseVerdict8616.UNUSED
    assert fact.kind is CallsiteReturnUseKind8616.CLOBBERED
    assert fact.witness_instruction_addr == 0x1003


def test_unresolved_jump_retains_unknown_fact_and_failure() -> None:
    # call 0x1020; jmp 0x1100, outside the independently proven caller range.
    project = _project({0x1000: bytes.fromhex("e81d00e9fa00")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1006),),
    )

    assert evidence.fact_census_complete
    assert evidence.verdict is CallerReturnUseVerdict8616.UNKNOWN
    assert evidence.failure_count == 1
    fact = evidence.facts[0]
    assert fact.verdict is CallerReturnUseVerdict8616.UNKNOWN
    assert fact.witness_instruction_addr == 0x1003
    assert not fact.classified


def test_recursive_passthrough_is_retained_but_excluded() -> None:
    # nop; nop; call self; ret
    project = _project({0x1000: bytes.fromhex("9090e8fbffc3")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1000,
        ((0x1000, 0x1006),),
    )

    assert evidence.fact_census_complete
    assert evidence.excluded_callsite_count == 1
    fact = evidence.facts[0]
    assert fact.kind is CallsiteReturnUseKind8616.FUNCTION_RETURN
    assert fact.witness_instruction_addr == 0x1005
    assert fact.excluded_recursive_passthrough
    assert not fact.classified


def test_wrapper_passthrough_retains_local_witness_and_transitive_verdict() -> None:
    # wrapper: call 0x1020; ret. observer: call wrapper; test ax, ax.
    project = _project(
        {
            0x1000: bytes.fromhex("e81d00c3"),
            0x1010: bytes.fromhex("e8edff85c0"),
        }
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1004), (0x1010, 0x1015)),
    )

    assert evidence.fact_census_complete
    fact = evidence.facts[0]
    assert fact.caller_addr == 0x1000
    assert fact.kind is CallsiteReturnUseKind8616.FUNCTION_RETURN
    assert fact.witness_instruction_addr == 0x1003
    assert fact.verdict is CallerReturnUseVerdict8616.USED
    assert fact.classified
