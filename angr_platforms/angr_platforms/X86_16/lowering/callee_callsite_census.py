"""Collect exact caller ownership with binary callsite summaries.

Layer: Types/Lowering.
Responsibility: retain the evidence project, caller function, machine callsite,
and typed summary for every direct incoming call to one callee.
Consumes alias, widening, and typed facts, including frontend function
boundaries and typed callsite summaries. This module does not infer argument
types or mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM

from ..analysis_helpers import (
    canonicalize_x86_16_padding_call_target_8616,
    collect_neighbor_call_targets,
)
from ..callsite_summary import CallsiteSummary8616, summarize_x86_16_callsite

__all__ = [
    "CalleeCallsiteCensus8616",
    "CalleeCallsiteFact8616",
    "collect_callee_callsite_census_8616",
]


@dataclass(frozen=True, slots=True)
class CalleeCallsiteFact8616:
    """One direct call with its exact runtime evidence owner."""

    evidence_project: object = field(compare=False, repr=False)
    evidence_target_addr: int
    caller_addr: int | None
    callsite_addr: int
    summary: CallsiteSummary8616 | None = field(compare=False)


@dataclass(frozen=True, slots=True)
class CalleeCallsiteCensus8616:
    """Closed normalization accounting for all discovered direct callers."""

    target_addr: int
    facts: tuple[CalleeCallsiteFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every discovered call has one typed summary."""
        return (
            self.raw_fact_count > 0
            and self.normalized_fact_count == self.raw_fact_count
            and self.failure_count == 0
        )


class _FunctionManager8616(Protocol):
    """Third-party angr function-manager surface used for discovery."""

    def values(self) -> Iterable[SimpleNamespace]:
        """Return discovered functions and stubs."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party angr knowledge-base surface consumed by this collector."""

    functions: _FunctionManager8616


class _ProjectSurface8616(Protocol):
    """angr project plus owned caller-census extensions."""

    kb: _KnowledgeBase8616
    _inertia_original_project: object
    _inertia_original_linear_delta: int
    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_caller_target_aliases_8616: tuple[int, ...]
    _inertia_caller_evidence_project_8616: object
    _inertia_caller_evidence_target_8616: int
    _inertia_callee_callsite_census_8616: dict[int, CalleeCallsiteCensus8616]


class _InstructionOperand8616(Protocol):
    """Capstone operand fields consumed at the disassembly boundary."""

    type: int
    imm: int


class _Instruction8616(Protocol):
    """Capstone instruction fields consumed for direct-call discovery."""

    address: int
    mnemonic: str
    operands: Sequence[_InstructionOperand8616]


class _Disassembler8616(Protocol):
    """Capstone engine surface used to decode proven caller ranges."""

    detail: bool

    def disasm(self, code: bytes, address: int) -> Iterable[_Instruction8616]:
        """Decode one bounded caller range."""
        ...


class _Memory8616(Protocol):
    """angr loader-memory surface used by the range decoder."""

    def load(self, address: int, size: int) -> bytes:
        """Read bytes from mapped binary memory."""
        ...


class _ArchSurface8616(Protocol):
    """angr architecture fields used by the range decoder."""

    capstone: _Disassembler8616


class _LoaderSurface8616(Protocol):
    """angr loader fields used by the range decoder."""

    memory: _Memory8616


class _RangeProjectSurface8616(Protocol):
    """angr project fields needed to summarize raw caller ranges."""

    arch: _ArchSurface8616
    loader: _LoaderSurface8616


def _function_addr_8616(function: object) -> int | None:
    """Return one exact third-party function address when available."""
    try:
        function_addr = cast(SimpleNamespace, function).addr
    except AttributeError:
        return None
    return function_addr if isinstance(function_addr, int) else None


def _project_target_pairs_8616(
    project: object,
    target_addr: int,
) -> tuple[tuple[object, int], ...]:
    """Return active/original project targets across explicit rebasing."""
    active = cast(_ProjectSurface8616, project)
    pairs: list[tuple[object, int]] = [(project, target_addr)]
    try:
        caller_project = active._inertia_caller_evidence_project_8616
        caller_target = active._inertia_caller_evidence_target_8616
    except AttributeError:
        caller_project = None
        caller_target = None
    if caller_project is not None and isinstance(caller_target, int):
        pairs.append((caller_project, caller_target))
    try:
        aliases = active._inertia_caller_target_aliases_8616
    except AttributeError:
        aliases = ()
    if not isinstance(aliases, tuple):
        raise TypeError("caller target aliases must be a tuple")
    try:
        original_project = active._inertia_original_project
    except AttributeError:
        if target_addr in aliases:
            pairs.extend((project, alias) for alias in aliases if isinstance(alias, int))
        return tuple(pairs)
    try:
        delta = active._inertia_original_linear_delta
    except AttributeError:
        delta = 0
    alias_scope_targets = {target_addr}
    if delta:
        alias_scope_targets.update((target_addr + delta, target_addr - delta))
    aliases_apply = any(alias in alias_scope_targets for alias in aliases)
    original_targets = (target_addr, target_addr + delta) if delta else (target_addr,)
    pairs.extend((original_project, candidate) for candidate in original_targets)
    if aliases_apply:
        pairs.extend((project, alias) for alias in aliases if isinstance(alias, int))
        pairs.extend((original_project, alias) for alias in aliases if isinstance(alias, int))
    return tuple(pairs)


def _caller_function_ranges_8616(project: object) -> tuple[tuple[int, int], ...]:
    """Return independently framed original-binary caller ranges."""
    try:
        ranges = cast(_ProjectSurface8616, project)._inertia_caller_function_ranges_8616
    except AttributeError:
        return ()
    if not isinstance(ranges, tuple):
        raise TypeError("caller function ranges must be a tuple")
    return tuple(
        (start, end)
        for start, end in ranges
        if isinstance(start, int) and isinstance(end, int) and end > start
    )


def _direct_call_target_8616(instruction: _Instruction8616) -> int | None:
    """Return one immediate near-call target from typed Capstone fields."""
    if instruction.mnemonic.lower() not in {"call", "lcall"}:
        return None
    operands = tuple(instruction.operands)
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    return operands[0].imm


def _range_callsite_facts_8616(
    project: object,
    target_addr: int,
    function_ranges: tuple[tuple[int, int], ...],
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Summarize matching direct calls from independently framed ranges."""
    surface = cast(_RangeProjectSurface8616, project)
    try:
        disassembler = surface.arch.capstone
        memory = surface.loader.memory
    except AttributeError:
        return ()
    disassembler.detail = True
    facts: list[CalleeCallsiteFact8616] = []
    for start, end in function_ranges:
        try:
            instructions = tuple(disassembler.disasm(bytes(memory.load(start, end - start)), start))
        except (KeyError, TypeError, ValueError):
            continue
        caller = SimpleNamespace(
            project=project,
            addr=start,
            size=end - start,
            block_addrs_set={start},
        )
        for instruction in instructions:
            direct_target = _direct_call_target_8616(instruction)
            if direct_target is None:
                continue
            canonical_target = canonicalize_x86_16_padding_call_target_8616(
                project,
                direct_target,
            )
            if canonical_target != target_addr:
                continue
            summary = summarize_x86_16_callsite(caller, instruction.address)
            if summary is None or summary.stack_probe_helper:
                continue
            facts.append(
                CalleeCallsiteFact8616(
                    evidence_project=project,
                    evidence_target_addr=target_addr,
                    caller_addr=start,
                    callsite_addr=instruction.address,
                    summary=summary,
                )
            )
    return tuple(facts)


def _census_cache_8616(project: object) -> dict[int, CalleeCallsiteCensus8616]:
    """Return the owned per-project direct-caller census cache."""
    surface = cast(_ProjectSurface8616, project)
    try:
        cache = surface._inertia_callee_callsite_census_8616
    except AttributeError:
        cache = {}
        surface._inertia_callee_callsite_census_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("callee callsite census cache must be a dict")
    return cache


def collect_callee_callsite_census_8616(
    project: object,
    target_addr: int,
) -> CalleeCallsiteCensus8616:
    """Collect every direct caller while retaining exact ownership facts."""
    cache = _census_cache_8616(project)
    cached = cache.get(target_addr)
    if cached is not None:
        return cached

    facts: dict[tuple[int, int], CalleeCallsiteFact8616] = {}
    raw_callsites: set[tuple[int, int]] = set()
    visited_projects: set[tuple[int, int]] = set()
    function_ranges = _caller_function_ranges_8616(project)
    for evidence_project, evidence_target in _project_target_pairs_8616(project, target_addr):
        project_key = (id(evidence_project), evidence_target)
        if project_key in visited_projects:
            continue
        visited_projects.add(project_key)
        try:
            functions = tuple(cast(_ProjectSurface8616, evidence_project).kb.functions.values())
        except (AttributeError, TypeError):
            continue
        for function in functions:
            try:
                targets = collect_neighbor_call_targets(function)
            except (AttributeError, KeyError, TypeError, ValueError):
                continue
            for target in targets:
                if target.target_addr != evidence_target:
                    continue
                callsite_key = (id(evidence_project), target.callsite_addr)
                raw_callsites.add(callsite_key)
                if callsite_key in facts and facts[callsite_key].summary is not None:
                    continue
                summary = summarize_x86_16_callsite(function, target.callsite_addr)
                if summary is not None and summary.stack_probe_helper:
                    summary = None
                facts[callsite_key] = CalleeCallsiteFact8616(
                    evidence_project=evidence_project,
                    evidence_target_addr=evidence_target,
                    caller_addr=_function_addr_8616(function),
                    callsite_addr=target.callsite_addr,
                    summary=summary,
                )
        for fact in _range_callsite_facts_8616(
            evidence_project,
            evidence_target,
            function_ranges,
        ):
            callsite_key = (id(evidence_project), fact.callsite_addr)
            raw_callsites.add(callsite_key)
            facts[callsite_key] = fact

    ordered = tuple(facts[key] for key in sorted(raw_callsites, key=lambda item: (item[1], item[0])))
    normalized_count = sum(fact.summary is not None for fact in ordered)
    census = CalleeCallsiteCensus8616(
        target_addr=target_addr,
        facts=ordered,
        raw_fact_count=len(raw_callsites),
        normalized_fact_count=normalized_count,
        failure_count=len(raw_callsites) - normalized_count,
    )
    cache[target_addr] = census
    return census
