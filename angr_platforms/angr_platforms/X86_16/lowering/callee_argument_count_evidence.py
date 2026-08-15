"""Aggregate binary caller evidence for one callee's logical argument count.

Layer: Types/Lowering.
Responsibility: join direct incoming callsite summaries by callee address and
publish a typed, closed-census logical arity verdict for interface lowering.
Consumes alias, widening, and typed facts, including binary callsite summaries.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import StrEnum
from types import SimpleNamespace
from typing import Iterable, Protocol, Sequence, cast

from capstone.x86_const import X86_OP_IMM

from ..analysis_helpers import (
    canonicalize_x86_16_padding_call_target_8616,
    collect_neighbor_call_targets,
)
from ..callsite_summary import (
    CallsiteSummary8616,
    logical_argument_widths_from_callsite_8616,
    summarize_x86_16_callsite,
)

_LOGGER = logging.getLogger(__name__)


class CalleeArgumentCountVerdict8616(StrEnum):
    """Typed outcome of joining all discovered direct callers."""

    UNKNOWN = "unknown"
    CONSISTENT = "consistent"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class CalleeArgumentCountEvidence8616:
    """Closed evidence census for one callee's incoming logical arity."""

    target_addr: int
    verdict: CalleeArgumentCountVerdict8616
    argument_count: int | None = None
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    callsite_addrs: tuple[int, ...] = ()
    callsite_summaries: tuple[CallsiteSummary8616, ...] = field(
        default=(),
        compare=False,
    )


class _FunctionManager8616(Protocol):
    """Third-party angr function-manager surface used for caller discovery."""

    def values(self) -> Iterable[SimpleNamespace]:
        """Return discovered functions and stubs."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party angr knowledge-base surface used by this collector."""

    functions: _FunctionManager8616


class _ProjectSurface8616(Protocol):
    """angr project plus owned Inertia evidence extensions."""

    kb: _KnowledgeBase8616
    _inertia_original_project: object
    _inertia_original_linear_delta: int
    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_caller_target_aliases_8616: tuple[int, ...]
    _inertia_caller_evidence_project_8616: object
    _inertia_caller_evidence_target_8616: int
    _inertia_callee_argument_count_evidence_8616: dict[int, CalleeArgumentCountEvidence8616]


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


def _logical_argument_count_8616(summary: CallsiteSummary8616) -> int | None:
    """Project one summary to logical arity without splitting wide values."""
    if summary.logical_arg_widths:
        return len(summary.logical_arg_widths)
    argument_count = summary.arg_count
    if isinstance(argument_count, int) and argument_count in {0, 1} and len(summary.arg_widths) == argument_count:
        return argument_count
    if not isinstance(summary.arg_count, int) or summary.arg_count < 0:
        return None
    widths = logical_argument_widths_from_callsite_8616(
        summary,
        expected_arg_count=summary.arg_count,
    )
    return len(widths) if widths is not None else None


def _same_near_target_8616(left: int, right: int) -> bool:
    """Match linear or same-segment normalized x86-16 near targets."""
    return left == right or (left & 0xFFFF) == (right & 0xFFFF)


def _project_target_pairs_8616(project: object, target_addr: int) -> tuple[tuple[object, int], ...]:
    """Return active/original project targets across exact-slice rebasing."""
    active = cast(_ProjectSurface8616, project)
    pairs: list[tuple[object, int]] = [(project, target_addr)]
    try:
        caller_evidence_project = active._inertia_caller_evidence_project_8616
        caller_evidence_target = active._inertia_caller_evidence_target_8616
    except AttributeError:
        caller_evidence_project = None
        caller_evidence_target = None
    if caller_evidence_project is not None and isinstance(caller_evidence_target, int):
        pairs.append((caller_evidence_project, caller_evidence_target))
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


def _range_callsite_summaries_8616(
    project: object,
    target_addr: int,
    function_ranges: tuple[tuple[int, int], ...],
) -> tuple[CallsiteSummary8616, ...]:
    """Summarize matching direct calls from independently framed ranges."""
    surface = cast(_RangeProjectSurface8616, project)
    try:
        disassembler = surface.arch.capstone
        memory = surface.loader.memory
    except AttributeError:
        return ()
    disassembler.detail = True
    summaries: list[CallsiteSummary8616] = []
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
            direct_target = canonicalize_x86_16_padding_call_target_8616(
                project,
                direct_target,
            )
            if direct_target is None:
                continue
            if not _same_near_target_8616(direct_target, target_addr):
                continue
            summary = summarize_x86_16_callsite(caller, instruction.address)
            if summary is not None and not summary.stack_probe_helper:
                summaries.append(summary)
    return tuple(summaries)


def _evidence_cache_8616(project: object) -> dict[int, CalleeArgumentCountEvidence8616]:
    """Return the owned per-project arity evidence cache."""
    surface = cast(_ProjectSurface8616, project)
    try:
        cache = surface._inertia_callee_argument_count_evidence_8616
    except AttributeError:
        cache = {}
        surface._inertia_callee_argument_count_evidence_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("callee argument-count evidence cache must be a dict")
    return cache


def collect_callee_argument_count_evidence_8616(
    project: object,
    target_addr: int,
) -> CalleeArgumentCountEvidence8616:
    """Collect and join logical argument counts from direct binary callers."""
    cache = _evidence_cache_8616(project)
    cached = cache.get(target_addr)
    if cached is not None:
        return cached

    raw_callsites: set[tuple[int, int]] = set()
    summaries: dict[tuple[int, int], CallsiteSummary8616] = {}
    counts: dict[tuple[int, int], int] = {}
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
                if not _same_near_target_8616(target.target_addr, evidence_target):
                    continue
                callsite_key = (id(evidence_project), target.callsite_addr)
                raw_callsites.add(callsite_key)
                if callsite_key in summaries:
                    continue
                summary = summarize_x86_16_callsite(function, target.callsite_addr)
                if summary is None or summary.stack_probe_helper:
                    continue
                summaries[callsite_key] = summary
                count = _logical_argument_count_8616(summary)
                if count is not None:
                    counts[callsite_key] = count
        for summary in _range_callsite_summaries_8616(
            evidence_project,
            evidence_target,
            function_ranges,
        ):
            callsite_key = (id(evidence_project), summary.callsite_addr)
            raw_callsites.add(callsite_key)
            summaries[callsite_key] = summary
            count = _logical_argument_count_8616(summary)
            if count is not None:
                counts[callsite_key] = count

    distinct_counts = set(counts.values())
    if len(distinct_counts) == 1:
        verdict = CalleeArgumentCountVerdict8616.CONSISTENT
        argument_count = next(iter(distinct_counts))
    elif len(distinct_counts) > 1:
        verdict = CalleeArgumentCountVerdict8616.CONFLICT
        argument_count = None
    else:
        verdict = CalleeArgumentCountVerdict8616.UNKNOWN
        argument_count = None
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        argument_count=argument_count,
        raw_fact_count=len(raw_callsites),
        normalized_fact_count=len(summaries),
        classified_fact_count=len(counts),
        materialized_count=len(counts),
        failure_count=len(raw_callsites) - len(counts) + int(verdict is CalleeArgumentCountVerdict8616.CONFLICT),
        callsite_addrs=tuple(sorted(callsite_addr for _project_id, callsite_addr in raw_callsites)),
        callsite_summaries=tuple(
            summaries[key]
            for key in sorted(summaries, key=lambda item: (item[1], item[0]))
        ),
    )
    if os.environ.get("INERTIA_DEBUG_CALLEE_ARITY") == "1":
        _LOGGER.warning(
            "callee arity evidence target=%#x verdict=%s count=%s ranges=%d raw=%d normalized=%d classified=%d failures=%d callsites=%s",
            target_addr,
            evidence.verdict.value,
            evidence.argument_count,
            len(function_ranges),
            evidence.raw_fact_count,
            evidence.normalized_fact_count,
            evidence.classified_fact_count,
            evidence.failure_count,
            evidence.callsite_addrs,
        )
    cache[target_addr] = evidence
    return evidence


__all__ = [
    "CalleeArgumentCountEvidence8616",
    "CalleeArgumentCountVerdict8616",
    "collect_callee_argument_count_evidence_8616",
]
