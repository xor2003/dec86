"""Collect direct-caller facts from independently framed binary ranges.

Layer: Types/Lowering.
Responsibility: decode each supplied caller range once, retain exact direct-call
coordinates, and bind existing recovery summaries to canonical callee targets.
This module does not derive argument interfaces or mutate generated C.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM

from ..analysis_helpers import canonicalize_x86_16_padding_call_target_8616
from ..callsite_summary import summarize_x86_16_callsite
from ..frontend_function_boundary_index import exact_function_range_inventory_8616
from .callee_callsite_contracts import CalleeCallsiteFact8616

__all__ = [
    "collect_range_callsite_facts_8616",
    "collect_range_callsite_facts_for_target_8616",
]


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


def _direct_call_target_8616(instruction: _Instruction8616) -> int | None:
    """Return one immediate near/far-call target."""
    if instruction.mnemonic.lower() not in {"call", "lcall"}:
        return None
    operands = tuple(instruction.operands)
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    return operands[0].imm


def collect_range_callsite_facts_8616(
    project: object,
    function_ranges: tuple[tuple[int, int], ...],
    *,
    excluded_fact_keys: frozenset[tuple[int, int]] = frozenset(),
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Summarize all direct calls while decoding every exact range once."""
    surface = cast(_RangeProjectSurface8616, project)
    try:
        disassembler = surface.arch.capstone
        memory = surface.loader.memory
    except AttributeError:
        return ()
    disassembler.detail = True
    inventory = exact_function_range_inventory_8616(project, function_ranges)
    boundaries = {
        (item.addr, item.addr + item.size): item for item in inventory.boundaries
    }
    facts: list[CalleeCallsiteFact8616] = []
    for start, end in function_ranges:
        try:
            instructions = tuple(
                disassembler.disasm(bytes(memory.load(start, end - start)), start)
            )
        except (KeyError, TypeError, ValueError):
            continue
        caller = boundaries.get((start, end))
        for instruction in instructions:
            direct_target = _direct_call_target_8616(instruction)
            if direct_target is None:
                continue
            target_addr = canonicalize_x86_16_padding_call_target_8616(
                project,
                direct_target,
            )
            if (target_addr, instruction.address) in excluded_fact_keys:
                continue
            summary = (
                None
                if caller is None
                else summarize_x86_16_callsite(caller, instruction.address)
            )
            if summary is None or summary.stack_probe_helper:
                continue
            facts.append(
                CalleeCallsiteFact8616(
                    evidence_project=project,
                    caller_function=caller,
                    evidence_target_addr=target_addr,
                    caller_addr=start,
                    callsite_addr=instruction.address,
                    summary=summary,
                )
            )
    return tuple(facts)


def collect_range_callsite_facts_for_target_8616(
    project: object,
    target_addr: int,
    function_ranges: tuple[tuple[int, int], ...],
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Build exact caller facts after a bounded direct-target prefilter."""
    surface = cast(_RangeProjectSurface8616, project)
    try:
        disassembler = surface.arch.capstone
        memory = surface.loader.memory
    except AttributeError:
        return ()
    disassembler.detail = True
    matching_calls: list[tuple[tuple[int, int], _Instruction8616]] = []
    for start, end in function_ranges:
        try:
            instructions = tuple(
                disassembler.disasm(bytes(memory.load(start, end - start)), start)
            )
        except (KeyError, TypeError, ValueError):
            continue
        for instruction in instructions:
            direct_target = _direct_call_target_8616(instruction)
            if direct_target is None:
                continue
            canonical_target = canonicalize_x86_16_padding_call_target_8616(
                project,
                direct_target,
            )
            if canonical_target == target_addr:
                matching_calls.append(((start, end), instruction))
    if not matching_calls:
        return ()

    matching_ranges = tuple(dict.fromkeys(item[0] for item in matching_calls))
    inventory = exact_function_range_inventory_8616(project, matching_ranges)
    boundaries = {
        (item.addr, item.addr + item.size): item for item in inventory.boundaries
    }
    facts: list[CalleeCallsiteFact8616] = []
    for caller_range, instruction in matching_calls:
        caller = boundaries.get(caller_range)
        summary = (
            None
            if caller is None
            else summarize_x86_16_callsite(caller, instruction.address)
        )
        if summary is None or summary.stack_probe_helper:
            continue
        facts.append(
            CalleeCallsiteFact8616(
                evidence_project=project,
                caller_function=caller,
                evidence_target_addr=target_addr,
                caller_addr=caller_range[0],
                callsite_addr=instruction.address,
                summary=summary,
            )
        )
    return tuple(facts)
