"""Recover pointer parameter classes from bounded callee machine evidence.

Layer: Types/lowering.
Responsibility: prove which BP-based parameters are dereferenced as near
pointers, materialize those parameter types, and expose typed evidence to
callsite lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence, cast

from angr.sim_type import SimType, SimTypeFunction
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_INVALID,
)

from .callee_argument_interface import materialize_callee_pointer_prefix_prototype_8616


class _FunctionBoundary8616(Protocol):
    """Typed third-party function fields updated by pointer-class lowering."""

    addr: int
    prototype: object | None


class _FunctionManagerBoundary8616(Protocol):
    """Third-party function lookup used for address-based evidence queries."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return one discovered function without creating a guessed one."""


class _KnowledgeBaseBoundary8616(Protocol):
    """Third-party knowledge-base surface used by pointer evidence."""

    functions: _FunctionManagerBoundary8616


class _ProjectFunctionBoundary8616(Protocol):
    """Third-party project surface used for exact function lookup."""

    kb: _KnowledgeBaseBoundary8616


@dataclass(frozen=True, slots=True)
class CalleePointerArgumentEvidence8616:
    """Closed evidence loop for one callee's near-pointer parameter classes."""

    target_addr: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    pointer_stack_offsets: tuple[int, ...]
    pointer_argument_indices: tuple[int, ...]
    ambiguous_displaced_stack_offsets: tuple[int, ...]


class _ProjectEvidenceCarrier8616(Protocol):
    """Owned lowering evidence registry carried across one angr project."""

    _inertia_callee_pointer_argument_evidence_8616: dict[
        int,
        CalleePointerArgumentEvidence8616,
    ]


def _project_evidence_registry_8616(
    project: object,
) -> dict[int, CalleePointerArgumentEvidence8616]:
    """Return the active project's owned typed pointer-evidence registry."""
    carrier = cast(_ProjectEvidenceCarrier8616, project)
    try:
        return carrier._inertia_callee_pointer_argument_evidence_8616
    except AttributeError:
        registry: dict[int, CalleePointerArgumentEvidence8616] = {}
        carrier._inertia_callee_pointer_argument_evidence_8616 = registry
        return registry


def _instruction(value: object) -> object:
    """Return the capstone instruction behind angr's optional wrapper."""
    return cast(Any, value).insn if hasattr(value, "insn") else value


def _bounded_instructions_8616(
    project: object,
    address: int,
    *,
    scan_size: int,
) -> tuple[object, ...]:
    """Decode one bounded linear callee body through its first return."""
    if address < 0 or not 16 <= scan_size <= 4096:
        return ()
    try:
        block = cast(Any, project).factory.block(
            address,
            size=scan_size,
            opt_level=0,
        )
        wrapped_instructions = tuple(block.capstone.insns or ())
    except (AttributeError, KeyError, TypeError, ValueError):
        return ()
    instructions: list[object] = []
    for wrapped in wrapped_instructions:
        insn = _instruction(wrapped)
        instructions.append(insn)
        if str(cast(Any, insn).mnemonic).lower() in {"ret", "retf", "iret"}:
            break
    if not instructions or str(cast(Any, instructions[-1]).mnemonic).lower() not in {
        "ret",
        "retf",
        "iret",
    }:
        return ()
    return tuple(instructions)


def _pointer_stack_offsets_8616(
    instructions: Sequence[object],
) -> tuple[int, tuple[int, ...], tuple[int, ...]]:
    """Classify direct carrier dereferences and displaced-only ambiguities."""
    carriers: dict[int, int] = {}
    observed_offsets: set[int] = set()
    pointer_offsets: list[int] = []
    raw_fact_count = 0
    for insn_value in instructions:
        insn = cast(Any, insn_value)
        operands = tuple(insn.operands)
        for operand in operands:
            if operand.type != X86_OP_MEM:
                continue
            stack_offset = carriers.get(int(operand.mem.base))
            if stack_offset is None or int(operand.size) <= 0:
                continue
            raw_fact_count += 1
            observed_offsets.add(stack_offset)
            if (
                int(operand.mem.index) == X86_REG_INVALID
                and int(operand.mem.disp) == 0
            ):
                pointer_offsets.append(stack_offset)
        if insn.id in {X86_INS_CALL, X86_INS_LCALL}:
            carriers.clear()
            continue
        if not operands or operands[0].type != X86_OP_REG:
            continue
        destination_register = int(operands[0].reg)
        if insn.id == X86_INS_ADD and destination_register in carriers:
            continue
        if insn.id != X86_INS_MOV or len(operands) != 2:
            carriers.pop(destination_register, None)
            continue
        source = operands[1]
        if (
            source.type == X86_OP_MEM
            and int(source.mem.base) == X86_REG_BP
            and int(source.mem.index) == X86_REG_INVALID
            and int(source.mem.disp) >= 4
            and int(source.size) == 2
        ):
            carriers[destination_register] = int(source.mem.disp)
            continue
        if source.type == X86_OP_REG and int(source.reg) in carriers:
            carriers[destination_register] = carriers[int(source.reg)]
            continue
        carriers.pop(destination_register, None)
    proven_offsets = tuple(sorted(set(pointer_offsets)))
    ambiguous_offsets = tuple(sorted(observed_offsets - set(proven_offsets)))
    return raw_fact_count, proven_offsets, ambiguous_offsets


def _prototype_stack_offsets_8616(
    prototype: SimTypeFunction,
) -> dict[int, int] | None:
    """Map exact two-byte BP parameter slots to source argument indices."""
    offsets: dict[int, int] = {}
    stack_offset = 4
    for index, argument_type in enumerate(tuple(prototype.args or ())):
        try:
            size_bits = cast(SimType, argument_type).size
        except (AttributeError, ValueError):
            return None
        if not isinstance(size_bits, int) or size_bits <= 0 or size_bits % 8:
            return None
        size_bytes = size_bits // 8
        if size_bytes == 2:
            offsets[stack_offset] = index
        stack_offset += size_bytes
    return offsets


def _contiguous_pointer_prefix_indices_8616(
    pointer_offsets: tuple[int, ...],
) -> tuple[int, ...]:
    """Map only a contiguous two-byte pointer prefix without a prototype."""
    expected_offsets = tuple(
        range(4, 4 + 2 * len(pointer_offsets), 2)
    )
    if pointer_offsets != expected_offsets:
        return ()
    return tuple(range(len(pointer_offsets)))


def apply_callee_pointer_argument_evidence_at_address_8616(
    project: object,
    function: object,
    address: int,
    *,
    scan_size: int = 512,
) -> bool:
    """Promote parameter slots proven to feed near-pointer dereferences."""
    instructions = _bounded_instructions_8616(
        project,
        address,
        scan_size=scan_size,
    )
    raw_count, pointer_offsets, ambiguous_offsets = _pointer_stack_offsets_8616(
        instructions
    )
    typed_function = cast(_FunctionBoundary8616, function)
    prototype = typed_function.prototype
    offset_to_index = (
        _prototype_stack_offsets_8616(prototype)
        if isinstance(prototype, SimTypeFunction)
        else None
    )
    prototype_pointer_indices = (
        tuple(offset_to_index[offset] for offset in pointer_offsets if offset in offset_to_index)
        if offset_to_index is not None
        else ()
    )
    pointer_indices = (
        prototype_pointer_indices
        if len(prototype_pointer_indices) == len(pointer_offsets)
        else _contiguous_pointer_prefix_indices_8616(pointer_offsets)
    )
    classified_count = len(pointer_indices)
    materialize_callee_pointer_prefix_prototype_8616(
        project,
        typed_function,
        pointer_indices,
    )
    evidence = CalleePointerArgumentEvidence8616(
        target_addr=address,
        raw_fact_count=raw_count,
        normalized_fact_count=len(pointer_offsets),
        classified_fact_count=classified_count,
        materialized_count=classified_count,
        failure_count=(
            max(0, len(pointer_offsets) - classified_count)
            + len(ambiguous_offsets)
        ),
        pointer_stack_offsets=pointer_offsets,
        pointer_argument_indices=pointer_indices,
        ambiguous_displaced_stack_offsets=ambiguous_offsets,
    )
    _project_evidence_registry_8616(project)[typed_function.addr] = evidence
    return classified_count > 0 and evidence.failure_count == 0


def callee_pointer_argument_is_proven_8616(
    project: object,
    callee_name: str,
    argument_index: int,
) -> bool:
    """Return whether typed callee evidence proves one pointer argument."""
    try:
        functions = cast(Any, project).kb.functions
        function = functions.function(name=callee_name, create=False)
    except (AttributeError, KeyError, TypeError):
        return False
    if function is None:
        return False
    function_addr = cast(_FunctionBoundary8616, function).addr
    registry = _project_evidence_registry_8616(project)
    evidence = registry.get(function_addr)
    if evidence is None:
        apply_callee_pointer_argument_evidence_at_address_8616(
            project,
            function,
            function_addr,
        )
        evidence = registry.get(function_addr)
    return (
        isinstance(evidence, CalleePointerArgumentEvidence8616)
        and argument_index in evidence.pointer_argument_indices
    )


def callee_pointer_argument_indices_at_address_8616(
    project: object,
    function_addr: int,
) -> tuple[int, ...]:
    """Return exact binary-proven pointer argument indices for one address."""
    evidence = callee_pointer_argument_evidence_at_address_8616(project, function_addr)
    if (
        evidence is None
        or evidence.failure_count != 0
        or evidence.classified_fact_count == 0
        or evidence.materialized_count != evidence.classified_fact_count
    ):
        return ()
    return evidence.pointer_argument_indices


def callee_pointer_argument_evidence_at_address_8616(
    project: object,
    function_addr: int,
) -> CalleePointerArgumentEvidence8616 | None:
    """Return retained binary pointer evidence, including typed ambiguities."""
    registry = _project_evidence_registry_8616(project)
    evidence = registry.get(function_addr)
    if evidence is None:
        try:
            function = cast(_ProjectFunctionBoundary8616, project).kb.functions.function(
                addr=function_addr,
                create=False,
            )
        except (AttributeError, KeyError, TypeError):
            return None
        if function is None:
            return None
        apply_callee_pointer_argument_evidence_at_address_8616(
            project,
            function,
            function_addr,
        )
        evidence = registry.get(cast(_FunctionBoundary8616, function).addr)
    return evidence if isinstance(evidence, CalleePointerArgumentEvidence8616) else None
