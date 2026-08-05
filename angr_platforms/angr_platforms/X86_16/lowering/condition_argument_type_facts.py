"""Collect stack-argument signedness facts from proven conditions.

Layer: Types/lowering.
Responsibility: normalize direct and transferred ConditionIR operands into
typed positive-BP stack slices for argument type materialization.

Wide facts recorded by Structuring already contain CFG-proven 32-bit meaning.
Raw word facts covered by one such proof are ignored so low-word unsigned
comparisons cannot conflict with the signedness of the logical wide argument.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace

__all__ = [
    "ConditionArgumentFactsResult8616",
    "StackArgumentSignedness8616",
    "StackArgumentTypeFact8616",
    "collect_condition_argument_type_facts_8616",
    "record_wide_condition_argument_type_evidence_8616",
]


class _CodegenFactSurface8616(Protocol):
    """Dynamic condition-transfer metadata consumed by fact collection."""

    _inertia_typed_conditions: object
    _inertia_typed_condition_register_exprs_by_ins_addr_8616: dict[tuple[int, str, int], object]
    _inertia_wide_condition_argument_type_evidence_8616: tuple[ConditionIR, ...]


class StackArgumentSignedness8616(StrEnum):
    """Signedness proven for one logical stack argument."""

    SIGNED = "signed"
    UNSIGNED = "unsigned"


@dataclass(frozen=True, slots=True)
class StackArgumentTypeFact8616:
    """One normalized typed-condition fact for a positive-BP stack slice."""

    offset: int
    size: int
    signedness: StackArgumentSignedness8616
    source: str


@dataclass(frozen=True, slots=True)
class ConditionArgumentFactsResult8616:
    """Closed accounting for normalized stack-argument type facts."""

    facts: tuple[StackArgumentTypeFact8616, ...]
    raw_fact_count: int
    failure_count: int


def record_wide_condition_argument_type_evidence_8616(
    codegen: object,
    condition: ConditionIR,
) -> bool:
    """Record one CFG-proven wide condition for the later Types/Lowering pass."""
    if condition.width_bits != 32 or not (condition.is_signed or condition.is_unsigned):
        return False
    surface = cast(_CodegenFactSurface8616, codegen)
    try:
        existing = surface._inertia_wide_condition_argument_type_evidence_8616
    except AttributeError:
        existing = ()
    if condition in existing:
        return False
    surface._inertia_wide_condition_argument_type_evidence_8616 = (*existing, condition)
    return True


def _stack_slice_8616(operand: object) -> tuple[int, int] | None:
    """Return a direct positive-BP stack slice from one IR operand."""
    if not isinstance(operand, IRValue) or operand.space is not MemSpace.SS or operand.name != "bp":
        return None
    offset = int(operand.offset)
    if offset < 4:
        return None
    return offset, max(1, int(operand.size or 2))


def _registered_stack_slice_8616(
    codegen: object,
    condition: ConditionIR,
    operand: object,
) -> tuple[int, int] | None:
    """Resolve a register operand through typed condition-transfer metadata."""
    direct = _stack_slice_8616(operand)
    if direct is not None:
        return direct
    if not isinstance(operand, IRValue) or operand.space is not MemSpace.REG:
        return None
    if not isinstance(operand.name, str) or not operand.name:
        return None
    bind_addr = condition.producer_insn if isinstance(condition.producer_insn, int) else condition.src_insn
    if not isinstance(bind_addr, int):
        return None
    try:
        expressions = cast(
            _CodegenFactSurface8616,
            codegen,
        )._inertia_typed_condition_register_exprs_by_ins_addr_8616
    except AttributeError:
        return None
    size = max(1, int(operand.size or 2))
    candidates = [
        (ins_addr, expression)
        for (ins_addr, name, expression_size), expression in expressions.items()
        if name.lower() == operand.name.lower() and expression_size == size and ins_addr <= bind_addr
    ]
    if not candidates:
        return None
    expression = max(candidates, key=lambda item: item[0])[1]
    if not isinstance(expression, CVariable) or not isinstance(expression.variable, SimStackVariable):
        return None
    variable = expression.variable
    if variable.base != "bp" or not isinstance(variable.offset, int) or variable.offset < 4:
        return None
    return variable.offset, max(1, int(variable.size or size))


def _condition_facts_8616(
    codegen: object,
    conditions: tuple[ConditionIR, ...],
    source: str,
) -> tuple[StackArgumentTypeFact8616, ...]:
    """Normalize signed or unsigned order predicates into stack-slice facts."""
    facts: list[StackArgumentTypeFact8616] = []
    for condition in conditions:
        if not (condition.is_signed or condition.is_unsigned):
            continue
        signedness = (
            StackArgumentSignedness8616.SIGNED
            if condition.is_signed
            else StackArgumentSignedness8616.UNSIGNED
        )
        for operand in (condition.lhs, condition.rhs):
            stack_slice = _registered_stack_slice_8616(codegen, condition, operand)
            if stack_slice is not None:
                facts.append(StackArgumentTypeFact8616(*stack_slice, signedness, source))
    return tuple(facts)


def collect_condition_argument_type_facts_8616(
    codegen: object,
) -> ConditionArgumentFactsResult8616:
    """Collect wide proofs first and refuse conflicting raw word signedness."""
    surface = cast(_CodegenFactSurface8616, codegen)
    try:
        wide_conditions = surface._inertia_wide_condition_argument_type_evidence_8616
    except AttributeError:
        wide_conditions = ()
    try:
        raw_value = surface._inertia_typed_conditions
    except AttributeError:
        raw_value = ()
    raw_conditions = (
        tuple(condition for condition in raw_value if isinstance(condition, ConditionIR))
        if isinstance(raw_value, (list, tuple))
        else ()
    )
    wide_facts = _condition_facts_8616(codegen, wide_conditions, "wide-condition")
    covered = tuple((fact.offset, fact.offset + fact.size) for fact in wide_facts)
    raw_facts = tuple(
        fact
        for fact in _condition_facts_8616(codegen, raw_conditions, "condition")
        if not any(start <= fact.offset and fact.offset + fact.size <= end for start, end in covered)
    )
    grouped: dict[tuple[int, int], list[StackArgumentTypeFact8616]] = {}
    for fact in (*wide_facts, *raw_facts):
        grouped.setdefault((fact.offset, fact.size), []).append(fact)
    selected: list[StackArgumentTypeFact8616] = []
    failures = 0
    for candidates in grouped.values():
        if len({candidate.signedness for candidate in candidates}) != 1:
            failures += 1
            continue
        selected.append(candidates[0])
    return ConditionArgumentFactsResult8616(
        tuple(selected),
        len(wide_conditions) + len(raw_conditions),
        failures,
    )
