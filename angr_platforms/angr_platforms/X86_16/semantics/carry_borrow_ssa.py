"""Exact SSA helpers for carry/borrow semantic classification.

Layer: Semantics.
Responsibility: normalize exact IR operations, temporary definitions, operands,
and dependency traversal used by carry/borrow classification. This module does
not classify aliases, widen values, lower types, or inspect rendered text.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeAlias

from ..ir import IRAddress, IRInstr, IRValue, MemSpace
from .carry_borrow_contracts import (
    CarryBorrowConversion8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowIROp8616,
    CarryBorrowKind8616,
    CarryBorrowMemoryWordUse8616,
    CarryBorrowOperandUse8616,
)

CarryBorrowDefinitions8616: TypeAlias = dict[int, CarryBorrowDefinitionSite8616]


def ir_op_8616(instruction: IRInstr) -> CarryBorrowIROp8616 | None:
    """Normalize one exact IR operation into the admitted operation enum."""
    try:
        return CarryBorrowIROp8616(instruction.op)
    except ValueError:
        return None


def arithmetic_kind_8616(instruction: IRInstr) -> CarryBorrowKind8616 | None:
    """Return the carry/borrow kind of one admitted arithmetic operation."""
    op = ir_op_8616(instruction)
    if op is CarryBorrowIROp8616.ADD16:
        return CarryBorrowKind8616.ADD_WITH_CARRY
    if op is CarryBorrowIROp8616.SUB16:
        return CarryBorrowKind8616.SUB_WITH_BORROW
    return None


def site_value_args_8616(site: CarryBorrowDefinitionSite8616) -> tuple[IRValue, ...]:
    """Return typed value arguments only when every argument is a value."""
    if not all(isinstance(arg, IRValue) for arg in site.instruction.args):
        return ()
    return tuple(arg for arg in site.instruction.args if isinstance(arg, IRValue))


def definition_for_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> CarryBorrowDefinitionSite8616 | None:
    """Resolve one exact temporary use without parsing its display name."""
    if value.source_tmp is None:
        return None
    return definitions.get(value.source_tmp)


def single_source_8616(site: CarryBorrowDefinitionSite8616) -> IRValue | None:
    """Return the only source of one exact typed MOV definition."""
    args = site_value_args_8616(site)
    if ir_op_8616(site.instruction) is not CarryBorrowIROp8616.MOV or len(args) != 1:
        return None
    return args[0]


def conversion_source_8616(
    site: CarryBorrowDefinitionSite8616,
    conversion: CarryBorrowConversion8616,
) -> IRValue | None:
    """Return the source of one exact unary conversion projection."""
    source = single_source_8616(site)
    if source is None or source.expr != (conversion.value,):
        return None
    return source


def is_constant_8616(value: IRValue, expected: int) -> bool:
    """Return whether a value is the expected exact IR constant."""
    return value.space is MemSpace.CONST and value.const == expected


def _value_identity_8616(value: IRValue) -> tuple[object, ...]:
    return (
        value.space,
        value.name,
        value.offset,
        value.const,
        value.size,
        value.version,
        value.expr,
        value.source_tmp,
    )


def same_operands_8616(lhs: Iterable[IRValue], rhs: Iterable[IRValue]) -> bool:
    """Compare arithmetic operands including exact temporary provenance."""
    return tuple(_value_identity_8616(value) for value in lhs) == tuple(
        _value_identity_8616(value) for value in rhs
    )


def operand_use_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> CarryBorrowOperandUse8616 | None:
    """Retain an operand together with its exact temporary definition."""
    if value.space is MemSpace.CONST:
        return CarryBorrowOperandUse8616(value, None)
    definition = definition_for_8616(value, definitions)
    if definition is None:
        return None
    return CarryBorrowOperandUse8616(
        value,
        definition,
        _memory_word_use_8616(definition, definitions),
    )


def _load_byte_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> tuple[CarryBorrowDefinitionSite8616, IRAddress] | None:
    conversion = definition_for_8616(value, definitions)
    if conversion is None:
        return None
    source = conversion_source_8616(
        conversion,
        CarryBorrowConversion8616.WIDEN_BYTE_TO_WORD,
    )
    load = None if source is None else definition_for_8616(source, definitions)
    if (
        load is None
        or ir_op_8616(load.instruction) is not CarryBorrowIROp8616.LOAD
        or load.instruction.dst is None
        or load.instruction.dst.size != 1
        or len(load.instruction.args) != 1
        or not isinstance(load.instruction.args[0], IRAddress)
        or load.instruction.args[0].size != 1
    ):
        return None
    return load, load.instruction.args[0]


def _shifted_high_byte_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> tuple[CarryBorrowDefinitionSite8616, IRAddress] | None:
    shift = definition_for_8616(value, definitions)
    if shift is None or ir_op_8616(shift.instruction) is not CarryBorrowIROp8616.SHL16:
        return None
    args = site_value_args_8616(shift)
    if len(args) != 2 or not is_constant_8616(args[1], 8):
        return None
    return _load_byte_8616(args[0], definitions)


def _memory_word_use_8616(
    definition: CarryBorrowDefinitionSite8616,
    definitions: CarryBorrowDefinitions8616,
) -> CarryBorrowMemoryWordUse8616 | None:
    destination = definition.instruction.dst
    direct_args = definition.instruction.args
    if (
        ir_op_8616(definition.instruction) is CarryBorrowIROp8616.LOAD
        and destination is not None
        and destination.size == 2
        and len(direct_args) == 1
        and isinstance(direct_args[0], IRAddress)
        and direct_args[0].size == 2
    ):
        return CarryBorrowMemoryWordUse8616(
            loads=(definition,),
            addresses=(direct_args[0],),
        )
    if ir_op_8616(definition.instruction) is not CarryBorrowIROp8616.OR16:
        return None
    args = site_value_args_8616(definition)
    if len(args) != 2:
        return None
    choices = tuple(
        (low, high)
        for low_index, low_value in enumerate(args)
        if (low := _load_byte_8616(low_value, definitions)) is not None
        for high_index, high_value in enumerate(args)
        if high_index != low_index
        and (high := _shifted_high_byte_8616(high_value, definitions)) is not None
    )
    if len(choices) != 1:
        return None
    (low_load, low_address), (high_load, high_address) = choices[0]
    return CarryBorrowMemoryWordUse8616(
        loads=(low_load, high_load),
        addresses=(low_address, high_address),
    )


def dependency_arithmetic_sites_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
    kind: CarryBorrowKind8616,
) -> tuple[CarryBorrowDefinitionSite8616, ...]:
    """Collect exact matching arithmetic definitions in one SSA dependency DAG."""
    pending = [value]
    seen: set[int] = set()
    matches: list[CarryBorrowDefinitionSite8616] = []
    while pending:
        current = pending.pop()
        if current.source_tmp is None or current.source_tmp in seen:
            continue
        seen.add(current.source_tmp)
        site = definitions.get(current.source_tmp)
        if site is None:
            continue
        if arithmetic_kind_8616(site.instruction) is kind:
            matches.append(site)
        pending.extend(site_value_args_8616(site))
    return tuple(matches)


__all__ = [
    "CarryBorrowDefinitions8616",
    "arithmetic_kind_8616",
    "conversion_source_8616",
    "definition_for_8616",
    "dependency_arithmetic_sites_8616",
    "ir_op_8616",
    "is_constant_8616",
    "operand_use_8616",
    "same_operands_8616",
    "single_source_8616",
    "site_value_args_8616",
]
