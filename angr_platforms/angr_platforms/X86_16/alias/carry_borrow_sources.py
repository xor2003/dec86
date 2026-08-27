"""Resolve exact carry/borrow operand carriers at the Alias boundary.

Layer: Alias.
Responsibility: classify Semantics operands as canonical full-register,
segmented-memory, or immutable constant carriers while retaining exact SSA and
original-address provenance. This module does not widen values or inspect C.
Owns storage identity and source carrier identity only.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..ir import IRValue, MemSpace
from ..ir.logical_memory_contracts import (
    logical_memory_byte_offset_8616,
    logical_memory_execution_address_matches_8616,
)
from ..semantics.carry_borrow_contracts import (
    CarryBorrowIROp8616,
    CarryBorrowOperandUse8616,
)
from .alias_model_impl import AliasStorageFacts, alias_facts_for_ir_address_8616
from .carry_borrow_contracts import (
    CarryBorrowAliasFailure8616,
    CarryBorrowOperandAlias8616,
)
from .domains import FULL16, DomainKey, register_domain_for_name, register_view_for_name
from .storage_fact_join import build_segmented_alias_range_8616


def register_domain_for_value_8616(value: IRValue) -> DomainKey | None:
    """Return the canonical full-width register domain for one exact value."""
    if value.space is not MemSpace.REG or value.size != 2:
        return None
    if register_view_for_name(value.name) != FULL16:
        return None
    return register_domain_for_name(value.name)


def _constant_source_alias_8616(
    use: CarryBorrowOperandUse8616,
) -> CarryBorrowOperandAlias8616 | CarryBorrowAliasFailure8616:
    value = use.value
    if value.space is not MemSpace.CONST or value.size != 2 or not isinstance(value.const, int):
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    return CarryBorrowOperandAlias8616(
        use=use,
        source=value,
        constant=value,
    )


def _register_source_alias_8616(
    use: CarryBorrowOperandUse8616,
) -> CarryBorrowOperandAlias8616 | CarryBorrowAliasFailure8616:
    definition = use.definition
    if definition is None or use.value.source_tmp is None:
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    destination = definition.instruction.dst
    args = definition.instruction.args
    if (
        definition.instruction.op != CarryBorrowIROp8616.MOV.value
        or destination is None
        or destination.source_tmp != use.value.source_tmp
        or len(args) != 1
        or not isinstance(args[0], IRValue)
    ):
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    source = args[0]
    source_domain = register_domain_for_value_8616(source)
    use_domain = register_domain_for_value_8616(use.value)
    if source_domain is None or use_domain != source_domain or source.version != use.value.version:
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    return CarryBorrowOperandAlias8616(
        use=use,
        source=source,
        register_domain=source_domain,
    )


def _memory_word_alias_8616(
    use: CarryBorrowOperandUse8616,
) -> CarryBorrowOperandAlias8616 | CarryBorrowAliasFailure8616:
    definition = use.definition
    memory_word = use.memory_word
    if definition is None or memory_word is None or use.value.source_tmp is None:
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    destination = definition.instruction.dst
    execution_loads = memory_word.execution_loads
    logical_address = memory_word.logical_address
    if len(execution_loads) == 1:
        expected_op = CarryBorrowIROp8616.LOAD
    elif len(execution_loads) == 2:
        expected_op = CarryBorrowIROp8616.OR16
    else:
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    if (
        definition.instruction.op != expected_op.value
        or destination is None
        or destination.source_tmp != use.value.source_tmp
        or memory_word.size != 2
    ):
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    if expected_op is CarryBorrowIROp8616.LOAD and execution_loads[0].site != definition:
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    for execution_load in execution_loads:
        load = execution_load.site
        address = execution_load.address
        load_destination = load.instruction.dst
        if (
            load.instruction.op != CarryBorrowIROp8616.LOAD.value
            or load_destination is None
            or load_destination.source_tmp is None
            or load_destination.size != address.size
            or load.instruction.args != (address,)
        ):
            return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    execution_addresses = tuple(item.address for item in execution_loads)
    if sum(address.size for address in execution_addresses) != memory_word.size:
        return CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    first_execution = execution_addresses[0]
    if any(
        address.space is not first_execution.space
        for address in execution_addresses[1:]
    ) or logical_address.space is not first_execution.space:
        return CarryBorrowAliasFailure8616.SEGMENT_MISMATCH
    if any(
        not logical_memory_execution_address_matches_8616(
            current,
            logical_address,
            source_byte_offset,
            memory_word.address_bits,
        )
        for source_byte_offset, current in enumerate(execution_addresses)
    ):
        return CarryBorrowAliasFailure8616.SOURCE_RANGE_MISMATCH
    if (
        not logical_address.base
        and logical_memory_byte_offset_8616(
            logical_address,
            memory_word.size - 1,
            memory_word.address_bits,
        )
        < logical_memory_byte_offset_8616(
            logical_address,
            0,
            memory_word.address_bits,
        )
    ):
        return CarryBorrowAliasFailure8616.SOURCE_RANGE_WRAP_UNSUPPORTED
    classified = alias_facts_for_ir_address_8616(logical_address)
    if not isinstance(classified, AliasStorageFacts):
        return CarryBorrowAliasFailure8616.SOURCE_ALIAS_UNPROVEN
    memory = build_segmented_alias_range_8616((logical_address,), (classified,))
    if memory is None or memory.size != 2:
        return CarryBorrowAliasFailure8616.SOURCE_ALIAS_UNPROVEN
    return CarryBorrowOperandAlias8616(
        use=use,
        source=use.value,
        memory=memory,
    )


def resolve_carry_borrow_source_alias_8616(
    use: CarryBorrowOperandUse8616,
) -> CarryBorrowOperandAlias8616 | CarryBorrowAliasFailure8616:
    """Resolve one exact Semantics operand or return a typed Alias refusal."""
    if use.value.space is MemSpace.CONST:
        return _constant_source_alias_8616(use)
    if use.memory_word is not None:
        return _memory_word_alias_8616(use)
    return _register_source_alias_8616(use)


__all__ = [
    "register_domain_for_value_8616",
    "resolve_carry_borrow_source_alias_8616",
]
