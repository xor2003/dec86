"""Bind carry-linked register results to exact Alias-proven stack stores.

Layer: Alias.
Responsibility: prove direct function-SSA value flow from both result registers
to one adjacent pair of stack-memory Alias facts. This module does not join the
pair, infer a C type, mutate codegen, or inspect rendered C/assembly text.
Owns storage identity and exact definition-to-store carrier identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir import IRInstr, IRValue, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
from .carry_borrow_projection import (
    CarryBorrowAliasEvidence8616,
    CarryBorrowAliasFact8616,
)
from .domains import DomainKey, register_domain_for_name
from .stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasArtifact8616,
    StackMemorySSAAliasFact8616,
)


class CarryBorrowDestinationAliasVerdict8616(StrEnum):
    """Stable Alias outcome for one observed destination-store candidate."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CarryBorrowDestinationAliasFailure8616(StrEnum):
    """Stable reason a result-store pair lacks exact Alias proof."""

    AMBIGUOUS_STORE = "ambiguous_store"
    CROSS_BLOCK_FLOW = "cross_block_flow"
    DESTINATION_ALIAS_MISMATCH = "destination_alias_mismatch"
    DESTINATION_RANGE_MISMATCH = "destination_range_mismatch"
    FUNCTION_IDENTITY_MISMATCH = "function_identity_mismatch"
    PARTIAL_STORE = "partial_store"
    STORE_ORDER_MISMATCH = "store_order_mismatch"


@dataclass(frozen=True, slots=True)
class CarryBorrowDestinationAliasFact8616:
    """Exact low/high result stores retaining source carry and stack Alias facts."""

    carry: CarryBorrowAliasFact8616
    low_store: StackMemorySSAAliasFact8616
    high_store: StackMemorySSAAliasFact8616


@dataclass(frozen=True, slots=True)
class CarryBorrowDestinationAliasResolution8616:
    """Proven destination pair or typed refusal for one observed store flow."""

    carry: CarryBorrowAliasFact8616
    verdict: CarryBorrowDestinationAliasVerdict8616
    fact: CarryBorrowDestinationAliasFact8616 | None = None
    failure: CarryBorrowDestinationAliasFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class CarryBorrowDestinationAliasStats8616:
    """Closed accounting for observed destination-store candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every observed candidate has one retained outcome."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class CarryBorrowDestinationAliasEvidence8616:
    """Function-level destination pairs and explicit refusals."""

    function_addr: int
    resolutions: tuple[CarryBorrowDestinationAliasResolution8616, ...]
    stats: CarryBorrowDestinationAliasStats8616

    @property
    def facts(self) -> tuple[CarryBorrowDestinationAliasFact8616, ...]:
        """Return proven destination pairs in deterministic order."""
        return tuple(item.fact for item in self.resolutions if item.fact is not None)

    @property
    def complete(self) -> bool:
        """Return whether result count and evidence accounting are closed."""
        return self.stats.complete and len(self.resolutions) == self.stats.raw_fact_count


def _register_domain(value: IRValue) -> DomainKey | None:
    if value.space is not MemSpace.REG or value.size != 2:
        return None
    return register_domain_for_name(value.name)


def _direct_store_copies_domain(
    instructions: tuple[IRInstr, ...],
    store_index: int,
    expected: IRValue,
    expected_domain: DomainKey,
) -> bool:
    store = instructions[store_index]
    if store.op != "STORE" or len(store.args) != 2 or not isinstance(store.args[1], IRValue):
        return False
    data = store.args[1]
    if data.source_tmp is None or _register_domain(data) != expected_domain:
        return False
    definitions = tuple(
        (index, instruction)
        for index, instruction in enumerate(instructions[:store_index])
        if instruction.dst is not None and instruction.dst.source_tmp == data.source_tmp
    )
    if len(definitions) != 1:
        return False
    definition_index, definition = definitions[0]
    if definition.op != "MOV" or len(definition.args) != 1 or not isinstance(definition.args[0], IRValue):
        return False
    source = definition.args[0]
    if _register_domain(source) != expected_domain or source.version != expected.version:
        return False
    return not any(
        instruction.dst is not None
        and _register_domain(instruction.dst) == expected_domain
        for instruction in instructions[definition_index + 1 : store_index]
    )


def _stores_for_result(
    function_ssa: SSAFunctionArtifact,
    stack_aliases: StackMemorySSAAliasArtifact8616,
    result: IRValue,
    domain: DomainKey,
) -> tuple[StackMemorySSAAliasFact8616, ...]:
    blocks = {block.addr: block for block in function_ssa.blocks}
    stores: list[StackMemorySSAAliasFact8616] = []
    for fact in stack_aliases.facts:
        index = fact.instr_index
        block = blocks.get(fact.block_addr)
        if (
            fact.kind is StackMemoryAliasFactKind8616.STORE
            and isinstance(index, int)
            and block is not None
            and 0 <= index < len(block.instrs)
            and _direct_store_copies_domain(block.instrs, index, result, domain)
        ):
            stores.append(fact)
    return tuple(stores)


def _refusal(
    carry: CarryBorrowAliasFact8616,
    failure: CarryBorrowDestinationAliasFailure8616,
) -> CarryBorrowDestinationAliasResolution8616:
    return CarryBorrowDestinationAliasResolution8616(
        carry=carry,
        verdict=CarryBorrowDestinationAliasVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
    )


def _resolve_destination(
    function_ssa: SSAFunctionArtifact,
    stack_aliases: StackMemorySSAAliasArtifact8616,
    carry: CarryBorrowAliasFact8616,
) -> CarryBorrowDestinationAliasResolution8616 | None:
    link = carry.link
    low_result = link.low_result_write.instruction.dst
    high_result = link.high_result_write.instruction.dst
    if low_result is None or high_result is None:
        return None
    low_stores = _stores_for_result(function_ssa, stack_aliases, low_result, carry.low_result_domain)
    high_stores = _stores_for_result(function_ssa, stack_aliases, high_result, carry.high_result_domain)
    if not low_stores and not high_stores:
        return None
    if not low_stores or not high_stores:
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.PARTIAL_STORE)
    if len(low_stores) != 1 or len(high_stores) != 1:
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.AMBIGUOUS_STORE)
    low_store, high_store = low_stores[0], high_stores[0]
    if low_store.block_addr != high_store.block_addr or low_store.block_addr != link.high_result_write.block_addr:
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.CROSS_BLOCK_FLOW)
    low_index = low_store.instr_index
    high_index = high_store.instr_index
    if (
        not isinstance(low_index, int)
        or not isinstance(high_index, int)
        or low_index <= link.high_result_write.instr_index
        or high_index <= low_index
    ):
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.STORE_ORDER_MISMATCH)
    low_address = low_store.address
    high_address = high_store.address
    if (
        low_address.space is not high_address.space
        or low_address.base != high_address.base
        or low_address.size != high_address.size
        or low_address.size != 2
        or high_address.offset != low_address.offset + low_address.size
        or low_address.status is not high_address.status
        or low_address.segment_origin is not high_address.segment_origin
    ):
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.DESTINATION_RANGE_MISMATCH)
    if not low_store.storage.can_join(high_store.storage):
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.DESTINATION_ALIAS_MISMATCH)
    return CarryBorrowDestinationAliasResolution8616(
        carry=carry,
        verdict=CarryBorrowDestinationAliasVerdict8616.PROVEN,
        fact=CarryBorrowDestinationAliasFact8616(carry, low_store, high_store),
    )


def project_carry_borrow_destination_aliases_8616(
    function_ssa: SSAFunctionArtifact,
    carry_aliases: CarryBorrowAliasEvidence8616,
    stack_aliases: StackMemorySSAAliasArtifact8616 | None,
) -> CarryBorrowDestinationAliasEvidence8616:
    """Project observed direct result stores onto exact stack Alias pairs."""
    if (
        stack_aliases is None
        or function_ssa.function_addr != carry_aliases.function_addr
        or function_ssa.function_addr != stack_aliases.function_addr
    ):
        resolutions = (
            tuple(
                _refusal(fact, CarryBorrowDestinationAliasFailure8616.FUNCTION_IDENTITY_MISMATCH)
                for fact in carry_aliases.facts
            )
            if stack_aliases is not None
            else ()
        )
    else:
        resolved = (
            _resolve_destination(function_ssa, stack_aliases, fact)
            for fact in carry_aliases.facts
        )
        resolutions = tuple(item for item in resolved if item is not None)
    materialized = sum(item.fact is not None for item in resolutions)
    return CarryBorrowDestinationAliasEvidence8616(
        function_addr=function_ssa.function_addr,
        resolutions=resolutions,
        stats=CarryBorrowDestinationAliasStats8616(
            raw_fact_count=len(resolutions),
            normalized_fact_count=len(resolutions),
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(resolutions) - materialized,
        ),
    )


__all__ = [
    "CarryBorrowDestinationAliasEvidence8616",
    "CarryBorrowDestinationAliasFact8616",
    "CarryBorrowDestinationAliasFailure8616",
    "CarryBorrowDestinationAliasResolution8616",
    "CarryBorrowDestinationAliasStats8616",
    "CarryBorrowDestinationAliasVerdict8616",
    "project_carry_borrow_destination_aliases_8616",
]
