"""Project semantic carry/borrow links onto exact Alias identities.

Layer: Alias.
Responsibility: resolve every result and operand in a proven Semantics
carry/borrow link to canonical register, segmented-memory, or immutable
constant evidence and an exact SSA-backed source definition. This module does
not widen values, lower C, or inspect text. Owns storage identity and exact
carrier identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..ir import MemSpace
from ..semantics.carry_borrow_contracts import (
    CarryBorrowEvidence8616,
    CarryBorrowLink8616,
    CarryBorrowResolution8616,
    CarryBorrowVerdict8616,
)
from .carry_borrow_contracts import (
    CarryBorrowAliasEvidence8616,
    CarryBorrowAliasFact8616,
    CarryBorrowAliasFailure8616,
    CarryBorrowAliasResolution8616,
    CarryBorrowAliasStats8616,
    CarryBorrowAliasVerdict8616,
    CarryBorrowOperandAlias8616,
)
from .carry_borrow_sources import (
    register_domain_for_value_8616,
    resolve_carry_borrow_source_alias_8616,
)
from .storage_fact_join import (
    join_adjacent_segmented_alias_facts_8616,
)


def _refusal(
    semantics: CarryBorrowResolution8616 | None,
    failure: CarryBorrowAliasFailure8616,
) -> CarryBorrowAliasResolution8616:
    return CarryBorrowAliasResolution8616(
        semantics=semantics,
        verdict=CarryBorrowAliasVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
    )


def _project_link(
    semantics: CarryBorrowResolution8616,
    link: CarryBorrowLink8616,
) -> CarryBorrowAliasResolution8616:
    low_result = link.low_result_write.instruction.dst
    high_result = link.high_result_write.instruction.dst
    if low_result is None or high_result is None:
        return _refusal(semantics, CarryBorrowAliasFailure8616.RESULT_CARRIER_MISMATCH)
    if low_result.space is not MemSpace.REG or high_result.space is not MemSpace.REG:
        return _refusal(semantics, CarryBorrowAliasFailure8616.SEGMENT_MISMATCH)
    low_result_domain = register_domain_for_value_8616(low_result)
    high_result_domain = register_domain_for_value_8616(high_result)
    if low_result_domain is None or high_result_domain is None:
        return _refusal(semantics, CarryBorrowAliasFailure8616.WIDTH_MISMATCH)
    if low_result_domain == high_result_domain:
        return _refusal(semantics, CarryBorrowAliasFailure8616.CARRIER_ALIAS_MISMATCH)

    alias_results = tuple(
        resolve_carry_borrow_source_alias_8616(use)
        for use in (link.low_lhs, link.low_rhs, link.high_lhs, link.high_rhs)
    )
    failure = next(
        (item for item in alias_results if isinstance(item, CarryBorrowAliasFailure8616)),
        None,
    )
    if failure is not None:
        return _refusal(semantics, failure)
    aliases = tuple(
        item for item in alias_results if isinstance(item, CarryBorrowOperandAlias8616)
    )
    if len(aliases) != 4:
        return _refusal(semantics, CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH)
    low_lhs, low_rhs, high_lhs, high_rhs = aliases
    if (
        not all(alias.complete for alias in (low_lhs, low_rhs, high_lhs, high_rhs))
        or low_lhs.register_domain != low_result_domain
        or high_lhs.register_domain != high_result_domain
        or low_lhs.memory is not None
        or high_lhs.memory is not None
    ):
        return _refusal(semantics, CarryBorrowAliasFailure8616.RESULT_CARRIER_MISMATCH)
    source_memory = None
    source_constant = None
    if low_rhs.register_domain is not None and high_rhs.register_domain is not None:
        if low_rhs.register_domain == high_rhs.register_domain:
            return _refusal(semantics, CarryBorrowAliasFailure8616.CARRIER_ALIAS_MISMATCH)
    elif low_rhs.memory is not None and high_rhs.memory is not None:
        if low_rhs.memory.space is not high_rhs.memory.space:
            return _refusal(semantics, CarryBorrowAliasFailure8616.SEGMENT_MISMATCH)
        source_memory = join_adjacent_segmented_alias_facts_8616(
            low_rhs.memory.addresses + high_rhs.memory.addresses,
            low_rhs.memory.source_facts + high_rhs.memory.source_facts,
        )
        if source_memory is None or source_memory.size != 4:
            return _refusal(semantics, CarryBorrowAliasFailure8616.SOURCE_RANGE_MISMATCH)
    elif low_rhs.constant is not None and high_rhs.constant is not None:
        low_constant = low_rhs.constant.const
        high_constant = high_rhs.constant.const
        if not isinstance(low_constant, int) or not isinstance(high_constant, int):
            return _refusal(semantics, CarryBorrowAliasFailure8616.SOURCE_CARRIER_MISMATCH)
        source_constant = ((high_constant & 0xFFFF) << 16) | (low_constant & 0xFFFF)
    else:
        return _refusal(semantics, CarryBorrowAliasFailure8616.SOURCE_CARRIER_MISMATCH)
    return CarryBorrowAliasResolution8616(
        semantics=semantics,
        verdict=CarryBorrowAliasVerdict8616.PROVEN,
        fact=CarryBorrowAliasFact8616(
            link=link,
            low_result_domain=low_result_domain,
            high_result_domain=high_result_domain,
            low_lhs=low_lhs,
            low_rhs=low_rhs,
            high_lhs=high_lhs,
            high_rhs=high_rhs,
            source_memory=source_memory,
            source_constant=source_constant,
        ),
    )


def project_carry_borrow_aliases_8616(
    evidence: CarryBorrowEvidence8616,
) -> CarryBorrowAliasEvidence8616:
    """Resolve exact Alias identities for all semantic carry/borrow outcomes."""
    resolutions: tuple[CarryBorrowAliasResolution8616, ...]
    if not evidence.complete:
        resolutions = (
            _refusal(None, CarryBorrowAliasFailure8616.SEMANTICS_INCOMPLETE),
        )
    else:
        resolutions = tuple(
            _project_link(item, item.link)
            if item.verdict is CarryBorrowVerdict8616.PROVEN and item.link is not None
            else _refusal(item, CarryBorrowAliasFailure8616.SEMANTICS_REFUSED)
            for item in evidence.resolutions
        )
    materialized = sum(item.fact is not None for item in resolutions)
    return CarryBorrowAliasEvidence8616(
        function_addr=evidence.function_addr,
        resolutions=resolutions,
        stats=CarryBorrowAliasStats8616(
            raw_fact_count=len(resolutions),
            normalized_fact_count=len(resolutions),
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(resolutions) - materialized,
        ),
    )


__all__ = [
    "CarryBorrowAliasEvidence8616",
    "CarryBorrowAliasFact8616",
    "CarryBorrowAliasFailure8616",
    "CarryBorrowAliasResolution8616",
    "CarryBorrowAliasStats8616",
    "CarryBorrowAliasVerdict8616",
    "CarryBorrowOperandAlias8616",
    "project_carry_borrow_aliases_8616",
]
