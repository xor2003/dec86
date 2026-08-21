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

from ..ir import IRCallOutputProvenance8616, IRCallOutputShape8616, IRInstr, IRValue, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
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
    CarryBorrowCallOutputAlias8616,
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


def _ssa_identity_8616(value: IRValue) -> tuple[MemSpace, str | None, int, int, int | None]:
    """Return the exact SSA storage identity relevant to Alias projection."""
    return (value.space, value.name, value.offset, value.size, value.version)


def _valid_call_output_definition_8616(
    instruction: IRInstr,
    expected: IRValue,
    provenance: IRCallOutputProvenance8616,
) -> bool:
    """Check one typed CALL_OUTPUT definition without parsing diagnostic text."""
    destination = instruction.dst
    if (
        instruction.op != "CALL_OUTPUT"
        or destination is None
        or destination.call_output != provenance
        or instruction.addr != provenance.callsite_addr
        or _ssa_identity_8616(destination) != _ssa_identity_8616(expected)
        or len(instruction.args) != 1
    ):
        return False
    target = instruction.args[0]
    return (
        isinstance(target, IRValue)
        and target.space is MemSpace.CONST
        and target.const == provenance.target_addr
    )


def _call_output_candidates_8616(
    function_ssa: SSAFunctionArtifact,
    expected: IRValue,
    provenance: IRCallOutputProvenance8616,
) -> tuple[tuple[int, int, IRValue], ...]:
    """Collect exact CALL_OUTPUT definitions for one SSA register use."""
    return tuple(
        (block.addr, instr_index, instruction.dst)
        for block in function_ssa.blocks
        for instr_index, instruction in enumerate(block.instrs)
        if instruction.dst is not None
        and _valid_call_output_definition_8616(instruction, expected, provenance)
    )


def _resolve_lhs_call_output_8616(
    function_ssa: SSAFunctionArtifact | None,
    link: CarryBorrowLink8616,
) -> CarryBorrowCallOutputAlias8616 | CarryBorrowAliasFailure8616 | None:
    """Resolve a complete exact call-return identity for both arithmetic halves."""
    low_value = link.low_lhs.value
    high_value = link.high_lhs.value
    low_provenance = low_value.call_output
    high_provenance = high_value.call_output
    if low_provenance is None and high_provenance is None:
        return None
    if low_provenance is None or high_provenance is None:
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_PARTIAL
    if low_provenance != high_provenance:
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_CONFLICT
    if (
        low_provenance.shape is not IRCallOutputShape8616.DX_AX
        or (low_value.name, high_value.name) != ("ax", "dx")
        or low_value.size != 2
        or high_value.size != 2
    ):
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_SHAPE_MISMATCH
    if function_ssa is None:
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_SSA_MISSING
    low_candidates = _call_output_candidates_8616(function_ssa, low_value, low_provenance)
    high_candidates = _call_output_candidates_8616(function_ssa, high_value, high_provenance)
    if not low_candidates or not high_candidates:
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_DEFINITION_MISSING
    if len(low_candidates) != 1 or len(high_candidates) != 1:
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_DEFINITION_AMBIGUOUS
    low_block, low_index, low_output = low_candidates[0]
    high_block, high_index, high_output = high_candidates[0]
    if (
        low_block != link.low_arithmetic.block_addr
        or high_block != link.high_base_arithmetic.block_addr
        or low_index >= link.low_arithmetic.instr_index
        or high_index >= link.high_base_arithmetic.instr_index
    ):
        return CarryBorrowAliasFailure8616.CALL_OUTPUT_ORDER_MISMATCH
    return CarryBorrowCallOutputAlias8616(
        provenance=low_provenance,
        low_output=low_output,
        high_output=high_output,
    )


def _project_link(
    semantics: CarryBorrowResolution8616,
    link: CarryBorrowLink8616,
    function_ssa: SSAFunctionArtifact | None,
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
    lhs_call_output = _resolve_lhs_call_output_8616(function_ssa, link)
    if isinstance(lhs_call_output, CarryBorrowAliasFailure8616):
        return _refusal(semantics, lhs_call_output)
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
            lhs_call_output=lhs_call_output,
            source_memory=source_memory,
            source_constant=source_constant,
        ),
    )


def project_carry_borrow_aliases_8616(
    evidence: CarryBorrowEvidence8616,
    function_ssa: SSAFunctionArtifact | None = None,
) -> CarryBorrowAliasEvidence8616:
    """Resolve exact Alias identities for all semantic carry/borrow outcomes."""
    resolutions: tuple[CarryBorrowAliasResolution8616, ...]
    if function_ssa is not None and function_ssa.function_addr != evidence.function_addr:
        resolutions = (
            _refusal(None, CarryBorrowAliasFailure8616.FUNCTION_SSA_MISMATCH),
        )
    elif not evidence.complete:
        resolutions = (
            _refusal(None, CarryBorrowAliasFailure8616.SEMANTICS_INCOMPLETE),
        )
    else:
        resolutions = tuple(
            _project_link(item, item.link, function_ssa)
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
    "CarryBorrowCallOutputAlias8616",
    "CarryBorrowOperandAlias8616",
    "project_carry_borrow_aliases_8616",
]
