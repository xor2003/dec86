"""Resolve call arguments to exact typed SSA reaching definitions.

Layer: Types/Lowering.
Responsibility: select one structured callsite argument, verify its exact CALL
use, and orchestrate source-definition proof over ``SSAFunctionArtifact``.
Source matching is owned by ``interprocedural_storage_source_defs``; durable
outcomes are owned by ``interprocedural_storage_reaching_contracts``.
Consumes alias, widening, and typed facts.
This module does not classify C types or mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..callsite_summary import (
    CallsiteSummary8616,
    logical_argument_widths_from_callsite_8616,
)
from ..ir import IRValue
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import StorageUseEvidence8616
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionResolution8616,
    CallArgumentDefinitionStats8616,
    CallArgumentDefinitionVerdict8616,
    PhysicalCallArgument8616,
    SSAInstructionSite8616,
)
from .interprocedural_storage_source_defs import (
    resolve_argument_source_definitions_8616,
)

__all__ = [
    "CallArgumentDefinitionFailure8616",
    "CallArgumentDefinitionResolution8616",
    "CallArgumentDefinitionStats8616",
    "CallArgumentDefinitionVerdict8616",
    "physical_call_argument_8616",
    "resolve_call_argument_reaching_definition_8616",
]


def _refusal_8616(
    failure: CallArgumentDefinitionFailure8616,
    *,
    normalized: bool,
    conflict: bool = False,
) -> CallArgumentDefinitionResolution8616:
    """Build one deterministic refusal with closed evidence counters."""
    verdict = (
        CallArgumentDefinitionVerdict8616.CONFLICT if conflict else CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    )
    return CallArgumentDefinitionResolution8616(
        verdict=verdict,
        definitions=(),
        use=None,
        failure=failure,
        stats=CallArgumentDefinitionStats8616(
            raw_fact_count=1,
            normalized_fact_count=int(normalized),
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        ),
    )


def _sites_8616(
    function_ssa: SSAFunctionArtifact,
) -> tuple[SSAInstructionSite8616, ...]:
    """Return all SSA instructions in deterministic block/index order."""
    return tuple(
        SSAInstructionSite8616(block, instr_index, instr)
        for block in sorted(function_ssa.blocks, key=lambda item: item.addr)
        for instr_index, instr in enumerate(block.instrs)
    )


def _call_use_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    summary: CallsiteSummary8616,
) -> tuple[
    StorageUseEvidence8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Find one exact SSA CALL and verify its constant internal target."""
    calls = tuple(site for site in sites if site.instr.op == "CALL" and site.instr.addr == summary.callsite_addr)
    if not calls:
        return None, CallArgumentDefinitionFailure8616.CALLSITE_NOT_FOUND
    if len(calls) != 1:
        return None, CallArgumentDefinitionFailure8616.CALLSITE_CONFLICT
    site = calls[0]
    target = site.instr.args[0] if site.instr.args else None
    if (
        not isinstance(summary.target_addr, int)
        or not isinstance(target, IRValue)
        or target.const != summary.target_addr
    ):
        return None, CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT
    return (
        StorageUseEvidence8616(
            block_addr=site.block.addr,
            instr_index=site.instr_index,
            instr_addr=summary.callsite_addr,
            callsite_addr=summary.callsite_addr,
        ),
        None,
    )


def physical_call_argument_8616(
    summary: CallsiteSummary8616,
    logical_index: int,
) -> tuple[
    PhysicalCallArgument8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Map one source-order argument to its one exact physical push."""
    count = summary.arg_count
    if not isinstance(count, int) or logical_index < 0 or logical_index >= count:
        return None, CallArgumentDefinitionFailure8616.INVALID_ARGUMENT_INDEX
    widths = logical_argument_widths_from_callsite_8616(
        summary,
        expected_arg_count=count,
    )
    if widths is None or len(summary.push_arg_instruction_addrs) != count or len(summary.push_arg_sources) != count:
        return None, CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT
    physical_index = count - logical_index - 1
    source = summary.push_arg_sources[physical_index]
    push_addr = summary.push_arg_instruction_addrs[physical_index]
    if not isinstance(source, tuple) or not isinstance(push_addr, int):
        return None, CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT
    return PhysicalCallArgument8616(
        width=widths[logical_index],
        source=source,
        push_addr=push_addr,
    ), None


def resolve_call_argument_reaching_definition_8616(
    function_ssa: SSAFunctionArtifact,
    summary: CallsiteSummary8616,
    logical_index: int,
) -> CallArgumentDefinitionResolution8616:
    """Resolve one source-order call argument without inventing missing proof."""
    sites = _sites_8616(function_ssa)
    use, call_failure = _call_use_8616(sites, summary)
    if call_failure is not None or use is None:
        failure = call_failure or CallArgumentDefinitionFailure8616.CALLSITE_NOT_FOUND
        return _refusal_8616(
            failure,
            normalized=False,
            conflict=failure
            in {
                CallArgumentDefinitionFailure8616.CALLSITE_CONFLICT,
                CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT,
            },
        )
    fact, physical_failure = physical_call_argument_8616(summary, logical_index)
    if physical_failure is not None or fact is None:
        return _refusal_8616(
            physical_failure or CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT,
            normalized=False,
        )
    definitions, source_failure = resolve_argument_source_definitions_8616(
        sites,
        fact,
    )
    if source_failure is not None or definitions is None:
        failure = source_failure or CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        return _refusal_8616(
            failure,
            normalized=True,
            conflict=failure
            in {
                CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT,
                CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT,
                CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT,
            },
        )
    return CallArgumentDefinitionResolution8616(
        verdict=CallArgumentDefinitionVerdict8616.PROVEN,
        definitions=definitions,
        use=use,
        failure=None,
        stats=CallArgumentDefinitionStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        ),
    )
