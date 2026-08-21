"""Materialize exact caller-frame effects before function memory SSA.

Layer: Semantics.
Responsibility: consume typed callsite summaries and exact IR CALL/storage facts
to prove which stable ``SS:BP`` ranges survive each call. Unknown interfaces,
pointer escape, cleanup disagreement, duplicate calls, and conflicting existing
effects are retained as typed refusals.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Mapping

from ..callsite_summary import (
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from ..ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
    MemSpace,
)
from .call_stack_effect_contracts import (
    CallStackEffectFact8616,
    CallStackEffectFailure8616,
    CallStackEffectStats8616,
    CallStackEffectVerdict8616,
)


@dataclass(frozen=True, slots=True)
class CallStackEffectArtifact8616:
    """Semantics-enriched IR plus one outcome for every exact CALL."""

    function: IRFunctionArtifact
    facts: tuple[CallStackEffectFact8616, ...]
    stats: CallStackEffectStats8616

    @property
    def complete(self) -> bool:
        """Return whether every CALL has a positive preservation proof."""
        return bool(self.stats.complete)

    def to_dict(self) -> dict[str, object]:
        """Return deterministic diagnostics without duplicating the full IR."""
        return {
            "function_addr": self.function.function_addr,
            "facts": [
                {
                    "block_addr": fact.block_addr,
                    "instr_index": fact.instr_index,
                    "callsite_addr": fact.callsite_addr,
                    "target_addr": fact.target_addr,
                    "verdict": fact.verdict.value,
                    "effect": fact.effect.to_dict(),
                    "failure": None if fact.failure is None else fact.failure.value,
                }
                for fact in self.facts
            ],
            "stats": self.stats.to_dict(),
        }


def _stable_bp_ranges_8616(artifact: IRFunctionArtifact) -> tuple[IRAddress, ...]:
    """Return byte-exact stable BP ranges observed by typed LOAD/STORE facts."""
    ranges = {
        address
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op in {"LOAD", "STORE"}
        and instruction.args
        and isinstance((address := instruction.args[0]), IRAddress)
        and address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.size > 0
    }
    return tuple(sorted(ranges, key=lambda item: (item.offset, item.size)))


def _refused_effect_8616(
    ranges: tuple[IRAddress, ...],
    failure: CallStackEffectFailure8616,
) -> tuple[IRCallStackEffect8616, CallStackEffectFailure8616]:
    """Create one explicit non-preserving call effect."""
    escaped = ranges if failure is CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE else ()
    return IRCallStackEffect8616(escaped_ranges=escaped, complete=False), failure


def _effect_from_summary_8616(
    summary: CallsiteSummary8616,
    ranges: tuple[IRAddress, ...],
) -> tuple[IRCallStackEffect8616, CallStackEffectFailure8616 | None]:
    """Classify caller-frame preservation from one authoritative summary."""
    if summary.target_addr is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.TARGET_UNRESOLVED)
    if callsite_machine_frame_kind_8616(summary) is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.FRAME_KIND_UNKNOWN)
    if summary.return_addr is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.RETURN_ADDRESS_UNKNOWN)
    if summary.arg_count is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.ARGUMENT_COUNT_UNKNOWN)
    if len(summary.arg_widths) != summary.arg_count or any(width <= 0 for width in summary.arg_widths):
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.ARGUMENT_WIDTHS_INCOMPLETE)
    argument_bytes = sum(summary.arg_widths)
    stack_cleanup = 0 if summary.arg_count == 0 and summary.stack_cleanup is None else summary.stack_cleanup
    if stack_cleanup is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.STACK_CLEANUP_UNKNOWN)
    if argument_bytes != stack_cleanup:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.STACK_CLEANUP_MISMATCH)
    if summary.arg_count:
        if (
            len(summary.logical_arg_widths) != summary.arg_count
            or len(summary.logical_arg_classes) != summary.arg_count
            or sum(summary.logical_arg_widths) != sum(summary.arg_widths)
        ):
            return _refused_effect_8616(
                ranges,
                CallStackEffectFailure8616.ARGUMENT_CLASSES_INCOMPLETE,
            )
        if any(
            argument_class is CallsiteArgumentClass8616.POINTER
            for argument_class in summary.logical_arg_classes
        ):
            return _refused_effect_8616(
                ranges,
                CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE,
            )
    net_stack_delta = (
        stack_cleanup
        if stack_cleanup > 0 and summary.stack_cleanup_instruction_addr is None
        else 0
    )
    return (
        IRCallStackEffect8616(
            net_stack_delta=net_stack_delta,
            preserved_ranges=ranges,
            complete=True,
        ),
        None,
    )


def materialize_call_stack_effects_8616(
    artifact: IRFunctionArtifact,
    summaries: Mapping[int, CallsiteSummary8616],
) -> CallStackEffectArtifact8616:
    """Attach one summary-derived stack effect to every exact IR CALL."""
    ranges = _stable_bp_ranges_8616(artifact)
    call_addresses = tuple(
        instruction.addr
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    address_counts = Counter(address for address in call_addresses if address is not None)
    facts: list[CallStackEffectFact8616] = []
    rewritten_blocks: list[IRBlock] = []
    for block in artifact.blocks:
        rewritten: list[IRInstr] = []
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "CALL":
                rewritten.append(instruction)
                continue
            summary = summaries.get(instruction.addr) if instruction.addr is not None else None
            target_addr = None if summary is None else summary.target_addr
            failure: CallStackEffectFailure8616 | None
            if instruction.addr is None:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.CALL_ADDRESS_MISSING,
                )
            elif address_counts[instruction.addr] != 1:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.DUPLICATE_CALL_ADDRESS,
                )
            elif summary is None:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.SUMMARY_MISSING,
                )
            else:
                effect, failure = _effect_from_summary_8616(summary, ranges)
            if instruction.call_stack_effect is not None and instruction.call_stack_effect != effect:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.EXISTING_EFFECT_CONFLICT,
                )
            verdict = (
                CallStackEffectVerdict8616.PROVEN
                if failure is None
                else CallStackEffectVerdict8616.UNKNOWN_REFUSE
            )
            facts.append(
                CallStackEffectFact8616(
                    block.addr,
                    instr_index,
                    instruction.addr,
                    target_addr,
                    verdict,
                    effect,
                    failure,
                )
            )
            rewritten.append(
                IRInstr(
                    instruction.op,
                    instruction.dst,
                    instruction.args,
                    instruction.size,
                    instruction.addr,
                    effect,
                )
            )
        rewritten_blocks.append(
            IRBlock(block.addr, tuple(rewritten), block.refusals, block.successor_addrs)
        )
    raw_count = len(call_addresses)
    failure_count = sum(fact.failure is not None for fact in facts)
    stats = CallStackEffectStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=len(facts),
        failure_count=failure_count,
    )
    summary = {
        **artifact.summary,
        "call_stack_effect_raw_fact_count": stats.raw_fact_count,
        "call_stack_effect_normalized_fact_count": stats.normalized_fact_count,
        "call_stack_effect_classified_fact_count": stats.classified_fact_count,
        "call_stack_effect_materialized_count": stats.materialized_count,
        "call_stack_effect_failure_count": stats.failure_count,
    }
    return CallStackEffectArtifact8616(
        IRFunctionArtifact(
            artifact.function_addr,
            tuple(rewritten_blocks),
            artifact.refusals,
            summary,
        ),
        tuple(facts),
        stats,
    )


__all__ = [
    "CallStackEffectArtifact8616",
    "materialize_call_stack_effects_8616",
]
