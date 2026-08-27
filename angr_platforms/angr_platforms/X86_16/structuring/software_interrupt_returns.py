"""Materialize terminal software-interrupt results from typed evidence.

Layer: Structuring.
Responsibility: replace a stale pre-interrupt selector return with the exact
terminal interrupt call only when Semantics identifies the result register and
the binary CFG proves that register reaches the function return unchanged.
This module does not infer interrupt inputs, types, aliases, or rendered text.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from ..semantics.software_interrupt_inputs import (
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
)
from ..structured_tags import copy_structured_tags_8616
from .return_chains import (
    TerminalCallResultReturnCallbacks8616,
    TerminalCallResultReturnStatus8616,
    prove_terminal_call_result_path_8616,
)

__all__ = [
    "SoftwareInterruptResultMaterializationStats8616",
    "SoftwareInterruptResultStatus8616",
    "materialize_software_interrupt_terminal_results_8616",
]


class SoftwareInterruptResultStatus8616(StrEnum):
    """Typed result of terminal interrupt-result materialization."""

    NO_INPUT_ARTIFACT = "no-input-artifact"
    NO_RESULT_FACT = "no-result-fact"
    NO_STALE_SELECTOR_RETURN = "no-stale-selector-return"
    AMBIGUOUS_CANDIDATE = "ambiguous-candidate"
    CFG_PROOF_REFUSED = "cfg-proof-refused"
    ALREADY_MATERIALIZED = "already-materialized"
    MATERIALIZED = "materialized"


@dataclass(frozen=True, slots=True)
class SoftwareInterruptResultMaterializationStats8616:
    """Closed evidence loop for terminal interrupt-result materialization."""

    status: SoftwareInterruptResultStatus8616
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    callsite_addr: int | None = None
    path_block_addrs: tuple[int, ...] = ()
    path_status: TerminalCallResultReturnStatus8616 | None = None


@dataclass(frozen=True, slots=True)
class _StaleSelectorCandidate8616:
    """One call assignment and stale selector return on the terminal path."""

    call_container: structured_c.CStatements
    return_container: structured_c.CStatements
    assignment_index: int
    return_index: int
    call: structured_c.CFunctionCall
    return_statement: structured_c.CReturn


class _CodegenInterruptResultSurface8616(Protocol):
    """Owned interrupt artifacts attached to the dynamic codegen boundary."""

    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616
    _inertia_software_interrupt_result_stats_8616: SoftwareInterruptResultMaterializationStats8616


def _leaf_statement_8616(statement: object) -> object | None:
    """Unwrap only transparent one-statement C containers."""
    current = statement
    visited: set[int] = set()
    while isinstance(current, structured_c.CStatements):
        if id(current) in visited:
            return None
        visited.add(id(current))
        children = tuple(current.statements or ())
        if len(children) != 1:
            return None
        current = children[0]
    return current


def _callsite_addr_8616(call: structured_c.CFunctionCall) -> int | None:
    """Read one exact callsite tag from angr's structured-C boundary."""
    tags = copy_structured_tags_8616(call.tags)
    if tags is None:
        return None
    addr = tags.get("ins_addr")
    return addr if isinstance(addr, int) else None


def _statement_containers_8616(root: object) -> tuple[structured_c.CStatements, ...]:
    """Collect unique mutable statement containers deterministically."""
    containers: list[structured_c.CStatements] = []
    seen: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, structured_c.CStatements) or id(node) in seen:
            continue
        seen.add(id(node))
        containers.append(node)
    return tuple(containers)


def _returned_call_matches_8616(root: object, fact: SoftwareInterruptInputFact8616) -> bool:
    """Return whether final C already returns the exact interrupt call."""
    return any(
        isinstance(node, structured_c.CReturn)
        and isinstance(node.retval, structured_c.CFunctionCall)
        and _callsite_addr_8616(node.retval) == fact.callsite_addr
        for node in _iter_c_nodes_deep_8616(root)
    )


def _stale_selector_candidates_8616(
    root: object,
    fact: SoftwareInterruptInputFact8616,
) -> tuple[_StaleSelectorCandidate8616, ...]:
    """Collect exact call assignments and stale selector return candidates."""
    candidates: list[_StaleSelectorCandidate8616] = []
    candidate_keys: set[tuple[int, int]] = set()
    assigned_calls: list[
        tuple[structured_c.CStatements, int, structured_c.CFunctionCall]
    ] = []
    selector_returns: list[
        tuple[structured_c.CStatements, int, structured_c.CReturn]
    ] = []
    for container in _statement_containers_8616(root):
        statements = tuple(cast(Iterable[structured_c.CStatement], container.statements or ()))
        leaves = tuple(_leaf_statement_8616(statement) for statement in statements)
        for index, leaf in enumerate(leaves):
            if (
                isinstance(leaf, structured_c.CAssignment)
                and isinstance(leaf.rhs, structured_c.CFunctionCall)
                and _callsite_addr_8616(leaf.rhs) == fact.callsite_addr
            ):
                assigned_calls.append((container, index, leaf.rhs))
            elif (
                isinstance(leaf, structured_c.CReturn)
                and isinstance(leaf.retval, structured_c.CConstant)
                and leaf.retval.value == fact.selector_value
            ):
                selector_returns.append((container, index, leaf))
    for call_container, assignment_index, call in assigned_calls:
        for return_container, return_index, return_statement in selector_returns:
            if call_container is return_container and return_index != assignment_index + 1:
                continue
            key = (id(call), id(return_statement))
            if key in candidate_keys:
                continue
            candidate_keys.add(key)
            candidates.append(
                _StaleSelectorCandidate8616(
                    call_container=call_container,
                    return_container=return_container,
                    assignment_index=assignment_index,
                    return_index=return_index,
                    call=call,
                    return_statement=return_statement,
                )
            )
    return tuple(candidates)


def _materialize_fact_8616(
    root: object,
    codegen: object,
    fact: SoftwareInterruptInputFact8616,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> SoftwareInterruptResultMaterializationStats8616:
    """Materialize one exact terminal interrupt-result fact."""
    if _returned_call_matches_8616(root, fact):
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.ALREADY_MATERIALIZED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            callsite_addr=fact.callsite_addr,
        )
    candidates = _stale_selector_candidates_8616(root, fact)
    if not candidates:
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.NO_STALE_SELECTOR_RETURN,
            raw_fact_count=1,
        )
    if len(candidates) != 1:
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.AMBIGUOUS_CANDIDATE,
            raw_fact_count=1,
            normalized_fact_count=len(candidates),
            classified_fact_count=len(candidates),
            failure_count=len(candidates),
            callsite_addr=fact.callsite_addr,
        )
    candidate = candidates[0]
    path_status, path = prove_terminal_call_result_path_8616(
        fact.callsite_addr,
        callbacks,
    )
    if path_status is not TerminalCallResultReturnStatus8616.MATERIALIZED:
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.CFG_PROOF_REFUSED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            failure_count=1,
            callsite_addr=fact.callsite_addr,
            path_block_addrs=path,
            path_status=path_status,
        )
    replacement = structured_c.CReturn(
        candidate.call,
        tags=candidate.return_statement.tags,
        codegen=codegen,
    )
    if candidate.call_container is candidate.return_container:
        statements = list(
            cast(
                Iterable[structured_c.CStatement],
                candidate.call_container.statements or (),
            )
        )
        statements[candidate.assignment_index : candidate.return_index + 1] = [replacement]
        candidate.call_container.statements = statements
    else:
        call_statements = list(
            cast(
                Iterable[structured_c.CStatement],
                candidate.call_container.statements or (),
            )
        )
        del call_statements[candidate.assignment_index]
        candidate.call_container.statements = call_statements
        return_statements = list(
            cast(
                Iterable[structured_c.CStatement],
                candidate.return_container.statements or (),
            )
        )
        return_statements[candidate.return_index] = replacement
        candidate.return_container.statements = return_statements
    return SoftwareInterruptResultMaterializationStats8616(
        status=SoftwareInterruptResultStatus8616.MATERIALIZED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        callsite_addr=fact.callsite_addr,
        path_block_addrs=path,
        path_status=path_status,
    )


def materialize_software_interrupt_terminal_results_8616(
    root: object,
    codegen: object,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> bool:
    """Return terminal interrupt results only from typed ABI and CFG proof."""
    surface = cast(_CodegenInterruptResultSurface8616, codegen)
    try:
        artifact = surface._inertia_software_interrupt_input_artifact_8616
    except AttributeError:
        stats = SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.NO_INPUT_ARTIFACT,
        )
        surface._inertia_software_interrupt_result_stats_8616 = stats
        return False
    facts = tuple(fact for fact in artifact.facts if fact.result_register is not None)
    if not facts:
        stats = SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.NO_RESULT_FACT,
        )
        surface._inertia_software_interrupt_result_stats_8616 = stats
        return False
    if len(facts) != 1:
        stats = SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.AMBIGUOUS_CANDIDATE,
            raw_fact_count=len(facts),
            failure_count=len(facts),
        )
    else:
        stats = _materialize_fact_8616(root, codegen, facts[0], callbacks)
    surface._inertia_software_interrupt_result_stats_8616 = stats
    if stats.classified_fact_count > stats.materialized_count or stats.failure_count:
        raise PipelineHardError(
            "classified software interrupt result was not materialized",
            layer="structuring",
        )
    return stats.status is SoftwareInterruptResultStatus8616.MATERIALIZED
