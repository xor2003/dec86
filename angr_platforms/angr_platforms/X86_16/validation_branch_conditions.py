"""Validate final structured branch predicates against exact ConditionIR facts.

Layer: Validation.
Responsibility: compare Structuring-tagged final C conditions with their unique
typed branch facts without recovering semantics or mutating the AST.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimStackVariable

from .c_ast_utils import _iter_c_nodes_deep_8616
from .callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    structured_callsite_addr_8616,
)
from .ir.condition_ir import (
    ConditionIR,
    canonicalize_condition_storage_fingerprint_8616,
    condition_sort_key_8616,
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .ir.core import IRValue, MemSpace
from .validation_condition_precision import condition_precision_evidence_8616

__all__ = [
    "BranchConditionIssue8616",
    "BranchConditionIssueKind8616",
    "BranchConditionValidationReport8616",
    "validate_materialized_branch_conditions_8616",
]

class BranchConditionIssueKind8616(StrEnum):
    """Contradictions between one materialized branch and typed evidence."""

    CONFLICTING_FACTS = "conflicting-facts"
    DUPLICATE_SURFACE = "duplicate-surface"
    INVALID_FINGERPRINT = "invalid-fingerprint"
    MISSING_FACT = "missing-fact"
    PREDICATE_MISMATCH = "predicate-mismatch"


@dataclass(frozen=True, order=True, slots=True)
class BranchConditionIssue8616:
    """One exact JCC whose final predicate is not uniquely evidence-backed."""

    kind: BranchConditionIssueKind8616
    jcc_addr: int
    match_count: int = 0
    expected: str | None = None
    actual: str | None = None
    precision_candidates: tuple[str, ...] = ()

    def token(self) -> str:
        """Return a deterministic validation issue token."""
        token = (
            f"branch-condition:{self.kind.value}:jcc={self.jcc_addr:#x}:"
            f"matches={self.match_count}"
        )
        if self.expected is not None:
            token += f":expected={self.expected}"
        if self.actual is not None:
            token += f":actual={self.actual}"
        if self.precision_candidates:
            token += ":precision=" + "|".join(self.precision_candidates)
        return token


@dataclass(frozen=True, slots=True)
class BranchConditionValidationReport8616:
    """Closed evidence-loop counters for materialized branch predicates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: tuple[BranchConditionIssue8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return the number of predicate contradictions."""
        return len(self.issues)

    @property
    def passed(self) -> bool:
        """Return whether every classified predicate matches its typed fact."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count


class _TypedConditionCodegen8616(Protocol):
    """Dynamic codegen metadata consumed at the Validation boundary."""

    _inertia_typed_conditions: object
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    project: _ConditionProject8616


class _ConditionArch8616(Protocol):
    """Architecture register map used at the dynamic angr boundary."""

    registers: Mapping[str, tuple[int, int]]


class _ConditionProject8616(Protocol):
    """Project architecture surface used by Validation."""

    arch: _ConditionArch8616


class _TaggedConditionNode8616(Protocol):
    """Third-party C AST node carrying optional Structuring tags."""

    tags: Mapping[str, object] | None


def _node_tags_8616(node: object) -> Mapping[str, object]:
    """Read tags at the dynamic angr C AST boundary."""
    try:
        tags = cast(_TaggedConditionNode8616, node).tags
    except AttributeError:
        return {}
    return tags if isinstance(tags, Mapping) else {}


def _materialized_conditions_8616(root: object) -> tuple[tuple[int, object], ...]:
    """Return unique final conditions explicitly owned by Structuring."""
    found: list[tuple[int, object]] = []
    seen: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        candidates: tuple[object, ...] = ()
        if isinstance(node, CIfBreak):
            candidates = (node.condition,)
        elif isinstance(node, CIfElse):
            candidates = tuple(condition for condition, _body in node.condition_and_nodes)
        elif isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            candidates = (node.condition,)
        for condition in candidates:
            marker = id(condition)
            tags = _node_tags_8616(condition)
            jcc_addr = tags.get("ins_addr")
            structuring_owned = (
                tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
                or tags.get("inertia_typed_loop_condition_bound_8616") is True
            )
            if (
                marker in seen
                or not structuring_owned
                or not isinstance(jcc_addr, int)
            ):
                continue
            seen.add(marker)
            found.append((jcc_addr, condition))
    return tuple(found)


def _typed_conditions_8616(codegen: object) -> tuple[ConditionIR, ...]:
    """Read transferred typed conditions from the dynamic codegen boundary."""
    try:
        value = cast(_TypedConditionCodegen8616, codegen)._inertia_typed_conditions
    except AttributeError:
        return ()
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(condition for condition in value if isinstance(condition, ConditionIR))


def _proven_call_return_condition_8616(
    codegen: object,
    fact: ConditionIR,
    candidate: object,
) -> bool:
    """Prove a bound call predicate equivalent to its AX-family comparison."""
    if (
        not isinstance(candidate, CBinaryOp)
        or candidate.op not in {"CmpEQ", "CmpNE"}
        or fact.op not in {"eq", "ne"}
    ):
        return False
    operands = (candidate.lhs, candidate.rhs)
    calls = tuple(operand for operand in operands if isinstance(operand, CFunctionCall))
    constants = tuple(operand for operand in operands if isinstance(operand, CConstant))
    if len(calls) != 1 or len(constants) != 1 or not isinstance(constants[0].value, int):
        return False
    surface = cast(_TypedConditionCodegen8616, codegen)
    callsite_addr = structured_callsite_addr_8616(calls[0])
    try:
        summary = surface._inertia_callsite_summaries.get(id(calls[0]))
        if summary is None and isinstance(callsite_addr, int):
            summary = surface._inertia_callsite_summary_inventory_8616.get(callsite_addr)
        registers = surface.project.arch.registers
    except AttributeError:
        return False
    if (
        not isinstance(summary, CallsiteSummary8616)
        or summary.return_used is not True
        or summary.return_use_kind is not CallsiteReturnUseKind8616.CONDITION
        or summary.return_addr != fact.block_addr
        or callsite_addr != summary.callsite_addr
        or not isinstance(summary.return_register, str)
    ):
        return False
    register = registers.get(summary.return_register.lower())
    if register is None:
        return False
    values = (fact.lhs, fact.rhs)
    register_matches = any(
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and (int(value.offset), int(value.size or register[1])) == (int(register[0]), int(register[1]))
        for value in values
    )
    constant_matches = any(
        isinstance(value, IRValue)
        and value.space is MemSpace.CONST
        and value.const == constants[0].value
        for value in values
    )
    return not (not register_matches or not constant_matches)


def _proven_stored_call_return_condition_8616(
    codegen: object,
    fact: ConditionIR,
    candidate: object,
) -> bool:
    """Accept a condition bound to the exact stack store of a call return."""
    if not isinstance(candidate, CBinaryOp) or candidate.op not in {"CmpEQ", "CmpNE"}:
        return False
    surface = cast(_TypedConditionCodegen8616, codegen)
    stack_nodes = tuple(
        node
        for node in _iter_c_nodes_deep_8616(candidate)
        if isinstance(node, CVariable)
        and isinstance(node.variable, SimStackVariable)
        and node.variable.base == "bp"
    )
    if len(stack_nodes) != 1:
        return False
    variable = stack_nodes[0].variable
    offset = variable.offset
    size = variable.size
    if not isinstance(offset, int) or not isinstance(size, int):
        return False
    for summary in surface._inertia_callsite_summary_inventory_8616.values():
        if not isinstance(summary, CallsiteSummary8616) or summary.return_use_kind is not CallsiteReturnUseKind8616.VALUE:
            continue
        if summary.return_addr != fact.block_addr or summary.return_store_destination != ("bp", offset):
            continue
        if summary.return_store_width == size and summary.return_used is True:
            return True
    return False


def _normalized_fingerprint_8616(
    fingerprint: str,
    normalizer: Callable[[str], str] | None,
) -> str:
    """Canonicalize one semantic condition fingerprint."""
    normalized = str(
        normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(
                canonicalize_condition_storage_fingerprint_8616(fingerprint)
            )
        )
    )
    if normalizer is not None:
        normalized = str(
            normalize_condition_fingerprint_algebraic_8616(
                normalize_condition_fingerprint_string_8616(
                    canonicalize_condition_storage_fingerprint_8616(normalizer(normalized))
                )
            )
        )
    return normalized


def validate_materialized_branch_conditions_8616(
    codegen: object,
    root: object,
    *,
    condition_fingerprint: Callable[[object], str],
    condition_ir_fingerprint: Callable[[ConditionIR], str | None],
    condition_fingerprint_normalizer: Callable[[str], str] | None = None,
) -> BranchConditionValidationReport8616:
    """Validate each Structuring-tagged predicate against one exact typed fact."""
    surfaces = _materialized_conditions_8616(root)
    surfaces_by_jcc: dict[int, list[object]] = {}
    for jcc_addr, condition in surfaces:
        surfaces_by_jcc.setdefault(jcc_addr, []).append(condition)
    facts_by_jcc: dict[int, dict[tuple[object, ...], ConditionIR]] = {}
    for fact in _typed_conditions_8616(codegen):
        if isinstance(fact.src_insn, int):
            facts_by_jcc.setdefault(fact.src_insn, {})[
                condition_sort_key_8616(fact)
            ] = fact
    precision_after_by_jcc: dict[int, set[str]] = {}
    for evidence in condition_precision_evidence_8616(codegen):
        if isinstance(evidence.jcc_addr, int):
            precision_after_by_jcc.setdefault(evidence.jcc_addr, set()).add(
                _normalized_fingerprint_8616(
                    evidence.after,
                    condition_fingerprint_normalizer,
                )
            )

    classified_count = 0
    materialized_count = 0
    issues: list[BranchConditionIssue8616] = []
    for jcc_addr, candidates in sorted(surfaces_by_jcc.items()):
        classified_count += 1
        if len(candidates) != 1:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.DUPLICATE_SURFACE,
                    jcc_addr,
                    len(candidates),
                )
            )
            continue
        facts = tuple(facts_by_jcc.get(jcc_addr, {}).values())
        if not facts:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.MISSING_FACT,
                    jcc_addr,
                )
            )
            continue
        if len(facts) != 1:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.CONFLICTING_FACTS,
                    jcc_addr,
                    len(facts),
                )
            )
            continue
        expected_raw = condition_ir_fingerprint(facts[0])
        if expected_raw is None:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.INVALID_FINGERPRINT,
                    jcc_addr,
                )
            )
            continue
        actual = _normalized_fingerprint_8616(
            condition_fingerprint(candidates[0]),
            condition_fingerprint_normalizer,
        )
        expected = _normalized_fingerprint_8616(
            expected_raw,
            condition_fingerprint_normalizer,
        )
        inverted_raw = invert_condition_fingerprint_string_8616(expected_raw)
        inverted = (
            _normalized_fingerprint_8616(
                inverted_raw,
                condition_fingerprint_normalizer,
            )
            if inverted_raw is not None
            else None
        )
        precision_after = precision_after_by_jcc.get(jcc_addr, set())
        if (
            actual in {expected, inverted}
            or precision_after == {actual}
            or _proven_call_return_condition_8616(codegen, facts[0], candidates[0])
            or _proven_stored_call_return_condition_8616(codegen, facts[0], candidates[0])
        ):
            materialized_count += 1
            continue
        issues.append(
            BranchConditionIssue8616(
                BranchConditionIssueKind8616.PREDICATE_MISMATCH,
                jcc_addr,
                expected=expected,
                actual=actual,
                precision_candidates=tuple(sorted(precision_after)),
            )
        )
    return BranchConditionValidationReport8616(
        raw_fact_count=len(surfaces),
        normalized_fact_count=len(surfaces_by_jcc),
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        issues=tuple(issues),
    )
