"""Materialize signed scalar global declarations from typed conditions.

Layer: Types/Lowering.
Responsibility: join canonical wide scalar storage with signed high-word
ConditionIR evidence and materialize the corresponding C declaration type.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: name/address allowlists, rendered-C parsing, AST semantic rewrites,
or signed promotion without an exact canonical scalar and high-word join.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CIndexedVariable, CVariable
from angr.sim_variable import SimMemoryVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..codegen_metadata import GlobalDeclarationArrayLength8616
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from ..pipeline.errors import PipelineHardError
from ..semantics.direct_global_ordering import DirectGlobalOrdering8616
from .global_declarations import (
    GlobalDeclarationCType8616,
    initialize_global_declaration_specs_8616,
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)
from .project_global_signedness import collect_project_global_signedness_evidence_8616

log: logging.Logger = logging.getLogger(__name__)

__all__ = [
    "SignedGlobalDeclarationFact8616",
    "SignedGlobalDeclarationStats8616",
    "materialize_signed_global_declarations_8616",
]


class _CodegenSurface8616(Protocol):
    """Owned codegen metadata consumed and produced by this lowering pass."""

    cfunc: object
    _inertia_global_declaration_specs_8616: tuple[
        tuple[str, str, GlobalDeclarationArrayLength8616], ...
    ]
    _inertia_signed_global_declaration_facts_8616: tuple[SignedGlobalDeclarationFact8616, ...]
    _inertia_signed_global_declaration_stats_8616: SignedGlobalDeclarationStats8616
    _inertia_typed_conditions: object


@dataclass(slots=True)
class SignedGlobalDeclarationStats8616:
    """Closed evidence census for signed wide-global declaration lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class SignedGlobalDeclarationFact8616:
    """One canonical scalar whose high word has signed comparison semantics."""

    base_offset: int
    name: str
    width: int = 4


@dataclass(frozen=True, slots=True)
class _WideScalarCandidate8616:
    """One exact canonical four-byte scalar visible in the current C AST."""

    base_offset: int
    name: str


def _typed_conditions_8616(codegen: _CodegenSurface8616) -> tuple[ConditionIR, ...]:
    """Return transferred typed conditions from the owned codegen contract."""
    try:
        raw_conditions = codegen._inertia_typed_conditions
    except AttributeError:
        return ()
    if not isinstance(raw_conditions, (list, tuple)):
        return ()
    return tuple(condition for condition in raw_conditions if isinstance(condition, ConditionIR))


def _condition_key_8616(condition: ConditionIR) -> tuple[int, int] | None:
    """Return exact instruction/block provenance for one ordering condition."""
    if (
        not (condition.is_signed or condition.is_unsigned)
        or not isinstance(condition.src_insn, int)
        or not isinstance(condition.block_addr, int)
    ):
        return None
    return condition.src_insn, condition.block_addr


def _ast_condition_key_8616(node: CBinaryOp) -> tuple[int, int] | None:
    """Return typed provenance from one materialized C comparison."""
    ins_addr = node.tags.get("ins_addr")
    block_addr = node.tags.get("vex_block_addr")
    if not isinstance(ins_addr, int) or not isinstance(block_addr, int):
        return None
    return ins_addr, block_addr


def _global_declaration_specs_8616(
    codegen: _CodegenSurface8616,
) -> tuple[tuple[str, str, GlobalDeclarationArrayLength8616], ...]:
    """Return normalized declaration specs from the owned metadata contract."""
    try:
        raw_specs = codegen._inertia_global_declaration_specs_8616
    except AttributeError:
        return ()
    return tuple(
        (ctype, name, array_len)
        for ctype, name, array_len in raw_specs
        if isinstance(ctype, str) and isinstance(name, str)
    )


def _canonical_scalar_names_8616(codegen: _CodegenSurface8616) -> frozenset[str]:
    """Return four-byte scalar names already proven by widening."""
    return frozenset(
        name
        for ctype, name, array_len in _global_declaration_specs_8616(codegen)
        if ctype in {"long", "unsigned long", "int32_t", "uint32_t"} and array_len is None
    )


def _wide_scalar_candidate_8616(
    node: object,
    scalar_names: frozenset[str],
) -> _WideScalarCandidate8616 | None:
    """Return a canonical scalar from an exact high-word projection."""
    base: object | None = None
    if (
        isinstance(node, CBinaryOp)
        and node.op == "Shr"
        and isinstance(node.rhs, CConstant)
        and node.rhs.value == 16
    ):
        base = node.lhs
    elif (
        isinstance(node, CIndexedVariable)
        and isinstance(node.index, CConstant)
        and node.index.value == 1
    ):
        base = node.variable
    return _wide_scalar_variable_candidate_8616(base, scalar_names)


def _wide_scalar_variable_candidate_8616(
    node: object,
    scalar_names: frozenset[str],
) -> _WideScalarCandidate8616 | None:
    """Return an exact canonical four-byte scalar variable."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimMemoryVariable):
        return None
    variable = node.variable
    name = node.name
    if (
        not isinstance(variable.addr, int)
        or int(variable.size or 0) != 4
        or not isinstance(name, str)
        or name not in scalar_names
    ):
        return None
    return _WideScalarCandidate8616(variable.addr & 0xFFFF, name)


def _condition_high_word_candidate_8616(
    condition: ConditionIR,
    candidates: frozenset[_WideScalarCandidate8616],
) -> _WideScalarCandidate8616 | None:
    """Join one typed DS high-word comparison to one canonical wide scalar."""
    if not isinstance(condition.lhs, IRValue) or not isinstance(condition.rhs, IRValue):
        return None
    operands = ((condition.lhs, condition.rhs), (condition.rhs, condition.lhs))
    matched: set[_WideScalarCandidate8616] = set()
    for value, other in operands:
        if (
            value.space is not MemSpace.DS
            or not isinstance(value.offset, int)
            or int(value.size or 0) != 2
            or other.space is not MemSpace.CONST
        ):
            continue
        matched.update(
            candidate
            for candidate in candidates
            if ((candidate.base_offset + 2) & 0xFFFF) == (value.offset & 0xFFFF)
        )
    if len(matched) != 1:
        return None
    return next(iter(matched))


def _comparison_high_word_candidate_8616(
    node: object,
    scalar_names: frozenset[str],
) -> _WideScalarCandidate8616 | None:
    """Return the sole canonical high-word projection in one comparison."""
    if not isinstance(node, CBinaryOp) or not str(node.op).startswith("Cmp"):
        return None
    candidates = tuple(
        candidate
        for candidate in (
            _wide_scalar_candidate_8616(node.lhs, scalar_names),
            _wide_scalar_candidate_8616(node.rhs, scalar_names),
        )
        if candidate is not None
    )
    other_is_constant = isinstance(node.rhs, CConstant) or isinstance(node.lhs, CConstant)
    if len(candidates) != 1 or not other_is_constant:
        return None
    return candidates[0]


def materialize_signed_global_declarations_8616(project: object, codegen: object) -> bool:
    """Materialize signed wide globals from exact high-word condition evidence.

    A signed ordering comparison of the high word gives the sign semantics of
    an already-proven four-byte scalar. An unsigned comparison of that same
    high word is a conflict and causes conservative refusal. The body AST is
    intentionally unchanged so validation continues to compare semantics, not
    declaration representation.
    """
    surface = cast(_CodegenSurface8616, codegen)
    initialize_global_declaration_specs_8616(codegen)
    project_evidence = collect_project_global_signedness_evidence_8616(project)
    conditions = _typed_conditions_8616(surface)
    stats = SignedGlobalDeclarationStats8616(raw_fact_count=len(conditions))
    signed_keys: set[tuple[int, int]] = set()
    unsigned_keys: set[tuple[int, int]] = set()
    for condition in conditions:
        key = _condition_key_8616(condition)
        if key is None:
            continue
        target = signed_keys if condition.is_signed else unsigned_keys
        target.add(key)

    try:
        previous_facts = surface._inertia_signed_global_declaration_facts_8616
    except AttributeError:
        previous_facts = ()
    before_specs = _global_declaration_specs_8616(surface)
    scalar_names = _canonical_scalar_names_8616(surface)
    if os.environ.get("INERTIA_DEBUG_SIGNED_GLOBAL_DECLARATIONS") == "1":
        log.warning(
            "signed-global inputs conditions=%d signed=%d unsigned=%d declaration_specs=%r",
            len(conditions),
            len(signed_keys),
            len(unsigned_keys),
            before_specs,
        )
    signed_candidates: set[_WideScalarCandidate8616] = set()
    unsigned_candidates: set[_WideScalarCandidate8616] = set()
    try:
        cfunc = surface.cfunc
    except AttributeError:
        cfunc = None
    c_nodes = tuple(_iter_c_nodes_deep_8616(cfunc))
    scalar_candidates = frozenset(
        candidate
        for node in c_nodes
        if (candidate := _wide_scalar_variable_candidate_8616(node, scalar_names)) is not None
    )
    signed_project_bases = {
        contract.base_offset
        for contract in project_evidence.contracts
        if contract.ordering is DirectGlobalOrdering8616.SIGNED
    }
    unsigned_project_bases = {
        contract.base_offset
        for contract in project_evidence.contracts
        if contract.ordering is DirectGlobalOrdering8616.UNSIGNED
    }
    conflicting_project_bases = set(project_evidence.conflicting_base_offsets)
    for candidate in scalar_candidates:
        if candidate.base_offset in signed_project_bases:
            signed_candidates.add(candidate)
        if candidate.base_offset in unsigned_project_bases:
            unsigned_candidates.add(candidate)
        if candidate.base_offset in conflicting_project_bases:
            signed_candidates.add(candidate)
            unsigned_candidates.add(candidate)
    normalized_joins: set[tuple[tuple[int, int], _WideScalarCandidate8616]] = set()
    for node in c_nodes:
        if not isinstance(node, CBinaryOp):
            continue
        key = _ast_condition_key_8616(node)
        if key not in signed_keys and key not in unsigned_keys:
            continue
        candidate = _comparison_high_word_candidate_8616(node, scalar_names)
        if candidate is None:
            continue
        normalized_joins.add((key, candidate))
        if key in signed_keys:
            signed_candidates.add(candidate)
        if key in unsigned_keys:
            unsigned_candidates.add(candidate)

    for condition in conditions:
        key = _condition_key_8616(condition)
        if key is None:
            continue
        candidate = _condition_high_word_candidate_8616(condition, scalar_candidates)
        if candidate is None:
            continue
        normalized_joins.add((key, candidate))
        if condition.is_signed:
            signed_candidates.add(candidate)
        if condition.is_unsigned:
            unsigned_candidates.add(candidate)

    project_candidate_fact_count = sum(
        candidate.base_offset in signed_project_bases | unsigned_project_bases | conflicting_project_bases
        for candidate in scalar_candidates
    )
    stats.raw_fact_count += project_candidate_fact_count
    stats.normalized_fact_count = len(normalized_joins) + project_candidate_fact_count

    if os.environ.get("INERTIA_DEBUG_SIGNED_GLOBAL_DECLARATIONS") == "1":
        log.warning(
            "signed-global candidates signed=%r unsigned=%r stats=%r",
            signed_candidates,
            unsigned_candidates,
            stats,
        )

    materialized_facts: list[SignedGlobalDeclarationFact8616] = []
    for candidate in sorted(signed_candidates, key=lambda item: (item.base_offset, item.name)):
        if candidate in unsigned_candidates:
            stats.failure_count += 1
            continue
        stats.classified_fact_count += 1
        fact = SignedGlobalDeclarationFact8616(candidate.base_offset, candidate.name)
        if fact not in previous_facts or ("long", candidate.name, None) not in _global_declaration_specs_8616(surface):
            replace_global_declaration_spec_from_stronger_typed_evidence_8616(
                codegen,
                ctype=GlobalDeclarationCType8616.SIGNED_LONG,
                name=candidate.name,
                array_len=None,
            )
        if ("long", candidate.name, None) not in _global_declaration_specs_8616(surface):
            stats.failure_count += 1
            continue
        materialized_facts.append(fact)
        stats.materialized_count += 1

    facts = tuple(dict.fromkeys(materialized_facts))
    surface._inertia_signed_global_declaration_facts_8616 = facts
    surface._inertia_signed_global_declaration_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified signed global declarations were not materialized")
    return facts != previous_facts or _global_declaration_specs_8616(surface) != before_specs
