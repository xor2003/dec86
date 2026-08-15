"""Normalize proven register carriers across decrement dispatch chains.

Layer: Alias.
Responsibility: Owns storage identity by binding a condition register to one concrete storage identity only
when duplicate typed facts prove both operands for the same CFG branch, then
carry that identity through an exact fallthrough chain of ``DEC reg`` branches.
This module never decodes assembly or inspects source, symbols, or rendered C.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TypeAlias

from ..ir.condition_ir import ConditionIR, condition_sort_key_8616
from ..ir.core import IRValue, MemSpace

_BranchIdentity8616: TypeAlias = tuple[
    object,
    int,
    tuple[str, ...],
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
]


@dataclass(frozen=True, slots=True)
class ConditionRegisterCarrierStats8616:
    """Closed evidence counters for register-carrier normalization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class ConditionRegisterCarrierResult8616:
    """Return normalized conditions and their evidence accounting."""

    conditions: tuple[ConditionIR, ...]
    stats: ConditionRegisterCarrierStats8616


@dataclass(frozen=True, slots=True)
class _CarrierSeed8616:
    """Proven concrete identity for one register at a branch fallthrough."""

    next_block: int
    register_name: str
    value: IRValue
    width_bits: int


def _branch_identity_8616(condition: ConditionIR) -> _BranchIdentity8616:
    """Return one operand-independent branch identity."""
    return (
        condition.op,
        condition.width_bits,
        condition.source,
        condition.src_insn,
        condition.block_addr,
        condition.producer_insn,
        condition.taken_target,
        condition.fallthrough_target,
        condition.operand_bind_insn,
    )


def _unique_values_8616(values: list[IRValue]) -> tuple[IRValue, ...]:
    """Deduplicate owned IR values while preserving deterministic order."""
    unique: list[IRValue] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return tuple(unique)


def _carrier_seeds_8616(
    conditions: tuple[ConditionIR, ...],
) -> tuple[tuple[_CarrierSeed8616, ...], int]:
    """Collect unambiguous register-to-storage proofs from duplicate facts."""
    grouped: dict[_BranchIdentity8616, list[ConditionIR]] = {}
    for condition in conditions:
        grouped.setdefault(_branch_identity_8616(condition), []).append(condition)

    candidates: list[_CarrierSeed8616] = []
    failures = 0
    for group in grouped.values():
        register_values = _unique_values_8616(
            [
                condition.lhs
                for condition in group
                if isinstance(condition.lhs, IRValue)
                and condition.lhs.space is MemSpace.REG
                and isinstance(condition.lhs.name, str)
            ]
        )
        storage_values = _unique_values_8616(
            [
                condition.lhs
                for condition in group
                if isinstance(condition.lhs, IRValue)
                and condition.lhs.space in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
            ]
        )
        if not register_values or not storage_values:
            continue
        if len(register_values) != 1 or len(storage_values) != 1:
            failures += 1
            continue
        register = register_values[0]
        storage = storage_values[0]
        if register.size != storage.size:
            failures += 1
            continue
        representative = group[0]
        if not isinstance(representative.fallthrough_target, int):
            failures += 1
            continue
        if any(condition.rhs != representative.rhs for condition in group):
            failures += 1
            continue
        register_name = register.name
        if not isinstance(register_name, str):
            failures += 1
            continue
        candidates.append(
            _CarrierSeed8616(
                next_block=representative.fallthrough_target,
                register_name=register_name,
                value=storage,
                width_bits=representative.width_bits,
            )
        )

    by_key: dict[tuple[int, str], list[_CarrierSeed8616]] = {}
    for seed in candidates:
        by_key.setdefault((seed.next_block, seed.register_name), []).append(seed)
    seeds: list[_CarrierSeed8616] = []
    for grouped_seeds in by_key.values():
        unique: list[_CarrierSeed8616] = []
        for seed in grouped_seeds:
            if seed not in unique:
                unique.append(seed)
        if len(unique) == 1:
            seeds.append(unique[0])
        else:
            failures += 1
    seeds.sort(key=lambda seed: (seed.next_block, seed.register_name))
    return tuple(seeds), failures


def _dec_semantics_8616(condition: ConditionIR) -> tuple[str, int] | None:
    """Return a validated ``DEC reg`` producer description."""
    semantics = condition.producer_semantics
    if (
        not isinstance(semantics, tuple)
        or len(semantics) != 3
        or semantics[0] != "dec_reg16"
        or not isinstance(semantics[1], str)
        or not isinstance(semantics[2], int)
        or semantics[2] <= 0
    ):
        return None
    return semantics[1].lower(), semantics[2]


def normalize_condition_register_carriers_8616(
    conditions: list[ConditionIR] | tuple[ConditionIR, ...],
) -> ConditionRegisterCarrierResult8616:
    """Bind decrement-dispatch comparisons to a proven concrete input value."""
    ordered = tuple(sorted(conditions, key=condition_sort_key_8616))
    seeds, failures = _carrier_seeds_8616(ordered)
    by_block: dict[int, list[tuple[int, ConditionIR]]] = {}
    for index, condition in enumerate(ordered):
        if isinstance(condition.block_addr, int):
            by_block.setdefault(condition.block_addr, []).append((index, condition))

    replacements: dict[int, ConditionIR] = {}
    classified = 0
    materialized = 0
    for seed in seeds:
        block_addr = seed.next_block
        delta = 0
        visited: set[int] = set()
        while block_addr not in visited:
            visited.add(block_addr)
            dec_candidates = [
                (index, condition, semantics)
                for index, condition in by_block.get(block_addr, ())
                if (semantics := _dec_semantics_8616(condition)) is not None
            ]
            identities = {
                _branch_identity_8616(condition)
                for _index, condition, _semantics in dec_candidates
            }
            if not dec_candidates:
                break
            if len(identities) != 1:
                failures += 1
                break
            representative = dec_candidates[0][1]
            semantics = dec_candidates[0][2]
            register_name, dec_count = semantics
            rhs = representative.rhs
            if (
                register_name != seed.register_name
                or representative.width_bits != seed.width_bits
                or not isinstance(representative.lhs, IRValue)
                or representative.lhs.space is not MemSpace.REG
                or representative.lhs.name != register_name
                or not isinstance(rhs, IRValue)
                or rhs.space is not MemSpace.CONST
                or rhs.const != dec_count
            ):
                failures += 1
                break
            classified += 1
            delta += dec_count
            normalized_rhs = replace(rhs, const=delta)
            for index, condition, candidate_semantics in dec_candidates:
                if candidate_semantics != semantics:
                    failures += 1
                    continue
                replacement = replace(
                    condition,
                    lhs=seed.value,
                    rhs=normalized_rhs,
                )
                existing = replacements.get(index)
                if existing is not None and existing != replacement:
                    failures += 1
                    continue
                replacements[index] = replacement
            materialized += 1
            if not isinstance(representative.fallthrough_target, int):
                break
            block_addr = representative.fallthrough_target

    normalized = tuple(
        replacements.get(index, condition)
        for index, condition in enumerate(ordered)
    )
    return ConditionRegisterCarrierResult8616(
        conditions=normalized,
        stats=ConditionRegisterCarrierStats8616(
            raw_fact_count=len(ordered),
            normalized_fact_count=len(seeds),
            classified_fact_count=classified,
            materialized_count=materialized,
            failure_count=failures,
        ),
    )
