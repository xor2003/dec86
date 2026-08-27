"""Classify typed condition-producer register bindings.

Layer: Alias.
Responsibility: Translate canonical ConditionIR producer semantics and proven
cross-CFG reaching sources into exact register-to-storage binding facts.
Consumers still decide whether CFG topology permits propagation.
Owns storage identity in segmented address spaces for those proven register bindings.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
This module consumes decoded-fact proofs but does not inspect rendered C, names,
source, COD, or sidecars.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..callsite_register_provenance import recover_register_source_before_instruction_8616
from ..ir.condition_ir import ConditionIR, ConditionRegisterBindingIR, condition_sort_key_8616
from ..ir.core import IRValue, MemSpace
from ..pipeline.errors import PipelineHardError
from .register_reaching_source import RegisterReachingSourceVerdict8616

__all__ = (
    "ConditionRegisterSourceBindingResult8616",
    "ConditionRegisterSourceBindingStats8616",
    "ConditionRegisterSourceBindingVerdict8616",
    "bind_condition_register_sources_8616",
    "condition_self_test_register_binding_8616",
    "condition_self_test_storage_bindings_8616",
    "condition_semantic_register_operands_8616",
)


class ConditionRegisterSourceBindingVerdict8616(StrEnum):
    """Typed outcome of cross-block condition-register binding."""

    MATERIALIZED = "materialized"
    NO_CANDIDATE = "no_candidate"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class ConditionRegisterSourceBindingStats8616:
    """Closed evidence counters for cross-block condition-register binding."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ConditionRegisterSourceBindingResult8616:
    """Return bound conditions, a typed verdict, and closed evidence counts."""

    conditions: tuple[ConditionIR, ...]
    verdict: ConditionRegisterSourceBindingVerdict8616
    stats: ConditionRegisterSourceBindingStats8616


def condition_self_test_register_binding_8616(
    condition: ConditionIR,
) -> tuple[str, object] | None:
    """Return the register and operand proven by a logical self-test."""
    semantics = condition.producer_semantics
    if (
        not isinstance(semantics, tuple)
        or len(semantics) < 3
        or semantics[0] not in {"and_reg_reg16", "or_reg_reg16"}
        or not isinstance(semantics[1], str)
        or not isinstance(semantics[2], str)
        or semantics[1].lower() != semantics[2].lower()
    ):
        return None
    return semantics[1].lower(), condition.lhs


def condition_self_test_storage_bindings_8616(
    condition: ConditionIR,
) -> tuple[tuple[str, object], ...]:
    """Return explicit bindings for the register used by one logical self-test."""
    self_test = condition_self_test_register_binding_8616(condition)
    if self_test is None:
        return ()
    register_name, _operand = self_test
    return tuple(
        (register_name, binding.value)
        for binding in condition.register_bindings
        if binding.register_name.lower() == register_name
    )


def condition_semantic_register_operands_8616(
    condition: ConditionIR,
) -> tuple[tuple[str, object], ...]:
    """Map canonical condition-producer semantics to register operands."""
    self_test = condition_self_test_register_binding_8616(condition)
    if self_test is not None:
        return (self_test,)
    semantics = condition.producer_semantics
    if not isinstance(semantics, tuple) or not semantics:
        return ()
    kind = semantics[0]
    if kind in {"cmp_reg_mem16", "cmp_reg_abs16", "cmp_reg_imm16"}:
        return ((str(semantics[1]).lower(), condition.lhs),)
    if kind in {"cmp_mem_reg16", "cmp_abs_reg16"}:
        return ((str(semantics[2]).lower(), condition.rhs),)
    if kind == "cmp_reg_reg16":
        return (
            (str(semantics[1]).lower(), condition.lhs),
            (str(semantics[2]).lower(), condition.rhs),
        )
    return ()


def _storage_from_reaching_source_8616(
    source: tuple[object, ...] | None,
    *,
    width_bits: int,
) -> IRValue | None:
    """Map one exact reaching source to segmented storage without flattening."""
    if not source or not isinstance(source[0], str):
        return None
    width = max(1, (width_bits + 7) // 8)
    if source[0] == "global" and len(source) == 3:
        offset, source_width = source[1], source[2]
        if isinstance(offset, int) and source_width == width:
            return IRValue(MemSpace.DS, offset=offset, size=width)
        return None
    if source[0] == "bp" and len(source) in {2, 3}:
        offset = source[1]
        source_width = 2 if len(source) == 2 else source[2]
        if isinstance(offset, int) and source_width == width:
            return IRValue(MemSpace.SS, name="bp", offset=offset, size=width)
    return None


def _with_register_storage_binding_8616(
    condition: ConditionIR,
    *,
    register_name: str,
    storage: IRValue,
) -> ConditionIR:
    """Attach one coherent storage binding or fail on competing owned truth."""
    same_register = tuple(
        binding
        for binding in condition.register_bindings
        if binding.register_name.lower() == register_name
    )
    if any(binding.value != storage for binding in same_register):
        raise PipelineHardError(
            "proven condition-register source conflicts with an existing binding",
            layer="alias",
            details={
                "block_addr": condition.block_addr,
                "producer_insn": condition.producer_insn,
                "register": register_name,
            },
        )
    if same_register:
        return condition
    return replace(
        condition,
        register_bindings=(
            *condition.register_bindings,
            ConditionRegisterBindingIR(register_name, storage),
        ),
    )


def bind_condition_register_sources_8616(
    function: object,
    conditions: list[ConditionIR] | tuple[ConditionIR, ...],
) -> ConditionRegisterSourceBindingResult8616:
    """Bind semantic register operands to storage proven at their producer."""
    ordered = tuple(sorted(conditions, key=condition_sort_key_8616))
    bound: list[ConditionIR] = []
    normalized = 0
    classified = 0
    materialized = 0
    failures = 0
    for condition in ordered:
        current = condition
        for register_name, operand in condition_semantic_register_operands_8616(condition):
            if (
                not isinstance(operand, IRValue)
                or operand.space is not MemSpace.REG
                or not isinstance(condition.producer_insn, int)
            ):
                continue
            normalized += 1
            reaching = recover_register_source_before_instruction_8616(
                function,
                instruction_addr=condition.producer_insn,
                register=register_name,
            )
            if reaching.verdict is not RegisterReachingSourceVerdict8616.PROVEN:
                failures += 1
                continue
            storage = _storage_from_reaching_source_8616(
                reaching.source,
                width_bits=condition.width_bits,
            )
            if storage is None:
                failures += 1
                continue
            classified += 1
            current = _with_register_storage_binding_8616(
                current,
                register_name=register_name,
                storage=storage,
            )
            materialized += 1
        bound.append(current)

    stats = ConditionRegisterSourceBindingStats8616(
        raw_fact_count=len(ordered),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
    )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified condition-register sources were not materialized",
            layer="alias",
        )
    verdict = (
        ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
        if materialized
        else ConditionRegisterSourceBindingVerdict8616.UNKNOWN_REFUSE
        if normalized
        else ConditionRegisterSourceBindingVerdict8616.NO_CANDIDATE
    )
    return ConditionRegisterSourceBindingResult8616(tuple(bound), verdict, stats)
