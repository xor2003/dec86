"""Typed contracts for exact scalar affine-expression provenance.

Layer: IR.
Responsibility: retain one modular scalar expression as a constant plus exact
stack-derived terms and the SSA definition path proving that expression.
This module does not interpret values as pointers, choose segments, infer
aliases or types, mutate code generation, or consume callsite summaries.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin
from .indexed_address_contracts import IndexedAddressDefinitionSite8616


class ScalarAffineFailure8616(StrEnum):
    """Stable reasons an exact affine scalar trace cannot close."""

    ROOT_UNPROVEN = "root_unproven"
    DEFINITION_MISSING = "definition_missing"
    DEFINITION_CONFLICT = "definition_conflict"
    WIDTH_CONFLICT = "width_conflict"
    EXPRESSION_UNSUPPORTED = "expression_unsupported"
    SOURCE_UNPROVEN = "source_unproven"


@dataclass(frozen=True, slots=True)
class ScalarAffineTerm8616:
    """One exact stack-loaded value multiplied by a modular coefficient."""

    value: IRValue
    source: IRAddress
    coefficient: int

    @property
    def complete(self) -> bool:
        """Return whether this term retains exact value and stack identity."""
        return bool(
            self.coefficient != 0
            and (
                isinstance(self.value.version, int)
                or isinstance(self.value.source_tmp, int)
            )
            and self.source.space is MemSpace.SS
            and self.source.base == ("bp",)
            and self.source.size == self.value.size
            and self.source.status is AddressStatus.STABLE
            and self.source.segment_origin is SegmentOrigin.PROVEN
        )


@dataclass(frozen=True, slots=True)
class ScalarAffineExpression8616:
    """One exact width-bounded affine value and its complete SSA proof path."""

    root: IRValue
    width: int
    constant: int
    terms: tuple[ScalarAffineTerm8616, ...]
    definition_path: tuple[IndexedAddressDefinitionSite8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether the root, terms, constant, and path agree."""
        mask = (1 << (self.width * 8)) - 1 if self.width in {1, 2, 4} else -1
        root_exact = bool(
            isinstance(self.root.const, int)
            or isinstance(self.root.version, int)
            or isinstance(self.root.source_tmp, int)
        )
        return bool(
            mask >= 0
            and self.root.size == self.width
            and root_exact
            and 0 <= self.constant <= mask
            and all(term.complete for term in self.terms)
            and (not self.terms or self.definition_path)
            and all(site.complete for site in self.definition_path)
        )


@dataclass(frozen=True, slots=True)
class ScalarAffineTraceStats8616:
    """Closed accounting for one scalar affine trace attempt."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether one raw value became one retained expression."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class ScalarAffineTrace8616:
    """One proven scalar affine expression or one atomic typed refusal."""

    expression: ScalarAffineExpression8616 | None
    failure: ScalarAffineFailure8616 | None
    stats: ScalarAffineTraceStats8616

    @property
    def complete(self) -> bool:
        """Return whether the trace closed without partial publication."""
        return bool(
            self.failure is None
            and self.expression is not None
            and self.expression.complete
            and self.stats.complete
        )


__all__ = [
    "ScalarAffineExpression8616",
    "ScalarAffineFailure8616",
    "ScalarAffineTerm8616",
    "ScalarAffineTrace8616",
    "ScalarAffineTraceStats8616",
]
