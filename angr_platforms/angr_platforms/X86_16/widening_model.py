from __future__ import annotations

from dataclasses import dataclass

from .alias_model import _StorageDomainSignature, _StorageView, _merge_storage_domains, _storage_domain_for_expr


@dataclass(frozen=True)
class WideningCandidate:
    domain: _StorageDomainSignature
    view: _StorageView
    expr: object

    def is_joinable_with(self, other: "WideningCandidate") -> bool:
        return self.domain.can_join(other.domain) and self.view.can_join(other.view)

    @classmethod
    def from_expr(cls, expr: object) -> "WideningCandidate":
        domain = _storage_domain_for_expr(expr)
        if domain.view is None:
            raise ValueError("cannot build widening candidate without a concrete storage view")
        return cls(domain, domain.view, expr)


def can_join_adjacent_storage_slices(low_expr, high_expr) -> bool:
    low_candidate = WideningCandidate.from_expr(low_expr)
    high_candidate = WideningCandidate.from_expr(high_expr)
    if low_candidate.domain.is_unknown() or high_candidate.domain.is_unknown():
        return False
    if low_candidate.domain.is_mixed() or high_candidate.domain.is_mixed():
        return False
    if not low_candidate.is_joinable_with(high_candidate):
        return False
    return True


def merge_storage_slice_domains(low_expr, high_expr) -> _StorageDomainSignature:
    low_domain = _storage_domain_for_expr(low_expr)
    high_domain = _storage_domain_for_expr(high_expr)
    return _merge_storage_domains(low_domain, high_domain)


__all__ = [
    "WideningCandidate",
    "can_join_adjacent_storage_slices",
    "merge_storage_slice_domains",
]
