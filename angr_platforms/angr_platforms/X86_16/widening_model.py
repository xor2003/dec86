from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .alias_model import _StorageDomainSignature, _StorageView, _merge_storage_domains, _storage_domain_for_expr


@dataclass(frozen=True)
class WideningCandidate:
    domain: _StorageDomainSignature
    view: _StorageView
    expr: object

    def is_joinable_with(self, other: "WideningCandidate") -> bool:
        return self.domain.can_join(other.domain) and self.view.can_join(other.view)


def _unwrap_c_casts(expr):
    while isinstance(expr, structured_c.CTypeCast):
        expr = expr.expr
    return expr


def can_join_adjacent_storage_slices(low_expr, high_expr) -> bool:
    low_domain = _storage_domain_for_expr(low_expr)
    high_domain = _storage_domain_for_expr(high_expr)
    if low_domain.is_unknown() or high_domain.is_unknown():
        return False
    if low_domain.is_mixed() or high_domain.is_mixed():
        return False
    if not low_domain.can_join(high_domain):
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
