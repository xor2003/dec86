from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .alias_domains import register_pair_name


@dataclass(frozen=True)
class _StorageView:
    bit_offset: int = 0
    bit_width: int | None = None

    def is_full_width(self) -> bool:
        return self.bit_offset == 0 and self.bit_width is not None

    def end_bit(self) -> int | None:
        if self.bit_width is None:
            return None
        return self.bit_offset + self.bit_width

    def can_join(self, other: "_StorageView") -> bool:
        if self.bit_width is None or other.bit_width is None:
            return False
        return self.end_bit() == other.bit_offset or other.end_bit() == self.bit_offset

    def join(self, other: "_StorageView") -> "_StorageView | None":
        if self.bit_width is None or other.bit_width is None:
            return None
        if self.bit_offset <= other.bit_offset:
            first, second = self, other
        else:
            first, second = other, self
        if first.end_bit() != second.bit_offset:
            return None
        return _StorageView(first.bit_offset, first.bit_width + second.bit_width)


@dataclass(frozen=True)
class _StackSlotIdentity:
    base: str
    offset: int
    width: int | None = None
    region: int | None = None

    def end_offset(self) -> int | None:
        if self.width is None:
            return None
        return self.offset + self.width

    def can_join(self, other: "_StackSlotIdentity") -> bool:
        if self.base != other.base:
            return False
        if self.region is not None and other.region is not None and self.region != other.region:
            return False
        if self.width is None or other.width is None:
            return False
        return self.end_offset() == other.offset or other.end_offset() == self.offset

    def join(self, other: "_StackSlotIdentity") -> "_StackSlotIdentity | None":
        if not self.can_join(other):
            return None
        if self.offset <= other.offset:
            first, second = self, other
        else:
            first, second = other, self
        if first.end_offset() != second.offset:
            return None
        region = first.region if first.region == second.region else first.region or second.region
        return _StackSlotIdentity(first.base, first.offset, first.width + second.width, region=region)


def _storage_view_for_variable(variable) -> _StorageView:
    size = getattr(variable, "size", 0) or 0
    width_bits = size * 8 if size else None
    name = (getattr(variable, "ident", None) or getattr(variable, "name", None) or "").lower()
    if isinstance(variable, SimRegisterVariable):
        low_high_offsets = {
            "al": 0,
            "ah": 8,
            "bl": 0,
            "bh": 8,
            "cl": 0,
            "ch": 8,
            "dl": 0,
            "dh": 8,
        }
        if name in low_high_offsets:
            return _StorageView(low_high_offsets[name], width_bits)
    if isinstance(variable, SimStackVariable):
        return _StorageView(getattr(variable, "offset", 0) * 8, width_bits)
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", 0)
        if isinstance(addr, int):
            return _StorageView(addr * 8, width_bits)
    return _StorageView(0, width_bits)


@dataclass(frozen=True)
class _StorageDomainSignature:
    space: str
    width: int | None = None
    view: _StorageView | None = None
    stack_slot: _StackSlotIdentity | None = field(default=None, compare=False)

    def is_mixed(self) -> bool:
        return self.space == "mixed"

    def is_unknown(self) -> bool:
        return self.space == "unknown"

    def is_const(self) -> bool:
        return self.space == "const"

    def __str__(self) -> str:
        if self.width is None:
            return self.space
        return f"{self.space}:{self.width}"

    def can_join(self, other: "_StorageDomainSignature") -> bool:
        if self.space != other.space:
            return False
        if self.view is None or other.view is None:
            return False
        if self.space == "stack":
            if self.stack_slot is None or other.stack_slot is None:
                return self.view.can_join(other.view)
            if not self.stack_slot.can_join(other.stack_slot):
                return False
        return self.view.can_join(other.view)

    def join(self, other: "_StorageDomainSignature") -> "_StorageDomainSignature | None":
        if not self.can_join(other):
            return None
        joined_view = self.view.join(other.view)
        if joined_view is None:
            return None
        width = self.width or 0
        other_width = other.width or 0
        stack_slot = None
        if self.space == "stack" and self.stack_slot is not None and other.stack_slot is not None:
            stack_slot = self.stack_slot.join(other.stack_slot)
        return _StorageDomainSignature(self.space, width + other_width, joined_view, stack_slot=stack_slot)


@dataclass(frozen=True)
class _CopyAliasState:
    domain: _StorageDomainSignature
    expr: object
    needs_synthesis: bool = False

    def can_inline(self) -> bool:
        return not self.domain.is_mixed() and not self.needs_synthesis

    def merge(self, other: "_CopyAliasState") -> "_CopyAliasState":
        merged_domain = _merge_storage_domains(self.domain, other.domain)
        merged_expr = self.expr if self.expr is not None else other.expr
        merged_needs_synthesis = self.needs_synthesis or other.needs_synthesis
        if merged_domain.is_mixed():
            merged_needs_synthesis = True
            merged_expr = other.expr
        return _CopyAliasState(merged_domain, merged_expr, needs_synthesis=merged_needs_synthesis)


@dataclass(frozen=True)
class _StackPointerAliasState:
    base: structured_c.CVariable
    offset: int = 0

    def shifted(self, delta: int) -> "_StackPointerAliasState":
        return _StackPointerAliasState(self.base, self.offset + delta)


@dataclass(frozen=True)
class AliasStorageFacts:
    domain: _StorageDomainSignature
    identity: tuple[str, Any] | None = None

    def same_domain(self, other: "AliasStorageFacts") -> bool:
        if self.domain.space != other.domain.space:
            return False
        if self.identity is None or other.identity is None:
            return True
        kind, value = self.identity
        other_kind, other_value = other.identity
        if kind != other_kind:
            return False
        if kind == "register":
            return value == other_value
        if kind == "stack":
            return value == other_value or (hasattr(value, "can_join") and value.can_join(other_value))
        return True

    def compatible_view(self, other: "AliasStorageFacts") -> bool:
        if self.domain.view is None or other.domain.view is None:
            return False
        return self.domain.view.can_join(other.domain.view)

    def needs_synthesis(self) -> bool:
        return self.domain.is_mixed() or self.domain.is_unknown()

    def can_join(self, other: "AliasStorageFacts") -> bool:
        return self.same_domain(other) and self.compatible_view(other) and not self.needs_synthesis() and not other.needs_synthesis()


def _storage_domain_for_variable(variable) -> _StorageDomainSignature:
    if isinstance(variable, SimStackVariable):
        width = getattr(variable, "size", 0)
        base = getattr(variable, "base", None) or "sp"
        offset = getattr(variable, "offset", 0)
        region = getattr(variable, "region", None)
        return _StorageDomainSignature(
            "stack",
            width,
            _storage_view_for_variable(variable),
            stack_slot=_StackSlotIdentity(base, offset, width, region=region),
        )
    if isinstance(variable, SimRegisterVariable):
        width = getattr(variable, "size", 0)
        return _StorageDomainSignature("register", width, _storage_view_for_variable(variable))
    if isinstance(variable, SimMemoryVariable):
        width = getattr(variable, "size", 0)
        return _StorageDomainSignature("memory", width, _storage_view_for_variable(variable))
    return _StorageDomainSignature("unknown")


def _alias_identity_for_variable(variable) -> tuple[str, Any] | None:
    if isinstance(variable, SimStackVariable):
        slot = _stack_slot_identity_for_variable(variable)
        if slot is not None:
            return ("stack", slot)
    if isinstance(variable, SimRegisterVariable):
        name = getattr(variable, "name", None)
        pair_name = register_pair_name(name)
        if pair_name is not None:
            return ("register", pair_name)
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", None)
        if isinstance(addr, int):
            return ("memory", addr)
    return None


def _stack_slot_identity_for_variable(variable) -> _StackSlotIdentity | None:
    if not isinstance(variable, SimStackVariable):
        return None
    base = getattr(variable, "base", None) or "sp"
    offset = getattr(variable, "offset", 0)
    width = getattr(variable, "size", 0) or None
    region = getattr(variable, "region", None)
    return _StackSlotIdentity(base, offset, width, region=region)


def _same_stack_slot_identity(lhs, rhs) -> bool:
    if not isinstance(lhs, SimStackVariable) or not isinstance(rhs, SimStackVariable):
        return False
    lhs_identity = _stack_slot_identity_for_variable(lhs)
    rhs_identity = _stack_slot_identity_for_variable(rhs)
    if lhs_identity is None or rhs_identity is None:
        return False
    return lhs_identity == rhs_identity or lhs_identity.can_join(rhs_identity)


def _storage_domain_for_expr(expr) -> _StorageDomainSignature:
    expr = _unwrap_c_casts(expr)
    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return _StorageDomainSignature("unknown")
        return _storage_domain_for_variable(variable)
    if isinstance(expr, structured_c.CConstant):
        return _StorageDomainSignature("const")
    if isinstance(expr, structured_c.CUnaryOp):
        return _storage_domain_for_expr(expr.operand)
    if isinstance(expr, structured_c.CBinaryOp):
        domains: set[_StorageDomainSignature] = set()
        domain_list: list[_StorageDomainSignature] = []
        for child in (expr.lhs, expr.rhs):
            domain = _storage_domain_for_expr(child)
            if domain.is_const():
                continue
            if domain.is_unknown():
                return _StorageDomainSignature("unknown")
            domains.add(domain)
            domain_list.append(domain)
        if not domains:
            return _StorageDomainSignature("const")
        if len(domains) == 1:
            return next(iter(domains))
        if len(domain_list) == 2:
            joined = domain_list[0].join(domain_list[1])
            if joined is not None:
                return joined
        return _StorageDomainSignature("mixed")
    return _StorageDomainSignature("unknown")


def describe_alias_storage(expr) -> AliasStorageFacts:
    domain = _storage_domain_for_expr(expr)
    identity: tuple[str, Any] | None = None
    expr = _unwrap_c_casts(expr)
    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if variable is not None:
            identity = _alias_identity_for_variable(variable)
    return AliasStorageFacts(domain, identity)


def same_alias_storage_domain(lhs, rhs) -> bool:
    return describe_alias_storage(lhs).same_domain(describe_alias_storage(rhs))


def compatible_alias_storage_views(lhs, rhs) -> bool:
    return describe_alias_storage(lhs).compatible_view(describe_alias_storage(rhs))


def needs_alias_synthesis(expr) -> bool:
    return describe_alias_storage(expr).needs_synthesis()


def can_join_alias_storage(lhs, rhs) -> bool:
    return describe_alias_storage(lhs).can_join(describe_alias_storage(rhs))


def _merge_storage_domains(existing: _StorageDomainSignature | None, incoming: _StorageDomainSignature) -> _StorageDomainSignature:
    if existing is None:
        return incoming
    if existing == incoming:
        return existing
    joined = existing.join(incoming)
    if joined is not None:
        return joined
    return _StorageDomainSignature("mixed")


def _unwrap_c_casts(expr):
    while isinstance(expr, structured_c.CTypeCast):
        expr = expr.expr
    return expr


__all__ = [
    "_StorageView",
    "_StackSlotIdentity",
    "_StorageDomainSignature",
    "_CopyAliasState",
    "_StackPointerAliasState",
    "_stack_slot_identity_for_variable",
    "_same_stack_slot_identity",
    "_storage_view_for_variable",
    "_storage_domain_for_variable",
    "_storage_domain_for_expr",
    "_merge_storage_domains",
    "AliasStorageFacts",
    "can_join_alias_storage",
    "compatible_alias_storage_views",
    "describe_alias_storage",
    "needs_alias_synthesis",
    "same_alias_storage_domain",
]
