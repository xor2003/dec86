from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from .alias_domains import DomainKey, FULL16, HIGH8, LOW8, register_domain_for_name, register_offset_for_name, register_pair_name, register_view_for_name, register_views_can_join


@dataclass(frozen=True)
class RegisterWideningCandidate:
    domain: DomainKey
    view: object
    expr: object

    def is_joinable_with(self, other: "RegisterWideningCandidate") -> bool:
        return self.domain == other.domain and self.view.can_join(other.view)

    @classmethod
    def from_expr(cls, expr: object) -> "RegisterWideningCandidate":
        if not isinstance(expr, structured_c.CVariable):
            raise ValueError("expected a register CVariable")
        variable = getattr(expr, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            raise ValueError("expected a register variable")
        domain, view = _register_domain_and_view(variable)
        if domain is None or view is None:
            raise ValueError("unsupported register slice")
        return cls(domain, view, expr)


def _register_pair_name_for_variable(variable) -> str | None:
    reg = getattr(variable, "reg", None)
    size = getattr(variable, "size", 0) or 0
    if isinstance(reg, int) and size in {1, 2}:
        pair_names = ("ax", "cx", "dx", "bx")
        pair_index = reg // 2
        if 0 <= pair_index < len(pair_names):
            return pair_names[pair_index]
    return register_pair_name(getattr(variable, "name", None))


def _register_domain_and_view(variable) -> tuple[DomainKey | None, object | None]:
    pair_name = _register_pair_name_for_variable(variable)
    if pair_name is None:
        return None, None
    domain = register_domain_for_name(pair_name)
    if domain is None:
        return None, None
    reg = getattr(variable, "reg", None)
    size = getattr(variable, "size", 0) or 0
    if isinstance(reg, int) and size == 1:
        view = HIGH8 if reg % 2 else LOW8
    elif isinstance(reg, int) and size == 2:
        view = FULL16
    else:
        view = register_view_for_name(getattr(variable, "name", None))
    return domain, view


def can_join_adjacent_register_slices(low_expr, high_expr, *, alias_state=None) -> bool:
    if alias_state is None:
        return False
    from .widening_model import prove_adjacent_storage_slices

    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok:
        return False
    try:
        low_candidate = RegisterWideningCandidate.from_expr(low_expr)
        high_candidate = RegisterWideningCandidate.from_expr(high_expr)
    except ValueError:
        return False
    if low_candidate.domain is None or high_candidate.domain is None:
        return False
    return low_candidate.is_joinable_with(high_candidate)


def join_adjacent_register_slices(low_expr, high_expr, codegen, *, alias_state=None) -> structured_c.CVariable | None:
    if not can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state):
        return None

    low_var = getattr(low_expr, "variable", None)
    high_var = getattr(high_expr, "variable", None)
    low_name = _register_pair_name_for_variable(low_var)
    high_name = _register_pair_name_for_variable(high_var)
    pair_name = low_name if low_name is not None else high_name
    if pair_name is None:
        return None

    reg_offset = register_offset_for_name(pair_name)
    project = getattr(codegen, "project", None)
    if project is not None:
        registers = getattr(project.arch, "registers", {})
        reg_info = registers.get(pair_name)
        if reg_info is not None and isinstance(reg_info, tuple):
            reg_offset = reg_info[0]
    if reg_offset is None:
        return None

    return structured_c.CVariable(
        SimRegisterVariable(reg_offset, 2, name=pair_name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


__all__ = [
    "RegisterWideningCandidate",
    "can_join_adjacent_register_slices",
    "join_adjacent_register_slices",
]
