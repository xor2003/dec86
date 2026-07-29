"""Bind proven scalar call returns to structured switch selectors.

Layer: Types/Lowering.
Responsibility: materialize one storage identity for an ABI-proven scalar call
return and its structured switch use after Structuring rebuilds the C AST.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This pass consumes typed callsite summaries and structured AST nodes only. It
does not infer calls from names or rendered C, recover switch shape, or relax
validation. A missing or interrupted dataflow path is an explicit refusal.

Dynamic boundary: angr structured-codegen nodes and codegen containers are
third-party surfaces, so narrowly scoped dynamic attribute access is required.
Owned callsite summaries and result contracts use typed dot access.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616

__all__ = [
    "CallReturnSelectorBindingResult8616",
    "bind_call_return_switch_selectors_8616",
]


@dataclass(frozen=True, slots=True)
class CallReturnSelectorBindingResult8616:
    """Closed evidence counters for scalar call-return selector binding."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one proven selector identity was bound."""
        return self.materialized_count > 0


def _register_cvar_8616(node: object) -> structured_c.CVariable | None:
    """Return a register-backed C variable through harmless C casts."""
    current = node
    while isinstance(current, structured_c.CTypeCast):
        current = current.expr
    if not isinstance(current, structured_c.CVariable):
        return None
    if not isinstance(current.variable, SimRegisterVariable):
        return None
    return current


def _same_register_view_8616(
    left: structured_c.CVariable,
    right: structured_c.CVariable,
) -> bool:
    """Return whether two C variables are the same physical register view."""
    left_variable = left.variable
    right_variable = right.variable
    return (
        isinstance(left_variable, SimRegisterVariable)
        and isinstance(right_variable, SimRegisterVariable)
        and left_variable.reg == right_variable.reg
        and left_variable.size == right_variable.size
    )


def _flatten_sequential_statements_8616(root: structured_c.CStatements) -> tuple[object, ...]:
    """Flatten only transparent nested statement lists in execution order."""
    flattened: list[object] = []
    for statement in root.statements:
        if isinstance(statement, structured_c.CStatements):
            flattened.extend(_flatten_sequential_statements_8616(statement))
        else:
            flattened.append(statement)
    return tuple(flattened)


def _statement_writes_register_view_8616(
    statement: object,
    register: structured_c.CVariable,
) -> bool:
    """Return whether a statement overwrites the candidate register view."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = _register_cvar_8616(statement.lhs)
    return lhs is not None and _same_register_view_8616(lhs, register)


def _statement_contains_call_8616(statement: object) -> bool:
    """Return whether a structured statement contains any call."""
    return any(
        isinstance(node, structured_c.CFunctionCall)
        for node in _iter_c_nodes_deep_8616(statement)
    )


def _selector_after_call_8616(
    statements: tuple[object, ...],
    call_index: int,
    register: structured_c.CVariable,
) -> structured_c.CVariable | None:
    """Find the first uninterrupted switch read of one call-return register."""
    for statement in statements[call_index + 1 :]:
        if isinstance(statement, structured_c.CSwitchCase):
            selector = _register_cvar_8616(statement.switch)
            if selector is not None and _same_register_view_8616(selector, register):
                return selector
            return None
        if _statement_writes_register_view_8616(statement, register):
            return None
        if _statement_contains_call_8616(statement):
            return None
        if not isinstance(
            statement,
            (structured_c.CAssignment, structured_c.CExpressionStatement),
        ):
            return None
    return None


def _structured_return_variable_8616(
    summary: CallsiteSummary8616,
    register: structured_c.CVariable,
    function_addr: int,
) -> SimRegisterVariable:
    """Build deterministic register-SSA identity from one exact callsite fact."""
    variable = register.variable
    assert isinstance(variable, SimRegisterVariable)
    name = variable.name if isinstance(variable.name, str) and variable.name else summary.return_register
    return SimRegisterVariable(
        variable.reg,
        variable.size,
        ident=f"call-return-{summary.callsite_addr:x}",
        name=name,
        region=function_addr,
    )


def _bind_cvar_identity_8616(
    cvar: structured_c.CVariable,
    variable: SimRegisterVariable,
) -> None:
    """Bind both concrete and unified views to one proven storage identity."""
    cvar.variable = variable
    cvar.unified_variable = variable


def bind_call_return_switch_selectors_8616(
    codegen: object,
) -> CallReturnSelectorBindingResult8616:
    """Bind exact used AX call returns to uninterrupted AX switch selectors.

    The call object must have an exact ``CallsiteSummary8616`` entry, its return
    shape must be the 16-bit AX view, and assignment-to-switch flow must contain
    no AX clobber, nested call, or control-flow boundary.
    """
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    function_addr = getattr(cfunc, "addr", None)
    raw_summaries = getattr(codegen, "_inertia_callsite_summaries", None)
    if (
        not isinstance(root, structured_c.CStatements)
        or not isinstance(function_addr, int)
        or not isinstance(raw_summaries, dict)
    ):
        return CallReturnSelectorBindingResult8616()

    summaries = {
        call_id: summary
        for call_id, summary in raw_summaries.items()
        if isinstance(call_id, int) and isinstance(summary, CallsiteSummary8616)
    }
    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    failure_count = 0
    visited_calls: set[int] = set()

    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        statements = _flatten_sequential_statements_8616(node)
        for index, statement in enumerate(statements):
            if not isinstance(statement, structured_c.CAssignment):
                continue
            call = statement.rhs
            if not isinstance(call, structured_c.CFunctionCall) or id(call) in visited_calls:
                continue
            visited_calls.add(id(call))
            summary = summaries.get(id(call))
            if (
                summary is None
                or summary.return_register != "ax"
                or summary.return_used is not True
                or summary.return_shape != "ax"
            ):
                continue
            raw_fact_count += 1
            register = _register_cvar_8616(statement.lhs)
            if register is None or register.variable.size != 2:
                failure_count += 1
                continue
            normalized_fact_count += 1
            selector = _selector_after_call_8616(statements, index, register)
            if selector is None:
                failure_count += 1
                continue
            classified_fact_count += 1
            identity = _structured_return_variable_8616(summary, register, function_addr)
            _bind_cvar_identity_8616(register, identity)
            _bind_cvar_identity_8616(selector, identity)
            materialized_count += 1

    return CallReturnSelectorBindingResult8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
