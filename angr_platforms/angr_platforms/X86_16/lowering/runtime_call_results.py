"""Read already-executed call outputs from proven architectural register state.

Layer: Types/Lowering.
Responsibility: consume exact callsite return-source and owned GP-write evidence
to materialize a value read without replaying a live call.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
No calls or statements are deleted or moved. Unknown placement, write shapes,
or intervening effects refuse reuse; physical register spelling is not proof.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import structured_callsite_addr_8616
from .gp_register_state import (
    RuntimeGPExpressionView8616,
    runtime_gp_expression_view_8616,
    runtime_gp_name_for_variable_8616,
    runtime_gp_state_expr_8616,
)


class RuntimeCallResultVerdict8616(StrEnum):
    """Whether a live producer can be read without executing it again."""

    ABSENT = "absent"
    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class RuntimeCallResultRead8616:
    """One return-source request and its explicit materialization counters."""

    verdict: RuntimeCallResultVerdict8616
    expression: structured_c.CExpression | None = None
    raw_fact_count: int = 1
    normalized_fact_count: int = 1
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _calls_at_8616(root: object, callsite_addr: int) -> tuple[structured_c.CFunctionCall, ...]:
    """Find exact tagged call nodes, without resolving targets by name."""
    return tuple(
        node for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
        and structured_callsite_addr_8616(node) == callsite_addr
    )


def _flatten_8616(statements: Sequence[object]) -> list[object]:
    """Flatten transparent sequences only, retaining control-flow boundaries."""
    result: list[object] = []
    for statement in statements:
        if isinstance(statement, structured_c.CStatements):
            result.extend(_flatten_8616(statement.statements))
        else:
            result.append(statement)
    return result


def _masked_call_write_8616(
    statement: object, call: structured_c.CFunctionCall, requested: RuntimeGPExpressionView8616,
) -> bool:
    """Recognize the exact low-word publication emitted by GP-state Lowering."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = runtime_gp_expression_view_8616(statement.lhs)
    rhs = statement.rhs
    if lhs is None or lhs.width != 4 or not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
        return False
    preserved, inserted = rhs.lhs, rhs.rhs
    if not isinstance(preserved, structured_c.CBinaryOp) or preserved.op != "And":
        return False
    preserved_view = runtime_gp_expression_view_8616(preserved.lhs)
    if preserved_view != lhs or not isinstance(preserved.rhs, structured_c.CConstant):
        return False
    if preserved.rhs.value != 0xFFFF0000:
        return False
    if not isinstance(inserted, structured_c.CBinaryOp) or inserted.op != "And":
        return False
    if inserted.lhs is not call or not isinstance(inserted.rhs, structured_c.CConstant):
        return False
    return bool(
        inserted.rhs.value == 0xFFFF
        and requested.width == 2 and requested.bit_shift == 0
        and requested.parent_name == lhs.parent_name
    )


def _preserves_result_8616(statement: object, parent_name: str) -> bool:
    """Allow only explicit writes to disjoint stack storage or other GP lanes."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    if any(not isinstance(node, (structured_c.CVariable, structured_c.CConstant,
                                 structured_c.CBinaryOp, structured_c.CTypeCast))
           for node in _iter_c_nodes_deep_8616(statement.rhs)):
        return False
    lhs = statement.lhs
    while isinstance(lhs, structured_c.CTypeCast):
        lhs = lhs.expr
    if not isinstance(lhs, structured_c.CVariable):
        return False
    if isinstance(lhs.variable, SimStackVariable):
        return True
    register = runtime_gp_name_for_variable_8616(lhs.variable)
    return register is not None and register != parent_name


def materialize_runtime_call_result_read_8616(
    root: object,
    prefix: Sequence[object],
    callsite_addr: int,
    register_name: str,
    *,
    codegen: object,
    function_addr: int,
) -> RuntimeCallResultRead8616:
    """Read a uniquely placed, unchanged GP call result or refuse live replay."""
    calls = _calls_at_8616(root, callsite_addr)
    statements = _flatten_8616(prefix)
    positions = [index for index, statement in enumerate(statements) if _calls_at_8616(statement, callsite_addr)]
    if not calls and not positions:
        return RuntimeCallResultRead8616(RuntimeCallResultVerdict8616.ABSENT)
    refused = RuntimeCallResultRead8616(RuntimeCallResultVerdict8616.UNKNOWN_REFUSE, failure_count=1)
    if len(calls) > 1 or len(positions) != 1:
        return refused
    index = positions[0]
    call = _calls_at_8616(statements[index], callsite_addr)
    expression = runtime_gp_state_expr_8616(register_name, codegen=codegen, function_addr=function_addr)
    view = runtime_gp_expression_view_8616(expression)
    if view is None or len(call) != 1 or not _masked_call_write_8616(statements[index], call[0], view):
        return refused
    if any(not _preserves_result_8616(statement, view.parent_name) for statement in statements[index + 1:]):
        return refused
    return RuntimeCallResultRead8616(
        RuntimeCallResultVerdict8616.PROVEN, expression,
        classified_fact_count=1, materialized_count=1,
    )
