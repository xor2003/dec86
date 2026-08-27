"""Materialize early exits from stored call-return conditions.

Layer: Structuring.
Responsibility: bind exact Lowering-owned call-return stack conditions to
terminal branch placeholders while preserving the continuation body.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Consumes typed condition/storage evidence and semantic branch-return effects.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here. Call discovery,
source/COD/name evidence, rendered text, and guessed return values are forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpression,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..lowering.call_return_stack_conditions import (
    StoredCallReturnConditionEvidence8616,
    StoredCallReturnConditionKind8616,
    classify_stored_call_return_condition_8616,
)
from .branch_return_expressions import (
    recover_branch_target_return_expression_8616,
    sole_return_statement_8616,
)
from .call_return_conditions import structured_condition_key_8616

__all__ = [
    "StoredCallReturnEarlyExitEvidence8616",
    "StoredCallReturnEarlyExitResult8616",
    "StoredCallReturnEarlyExitStatus8616",
    "materialize_stored_call_return_early_exit_8616",
]


class StoredCallReturnEarlyExitStatus8616(StrEnum):
    """Outcome of one stored call-return early-exit decision."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED = "refused"
    ALREADY_MATERIALIZED = "already_materialized"
    MATERIALIZED = "materialized"


@dataclass(frozen=True, slots=True)
class StoredCallReturnEarlyExitEvidence8616:
    """Closed evidence accounting for one early-exit materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class StoredCallReturnEarlyExitResult8616:
    """Typed result of one early-exit Structuring pass."""

    changed: bool
    status: StoredCallReturnEarlyExitStatus8616
    evidence: StoredCallReturnEarlyExitEvidence8616


class _StoredReturnCFunction8616(Protocol):
    """Structured function root consumed by this pass."""

    statements: object


class _StoredReturnCodegen8616(Protocol):
    """Owned codegen fields consumed and published by this pass."""

    cfunc: _StoredReturnCFunction8616
    _inertia_stored_call_return_early_exit_result_8616: StoredCallReturnEarlyExitResult8616


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to its signed identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _stored_return_operand_8616(
    condition: object,
    evidence: StoredCallReturnConditionEvidence8616,
) -> CVariable | None:
    """Return the exact stack operand from the inverted continuation guard."""
    expected_op = (
        "CmpNE"
        if evidence.kind is StoredCallReturnConditionKind8616.ZERO
        else "CmpEQ"
    )
    if not isinstance(condition, CBinaryOp) or condition.op != expected_op:
        return None
    variables = tuple(
        operand
        for operand in (condition.lhs, condition.rhs)
        if isinstance(operand, CVariable)
        and isinstance(operand.variable, SimStackVariable)
    )
    constants = tuple(
        operand
        for operand in (condition.lhs, condition.rhs)
        if isinstance(operand, CConstant) and operand.value == 0
    )
    if len(variables) != 1 or len(constants) != 1:
        return None
    variable = variables[0].variable
    store = evidence.stack_store
    if (
        variable.base != "bp"
        or not isinstance(variable.offset, int)
        or _canonical_stack_offset_8616(variable.offset) != _canonical_stack_offset_8616(store.dst_offset)
        or int(variable.size) != store.width
    ):
        return None
    return variables[0]


def _terminal_return_8616(body: object) -> CReturn | None:
    """Return one unique return occupying the continuation's terminal leaf."""
    returns = tuple(
        node
        for node in (body, *_iter_c_nodes_deep_8616(body))
        if isinstance(node, CReturn)
    )
    if len({id(node): node for node in returns}) != 1:
        return None
    current = body
    for _depth in range(12):
        if isinstance(current, CReturn):
            return current if current is returns[0] else None
        if not isinstance(current, CStatements):
            return None
        statements = tuple(current.statements or ())
        if not statements:
            return None
        current = statements[-1]
    return None


def _statement_container_8616(root: CStatements, statement: object) -> tuple[CStatements, int] | None:
    """Return the unique direct statement container and index."""
    matches: dict[tuple[int, int], tuple[CStatements, int]] = {}
    for candidate in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(candidate, CStatements):
            continue
        for index, child in enumerate(tuple(candidate.statements or ())):
            if child is statement:
                matches[(id(candidate), index)] = (candidate, index)
    return next(iter(matches.values())) if len(matches) == 1 else None


def _terminal_return_after_8616(container: CStatements, index: int) -> CReturn | None:
    """Return the unique terminal return after one flattened early-exit branch."""
    suffix = tuple(container.statements or ())[index + 1 :]
    returns = tuple(
        node
        for statement in suffix
        for node in (statement, *_iter_c_nodes_deep_8616(statement))
        if isinstance(node, CReturn)
    )
    if len({id(node): node for node in returns}) != 1 or not suffix:
        return None
    current = suffix[-1]
    for _depth in range(12):
        if isinstance(current, CReturn):
            return current if current is returns[0] else None
        if not isinstance(current, CStatements):
            return None
        statements = tuple(current.statements or ())
        if not statements:
            return None
        current = statements[-1]
    return None


def _matching_candidate_8616(
    project: object,
    codegen: object,
    root: CStatements,
) -> tuple[CIfElse, CExpression, StoredCallReturnConditionEvidence8616] | None:
    """Return one unique structured branch backed by exact stored-return evidence."""
    candidates: list[tuple[CIfElse, CExpression, StoredCallReturnConditionEvidence8616]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse) or len(node.condition_and_nodes) != 1:
            continue
        condition, _body = node.condition_and_nodes[0]
        key = structured_condition_key_8616(condition)
        if key is None:
            continue
        evidence = classify_stored_call_return_condition_8616(
            project,
            codegen,
            jcc_addr=key[0],
            block_addr=key[1],
        )
        if evidence is not None:
            candidates.append((node, condition, evidence))
    return candidates[0] if len(candidates) == 1 else None


def _result_8616(
    codegen: _StoredReturnCodegen8616,
    status: StoredCallReturnEarlyExitStatus8616,
    evidence: StoredCallReturnEarlyExitEvidence8616,
    *,
    changed: bool = False,
) -> StoredCallReturnEarlyExitResult8616:
    """Publish one typed Structuring result on the codegen owner."""
    result = StoredCallReturnEarlyExitResult8616(changed, status, evidence)
    codegen._inertia_stored_call_return_early_exit_result_8616 = result
    return result


def materialize_stored_call_return_early_exit_8616(
    project: object,
    codegen: object,
) -> StoredCallReturnEarlyExitResult8616:
    """Materialize a stored error return and its proven continuation return."""
    typed_codegen = cast(_StoredReturnCodegen8616, codegen)
    try:
        root = typed_codegen.cfunc.statements
    except AttributeError:
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.NOT_APPLICABLE,
            StoredCallReturnEarlyExitEvidence8616(),
        )
    if not isinstance(root, CStatements):
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.NOT_APPLICABLE,
            StoredCallReturnEarlyExitEvidence8616(),
        )
    candidate = _matching_candidate_8616(project, codegen, root)
    if candidate is None:
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.NOT_APPLICABLE,
            StoredCallReturnEarlyExitEvidence8616(),
        )
    branch, condition, stored_evidence = candidate
    return_operand = _stored_return_operand_8616(condition, stored_evidence)
    true_body = branch.condition_and_nodes[0][1]
    true_return = sole_return_statement_8616(true_body)
    taken_target = stored_evidence.condition.taken_target
    container = _statement_container_8616(root, branch)
    if (
        return_operand is None
        or true_return is None
        or not isinstance(taken_target, int)
        or container is None
    ):
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    statement_container, branch_index = container
    final_expression = recover_branch_target_return_expression_8616(
        project,
        codegen,
        taken_target,
    )
    if not isinstance(final_expression, CExpression):
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    true_ready = true_return.retval is return_operand or _same_c_expression_8616(
        true_return.retval,
        return_operand,
    )
    if branch.else_node is None:
        final_return = _terminal_return_after_8616(statement_container, branch_index)
        final_ready = final_return is not None and _same_c_expression_8616(
            final_return.retval,
            final_expression,
        )
        if true_ready and final_ready:
            return _result_8616(
                typed_codegen,
                StoredCallReturnEarlyExitStatus8616.ALREADY_MATERIALIZED,
                StoredCallReturnEarlyExitEvidence8616(1, 1, 1, 1, 0),
            )
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    if not isinstance(branch.else_node, CStatements):
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    false_return = _terminal_return_8616(branch.else_node)
    if false_return is None:
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    false_ready = _same_c_expression_8616(false_return.retval, final_expression)
    if true_return.retval is not None and not true_ready:
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    if false_return.retval is not None and not false_ready:
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.REFUSED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
        )
    true_return.retval = return_operand
    false_return.retval = final_expression
    continuation = tuple(branch.else_node.statements or ())
    branch.else_node = None
    statements = list(statement_container.statements or ())
    statements[branch_index : branch_index + 1] = [branch, *continuation]
    statement_container.statements = statements
    return _result_8616(
        typed_codegen,
        StoredCallReturnEarlyExitStatus8616.MATERIALIZED,
        StoredCallReturnEarlyExitEvidence8616(1, 1, 1, 1, 0),
        changed=True,
    )
