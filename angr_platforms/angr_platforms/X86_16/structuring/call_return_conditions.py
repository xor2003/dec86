"""Materialize proven call-return values used as structured conditions.

Layer: Structuring.
Responsibility: binds an existing structured condition to one exact typed
callsite whose AX-family return value feeds that condition.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This module owns only the call-to-condition CFG shape. Callsite discovery,
argument recovery, return-use classification, and register identity are
upstream typed evidence. Argument materialization remains in Types/Lowering.
Refuse ambiguous facts; never infer calls from rendered C, names, or samples.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CIfElse,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..call_target_identity import (
    resolve_x86_16_call_target_function_8616,
    x86_16_call_targets_equivalent_8616,
)
from ..callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
    structured_callsite_addr_8616,
)
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from ..lowering.call_return_stack_stores import (
    CallReturnStackStoreEvidence8616,
    classify_call_return_stack_store_8616,
)
from ..lowering.stack_lowering_from_facts import (
    materialize_stack_cvar_at_offset_from_facts_8616,
)
from ..pipeline.errors import PipelineHardError
from .expression_substitution import replace_exact_expression_8616


class _CallReturnFunction8616(Protocol):
    """Exact callee surface required to construct one structured call."""

    addr: int
    name: str


class _CallReturnFunctionManager8616(Protocol):
    """Third-party angr function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> _CallReturnFunction8616 | None:
        """Return one exact existing function."""


class _CallReturnKnowledgeBase8616(Protocol):
    """Third-party angr knowledge-base boundary."""

    functions: _CallReturnFunctionManager8616


class _CallReturnProject8616(Protocol):
    """Project fields required by call-return condition materialization."""

    arch: Arch
    kb: _CallReturnKnowledgeBase8616


class _CallReturnCFunction8616(Protocol):
    """Structured function root owned by angr codegen."""

    statements: object


class _CallReturnCodegen8616(Protocol):
    """Owned evidence fields consumed and produced by this pass."""

    cfunc: _CallReturnCFunction8616
    _inertia_typed_conditions: object
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_call_return_condition_stats_8616: CallReturnConditionStats8616


@dataclass(frozen=True, slots=True)
class CallReturnConditionStats8616:
    """Closed evidence accounting for call-return condition materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _condition_key_8616(expression: object) -> tuple[int, int] | None:
    """Return one exact typed condition instruction/block identity."""
    for node in _iter_c_nodes_deep_8616(expression):
        tags = node.tags if isinstance(node, CExpression) else None
        if not isinstance(tags, dict):
            continue
        ins_addr = tags.get("ins_addr")
        block_addr = tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            return ins_addr, block_addr
    return None


def _return_register_slice_8616(
    project: _CallReturnProject8616,
    summary: CallsiteSummary8616,
) -> tuple[int, int] | None:
    """Resolve the summary return register through the active architecture."""
    register_name = summary.return_register
    if not isinstance(register_name, str):
        return None
    register = project.arch.registers.get(register_name.lower())
    if register is None:
        return None
    return int(register[0]), int(register[1])


def _is_constant_value_8616(value: object) -> bool:
    """Return whether one typed IR operand is an exact integer constant."""
    return isinstance(value, IRValue) and value.space is MemSpace.CONST and isinstance(value.const, int)


def _is_return_register_value_8616(
    value: object,
    register_slice: tuple[int, int],
) -> bool:
    """Return whether one typed IR operand is the exact return register."""
    return (
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and int(value.offset) == register_slice[0]
        and int(value.size or register_slice[1]) == register_slice[1]
    )


def _condition_tests_return_register_8616(
    condition: ConditionIR,
    register_slice: tuple[int, int],
) -> bool:
    """Prove an equality-family zero test of the exact return register."""
    if condition.op not in {"eq", "ne", "zero", "nonzero"}:
        return False
    if condition.op in {"zero", "nonzero"}:
        return _is_return_register_value_8616(condition.lhs, register_slice)
    return (
        _is_return_register_value_8616(condition.lhs, register_slice)
        and _is_constant_value_8616(condition.rhs)
    ) or (
        _is_constant_value_8616(condition.lhs)
        and _is_return_register_value_8616(condition.rhs, register_slice)
    )


def _expression_return_register_count_8616(
    expression: object,
    register_slice: tuple[int, int],
) -> int:
    """Count exact structured return-register carriers in one condition."""
    count = 0
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
            continue
        variable = node.variable
        if int(variable.reg) == register_slice[0] and int(variable.size) == register_slice[1]:
            count += 1
    return count


def _replace_return_register_8616(
    expression: CExpression,
    register_slice: tuple[int, int],
    replacement: CExpression,
) -> CExpression:
    """Replace the single exact return-register leaf in a condition."""
    if isinstance(expression, CVariable) and isinstance(expression.variable, SimRegisterVariable):
        variable = expression.variable
        if int(variable.reg) == register_slice[0] and int(variable.size) == register_slice[1]:
            return replacement
        return expression
    if isinstance(expression, CBinaryOp):
        expression.lhs = _replace_return_register_8616(expression.lhs, register_slice, replacement)
        expression.rhs = _replace_return_register_8616(expression.rhs, register_slice, replacement)
    elif isinstance(expression, CUnaryOp):
        expression.operand = _replace_return_register_8616(expression.operand, register_slice, replacement)
    return expression


def _existing_callsite_count_8616(expression: object, callsite_addr: int) -> int:
    """Count already-bound calls for one exact machine callsite."""
    return sum(
        1
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall) and structured_callsite_addr_8616(node) == callsite_addr
    )


def _target_calls_8616(
    project: object,
    expression: object,
    target_addr: int,
) -> tuple[CFunctionCall, ...]:
    """Return calls whose exact angr callee address matches the typed target."""
    matches: list[CFunctionCall] = []
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, CFunctionCall) or node.callee_func is None:
            continue
        callee = cast(_CallReturnFunction8616, node.callee_func)
        try:
            callee_addr = callee.addr
        except AttributeError:
            continue
        if x86_16_call_targets_equivalent_8616(project, callee_addr, target_addr):
            matches.append(node)
    return tuple(matches)


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize a 16-bit BP displacement to its signed identity."""
    return offset - 0x10000 if offset >= 0x8000 else offset


def _is_exact_stack_destination_8616(
    expression: object,
    evidence: CallReturnStackStoreEvidence8616,
) -> bool:
    """Return whether one C variable is the exact proven return-store object."""
    if not isinstance(expression, CVariable) or not isinstance(expression.variable, SimStackVariable):
        return False
    variable = expression.variable
    return (
        variable.base == "bp"
        and isinstance(variable.offset, int)
        and _canonical_stack_offset_8616(variable.offset) == evidence.dst_offset
        and int(variable.size) == evidence.width
    )


def _stack_destination_count_8616(
    expression: object,
    evidence: CallReturnStackStoreEvidence8616,
) -> int:
    """Count exact uses of one proven BP-relative return-store object."""
    return sum(
        1
        for node in _iter_c_nodes_deep_8616(expression)
        if _is_exact_stack_destination_8616(node, evidence)
    )


def _unique_summary_call_8616(
    project: object,
    root: object,
    summary: CallsiteSummary8616,
) -> CFunctionCall | None:
    """Resolve one structured call by exact callsite or unique target identity."""
    bound = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and structured_callsite_addr_8616(node) == summary.callsite_addr
    )
    if len(bound) == 1:
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            return None
        exact = _target_calls_8616(project, bound[0], target_addr)
        return bound[0] if len(exact) == 1 else None
    if bound or not isinstance(summary.target_addr, int):
        return None
    target_calls = _target_calls_8616(project, root, summary.target_addr)
    return target_calls[0] if len(target_calls) == 1 else None


def _unique_call_assignment_8616(root: object, call: CFunctionCall) -> CAssignment | None:
    """Return the unique assignment whose RHS contains the exact call node."""
    assignments = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and any(candidate is call for candidate in _iter_c_nodes_deep_8616(node.rhs))
    )
    return assignments[0] if len(assignments) == 1 else None


def _materialize_stored_return_condition_8616(
    project: object,
    codegen: object,
    root: object,
    expression: CExpression,
    summary: CallsiteSummary8616,
    register_slice: tuple[int, int],
    summary_map: dict[int, CallsiteSummary8616],
) -> tuple[CExpression, bool] | None:
    """Bind a value-return store and its branch to one exact stack local."""
    evidence = classify_call_return_stack_store_8616(summary)
    if evidence is None or evidence.width != register_slice[1]:
        return None
    call = _unique_summary_call_8616(project, root, summary)
    if call is None:
        return None
    assignment = _unique_call_assignment_8616(root, call)
    if assignment is None:
        return None
    if _is_exact_stack_destination_8616(assignment.lhs, evidence):
        if _stack_destination_count_8616(expression, evidence) != 1:
            return None
        bind_structured_callsite_identity_8616(call, summary)
        summary_map[id(call)] = summary
        return expression, False
    old_lhs = assignment.lhs
    if not isinstance(old_lhs, CVariable) or not isinstance(old_lhs.variable, SimRegisterVariable):
        return None
    old_variable = old_lhs.variable
    if (int(old_variable.reg), int(old_variable.size)) != register_slice:
        return None
    definitions = sum(
        1
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and isinstance(node.lhs, CVariable)
        and node.lhs.variable is old_variable
    )
    if definitions != 1 or _expression_return_register_count_8616(expression, register_slice) != 1:
        return None
    destination = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        evidence.dst_offset,
        evidence.width,
    )
    if not isinstance(destination, CVariable):
        return None

    def replace_exact_carrier(node: object) -> object:
        """Replace only references to the assignment's exact SSA variable."""
        if isinstance(node, CVariable) and node.variable is old_variable:
            return destination
        return node

    changed = _replace_c_children_8616(root, replace_exact_carrier)
    remaining_registers = _expression_return_register_count_8616(expression, register_slice)
    if remaining_registers == 1:
        expression = _replace_return_register_8616(expression, register_slice, destination)
        changed = True
    elif remaining_registers != 0:
        return None
    if not changed or not _is_exact_stack_destination_8616(assignment.lhs, evidence):
        return None
    if _stack_destination_count_8616(expression, evidence) != 1:
        return None
    bind_structured_callsite_identity_8616(call, summary)
    summary_map[id(call)] = summary
    return expression, True


def materialize_call_return_conditions_8616(project: object, codegen: object) -> bool:
    """Bind exact return-used callsites to their structured AX conditions."""
    typed_project = cast(_CallReturnProject8616, project)
    typed_codegen = cast(_CallReturnCodegen8616, codegen)
    try:
        root = typed_codegen.cfunc.statements
        inventory = typed_codegen._inertia_callsite_summary_inventory_8616
        conditions = tuple(
            condition
            for condition in cast(tuple[object, ...], typed_codegen._inertia_typed_conditions)
            if isinstance(condition, ConditionIR)
        )
    except (AttributeError, TypeError):
        return False
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory must be a dict")
    condition_by_key = {
        (condition.src_insn, condition.block_addr): condition
        for condition in conditions
        if isinstance(condition.src_insn, int) and isinstance(condition.block_addr, int)
    }
    summaries_by_return = {
        summary.return_addr: summary
        for summary in inventory.values()
        if isinstance(summary, CallsiteSummary8616)
        and isinstance(summary.return_addr, int)
        and summary.return_used is True
        and summary.return_use_kind
        in {
            CallsiteReturnUseKind8616.CONDITION,
            CallsiteReturnUseKind8616.VALUE,
        }
        and isinstance(summary.target_addr, int)
    }
    raw = normalized = classified = materialized = failed = 0
    changed = False
    try:
        summary_map = typed_codegen._inertia_callsite_summaries
    except AttributeError:
        summary_map = {}
        typed_codegen._inertia_callsite_summaries = summary_map
    if not isinstance(summary_map, dict):
        raise TypeError("structured callsite summary map must be a dict")
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse) or len(node.condition_and_nodes) != 1:
            continue
        expression, body = node.condition_and_nodes[0]
        key = _condition_key_8616(expression)
        condition = condition_by_key.get(key) if key is not None else None
        if condition is None or not isinstance(condition.block_addr, int):
            continue
        summary = summaries_by_return.get(condition.block_addr)
        if summary is None:
            continue
        raw += 1
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            failed += 1
            continue
        register_slice = _return_register_slice_8616(typed_project, summary)
        if register_slice is None or not _condition_tests_return_register_8616(condition, register_slice):
            failed += 1
            continue
        normalized += 1
        if summary.return_use_kind is CallsiteReturnUseKind8616.VALUE:
            stored_result = _materialize_stored_return_condition_8616(
                project,
                codegen,
                root,
                expression,
                summary,
                register_slice,
                summary_map,
            )
            if stored_result is None:
                failed += 1
                continue
            replacement, stored_changed = stored_result
            node.condition_and_nodes = [(replacement, body)]
            classified += 1
            materialized += 1
            changed = stored_changed or changed
            continue
        existing_count = _existing_callsite_count_8616(expression, summary.callsite_addr)
        if existing_count == 1:
            exact_calls = _target_calls_8616(project, expression, target_addr)
            if len(exact_calls) != 1:
                failed += 1
                continue
            summary_map[id(exact_calls[0])] = summary
            classified += 1
            materialized += 1
            continue
        if existing_count != 0:
            failed += 1
            continue
        target_calls = _target_calls_8616(project, expression, target_addr)
        if len(target_calls) == 1:
            callee = resolve_x86_16_call_target_function_8616(project, target_addr)
            if callee is None or not isinstance(callee.name, str) or not callee.name:
                failed += 1
                continue
            call = CFunctionCall(callee.name, callee, [], codegen=codegen)
            bind_structured_callsite_identity_8616(call, summary)
            summary_map[id(call)] = summary
            replacement = replace_exact_expression_8616(expression, target_calls[0], call)
            node.condition_and_nodes = [(replacement, body)]
            classified += 1
            materialized += 1
            changed = True
            continue
        if target_calls or _expression_return_register_count_8616(expression, register_slice) != 1:
            failed += 1
            continue
        callee = resolve_x86_16_call_target_function_8616(project, target_addr)
        if callee is None or not isinstance(callee.name, str) or not callee.name:
            failed += 1
            continue
        classified += 1
        call = CFunctionCall(callee.name, callee, [], codegen=codegen)
        bind_structured_callsite_identity_8616(call, summary)
        summary_map[id(call)] = summary
        original_tags = dict(expression.tags) if isinstance(expression.tags, dict) else {}
        replacement = _replace_return_register_8616(expression, register_slice, call)
        if replacement is call:
            replacement = CBinaryOp(
                "CmpNE",
                call,
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
                tags=original_tags,
            )
        node.condition_and_nodes = [(replacement, body)]
        materialized += 1
        changed = True
    stats = CallReturnConditionStats8616(raw, normalized, classified, materialized, failed)
    typed_codegen._inertia_call_return_condition_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified call-return conditions were not materialized")
    return changed
