"""Materialize status-register outputs of DOS software interrupts.

Layer: Types/Lowering.
Responsibility: project an exact DOS interrupt call followed by a physical
FLAGS-carrier read into an explicit runtime status-output assignment.
Consumes typed call identity and structured register storage. It does not
infer branch meaning from rendered C or assembly text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from ..interrupt_contract import interrupt_core_addr_8616
from ..pipeline.errors import PipelineHardError

__all__ = [
    "SoftwareInterruptStatusOutputStats8616",
    "materialize_software_interrupt_status_outputs_8616",
]


@dataclass(frozen=True, slots=True)
class SoftwareInterruptStatusOutputStats8616:
    """Closed evidence counters for interrupt status-output Lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CodegenSurface8616(Protocol):
    """Owned fields needed from the dynamic structured-codegen boundary."""

    cfunc: _CFunctionSurface8616
    project: _ProjectRegisterSurface8616
    _inertia_software_interrupt_status_output_stats_8616: SoftwareInterruptStatusOutputStats8616


class _CFunctionSurface8616(Protocol):
    """Structured function root consumed by status-output Lowering."""

    statements: object


class _ArchRegisterSurface8616(Protocol):
    """Third-party architecture register map consumed at the typed boundary."""

    registers: Mapping[str, tuple[int, int]]


class _ProjectRegisterSurface8616(Protocol):
    """Project architecture surface consumed by status-output Lowering."""

    arch: _ArchRegisterSurface8616


class _TaggedNode8616(Protocol):
    """Third-party structured node tag boundary."""

    tags: object


class _CalleeIdentity8616(Protocol):
    """Third-party callee identity boundary."""

    name: object
    addr: object


def _instruction_address_8616(node: object) -> int | None:
    """Return one exact instruction tag from a structured node."""
    try:
        tags = cast(_TaggedNode8616, node).tags
    except AttributeError:
        return None
    if not isinstance(tags, dict):
        return None
    address = tags.get("ins_addr")
    return address if isinstance(address, int) else None


def _is_dos_int21_call_8616(node: object) -> bool:
    """Recognize the frontend-owned DOS interrupt helper identity."""
    if not isinstance(node, structured_c.CFunctionCall):
        return False
    target_addr = interrupt_core_addr_8616(0x21)
    if isinstance(node.callee_target, structured_c.CConstant):
        value = node.callee_target.value
        return isinstance(value, int) and value == target_addr
    if isinstance(node.callee_target, (str, int)) and node.callee_target in {
        "dos_int21",
        "interrupt_int21",
        target_addr,
    }:
        return True
    callee = node.callee_func
    if callee is None:
        return False
    boundary = cast(_CalleeIdentity8616, callee)
    try:
        name = boundary.name
    except AttributeError:
        name = None
    try:
        address = boundary.addr
    except AttributeError:
        address = None
    return name in {"dos_int21", "interrupt_int21"} or address == target_addr


def _interrupt_call_identity_8616(call: structured_c.CFunctionCall) -> int | None:
    """Return exact callsite tag or stable synthetic interrupt target identity."""
    address = _instruction_address_8616(call)
    if address is not None:
        return address
    target = call.callee_target
    if isinstance(target, structured_c.CConstant) and isinstance(target.value, int):
        return target.value
    return None


def _is_status_accessor_call_8616(node: object) -> bool:
    """Return whether a node is the owned status-output accessor."""
    return isinstance(node, structured_c.CFunctionCall) and node.callee_target == "dos_int21_flags"


def _physical_register_offset_8616(node: object) -> int | None:
    """Return exact physical register offset from either angr carrier form."""
    if isinstance(node, structured_c.CVariable):
        for candidate in (node.unified_variable, node.variable):
            if isinstance(candidate, SimRegisterVariable) and isinstance(candidate.reg, int):
                return candidate.reg
        return None
    if isinstance(node, structured_c.CDirtyExpression):
        offset = node.dirty.oident
        return offset if isinstance(offset, int) else None
    return None


def _statement_value_roots_8616(statement: object) -> tuple[object, ...]:
    """Return value-evaluated roots without descending into branch bodies."""
    if isinstance(statement, structured_c.CIfElse):
        return tuple(condition for condition, _body in statement.condition_and_nodes)
    return (statement,)


def _flags_carriers_8616(statement: object, flags_offset: int) -> tuple[structured_c.CExpression, ...]:
    """Collect one representative per physical FLAGS storage identity.

    Structured condition trees may clone the same register read into several
    boolean subexpressions.  Those nodes are distinct C-AST objects but consume
    one post-interrupt FLAGS definition, so object identity must not turn them
    into competing status outputs.
    """
    carriers: list[structured_c.CExpression] = []
    seen_registers: set[int] = set()
    for root in _statement_value_roots_8616(statement):
        assignment_lhs_ids = {
            id(node.lhs)
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, structured_c.CAssignment)
        }
        for node in _iter_c_nodes_deep_8616(root):
            register_offset = _physical_register_offset_8616(node)
            if (
                register_offset != flags_offset
                or id(node) in assignment_lhs_ids
                or register_offset in seen_registers
            ):
                continue
            seen_registers.add(register_offset)
            carriers.append(cast(structured_c.CExpression, node))
    return tuple(carriers)


def _writes_flags_8616(statement: object, flags_offset: int) -> bool:
    """Return whether a statement explicitly overwrites physical FLAGS."""
    for root in _statement_value_roots_8616(statement):
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, structured_c.CAssignment):
                continue
            if _physical_register_offset_8616(node.lhs) == flags_offset:
                return True
    return False


def _calls_in_statement_8616(statement: object) -> tuple[structured_c.CFunctionCall, ...]:
    """Return every call expression owned by one statement."""
    return tuple(
        node
        for root in _statement_value_roots_8616(statement)
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
    )


def _status_assignment_8616(
    carrier: structured_c.CExpression,
    callsite_addr: int,
    codegen: object,
) -> structured_c.CAssignment:
    """Build one explicit post-interrupt FLAGS output definition."""
    tags = {"ins_addr": callsite_addr, "inertia_software_interrupt_status_output_8616": True}
    accessor = structured_c.CFunctionCall(
        "dos_int21_flags",
        None,
        [],
        tags=tags,
        codegen=codegen,
    )
    return structured_c.CAssignment(
        cast(structured_c.CExpression, _clone_c_ast_tree_8616(carrier)),
        accessor,
        tags=tags,
        codegen=codegen,
    )


def materialize_software_interrupt_status_outputs_8616(codegen: object) -> bool:
    """Materialize every proven DOS interrupt FLAGS result consumed by C."""
    surface = cast(_CodegenSurface8616, codegen)
    cfunc = surface.cfunc
    root = cfunc.statements
    flags_info = surface.project.arch.registers.get("flags")
    if root is None or not isinstance(flags_info, tuple):
        stats = SoftwareInterruptStatusOutputStats8616()
        surface._inertia_software_interrupt_status_output_stats_8616 = stats
        return False
    flags_offset = int(flags_info[0])
    raw = normalized = classified = materialized = failures = 0
    changed = False
    containers = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CStatements)
    )
    for container in containers:
        statements = list(container.statements or ())
        pending: tuple[int, int] | None = None
        insertions: dict[int, structured_c.CAssignment] = {}
        for index, statement in enumerate(statements):
            calls = _calls_in_statement_8616(statement)
            interrupt_calls = tuple(call for call in calls if _is_dos_int21_call_8616(call))
            if interrupt_calls:
                if len(interrupt_calls) != 1:
                    pending = None
                    continue
                callsite_addr = _interrupt_call_identity_8616(interrupt_calls[0])
                pending = (index, callsite_addr) if isinstance(callsite_addr, int) else None
                continue
            carriers = _flags_carriers_8616(statement, flags_offset)
            if carriers and pending is not None:
                raw += 1
                call_index, callsite_addr = pending
                read_addr = _instruction_address_8616(statement)
                if len(carriers) != 1 or (
                    isinstance(read_addr, int)
                    and callsite_addr != interrupt_core_addr_8616(0x21)
                    and read_addr <= callsite_addr
                ):
                    failures += 1
                    pending = None
                    continue
                normalized += 1
                classified += 1
                if call_index + 1 < len(statements):
                    existing_calls = _calls_in_statement_8616(statements[call_index + 1])
                    if any(_is_status_accessor_call_8616(call) for call in existing_calls):
                        materialized += 1
                        pending = None
                        continue
                insertions[call_index] = _status_assignment_8616(
                    carriers[0],
                    callsite_addr,
                    codegen,
                )
                materialized += 1
                pending = None
                continue
            if pending is not None and (
                _writes_flags_8616(statement, flags_offset)
                or any(not _is_status_accessor_call_8616(call) for call in calls)
            ):
                pending = None
        if insertions:
            rewritten: list[structured_c.CStatement] = []
            for index, statement in enumerate(statements):
                rewritten.append(statement)
                insertion = insertions.get(index)
                if insertion is not None:
                    rewritten.append(insertion)
            container.statements = rewritten
            changed = True
    stats = SoftwareInterruptStatusOutputStats8616(
        raw,
        normalized,
        classified,
        materialized,
        failures,
    )
    surface._inertia_software_interrupt_status_output_stats_8616 = stats
    if failures or classified != materialized:
        raise PipelineHardError(
            "classified software interrupt status output was not materialized",
            layer="lowering",
        )
    return changed
