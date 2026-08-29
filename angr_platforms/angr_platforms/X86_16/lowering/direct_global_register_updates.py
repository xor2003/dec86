"""Materialize proven register-carried direct-global logical updates.

Layer: Types/Lowering.
Responsibility: consume adjacent binary instruction evidence for a direct
global load followed by a logical direct-global update through one register.
No rendered C text, symbol spelling, or corpus address participates in proof.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from capstone.x86_const import X86_INS_AND, X86_INS_MOV, X86_INS_OR, X86_INS_XOR, X86_OP_MEM, X86_OP_REG

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .real_mode_linear import _capstone_insns_for_direct_global_update_8616, _direct_global_update_blocks_8616
from .segment_access_policy import instruction_addrs_from_node_8616

type ProjectBoundary8616 = Any
type CodegenBoundary8616 = Any


class _FunctionLookupBoundary8616(Protocol):
    """Dynamic angr function-manager lookup used by materialization."""

    def get(self, key: object) -> object | None:
        """Return one function by address without creating it."""


def _boundary_attr_8616(value: object, name: str, default: object = None) -> object:
    """Read one dynamic third-party angr or Capstone boundary attribute."""
    # Dynamic boundary: angr and Capstone objects expose version-dependent fields.
    return getattr(value, name, default)


class DirectGlobalRegisterUpdateOp8616(StrEnum):
    """Supported logical operation proven by one machine instruction."""

    AND = "And"
    OR = "Or"
    XOR = "Xor"


@dataclass(frozen=True, slots=True)
class DirectGlobalRegisterUpdate8616:
    """One adjacent global-load and global-update instruction pair."""

    source_offset: int
    destination_offset: int
    width: int
    register_id: int
    operation: DirectGlobalRegisterUpdateOp8616
    load_insn_addr: int
    update_insn_addr: int


@dataclass(frozen=True, slots=True)
class DirectGlobalRegisterUpdateStats8616:
    """Closed materialization counters for register-carried updates."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every binary fact was materialized or refused."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count == self.classified_fact_count == self.raw_fact_count
        )


def _direct_memory_identity_8616(operand: object) -> tuple[int, int] | None:
    """Return an unindexed direct-memory offset and byte width."""
    if _boundary_attr_8616(operand, "type", None) != X86_OP_MEM:
        return None
    memory = _boundary_attr_8616(operand, "mem", None)
    width = _boundary_attr_8616(operand, "size", None)
    if memory is None or not isinstance(width, int) or width not in {1, 2, 4}:
        return None
    base = _boundary_attr_8616(memory, "base", 0)
    index = _boundary_attr_8616(memory, "index", 0)
    displacement = _boundary_attr_8616(memory, "disp", 0)
    if (
        not isinstance(base, int)
        or not isinstance(index, int)
        or not isinstance(displacement, int)
    ):
        return None
    if base != 0 or index != 0:
        return None
    return displacement & 0xFFFF, width


def collect_direct_global_register_updates_8616(
    project: ProjectBoundary8616,
    function: object,
) -> tuple[DirectGlobalRegisterUpdate8616, ...]:
    """Collect exact adjacent MOV-load plus logical-memory-update facts."""
    operations = {
        X86_INS_AND: DirectGlobalRegisterUpdateOp8616.AND,
        X86_INS_OR: DirectGlobalRegisterUpdateOp8616.OR,
        X86_INS_XOR: DirectGlobalRegisterUpdateOp8616.XOR,
    }
    facts: list[DirectGlobalRegisterUpdate8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        wrappers = _capstone_insns_for_direct_global_update_8616(project, block)
        for previous_wrapper, update_wrapper in pairwise(wrappers):
            previous = _boundary_attr_8616(previous_wrapper, "insn", previous_wrapper)
            update = _boundary_attr_8616(update_wrapper, "insn", update_wrapper)
            operation = operations.get(_boundary_attr_8616(update, "id", None))
            previous_operands_value = _boundary_attr_8616(previous, "operands", ())
            update_operands_value = _boundary_attr_8616(update, "operands", ())
            previous_operands: tuple[object, ...] = (
                tuple(previous_operands_value)
                if isinstance(previous_operands_value, Iterable)
                else ()
            )
            update_operands: tuple[object, ...] = (
                tuple(update_operands_value)
                if isinstance(update_operands_value, Iterable)
                else ()
            )
            if (
                operation is None
                or _boundary_attr_8616(previous, "id", None) != X86_INS_MOV
                or len(previous_operands) != 2
                or len(update_operands) != 2
                or _boundary_attr_8616(previous_operands[0], "type", None) != X86_OP_REG
                or _boundary_attr_8616(update_operands[1], "type", None) != X86_OP_REG
            ):
                continue
            source = _direct_memory_identity_8616(previous_operands[1])
            destination = _direct_memory_identity_8616(update_operands[0])
            register_id = _boundary_attr_8616(previous_operands[0], "reg", None)
            previous_address = _boundary_attr_8616(previous, "address", None)
            update_address = _boundary_attr_8616(update, "address", None)
            if (
                source is None
                or destination is None
                or source[1] != destination[1]
                or not isinstance(register_id, int)
                or register_id != _boundary_attr_8616(update_operands[1], "reg", None)
                or not isinstance(previous_address, int)
                or not isinstance(update_address, int)
            ):
                continue
            facts.append(
                DirectGlobalRegisterUpdate8616(
                    source[0], destination[0], source[1], register_id, operation,
                    previous_address, update_address,
                )
            )
    return tuple(dict.fromkeys(facts))


def _source_variable_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
    fact: DirectGlobalRegisterUpdate8616,
    variable_type: object,
) -> structured_c.CExpression | None:
    """Create a named source or an exact segmented-helper fallback."""
    if isinstance(synthetic_globals, dict):
        entry = synthetic_globals.get(fact.source_offset)
        if isinstance(entry, tuple) and len(entry) >= 2 and isinstance(entry[0], str):
            declared_width = entry[1]
            if isinstance(declared_width, int) and declared_width >= fact.width:
                region = _boundary_attr_8616(_boundary_attr_8616(codegen, "cfunc", None), "addr", None)
                return structured_c.CVariable(
                    SimMemoryVariable(fact.source_offset, fact.width, name=entry[0], region=region),
                    variable_type=variable_type,
                    codegen=codegen,
                )
    registers = _boundary_attr_8616(_boundary_attr_8616(project, "arch", None), "registers", None)
    register = registers.get("ds") if isinstance(registers, dict) else None
    if not isinstance(register, tuple) or len(register) < 2:
        return None
    segment = structured_c.CVariable(
        SimRegisterVariable(register[0], register[1], name="ds"),
        codegen=codegen,
    )
    return structured_c.CFunctionCall(
        "SEG_U16",
        None,
        [
            segment,
            structured_c.CConstant(fact.source_offset, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
        tags={"ins_addr": fact.load_insn_addr},
    )


def _replace_unsupported_carrier_8616(
    expression: object,
    replacement: structured_c.CExpression,
) -> int:
    """Replace unsupported leaves while preserving the existing projection tree."""
    if isinstance(expression, structured_c.CDirtyExpression):
        return -1
    changed = 0
    if isinstance(expression, structured_c.CBinaryOp):
        if isinstance(expression.lhs, structured_c.CDirtyExpression):
            expression.lhs = replacement
            changed += 1
        else:
            nested = _replace_unsupported_carrier_8616(expression.lhs, replacement)
            changed += max(0, nested)
        if isinstance(expression.rhs, structured_c.CDirtyExpression):
            expression.rhs = replacement
            changed += 1
        else:
            nested = _replace_unsupported_carrier_8616(expression.rhs, replacement)
            changed += max(0, nested)
    elif isinstance(expression, structured_c.CUnaryOp):
        if isinstance(expression.operand, structured_c.CDirtyExpression):
            expression.operand = replacement
            changed += 1
        else:
            nested = _replace_unsupported_carrier_8616(expression.operand, replacement)
            changed += max(0, nested)
    return changed


def materialize_direct_global_register_updates_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
) -> bool:
    """Replace exact tagged update RHSs from closed binary facts."""
    cfunc = _boundary_attr_8616(codegen, "cfunc", None)
    function_addr = _boundary_attr_8616(cfunc, "addr", None)
    functions = _boundary_attr_8616(_boundary_attr_8616(project, "kb", None), "functions", None)
    if functions is not None and isinstance(function_addr, int):
        try:
            function = cast(_FunctionLookupBoundary8616, functions).get(function_addr)
        except AttributeError:
            function = None
    else:
        function = None
    root = _boundary_attr_8616(cfunc, "statements", None)
    facts = collect_direct_global_register_updates_8616(project, function) if function is not None else ()
    debug = os.environ.get("INERTIA_DEBUG_DIRECT_GLOBAL_UPDATES") == "1"
    if debug:
        candidates = [
            (
                _boundary_attr_8616(_boundary_attr_8616(node, "lhs", None), "variable", None),
                type(_boundary_attr_8616(node, "lhs", None)).__name__,
                sorted(instruction_addrs_from_node_8616(node)),
                type(_boundary_attr_8616(node, "rhs", None)).__name__,
                sum(
                    isinstance(item, structured_c.CDirtyExpression)
                    for item in _iter_c_nodes_deep_8616(_boundary_attr_8616(node, "rhs", None))
                ),
            )
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, structured_c.CAssignment)
        ]
        print(f"[direct-global-register-update] facts={facts!r} assignments={candidates!r}", file=sys.stderr)
    materialized = 0
    failures = 0
    for fact in facts:
        direct_lane_matches = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, structured_c.CAssignment)
            and fact.update_insn_addr in instruction_addrs_from_node_8616(node)
            and isinstance(node.lhs, structured_c.CVariable)
            and isinstance(node.lhs.variable, SimMemoryVariable)
            and isinstance(node.lhs.variable.addr, int)
            and (node.lhs.variable.addr & 0xFFFF)
            in range(fact.destination_offset, fact.destination_offset + fact.width)
            and node.lhs.variable.size == 1
        ]
        segmented_store_matches = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, structured_c.CAssignment)
            and fact.update_insn_addr in instruction_addrs_from_node_8616(node)
            and isinstance(node.lhs, structured_c.CFunctionCall)
            and any(
                isinstance(item, structured_c.CDirtyExpression)
                for item in _iter_c_nodes_deep_8616(node.rhs)
            )
        ]
        lanes = {
            int(node.lhs.variable.addr) & 0xFFFF: node
            for node in direct_lane_matches
        }
        expected_lanes = set(range(fact.destination_offset, fact.destination_offset + fact.width))
        if set(lanes) == expected_lanes and len(direct_lane_matches) == fact.width:
            assignments = tuple(lanes.values())
        elif len(segmented_store_matches) == fact.width:
            assignments = tuple(segmented_store_matches)
        else:
            failures += 1
            continue
        replacements = 0
        for assignment in assignments:
            source = _source_variable_8616(project, codegen, synthetic_globals, fact, assignment.lhs.type)
            if source is None:
                break
            replacements += _replace_unsupported_carrier_8616(assignment.rhs, source)
        if replacements < fact.width:
            failures += 1
            continue
        materialized += 1
    stats = DirectGlobalRegisterUpdateStats8616(
        len(facts), len(facts), len(facts), materialized, failures
    )
    codegen._inertia_direct_global_register_update_stats_8616 = stats
    if not stats.complete:
        raise RuntimeError("direct-global register update evidence loop did not close")
    return materialized > 0


__all__ = [
    "DirectGlobalRegisterUpdate8616",
    "DirectGlobalRegisterUpdateOp8616",
    "DirectGlobalRegisterUpdateStats8616",
    "collect_direct_global_register_updates_8616",
    "materialize_direct_global_register_updates_8616",
]
