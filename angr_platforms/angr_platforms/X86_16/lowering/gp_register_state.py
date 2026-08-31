"""Lower proven SI/DI architectural live-ins to explicit C runtime state.

Layer: Types/Lowering.
Responsibility: project typed SSA-proven 16-bit index-register live-ins into
stable runtime globals instead of uninitialized automatic C locals.
Consumes IR/SSA facts. Do not infer semantics from listings or rendered C.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from ..c_ast_utils import _replace_c_children_8616
from ..ir.core import IRAddress, IRBinaryValue, IRCondition, IRValue, MemSpace
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.ssa_function import SSAFunctionArtifact

__all__ = [
    "GPRegisterStateLoweringStats8616",
    "gp_live_in_names_from_ssa_8616",
    "lower_architectural_gp_register_state_8616",
]

_RUNTIME_GP_STATE_SYMBOLS_8616 = {"di": "inertia_di", "si": "inertia_si"}
_RUNTIME_GP_STATE_ADDRESSES_8616 = {"di": 0x1_0010, "si": 0x1_0012}


class _ArchGPRegisters8616(Protocol):
    """Third-party architecture register maps used for exact identities."""

    registers: Mapping[str, tuple[int, int]]


class _ProjectGPRegisters8616(Protocol):
    """Project boundary consumed by GP-state lowering."""

    arch: _ArchGPRegisters8616


class _CFunctionGPRegisters8616(Protocol):
    """Structured function boundary mutated by GP-state lowering."""

    addr: int
    statements: object
    unified_local_vars: MutableMapping[object, object]


class _CodegenGPRegisters8616(Protocol):
    """Dynamic codegen boundary consumed by GP-state lowering."""

    cfunc: _CFunctionGPRegisters8616 | None
    project: _ProjectGPRegisters8616 | None
    _inertia_gp_register_state_lowering_stats_8616: GPRegisterStateLoweringStats8616


@dataclass(frozen=True, slots=True)
class GPRegisterStateLoweringStats8616:
    """Closed evidence counters for architectural GP-state lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _ir_register_names_8616(atom: object) -> tuple[str, ...]:
    """Return supported register names recursively referenced by one IR atom."""
    if isinstance(atom, IRValue):
        names: list[str] = []
        if atom.space is MemSpace.REG and atom.name in _RUNTIME_GP_STATE_SYMBOLS_8616:
            names.append(atom.name)
        if atom.index is not None:
            names.extend(_ir_register_names_8616(atom.index))
        return tuple(names)
    if isinstance(atom, IRBinaryValue):
        return (*_ir_register_names_8616(atom.lhs), *_ir_register_names_8616(atom.rhs))
    if isinstance(atom, IRAddress):
        return tuple(name for value in atom.base_values for name in _ir_register_names_8616(value))
    if isinstance(atom, IRCondition):
        return tuple(name for arg in atom.args for name in _ir_register_names_8616(arg))
    return ()


def gp_live_in_names_from_ssa_8616(artifact: SSAFunctionArtifact) -> frozenset[str]:
    """Return SI/DI names read on a path before any must-reaching definition."""
    supported = frozenset(_RUNTIME_GP_STATE_SYMBOLS_8616)
    uses_before_def: dict[int, set[str]] = {}
    definitions: dict[int, set[str]] = {}
    for block in artifact.blocks:
        seen_defs: set[str] = set()
        exposed: set[str] = set()
        for instruction in block.instrs:
            for argument in instruction.args:
                exposed.update(set(_ir_register_names_8616(argument)) - seen_defs)
            destination = instruction.dst
            if (
                isinstance(destination, IRValue)
                and destination.space is MemSpace.REG
                and destination.name in supported
            ):
                seen_defs.add(destination.name)
        uses_before_def[block.addr] = exposed
        definitions[block.addr] = seen_defs

    block_addrs = {block.addr for block in artifact.blocks}
    entry = artifact.function_addr
    must_in = {addr: (set() if addr == entry else set(supported)) for addr in block_addrs}
    changed = True
    while changed:
        changed = False
        for addr in sorted(block_addrs):
            if addr == entry:
                incoming: set[str] = set()
            else:
                predecessors = tuple(
                    pred for pred in artifact.predecessor_map.get(addr, ()) if pred in block_addrs
                )
                incoming = (
                    set.intersection(*(must_in[pred] | definitions[pred] for pred in predecessors))
                    if predecessors
                    else set()
                )
            if incoming != must_in[addr]:
                must_in[addr] = incoming
                changed = True
    return frozenset(
        name
        for addr, names in uses_before_def.items()
        for name in names - must_in.get(addr, set())
    )


def _register_name_for_shape_8616(project: _ProjectGPRegisters8616, offset: int, size: int) -> str | None:
    """Resolve one supported register only from an exact architecture shape."""
    names = {
        name.lower()
        for name, shape in project.arch.registers.items()
        if name.lower() in _RUNTIME_GP_STATE_SYMBOLS_8616
        and len(shape) >= 2
        and shape[0] == offset
        and shape[1] == size
    }
    return next(iter(names)) if len(names) == 1 else None


def _runtime_gp_cvar_8616(
    register_name: str,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    function_addr: int,
) -> structured_c.CVariable:
    """Build one explicit runtime-state C variable at its exact word width."""
    return structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_GP_STATE_ADDRESSES_8616[register_name],
            2,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
            region=function_addr,
            category="inertia_gp_register_state",
        ),
        variable_type=source.variable_type,
        codegen=source.codegen,
    )


def lower_architectural_gp_register_state_8616(codegen: object) -> bool:
    """Materialize SSA-proven SI/DI live-ins as explicit runtime globals."""
    boundary = cast(_CodegenGPRegisters8616, codegen)
    cfunc = boundary.cfunc
    project = boundary.project
    if cfunc is None or project is None:
        boundary._inertia_gp_register_state_lowering_stats_8616 = GPRegisterStateLoweringStats8616(0, 0, 0, 0, 0)
        return False
    resolution = registered_function_ssa_artifact_8616(project, cfunc.addr)
    if resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or resolution.artifact is None:
        boundary._inertia_gp_register_state_lowering_stats_8616 = GPRegisterStateLoweringStats8616(0, 0, 0, 0, 0)
        return False
    live_ins = gp_live_in_names_from_ssa_8616(resolution.artifact)
    raw_ids: set[int] = set()
    materialized_ids: set[int] = set()

    def transform(node: object) -> object:
        """Replace one exact live-in register carrier."""
        register_name: str | None = None
        if isinstance(node, structured_c.CDirtyExpression):
            dirty = node.dirty
            if dirty.category is VirtualVariableCategory.REGISTER:
                offset = dirty.oident
                size = dirty.size
                if isinstance(offset, int) and isinstance(size, int):
                    register_name = _register_name_for_shape_8616(project, offset, size)
        elif isinstance(node, structured_c.CVariable):
            variable = node.variable
            if isinstance(variable, SimRegisterVariable):
                register_name = _register_name_for_shape_8616(project, variable.reg, variable.size)
        if register_name is None:
            return node
        raw_ids.add(id(node))
        if register_name not in live_ins:
            return node
        materialized_ids.add(id(node))
        return _runtime_gp_cvar_8616(register_name, node, cfunc.addr)

    root = cfunc.statements
    new_root = transform(root)
    changed = new_root is not root
    if changed:
        cfunc.statements = new_root
    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True
    for variable in tuple(cfunc.unified_local_vars):
        if isinstance(variable, SimRegisterVariable):
            name = _register_name_for_shape_8616(project, variable.reg, variable.size)
            if name in live_ins:
                del cfunc.unified_local_vars[variable]
                changed = True
    classified = len(materialized_ids)
    boundary._inertia_gp_register_state_lowering_stats_8616 = GPRegisterStateLoweringStats8616(
        raw_fact_count=len(raw_ids),
        normalized_fact_count=len(raw_ids),
        classified_fact_count=classified,
        materialized_count=classified,
        failure_count=0,
    )
    return changed
