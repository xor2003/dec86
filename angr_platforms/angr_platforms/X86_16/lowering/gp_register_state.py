"""Lower proven GP architectural live-ins to explicit C runtime state.

Layer: Types/Lowering.
Responsibility: project typed SSA-proven 16/32-bit GP-register live-ins into
coherent 32-bit runtime lanes instead of uninitialized automatic C locals.
Consumes IR/SSA facts. Do not infer semantics from listings or rendered C.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from ..c_ast_utils import _replace_c_children_8616
from ..ir.core import IRAddress, IRBinaryValue, IRCondition, IRValue, MemSpace
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.ssa_function import SSAFunctionArtifact
from .global_declarations import (
    GlobalDeclarationCType8616,
    record_global_declaration_spec_8616,
)

__all__ = [
    "GPRegisterStateLoweringStats8616",
    "gp_live_in_names_from_ssa_8616",
    "lower_architectural_gp_register_state_8616",
    "runtime_gp_live_in_name_8616",
    "runtime_gp_name_for_variable_8616",
    "runtime_gp_state_expr_8616",
]

_RUNTIME_GP_STATE_SYMBOLS_8616 = {
    "eax": "inertia_eax",
    "ebx": "inertia_ebx",
    "ecx": "inertia_ecx",
    "edx": "inertia_edx",
    "edi": "inertia_edi",
    "esi": "inertia_esi",
}
_RUNTIME_GP_STATE_ADDRESSES_8616 = {
    "eax": 0x1_0000,
    "ebx": 0x1_0004,
    "ecx": 0x1_0008,
    "edx": 0x1_000C,
    "esi": 0x1_0010,
    "edi": 0x1_0014,
}
_GP_REGISTER_VIEWS_8616 = {
    "eax": ("eax", 0, 4),
    "ax": ("eax", 0, 2),
    "al": ("eax", 0, 1),
    "ah": ("eax", 8, 1),
    "ebx": ("ebx", 0, 4),
    "bx": ("ebx", 0, 2),
    "bl": ("ebx", 0, 1),
    "bh": ("ebx", 8, 1),
    "ecx": ("ecx", 0, 4),
    "cx": ("ecx", 0, 2),
    "cl": ("ecx", 0, 1),
    "ch": ("ecx", 8, 1),
    "edx": ("edx", 0, 4),
    "dx": ("edx", 0, 2),
    "dl": ("edx", 0, 1),
    "dh": ("edx", 8, 1),
    "esi": ("esi", 0, 4),
    "si": ("esi", 0, 2),
    "edi": ("edi", 0, 4),
    "di": ("edi", 0, 2),
}


def runtime_gp_name_for_variable_8616(variable: object) -> str | None:
    """Return the architectural GP name owned by one runtime-state variable."""
    if not isinstance(variable, SimMemoryVariable):
        return None
    if variable.category != "inertia_gp_register_state":
        return None
    name = variable.name
    if not isinstance(name, str):
        return None
    return next(
        (
            register_name
            for register_name, symbol_name in _RUNTIME_GP_STATE_SYMBOLS_8616.items()
            if symbol_name == name
        ),
        None,
    )


def runtime_gp_live_in_name_8616(register_name: str) -> str | None:
    """Return the canonical runtime lane for one supported GP register view."""
    view = _GP_REGISTER_VIEWS_8616.get(register_name.strip().lower())
    return view[0] if view is not None else None


def runtime_gp_state_expr_8616(
    register_name: str,
    *,
    codegen: object,
    function_addr: int,
) -> structured_c.CExpression | None:
    """Materialize one supported GP view from explicit architectural runtime state."""
    view = _GP_REGISTER_VIEWS_8616.get(register_name.strip().lower())
    if view is None:
        return None
    parent_name, bit_shift, view_width = view
    parent = structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_GP_STATE_ADDRESSES_8616[parent_name],
            4,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[parent_name],
            region=function_addr,
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeInt(False),
        codegen=codegen,
    )
    if view_width == 4:
        return parent
    projected: structured_c.CExpression = parent
    if bit_shift:
        projected = structured_c.CBinaryOp(
            "Shr",
            projected,
            structured_c.CConstant(bit_shift, SimTypeInt(False), codegen=codegen),
            codegen=codegen,
        )
    return structured_c.CBinaryOp(
        "And",
        projected,
        structured_c.CConstant((1 << (view_width * 8)) - 1, SimTypeInt(False), codegen=codegen),
        codegen=codegen,
    )


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
        if atom.space is MemSpace.REG and isinstance(atom.name, str):
            view = _GP_REGISTER_VIEWS_8616.get(atom.name.lower())
            if view is not None:
                names.append(view[0])
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
    """Return GP names read on a path before any must-reaching definition."""
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
                and isinstance(destination.name, str)
            ):
                view = _GP_REGISTER_VIEWS_8616.get(destination.name.lower())
                if view is not None:
                    seen_defs.add(view[0])
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


def _register_projection_for_shape_8616(
    project: _ProjectGPRegisters8616,
    offset: int,
    size: int,
) -> tuple[str, int, int] | None:
    """Resolve one exact GP view into its coherent 32-bit runtime lane."""
    names = {
        name.lower(): _GP_REGISTER_VIEWS_8616[name.lower()]
        for name, shape in project.arch.registers.items()
        if name.lower() in _GP_REGISTER_VIEWS_8616
        and len(shape) >= 2
        and shape[0] == offset
        and shape[1] == size
    }
    projections = frozenset(names.values())
    return next(iter(projections)) if len(projections) == 1 else None


def _runtime_gp_cvar_8616(
    register_name: str,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    function_addr: int,
) -> structured_c.CVariable:
    """Build one explicit runtime-state C variable at its canonical width."""
    return structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_GP_STATE_ADDRESSES_8616[register_name],
            4,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
            region=function_addr,
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeInt(False),
        codegen=source.codegen,
    )


def _runtime_gp_expr_8616(
    register_name: str,
    bit_shift: int,
    view_width: int,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    function_addr: int,
) -> structured_c.CExpression:
    """Build one coherent full-register state expression or narrow view."""
    parent = _runtime_gp_cvar_8616(register_name, source, function_addr)
    if view_width == 4:
        return parent
    projected: structured_c.CExpression = parent
    if bit_shift:
        projected = structured_c.CBinaryOp(
            "Shr",
            projected,
            structured_c.CConstant(bit_shift, SimTypeInt(False), codegen=source.codegen),
            codegen=source.codegen,
        )
    mask = (1 << (view_width * 8)) - 1
    return structured_c.CBinaryOp(
        "And",
        projected,
        structured_c.CConstant(mask, SimTypeInt(False), codegen=source.codegen),
        codegen=source.codegen,
    )


def _runtime_gp_subview_write_8616(
    register_name: str,
    bit_shift: int,
    view_width: int,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    value: structured_c.CExpression,
    function_addr: int,
) -> structured_c.CAssignment:
    """Project one narrow-register write into its coherent 32-bit parent."""
    codegen = source.codegen
    parent_lhs = _runtime_gp_cvar_8616(register_name, source, function_addr)
    parent_read = _runtime_gp_cvar_8616(register_name, source, function_addr)
    value_mask = (1 << (view_width * 8)) - 1
    preserve_mask = 0xFFFF_FFFF ^ (value_mask << bit_shift)
    preserved = structured_c.CBinaryOp(
        "And",
        parent_read,
        structured_c.CConstant(preserve_mask, SimTypeInt(False), codegen=codegen),
        codegen=codegen,
    )
    inserted: structured_c.CExpression = structured_c.CBinaryOp(
        "And",
        value,
        structured_c.CConstant(value_mask, SimTypeInt(False), codegen=codegen),
        codegen=codegen,
    )
    if bit_shift:
        inserted = structured_c.CBinaryOp(
            "Shl",
            inserted,
            structured_c.CConstant(bit_shift, SimTypeInt(False), codegen=codegen),
            codegen=codegen,
        )
    return structured_c.CAssignment(
        parent_lhs,
        structured_c.CBinaryOp("Or", preserved, inserted, codegen=codegen),
        codegen=codegen,
    )


def lower_architectural_gp_register_state_8616(codegen: object) -> bool:
    """Materialize SSA-proven GP live-ins as explicit runtime globals."""
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
        if isinstance(node, structured_c.CAssignment):
            lhs = node.lhs
            lhs_projection: tuple[str, int, int] | None = None
            if isinstance(lhs, structured_c.CDirtyExpression):
                dirty = lhs.dirty
                if (
                    dirty.category is VirtualVariableCategory.REGISTER
                    and isinstance(dirty.oident, int)
                    and isinstance(dirty.size, int)
                ):
                    lhs_projection = _register_projection_for_shape_8616(
                        project,
                        dirty.oident,
                        dirty.size,
                    )
            elif isinstance(lhs, structured_c.CVariable) and isinstance(
                lhs.variable,
                SimRegisterVariable,
            ):
                lhs_projection = _register_projection_for_shape_8616(
                    project,
                    lhs.variable.reg,
                    lhs.variable.size,
                )
            if lhs_projection is not None:
                register_name, bit_shift, view_width = lhs_projection
                if register_name in live_ins and view_width < 4:
                    raw_ids.add(id(lhs))
                    materialized_ids.add(id(lhs))
                    record_global_declaration_spec_8616(
                        codegen,
                        ctype=GlobalDeclarationCType8616.UNSIGNED_LONG,
                        name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
                        array_len=None,
                    )
                    return _runtime_gp_subview_write_8616(
                        register_name,
                        bit_shift,
                        view_width,
                        lhs,
                        node.rhs,
                        cfunc.addr,
                    )
        projection: tuple[str, int, int] | None = None
        if isinstance(node, structured_c.CDirtyExpression):
            dirty = node.dirty
            if dirty.category is VirtualVariableCategory.REGISTER:
                offset = dirty.oident
                size = dirty.size
                if isinstance(offset, int) and isinstance(size, int):
                    projection = _register_projection_for_shape_8616(project, offset, size)
        elif isinstance(node, structured_c.CVariable):
            variable = node.variable
            if isinstance(variable, SimRegisterVariable):
                projection = _register_projection_for_shape_8616(project, variable.reg, variable.size)
        if projection is None:
            return node
        register_name, bit_shift, view_width = projection
        raw_ids.add(id(node))
        if register_name not in live_ins:
            return node
        materialized_ids.add(id(node))
        record_global_declaration_spec_8616(
            codegen,
            ctype=GlobalDeclarationCType8616.UNSIGNED_LONG,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
            array_len=None,
        )
        return _runtime_gp_expr_8616(
            register_name,
            bit_shift,
            view_width,
            node,
            cfunc.addr,
        )

    root = cfunc.statements
    new_root = transform(root)
    changed = new_root is not root
    if changed:
        cfunc.statements = new_root
    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True
    for variable in tuple(cfunc.unified_local_vars):
        if isinstance(variable, SimRegisterVariable):
            projection = _register_projection_for_shape_8616(project, variable.reg, variable.size)
            if projection is not None and projection[0] in live_ins:
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
