"""Layer: Frontend/angr compatibility.

Responsibility: patch angr Typehoon primitives so 16-bit pointer facts stay typed.
Forbidden: source/COD/text-backed type recovery or object-shape guessing.
Dynamic boundary: compatibility monkeypatches touch third-party angr Typehoon internals only.
"""

from __future__ import annotations

import contextlib
import importlib
import os
from collections import defaultdict
from typing import Any, cast

import claripy
import networkx
from angr.analyses.reaching_definitions import rd_state as _rd_state
from angr.analyses.typehoon import simple_solver as _typehoon_simple_solver
from angr.analyses.typehoon import translator as _typehoon_translator
from angr.analyses.typehoon.simple_solver import BASE_LATTICES
from angr.analyses.typehoon.typeconsts import (
    BottomType,
    Int,
    Int16,
    Pointer,
    Pointer32,
    Pointer64,
    TopType,
    TypeConstant,
)
from angr.analyses.typehoon.typeconsts import Int16 as TCInt16
from angr.analyses.typehoon.typevars import TypeVariable
from angr.analyses.variable_recovery import variable_recovery_base as _variable_recovery_base
from angr.sim_type import (
    SimTypeBottom,
    SimTypePointer,
)

try:
    _typehoon_lifter = importlib.import_module("angr.analyses.typehoon.lifter")
except ImportError:
    _typehoon_lifter = None

__all__ = ["apply_x86_16_typehoon_compatibility"]


def apply_x86_16_typehoon_compatibility() -> None:
    """Patch angr Typehoon runtime classes across a dynamic third-party compatibility boundary."""
    solver_dynamic = cast(Any, _typehoon_simple_solver)
    translator_dynamic = cast(Any, _typehoon_translator)
    lifter_dynamic = cast(Any, _typehoon_lifter)
    _orig_stack_addr_from_offset = _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset

    def _stack_addr_from_offset_8616(self: object, offset: int) -> int:
        state = cast(Any, self)
        if state.arch.bits == 16:
            return (offset + 0x7FFE) & 0xFFFF
        return cast(Any, _orig_stack_addr_from_offset)(self, offset)

    if (
        getattr(_variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset, "__name__", "")
        != "_stack_addr_from_offset_8616"
    ):
        _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset = _stack_addr_from_offset_8616

    _orig_initial_stack_pointer = _rd_state.ReachingDefinitionsState._initial_stack_pointer

    def _initial_stack_pointer_8616(self: object) -> object:
        state = cast(Any, self)
        if state.arch.bits == 16:
            return claripy.BVS("stack_base", 16, explicit_name=True)
        return cast(Any, _orig_initial_stack_pointer)(self)

    if (
        getattr(_rd_state.ReachingDefinitionsState._initial_stack_pointer, "__name__", "")
        != "_initial_stack_pointer_8616"
    ):
        cast(Any, _rd_state.ReachingDefinitionsState)._initial_stack_pointer = _initial_stack_pointer_8616

    class Pointer16(Pointer, TCInt16):
        """16-bit Typehoon pointer constant installed into angr's runtime lattice."""

        def __init__(self, basetype: TypeConstant | None = None, name: str | None = None) -> None:
            Pointer.__init__(self, basetype, name=name)
            TCInt16.__init__(self, name=name)

        def __repr__(self, memo: object | None = None) -> str:
            bt = self.basetype.__repr__(memo=memo) if isinstance(self.basetype, TCInt16) else repr(self.basetype)
            name_str = f"{self.name}#" if self.name else ""
            return f"{name_str}ptr16({bt})"

    if not hasattr(solver_dynamic, "Pointer16"):
        solver_dynamic.Pointer16 = Pointer16
        solver_dynamic.Pointer16_ = Pointer16()
        solver_dynamic.PRIMITIVE_TYPES = set(solver_dynamic.PRIMITIVE_TYPES) | {
            solver_dynamic.Pointer16_
        }

    base_lattice_16 = networkx.DiGraph()
    base_lattice_16.add_edge(TopType(), Int())
    base_lattice_16.add_edge(Int(), Int16())
    base_lattice_16.add_edge(Int16(), solver_dynamic.Pointer16_)
    base_lattice_16.add_edge(solver_dynamic.Pointer16_, BottomType())
    BASE_LATTICES[16] = base_lattice_16

    def _pointer_class_16(self: object) -> type[object]:
        solver = cast(Any, self)
        if solver.bits == 16:
            return Pointer16
        if solver.bits == 32:
            return Pointer32
        if solver.bits == 64:
            return Pointer64
        raise NotImplementedError(f"Unsupported bits {solver.bits}")

    solver_dynamic.SimpleSolver._pointer_class = _pointer_class_16

    _orig_simple_solver_init = _typehoon_simple_solver.SimpleSolver.__init__

    def _simple_solver_init_8616(
        self: object,
        bits: int,
        constraints: object,
        typevars: object,
        constraint_set_degradation_threshold: int = 150,
        stackvar_max_sizes: dict[TypeVariable, int] | None = None,
    ) -> None:
        solver = cast(Any, self)
        constraints_payload = cast(Any, constraints)
        typevars_payload = cast(Any, typevars)
        if bits != 16:
            return cast(Any, _orig_simple_solver_init)(
                self,
                bits,
                constraints_payload,
                typevars_payload,
                constraint_set_degradation_threshold=constraint_set_degradation_threshold,
                stackvar_max_sizes=stackvar_max_sizes,
            )

        threshold_raw = os.environ.get("INERTIA_X86_16_TYPEHOON_DEGRADE_THRESHOLD", "").strip()
        if threshold_raw:
            with contextlib.suppress(ValueError):
                constraint_set_degradation_threshold = max(1, int(threshold_raw, 0))
        else:
            constraint_set_degradation_threshold = min(int(constraint_set_degradation_threshold), 32)

        solver.bits = bits
        solver._constraints = constraints_payload
        solver._typevars = typevars_payload
        solver.stackvar_max_sizes = stackvar_max_sizes if stackvar_max_sizes is not None else {}
        solver._constraint_set_degradation_threshold = constraint_set_degradation_threshold
        solver._base_lattice = cast(Any, BASE_LATTICES[bits])
        solver._base_lattice_inverted = networkx.DiGraph()
        for src, dst in solver._base_lattice.edges:
            solver._base_lattice_inverted.add_edge(dst, src)

        solver.processed_constraints_count = 0
        solver.simplified_constraints_count = 0
        solver.eqclass_constraints_count = []

        solver._equivalence = defaultdict(dict)
        for func_tv in list(solver._constraints):
            if solver._constraints[func_tv]:
                solver.processed_constraints_count += len(solver._constraints[func_tv])
                solver.preprocess(func_tv)
                solver.simplified_constraints_count += len(solver._constraints[func_tv])

        solver._repr_tv_to_tvs = defaultdict(set)
        for tv, repr_tv in solver._equivalence.items():
            solver._repr_tv_to_tvs[repr_tv].add(tv)

        solver.solution = {}
        for tv, sol in solver._equivalence.items():
            if isinstance(tv, TypeVariable) and isinstance(sol, TypeConstant):
                solver.solution[tv] = sol

        solver._solution_cache = {}
        solver.solve()
        for func_tv in list(solver._constraints):
            solver._convert_arrays(solver._constraints[func_tv])

        for tv, tv_eq in solver._equivalence.items():
            if tv not in solver.solution and tv_eq in solver.solution:
                solver.solution[tv] = solver.solution[tv_eq]

    if getattr(_typehoon_simple_solver.SimpleSolver.__init__, "__name__", "") != "_simple_solver_init_8616":
        solver_dynamic.SimpleSolver.__init__ = _simple_solver_init_8616

    def _translate_pointer16(self: object, tc: object) -> SimTypePointer:
        translator = cast(Any, self)
        pointer = cast(Any, tc)
        if isinstance(pointer.basetype, _typehoon_translator.typeconsts.BottomType):
            internal = SimTypeBottom(label="void").with_arch(translator.arch)
        else:
            internal = translator._tc2simtype(pointer.basetype)
        return SimTypePointer(internal).with_arch(translator.arch)

    def _translate_simtype_pointer_16(self: object, st: object) -> object:
        translator = cast(Any, self)
        sim_type = cast(Any, st)
        base = translator._simtype2tc(sim_type.pts_to)
        if translator.arch.bits == 16:
            return Pointer16(base)
        if translator.arch.bits == 32:
            return Pointer32(base)
        if translator.arch.bits == 64:
            return Pointer64(base)
        raise TypeError(f"Unsupported pointer size {translator.arch.bits}")

    translator_dynamic.TypeTranslator._translate_Pointer16 = _translate_pointer16
    translator_dynamic.TypeTranslator._translate_SimTypePointer = _translate_simtype_pointer_16
    translator_dynamic.TypeConstHandlers[Pointer16] = translator_dynamic.TypeTranslator._translate_Pointer16
    translator_dynamic.SimTypeHandlers[SimTypePointer] = translator_dynamic.TypeTranslator._translate_SimTypePointer

    if lifter_dynamic is not None:
        _orig_lifter_init = lifter_dynamic.TypeLifter.__init__

        def _typelifter_init_16(self: object, bits: int) -> None:
            lifter = cast(Any, self)
            if bits not in (16, 32, 64):
                raise ValueError("TypeLifter only supports 16-bit, 32-bit, or 64-bit pointers.")
            lifter.bits = bits
            lifter.memo = {}

        def _lift_simtype_pointer_16(self: object, ty: object) -> object:
            lifter = cast(Any, self)
            sim_type = cast(Any, ty)
            if lifter.bits == 16:
                return Pointer16(lifter.lift(sim_type.pts_to))
            if lifter.bits == 32:
                return lifter_dynamic.Pointer32(lifter.lift(sim_type.pts_to))
            if lifter.bits == 64:
                return lifter_dynamic.Pointer64(lifter.lift(sim_type.pts_to))
            raise ValueError(f"Unsupported bits {lifter.bits}.")

        lifter_dynamic.TypeLifter.__init__ = _typelifter_init_16
        lifter_dynamic.TypeLifter._lift_SimTypePointer = _lift_simtype_pointer_16
