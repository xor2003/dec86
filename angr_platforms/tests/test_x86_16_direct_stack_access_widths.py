"""Regressions for exact-width direct stack-access projection."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    _resolve_direct_stack_update_cvar_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)


def test_byte_update_keeps_containing_word_as_allocation_only() -> None:
    """Materialize a byte lvalue without turning its word owner into a byte."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            statements=None,
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    owner_variable = SimStackVariable(-4, 2, base="bp", name="local_6")
    owner_cvar = structured_c.CVariable(
        owner_variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[owner_variable] = owner_cvar
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=owner_variable,
        cvar=owner_cvar,
        bp_offset=-6,
        entry_sp_offset=-4,
        size=2,
    )

    byte_cvar = _resolve_direct_stack_update_cvar_8616(codegen, -6, 1)

    assert isinstance(byte_cvar, structured_c.CVariable)
    assert byte_cvar is not owner_cvar
    assert isinstance(byte_cvar.variable, SimStackVariable)
    assert byte_cvar.variable.size == 1
    assert owner_variable.size == 2
    assert machine_bp_offset_for_stack_variable_8616(codegen, byte_cvar.variable) == -6
    registry = stack_variable_coordinate_registry_8616(codegen)
    assert registry.for_bp_range(-6, 1) is not None
    assert registry.for_bp_range(-6, 2) is not None
