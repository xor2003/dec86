"""Regressions for exact-width direct stack-access projection."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.stack_memory_ssa_contracts import StackMemoryAliasFactKind8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.instruction_bp_stack_access import (
    InstructionBpStackAccess8616,
    InstructionBpStackAccessEvidence8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    _resolve_direct_stack_update_cvar_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
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


def test_instruction_proven_bp_access_materializes_without_frame_delta() -> None:
    """Keep exact Alias instruction evidence when frame coordinates are absent."""
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
    access = RealModeLinearStackAccess8616(-6, 1)
    instruction_access = InstructionBpStackAccess8616(
        -6,
        1,
        StackMemoryAliasFactKind8616.LOAD,
        InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS,
    )

    cvar = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        access,
        instruction_access=instruction_access,
    )

    assert isinstance(cvar, structured_c.CVariable)
    assert isinstance(cvar.variable, SimStackVariable)
    assert cvar.variable.size == 1


def test_logical_word_access_replaces_narrow_guessed_argument_type() -> None:
    """Keep exact Alias width authoritative over a stale byte prototype."""
    arch = Arch86_16()
    byte_type = SimTypeChar(False).with_arch(arch)
    word_type = SimTypeShort(False).with_arch(arch)
    stale_prototype = SimTypeFunction(
        [SimTypeLong(False).with_arch(arch), byte_type],
        word_type,
    ).with_arch(arch)
    stale_variable = SimStackVariable(8, 1, base="bp", name="arg_8")
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
            arg_list=[],
            statements=None,
            functy=stale_prototype,
            prototype=stale_prototype,
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    stale_cvar = structured_c.CVariable(
        stale_variable,
        variable_type=byte_type,
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[stale_variable] = stale_cvar
    codegen.cfunc.arg_list = [stale_cvar]

    cvar = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(8, 2),
        instruction_access=InstructionBpStackAccess8616(
            8,
            2,
            StackMemoryAliasFactKind8616.LOAD,
            InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS,
        ),
    )

    assert isinstance(cvar, structured_c.CVariable)
    assert isinstance(cvar.variable, SimStackVariable)
    assert cvar.variable.size == 2
    assert cvar.variable_type.size == 16
    assert codegen.cfunc.arg_list == [cvar]
    assert codegen.cfunc.functy.args[0].size == 16
