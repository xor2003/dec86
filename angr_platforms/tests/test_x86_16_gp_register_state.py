"""Tests for SSA-proven GP architectural runtime-state lowering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CVariable,
)
from angr.rustylib.ailment import VirtualVariableCategory
from angr.sim_type import SimTypeInt, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.lowering.gp_register_state import (
    gp_live_in_names_from_ssa_8616,
    lower_architectural_gp_register_state_8616,
    runtime_gp_name_for_variable_8616,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


def _gp_live_in_artifact(register_name: str = "di") -> SSAFunctionArtifact:
    """Build one exact GP read before a later definition of the same register."""
    offset, size = Arch86_16().registers[register_name]
    read = IRValue(MemSpace.REG, name=register_name, offset=offset, size=size)
    temp = IRValue(MemSpace.TMP, name="t0", offset=0, size=size)
    write = IRValue(MemSpace.REG, name=register_name, offset=offset, size=size)
    block = SSABlock(
        addr=0x10E85,
        instrs=(
            IRInstr("MOV", temp, (IRAddress(MemSpace.DS, base_values=(read,)),), 2, 0x10E87),
            IRInstr("MOV", write, (IRValue(MemSpace.CONST, const=0, size=size),), size, 0x10E93),
        ),
        bindings=(),
    )
    return SSAFunctionArtifact(function_addr=0x10E85, blocks=(block,), predecessor_map={0x10E85: ()})


def test_gp_live_in_names_uses_upward_exposed_ssa_read() -> None:
    """A read before the first DI definition proves architectural live-in state."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact()) == frozenset({"edi"})


def test_gp_live_in_names_supports_ax_parent_state() -> None:
    """AX uses the same typed architectural-state lane as index registers."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact("ax")) == frozenset({"eax"})


def test_gp_live_in_names_supports_eax_full_width_state() -> None:
    """An operand-size override keeps EAX as one typed 32-bit live-in lane."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact("eax")) == frozenset({"eax"})


def test_runtime_gp_name_uses_typed_state_category() -> None:
    """Synthetic runtime addresses retain architectural register identity."""
    variable = SimMemoryVariable(
        0x10014,
        4,
        name="inertia_edi",
        category="inertia_gp_register_state",
    )

    assert runtime_gp_name_for_variable_8616(variable) == "edi"


def test_tail_fingerprint_canonicalizes_runtime_edi_low_word_as_di() -> None:
    """A coherent EDI runtime lane and architectural DI have one identity."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    edi = CVariable(
        SimMemoryVariable(
            0x10014,
            4,
            name="inertia_edi",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeInt(False),
        codegen=codegen,
    )
    low_word = CBinaryOp(
        "And",
        edi,
        CConstant(0xFFFF, SimTypeInt(False), codegen=codegen),
        codegen=codegen,
    )

    assert _expr_fingerprint(low_word, project) == "reg:di"


def test_gp_runtime_state_replaces_untagged_di_carrier() -> None:
    """An exact DI carrier lowers to the low word of coherent EDI state."""
    arch = Arch86_16()
    offset, size = arch.registers["di"]
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={0x10E85: _gp_live_in_artifact()},
        _inertia_function_ssa_stages_8616={0x10E85: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    dirty = CDirtyExpression(
        Expr.VirtualVariable(1, 3, size * 8, VirtualVariableCategory.REGISTER, oident=offset),
        codegen=codegen,
    )
    root = CBinaryOp(
        "Shr",
        dirty,
        CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x10E85, statements=root, unified_local_vars={})

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements.lhs
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "And"
    assert isinstance(replacement.lhs, CVariable)
    assert isinstance(replacement.lhs.variable, SimMemoryVariable)
    assert replacement.lhs.variable.name == "inertia_edi"
    assert replacement.rhs.value == 0xFFFF
    assert codegen._inertia_gp_register_state_lowering_stats_8616.failure_count == 0


def test_gp_runtime_state_projects_al_from_coherent_ax_parent() -> None:
    """An AL live-in reads the low byte of AX runtime state, never separate storage."""
    arch = Arch86_16()
    al_offset, al_size = arch.registers["al"]
    read = IRValue(MemSpace.REG, name="al", offset=al_offset, size=al_size)
    block = SSABlock(
        addr=0x1241E,
        instrs=(
            IRInstr(
                "MOV",
                IRValue(MemSpace.TMP, name="t0", size=1),
                (read,),
                1,
                0x12431,
            ),
        ),
        bindings=(),
    )
    artifact = SSAFunctionArtifact(
        function_addr=0x1241E,
        blocks=(block,),
        predecessor_map={0x1241E: ()},
    )
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={0x1241E: artifact},
        _inertia_function_ssa_stages_8616={0x1241E: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    dirty = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            al_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=al_offset,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1241E, statements=dirty, unified_local_vars={})

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "And"
    assert isinstance(replacement.lhs, CVariable)
    assert replacement.lhs.variable.name == "inertia_eax"
    assert replacement.rhs.value == 0xFF
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned long", "inertia_eax", None),
    )


def test_gp_runtime_state_projects_dl_write_into_coherent_dx_parent() -> None:
    """A DL write preserves the high byte of the SSA-proven DX live-in."""
    arch = Arch86_16()
    dl_offset, dl_size = arch.registers["dl"]
    artifact = _gp_live_in_artifact("dx")
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={artifact.function_addr: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    dl = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            dl_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=dl_offset,
        ),
        codegen=codegen,
    )
    assignment = CAssignment(
        dl,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=assignment,
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CAssignment)
    assert isinstance(replacement.lhs, CVariable)
    assert replacement.lhs.variable.name == "inertia_edx"
    assert isinstance(replacement.rhs, CBinaryOp)
    assert replacement.rhs.op == "Or"
    assert replacement.rhs.lhs.op == "And"
    assert replacement.rhs.lhs.rhs.value == 0xFFFFFF00
    assert replacement.rhs.rhs.op == "And"
    assert replacement.rhs.rhs.rhs.value == 0xFF


def test_gp_runtime_state_materializes_eax_as_32bit_lane() -> None:
    """An SSA-proven EAX live-in lowers to one explicit 32-bit runtime global."""
    arch = Arch86_16()
    eax_offset, eax_size = arch.registers["eax"]
    artifact = _gp_live_in_artifact("eax")
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={artifact.function_addr: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    eax = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            eax_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=eax_offset,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=eax,
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CVariable)
    assert replacement.variable.name == "inertia_eax"
    assert isinstance(replacement.type, SimTypeInt)
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned long", "inertia_eax", None),
    )
