"""Tests for SSA-proven GP architectural runtime-state lowering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CDirtyExpression, CVariable
from angr.rustylib.ailment import VirtualVariableCategory
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.lowering.gp_register_state import (
    gp_live_in_names_from_ssa_8616,
    lower_architectural_gp_register_state_8616,
)


def _di_live_in_artifact() -> SSAFunctionArtifact:
    """Build one exact DI read before a later DI definition."""
    read = IRValue(MemSpace.REG, name="di", offset=0x1C, size=2)
    temp = IRValue(MemSpace.TMP, name="t0", offset=0, size=2)
    write = IRValue(MemSpace.REG, name="di", offset=0x1C, size=2)
    block = SSABlock(
        addr=0x10E85,
        instrs=(
            IRInstr("MOV", temp, (IRAddress(MemSpace.DS, base_values=(read,)),), 2, 0x10E87),
            IRInstr("MOV", write, (IRValue(MemSpace.CONST, const=0, size=2),), 2, 0x10E93),
        ),
        bindings=(),
    )
    return SSAFunctionArtifact(function_addr=0x10E85, blocks=(block,), predecessor_map={0x10E85: ()})


def test_gp_live_in_names_uses_upward_exposed_ssa_read() -> None:
    """A read before the first DI definition proves architectural live-in state."""
    assert gp_live_in_names_from_ssa_8616(_di_live_in_artifact()) == frozenset({"di"})


def test_gp_runtime_state_replaces_untagged_di_carrier() -> None:
    """An exact untagged DI carrier lowers to the stable runtime-state global."""
    arch = Arch86_16()
    offset, size = arch.registers["di"]
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={0x10E85: _di_live_in_artifact()},
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
    assert isinstance(replacement, CVariable)
    assert isinstance(replacement.variable, SimMemoryVariable)
    assert replacement.variable.name == "inertia_di"
    assert codegen._inertia_gp_register_state_lowering_stats_8616.failure_count == 0
