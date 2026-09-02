"""Regress canonical BP-frame setup carriers after GP-state lowering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.gp_register_state import (
    runtime_gp_state_assignment_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    prune_frame_prologue_stack_assignments_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_SP,
)


class _Codegen:
    """Minimal dynamic angr codegen boundary used by the focused regression."""

    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return a deterministic structured-C node index."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Return a deterministic structured-C node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return the requested stable identifier."""
        return name


def _instruction(
    address: int,
    size: int,
    instruction_id: int,
    *registers: int,
) -> SimpleNamespace:
    """Build one minimal decoded instruction boundary."""
    operands = tuple(
        SimpleNamespace(type=X86_OP_REG, size=2, reg=register)
        for register in registers
    )
    return SimpleNamespace(
        address=address,
        size=size,
        id=instruction_id,
        operands=operands,
    )


def _fixture(
    push_register: int,
) -> tuple[object, _Codegen, object, CAssignment, CAssignment]:
    """Build a lowered setup carrier without a surviving PUSH carrier."""
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    word_type = SimTypeShort(False)
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=word_type,
        codegen=codegen,
    )
    lowered = runtime_gp_state_assignment_8616(
        "bp",
        CUnaryOp("AddressOf", local, codegen=codegen),
        codegen=codegen,
        function_addr=0x1000,
    )
    assert lowered is not None
    setup = CAssignment(
        lowered.lhs,
        lowered.rhs,
        codegen=codegen,
        tags={"ins_addr": 0x1001},
    )
    ax_variable = SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax")
    body = CAssignment(
        CVariable(ax_variable, variable_type=word_type, codegen=codegen),
        CConstant(1, word_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    root = CStatements([setup, body], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(
                    insns=(
                        _instruction(0x1000, 1, X86_INS_PUSH, push_register),
                        _instruction(0x1001, 2, X86_INS_MOV, X86_REG_BP, X86_REG_SP),
                    )
                ),
            ),
        ),
    )
    return project, codegen, function, setup, body


def test_canonical_frame_prunes_lowered_setup_without_push_carrier() -> None:
    """Decoded entry plus an owned BP write survives earlier PUSH cleanup."""
    project, codegen, function, _setup, body = _fixture(X86_REG_BP)

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [body]
    stats = codegen._inertia_frame_prologue_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_noncanonical_entry_keeps_lowered_bp_assignment() -> None:
    """A tagged runtime BP write is not frame evidence without decoded PUSH BP."""
    project, codegen, function, setup, body = _fixture(X86_REG_AX)

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [setup, body]
