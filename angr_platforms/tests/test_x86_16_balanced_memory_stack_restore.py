"""Focused tests for exact memory PUSH/POP stack-object rebinding."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.lowering.balanced_memory_stack_restore import (
    rebind_balanced_memory_stack_restores_8616,
)
from archinfo import ArchX86
from capstone.x86_const import X86_GRP_JUMP, X86_INS_CALL, X86_INS_POP, X86_INS_PUSH, X86_OP_MEM


class _Codegen(SimpleNamespace):
    """Minimal structured-codegen identity allocator."""

    _next_index = 0
    cstyle_null_cmp = False

    def next_node_idx(self) -> int:
        """Return one deterministic node identity."""
        self._next_index += 1
        return self._next_index

    def next_ident(self, name: str) -> str:
        """Return one deterministic display identity."""
        return name


def _instruction(address: int, instruction_id: int, *, displacement: int | None = None) -> SimpleNamespace:
    operand = (
        SimpleNamespace(
            type=X86_OP_MEM,
            size=2,
            mem=SimpleNamespace(segment=0, base=0, index=0, scale=1, disp=displacement),
        )
        if displacement is not None
        else None
    )
    return SimpleNamespace(
        address=address,
        id=instruction_id,
        operands=() if operand is None else (operand,),
        groups=(),
    )


def _stack_variable(codegen: _Codegen, offset: int, name: str) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimStackVariable(offset, 1, base="bp", name=name, region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )


def _memory_variable(codegen: _Codegen) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimMemoryVariable(0x42, 1, name="g_0042"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )


def test_rebinds_memory_restore_across_caller_neutral_call() -> None:
    """A POP of the same saved memory object reads the PUSH stack carrier."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    pushed = _stack_variable(codegen, -2, "local_2")
    popped = _stack_variable(codegen, -4, "local_4")
    push_assignment = structured_c.CAssignment(
        pushed,
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        popped,
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    instructions = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x42),
        _instruction(0x103, X86_INS_CALL),
        _instruction(0x108, X86_INS_POP, displacement=0x42),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert isinstance(pop_assignment.rhs, structured_c.CVariable)
    assert pop_assignment.rhs.variable.offset == -2
    assert pop_assignment.rhs.variable.name == "local_2"


def test_refuses_mismatched_memory_restore() -> None:
    """Different PUSH/POP memory operands do not establish save ownership."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    push_assignment = structured_c.CAssignment(
        _stack_variable(codegen, -2, "local_2"),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        _stack_variable(codegen, -4, "local_4"),
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    instructions = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x42),
        _instruction(0x108, X86_INS_POP, displacement=0x44),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is False
    assert pop_assignment.rhs.variable.offset == -4


def test_branch_ends_only_current_pairing_window() -> None:
    """An earlier branch does not hide a later straight-line save/restore pair."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    push_assignment = structured_c.CAssignment(
        _stack_variable(codegen, -2, "local_2"),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x110},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        _stack_variable(codegen, -4, "local_4"),
        codegen=codegen,
        tags={"ins_addr": 0x118},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    branch = _instruction(0x108, 0)
    branch.groups = (X86_GRP_JUMP,)
    instructions = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x30),
        branch,
        _instruction(0x110, X86_INS_PUSH, displacement=0x42),
        _instruction(0x113, X86_INS_CALL),
        _instruction(0x118, X86_INS_POP, displacement=0x42),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert pop_assignment.rhs.variable.offset == -2


def test_accepts_semantically_identical_overlapping_block_decode() -> None:
    """Duplicate wrappers from overlapping angr blocks retain one exact pair."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    push_assignment = structured_c.CAssignment(
        _stack_variable(codegen, -2, "local_2"),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        _stack_variable(codegen, -4, "local_4"),
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    first = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x42),
        _instruction(0x108, X86_INS_POP, displacement=0x42),
    )
    duplicate = tuple(
        _instruction(instruction.address, instruction.id, displacement=0x42)
        for instruction in first
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=first)),
            SimpleNamespace(capstone=SimpleNamespace(insns=duplicate)),
        )
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert pop_assignment.rhs.variable.offset == -2
