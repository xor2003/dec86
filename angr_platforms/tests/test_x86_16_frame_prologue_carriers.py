"""Regress frame-carrier classification and its numeric guest-offset obligations."""

import io
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.ir.scalar_definitions import (
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.lowering.frame_prologue_carriers import (
    is_exact_push_bp_carrier_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from archinfo import ArchX86
from x86_16_logical_memory_fixtures import lift_ir_artifact


@pytest.mark.parametrize("entry_sp", [0x1000, 0x0000, 0x0001])
def test_frame_lea_stores_numeric_guest_offset_and_restores_frame(entry_sp: int) -> None:
    """A scalar LEA store must use guest offsets, including wrapped frame saves."""
    # push bp; mov bp,sp; sub sp,2; lea ax,[bp-2]; mov [200h],ax;
    # mov sp,bp; pop bp; ret. No source or sidecar supplies its semantics.
    code = bytes.fromhex("55 89 e5 83 ec 02 8d 46 fe a3 00 02 89 ec 5d c3")
    project = angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    state = project.factory.blank_state(addr=0x1000, add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    })
    state.regs.ss = 0x2000
    state.regs.ds = 0x3000
    state.regs.sp = entry_sp
    state.regs.bp = 0x4000
    state.memory.store(0x20000 + entry_sp, b"\x00\x18")

    successors = project.factory.successors(state, num_inst=8)

    assert len(successors.flat_successors) == 1
    final = successors.flat_successors[0]
    expected_offset = (entry_sp - 4) & 0xFFFF
    assert final.solver.eval(final.regs.ax) == expected_offset
    assert final.solver.eval(final.memory.load(0x30200, 2, endness="Iend_LE")) == expected_offset
    assert final.solver.eval(final.memory.load(0x20200, 2, endness="Iend_LE")) == 0
    assert final.solver.eval(final.regs.bp) == 0x4000
    assert final.solver.eval(final.regs.sp) == (entry_sp + 2) & 0xFFFF
    assert final.solver.eval(final.regs.ip) == 0x1800


@pytest.mark.parametrize("entry_sp", [0x1000, 0x0000, 0x0001])
def test_frame_lea_ir_keeps_exact_entry_sp_definition_path(entry_sp: int) -> None:
    """Numeric frame recovery must use SSA provenance, not a host object address."""
    code = bytes.fromhex("55 89 e5 83 ec 02 8d 46 fe a3 00 02 89 ec 5d c3")
    artifact = build_x86_16_function_ssa(lift_ir_artifact(code))
    block = artifact.blocks[0]
    definitions = build_scalar_definition_index_8616(artifact)
    index, assignment = next(
        (index, instruction) for index, instruction in enumerate(block.instrs)
        if instruction.addr == 0x1006 and instruction.dst is not None
        and instruction.dst.space is MemSpace.REG and instruction.dst.name == "ax"
    )
    roots = set()
    sites = set()
    constants = set()

    def trace(value: IRValue, before: int) -> int:
        if value.const is not None:
            constants.add(value.const)
            return value.const
        candidates = reaching_scalar_definitions_8616(
            definitions, value, block_addr=block.addr, before_index=before,
        )
        if not candidates:
            roots.add((value.space, value.name, value.version, value.size))
            assert value.source_tmp is None
            assert (value.space, value.name, value.version, value.size) == (MemSpace.REG, "sp", 0, 2)
            return entry_sp
        assert len(candidates) == 1
        definition = candidates[0]
        instruction = definition.instruction
        assert instruction.size == 2
        assert instruction.op in {"MOV", "Iop_Add16", "Iop_Sub16"}
        sites.add((instruction.addr, instruction.op))
        operands = []
        for argument in instruction.args:
            assert isinstance(argument, IRValue)
            operands.append(trace(argument, definition.instr_index))
        if instruction.op == "MOV":
            assert len(operands) == 1
            result = operands[0]
        else:
            assert len(operands) == 2
            result = operands[0] + operands[1] if instruction.op == "Iop_Add16" else operands[0] - operands[1]
        return result & 0xFFFF

    source = assignment.args[0]
    assert isinstance(source, IRValue)
    assert trace(source, index) == (entry_sp - 4) & 0xFFFF

    assert roots == {(MemSpace.REG, "sp", 0, 2)}
    assert constants == {0, 2, 0xFFFE}
    assert (0x1000, "Iop_Sub16") in sites
    assert (0x1001, "MOV") in sites
    assert (0x1006, "Iop_Add16") in sites
    assert {address for address, _operation in sites} == {0x1000, 0x1001, 0x1006}


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def test_push_bp_carrier_accepts_semantic_cast_storage_view() -> None:
    """A typed byte view must retain the tagged frame-store identity."""
    codegen = _Codegen()
    project = codegen.project
    saved_frame = CVariable(
        SimStackVariable(-4, 2, base="bp", name="fn"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    frame_anchor = CVariable(
        SimStackVariable(0, 1, base="bp", name="local_0"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    destination = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(False),
        saved_frame,
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        CUnaryOp("Reference", frame_anchor, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    root = CStatements([assignment], codegen=codegen)

    assert is_exact_push_bp_carrier_8616(
        assignment,
        root,
        project,
        0x4010,
        canonical_frame_proven=True,
    )
