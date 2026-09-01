"""Focused tests for typed segmented IR load carrier replay."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.function_ir_registry import FunctionIRArtifactVerdict8616
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactVerdict8616
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.lowering import ir_segmented_load_carriers as carriers


class _Codegen(SimpleNamespace):
    """Minimal identity allocation surface required by structured C nodes."""

    _next_node_index: int = 0
    cstyle_null_cmp: bool = False

    def next_ident(self, class_name: str) -> str:
        """Allocate one deterministic display identity."""
        self._next_node_index += 1
        return f"{class_name}_{self._next_node_index}"

    def next_node_idx(self) -> int:
        """Allocate one deterministic node index."""
        self._next_node_index += 1
        return self._next_node_index


def test_materializes_same_instruction_register_segmented_load(monkeypatch):
    """A proven MOV register, segmented-load temporary becomes one SEG_U16 expression."""
    arch = SimpleNamespace(registers={"di": (0x24, 2), "si": (0x18, 2), "ds": (0x30, 2)})
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project)
    lhs = structured_c.CVariable(
        SimRegisterVariable(0x18, 2, name="ir_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        lhs,
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x102},
    )
    statements = structured_c.CStatements([assignment], addr=0x100, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=statements)
    address = IRAddress(
        MemSpace.DS,
        base=("di",),
        offset=0x44D,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    tmp = IRValue(MemSpace.TMP, name="t7", size=2, source_tmp=7)
    loaded = IRValue(MemSpace.TMP, name="load_t7", size=2, source_tmp=7)
    block = SimpleNamespace(
        instrs=(
            IRInstr("LOAD", tmp, (address,), 2, 0x102),
            IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (loaded,), 2, 0x102),
        )
    )
    resolution = SimpleNamespace(
        verdict=FunctionIRArtifactVerdict8616.PROVEN,
        artifact=SimpleNamespace(blocks=(block,)),
    )
    monkeypatch.setattr(carriers, "registered_function_ir_artifact_8616", lambda *_args: resolution)

    assert carriers.materialize_ir_segmented_load_carriers_8616(codegen) is True
    assert isinstance(assignment.rhs, structured_c.CFunctionCall)
    assert assignment.rhs.callee_target == "SEG_U16"
    assert assignment.rhs.tags["inertia_source_instruction_addrs"] == (0x102,)
    stats = codegen._inertia_ir_segmented_load_carrier_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_materializes_proven_logical_word_reload(monkeypatch):
    """A byte-safe logical reload is emitted as one proven SEG_U16 expression."""
    arch = SimpleNamespace(registers={"di": (0x24, 2), "si": (0x18, 2), "ds": (0x30, 2)})
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project)
    lhs = structured_c.CVariable(
        SimRegisterVariable(0x18, 2, name="si"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        lhs,
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x104},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([assignment], addr=0x100, codegen=codegen),
    )
    address = IRAddress(
        MemSpace.DS,
        base=("di",),
        offset=0x1A85,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    logical_fact = carriers._LogicalRegisterWriteFact8616("si", 0x100, 0x104, address)
    monkeypatch.setattr(carriers, "_load_facts_8616", lambda _codegen: {})
    monkeypatch.setattr(carriers, "_register_write_facts_8616", lambda _codegen, _facts: {})
    monkeypatch.setattr(
        carriers,
        "_logical_register_write_facts_8616",
        lambda _codegen: {("si", 0x104): logical_fact},
    )

    assert carriers.materialize_ir_segmented_load_carriers_8616(codegen) is True
    assert isinstance(assignment.rhs, structured_c.CFunctionCall)
    assert assignment.rhs.callee_target == "SEG_U16"
    assert assignment.rhs.tags["inertia_source_instruction_addrs"] == (0x104,)


def test_preserves_earlier_typed_object_lowering(monkeypatch):
    """A resolved object expression outranks the lower-level register reload."""
    arch = SimpleNamespace(registers={"bx": (0x16, 2), "ax": (0, 2), "ds": (0x30, 2)})
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project)
    lhs = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ir_12"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    lowered_object = structured_c.CBinaryOp(
        "Or",
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        lhs,
        lowered_object,
        codegen=codegen,
        tags={"ins_addr": 0x102},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([assignment], addr=0x100, codegen=codegen),
    )
    address = IRAddress(
        MemSpace.DS,
        base=("bx",),
        offset=0xB4C,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="bx", size=2),),
    )
    fact = carriers._LogicalRegisterWriteFact8616("ax", 0x100, 0x102, address)
    monkeypatch.setattr(carriers, "_load_facts_8616", lambda _codegen: {})
    monkeypatch.setattr(carriers, "_register_write_facts_8616", lambda _codegen, _facts: {})
    monkeypatch.setattr(
        carriers,
        "_logical_register_write_facts_8616",
        lambda _codegen: {("ax", 0x102): fact},
    )

    assert carriers.materialize_ir_segmented_load_carriers_8616(codegen) is False
    assert assignment.rhs is lowered_object
    stats = codegen._inertia_ir_segmented_load_carrier_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_materializes_exact_same_block_ssa_read(monkeypatch):
    """A stable same-block reload defines and preserves its SSA carrier."""
    arch = SimpleNamespace(registers={"di": (0x24, 2), "si": (0x18, 2), "ds": (0x30, 2)})
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project)
    read = structured_c.CVariable(
        SimRegisterVariable(0x18, 2, ident="ir_4", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        structured_c.CVariable(
            SimRegisterVariable(0x40, 2, ident="out", region=0x100),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        read,
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([assignment], addr=0x100, codegen=codegen),
    )
    address = IRAddress(
        MemSpace.DS,
        base=("di",),
        offset=0x44D,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    block = SSABlock(
        0x100,
        (
            IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (), 2, 0x104),
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (), 2, 0x108),
        ),
        (),
    )
    artifact = SSAFunctionArtifact(0x100, (block,), predecessor_map={0x100: ()})
    ssa_resolution = SimpleNamespace(
        verdict=FunctionSSAArtifactVerdict8616.PROVEN,
        artifact=artifact,
    )
    logical_fact = carriers._LogicalRegisterWriteFact8616("si", 0x100, 0x104, address)
    monkeypatch.setattr(carriers, "_load_facts_8616", lambda _codegen: {})
    monkeypatch.setattr(carriers, "_register_write_facts_8616", lambda _codegen, _facts: {})
    monkeypatch.setattr(
        carriers,
        "_logical_register_write_facts_8616",
        lambda _codegen: {("si", 0x104): logical_fact},
    )
    monkeypatch.setattr(
        carriers,
        "registered_function_ssa_artifact_8616",
        lambda *_args: ssa_resolution,
    )

    assert carriers.materialize_ir_segmented_load_carriers_8616(codegen) is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    assert isinstance(statements[0], structured_c.CAssignment)
    assert isinstance(statements[0].rhs, structured_c.CFunctionCall)
    assert statements[0].rhs.callee_target == "SEG_U16"
    assert assignment.rhs is read


def test_refuses_reload_assignment_without_pre_mutation_boundary(monkeypatch):
    """A base mutation without an earlier AST boundary makes insertion unsafe."""
    arch = SimpleNamespace(registers={"di": (0x24, 2), "si": (0x18, 2), "ds": (0x30, 2)})
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project)
    read = structured_c.CVariable(
        SimRegisterVariable(0x18, 2, ident="ir_4", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    assignment = structured_c.CAssignment(
        structured_c.CVariable(SimRegisterVariable(0x40, 2, ident="out", region=0x100), codegen=codegen),
        read,
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([assignment], addr=0x100, codegen=codegen),
    )
    address = IRAddress(
        MemSpace.DS,
        base=("di",),
        offset=0,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    block = SSABlock(
        0x100,
        (
            IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (), 2, 0x104),
            IRInstr("MOV", IRValue(MemSpace.REG, name="di", size=2), (), 2, 0x106),
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (), 2, 0x108),
        ),
        (),
    )
    artifact = SSAFunctionArtifact(0x100, (block,), predecessor_map={0x100: ()})
    logical_fact = carriers._LogicalRegisterWriteFact8616("si", 0x100, 0x104, address)
    monkeypatch.setattr(carriers, "_load_facts_8616", lambda _codegen: {})
    monkeypatch.setattr(carriers, "_register_write_facts_8616", lambda _codegen, _facts: {})
    monkeypatch.setattr(
        carriers,
        "_logical_register_write_facts_8616",
        lambda _codegen: {("si", 0x104): logical_fact},
    )
    monkeypatch.setattr(
        carriers,
        "registered_function_ssa_artifact_8616",
        lambda *_args: SimpleNamespace(
            verdict=FunctionSSAArtifactVerdict8616.PROVEN,
            artifact=artifact,
        ),
    )

    assert carriers.materialize_ir_segmented_load_carriers_8616(codegen) is False
    assert assignment.rhs is read
    statements = codegen.cfunc.statements.statements
    assert statements == [assignment]


def test_selects_reload_across_unique_mutation_free_predecessor(monkeypatch):
    """A unique linear CFG edge preserves only an unmodified logical reload."""
    arch = SimpleNamespace(registers={"di": (0x24, 2), "si": (0x18, 2), "ds": (0x30, 2)})
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project, cfunc=SimpleNamespace(addr=0x100))
    address = IRAddress(
        MemSpace.DS,
        base=("di",),
        offset=0x44D,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    entry = SSABlock(
        0x100,
        (IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (), 2, 0x104),),
        (),
    )
    use = SSABlock(
        0x108,
        (IRInstr("CMP", None, (IRValue(MemSpace.REG, name="si", size=2),), 2, 0x108),),
        (),
    )
    artifact = SSAFunctionArtifact(
        0x100,
        (entry, use),
        predecessor_map={0x100: (), 0x108: (0x100,)},
    )
    monkeypatch.setattr(
        carriers,
        "registered_function_ssa_artifact_8616",
        lambda *_args: SimpleNamespace(
            verdict=FunctionSSAArtifactVerdict8616.PROVEN,
            artifact=artifact,
        ),
    )
    fact = carriers._LogicalRegisterWriteFact8616("si", 0x100, 0x104, address)

    selected = carriers._nearest_linear_logical_fact_8616(
        codegen,
        carriers._RegisterSSAIdentity8616(0x18, 2, 0x100, "ir_4"),
        0x108,
        {("si", 0x104): fact},
    )

    assert selected == fact

    mutated_entry = SSABlock(
        0x100,
        (
            IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (), 2, 0x104),
            IRInstr("ADD", IRValue(MemSpace.REG, name="si", size=2), (), 2, 0x106),
        ),
        (),
    )
    mutated_artifact = SSAFunctionArtifact(
        0x100,
        (mutated_entry, use),
        predecessor_map={0x100: (), 0x108: (0x100,)},
    )
    monkeypatch.setattr(
        carriers,
        "registered_function_ssa_artifact_8616",
        lambda *_args: SimpleNamespace(
            verdict=FunctionSSAArtifactVerdict8616.PROVEN,
            artifact=mutated_artifact,
        ),
    )

    assert carriers._nearest_linear_logical_fact_8616(
        codegen,
        carriers._RegisterSSAIdentity8616(0x18, 2, 0x100, "ir_4"),
        0x108,
        {("si", 0x104): fact},
    ) is None


def test_insertion_uses_statement_ancestry_of_exact_loop_condition() -> None:
    """A same-address loop-body boundary cannot compete with the condition owner."""
    codegen = _Codegen(project=SimpleNamespace(arch=SimpleNamespace()))
    read = structured_c.CVariable(
        SimRegisterVariable(0, 2, ident="ir_3", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x10F},
    )
    nested = structured_c.CAssignment(
        structured_c.CVariable(SimRegisterVariable(0x40, 2), codegen=codegen),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10B},
    )
    loop = structured_c.CDoWhileLoop(
        read,
        structured_c.CStatements([nested], addr=0x10B, codegen=codegen),
        codegen=codegen,
    )
    following = structured_c.CAssignment(
        structured_c.CVariable(SimRegisterVariable(0x18, 2), codegen=codegen),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10B},
    )
    replay = structured_c.CAssignment(
        structured_c.CVariable(SimRegisterVariable(0, 2), codegen=codegen),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x107},
    )
    root = structured_c.CStatements([following, loop], addr=0x100, codegen=codegen)

    changed = carriers._insert_before_unique_following_statement_8616(
        root,
        0x107,
        0x10F,
        replay,
        (read,),
    )

    assert changed is True
    assert root.statements == [following, replay, loop]
    assert loop.body.statements == [nested]


def test_inserted_assignment_owns_subsequent_read_replay() -> None:
    """Read-side replay cannot fold an inserted saved value back into memory."""
    codegen = _Codegen(project=SimpleNamespace(arch=SimpleNamespace()))
    identity = carriers._RegisterSSAIdentity8616(0, 2, 0x100, "ir_3")
    read = structured_c.CVariable(
        SimRegisterVariable(0, 2, ident="ir_3", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x10F},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(
                    structured_c.CVariable(SimRegisterVariable(0x40, 2), codegen=codegen),
                    read,
                    codegen=codegen,
                    tags={"ins_addr": 0x10F},
                )
            ],
            codegen=codegen,
        ),
    )

    replacements = carriers._read_side_logical_replacements_8616(
        codegen,
        {},
        frozenset({identity}),
    )

    assert replacements == {}
