from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.structuring.direct_stack_move_pretest_initializers import (
    materialize_direct_stack_move_pretest_initializers_8616,
    place_direct_stack_move_pretest_initializer_assignment_8616,
)
from archinfo import ArchX86
from capstone import CS_GRP_JUMP
from capstone.x86_const import X86_INS_JLE, X86_INS_JMP, X86_OP_IMM


def _instruction(
    address: int,
    *,
    instruction_id: int = 0,
    target: int | None = None,
) -> SimpleNamespace:
    operands = (
        (SimpleNamespace(type=X86_OP_IMM, imm=target),) if target is not None else ()
    )
    return SimpleNamespace(
        address=address,
        id=instruction_id,
        groups=(CS_GRP_JUMP,) if target is not None else (),
        operands=operands,
    )


def _function(*, with_entry_jump: bool = True) -> SimpleNamespace:
    entry_jump = (
        _instruction(0x1025C, instruction_id=X86_INS_JMP, target=0x10262)
        if with_entry_jump
        else _instruction(0x1025C)
    )
    instructions = (
        _instruction(0x10259),
        entry_jump,
        _instruction(0x1025F),
        _instruction(0x10265),
        _instruction(0x10268, instruction_id=X86_INS_JLE, target=0x1026D),
        _instruction(0x10275),
        _instruction(0x10288, instruction_id=X86_INS_JMP, target=0x1025F),
    )
    return SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )


def _surface(
    *,
    assignment_in_body: bool = True,
    condition_reads_destination: bool = True,
) -> tuple[object, object, object, CStatements, CForLoop, CAssignment]:
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        project=project,
    )
    destination = CVariable(
        SimStackVariable(-2, 2, base="bp", name="row"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = CVariable(
        SimStackVariable(4, 2, base="bp", name="top"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    limit = CVariable(
        SimStackVariable(10, 2, base="bp", name="height"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(
        destination,
        CBinaryOp("Add", source, one, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10259},
    )
    body_marker = CAssignment(
        source,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10275},
    )
    body = CStatements(
        [assignment, body_marker] if assignment_in_body else [body_marker],
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpLE",
        CSemanticCast8616(
            SimTypeShort(False),
            SimTypeShort(True),
            destination,
            codegen=codegen,
        )
        if condition_reads_destination
        else source,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x10265},
    )
    iterator = CAssignment(
        destination,
        CBinaryOp("Add", destination, one, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1025F},
    )
    loop = CForLoop(None, condition, iterator, body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_direct_stack_move_facts_8616 = (
        DirectStackMoveFact8616(
            dst_offset=-2,
            width=2,
            source_kind=DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
            source_offset=4,
            source_immediate=1,
            ins_addr=0x10259,
        ),
    )
    return project, _function(), codegen, body, loop, assignment


def test_moves_compare_tagged_initializer_before_pretest_loop() -> None:
    project, function, codegen, body, loop, assignment = _surface()

    assert materialize_direct_stack_move_pretest_initializers_8616(
        project,
        codegen,
        function,
    )
    assert codegen.cfunc.statements.statements == [assignment, loop]
    assert assignment not in body.statements
    stats = codegen._inertia_direct_stack_move_pretest_initializer_placement_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_pretest_initializer_replay_is_idempotent() -> None:
    project, function, codegen, _body, loop, assignment = _surface()
    assert materialize_direct_stack_move_pretest_initializers_8616(
        project,
        codegen,
        function,
    )

    assert not materialize_direct_stack_move_pretest_initializers_8616(
        project,
        codegen,
        function,
    )
    assert codegen.cfunc.statements.statements == [assignment, loop]
    stats = codegen._inertia_direct_stack_move_pretest_initializer_placement_8616
    assert stats.already_materialized_count == 1


def test_places_detached_lowering_assignment_at_proven_scope() -> None:
    project, function, codegen, _body, loop, assignment = _surface(
        assignment_in_body=False
    )
    fact = codegen._inertia_direct_stack_move_facts_8616[0]

    assert place_direct_stack_move_pretest_initializer_assignment_8616(
        project,
        codegen,
        function,
        fact,
        assignment,
    )
    assert codegen.cfunc.statements.statements == [assignment, loop]


def test_refuses_initializer_without_exact_entry_jump() -> None:
    project, _function_value, codegen, body, loop, assignment = _surface()

    assert not materialize_direct_stack_move_pretest_initializers_8616(
        project,
        codegen,
        _function(with_entry_jump=False),
    )
    assert codegen.cfunc.statements.statements == [loop]
    assert body.statements[0] is assignment
    stats = codegen._inertia_direct_stack_move_pretest_initializer_placement_8616
    assert stats.refused_no_evidence_count == 1
    assert stats.failure_count == 0


def test_refuses_loop_whose_condition_does_not_read_destination() -> None:
    project, function, codegen, body, loop, assignment = _surface(
        condition_reads_destination=False
    )

    assert not materialize_direct_stack_move_pretest_initializers_8616(
        project,
        codegen,
        function,
    )
    assert codegen.cfunc.statements.statements == [loop]
    assert body.statements[0] is assignment
    stats = codegen._inertia_direct_stack_move_pretest_initializer_placement_8616
    assert stats.refused_no_site_count == 1
    assert stats.failure_count == 0
