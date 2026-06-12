from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _dead_code_elimination_after_flag_prune_8616,
)
from angr_platforms.X86_16.postprocess.optimization.dce import (
    _dead_code_elimination_8616,
)


class _FakeCodegen(SimpleNamespace):
    def __init__(self):
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next


def _mk_codegen_with_statements(statements):
    codegen = _FakeCodegen()
    codegen.cfunc = SimpleNamespace()
    codegen.cfunc.statements = structured_c.CStatements(list(statements), codegen=codegen)
    return codegen


def _mk_cvar(codegen, name: str, reg: int = 0):
    return structured_c.CVariable(
        SimRegisterVariable(reg, 2, name=name),
        codegen=codegen,
    )


def _const(codegen, value: int = 1):
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def test_dce_deletes_unread_plain_temp_assignment():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    stmt = structured_c.CAssignment(tmp, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_refuses_unread_temp_assignment_from_dereference():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    ptr = _mk_cvar(codegen, "tmp_ptr", 2)
    deref = structured_c.CUnaryOp("Dereference", ptr, codegen=codegen)
    stmt = structured_c.CAssignment(tmp, deref, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_deletes_standalone_pure_mkfp_dereference_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([deref], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_deleted", 0) == 1


def test_dce_refuses_standalone_unknown_call_dereference_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("unknown_addr", None, [seg, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([deref], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [deref]
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_refused", 0) == 1


def test_dce_deletes_pure_named_local_self_assignment():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(local, local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_deletes_unread_pure_named_local_copy_after_callsite_materialization():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_arg_fact_count=0,
        call_arg_materialized_count=0,
        call_target_fact_count=0,
        call_target_materialized_count=0,
        failure_count=0,
    )
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="fn", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dst, src, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_keeps_unread_stack_assignment_with_direct_stack_move_evidence():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_arg_fact_count=0,
        call_arg_materialized_count=0,
        call_target_fact_count=0,
        call_target_materialized_count=0,
        failure_count=0,
    )
    total = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="total", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(total, _const(codegen, 0), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)
    codegen._inertia_direct_stack_move_evidence_8616 = ((("dst_offset", -2), ("ins_addr", 0x400B)),)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_protected", 0) == 1


def test_dce_refuses_dirty_lhs_provenance_carrier_without_typed_proof():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=13, idx=13, name="vvar_13", reg_offset=0, bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_deletes_unread_dirty_segmented_read_artifact_with_storage_provenance():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=14, idx=14, name="vvar_14", reg_offset=0, bits=16),
        codegen=codegen,
    )
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    rhs = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dirty_value_candidates", 0) == 1
    assert getattr(codegen, "dce_dirty_value_deleted", 0) == 1


def test_dce_keeps_live_dirty_segmented_read_artifact_with_storage_provenance():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=14, idx=14, name="vvar_14", reg_offset=0, bits=16),
        codegen=codegen,
    )
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    rhs = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    define_dirty = structured_c.CAssignment(dirty, rhs, codegen=codegen)
    use_dirty = structured_c.CAssignment(_mk_cvar(codegen, "tmp_dst", 4), dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([define_dirty, use_dirty], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [define_dirty, use_dirty]
    assert getattr(codegen, "dce_dirty_value_candidates", 0) == 1
    assert getattr(codegen, "dce_dirty_value_refused", 0) == 1


def test_dce_refuses_unread_dirty_unknown_call_artifact():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=14, idx=14, name="vvar_14", reg_offset=0, bits=16),
        codegen=codegen,
    )
    rhs = structured_c.CFunctionCall("unknown_addr", None, [_const(codegen, 0)], codegen=codegen)
    stmt = structured_c.CAssignment(dirty, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_dirty_value_candidates", 0) == 1
    assert getattr(codegen, "dce_dirty_value_refused", 0) == 1


def test_dce_deletes_unread_storage_free_dirty_only_in_post_flag_mode():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]

    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []


def test_post_flag_dirty_dce_deletes_unread_structured_body_carrier():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    condition = _mk_cvar(codegen, "tmp_cond", 9)
    if_node = structured_c.CIfElse(
        [(condition, structured_c.CStatements([stmt], codegen=codegen))],
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([if_node], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(if_node.condition_and_nodes[0][1].statements) == []


def test_post_flag_dirty_dce_keeps_condition_source():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    if_node = structured_c.CIfElse(
        [(dirty, structured_c.CStatements([], codegen=codegen))],
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt, if_node], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt, if_node]
    assert getattr(codegen, "dce_keep_live_use", 0) == 1


def test_post_flag_dirty_dce_deletes_pure_dirty_rhs_chain():
    codegen = _mk_codegen_with_statements([])
    dirty_a = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    dirty_b = structured_c.CDirtyExpression(
        SimpleNamespace(varid=226, idx=226, name="tmp_226", bits=16),
        codegen=codegen,
    )
    assign_a = structured_c.CAssignment(dirty_a, _const(codegen, 7), codegen=codegen)
    rhs_b = structured_c.CBinaryOp("Add", dirty_a, _const(codegen, 1), codegen=codegen)
    assign_b = structured_c.CAssignment(dirty_b, rhs_b, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([assign_a, assign_b], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 2


def test_post_flag_dirty_dce_deletes_dead_dirty_copy_from_storage_value_read():
    codegen = _mk_codegen_with_statements([])
    storage_dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=224, idx=224, name="vvar_224", reg_offset=0, bits=16),
        codegen=codegen,
    )
    temp_dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(temp_dirty, storage_dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []


def test_dce_does_not_count_parent_structured_body_as_outside_read():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_225", 225)
    body = structured_c.CStatements([structured_c.CAssignment(tmp, _const(codegen, 7), codegen=codegen)], codegen=codegen)
    loop = structured_c.CWhileLoop(_const(codegen, 1), body, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(body.statements) == []


def test_dce_matches_c_variable_liveness_by_emitted_name():
    codegen = _mk_codegen_with_statements([])
    tmp_def = _mk_cvar(codegen, "tmp_23", 23)
    tmp_use = _mk_cvar(codegen, "tmp_23", 2300)
    local = _mk_cvar(codegen, "local_2", 2)
    define_tmp = structured_c.CAssignment(tmp_def, _const(codegen, 7), codegen=codegen)
    use_tmp = structured_c.CAssignment(local, tmp_use, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([define_tmp, use_tmp], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [define_tmp, use_tmp]


def test_dce_deletes_adjacent_duplicate_pure_stack_assignment():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1


def test_dce_refuses_adjacent_duplicate_dereference_assignment():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ptr = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ptr"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    rhs = structured_c.CUnaryOp("Dereference", ptr, codegen=codegen)
    first = structured_c.CAssignment(dst, rhs, codegen=codegen)
    second = structured_c.CAssignment(dst, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [first, second]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_refused", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 0


def test_dce_deletes_adjacent_duplicate_assignments_inside_single_statement_wrappers():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    first_wrapper = structured_c.CStatements([first], codegen=codegen)
    second_wrapper = structured_c.CStatements([second], codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first_wrapper, second_wrapper], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first_wrapper]
    assert list(first_wrapper.statements) == [first]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1


def test_dce_deletes_duplicate_assignment_across_wrapper_boundary_after_call():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall("SwapBars", None, [dst, src], codegen=codegen)
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    first_wrapper = structured_c.CStatements([call, first], codegen=codegen)
    second_wrapper = structured_c.CStatements([second], codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first_wrapper, second_wrapper], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first_wrapper]
    assert list(first_wrapper.statements) == [call, first]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1


def test_dce_keeps_remaining_wrapper_statements_after_boundary_duplicate_delete():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    other_dst = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="other", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    other = structured_c.CAssignment(other_dst, _const(codegen, 3), codegen=codegen)
    first_wrapper = structured_c.CStatements([first], codegen=codegen)
    second_wrapper = structured_c.CStatements([second, other], codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first_wrapper, second_wrapper], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first_wrapper, second_wrapper]
    assert list(first_wrapper.statements) == [first]
    assert list(second_wrapper.statements) == [other]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1
