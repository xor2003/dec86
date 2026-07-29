from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.decompiler_postprocess_stage import finalize_late_ast_cleanup_8616
from angr_platforms.X86_16.postprocess.optimization.trivial_copy import (
    prune_adjacent_temporary_copy_assignments_8616,
)


class _FakeCodegen(SimpleNamespace):
    const_formats = {}

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


def _cvar(codegen, name: str, reg: int):
    return structured_c.CVariable(
        SimRegisterVariable(reg, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _stack_cvar(codegen, name: str, offset: int):
    return structured_c.CVariable(
        SimStackVariable(offset, 2, base="bp", name=name, region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _const(codegen, value: int):
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def test_prune_adjacent_temporary_copy_collapses_pure_rhs():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_195", 0)
    dst = _cvar(codegen, "ch", 2)
    first = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs.value == 75


def test_prune_adjacent_temporary_copy_matches_same_emitted_temp_name():
    codegen = _mk_codegen_with_statements([])
    temp_def = _cvar(codegen, "vvar_195", 0)
    temp_use = _cvar(codegen, "vvar_195", 4)
    dst = _cvar(codegen, "ch", 2)
    first = structured_c.CAssignment(temp_def, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp_use, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs.value == 75


def test_prune_adjacent_temporary_copy_preserves_call_rhs():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_224", 0)
    dst = _cvar(codegen, "ch", 2)
    call = structured_c.CFunctionCall("getch", None, [], codegen=codegen)
    first = structured_c.CAssignment(temp, call, codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs is call


def test_prune_temporary_constant_copy_skips_pure_generated_setup():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_195", 0)
    setup_src = _cvar(codegen, "vvar_7", 4)
    setup_tmp = _cvar(codegen, "vvar_196", 6)
    dst = _cvar(codegen, "ch", 2)
    first = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    setup = structured_c.CAssignment(setup_tmp, setup_src, codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, setup, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [setup, second]
    assert statements[1].rhs.value == 75


def test_prune_temporary_call_copy_refuses_to_skip_setup():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_224", 0)
    setup_src = _cvar(codegen, "vvar_48", 4)
    setup_tmp = _cvar(codegen, "vvar_228", 6)
    dst = _cvar(codegen, "ch", 2)
    call = structured_c.CFunctionCall("getch", None, [], codegen=codegen)
    first = structured_c.CAssignment(temp, call, codegen=codegen)
    setup = structured_c.CAssignment(setup_tmp, setup_src, codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, setup, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first, setup, second]


def test_prune_dead_temp_to_unread_local_assignment():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_17", 0)
    local = _stack_cvar(codegen, "local_0", 0)
    live_dst = _cvar(codegen, "ch", 4)
    dead = structured_c.CAssignment(local, temp, codegen=codegen)
    live = structured_c.CAssignment(live_dst, _const(codegen, 75), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([dead, live], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    assert list(codegen.cfunc.statements.statements) == [live]
    assert codegen.trivial_copy_dead_temp_to_local_pruned_8616 == 1


def test_prune_dead_temp_to_local_assignment_refuses_when_local_is_read():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_17", 0)
    local = _stack_cvar(codegen, "local_0", 0)
    dst = _cvar(codegen, "ch", 4)
    first = structured_c.CAssignment(local, temp, codegen=codegen)
    second = structured_c.CAssignment(dst, local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first, second]
    assert codegen.trivial_copy_dead_temp_to_local_pruned_8616 == 0


def test_prune_dead_temp_to_local_assignment_refuses_source_local_stack_slot():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_224", 0)
    ch = _stack_cvar(codegen, "local_2", -2)
    first = structured_c.CAssignment(ch, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first]
    assert codegen.trivial_copy_dead_temp_to_local_pruned_8616 == 0


def test_prune_adjacent_temporary_copy_moves_call_from_same_emitted_temp_name():
    codegen = _mk_codegen_with_statements([])
    temp_def = _cvar(codegen, "vvar_224", 0)
    temp_use = _cvar(codegen, "vvar_224", 4)
    dst = _cvar(codegen, "ch", 2)
    call = structured_c.CFunctionCall("getch", None, [], codegen=codegen)
    first = structured_c.CAssignment(temp_def, call, codegen=codegen)
    second = structured_c.CAssignment(dst, temp_use, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs is call


def test_finalize_late_ast_cleanup_marks_refresh_after_temp_copy_fold():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_195", 0)
    dst = _cvar(codegen, "ch", 2)
    first = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    result = finalize_late_ast_cleanup_8616(SimpleNamespace(), codegen)

    assert result.changed is True
    assert result.adjacent_temporary_copy_changed is True
    assert result.requires_dce_after_cleanup is True
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True
    assert codegen._inertia_late_ast_cleanup_finalize_8616 == {
        "changed": True,
        "adjacent_temporary_copy_changed": True,
        "requires_dce_after_cleanup": True,
        "owner": "postprocess.stage",
    }
    assert list(codegen.cfunc.statements.statements) == [second]


def test_prune_adjacent_temporary_copy_refuses_when_temp_used_later():
    codegen = _mk_codegen_with_statements([])
    temp_def = _cvar(codegen, "vvar_195", 0)
    temp_use = _cvar(codegen, "vvar_195", 4)
    temp_later = _cvar(codegen, "vvar_195", 6)
    dst = _cvar(codegen, "ch", 2)
    later_dst = _cvar(codegen, "other", 8)
    first = structured_c.CAssignment(temp_def, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp_use, codegen=codegen)
    later = structured_c.CAssignment(later_dst, temp_later, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second, later], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first, second, later]
    assert codegen.trivial_copy_candidates_8616 == 1
    assert codegen.trivial_copy_pruned_8616 == 0
    assert codegen.trivial_copy_refused_live_temp_8616 == 1
