from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CFunctionCall,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from capstone.x86_const import (
    X86_INS_ADC,
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_DEC,
    X86_INS_INC,
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_SHL,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_DX,
    X86_REG_INVALID,
)
from inertia_decompiler.cli_arg_parser import _build_cli_argument_parser
from inertia_decompiler.recompile_check import check_c_recompiles_8616

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveSourceKind8616,
    _direct_stack_move_instruction_facts_8616,
    materialize_direct_global_incdec_instructions_8616,
    materialize_direct_stack_incdec_instructions_8616,
    materialize_direct_stack_mov_instructions_8616,
)
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    apply_runtime_segment_lowering_8616,
    lower_runtime_segment_access_8616,
    lower_runtime_segment_address_8616,
)
from angr_platforms.X86_16.pipeline.architecture_guard import assert_final_c_quality_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={}, unified_local_vars={})
    return project, codegen


def _reg_operand(reg, *, size=2):
    return SimpleNamespace(type=X86_OP_REG, size=size, reg=reg)


def _bp_mem_operand(offset: int, *, size=2):
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=offset),
    )


def _imm_operand(value: int, *, size=2):
    return SimpleNamespace(type=X86_OP_IMM, size=size, imm=value)


def test_direct_stack_move_wide_call_return_uses_original_project_for_rebased_call_target():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0xFF38,
    )
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH
    assert fact.dst_offset == -4
    assert fact.width == 4
    assert fact.source_offset == 4
    assert fact.source_call_target == 0x1137E
    assert fact.source_call_name == "clock"


def test_materialize_wide_call_return_consumes_following_low_half_call_assignment():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project, codegen = _project()
    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project.kb = SimpleNamespace(functions=_Functions(), labels={})
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xFF38
    low_goal = CVariable(
        SimStackVariable(-4, 2, base="bp", name="goal"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(low_goal, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(low_goal, CFunctionCall("clock", None, [], codegen=codegen), codegen=codegen),
        ]
    )
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert isinstance(stmt.rhs.lhs, CFunctionCall)
    assert getattr(stmt.rhs.lhs, "callee_target", None) == "clock"


def test_materialize_direct_global_inc_instruction_from_binary_evidence():
    project, codegen = _project()
    metadata = SimpleNamespace(global_names=("counter",))
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: metadata}
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable.name == "counter"
    assert stmt.lhs.variable.addr == 0x1234
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"


def test_materialize_direct_global_add_immediate_instruction_from_binary_evidence():
    project, codegen = _project()
    metadata = SimpleNamespace(global_names=("seen",))
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: metadata}
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x0048)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=2)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_ADD, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable.name == "seen"
    assert stmt.lhs.variable.addr == 0x0048
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.rhs.value == 2


def test_materialize_direct_global_inc_redecodes_blocks_without_capstone_details():
    project, codegen = _project()
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: SimpleNamespace(global_names=("counter",))}
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    decoded_block = SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))
    project.factory = SimpleNamespace(block=lambda *_args, **_kwargs: decoded_block)
    sparse_block = SimpleNamespace(addr=0x4010, size=4, capstone=SimpleNamespace(insns=()))
    function = SimpleNamespace(addr=0x4010, blocks=(sparse_block,))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable.name == "counter"
    assert stmt.lhs.variable.addr == 0x1234


def test_materialize_direct_global_inc_refuses_without_tagged_site():
    project, codegen = _project()
    unknown_call = SimpleNamespace(address=0x4014, id=X86_INS_CALL, operands=(_imm_operand(0x2000),))
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(unknown_call, insn))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen.cfunc.statements.statements == []


def test_materialize_direct_global_inc_inserts_before_next_tagged_statement():
    project, codegen = _project()
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: SimpleNamespace(global_names=("counter",))}
    later_var = SimRegisterVariable(0, 2, name="ax")
    later = CVariable(later_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            later,
            CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4020},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable.name == "counter"
    assert inserted.lhs.variable.addr == 0x1234
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert statements[1].lhs.variable.name == "ax"
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["inserted_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_inserts_at_body_start_after_stack_probe_prefix_without_tags():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x2000: "aNchkstk"})
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: SimpleNamespace(global_names=("counter",))}
    later_var = SimRegisterVariable(0, 2, name="ax")
    later = CVariable(later_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            later,
            CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    )
    push_bp = SimpleNamespace(address=0x4010, id=X86_INS_PUSH, operands=(_reg_operand(X86_REG_BP),))
    mov_ax = SimpleNamespace(address=0x4011, id=X86_INS_MOV, operands=(_reg_operand(X86_REG_AX), _imm_operand(2)))
    call_probe = SimpleNamespace(address=0x4014, id=X86_INS_CALL, operands=(_imm_operand(0x2000),))
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    inc_global = SimpleNamespace(address=0x4017, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(push_bp, mov_ax, call_probe, inc_global))),),
    )

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable.name == "counter"
    assert inserted.lhs.variable.addr == 0x1234
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert statements[1].lhs.variable.name == "ax"
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["body_start_inserted_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_inc_instruction_replaces_tagged_loop_iterator():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    bad_iterator = CAssignment(
        stack_cvar,
        CBinaryOp("Shr", stack_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    loop = CForLoop(
        init,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        bad_iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_materialize_direct_stack_inc_instruction_removes_duplicate_tagged_assignments():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    first_bad = CAssignment(
        stack_cvar,
        CBinaryOp("Shr", stack_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    second_bad = CAssignment(
        stack_cvar,
        CBinaryOp("Shr", stack_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.extend([first_bad, second_bad])

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.rhs.value == 1


def test_materialize_direct_stack_mov_immediate_instruction_replaces_tagged_assignment():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    bad_stmt = CAssignment(
        stack_cvar,
        _reg(project, "di", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0


def test_materialize_direct_stack_mov_stack_copy_instruction_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    bad_stmt = CAssignment(
        dst_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x401A},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert stmt.rhs is src_cvar


def test_materialize_direct_stack_mov_shifted_stack_source_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    bad_stmt = CAssignment(dst_cvar, _reg(project, "ax", codegen), codegen=codegen, tags={"ins_addr": 0x401D})
    codegen.cfunc.statements.statements.append(bad_stmt)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    shift = SimpleNamespace(
        address=0x401A,
        id=X86_INS_SHL,
        operands=(ax_src, SimpleNamespace(type=X86_OP_IMM, size=1, imm=1)),
    )
    store = SimpleNamespace(
        address=0x401D,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, shift, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Shl"
    assert stmt.rhs.lhs is src_cvar
    assert stmt.rhs.rhs.value == 1


def test_materialize_direct_stack_mov_shifted_stack_source_inserts_before_following_nested_tagged_statement():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    guard_var = SimRegisterVariable(0, 2, name="flags")
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    guard_cvar = CVariable(guard_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    outer_anchor = CAssignment(
        src_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    following_guard = CAssignment(
        guard_cvar,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    nested_body = CStatements([following_guard], codegen=codegen)
    codegen.cfunc.statements.statements.extend([outer_anchor, nested_body])

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    shift = SimpleNamespace(
        address=0x401A,
        id=X86_INS_SHL,
        operands=(ax_src, SimpleNamespace(type=X86_OP_IMM, size=1, imm=1)),
    )
    store = SimpleNamespace(
        address=0x401D,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, shift, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [outer_anchor, nested_body]
    assert len(nested_body.statements) == 2
    inserted = nested_body.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is dst_cvar
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Shl"
    assert nested_body.statements[1] is following_guard


def test_materialize_direct_stack_mov_immediate_replaces_untagged_precontrol_assignment():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    bad_stmt = CAssignment(stack_cvar, _reg(project, "di", codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(bad_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0


def test_materialize_direct_stack_mov_immediate_descends_nested_precontrol_statements():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    nested = CStatements([CAssignment(stack_cvar, _reg(project, "di", codegen), codegen=codegen)], codegen=codegen)
    codegen.cfunc.statements.statements.append(nested)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = nested.statements[0]
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0


def test_materialize_direct_stack_mov_stack_copy_inserts_after_nearest_preceding_tagged_statement():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    anchor_var = SimStackVariable(-6, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    anchor = CAssignment(
        anchor_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4019},
    )
    codegen.cfunc.statements.statements.append(anchor)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    inserted = codegen.cfunc.statements.statements[1]
    assert inserted.lhs is dst_cvar
    assert inserted.rhs is src_cvar


def test_materialize_direct_stack_mov_stack_copy_is_idempotent():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    anchor_var = SimStackVariable(-6, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            anchor_cvar,
            CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4019},
        )
    )

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    first = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    second = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert first is True
    assert second is False
    assignments = [
        stmt
        for stmt in codegen.cfunc.statements.statements
        if isinstance(stmt, CAssignment) and getattr(stmt, "lhs", None) is dst_cvar
    ]
    assert len(assignments) == 1
    assert assignments[0].rhs is src_cvar


def test_materialize_direct_stack_mov_refuses_duplicate_across_transparent_statement_wrapper():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    anchor_var = SimStackVariable(-6, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    anchor = CAssignment(
        anchor_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4019},
    )
    existing = CAssignment(dst_cvar, src_cvar, codegen=codegen)
    nested_existing = CStatements([existing], codegen=codegen)
    codegen.cfunc.statements.statements.extend([anchor, nested_existing])

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen.cfunc.statements.statements == [anchor, nested_existing]
    assert nested_existing.statements == [existing]
    assert codegen._inertia_direct_stack_move_lowering_8616["already_materialized_count"] == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["failure_count"] == 0


def test_materialize_direct_stack_dec_refuses_without_tagged_assignment():
    project, codegen = _project()
    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_DEC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen._inertia_direct_stack_update_lowering_8616["raw_fact_count"] == 1
    assert codegen._inertia_direct_stack_update_lowering_8616["classified_fact_count"] == 1
    assert codegen._inertia_direct_stack_update_lowering_8616["materialized_count"] == 0
    assert codegen._inertia_direct_stack_update_lowering_8616["failure_count"] == 1


def _const(value: int, codegen, sim_type=None):
    return CConstant(value, sim_type or SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _seg_linear(project, seg_name: str, offset_expr, codegen, *, shl: bool = False):
    segment = _reg(project, seg_name, codegen)
    scale = _const(4 if shl else 16, codegen)
    op = "Shl" if shl else "Mul"
    return CBinaryOp("Add", CBinaryOp(op, segment, scale, codegen=codegen), offset_expr, codegen=codegen)


def test_lower_runtime_segment_access_rewrites_ds_word_dereference_to_seg_u16():
    project, codegen = _project()
    operand = _seg_linear(project, "ds", _const(0x0BA2, codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U16"
    assert lowered.args[0].variable.name == "ds"
    assert lowered.args[1].value == 0x0BA2


def test_lower_runtime_segment_access_rewrites_es_byte_runtime_offset_to_seg_u8():
    project, codegen = _project()
    di = _reg(project, "di", codegen)
    offset = CBinaryOp("Add", di, _const(4, codegen), codegen=codegen)
    operand = _seg_linear(project, "es", offset, codegen, shl=True)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="msc-dos")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U8"
    assert lowered.args[0].variable.name == "es"
    assert isinstance(lowered.args[1], CBinaryOp)
    assert lowered.args[1].op == "Add"


def test_lower_runtime_segment_address_rewrites_to_mk_fp():
    project, codegen = _project()
    bx = _reg(project, "bx", codegen)
    expr = _seg_linear(project, "ds", bx, codegen)

    lowered = lower_runtime_segment_address_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "MK_FP"
    assert lowered.args[0].variable.name == "ds"
    assert lowered.args[1] is bx


def test_apply_runtime_segment_lowering_rewrites_nested_ds_accesses():
    project, codegen = _project()
    result_var = CVariable(SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010), codegen=codegen)
    operand = _seg_linear(project, "ds", _const(2978, codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    deref = CUnaryOp("Dereference", operand, codegen=codegen)
    stmt = CAssignment(result_var, CBinaryOp("Sub", deref, _const(1, codegen), codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    lowered_rhs = codegen.cfunc.statements.statements[0].rhs.lhs
    assert isinstance(lowered_rhs, CFunctionCall)
    assert lowered_rhs.callee_target == "SEG_U16"


def test_apply_runtime_segment_lowering_preserves_ss_stack_dereferences():
    project, codegen = _project()
    ss = _reg(project, "ss", codegen)
    stack_ref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CUnaryOp(
                "Reference",
                CVariable(SimStackVariable(-2, 2, base="bp", name="local", region=0x4010), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert lower_runtime_segment_access_8616(stack_ref, target="portable-flat") is None


def test_architecture_guard_rejects_raw_linear_segment_arithmetic():
    with pytest.raises(Exception):
        assert_final_c_quality_8616("x = *((unsigned short *)((ds << 4) + 2978));", function_addr=0x10498)


def test_architecture_guard_accepts_segment_helpers():
    assert_final_c_quality_8616("x = SEG_U16(ds, 2978);\ny = MK_FP(es, di + 4);\n", function_addr=0x10498)


def test_architecture_guard_rejects_unreachable_call_after_return():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "int f(void)\n"
            "{\n"
            "    helper();\n"
            "    return 2;\n"
            "    aNchkstk();\n"
            "}\n",
            function_addr=0x1000,
        )


def test_architecture_guard_accepts_conditional_single_line_return_before_call():
    assert_final_c_quality_8616(
        "int f(int x)\n"
        "{\n"
        "    while (1)\n"
        "    {\n"
        "        if (x == 0)\n"
        "            return 0;\n"
        "        helper();\n"
        "    }\n"
        "}\n",
        function_addr=0x1000,
    )


def test_segment_linearization_through_tmp_is_rejected():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "unsigned short tmp;\nunsigned long linear;\ntmp = ss;\nlinear = tmp << 4;\n",
            function_addr=0x10498,
        )
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "unsigned short tmp;\nunsigned long linear;\ntmp = ds;\nlinear = tmp * 16;\n",
            function_addr=0x10498,
        )
    assert_final_c_quality_8616(
        "p = SEG_PTR(ds, off);\nx = SEG_U16(ds, off);\ny = MK_FP(ds, off);\n",
        function_addr=0x10498,
    )


def test_architecture_guard_rejects_heapsort_constant_percolatedown_arg():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "short HeapSort(void)\n{\n    PercolateDown(3);\n}\n",
            function_addr=0x10970,
        )


def test_architecture_guard_rejects_heapsort_reversed_swapbars_args():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "short HeapSort(void)\n{\n    SwapBars(i, 0);\n}\n",
            function_addr=0x10970,
        )


def test_architecture_guard_accepts_heapsort_pointer_and_value_arg_shapes():
    assert_final_c_quality_8616(
        "short HeapSort(void)\n"
        "{\n"
        "    PercolateUp(i);\n"
        "    Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));\n"
        "    SwapBars(0, i);\n"
        "    PercolateDown(i - 1);\n"
        "}\n",
        function_addr=0x10970,
    )


def test_architecture_guard_accepts_decimal_generated_arg_names():
    assert_final_c_quality_8616(
        "void PercolateDown(int arg_4)\n"
        "{\n"
        "    unsigned short iChild;\n"
        "    if (iChild <= arg_4)\n"
        "        SwapBars(0, iChild);\n"
        "}\n",
        function_addr=0x10A88,
    )


def test_architecture_guard_rejects_nondecimal_arg_placeholder_noise():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "void bad(int arg_fffe)\n"
            "{\n"
            "    SwapBars(0, arg_fffe);\n"
            "}\n",
            function_addr=0x10A88,
        )


def test_architecture_guard_rejects_heapsort_stack_placeholder_noise():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "short HeapSort(void)\n"
            "{\n"
            "    char s_4;\n"
            "    vvar_23 = &s_4 + 2;\n"
            "    Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));\n"
            "    SwapBars(0, i);\n"
            "    PercolateDown(i - 1);\n"
            "}\n",
            function_addr=0x10970,
        )


def test_render_c_runtime_header_portable_flat_exposes_seg_macros():
    header = render_c_runtime_header_8616("portable-flat")

    assert "extern uint8_t inertia_memory[];" in header
    assert "#define SEG_U16(seg, off)" in header
    assert "#define MK_FP(seg, off)" in header


def test_render_c_runtime_header_msc_dos_uses_far_mk_fp():
    header = render_c_runtime_header_8616("msc-dos")

    assert "#include <dos.h>" in header
    assert "SEG_U16" in header
    assert "far *)MK_FP" in header


def test_cli_arg_parser_accepts_c_target():
    parser = _build_cli_argument_parser()

    args = parser.parse_args(["sample.exe", "--c-target", "msc-dos"])

    assert args.c_target == "msc-dos"


def test_recompile_check_accepts_simple_portable_flat_c():
    result = check_c_recompiles_8616(
        "int demo(unsigned short ds) { return (int)SEG_U16(ds, 0x0BA2); }\n",
        target="portable-flat",
    )

    assert result.passed is True, result.stderr
