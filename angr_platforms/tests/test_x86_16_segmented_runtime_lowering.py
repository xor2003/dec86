from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from capstone.x86_const import (
    X86_INS_ADC,
    X86_INS_ADD,
    X86_INS_CBW,
    X86_INS_CALL,
    X86_INS_CDQ,
    X86_INS_DEC,
    X86_INS_INC,
    X86_INS_IDIV,
    X86_INS_MOV,
    X86_INS_OR,
    X86_INS_PUSH,
    X86_INS_SAR,
    X86_INS_SHL,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CX,
    X86_REG_DX,
    X86_REG_INVALID,
    X86_REG_SI,
)
from inertia_decompiler.cli_arg_parser import _build_cli_argument_parser
from inertia_decompiler.recompile_check import check_c_recompiles_8616

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveExpressionOp8616,
    DirectStackMoveSourceKind8616,
    DirectStackUpdateOp8616,
    DirectStackUpdateSourceKind8616,
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


def test_materialize_direct_global_inc_instruction_is_idempotent():
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

    first_changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)
    first_stmt = codegen.cfunc.statements.statements[0]
    second_changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert first_changed is True
    assert second_changed is False
    assert codegen.cfunc.statements.statements[0] is first_stmt
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["already_materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_add_refuses_duplicate_rebased_global_assignment():
    project, codegen = _project()
    existing_var = SimMemoryVariable(0x10048, 2, name="seen", region=0x4010)
    existing_cvar = CVariable(existing_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[existing_var] = existing_cvar
    codegen.cfunc.unified_local_vars[existing_var] = {(existing_cvar, SimTypeShort(False))}
    codegen.cfunc.statements.statements.append(
        CAssignment(
            existing_cvar,
            CBinaryOp(
                "Add",
                existing_cvar,
                CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x0048)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=2)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_ADD, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 1
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["already_materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_rewrites_all_tagged_structured_clones():
    project, codegen = _project()
    metadata = SimpleNamespace(global_names=("counter",))
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: metadata}
    for reg_name in ("ax", "bx"):
        placeholder_var = SimRegisterVariable(0, 2, name=reg_name)
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
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    for stmt in statements:
        assert isinstance(stmt, CAssignment)
        assert stmt.lhs.variable.name == "counter"
        assert stmt.lhs.variable.addr == 0x1234
        assert isinstance(stmt.rhs, CBinaryOp)
        assert stmt.rhs.op == "Add"


def test_materialize_direct_global_inc_refuses_guard_condition_rewrite():
    project, codegen = _project()
    metadata = SimpleNamespace(global_names=("counter",))
    project._inertia_cod_metadata_by_func_addr_8616 = {0x4010: metadata}

    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    statement_placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    condition_placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    statement_assignment = CAssignment(
        statement_placeholder,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    condition_assignment = CAssignment(
        condition_placeholder,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    if_stmt = CIfElse([(condition_assignment, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition = condition_assignment
    codegen.cfunc.statements.statements.extend([statement_assignment, if_stmt])

    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs.variable.name == "counter"
    assert if_stmt.condition is condition_assignment
    assert if_stmt.condition_and_nodes[0][0] is condition_assignment


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
        "refused_count": 0,
    }
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_materialize_direct_stack_inc_instruction_replaces_tagged_iterator_expression():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    placeholder_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="i"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    placeholder_var.tags = {"ins_addr": 0x4018}
    loop = CForLoop(
        init,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        placeholder_var,
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
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_materialize_direct_stack_inc_instruction_replaces_proven_untagged_for_iterator():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    condition = CBinaryOp("CmpLT", stack_cvar, CConstant(10, SimTypeShort(False), codegen=codegen), codegen=codegen)
    placeholder_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="j"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loop = CForLoop(
        init,
        condition,
        placeholder_var,
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
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_materialize_direct_stack_inc_instruction_replaces_stack_slot_iterator_expression():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    condition = CBinaryOp("CmpLT", stack_cvar, CConstant(10, SimTypeShort(False), codegen=codegen), codegen=codegen)
    loop = CForLoop(
        init,
        condition,
        stack_cvar,
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


def test_materialize_direct_stack_add_stack_slot_replaces_tagged_assignment():
    project, codegen = _project()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.unified_local_vars[total_var] = {(total_cvar, SimTypeShort(False))}
    codegen.cfunc.unified_local_vars[i_var] = {(i_cvar, SimTypeShort(False))}

    bad_stmt = CAssignment(
        i_cvar,
        CBinaryOp("Add", i_cvar, _reg(project, "ax", codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    load = SimpleNamespace(
        address=0x4015,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_ADD,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, update))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "refused_count": 0,
    }
    evidence = codegen._inertia_direct_stack_update_evidence_8616
    assert dict(evidence[0])["source_kind"] is DirectStackUpdateSourceKind8616.STACK_SLOT
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is total_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.lhs.variable is total_var
    assert stmt.rhs.rhs.variable is i_var


def test_materialize_direct_stack_or_immediate_replaces_tagged_assignment():
    project, codegen = _project()
    mask_var = SimStackVariable(-2, 2, base="bp", name=None, region=0x4010)
    mask_cvar = CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[mask_var] = mask_cvar
    codegen.cfunc.unified_local_vars[mask_var] = {(mask_cvar, SimTypeShort(False))}

    bad_stmt = CAssignment(
        mask_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_OR,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0x20)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    evidence = codegen._inertia_direct_stack_update_evidence_8616
    assert dict(evidence[0])["operation"] is DirectStackUpdateOp8616.OR
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is mask_var
    assert isinstance(stmt.lhs.variable.name, str)
    assert stmt.lhs.variable.name.isidentifier()
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Or"
    assert stmt.rhs.lhs.variable is mask_var
    assert stmt.rhs.rhs.value == 0x20


def test_materialize_direct_stack_or_immediate_refuses_unguarded_fallback_insertion():
    project, codegen = _project()
    mask_var = SimStackVariable(-2, 2, base="bp", name="mask", region=0x4010)
    mask_cvar = CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[mask_var] = mask_cvar
    codegen.cfunc.unified_local_vars[mask_var] = {(mask_cvar, SimTypeShort(False))}

    later_stmt = CAssignment(
        mask_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    guarded_later = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen),
                CStatements([later_stmt], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(guarded_later)

    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_OR,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0x20)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
        "refused_count": 1,
    }
    guarded_body = guarded_later.condition_and_nodes[0][1]
    assert guarded_body.statements == [later_stmt]
    assert not hasattr(codegen, "_inertia_direct_stack_update_evidence_8616")


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


def test_materialize_direct_stack_mov_zero_immediate_stays_constant_even_with_base_label():
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10000: "_sum_to"})
    stack_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
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


def test_materialize_direct_stack_mov_immediate_to_known_function_infers_near_symbol():
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10010: "_inc_one"})
    stack_var = SimStackVariable(-2, 2, base="bp", name="fn", region=0x4010)
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
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0x10)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CVariable)
    assert stmt.rhs.variable.name == "inc_one"
    assert stmt.rhs.variable.addr == 0x10010
    assert isinstance(stmt.lhs.variable_type, SimTypePointer)
    assert isinstance(stmt.lhs.variable_type.pts_to, SimTypeFunction)
    assert isinstance(stmt.rhs.variable_type, SimTypePointer)
    assert isinstance(stmt.rhs.variable_type.pts_to, SimTypeFunction)


def test_materialize_direct_stack_mov_immediate_inserts_missing_setup_before_loop_without_dup_init():
    project, codegen = _project()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    i_init = CAssignment(
        i_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CForLoop(
        i_init,
        CBinaryOp("CmpLT", i_cvar, CConstant(6, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CAssignment(
            i_cvar,
            CBinaryOp("Add", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        ),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    total_store = SimpleNamespace(
        address=0x400B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    i_store = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(total_store, i_store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is total_var
    assert isinstance(inserted.rhs, CConstant)
    assert inserted.rhs.value == 0
    assert statements[1] is loop
    assert codegen._inertia_direct_stack_move_lowering_8616["materialized_count"] == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["already_materialized_count"] == 1


def test_materialize_direct_stack_mov_prefers_used_stack_slot_identity():
    project, codegen = _project()
    generic_var = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010)
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    generic_cvar = CVariable(generic_var, variable_type=SimTypeShort(False), codegen=codegen)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[generic_var] = generic_cvar
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    later_use = CAssignment(
        total_cvar,
        CBinaryOp("Add", total_cvar, i_cvar, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(later_use)

    total_store = SimpleNamespace(
        address=0x400B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(total_store,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    inserted = codegen.cfunc.statements.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is total_var
    assert codegen.cfunc.statements.statements[1] is later_use


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


def test_materialize_direct_stack_mov_signed_half_stack_source_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    bad_stmt = CAssignment(dst_cvar, _reg(project, "ax", codegen), codegen=codegen, tags={"ins_addr": 0x401A})
    codegen.cfunc.statements.statements.append(bad_stmt)

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CDQ, operands=())
    subtract_sign = SimpleNamespace(
        address=0x4014,
        id=X86_INS_SUB,
        operands=(_reg_operand(X86_REG_AX), _reg_operand(X86_REG_DX)),
    )
    signed_shift = SimpleNamespace(
        address=0x4016,
        id=X86_INS_SAR,
        operands=(_reg_operand(X86_REG_AX), _imm_operand(1, size=1)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, sign_extend, subtract_sign, signed_shift, store))),),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    assert facts[0].source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR
    assert facts[0].source_op is DirectStackMoveExpressionOp8616.SIGNED_DIV2
    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Div"
    assert isinstance(stmt.rhs.lhs, CTypeCast)
    assert stmt.rhs.lhs.dst_type.signed is True
    assert stmt.rhs.lhs.expr is src_cvar
    assert stmt.rhs.rhs.value == 2


def test_materialize_direct_stack_mov_segmented_byte_source_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iBreak", region=0x4010)
    index_var = SimStackVariable(6, 2, base="bp", name="iHigh", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    index_cvar = CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[index_var] = index_cvar
    codegen.cfunc.arg_list = [index_cvar]
    bad_stmt = CAssignment(dst_cvar, _reg(project, "ax", codegen), codegen=codegen, tags={"ins_addr": 0x401A})
    codegen.cfunc.statements.statements.append(bad_stmt)

    load_index = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    shift_index = SimpleNamespace(
        address=0x4013,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1, size=1)),
    )
    load_byte = SimpleNamespace(
        address=0x4016,
        id=X86_INS_MOV,
        operands=(
            _reg_operand(X86_REG_AL, size=1),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=1,
                mem=SimpleNamespace(base=X86_REG_BX, index=X86_REG_INVALID, disp=0xB4C),
            ),
        ),
    )
    sign_extend = SimpleNamespace(address=0x4019, id=X86_INS_CBW, operands=())
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load_index, shift_index, load_byte, sign_extend, store))
            ),
        ),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.SEGMENTED_MEMORY
    assert fact.source_segment_name == "ds"
    assert fact.source_displacement == 0xB4C
    assert fact.source_index_offset == 6
    assert fact.source_index_shift == 1
    assert fact.source_access_width == 1
    assert fact.source_sign_extend is True
    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CFunctionCall)
    assert stmt.rhs.callee_target == "SEG_U8"
    assert stmt.rhs.args[0].variable.name == "ds"
    assert isinstance(stmt.rhs.args[1], CBinaryOp)


def test_materialize_direct_stack_mov_signed_idiv_remainder_replaces_tagged_assignment():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    bad_stmt = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc.statements.statements.append(bad_stmt)

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    assert facts[0].source_kind is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
    assert facts[0].source_op is DirectStackMoveExpressionOp8616.MOD
    assert facts[0].source_offset == -4
    assert facts[0].source_immediate == 1
    assert facts[0].source_call_ins_addr == 0x4010
    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Mod"
    assert isinstance(stmt.rhs.lhs, CTypeCast)
    assert isinstance(stmt.rhs.lhs.expr, CFunctionCall)
    assert stmt.rhs.lhs.expr.callee_target == "rand"
    assert isinstance(stmt.rhs.rhs, CTypeCast)
    assert isinstance(stmt.rhs.rhs.expr, CBinaryOp)
    assert stmt.rhs.rhs.expr.op == "Add"
    assert stmt.rhs.rhs.expr.lhs is divisor_cvar
    assert stmt.rhs.rhs.expr.rhs.value == 1


def test_materialize_direct_stack_mov_signed_idiv_reuses_call_result_and_reload():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    si_cvar = _reg(project, "si", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    bad_store = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    bad_reload = CAssignment(
        si_cvar,
        CBinaryOp("Add", _reg(project, "dx", codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4023},
    )
    codegen.cfunc.statements.statements.extend([call_stmt, bad_store, bad_reload])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    reload_remainder = SimpleNamespace(
        address=0x4023,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-0x76)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(load_divisor, inc_divisor, sign_extend, idiv, store_remainder, reload_remainder)
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    store_stmt = codegen.cfunc.statements.statements[1]
    reload_stmt = codegen.cfunc.statements.statements[2]
    assert isinstance(store_stmt.rhs, CBinaryOp)
    assert isinstance(store_stmt.rhs.lhs, CTypeCast)
    assert store_stmt.rhs.lhs.expr is ax_cvar
    assert reload_stmt.lhs is si_cvar
    assert reload_stmt.rhs is dst_cvar
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["call_result_reused_count"] == 1
    assert stats["reload_raw_fact_count"] == 1
    assert stats["reload_materialized_count"] == 1
    assert stats["reload_failure_count"] == 0


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


def test_lower_runtime_segment_access_resolves_single_assignment_ss_address_carrier():
    project, codegen = _project()
    ss = _reg(project, "ss", codegen)
    seg_carrier = CVariable(SimRegisterVariable(0x220, 2, name="vvar_31"), codegen=codegen)
    offset_carrier = CVariable(SimRegisterVariable(0x222, 2, name="vvar_1225"), codegen=codegen)
    address_carrier = CVariable(SimRegisterVariable(0x224, 2, name="vvar_1237"), codegen=codegen)
    result = CVariable(SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4010), codegen=codegen)
    scaled_segment = CBinaryOp("Shl", seg_carrier, _const(4, codegen), codegen=codegen)
    address_value = CBinaryOp("Add", scaled_segment, offset_carrier, codegen=codegen)
    operand = CBinaryOp("Add", address_carrier, _const(1, codegen), codegen=codegen)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    deref = CUnaryOp("Dereference", operand, codegen=codegen)
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(seg_carrier, ss, codegen=codegen),
            CAssignment(address_carrier, address_value, codegen=codegen),
            CAssignment(result, deref, codegen=codegen),
        ]
    )

    lowered = lower_runtime_segment_access_8616(deref, target="msc-dos")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U8"
    assert lowered.args[0] is seg_carrier
    assert isinstance(lowered.args[1], CBinaryOp)
    assert int(getattr(codegen, "_inertia_runtime_segment_carrier_resolved_count_8616", 0)) >= 1


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


def test_apply_runtime_segment_lowering_prunes_pure_address_self_assignment():
    project, codegen = _project()
    address = _seg_linear(project, "ds", _const(0x160, codegen), codegen)
    stmt = CAssignment(address, address, codegen=codegen)
    codegen.cfunc.statements = CStatements([stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    assert codegen._inertia_runtime_segment_address_self_assign_candidates_8616 == 1
    assert codegen._inertia_runtime_segment_address_self_assign_pruned_8616 == 1
    assert codegen._inertia_runtime_segment_address_self_assign_refused_8616 == 0


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
    assert "#define MEM_U16(ptr)" in header
    assert "#define MK_FP(seg, off)" in header


def test_render_c_runtime_header_msc_dos_uses_far_mk_fp():
    header = render_c_runtime_header_8616("msc-dos")

    assert "#include <DOS.H>" in header
    assert "#define MK_FP(seg, off) ((uint8_t far *)" in header
    assert "SEG_U16" in header
    assert "MEM_U16" in header
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
