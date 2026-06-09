from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CITE,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_jcc import (
    _COND_TO_CMP_OP_8616,
    _JCC_COMPARE_OPS_8616,
    _DecodedCmpGuard8616,
    _bp_operand_stack_expr_8616,
    _decode_inc_dec_jcc_guard_8616,
    _decode_test_jcc_guard_8616,
    _ensure_c_expr_type_has_arch_8616,
    _rewrite_decoded_jcc_conditions_8616,
    _translate_cmp_jcc_guard_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _is_jcc_condition_materialization_validation_delta_8616,
)


from angr_platforms.X86_16.ir.condition_ir import JCC_TO_COND_8616
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements):
    codegen = _DummyCodegen()
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


class _FakeOperand:
    def __init__(self, operand_type: int, *, reg: int = 0, size: int = 2):
        self.type = operand_type
        self.reg = reg
        self.size = size


class _FakeInsn:
    def __init__(self, mnemonic: str, operands: tuple[_FakeOperand, ...], project, *, address: int = 0x4020):
        self.mnemonic = mnemonic
        self.operands = operands
        self.address = address
        self._project = project

    def reg_name(self, reg: int) -> str:
        for name, (offset, _size) in self._project.arch.registers.items():
            if int(offset) == int(reg):
                return name
        return f"reg_{reg:x}"


def _expr_contains_register(project, expr, name: str) -> bool:
    target = project.arch.registers[name][0]
    seen: set[int] = set()

    def _walk(node) -> bool:
        if node is None:
            return False
        marker = id(node)
        if marker in seen:
            return False
        seen.add(marker)
        if isinstance(node, CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                return int(getattr(variable, "reg", -1)) == int(target)
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "iftrue", "iffalse"):
            if _walk(getattr(node, attr, None)):
                return True
        args = getattr(node, "args", None)
        if isinstance(args, (list, tuple)):
            return any(_walk(arg) for arg in args)
        return False

    return _walk(expr)


def _stack(offset: int, codegen, name: str):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def test_rewrite_decoded_jcc_conditions_refuses_self_compare(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    same_expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=same_expr,
            rhs=same_expr,
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_decode_dec_signed_jcc_uses_predecessor_value_baseline():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    insn = _FakeInsn("dec", (_FakeOperand(1, reg=ax_offset, size=2),), project)

    jge = _decode_inc_dec_jcc_guard_8616(project, codegen, insn, "jge", {})
    jg = _decode_inc_dec_jcc_guard_8616(project, codegen, insn, "jg", {})

    assert jge is not None
    assert jge.op == "CmpGE"
    assert isinstance(jge.rhs, CConstant)
    assert jge.rhs.value == 1
    assert jg is not None
    assert jg.op == "CmpGT"
    assert isinstance(jg.rhs, CConstant)
    assert jg.rhs.value == 1


def test_decode_or_same_register_jcc_as_zero_test():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    insn = _FakeInsn(
        "or",
        (
            _FakeOperand(1, reg=ax_offset, size=2),
            _FakeOperand(1, reg=ax_offset, size=2),
        ),
        project,
    )

    decoded = _decode_test_jcc_guard_8616(project, codegen, insn, "jne", {}, None)

    assert decoded is not None
    assert decoded.op == "CmpNE"
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_bp_operand_stack_expr_uses_offset_name_without_exact_prototype_slot():
    arch = Arch86_16()
    codegen = _DummyCodegen()
    codegen.project = SimpleNamespace(arch=arch)
    wrong_offset_arg = CVariable(
        SimStackVariable(8, 2, base="bp", name="x", region=0x4010),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, arg_list=[wrong_offset_arg], variables_in_use={})

    expr = _bp_operand_stack_expr_8616(codegen, 4, 2)

    assert isinstance(expr, CVariable)
    assert expr is not wrong_offset_arg
    assert expr.name == "arg_4"
    assert isinstance(expr.variable, SimStackVariable)
    assert expr.variable.offset == 4


def test_jcc_cmp_operand_type_arch_is_bound_before_binary_op():
    project = _project()
    codegen = _codegen([])
    lhs = CVariable(
        SimStackVariable(4, 2, base="bp", name="lhs", region=0x4010),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    rhs = CConstant(0, SimTypeShort(False), codegen=codegen)
    lhs.variable_type = SimTypeShort(True)
    rhs._type = SimTypeShort(False)

    with pytest.raises(ValueError, match="without an arch"):
        CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)

    _ensure_c_expr_type_has_arch_8616(project, lhs)
    _ensure_c_expr_type_has_arch_8616(project, rhs)
    expr = CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)

    assert expr.op == "CmpGT"
    assert lhs.variable_type.signed is True
    assert rhs.type.signed is False


def test_jcc_materialization_validation_accepts_callsite_helper_and_ax_setup_delta():
    project = _project()
    function = SimpleNamespace(
        get_call_sites=lambda: (0x10522,),
        get_call_target=lambda _addr: 0x12756,
    )
    codegen = SimpleNamespace(_inertia_semantic_condition_materialized_count=1)
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0x12756",), "removed": ()},
            "register_writes": {"added": (), "removed": ("reg:ax",)},
            "stack_writes": {"added": (), "removed": ()},
            "global_writes": {"added": (), "removed": ()},
            "segmented_writes": {"added": (), "removed": ()},
            "returns": {"added": (), "removed": ()},
            "conditions": {"added": (), "removed": ()},
            "control_flow_effects": {"added": (), "removed": ()},
        }
    }

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            validation,
            function=function,
        )
        is True
    )


def test_jcc_materialization_validation_refuses_non_ax_register_removal():
    project = _project()
    function = SimpleNamespace(
        get_call_sites=lambda: (0x10522,),
        get_call_target=lambda _addr: 0x12756,
    )
    codegen = SimpleNamespace(_inertia_semantic_condition_materialized_count=1)
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0x12756",), "removed": ()},
            "register_writes": {"added": (), "removed": ("reg:bx",)},
        }
    }

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            validation,
            function=function,
        )
        is False
    )


def test_rewrite_decoded_jcc_conditions_refuses_fingerprint_equal_compare(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    lhs = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    rhs = CBinaryOp("Add", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=lhs,
            rhs=rhs,
            op="CmpGT",
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._expr_fingerprint",
        lambda _expr, _project: "same",
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rewrites_direct_condition_attr(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    if_stmt.iftrue = CStatements([], codegen=codegen)
    if_stmt.iffalse = None
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rewrites_loop_body_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), CStatements([if_stmt], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_refuses_conflicting_repeated_key(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    key = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    cond1 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    cond2 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x80, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    if_stmt = CIfElse(
        [
            (cond1, CStatements([], codegen=codegen)),
            (cond2, CStatements([], codegen=codegen)),
        ],
        codegen=codegen,
    )
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    decode_calls = []

    def _decode(_project, _codegen, _block_addr, _jcc_addr):
        decode_calls.append(1)
        if len(decode_calls) == 1:
            return _DecodedCmpGuard8616(lhs=_reg(project, "ax", codegen), rhs=_reg(project, "bx", codegen), op="CmpGT")
        return _DecodedCmpGuard8616(lhs=_reg(project, "ax", codegen), rhs=_reg(project, "bx", codegen), op="CmpLT")

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        _decode,
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond1
    assert if_stmt.condition_and_nodes[1][0] is cond2


def test_rewrite_decoded_jcc_conditions_allows_matching_repeated_key(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    key = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    cond1 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    cond2 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x80, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    if_stmt = CIfElse(
        [
            (cond1, CStatements([], codegen=codegen)),
            (cond2, CStatements([], codegen=codegen)),
        ],
        codegen=codegen,
    )
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert isinstance(if_stmt.condition_and_nodes[1][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert if_stmt.condition_and_nodes[1][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_finds_nested_tags_on_direct_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    inner = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    cond = CBinaryOp("LogicalAnd", CConstant(1, SimTypeShort(False), codegen=codegen), inner, codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rewrites_not_cite_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    inner = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    cond = CUnaryOp("Not", inner, codegen=codegen, tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000})
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_uses_branch_target_body_polarity(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(1, codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    cond = CUnaryOp("Not", carrier, codegen=codegen, tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000})
    body_stmt = CAssignment(
        _reg(project, "ax", codegen, var_name="body_ax"),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    body = CStatements([body_stmt], codegen=codegen)
    if_stmt = CIfElse([(cond, body)], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4000, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    class _Operand:
        def __init__(self, type_, *, imm=0):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=(
                    _Insn(0x4000, "cmp", ()),
                    _Insn(0x4005, "jle", (_Operand(2, imm=0x4010),)),
                )
            )
        )
    )

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpLE"


def test_rewrite_decoded_jcc_conditions_preserves_negated_cite_polarity(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(carrier, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpNE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpEQ"

    changed_again = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed_again is False
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpEQ"


def test_rewrite_decoded_jcc_conditions_preserves_call_cmp_under_not(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    carrier.tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    cond = carrier
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    call = CFunctionCall("clock", SimpleNamespace(name="clock", prototype=None), [], codegen=codegen)
    goal = CVariable(SimStackVariable(-4, 4, base="bp", name="goal", region=0x4010), codegen=codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=call,
            rhs=goal,
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CUnaryOp)
    assert rewritten.op == "Not"
    assert isinstance(rewritten.operand, CBinaryOp)
    assert rewritten.operand.op == "CmpLE"


def test_rewrite_decoded_jcc_conditions_rebinds_adjacent_call_return_register_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    ret_var = CVariable(SimRegisterVariable(0x120, 2, name="vret"), codegen=codegen)
    call_assign = CAssignment(ret_var, CFunctionCall("sub_1234", None, [], codegen=codegen), codegen=codegen)
    ax = _reg(project, "ax", codegen)
    cond = CBinaryOp("CmpNE", ax, _const(35, codegen), codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([call_assign, if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setenv("INERTIA_ENABLE_JCC_CALL_RETURN_REBIND", "1")

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert rewritten is cond
    assert rewritten.lhs is ret_var
    assert if_stmt.condition.lhs is ret_var
    assert codegen._inertia_jcc_call_return_register_rebindings >= 1


def test_rewrite_decoded_jcc_conditions_allows_argument_bp_positive_slots(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    arg = _stack(4, codegen, "arg_4")
    codegen.cfunc.arg_list = (arg,)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=arg,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_allows_argument_bp_positive_slots_from_variables_in_use(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    arg_slot = _stack(6, codegen, "iSecond")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {arg_slot.variable: arg_slot}
    codegen.cfunc.unified_local_vars = {}
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=arg_slot,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rejects_nonargument_bp_positive_slots(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.arg_list = ()
    local = _stack(4, codegen, "tmp_4")
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=local,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rejects_nonargument_bp_positive_slots_in_variables_in_use(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    local_slot = _stack(4, codegen, "tmp_4")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {local_slot.variable: local_slot}
    codegen.cfunc.unified_local_vars = {}
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=local_slot,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rewrites_tuple_condition_pairs(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes, tuple)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_handles_cycle_guard(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    cycle_body = CStatements([if_stmt], codegen=codegen)
    if_stmt.iftrue = cycle_body
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


@pytest.mark.parametrize(
    ("mnemonic", "expected_op"),
    [
        ("jc", "CmpLT"),
        ("jnae", "CmpLT"),
        ("jnb", "CmpGE"),
        ("jnc", "CmpGE"),
        ("jna", "CmpLE"),
        ("jnbe", "CmpGT"),
        ("jnge", "CmpLT"),
        ("jnl", "CmpGE"),
        ("jng", "CmpLE"),
        ("jnle", "CmpGT"),
    ],
)
def test_translate_cmp_jcc_guard_supports_all_alias_mnemonics(monkeypatch, mnemonic, expected_op):
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}
    stale_al_rhs = CBinaryOp("Mul", _reg(project, "si", codegen), _const(2, codegen), codegen=codegen)
    stale_al = CAssignment(
        _reg(project, "al", codegen),
        stale_al_rhs,
        codegen=codegen,
        tags={"ins_addr": 0x400C, "vex_block_addr": 0x4000},
    )
    codegen.cfunc.statements = CStatements([stale_al], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4002, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2))),
        _Insn(0x4004, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x400A, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x400C, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400E, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x4010, mnemonic, (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4010)

    assert decoded is not None
    assert decoded.op == expected_op
    assert _expr_fingerprint(decoded.rhs, project) != _expr_fingerprint(stale_al_rhs, project)
    assert not _expr_contains_register(project, decoded.rhs, "si")


@pytest.mark.parametrize(
    ("mnemonic", "expected_op", "expected_mask"),
    [
        ("jo", "CmpNE", 0x800),
        ("jno", "CmpEQ", 0x800),
        ("js", "CmpNE", 0x80),
        ("jns", "CmpEQ", 0x80),
        ("jp", "CmpNE", 0x4),
        ("jpe", "CmpNE", 0x4),
        ("jnp", "CmpEQ", 0x4),
        ("jpo", "CmpEQ", 0x4),
    ],
)
def test_translate_cmp_jcc_guard_supports_flag_variants(monkeypatch, mnemonic, expected_op, expected_mask):
    project = _project()
    codegen = _codegen([])

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, imm=0, size=2):
            self.type = type_
            self.reg = 0
            self.imm = imm
            self.mem = _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

    insns = (
        _Insn(0x4000, "mov", (_Operand(2, imm=0x4000),)),
        _Insn(0x4002, mnemonic, (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4002)

    assert decoded is not None
    assert decoded.op == expected_op
    left = getattr(decoded, "lhs", None)
    assert isinstance(left, CBinaryOp)
    assert left.op == "And"
    masked = getattr(left, "rhs", None)
    assert isinstance(masked, CConstant)
    assert masked.value == expected_mask
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_translate_cmp_jcc_guard_decodes_test_mask_on_bp_argument():
    project = _project()
    codegen = _codegen([])
    arg_x = _stack(4, codegen, "x")
    codegen.cfunc.arg_list = (arg_x,)
    codegen.cfunc.variables_in_use = {arg_x.variable: arg_x}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "test", (_Operand(3, mem=_Mem(5, 4), size=1), _Operand(2, imm=1, size=1))),
        _Insn(0x4003, "jne", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4003)

    assert decoded is not None
    assert decoded.op == "CmpNE"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "And"
    assert _expr_fingerprint(decoded.lhs.lhs, project) == _expr_fingerprint(arg_x, project)
    assert isinstance(decoded.lhs.rhs, CConstant)
    assert decoded.lhs.rhs.value == 1
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_translate_cmp_jcc_guard_uses_existing_bp_slot_variables_for_stack_loads(monkeypatch):
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4002, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2))),
        _Insn(0x4004, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x400A, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x400C, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400E, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x4010, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4010)

    assert decoded is not None
    assert decoded.op == "CmpGT"


def test_translate_cmp_jcc_guard_keeps_distinct_bp_slot_operands():
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4004, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400A, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x400C, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400C)

    assert decoded is not None
    assert decoded.op == "CmpGT"
    assert _expr_fingerprint(decoded.lhs, project) != _expr_fingerprint(decoded.rhs, project)


def test_translate_cmp_jcc_guard_synthesizes_distinct_bp_slots_when_locals_missing():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4004, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400A, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x400C, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400C)

    assert decoded is not None
    assert decoded.op == "CmpGT"
    assert _expr_fingerprint(decoded.lhs, project) != _expr_fingerprint(decoded.rhs, project)


def test_translate_cmp_jcc_guard_supports_cmp_reg_mem_operand_order():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4002, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4004, "jle", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4004)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert decoded.lhs is not None
    assert decoded.rhs is not None


def test_translate_cmp_jcc_guard_tracks_register_inc_before_cmp():
    project = _project()
    codegen = _codegen([])
    arg = _stack(4, codegen, "arg_4")
    child = _stack(-4, codegen, "iChild")
    codegen.cfunc.arg_list = (arg,)
    codegen.cfunc.variables_in_use = {arg.variable: arg, child.variable: child}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "inc", (_Operand(1, reg=1, size=2),)),
        _Insn(0x4003, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4005, "jle", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4005)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "Add"
    assert _expr_fingerprint(decoded.lhs.lhs, project) == _expr_fingerprint(child, project)
    assert isinstance(decoded.lhs.rhs, CConstant)
    assert decoded.lhs.rhs.value == 1
    assert _expr_fingerprint(decoded.rhs, project) == _expr_fingerprint(arg, project)


def test_compare_jcc_mapping_stays_in_sync_with_condition_ir_aliases():
    expected = {
        mnemonic: _COND_TO_CMP_OP_8616[cond_op]
        for mnemonic, cond_op in JCC_TO_COND_8616.items()
        if cond_op in _COND_TO_CMP_OP_8616
    }
    assert _JCC_COMPARE_OPS_8616 == expected


def test_translate_cmp_jcc_guard_decodes_32bit_le_chain():
    project = _project()
    codegen = _codegen([])
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (_Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),)
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=blocks.get(addr, ())))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.expr is not None
    assert isinstance(decoded.expr, CBinaryOp)


def test_translate_cmp_jcc_guard_decodes_32bit_call_return_stack_pair():
    project = _project()
    codegen = _codegen([])
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}
    codegen._func = SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": {-4: {"name": "goal"}}}})

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = 1

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    call_insn = _Insn(0x4FFE, "call", (_Operand(2, imm=0x6000, size=2),))
    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (_Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),)
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=blocks.get(addr, ())))
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: SimpleNamespace(name="clock") if addr == 0x6000 else None
        )
    )
    codegen._inertia_jcc_function_insns_8616 = (call_insn, *block_hi, *block_mid, *block_lo)

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.expr is None
    assert decoded.op == "CmpLE"
    assert isinstance(decoded.lhs, CFunctionCall)
    assert getattr(decoded.lhs, "callee_target", None) == "clock"
    assert isinstance(decoded.rhs, CVariable)
    assert isinstance(decoded.rhs.variable, SimStackVariable)
    assert decoded.rhs.variable.offset == -4
    assert decoded.rhs.variable.size == 4
    assert decoded.rhs.variable.name == "goal"
    assert not _expr_contains_register(project, decoded.lhs, "dx")
    assert not _expr_contains_register(project, decoded.lhs, "ax")
    assert codegen._inertia_jcc_wide_call_return_pair_materialized_8616 == 1


def test_translate_cmp_jcc_guard_decodes_call_return_from_previous_linear_block():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.addr = 0x10F38
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}
    codegen._func = SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": {-4: {"name": "goal"}}}})

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands, *, size=1):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = size

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    store_lo = _Insn(0x4FFA, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2)), size=2)
    store_hi = _Insn(0x4FFC, "mov", (_Operand(3, mem=_Mem(5, -2), size=2), _Operand(1, reg=2, size=2)), size=2)
    call_insn = _Insn(0x4FFE, "call", (_Operand(2, imm=0x6000, size=2),), size=2)
    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (_Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),)
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x4FFA: (store_lo,),
        0x4FFC: (store_hi,),
        0x4FFE: (call_insn,),
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, num_inst=None, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=blocks.get(addr, ())))
    )
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x4FFA), min_addr=0x4FFA)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: SimpleNamespace(name="clock", prototype=SimpleNamespace(args=()))
            if addr == 0x6000
            else None
        )
    )
    codegen._inertia_jcc_function_insns_8616 = (*block_hi, *block_mid, *block_lo)

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert isinstance(decoded.lhs, CFunctionCall)
    assert getattr(decoded.lhs, "callee_target", None) == "clock"
    assert isinstance(decoded.rhs, CVariable)
    assert isinstance(decoded.rhs.variable, SimStackVariable)
    assert decoded.rhs.variable.offset == -4
    assert decoded.rhs.variable.size == 4
    assert decoded.rhs.variable.name == "goal"
    assert codegen._inertia_jcc_wide_call_return_pair_materialized_8616 == 1
