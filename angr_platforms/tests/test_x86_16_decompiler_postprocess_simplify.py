from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_simplify import (
    _eliminate_single_use_temporaries_8616,
    _maybe_eliminate_single_use_temporaries_8616,
    _simplify_structured_expressions_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

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


def _global(addr: int, codegen, *, size: int = 1):
    return CVariable(SimMemoryVariable(addr, size, name=f"g_{addr:x}"), codegen=codegen)


def test_simplify_structured_expressions_folds_joinable_memory_byte_pair_to_word():
    codegen = _codegen([])
    low = _global(0x2000, codegen, size=1)
    high = _global(0x2001, codegen, size=1)
    expr = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CVariable)
    assert isinstance(result.variable, SimMemoryVariable)
    assert result.variable.addr == 0x2000
    assert result.variable.size == 2


def test_simplify_structured_expressions_folds_nested_literal_arithmetic_to_one_constant():
    codegen = _codegen([])
    expr = CBinaryOp(
        "Or",
        _const(13532, codegen),
        CBinaryOp("Shl", _const(18, codegen), _const(16, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CConstant)
    assert result.value == 1193180


def test_simplify_structured_expressions_folds_casted_literal_arithmetic_inside_call_arg():
    codegen = _codegen([])
    long_type = SimTypeLong(False)
    expr = CFunctionCall(
        "aNldiv",
        None,
        [
            CBinaryOp(
                "Or",
                CTypeCast(None, long_type, _const(13532, codegen), codegen=codegen),
                CBinaryOp(
                    "Shl",
                    CTypeCast(None, long_type, _const(18, codegen), codegen=codegen),
                    _const(16, codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _global(0x2000, codegen, size=2),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CFunctionCall)
    assert isinstance(result.args[0], CConstant)
    assert result.args[0].value == 1193180


def test_simplify_structured_expressions_folds_adjacent_seg_u8_pair_to_seg_u16():
    project = _project()
    codegen = _codegen([])
    ds = _reg(project, "ds", codegen)
    index = _reg(project, "bx", codegen, var_name="idx")
    scale = CBinaryOp("Mul", index, _const(2, codegen), codegen=codegen)
    low_offset = CBinaryOp("Add", _const(2288, codegen), scale, codegen=codegen)
    high_offset = CBinaryOp("Add", _const(2289, codegen), scale, codegen=codegen)
    low = CFunctionCall(
        "SEG_U8",
        None,
        [ds, low_offset],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
    )
    high = CFunctionCall(
        "SEG_U8",
        None,
        [ds, high_offset],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
    )
    expr = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Mul", high, _const(0x100, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CFunctionCall)
    assert result.callee_target == "SEG_U16"
    assert result.args == [ds, low_offset]


def test_simplify_structured_expressions_folds_adjacent_indexed_global_byte_derefs_to_word_deref():
    codegen = _codegen([])
    index = _reg(_project(), "bx", codegen, var_name="idx")

    def byte_deref(addr: int):
        base_addr = CUnaryOp("Reference", _global(addr, codegen, size=1), codegen=codegen)
        addr_expr = CBinaryOp(
            "Add",
            base_addr,
            CBinaryOp("Mul", index, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        )
        return CUnaryOp("Dereference", addr_expr, codegen=codegen)

    expr = CBinaryOp(
        "Or",
        byte_deref(0x3000),
        CBinaryOp("Mul", byte_deref(0x3001), _const(0x100, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CFunctionCall)
    assert result.callee_target == "MEM_U16"
    assert len(result.args) == 1


def test_simplify_structured_expressions_refuses_mixed_byte_pair_sources():
    codegen = _codegen([])
    low = _global(0x2000, codegen, size=1)
    high = _reg(_project(), "ax", codegen)
    expr = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is False
    assert isinstance(codegen.cfunc.statements, CBinaryOp)


def test_simplify_structured_expressions_inverts_negated_compare():
    project = _project()
    codegen = _codegen([])
    expr = CUnaryOp(
        "Not",
        CBinaryOp("CmpLE", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CBinaryOp)
    assert result.op == "CmpGT"


def test_simplify_structured_expressions_removes_same_arm_cite_condition_source():
    project = _project()
    codegen = _codegen([])
    dead_selector = CBinaryOp("CmpEQ", _reg(project, "ax", codegen), _const(0, codegen), codegen=codegen)
    live_value = CUnaryOp("Not", _reg(project, "bx", codegen), codegen=codegen)
    expr = CITE(dead_selector, live_value, live_value, codegen=codegen)
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements is live_value
    assert codegen._inertia_same_arm_cite_simplified_count_8616 == 1


def test_simplify_virtual_key_extraction_refuses_non_register_dirty_without_crash():
    class _NonRegisterDirty:
        varid = 7
        name = "vvar_7"
        bits = 16

        @property
        def reg_offset(self):
            raise TypeError("Is not a register")

    codegen = _codegen([])
    dirty_lhs = CDirtyExpression(_NonRegisterDirty(), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [CAssignment(dirty_lhs, _const(3, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 1


def test_simplify_virtual_inline_refuses_dereference_address_carrier():
    class _DirtyCarrier:
        varid = 31
        name = "vvar_31"
        bits = 16

    project = _project()
    codegen = _codegen([])
    dirty_lhs = CDirtyExpression(_DirtyCarrier(), codegen=codegen)
    dirty_use = CDirtyExpression(_DirtyCarrier(), codegen=codegen)
    replacement = _reg(project, "ss", codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", dirty_use, _const(16, codegen), codegen=codegen),
            _const(-2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(dirty_lhs, replacement, codegen=codegen),
            CAssignment(deref, _const(1, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is False
    write_lhs = codegen.cfunc.statements.statements[1].lhs
    assert write_lhs.operand.lhs.lhs is dirty_use
    assert codegen._inertia_virtual_inline_protected_address_refused == 1


def test_eliminate_single_use_temporaries_inlines_immediate_use():
    project = _project()
    before_codegen = _codegen([])
    temp = CVariable(SimRegisterVariable(4, 2, name="tmp_1"), codegen=before_codegen)
    expr = CBinaryOp("Add", _reg(project, "ax", before_codegen), _const(1, before_codegen), codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(temp, expr, codegen=before_codegen),
            CReturn(temp, codegen=before_codegen),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = _eliminate_single_use_temporaries_8616(after_codegen)

    assert changed is True
    assert len(after_codegen.cfunc.statements.statements) == 1
    retval = after_codegen.cfunc.statements.statements[0].retval
    assert isinstance(retval, CBinaryOp)
    assert retval.op == "Add"


def test_eliminate_single_use_temporaries_refuses_multi_use_temporary():
    project = _project()
    codegen = _codegen([])
    temp = CVariable(SimRegisterVariable(4, 2, name="tmp_1"), codegen=codegen)
    expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(temp, expr, codegen=codegen),
            CReturn(CBinaryOp("Add", temp, temp, codegen=codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _eliminate_single_use_temporaries_8616(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 2


def test_maybe_eliminate_single_use_temporaries_respects_feature_flag():
    project = _project()
    codegen = _codegen([])
    temp = CVariable(SimRegisterVariable(4, 2, name="tmp_1"), codegen=codegen)
    expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(temp, expr, codegen=codegen),
            CReturn(temp, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    assert _maybe_eliminate_single_use_temporaries_8616(project, codegen) is False
    assert len(codegen.cfunc.statements.statements) == 2

    project._inertia_postprocess_single_use_temporaries_enabled = True
    assert _maybe_eliminate_single_use_temporaries_8616(project, codegen) is True
    assert len(codegen.cfunc.statements.statements) == 1
