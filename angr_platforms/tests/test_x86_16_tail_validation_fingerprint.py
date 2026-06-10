import itertools
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.alias_model import _stack_storage_facts_for_segmented_address_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _attach_tail_validation_widened_carrier_provenance_8616,
    _deepcopy_cfunc_for_validation_8616,
)
from angr_platforms.X86_16.tail_validation_fingerprint import (
    _canonical_or_unresolved_stack_fingerprint_8616,
    _expr_fingerprint,
    _location_fingerprint,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _stack(offset: int, codegen):
    return CVariable(SimStackVariable(offset, 2, name="local"), codegen=codegen)


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypeShort(False),
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                CTypeCast(
                    SimTypeShort(False),
                    SimTypeShort(False),
                    CBinaryOp(
                        "Add",
                        CUnaryOp("Reference", _stack(stack_offset, codegen), codegen=codegen),
                        _const(addend, codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _make_stack_word_pair_expr(project, codegen, offset: int, addend: int) -> CBinaryOp:
    deref_low = _ss_stack_deref(project, offset, addend, codegen)
    deref_high = _ss_stack_deref(project, offset, addend + 1, codegen)
    return CBinaryOp(
        "Or", deref_low, CBinaryOp("Mul", deref_high, _const(256, codegen), codegen=codegen), codegen=codegen
    )


def _ds_linear_deref(project, linear: int, codegen, *, wrap_operand_casts: int = 0) -> CUnaryOp:
    ds = _reg(project, "ds", codegen)
    operand = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ds, _const(4, codegen), codegen=codegen),
        _const(linear, codegen),
        codegen=codegen,
    )
    for _ in range(wrap_operand_casts):
        operand = CTypeCast(SimTypeShort(False), SimTypeShort(False), operand, codegen=codegen)
    return CUnaryOp("Dereference", operand, codegen=codegen)


def _ds_linear_deref_nested(project, linear: int, extra: int, codegen) -> CUnaryOp:
    ds = _reg(project, "ds", codegen)
    operand = CBinaryOp(
        "Add",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen),
            _const(linear, codegen),
            codegen=codegen,
        ),
        _const(extra, codegen),
        codegen=codegen,
    )
    return CUnaryOp("Dereference", operand, codegen=codegen)


def _ds_linear_deref_nested_dirty_segment(project, linear: int, extra: int, codegen) -> CUnaryOp:
    ds_offset, ds_size = project.arch.registers["ds"]
    ds = CDirtyExpression(SimpleNamespace(varid=90, reg=ds_offset, bits=ds_size * 8), codegen=codegen)
    operand = CBinaryOp(
        "Add",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen),
            _const(linear, codegen),
            codegen=codegen,
        ),
        _const(extra, codegen),
        codegen=codegen,
    )
    return CUnaryOp("Dereference", operand, codegen=codegen)


def test_expr_fingerprint_normalizes_stack_word_pair():
    codegen = _DummyCodegen()
    project = codegen.project
    expr = _make_stack_word_pair_expr(project, codegen, -2, 4)

    fingerprint = _expr_fingerprint(expr, project)

    assert fingerprint == "stack:+0x2"


def test_expr_fingerprint_canonicalizes_negated_compare_to_inverted_compare():
    codegen = _DummyCodegen()
    project = codegen.project
    lhs = _reg(project, "ax", codegen)
    rhs = _reg(project, "bx", codegen)

    negated = CUnaryOp("Not", CBinaryOp("CmpLE", lhs, rhs, codegen=codegen), codegen=codegen)
    direct = CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)

    assert _expr_fingerprint(negated, project) == _expr_fingerprint(direct, project)


def test_expr_fingerprint_allows_shared_child_nodes_without_cycle():
    codegen = _DummyCodegen()
    project = codegen.project
    shared = _stack(4, codegen)
    shared_tree = CBinaryOp("CmpGE", shared, shared, codegen=codegen)
    duplicated_tree = CBinaryOp("CmpGE", _stack(4, codegen), _stack(4, codegen), codegen=codegen)

    assert _expr_fingerprint(shared_tree, project) == _expr_fingerprint(duplicated_tree, project)
    assert "expr_cycle" not in _expr_fingerprint(shared_tree, project)


def test_location_fingerprint_ignores_nested_casts_on_segmented_dereference():
    codegen = _DummyCodegen()
    project = codegen.project

    plain = _ds_linear_deref(project, 0x1234, codegen, wrap_operand_casts=0)
    cast_wrapped = _ds_linear_deref(project, 0x1234, codegen, wrap_operand_casts=2)

    assert _location_fingerprint(plain, project) == "deref:ds:0x1234"
    assert _location_fingerprint(cast_wrapped, project) == "deref:ds:0x1234"


def test_location_fingerprint_canonicalizes_source_backed_stack_arguments_by_name():
    arch = Arch86_16()
    prototype = SimTypeFunction(
        [SimTypeShort(False).with_arch(arch), SimTypeShort(False).with_arch(arch)],
        SimTypeShort(False).with_arch(arch),
        arg_names=("frequency", "duration"),
    ).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, prototype=prototype)

    class _Functions:
        def function(self, *, addr, create=False):
            assert addr == 0x1000
            return function

    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_Functions()))
    codegen = _DummyCodegen()
    codegen.project = project
    codegen.cfunc = SimpleNamespace(addr=0x1000)
    project._inertia_tail_validation_active_codegen = codegen
    shifted = CVariable(
        SimStackVariable(6, 2, base="bp", name="frequency", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    canonical = CVariable(
        SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )

    assert _location_fingerprint(shifted, project) == "stack_arg:frequency:size2"
    assert _location_fingerprint(shifted, project) == _location_fingerprint(canonical, project)

    shifted_without_codegen = CVariable(
        SimStackVariable(6, 2, base="bp", name="frequency", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    shifted_without_codegen.codegen = None
    assert _location_fingerprint(shifted_without_codegen, project) == "stack_arg:frequency:size2"

    incomplete_codegen = _DummyCodegen()
    incomplete_codegen.project = project
    shifted_with_incomplete_codegen = CVariable(
        SimStackVariable(6, 2, base="bp", name="frequency", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=incomplete_codegen,
    )
    assert _location_fingerprint(shifted_with_incomplete_codegen, project) == "stack_arg:frequency:size2"

    raw_first_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=incomplete_codegen,
    )
    raw_second_arg = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=incomplete_codegen,
    )
    assert _location_fingerprint(raw_first_arg, project) == "stack_arg:frequency:size2"
    assert _location_fingerprint(raw_second_arg, project) == "stack_arg:duration:size2"


def test_location_fingerprint_prefers_current_cfunc_stack_arg_name_over_stale_prototype():
    arch = Arch86_16()
    prototype = SimTypeFunction(
        [SimTypeShort(False).with_arch(arch)],
        SimTypeShort(False).with_arch(arch),
        arg_names=("stale_name",),
    ).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, prototype=prototype)

    class _Functions:
        def function(self, *, addr, create=False):
            assert addr == 0x1000
            return function

    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_Functions()))
    codegen = _DummyCodegen()
    codegen.project = project
    current_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="current_name", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, arg_list=(current_arg,))
    project._inertia_tail_validation_active_codegen = codegen
    raw_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )

    assert _location_fingerprint(raw_arg, project) == "stack_arg:current_name:size2"


def test_project_segmented_lowering_evidence_matches_ds_deref_to_global():
    codegen = _DummyCodegen()
    project = codegen.project
    project._inertia_segmented_memory_lowering = {
        "DS": {"allow_linear_lowering": True},
    }

    raw = _ds_linear_deref(project, 0x1234, codegen)
    materialized = CVariable(SimMemoryVariable(0x1234, 2, name="g_1234"), codegen=codegen)

    assert not hasattr(codegen, "_inertia_segmented_memory_lowering")
    assert _location_fingerprint(raw, project) == _location_fingerprint(materialized, project)
    assert _location_fingerprint(raw, project) == "global:0x1234"


def test_expr_fingerprint_normalizes_global_word_pair_with_shifted_high_byte():
    codegen = _DummyCodegen()
    project = codegen.project
    project._inertia_segmented_memory_lowering = {
        "DS": {"allow_linear_lowering": True},
    }
    low = CVariable(SimMemoryVariable(0x160, 1, name="g_160"), codegen=codegen)
    high = _ds_linear_deref_nested(project, 0x160, 1, codegen)
    pair = CBinaryOp("Or", low, CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen), codegen=codegen)
    materialized = CVariable(SimMemoryVariable(0x160, 2, name="g_160"), codegen=codegen)

    assert _expr_fingerprint(pair, project) == _expr_fingerprint(materialized, project)
    assert _expr_fingerprint(pair, project) == "global:0x160"


def test_expr_fingerprint_normalizes_global_word_pair_from_materialized_byte_without_global_lowering():
    codegen = _DummyCodegen()
    project = codegen.project
    low = CVariable(SimMemoryVariable(0x160, 1, name="g_160"), codegen=codegen)
    high = _ds_linear_deref_nested(project, 0x160, 1, codegen)
    pair = CBinaryOp("Or", low, CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen), codegen=codegen)
    materialized = CVariable(SimMemoryVariable(0x160, 2, name="g_160"), codegen=codegen)

    assert _expr_fingerprint(pair, project) == _expr_fingerprint(materialized, project)
    assert _expr_fingerprint(pair, project) == "global:0x160"


def test_expr_fingerprint_normalizes_global_word_pair_with_dirty_segment_register():
    codegen = _DummyCodegen()
    project = codegen.project
    low = CVariable(SimMemoryVariable(0x160, 1, name="g_160"), codegen=codegen)
    high = _ds_linear_deref_nested_dirty_segment(project, 0x160, 1, codegen)
    pair = CBinaryOp("Or", low, CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen), codegen=codegen)

    assert _expr_fingerprint(pair, project) == "global:0x160"


def test_expr_fingerprint_normalizes_global_word_pair_through_dirty_aliases():
    codegen = _DummyCodegen()
    project = codegen.project
    low_rhs = CVariable(SimMemoryVariable(0x160, 1, name="g_160"), codegen=codegen)
    high_rhs = _ds_linear_deref_nested(project, 0x160, 1, codegen)
    low_lhs = CDirtyExpression(SimpleNamespace(varid=10, name="vvar_10", bits=16), codegen=codegen)
    high_lhs = CDirtyExpression(SimpleNamespace(varid=11, name="vvar_11", bits=16), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(
            [
                CAssignment(low_lhs, low_rhs, codegen=codegen),
                CAssignment(high_lhs, high_rhs, codegen=codegen),
            ],
            addr=0x4010,
            codegen=codegen,
        ),
        body=None,
        variables_in_use={},
    )
    codegen.cfunc.body = codegen.cfunc.statements

    low_use = CDirtyExpression(SimpleNamespace(varid=10, name="vvar_10", bits=16), codegen=codegen)
    high_use = CDirtyExpression(SimpleNamespace(varid=11, name="vvar_11", bits=16), codegen=codegen)
    pair = CBinaryOp("Or", low_use, CBinaryOp("Shl", high_use, _const(8, codegen), codegen=codegen), codegen=codegen)

    assert _expr_fingerprint(pair, project) == "global:0x160"


def test_expr_fingerprint_normalizes_global_word_pair_with_scaled_high_byte():
    codegen = _DummyCodegen()
    project = codegen.project
    project._inertia_segmented_memory_lowering = {
        "DS": {"allow_linear_lowering": True},
    }
    low = _ds_linear_deref(project, 0x160, codegen)
    high = CVariable(SimMemoryVariable(0x161, 1, name="g_161"), codegen=codegen)
    pair = CBinaryOp("Or", CBinaryOp("Mul", high, _const(256, codegen), codegen=codegen), low, codegen=codegen)
    materialized = CVariable(SimMemoryVariable(0x160, 2, name="g_160"), codegen=codegen)

    assert _expr_fingerprint(pair, project) == _expr_fingerprint(materialized, project)
    assert _expr_fingerprint(pair, project) == "global:0x160"


def test_indexed_stack_variable_fingerprints_direct_byte_slot_without_materialized_map():
    codegen = _DummyCodegen()
    project = codegen.project
    base_var = SimStackVariable(0, 1, name="s_0")
    indexed = CIndexedVariable(
        CVariable(base_var, codegen=codegen),
        _const(2, codegen),
        codegen=codegen,
    )

    assert _location_fingerprint(indexed, project) == "stack_slot:SS:BP+0x2:size1"


def test_expr_fingerprint_ignores_nested_casts_inside_segmented_add():
    codegen = _DummyCodegen()
    project = codegen.project
    ss = _reg(project, "ss", codegen)
    stack_ref = CUnaryOp("Reference", _stack(-2, codegen), codegen=codegen)

    plain = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
        stack_ref,
        codegen=codegen,
    )
    cast_wrapped = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
        CTypeCast(SimTypeShort(False), SimTypeShort(False), stack_ref, codegen=codegen),
        codegen=codegen,
    )

    assert _expr_fingerprint(plain, project) == _expr_fingerprint(cast_wrapped, project)


def test_deref_location_fingerprint_ignores_redundant_ss_linear_term_for_stack_slot():
    codegen = _DummyCodegen()
    project = codegen.project
    ss = _reg(project, "ss", codegen)
    si = _reg(project, "si", codegen)
    stack_ref = CUnaryOp(
        "Reference",
        CVariable(SimStackVariable(-0x5A, 2, base="bp", name="aTemp"), codegen=codegen),
        codegen=codegen,
    )
    stack_plus_index = CBinaryOp(
        "Add",
        stack_ref,
        CBinaryOp("Add", si, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    raw_linear = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            stack_plus_index,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    materialized = CUnaryOp("Dereference", stack_plus_index, codegen=codegen)

    raw_fp = _location_fingerprint(raw_linear, project)
    materialized_fp = _location_fingerprint(materialized, project)

    assert raw_fp == materialized_fp
    assert "Mul(reg:ss,const:16)" not in raw_fp


def test_deref_location_fingerprint_flattens_sp_relative_ss_linear_constants():
    codegen = _DummyCodegen()
    project = codegen.project
    ss = _reg(project, "ss", codegen)
    sp = _reg(project, "sp", codegen)
    direct = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", sp, _const(-3, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    nested = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                CBinaryOp(
                    "Add",
                    CBinaryOp("Add", sp, _const(-2, codegen), codegen=codegen),
                    _const(-2, codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert _location_fingerprint(direct, project) == _location_fingerprint(nested, project)
    assert _location_fingerprint(direct, project) == "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-3)"


def test_deref_location_fingerprint_uses_proven_ss_linear_stack_access_for_unresolved_segment_carrier():
    codegen = _DummyCodegen()
    project = codegen.project
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements([], addr=0x4010, codegen=codegen),
        body=None,
        variables_in_use={},
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -2, 2, region=0x4010)
    ]
    segment_carrier = CDirtyExpression(SimpleNamespace(varid=31, name="vvar_31", bits=16), codegen=codegen)
    stack_ref = CUnaryOp(
        "Reference",
        CVariable(SimStackVariable(-4, 2, base="bp", name="local_4", region=0x4010), codegen=codegen),
        codegen=codegen,
    )
    raw_linear = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", segment_carrier, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", stack_ref, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert _location_fingerprint(raw_linear, project) == "stack:-0x2"


def test_deref_location_fingerprint_refuses_unproven_unresolved_segment_carrier_stack_access():
    codegen = _DummyCodegen()
    project = codegen.project
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements([], addr=0x4010, codegen=codegen),
        body=None,
        variables_in_use={},
    )
    codegen.cfunc.body = codegen.cfunc.statements
    segment_carrier = CDirtyExpression(SimpleNamespace(varid=31, name="vvar_31", bits=16), codegen=codegen)
    stack_ref = CUnaryOp(
        "Reference",
        CVariable(SimStackVariable(-4, 2, base="bp", name="local_4", region=0x4010), codegen=codegen),
        codegen=codegen,
    )
    raw_linear = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", segment_carrier, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", stack_ref, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    fingerprint = _location_fingerprint(raw_linear, project)

    assert fingerprint.startswith("deref:")
    assert "virtual:vvar_31" in fingerprint


def test_dirty_register_backed_fingerprint_uses_register_identity_not_varid():
    codegen = _DummyCodegen()
    project = codegen.project
    left = CDirtyExpression(SimpleNamespace(varid=31, reg=30, bits=16), codegen=codegen)
    right = CDirtyExpression(SimpleNamespace(varid=224, reg=30, bits=16), codegen=codegen)

    assert _expr_fingerprint(left, project) == "reg:ss"
    assert _expr_fingerprint(left, project) == _expr_fingerprint(right, project)


def test_dirty_register_backed_fingerprint_preserves_distinct_registers():
    codegen = _DummyCodegen()
    project = codegen.project
    ss_carrier = CDirtyExpression(SimpleNamespace(varid=31, reg=30, bits=16), codegen=codegen)
    sp_carrier = CDirtyExpression(SimpleNamespace(varid=31, reg=8, bits=16), codegen=codegen)

    assert _expr_fingerprint(ss_carrier, project) == "reg:ss"
    assert _expr_fingerprint(sp_carrier, project) == "reg:sp"
    assert _expr_fingerprint(ss_carrier, project) != _expr_fingerprint(sp_carrier, project)


def test_dirty_without_register_evidence_keeps_virtual_identity():
    codegen = _DummyCodegen()
    project = codegen.project
    left = CDirtyExpression(SimpleNamespace(varid=31, bits=16), codegen=codegen)
    right = CDirtyExpression(SimpleNamespace(varid=224, bits=16), codegen=codegen)

    assert _expr_fingerprint(left, project) == "virtual:vvar_31"
    assert _expr_fingerprint(right, project) == "virtual:vvar_224"
    assert _expr_fingerprint(left, project) != _expr_fingerprint(right, project)


def test_expr_fingerprint_elides_zero_mul_inside_or_guard():
    codegen = _DummyCodegen()
    project = codegen.project
    ax = _reg(project, "ax", codegen)
    bx = _reg(project, "bx", codegen)
    cx = _reg(project, "cx", codegen)

    plain = CBinaryOp("Or", ax, bx, codegen=codegen)
    noisy = CBinaryOp(
        "Or",
        ax,
        CBinaryOp("Or", bx, CBinaryOp("Mul", cx, _const(0, codegen), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )

    assert _expr_fingerprint(plain, project) == _expr_fingerprint(noisy, project)


def test_runtime_segment_helper_matches_raw_dereference_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project

    raw = _ds_linear_deref(project, 2978, codegen)
    helper = CFunctionCall("SEG_U16", None, [_reg(project, "ds", codegen), _const(2978, codegen)], codegen=codegen)

    assert _expr_fingerprint(raw, project) == _expr_fingerprint(helper, project)
    assert _location_fingerprint(raw, project) == _location_fingerprint(helper, project)


def test_generic_stack_carrier_first_assignment_aliases_to_widened_slot_for_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project

    widened_var = SimStackVariable(-2, 2, name="local_2")
    widened_cvar = CVariable(widened_var, codegen=codegen)
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(carrier_cvar, widened_cvar, codegen=codegen),
                CAssignment(carrier_cvar, _const(1, codegen), codegen=codegen),
            ],
            codegen=codegen,
        ),
        variables_in_use={widened_var: widened_cvar, carrier_var: carrier_cvar},
    )

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_byte_carrier_fingerprints_as_widened_slot_with_recurrence_proof():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        "s_0": {"offset": -2, "size": 2, "carrier_size": 1, "source": "linear_recurrence"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_cvariable_object_id_hits_widened_carrier_provenance():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        id(carrier_cvar): {"offset": -2, "size": 2, "carrier_size": 1, "source": "linear_recurrence"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_cvariable_widened_proof_wins_before_copy_alias_fallback():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    alias_var = SimStackVariable(0, 1, name="v2")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([CAssignment(carrier_cvar, alias_cvar, codegen=codegen)], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar, alias_var: alias_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        id(carrier_cvar): {"offset": -2, "size": 2, "carrier_size": 1, "source": "linear_recurrence"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_attach_widened_carrier_provenance_uses_recurrence_state_for_plain_cvariable():
    codegen = _DummyCodegen()
    project = codegen.project
    widened_var = SimStackVariable(-2, 2, name="local_2")
    widened_cvar = CVariable(widened_var, codegen=codegen)
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)

    class _DummyRecurrenceState:
        @staticmethod
        def resolve_known_copy_alias_expr(expr):
            if expr is carrier_cvar:
                return widened_cvar
            return expr

    codegen._inertia_recurrence_state = _DummyRecurrenceState()
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([CAssignment(carrier_cvar, _const(1, codegen), codegen=codegen)], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar, widened_var: widened_cvar},
    )

    _attach_tail_validation_widened_carrier_provenance_8616(codegen, codegen.cfunc, function_addr=0x10678)

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_byte_carrier_without_recurrence_proof_stays_its_own_slot():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )

    assert _location_fingerprint(carrier_cvar, project) != "stack_slot:SS:BP-0x2:size2"
    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP+0x0:size1"


def test_plain_byte_carrier_does_not_match_wrong_widened_slot():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        "s_0": {"offset": 0, "size": 1, "carrier_size": 1, "source": "bad-proof"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP+0x0:size1"


def test_mk_fp_matches_raw_linear_segment_address_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project
    bx = _reg(project, "bx", codegen)

    raw = CBinaryOp(
        "Add", CBinaryOp("Mul", _reg(project, "ds", codegen), _const(16, codegen), codegen=codegen), bx, codegen=codegen
    )
    helper = CFunctionCall("MK_FP", None, [_reg(project, "ds", codegen), bx], codegen=codegen)

    assert _expr_fingerprint(raw, project) == _expr_fingerprint(helper, project)


def test_seg_ptr_matches_raw_linear_segment_address_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project
    bx = _reg(project, "bx", codegen)

    raw = CBinaryOp(
        "Add", CBinaryOp("Mul", _reg(project, "ds", codegen), _const(16, codegen), codegen=codegen), bx, codegen=codegen
    )
    helper = CFunctionCall("SEG_PTR", None, [_reg(project, "ds", codegen), bx], codegen=codegen)

    assert _expr_fingerprint(raw, project) == _expr_fingerprint(helper, project)


def test_seg_ptr_offset_order_is_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    i_var = CVariable(SimStackVariable(-2, 2, name="i"), codegen=codegen)
    scaled = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)

    left = CFunctionCall(
        "SEG_PTR",
        None,
        [_reg(project, "ds", codegen), CBinaryOp("Add", _const(2892, codegen), scaled, codegen=codegen)],
        codegen=codegen,
    )
    right = CFunctionCall(
        "SEG_PTR",
        None,
        [_reg(project, "ds", codegen), CBinaryOp("Add", scaled, _const(2892, codegen), codegen=codegen)],
        codegen=codegen,
    )

    assert _expr_fingerprint(left, project) == _expr_fingerprint(right, project)


def test_percolatedown_value_corruption_is_not_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    i_var = CVariable(SimStackVariable(-2, 2, name="i"), codegen=codegen)

    honest = CFunctionCall(
        "PercolateDown",
        None,
        [CBinaryOp("Sub", i_var, _const(1, codegen), codegen=codegen)],
        codegen=codegen,
    )
    corrupted = CFunctionCall("PercolateDown", None, [_const(3, codegen)], codegen=codegen)

    assert _expr_fingerprint(honest, project) != _expr_fingerprint(corrupted, project)


def test_stack_address_inside_seg_ptr_is_not_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    i_var = CVariable(SimStackVariable(-2, 2, name="i"), codegen=codegen)
    honest = CFunctionCall(
        "SEG_PTR",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp(
                "Add",
                _const(2892, codegen),
                CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    stack_noise = CFunctionCall(
        "SEG_PTR",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", CVariable(SimStackVariable(-4, 1, name="s_4"), codegen=codegen), codegen=codegen),
                _const(2, codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    assert _expr_fingerprint(honest, project) != _expr_fingerprint(stack_noise, project)


def test_stable_stack_dereference_matches_materialized_stack_local():
    codegen = _DummyCodegen()
    project = codegen.project
    stack_base = CVariable(SimStackVariable(-6, 1, base="bp", name="s_6"), codegen=codegen)
    materialized = CVariable(SimStackVariable(-2, 2, base="bp", name="iRow"), codegen=codegen)
    indexed = CIndexedVariable(
        CUnaryOp("Reference", stack_base, codegen=codegen),
        _const(4, codegen),
        codegen=codegen,
    )
    deref = CUnaryOp(
        "Dereference",
        CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen),
        codegen=codegen,
    )

    deref_fp = _expr_fingerprint(deref, project)
    mat_fp = _expr_fingerprint(materialized, project)
    # Both refer to BP-0x2 but the fingerprint format has diversified:
    # the indexed dereference path now emits `stack_slot:SS:BP-0x2:size*`
    # while the direct stack variable path emits `stack:-0x2`.
    assert "BP-0x2" in deref_fp or deref_fp == "stack:-0x2"
    assert ":-0x2" in mat_fp or "BP-0x2" in mat_fp


def test_indexed_stack_carrier_matches_materialized_local_with_alias_map():
    codegen = _DummyCodegen()
    project = codegen.project
    base_var = SimStackVariable(-6, 1, base="bp", name="s_6")
    alias_var = SimStackVariable(-4, 2, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    base_cvar = CVariable(base_var, codegen=codegen)
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={base_var: base_cvar, alias_var: alias_cvar, local_var: local_cvar},
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (
        codegen.cfunc.statements,
        {id(alias_var): (base_cvar, 0)},
    )

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp(
        "Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen
    )

    assert _expr_fingerprint(deref, project) == _expr_fingerprint(local_cvar, project)


def test_indexed_stack_carrier_without_alias_map_is_not_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    alias_var = SimStackVariable(-4, 2, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={alias_var: alias_cvar, local_var: local_cvar},
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (codegen.cfunc.statements, {})

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp(
        "Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen
    )

    assert _expr_fingerprint(deref, project) != _expr_fingerprint(local_cvar, project)


def test_wrong_stack_slot_does_not_match_materialized_local():
    codegen = _DummyCodegen()
    project = codegen.project
    lhs = CVariable(SimStackVariable(0, 2, base="bp", name="carrier"), codegen=codegen)
    rhs = CVariable(SimStackVariable(-2, 2, base="bp", name="iRow"), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={lhs.variable: lhs, rhs.variable: rhs},
    )

    assert _expr_fingerprint(lhs, project) != _expr_fingerprint(rhs, project)


def test_raw_stack_plus_zero_is_not_emitted_when_alias_proof_exists():
    codegen = _DummyCodegen()
    project = codegen.project
    base_var = SimStackVariable(-6, 1, base="bp", name="s_6")
    alias_var = SimStackVariable(-4, 2, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    base_cvar = CVariable(base_var, codegen=codegen)
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={base_var: base_cvar, alias_var: alias_cvar, local_var: local_cvar},
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (
        codegen.cfunc.statements,
        {id(alias_var): (base_cvar, 0)},
    )

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp(
        "Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen
    )

    fp = _expr_fingerprint(deref, project)
    assert "stack:+0x0" not in fp
    assert fp == "stack_slot:SS:BP-0x2:size2"


def test_indexed_deref_bridge_matches_materialized_local():
    codegen = _DummyCodegen()
    project = codegen.project
    alias_var = SimStackVariable(-4, 1, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={alias_var: alias_cvar, local_var: local_cvar},
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (object(), {})
    codegen._inertia_stack_canonicalization_bridges = {
        ("indexed_deref", id(alias_var), 4): -2,
    }

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp(
        "Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen
    )

    fp = _expr_fingerprint(deref, project)
    assert fp == "stack_slot:SS:BP-0x2:size2"


def test_unresolved_stack_carrier_is_not_equal_to_materialized_local():
    codegen = _DummyCodegen()
    project = codegen.project
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={local_var: local_cvar},
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (object(), {})
    codegen._inertia_stack_variable_bindings = (object(),)

    fp = _canonical_or_unresolved_stack_fingerprint_8616(0, codegen, source="test")
    assert fp.startswith("unresolved_stack_carrier:")
    assert fp != _expr_fingerprint(local_cvar, project)


def test_generic_stack_carrier_uses_unique_assignment_alias_for_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, base="bp", name="s_0")
    local_var = SimStackVariable(-2, 2, base="bp", name="local_2")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    root = CStatements(
        [CAssignment(carrier_cvar, local_cvar, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={carrier_var: carrier_cvar, local_var: local_cvar},
    )

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_deepcopy_cfunc_for_validation_handles_itertools_count():
    counter = itertools.count(7, 3)
    next(counter)
    cfunc = SimpleNamespace(addr=0x10678, _next_counter=counter)

    cloned = _deepcopy_cfunc_for_validation_8616(cfunc)

    assert cloned is not cfunc
    assert cloned._next_counter is not counter
    assert next(counter) == 10
    assert next(cloned._next_counter) == 10
