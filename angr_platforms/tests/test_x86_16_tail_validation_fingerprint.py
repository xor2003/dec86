from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CTypeCast, CUnaryOp, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint, _location_fingerprint


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
    return CBinaryOp("Or", deref_low, CBinaryOp("Mul", deref_high, _const(256, codegen), codegen=codegen), codegen=codegen)


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


def test_location_fingerprint_ignores_nested_casts_on_segmented_dereference():
    codegen = _DummyCodegen()
    project = codegen.project

    plain = _ds_linear_deref(project, 0x1234, codegen, wrap_operand_casts=0)
    cast_wrapped = _ds_linear_deref(project, 0x1234, codegen, wrap_operand_casts=2)

    assert _location_fingerprint(plain, project) == "deref:ds:0x1234"
    assert _location_fingerprint(cast_wrapped, project) == "deref:ds:0x1234"


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
