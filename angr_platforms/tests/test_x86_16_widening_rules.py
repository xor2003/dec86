from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.widening.stack_subview_projection import materialize_contained_stack_subviews_8616
from angr_platforms.X86_16.widening.widening_rules import collect_bp_stack_access_widths_from_instructions_8616


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: SimpleNamespace | None = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _constant(value: int, codegen: _DummyCodegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _stack_var(offset: int, size: int, name: str, codegen: _DummyCodegen, *, region: int = 0x4010) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=region),
        codegen=codegen,
    )


def test_collect_bp_stack_access_widths_uses_linear_summaries_without_block_metadata():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # mov word ptr [bp-2], ax
            return b"\x89\x46\xfe"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=None),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, size=3, name="store_tmp"),
    )

    widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)

    assert widths == {-2: 2}


def test_collect_bp_stack_access_widths_excludes_lea_address_width():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # lea ax, [bp-82]; mov byte ptr [bp-82], 0
            return b"\x8d\x46\xae\xc6\x46\xae\x00"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=None),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, size=7, name="addressed_byte_array"),
    )

    widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)

    assert widths == {-82: 1}


def test_contained_stack_high_byte_recomposition_materializes_to_word():
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed = CBinaryOp(
        "Or",
        word,
        CBinaryOp("Mul", high_byte, _constant(0x100, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(
        word,
        CBinaryOp("Add", recomposed, _constant(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([assignment], codegen=codegen))

    changed = materialize_contained_stack_subviews_8616(codegen)

    assert changed is True
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert isinstance(assignment.rhs.lhs, CVariable)
    assert assignment.rhs.lhs.variable.offset == -4
    assert codegen._inertia_stack_subview_raw_fact_count == 1
    assert codegen._inertia_stack_subview_normalized_fact_count == 1
    assert codegen._inertia_stack_subview_classified_fact_count == 1
    assert codegen._inertia_stack_subview_materialized_count == 1
    assert codegen._inertia_stack_subview_failure_count == 0


def test_contained_stack_high_byte_recomposition_refuses_wrong_region_and_scale():
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    wrong_region_high = _stack_var(-3, 1, "local_3", codegen, region=0x5000)
    wrong_region = CBinaryOp(
        "Or",
        word,
        CBinaryOp("Shl", wrong_region_high, _constant(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    wrong_scale = CBinaryOp(
        "Or",
        word,
        CBinaryOp("Mul", _stack_var(-3, 1, "local_3", codegen), _constant(0x80, codegen), codegen=codegen),
        codegen=codegen,
    )
    first = CAssignment(word, wrong_region, codegen=codegen)
    second = CAssignment(word, wrong_scale, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([first, second], codegen=codegen))

    changed = materialize_contained_stack_subviews_8616(codegen)

    assert changed is False
    assert first.rhs is wrong_region
    assert second.rhs is wrong_scale
    assert codegen._inertia_stack_subview_raw_fact_count == 2
    assert codegen._inertia_stack_subview_normalized_fact_count == 1
    assert codegen._inertia_stack_subview_classified_fact_count == 0
    assert codegen._inertia_stack_subview_materialized_count == 0
    assert codegen._inertia_stack_subview_failure_count == 2


def test_contained_stack_subview_materializer_does_not_rewrite_assignment_lvalue():
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed_lvalue = CBinaryOp(
        "Or",
        word,
        CBinaryOp("Shl", high_byte, _constant(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(recomposed_lvalue, _constant(1, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([assignment], codegen=codegen))

    changed = materialize_contained_stack_subviews_8616(codegen)

    assert changed is False
    assert assignment.lhs is recomposed_lvalue
    assert codegen._inertia_stack_subview_raw_fact_count == 0
