from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.codegen_metadata import get_codegen_side_metadata
from angr_platforms.X86_16.widening import widening_rules
from angr_platforms.X86_16.widening.widening_rules import (
    collect_bp_stack_access_widths_from_instructions_8616,
    promote_stack_slots_from_instruction_widths_8616,
)
from angr_platforms.X86_16.widening.word_projection_recomposition import (
    WordProjectionRecompositionStats8616,
    materialize_word_projection_recompositions_8616,
)


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


def _word_projection(source: CBinaryOp | CVariable, codegen: _DummyCodegen) -> CBinaryOp:
    low = CBinaryOp("And", source, _constant(0xFF, codegen), codegen=codegen)
    high = CBinaryOp(
        "Shl",
        CBinaryOp(
            "And",
            CBinaryOp("Shr", source, _constant(8, codegen), codegen=codegen),
            _constant(0xFF, codegen),
            codegen=codegen,
        ),
        _constant(8, codegen),
        codegen=codegen,
    )
    return CBinaryOp("Or", low, high, codegen=codegen)


def test_word_projection_recomposition_materializes_for_alias_proven_word_destination() -> None:
    codegen = _DummyCodegen()
    source = CBinaryOp("Shl", _stack_var(4, 2, "x", codegen), _constant(1, codegen), codegen=codegen)
    destination = CVariable(
        SimMemoryVariable(0x44, 2, name="g_word", region=0x4010),
        codegen=codegen,
    )
    assignment = CAssignment(destination, _word_projection(source, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([assignment], codegen=codegen))

    changed = materialize_word_projection_recompositions_8616(codegen)

    assert changed is True
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Shl"
    stats = get_codegen_side_metadata(codegen)["word_projection_recomposition_8616"]
    assert isinstance(stats, WordProjectionRecompositionStats8616)
    assert stats == WordProjectionRecompositionStats8616(1, 1, 1, 1, 0)


def test_word_projection_recomposition_refuses_unknown_destination_width() -> None:
    codegen = _DummyCodegen()
    source = _stack_var(4, 2, "x", codegen)
    destination = CVariable(SimpleNamespace(name="unknown"), codegen=codegen)
    projection = _word_projection(source, codegen)
    assignment = CAssignment(destination, projection, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([assignment], codegen=codegen))

    changed = materialize_word_projection_recompositions_8616(codegen)

    assert changed is False
    assert assignment.rhs is projection
    stats = get_codegen_side_metadata(codegen)["word_projection_recomposition_8616"]
    assert isinstance(stats, WordProjectionRecompositionStats8616)
    assert stats == WordProjectionRecompositionStats8616(1, 1, 0, 0, 1)


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


def test_instruction_width_promotion_refuses_to_narrow_signed_long(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codegen = _DummyCodegen()
    stack_value = _stack_var(4, 4, "a", codegen)
    stack_value.variable_type = SimTypeLong(True)
    codegen.cfunc = SimpleNamespace()
    promotions: list[tuple[int, object]] = []

    monkeypatch.setattr(
        widening_rules,
        "collect_bp_stack_access_widths_from_instructions_8616",
        lambda _project, _codegen: {4: 2},
    )

    def promote(_codegen: object, _cvar: object, size: int, target_type: object) -> bool:
        promotions.append((size, target_type))
        return True

    changed = promote_stack_slots_from_instruction_widths_8616(
        codegen.project,
        codegen,
        resolve_stack_cvar_at_offset=lambda _codegen, _offset, *, preferred_size: stack_value,
        promote_direct_stack_cvariable=promote,
        stack_type_for_size=lambda _size: SimTypeShort(False),
    )

    assert changed is False
    assert promotions == []
    assert isinstance(stack_value.variable_type, SimTypeLong)
    assert stack_value.variable_type.signed is True
    assert stack_value.variable.size == 4
    assert codegen._inertia_stack_width_instruction_fact_count == 1
    assert codegen._inertia_stack_width_instruction_materialized_count == 0


def test_instruction_width_promotion_still_expands_smaller_stack_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codegen = _DummyCodegen()
    stack_value = _stack_var(-2, 1, "local_2", codegen)
    codegen.cfunc = SimpleNamespace()
    target_type = SimTypeShort(False)

    monkeypatch.setattr(
        widening_rules,
        "collect_bp_stack_access_widths_from_instructions_8616",
        lambda _project, _codegen: {-2: 2},
    )

    def promote(_codegen: object, cvar: object, size: int, type_: object) -> bool:
        assert cvar is stack_value
        assert size == 2
        assert type_ is target_type
        stack_value.variable.size = size
        stack_value.variable_type = type_
        return True

    changed = promote_stack_slots_from_instruction_widths_8616(
        codegen.project,
        codegen,
        resolve_stack_cvar_at_offset=lambda _codegen, _offset, *, preferred_size: stack_value,
        promote_direct_stack_cvariable=promote,
        stack_type_for_size=lambda _size: target_type,
    )

    assert changed is True
    assert stack_value.variable.size == 2
    assert stack_value.variable_type is target_type
    assert codegen._inertia_stack_width_instruction_fact_count == 1
    assert codegen._inertia_stack_width_instruction_materialized_count == 1
