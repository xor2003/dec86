from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.indexed_load_subviews import (
    project_indexed_load_subview_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import RealModeLinearGlobalAddress8616


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._node_index = 0

    def next_node_idx(self) -> int:
        self._node_index += 1
        return self._node_index

    def next_ident(self, name: str) -> str:
        return name


def _value(codegen: _Codegen, *, width: int) -> CVariable:
    variable_type = SimTypeChar(False) if width == 1 else SimTypeShort(False)
    return CVariable(
        SimMemoryVariable(0x222, width, name="words"),
        variable_type=variable_type,
        codegen=codegen,
    )


def test_indexed_load_subview_projects_high_byte_from_binary_word_site() -> None:
    codegen = _Codegen()
    full_value = _value(codegen, width=2)
    access_node = _value(codegen, width=1)
    access = RealModeLinearGlobalAddress8616("ds", 0x223, (), width=1)

    projection = project_indexed_load_subview_8616(
        codegen,
        access_node,
        full_value,
        access,
        site_base_offset=0x222,
        site_width=2,
    )

    assert projection is not None
    assert projection.byte_offset == 1
    assert projection.access_width == 1
    assert isinstance(projection.expression, CBinaryOp)
    assert projection.expression.op == "And"
    assert projection.expression.rhs.value == 0xFF
    assert isinstance(projection.expression.lhs, CBinaryOp)
    assert projection.expression.lhs.op == "Shr"
    assert projection.expression.lhs.lhs is full_value
    assert projection.expression.lhs.rhs.value == 8


def test_indexed_load_subview_keeps_exact_full_width_value() -> None:
    codegen = _Codegen()
    full_value = _value(codegen, width=2)

    projection = project_indexed_load_subview_8616(
        codegen,
        full_value,
        full_value,
        None,
        site_base_offset=0x222,
        site_width=2,
    )

    assert projection is not None
    assert projection.expression is full_value
    assert projection.byte_offset == 0
    assert projection.access_width == 2


def test_indexed_load_subview_accepts_untyped_single_byte_site() -> None:
    """A one-byte binary site has no ambiguous narrower lane to project."""
    codegen = _Codegen()
    full_value = _value(codegen, width=1)

    projection = project_indexed_load_subview_8616(
        codegen,
        object(),
        full_value,
        None,
        site_base_offset=0x222,
        site_width=1,
    )

    assert projection is not None
    assert projection.expression is full_value
    assert projection.byte_offset == 0
    assert projection.access_width == 1


def test_indexed_load_subview_refuses_wrong_segment_or_out_of_range_lane() -> None:
    codegen = _Codegen()
    full_value = _value(codegen, width=2)
    access_node = _value(codegen, width=1)

    for access in (
        RealModeLinearGlobalAddress8616("es", 0x222, (), width=1),
        RealModeLinearGlobalAddress8616("ds", 0x224, (), width=1),
    ):
        assert (
            project_indexed_load_subview_8616(
                codegen,
                access_node,
                full_value,
                access,
                site_base_offset=0x222,
                site_width=2,
            )
            is None
        )
