from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.structuring.terminal_register_values import (
    compose_ax_byte_lanes_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def test_compose_ax_byte_lanes_masks_and_shifts_proven_values() -> None:
    codegen = _DummyCodegen()
    low = CVariable(
        SimStackVariable(-4, 1, base="bp", name="low", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    high = CVariable(
        SimStackVariable(-2, 1, base="bp", name="high", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )

    result = compose_ax_byte_lanes_8616(codegen, low, high)

    assert result.op == "Or"
    assert isinstance(result.lhs, CBinaryOp)
    assert result.lhs.op == "And"
    assert result.lhs.rhs.value == 0xFF
    assert isinstance(result.rhs, CBinaryOp)
    assert result.rhs.op == "Shl"
    assert result.rhs.rhs.value == 8
