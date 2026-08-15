"""AIL return-maker regressions for closed unobserved result evidence."""

from __future__ import annotations

from types import SimpleNamespace

from angr import ailment
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.calling_conventions import SimRegArg
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_return_compat import (
    apply_x86_16_decompiler_return_compatibility,
)


class _SingleBlockGraph:
    """Minimal third-party graph surface consumed by ReturnMaker."""

    def __init__(self, block: object) -> None:
        self._block = block

    def nodes(self) -> list[object]:
        """Return the only AIL block in this fixture graph."""
        return [self._block]

    def predecessors(self, _node: object) -> list[object]:
        """Return no predecessors for the single-block fixture."""
        return []


def test_proven_unobserved_return_keeps_binary_ax_value(monkeypatch) -> None:
    """Preserve the proven terminal AX value even when current callers ignore it."""
    monkeypatch.setattr(ReturnMaker, "_handle_Return", lambda *_args: "fallback")
    apply_x86_16_decompiler_return_compatibility()

    arch = Arch86_16()
    ax = ailment.Expr.Register(
        1,
        None,
        arch.registers["ax"][0],
        16,
        reg_name="ax",
        ins_addr=0x10517,
    )
    assignment = ailment.Stmt.Assignment(
        2,
        ax,
        ailment.Expr.Const(3, None, 75, 16, ins_addr=0x10517),
        ins_addr=0x10517,
    )
    ret_stmt = ailment.Stmt.Return(4, [], ins_addr=0x1051F)
    block = SimpleNamespace(statements=[assignment, ret_stmt])
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimpleNamespace(returnty=SimTypeShort(False)),
        calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
        is_prototype_guessed=True,
        _inertia_return_compat_caller_uses_return_8616=False,
    )
    maker = SimpleNamespace(
        function=function,
        graph=_SingleBlockGraph(block),
        arch=arch,
        _next_atom=lambda: 99,
        _new_block=None,
    )

    result = ReturnMaker._handle_Return(maker, 1, ret_stmt, block)

    assert isinstance(result, ailment.Stmt.Return)
    assert len(result.ret_exprs) == 1
    assert isinstance(result.ret_exprs[0], ailment.Expr.Const)
    assert result.ret_exprs[0].value == 75
    assert isinstance(function.prototype.returnty, SimTypeShort)
