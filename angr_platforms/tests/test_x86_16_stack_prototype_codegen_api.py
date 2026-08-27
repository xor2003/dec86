"""Regression tests for the current angr structured-codegen allocator API."""

from __future__ import annotations

from types import SimpleNamespace

from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import stack_prototype_materialization


class _CurrentAngrCodegen:
    """Expose current `next_ident`/`next_node_idx` without legacy `next_idx`."""

    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            functy=None,
            unified_local_vars={},
            variables_in_use={},
        )

    def next_ident(self, name: str) -> str:
        """Return a stable class display identity."""
        return name

    def next_node_idx(self) -> int:
        """Return one unique C AST node identity."""
        self._idx += 1
        return self._idx


def test_stack_argument_materialization_uses_current_angr_node_allocator() -> None:
    """A new BP argument must not require angr's removed `next_idx` method."""
    codegen = _CurrentAngrCodegen()

    cvar, changed = stack_prototype_materialization._ensure_arg_cvar_8616(
        codegen=codegen,
        offset=4,
        name="value",
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        width=2,
    )

    assert changed is True
    assert cvar is not None
    assert cvar.variable.offset == 4
    assert codegen.cfunc.variables_in_use[cvar.variable] is cvar
