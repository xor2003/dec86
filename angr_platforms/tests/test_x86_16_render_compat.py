from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunction, CFunctionCall, CReturn, CStatements
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.render_compat import (
    install_structured_codegen_sort_compat_8616,
    repair_cfunctioncall_render_targets_8616,
)


class _NoKbProject:
    kb = None


class _Codegen(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._idx = 0

    def next_idx(self, _name):
        self._idx += 1
        return self._idx


def test_render_compat_disables_disambiguation_for_projectless_callee():
    codegen = _Codegen(project=_NoKbProject())
    callee = SimpleNamespace(project=None, addr=0x1234, name="helper")
    call = CFunctionCall("helper", callee, [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([call], codegen=codegen))

    repaired = repair_cfunctioncall_render_targets_8616(codegen)

    assert repaired == 1
    assert call.show_disambiguated_name is False


def test_render_compat_repairs_return_value_call_targets():
    codegen = _Codegen(project=_NoKbProject())
    callee = SimpleNamespace(project=None, addr=0x1234, name="helper")
    call = CFunctionCall("helper", callee, [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([CReturn(call, codegen=codegen)], codegen=codegen))

    repaired = repair_cfunctioncall_render_targets_8616(codegen)

    assert repaired == 1
    assert call.show_disambiguated_name is False


def test_render_compat_sort_local_vars_accepts_none_and_string_idents():
    install_structured_codegen_sort_compat_8616()
    unnamed = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000)
    named = SimStackVariable(-2, 2, base="bp", name="local_2_alias", region=0x1000)
    unnamed.ident = None
    named.ident = "local_2_alias"

    assert CFunction.sort_local_vars((named, unnamed)) == [unnamed, named]
