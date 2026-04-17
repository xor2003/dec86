from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CStatements

from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import _attach_callsite_summaries_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def test_attach_callsite_summaries_sets_summary_and_binds_callee(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    callee = SimpleNamespace(name="::0x1544::InitBars")
    function = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else (callee if addr == 0x1544 else None)
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_summaries[id(call)] == CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x1544,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
    )
    assert call.callee_func is callee
    assert call.callee_target == "InitBars"
