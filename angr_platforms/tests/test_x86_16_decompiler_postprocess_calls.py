from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CReturn, CStatements

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _attach_callsite_summaries_8616,
    _align_cod_call_names_8616,
    _normalize_call_target_names_8616,
)
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(project, statements):
    codegen = _DummyCodegen(project)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _empty_codegen(project):
    return _codegen(project, [])


def test_normalize_call_target_names_rewrites_namespaced_callee_target():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    call = codegen.cfunc.statements.statements[0]
    assert changed is True
    assert call.callee_target == "InitBars"


def test_normalize_call_target_names_strips_wrapper_suffix_parens():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars()", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    call = codegen.cfunc.statements.statements[0]
    assert changed is True
    assert call.callee_target == "InitBars"


def test_normalize_call_target_names_rewrites_namespaced_callee_func_name():
    project = _project()
    codegen = _empty_codegen(project)
    callee_func = SimpleNamespace(name="::0x1544::InitBars")
    call = CFunctionCall(None, callee_func, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert callee_func.name == "InitBars"


def test_normalize_call_target_names_keeps_tail_validation_stable():
    project = _project()
    before_codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars", None, [], codegen=before_codegen)
    ret = CReturn(None, codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([call, ret], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = deepcopy(before_codegen)
    changed = _normalize_call_target_names_8616(after_codegen)

    assert changed is True
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_normalize_call_target_names_keeps_tail_validation_stable_for_same_addr_sidecar_rename():
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    before_codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=before_codegen)
    ret = CReturn(None, codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([call, ret], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = deepcopy(before_codegen)
    changed = _normalize_call_target_names_8616(after_codegen)

    assert changed is True
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_normalize_call_target_names_prefers_sidecar_label_for_sub_target_without_summary():
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_func.name == "InitMenu"
    assert call.callee_target == "InitMenu"


def test_attach_callsite_summaries_prefers_sidecar_labels_for_sub_targets(monkeypatch):
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else SimpleNamespace(addr=addr, name="sub_104d")
        )
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr: CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x104D,
            return_addr=0x4015,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func.name == "InitMenu"
    assert call.callee_target == "InitMenu"


def test_align_cod_call_names_rewrites_unknown_call_by_source_order(monkeypatch):
    project = _project()
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen),
        CFunctionCall("InitBars", SimpleNamespace(addr=0x1040, name="InitBars"), [], codegen=codegen),
        CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen),
        CFunctionCall("RunMenu", SimpleNamespace(addr=0x1060, name="RunMenu"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(
            call_names=("aNchkstk", "InitBars", "InitMenu", "RunMenu")
        ),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is True
    assert calls[2].callee_func.name == "InitMenu"
    assert calls[2].callee_target == "InitMenu"


def test_align_cod_call_names_uses_rebased_original_function_metadata(monkeypatch):
    project = _project()
    original_project = _project()
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xF010
    project._inertia_lst_metadata = SimpleNamespace(cod_path="/tmp/missing.cod", cod_proc_kinds={})
    original_project._inertia_lst_metadata = SimpleNamespace(
        cod_path="/tmp/fake.cod",
        cod_proc_kinds={0x10010: "NEAR"},
    )
    original_project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: SimpleNamespace(addr=addr, name="main") if addr == 0x10010 else None
        )
    )
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("InitBars", SimpleNamespace(addr=0x1040, name="InitBars"), [], codegen=codegen),
        CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen),
        CFunctionCall("RunMenu", SimpleNamespace(addr=0x1060, name="RunMenu"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements(calls, addr=0x1000, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.extract_cod_proc_metadata",
        lambda _path, _name, _kind: SimpleNamespace(call_names=("InitBars", "InitMenu", "RunMenu")),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is True
    assert calls[1].callee_func.name == "InitMenu"
    assert calls[1].callee_target == "InitMenu"


def test_tail_validation_call_fingerprint_prefers_resolved_function_addr_for_named_target():
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: SimpleNamespace(addr=0x104D, name="InitMenu")
            if name == "InitMenu"
            else None
        )
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("InitMenu", None, [], codegen=codegen)

    fingerprint = _expr_fingerprint(call, project)

    assert fingerprint == "call:addr:0x104d()"


def test_tail_validation_stays_stable_for_unknown_to_named_call_when_callsite_matches():
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                function
                if addr == 0x4010
                else SimpleNamespace(addr=0x104D, name="InitMenu")
                if name == "InitMenu"
                else None
            )
        )
    )
    before_codegen = _empty_codegen(project)
    before_call = CFunctionCall(None, None, [], codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([before_call, CReturn(None, codegen=before_codegen)], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = _empty_codegen(project)
    after_call = CFunctionCall("InitMenu", None, [], codegen=after_codegen)
    after_codegen.cfunc.statements = CStatements([after_call, CReturn(None, codegen=after_codegen)], addr=0x4010, codegen=after_codegen)
    after_codegen.cfunc.body = after_codegen.cfunc.statements

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )

    assert diff["changed"] is False
