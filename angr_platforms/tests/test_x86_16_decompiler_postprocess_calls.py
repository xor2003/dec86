from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CReturn, CStatements

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_calls import _normalize_call_target_names_8616
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)


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
