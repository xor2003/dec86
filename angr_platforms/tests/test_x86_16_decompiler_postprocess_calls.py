from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler import structured_codegen as _scg
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CExpressionStatement, CForLoop, CFunctionCall, CReturn, CStatements
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _attach_callsite_summaries_8616,
    _materialize_callsite_stack_arguments_8616,
    _materialize_callsite_prototypes_8616,
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


def test_align_cod_call_names_does_not_override_known_repeated_calls_without_unknown_nodes(monkeypatch):
    project = _project()
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1040, name="DrawBar"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1041, name="DrawBar"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("aNchkstk", "DrawBar", "DrawTime")),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[2].callee_func.name == "DrawBar"
    assert calls[2].callee_target == "DrawBar"


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


def test_materialize_callsite_stack_arguments_rewrites_preceding_stack_store_into_call_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    assert only_stmt.expr.args == [arg_slot]


def test_materialize_callsite_stack_arguments_infers_one_arg_after_stack_probe_helper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    only_call_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert only_call_stmt.expr.args == [arg_slot]
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_infers_multi_args_after_stack_probe_helper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_a = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    outgoing_b = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing_a, arg_slot_a, codegen=codegen),
            CAssignment(outgoing_b, arg_slot_b, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    only_call_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert only_call_stmt.expr.args == [arg_slot_a, arg_slot_b]
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_allows_temp_carrier_between_store_and_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_a = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    outgoing_b = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing_a, arg_slot_a, codegen=codegen),
            CAssignment(outgoing_b, arg_slot_b, codegen=codegen),
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0x200, SimTypeShort(False), codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == [arg_slot_a, arg_slot_b]


def test_materialize_callsite_stack_arguments_upgrades_undercounted_probe_summary():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_65"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_after = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_a,
                codegen=codegen,
            ),
            CAssignment(
                carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_b,
                codegen=codegen,
            ),
            CAssignment(
                carrier_after,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_next,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == [arg_slot_a, arg_slot_b]
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_carries_probe_evidence_into_loop_body():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                stack_carrier,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    loop_body = CStatements(
        [
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4020,
        codegen=codegen,
    )
    loop = CForLoop(None, None, None, loop_body, codegen=codegen)
    codegen.cfunc.statements = CStatements([probe, loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(loop_body.statements) == 1
    final_stmt = loop_body.statements[0]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == [arg_slot]
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_does_not_promote_segment_carrier_as_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            stack_carrier,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("RunMenu", SimpleNamespace(name="RunMenu"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []


def test_materialize_callsite_stack_arguments_refuses_unnamed_segment_register_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name=None),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name=None),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            stack_carrier,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("RunMenu", SimpleNamespace(name="RunMenu"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []


def test_materialize_callsite_prototypes_keeps_materialized_stack_probe_args_visible():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    callee = SimpleNamespace(name="DrawBar", prototype=None, is_prototype_guessed=False)
    call = CFunctionCall("DrawBar", callee, [arg_slot], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_prototypes_8616(project, codegen)

    assert changed is False
    assert getattr(callee, "prototype", None) is None


def test_materialize_callsite_stack_arguments_handles_tuple_statement_blocks():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        (
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            call,
        ),
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {}

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_call = codegen.cfunc.statements.statements[1]
    assert isinstance(final_call, CFunctionCall)
    assert final_call.args == [arg_slot]


def test_materialize_callsite_stack_arguments_accepts_ss_shift_linear_store_shape():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                structured_c.CVariable(
                    SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [probe, CAssignment(outgoing, arg_slot, codegen=codegen), CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == [arg_slot]


def test_materialize_callsite_stack_arguments_extracts_inline_store_before_call_from_cstatements_wrapper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Mul",
                        structured_c.CVariable(
                            SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Add",
                        structured_c.CUnaryOp(
                            "Reference",
                            structured_c.CVariable(
                                SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                                variable_type=SimTypeShort(False),
                                codegen=codegen,
                            ),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs_expr,
            codegen=codegen,
        )

    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    drawbar_call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)
    irow2 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CStatements([CExpressionStatement(probe_call, codegen=codegen)], codegen=codegen),
            CStatements([_ss_store(irow2), CExpressionStatement(drawbar_call, codegen=codegen)], codegen=codegen),
            CStatements([_ss_store(irow1), CExpressionStatement(drawtime_call, codegen=codegen)], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(drawbar_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
            return_addr=0x4019,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped_drawbar = codegen.cfunc.statements.statements[1]
    wrapped_drawtime = codegen.cfunc.statements.statements[2]
    assert isinstance(wrapped_drawbar, CStatements)
    assert isinstance(wrapped_drawtime, CStatements)
    assert len(wrapped_drawbar.statements) == 1
    assert len(wrapped_drawtime.statements) == 1
    assert isinstance(wrapped_drawbar.statements[0], CExpressionStatement)
    assert isinstance(wrapped_drawtime.statements[0], CExpressionStatement)
    assert wrapped_drawbar.statements[0].expr.args == [irow2]
    assert wrapped_drawtime.statements[0].expr.args == [irow1]


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
