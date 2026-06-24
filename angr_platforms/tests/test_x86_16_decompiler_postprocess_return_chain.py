from __future__ import annotations

from types import SimpleNamespace

import angr_platforms.X86_16.decompiler_postprocess_stage as post_stage
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _is_cfg_return_chain_callsite_materialization_delta_8616,
    _is_cfg_return_expr_chain_materialization_delta_8616,
    _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_calls import CallsiteMaterializationDecision8616


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _if_return(cond_value: int, return_value: int, codegen):
    body = CStatements(
        statements=[CReturn(_const(return_value, codegen), codegen=codegen)],
        codegen=codegen,
    )
    return CIfElse([(_const(cond_value, codegen), body)], else_node=None, cstyle_ifs=True, codegen=codegen)


def test_prune_duplicate_empty_return_accepts_single_statement_wrapper_before_cfg_suffix():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    wrapped_empty_return = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            wrapped_empty_return,
            _if_return(1, -1, codegen),
            _if_return(2, 0, codegen),
            _if_return(3, 1, codegen),
            CReturn(_const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_return_chain_suffix_materialized_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = (-1, 0, 1)

    changed = _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_return_chain_empty_prefix_pruned_8616 is True
    assert codegen.cfunc.statements.statements[0] is not wrapped_empty_return


def test_cfg_return_chain_delta_accepts_suffix_materialization_with_refused_full_flatten(monkeypatch):
    codegen = SimpleNamespace(
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=True,
        _inertia_empty_return_branch_stats_8616={"materialized": 3, "refused": 3},
        _inertia_return_chain_materialized_values_8616=(1, 2, 3),
        _inertia_return_chain_final_value_8616=255,
        _inertia_return_chain_materialized_condition_fingerprints_8616=(),
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("const:1", "const:2", "const:3", "const:255"),
                "removed": ("none",),
            },
        }
    }

    monkeypatch.setattr(post_stage, "_ordered_conditional_return_values_8616", lambda _project, _codegen: ())
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_pairs_from_cfg_8616",
        lambda _project, _codegen: (("cond1", 1), ("cond2", 2), ("cond3", 3)),
    )
    monkeypatch.setattr(post_stage, "_last_ax_return_value_8616", lambda _project, _codegen: 255)

    assert _is_cfg_return_chain_callsite_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_return_chain_delta_refuses_helper_call_changes(monkeypatch):
    codegen = SimpleNamespace(
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=True,
        _inertia_empty_return_branch_stats_8616={"materialized": 3, "refused": 3},
        _inertia_return_chain_materialized_values_8616=(1, 2, 3),
        _inertia_return_chain_final_value_8616=255,
        _inertia_return_chain_materialized_condition_fingerprints_8616=(),
    )
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0xd368",), "removed": ()},
            "returns": {
                "added": ("const:1", "const:2", "const:3", "const:255"),
                "removed": ("none",),
            },
        }
    }

    monkeypatch.setattr(post_stage, "_ordered_conditional_return_values_8616", lambda _project, _codegen: ())
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_pairs_from_cfg_8616",
        lambda _project, _codegen: (("cond1", 1), ("cond2", 2), ("cond3", 3)),
    )
    monkeypatch.setattr(post_stage, "_last_ax_return_value_8616", lambda _project, _codegen: 255)

    assert not _is_cfg_return_chain_callsite_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_empty_if_return_materialization_refuses_unsafe_effect_function(monkeypatch):
    codegen = _DummyCodegen()
    empty_body = CStatements(statements=[], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(_const(1, codegen), empty_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_selector_function_has_unsafe_effects_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(post_stage, "_ordered_conditional_return_values_8616", lambda _project, _codegen: (7,))

    changed = post_stage._materialize_empty_if_return_branches_8616(SimpleNamespace(arch=Arch86_16()), codegen)

    assert changed is False
    assert empty_body.statements == []
    assert codegen._inertia_empty_return_branch_stats_8616["candidates"] == 1
    assert codegen._inertia_empty_return_branch_stats_8616["materialized"] == 0
    assert codegen._inertia_empty_return_branch_stats_8616["refused"] >= 1
    assert codegen._inertia_empty_return_branch_refused_unsafe_effects_8616 == 1


def test_void_tail_call_guard_repair_moves_cfg_proven_call_into_if_body(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
            CReturn(tail_call, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    assert len(root.statements) == 1
    repaired_if = root.statements[0]
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert repaired_body.statements == [tail_call]
    assert codegen._inertia_void_tail_call_guard_stats_8616 == {
        "candidates": 1,
        "materialized": 1,
        "refused": 0,
    }


def test_void_tail_call_guard_repair_handles_else_node_tail_call(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    else_body = CStatements(statements=[CReturn(tail_call, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert repaired_body.statements == [tail_call]


def test_void_tail_call_guard_repair_handles_wrapped_else_tail_call(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    else_body = CStatements(
        statements=[
            CStatements(statements=[], codegen=codegen),
            CStatements(statements=[CReturn(tail_call, codegen=codegen)], codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert repaired_body.statements == [tail_call]


def test_void_tail_call_guard_repair_preserves_setup_sequence(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    setup_a = post_stage.CAssignment(
        CVariable(SimStackVariable(-2, 2, base="bp", name="tmp_a"), codegen=codegen),
        _const(97, codegen),
        codegen=codegen,
    )
    setup_b = post_stage.CAssignment(
        CVariable(SimStackVariable(-4, 2, base="bp", name="tmp_b"), codegen=codegen),
        _const(3, codegen),
        codegen=codegen,
    )
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    else_body = CStatements(
        statements=[
            CStatements(
                statements=[
                    setup_a,
                    setup_b,
                    CExpressionStatement(tail_call, codegen=codegen),
                ],
                codegen=codegen,
            ),
            CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert setup_a in repaired_body.statements
    assert setup_b in repaired_body.statements
    assert any(isinstance(stmt, CExpressionStatement) for stmt in repaired_body.statements)


def test_void_tail_call_guard_repair_accepts_exact_condition_with_unmaterialized_args(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [], codegen=codegen)
    else_body = CStatements(statements=[CReturn(tail_call, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert repaired_body.statements == [tail_call]


def test_void_tail_call_guard_repair_inverts_cfg_proven_suffix_diamond(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    false_call = CFunctionCall("sleep", None, [_const(30, codegen)], codegen=codegen)
    false_body = CStatements(
        statements=[
            CExpressionStatement(false_call, codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        codegen=codegen,
    )
    setup = post_stage.CAssignment(
        CVariable(SimStackVariable(-2, 2, base="bp", name="tmp"), codegen=codegen),
        _const(97, codegen),
        codegen=codegen,
    )
    true_call = CFunctionCall("outp", None, [_const(97, codegen), _const(3, codegen)], codegen=codegen)
    true_sleep = CFunctionCall("sleep", None, [_const(25, codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, false_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
            setup,
            CExpressionStatement(true_call, codegen=codegen),
            CExpressionStatement(true_sleep, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    assert len(root.statements) == 1
    repaired_if = root.statements[0]
    true_body = repaired_if.condition_and_nodes[0][1]
    assert len(true_body.statements) == 3
    assert true_body.statements[0] is setup
    assert true_body.statements[1].expr is true_call
    assert true_body.statements[2].expr is true_sleep
    assert repaired_if.else_node is false_body


def test_cfg_selector_return_delta_accepts_proven_stack_probe_helper_cleanup():
    cond_fp = "CmpGE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0x4:size2)"
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=(
            "stack_slot:SS:BP+0x4:size2",
            "stack_slot:SS:BP+0x6:size2",
        ),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(cond_fp,),
        _inertia_stack_probe_helper_target_fingerprints_8616=("addr:0xd5d2",),
        _inertia_stack_probe_fact_stats={"stack_probe_summaries": 1},
    )
    validation = {
        "delta": {
            "helper_calls": {"added": (), "removed": ("addr:0xd5d2",)},
            "returns": {"added": ("stack_slot:SS:BP+0x4:size2",), "removed": ("CDirtyExpression",)},
            "conditions": {"added": (cond_fp,), "removed": ()},
            "control_flow_effects": {"added": (f"if:{cond_fp}",), "removed": ()},
        }
    }

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_refuses_unproven_helper_cleanup():
    cond_fp = "CmpGE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0x4:size2)"
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=(
            "stack_slot:SS:BP+0x4:size2",
            "stack_slot:SS:BP+0x6:size2",
        ),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(cond_fp,),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "helper_calls": {"added": (), "removed": ("addr:0xd5d2",)},
            "returns": {"added": ("stack_slot:SS:BP+0x4:size2",), "removed": ("CDirtyExpression",)},
            "conditions": {"added": (cond_fp,), "removed": ()},
            "control_flow_effects": {"added": (f"if:{cond_fp}",), "removed": ()},
        }
    }

    assert not _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_accepts_raw_stack_slot_consumed_as_source_arg(monkeypatch):
    dummy_codegen = _DummyCodegen()
    project = dummy_codegen.project
    arg_b_var = SimStackVariable(6, 2, base="bp", name="b")
    arg_b = CVariable(arg_b_var, codegen=dummy_codegen)
    cond = _const(1, dummy_codegen)
    body = CStatements(statements=[CReturn(arg_b, codegen=dummy_codegen)], codegen=dummy_codegen)
    root = CStatements(
        statements=[CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=dummy_codegen)],
        codegen=dummy_codegen,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(arg_list=(arg_b,), statements=root),
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=("stack_arg:b:size2",),
        _inertia_return_chain_materialized_condition_fingerprints_8616=("CmpNE(stack_arg:b:size2,const:0)",),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("stack_arg:b:size2",),
                "removed": ("stack_slot:SS:BP+0x6:size2",),
            },
            "conditions": {
                "added": ("CmpNE(stack_arg:which:size2,const:0)",),
                "removed": ("CmpNE(stack_arg:b:size2,const:0)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpNE(stack_arg:which:size2,const:0)",),
                "removed": ("if:CmpNE(stack_arg:b:size2,const:0)",),
            },
        }
    }

    def fake_expr_fingerprint(expr, _project):
        if expr is arg_b:
            return "stack_arg:b:size2"
        if expr is cond:
            return "CmpNE(stack_arg:which:size2,const:0)"
        return "<unexpected>"

    monkeypatch.setattr(post_stage, "_expr_fingerprint", fake_expr_fingerprint)

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        project,
        None,
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_accepts_source_view_stack_bias_alias():
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_selector_raw_stack_slot_aliases_8616={
            "stack_arg:x:size2": (
                "stack_slot:SS:BP+0x4:size2",
                "stack_slot:SS:BP+0x8:size2",
            ),
        },
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=(
            "Add(stack_arg:x:size2,const:-5)",
            "Add(stack_arg:x:size2,const:20)",
            "Shl(stack_arg:x:size2,const:1)",
            "const:10",
        ),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(
            "CmpEQ(stack_arg:x:size2,const:0)",
            "CmpLT(stack_arg:x:size2,const:1)",
            "CmpLE(stack_arg:x:size2,const:2)",
            "CmpEQ(stack_arg:x:size2,const:3)",
        ),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "returns": {
                "added": (
                    "Add(stack_arg:x:size2,const:-5)",
                    "Add(stack_arg:x:size2,const:20)",
                    "Shl(stack_arg:x:size2,const:1)",
                ),
                "removed": (
                    "Add(stack_arg:x:size2,const:-1)",
                    "Add(stack_slot:SS:BP+0x8:size2,const:20)",
                ),
            },
        }
    }

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        None,
        codegen,
        validation,
    )


def test_after_call_stack_lowering_rerun_is_single_round(monkeypatch):
    captured = {}

    def fake_run_stack_lowering_pass_8616(**kwargs):
        captured.update(kwargs)
        return False

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)

    codegen = SimpleNamespace()
    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert captured["max_rounds"] == 1
    assert captured["lower_global_segment_accesses"] is False
    assert captured["lower_runtime_segment_accesses"] is True
    assert captured["codegen"]._inertia_stack_lowering_after_call_canonicalize_budget_8616 == 16
    assert not hasattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616")


def test_after_call_stack_lowering_rerun_large_function_uses_byte_only_path(monkeypatch):
    import inertia_decompiler.cli_c_ast_rewrites as ast_rewrites

    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("large function must not run broad stack lowering rerun")

    calls: list[str] = []

    def fake_rewrite_ss_stack_byte_offsets(_project, _codegen):
        calls.append("byte-only")
        return True

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    monkeypatch.setattr(ast_rewrites, "_rewrite_ss_stack_byte_offsets", fake_rewrite_ss_stack_byte_offsets)

    codegen = SimpleNamespace(_inertia_skip_per_pass_validation_large_function=True)
    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is True
    assert calls == ["byte-only"]
    assert codegen._inertia_stack_lowering_large_function_byte_only_8616 == 1


def test_after_call_stack_lowering_rerun_refuses_selector_return_contract(monkeypatch):
    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("stack lowering rerun must not run after selector-return materialization")

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    codegen = SimpleNamespace(
        _inertia_return_selector_materialized_8616=True,
        _inertia_postprocess_validation_failed=False,
    )

    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert codegen._inertia_stack_lowering_rerun_refused_selector_return_8616 == 1


def test_after_call_stack_lowering_rerun_refuses_callsite_cache_hit():
    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("cache-hit should skip stack-lowering rerun")

    original = post_stage.run_stack_lowering_pass_8616
    post_stage.run_stack_lowering_pass_8616 = fake_run_stack_lowering_pass_8616
    try:
        codegen = SimpleNamespace(
            _inertia_callsite_materialization_last_decision_8616=CallsiteMaterializationDecision8616.CACHE_HIT,
            _inertia_callsite_materialization_last_changed_8616=False,
        )
        changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

        assert changed is False
        assert codegen._inertia_stack_lowering_rerun_refused_callsite_cache_hit_8616 == 1
    finally:
        post_stage.run_stack_lowering_pass_8616 = original


def test_postprocess_scheduler_skips_stack_identity_passes_after_selector_return():
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(
        _inertia_return_selector_materialized_8616=True,
        _inertia_postprocess_validation_failed=False,
    )
    pass_specs = (
        post_stage.DecompilerPostprocessPassSpec(
            "_apply_annotations_8616",
            lambda _project, _codegen: calls.append("bad_annotation_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            lambda _project, _codegen: calls.append("bad_stack_identity_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_rerun_stack_lowering_consumers_after_calls_8616",
            lambda _project, _codegen: calls.append("stack_rerun_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_unit_test_unrelated_cleanup_8616",
            lambda _codegen: calls.append("unrelated_cleanup") or False,
            False,
        ),
    )

    post_stage._postprocess_run_pass_specs_8616(
        project,
        codegen,
        pass_specs,
        None,
        lambda name, step: calls.append(name) or step(),
    )

    assert calls == [
        "_rerun_stack_lowering_consumers_after_calls_8616",
        "stack_rerun_pass",
        "_unit_test_unrelated_cleanup_8616",
        "unrelated_cleanup",
    ]
    assert codegen._inertia_postprocess_selector_return_skipped_passes_8616 == (
        "_apply_annotations_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
    )
