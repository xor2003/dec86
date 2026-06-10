from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CIfElse, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
import angr_platforms.X86_16.decompiler_postprocess_stage as post_stage
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _is_cfg_return_chain_callsite_materialization_delta_8616,
    _is_cfg_return_expr_chain_materialization_delta_8616,
    _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
)


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
    root = CStatements(statements=[CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=dummy_codegen)], codegen=dummy_codegen)
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
