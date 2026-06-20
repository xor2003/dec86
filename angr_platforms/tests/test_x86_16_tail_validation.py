from __future__ import annotations

import importlib
from types import SimpleNamespace

import angr_platforms.X86_16.tail_validation as tail_validation_module
import angr_platforms.X86_16.tail_validation_fingerprint as tail_validation_fingerprint_module
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDirtyExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16 import decompiler_postprocess_stage as postprocess_stage
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation import (
    X86_16TailValidationSummary,
    X86_16ValidationCacheDescriptor,
    annotate_x86_16_tail_validation_surface_with_baseline,
    build_x86_16_tail_validation_aggregate,
    build_x86_16_tail_validation_baseline,
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_surface,
    build_x86_16_tail_validation_verdict,
    build_x86_16_validation_cache_descriptor,
    check_x86_16_tail_validation_surface_consistency,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_baseline,
    compare_x86_16_tail_validation_summaries,
    describe_x86_16_tail_validation_scope,
    extract_x86_16_tail_validation_snapshot,
    fingerprint_x86_16_tail_validation_boundary,
    format_x86_16_tail_validation_diff,
    persist_x86_16_tail_validation_snapshot,
    resolve_x86_16_validation_cached_artifact,
    summarize_x86_16_tail_validation_records,
    x86_16_tail_validation_result_passed,
    x86_16_tail_validation_snapshot_passed,
)
from angr_platforms.X86_16.tail_validation_condition_context import build_x86_16_contextual_condition_fingerprints
from angr_platforms.X86_16.tail_validation_fingerprint import build_x86_16_contextual_call_fingerprints
from angr_platforms.X86_16.tail_validation_stack_policy import include_x86_16_tail_validation_stack_write

from inertia_decompiler.tail_validation import tail_validation_snapshot_for_function_run


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def test_tail_validation_call_fingerprint_resolves_original_project_function_alias():
    class CurrentFunctions:
        def function(self, **_kwargs):
            return None

    class OriginalFunctions:
        def function(self, *, name=None, create=False, **_kwargs):
            if not create and name in {"rel_i16", "_rel_i16"}:
                return SimpleNamespace(addr=0x1005A, name="rel_i16")
            return None

    project = _project()
    project.kb = SimpleNamespace(functions=CurrentFunctions(), labels={})
    project._inertia_original_project = SimpleNamespace(kb=SimpleNamespace(functions=OriginalFunctions(), labels={}))
    codegen = _DummyCodegen()
    call = CFunctionCall("rel_i16", None, [], codegen=codegen)

    assert tail_validation_fingerprint_module._call_target_name(call, project) == "addr:0x1005a"
    assert tail_validation_fingerprint_module._expr_fingerprint(call, project) == "call:addr:0x1005a()"


def test_tail_validation_compare_canonicalizes_resolved_name_addr_helper_calls():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("name:addr:0x128E4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ()}


def test_tail_validation_compact_limit_env_allows_uncompacted_debug(monkeypatch):
    value = "CmpNE(" + "x" * 600 + ",const:0)"

    monkeypatch.delenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", raising=False)
    compacted = tail_validation_module._compact_tail_validation_observable_8616("conditions", value)
    assert compacted.startswith("conditions:sha256:")

    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", "1000")
    assert tail_validation_module._compact_tail_validation_observable_8616("conditions", value) == value


def test_tail_validation_compare_preserves_duplicate_helper_call_loss():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4", "addr:0x128e4"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("name:addr:0x128E4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ("addr:0x128e4",)}


def test_tail_validation_compare_fails_missing_callsite_coverage_even_when_stable():
    before = X86_16TailValidationSummary(
        helper_calls=("missing-callsite:addr:0x128e4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("missing-callsite:addr:0x128e4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {
        "added": (),
        "removed": ("missing-callsite:addr:0x128e4",),
    }


def test_tail_validation_compare_treats_global_byte_pair_condition_as_word_global():
    before_condition = "CmpLT(stack_slot:SS:BP-0x2:size2,Or(global:0x160,Shl(global:0x161,const:8)))"
    after_condition = "CmpLT(stack_slot:SS:BP-0x2:size2,global:0x160)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_treats_source_arg_bp_suffix_as_stack_slot_identity():
    before_condition = "CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)"
    after_condition = "CmpLT(stack_arg:iLow:size2:bp+0x4,stack_arg:iHigh:size2:bp+0x6)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0xfd1(stack_slot:SS:BP+0x4:size2)",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0xfd1(stack_arg:iLow:size2:bp+0x4)",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ()}
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_classifies_switch_helper_structuring_precision():
    before_conditions = (
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:1)",
        "CmpGT(Add(stack_slot:SS:BP+0x4:size2,const:-1),const:1)",
        "CmpNE(Add(stack_slot:SS:BP+0x4:size2,const:-2),const:1)",
        "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)",
    )
    after_conditions = (
        "CmpEQ(stack_arg:x:size2:bp+0x4,const:0)",
        "CmpEQ(stack_arg:x:size2:bp+0x4,const:3)",
        "CmpLE(stack_arg:x:size2:bp+0x4,const:2)",
        "CmpLT(stack_arg:x:size2:bp+0x4,const:1)",
    )
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1043c",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:-5)",
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:20)",
            "Mul(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:2)",
            "const:10",
        ),
        conditions=before_conditions,
        control_flow_effects=tuple(f"if:{condition}" for condition in before_conditions) + ("if:else", "return"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(stack_arg:x:size2:bp+0x4,const:-5)",
            "Add(stack_arg:x:size2:bp+0x4,const:20)",
            "Shl(stack_arg:x:size2:bp+0x4,const:1)",
            "const:10",
        ),
        conditions=after_conditions,
        control_flow_effects=tuple(f"if:{condition}" for condition in after_conditions) + ("return",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "switch_helper_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_treats_dword_scalar_projections_as_word_globals():
    before_low = "CmpEQ(global:0x132,const:900)"
    before_high = "CmpEQ(global:0x134,const:0)"
    after_low = "CmpEQ(And(global:0x132,const:65535),const:900)"
    after_high = "CmpEQ(Shr(global:0x132,const:16),const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_low, before_high),
        control_flow_effects=(f"if:{before_low}", f"if:{before_high}"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_low, after_high),
        control_flow_effects=(f"if:{after_low}", f"if:{after_high}"),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_compacts_global_byte_pair_condition_after_canonicalization():
    lhs = "Add(" + ",".join(f"reg:r{idx}" for idx in range(90)) + ")"
    before_condition = f"CmpLT({lhs},Or(global:0x160,Shl(global:0x161,const:8)))"
    after_condition = f"CmpLT({lhs},global:0x160)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_compacts_identical_oversized_conditions():
    long_condition = "CmpNE(" + ",".join(f"Add(reg:sp,const:{idx})" for idx in range(128)) + ")"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_condition,),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_condition,),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}


def test_tail_validation_compare_compacts_changed_oversized_conditions():
    long_before = "CmpNE(" + ",".join(f"Add(reg:sp,const:{idx})" for idx in range(128)) + ")"
    long_after = "CmpNE(" + ",".join(f"Add(reg:sp,const:{idx + 1})" for idx in range(128)) + ")"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_before,),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_after,),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)
    formatted = format_x86_16_tail_validation_diff(diff)

    assert diff["changed"] is True
    assert diff["delta"]["conditions"]["added"][0].startswith("conditions:sha256:")
    assert diff["delta"]["conditions"]["removed"][0].startswith("conditions:sha256:")
    assert len(formatted) < 220


def test_large_function_local_evidence_only_allows_primary_callsite_materialization():
    codegen = SimpleNamespace(
        _inertia_postprocess_function_complexity_8616={"blocks": 42, "bytes": 0x180},
        _inertia_callsite_summaries={
            1: SimpleNamespace(push_arg_sources=("ax", None)),
        },
    )
    very_large_codegen = SimpleNamespace(
        _inertia_postprocess_function_complexity_8616={"blocks": 76, "bytes": 0x1AE},
        _inertia_callsite_summaries={
            1: SimpleNamespace(push_arg_sources=("ax", None)),
        },
    )

    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_callsite_stack_arguments_8616",
            codegen,
        )
        is True
    )
    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_recovered_callsite_stack_arguments_8616",
            codegen,
        )
        is False
    )
    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_callsite_stack_arguments_8616",
            very_large_codegen,
        )
        is False
    )
    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_callsite_stack_arguments_final_8616",
            codegen,
        )
        is False
    )


def test_tail_validation_normalizes_named_helper_call_with_project_label_to_addr():
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda **_kwargs: None), labels={0x112BA: "_sprintf"}
    )

    assert tail_validation_module._normalize_helper_call_fingerprint_8616(project, "name:sprintf") == "addr:0x112ba"


def test_tail_validation_normalizes_cod_helper_call_with_project_label_to_addr():
    project = _project()
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: None), labels={0x11414: "_rand"})

    assert tail_validation_module._normalize_helper_call_fingerprint_8616(project, "codcall:rand") == "addr:0x11414"


def test_tail_validation_normalizes_exact_slice_call_target_to_original_addr():
    project = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x10A8))
    project._inertia_original_linear_delta = 0xFE70
    project._inertia_original_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x5000))
    )

    assert tail_validation_module._normalized_call_target_addr_8616(project, 0x14AE) == 0x1131E
    assert tail_validation_module._normalized_call_target_addr_8616(project, 0x1131E) == 0x1131E


def test_postprocess_validation_accepts_direct_helper_callsite_rename():
    class Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            if addr == 0x105D2 and not create:
                return SimpleNamespace(addr=addr, name="sub_105d2")
            return None

    project = _project()
    project.kb = SimpleNamespace(functions=Functions(), labels={})
    function = SimpleNamespace(
        get_call_sites=lambda: (0x10016,),
        get_call_target=lambda _addr: 0x105D2,
    )
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:aNchkstk",),
                "removed": ("name:addr:0x105d2",),
            },
            "returns": {"added": (), "removed": ()},
            "conditions": {"added": (), "removed": ()},
        }
    }

    assert postprocess_stage._is_direct_callsite_helper_delta_only_8616(project, function, validation) is True


def test_tail_validation_counts_helper_call_in_assignment_rhs():
    project = _project()
    codegen = _DummyCodegen()
    call = CFunctionCall("::0x112ba::sprintf", None, [_const(1, codegen)], codegen=codegen)
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="ret"),
                call,
                codegen=codegen,
            )
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:sprintf",)


def test_tail_validation_summary_uses_precomputed_boundary_fingerprint(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)

    def fail_fingerprint(*_args, **_kwargs):
        raise AssertionError("boundary fingerprint was recomputed")

    monkeypatch.setattr(tail_validation_module, "fingerprint_x86_16_tail_validation_boundary", fail_fingerprint)

    summary = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="precomputed:empty",
    )

    assert summary == X86_16TailValidationSummary((), (), (), (), (), (), (), ())


def test_tail_validation_summary_cache_hit_skips_ast_walk(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)

    first = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="precomputed:empty",
    )

    def fail_iter(*_args, **_kwargs):
        raise AssertionError("cached summary walked AST")

    monkeypatch.setattr(tail_validation_module, "_iter_c_nodes_deep_8616", fail_iter)

    second = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="precomputed:empty",
    )

    assert second == first
    assert codegen._inertia_tail_validation_last_summary_cache_hit is True


def test_tail_validation_collects_duplicate_helper_calls():
    project = _project()
    codegen = _DummyCodegen()
    first = CFunctionCall("::0x112ba::sprintf", None, [_const(1, codegen)], codegen=codegen)
    second = CFunctionCall("::0x112ba::sprintf", None, [_const(2, codegen)], codegen=codegen)
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="ret1"),
                first,
                codegen=codegen,
            ),
            CAssignment(
                _reg(project, "ax", codegen, var_name="ret2"),
                second,
                codegen=codegen,
            ),
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:sprintf", "name:sprintf")


def test_tail_validation_collects_missing_original_callsite(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x4012,)
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: SimpleNamespace(target_addr=0x5000, stack_probe_helper=False),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("missing-callsite:addr:0x5000",)


def test_tail_validation_missing_callsite_gate_ignores_stack_probe(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x4012,)
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: SimpleNamespace(target_addr=0x5000, stack_probe_helper=True),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ()


def _codegen(statements, codegen=None):
    codegen = codegen or _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=CStatements(statements, addr=0x4010, codegen=codegen))
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, name=name), codegen=codegen)


def _global(addr: int, codegen, *, name: str = "g"):
    return CVariable(SimMemoryVariable(addr, 2, name=name), codegen=codegen)


def test_tail_validation_summary_does_not_reuse_stale_expr_cache_after_condition_mutation():
    project = _project()
    codegen = _DummyCodegen()
    lhs = _stack(-2, codegen)
    rhs = _const(10, codegen)
    cond = CBinaryOp("CmpLT", lhs, rhs, codegen=codegen)
    stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    _codegen([stmt], codegen)

    before = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
    cond.op = "CmpGT"
    after = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert "CmpLT(stack_slot:SS:BP-0x2:size2,const:10)" in before.conditions
    assert "CmpGT(stack_slot:SS:BP-0x2:size2,const:10)" in after.conditions
    assert "CmpLT(stack_slot:SS:BP-0x2:size2,const:10)" not in after.conditions


def test_tail_validation_source_stack_arg_uses_x86_16_int_width():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction((SimTypeInt(signed=True),), SimTypeInt(signed=True), arg_names=("x",)),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(CVariable(SimStackVariable(4, 4, base="bp", name="x"), codegen=codegen),),
    )
    node = CVariable(SimStackVariable(4, 4, base="bp", name="x"), codegen=codegen)

    assert tail_validation_fingerprint_module._source_arg_location_fingerprint_8616(node, project) == (
        "stack_arg:x:size2:bp+0x4"
    )

    wrong_offset = CVariable(SimStackVariable(8, 2, base="bp", name="x"), codegen=codegen)
    assert tail_validation_fingerprint_module._source_arg_location_fingerprint_8616(wrong_offset, project) is None


def test_tail_validation_source_stack_arg_prefers_source_offset_over_mutated_cfunc_arg_name():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeInt(signed=True), SimTypeInt(signed=True)),
            SimTypeInt(signed=True),
            arg_names=("a", "b"),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(
            CVariable(SimStackVariable(4, 2, base="bp", name="b"), codegen=codegen),
            CVariable(SimStackVariable(6, 2, base="bp", name="arg_6"), codegen=codegen),
        ),
    )
    node = CVariable(SimStackVariable(4, 2, base="bp", name="b"), codegen=codegen)

    assert tail_validation_fingerprint_module._source_arg_location_fingerprint_8616(node, project) == (
        "stack_arg:a:size2:bp+0x4"
    )


def test_tail_validation_positive_bp_stack_slot_fingerprint_uses_source_arg_offset():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeInt(signed=True), SimTypeInt(signed=True)),
            SimTypeInt(signed=True),
            arg_names=("iLow", "iHigh"),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    codegen = _DummyCodegen()
    codegen.project = project
    codegen.cfunc = SimpleNamespace(addr=0x1000)

    assert tail_validation_fingerprint_module._canonical_or_unresolved_stack_fingerprint_8616(
        6,
        codegen,
        source="word_pair",
    ) == "stack_arg:iHigh:size2:bp+0x6"


def test_tail_validation_positive_bp_stack_slot_fingerprint_uses_cfunc_arg_offset_fallback():
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr=None, **_kwargs: None)),
    )
    codegen = _DummyCodegen()
    codegen.project = project
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(
            CVariable(SimStackVariable(4, 2, base="bp", name="iLow"), codegen=codegen),
            CVariable(SimStackVariable(6, 2, base="bp", name="iHigh"), codegen=codegen),
        ),
    )

    assert tail_validation_fingerprint_module._canonical_or_unresolved_stack_fingerprint_8616(
        4,
        codegen,
        source="indexed_combined",
    ) == "stack_arg:iLow:size2:bp+0x4"


def test_tail_validation_positive_bp_stack_slot_uses_active_codegen_fallback():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeInt(signed=True), SimTypeInt(signed=True)),
            SimTypeInt(signed=True),
            arg_names=("iLow", "iHigh"),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr=None, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    active_codegen = _DummyCodegen()
    active_codegen.project = project
    active_codegen.cfunc = SimpleNamespace(addr=0x1000)
    project._inertia_tail_validation_active_codegen = active_codegen
    stale_codegen = _DummyCodegen()
    stale_codegen.project = project
    stale_codegen.cfunc = SimpleNamespace(addr=None)

    assert tail_validation_fingerprint_module._canonical_or_unresolved_stack_fingerprint_8616(
        4,
        stale_codegen,
        source="bp_deref",
    ) == "stack_arg:iLow:size2:bp+0x4"


def test_tail_validation_bp_stack_fingerprint_is_not_reused_after_source_arg_context_arrives():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction((SimTypeInt(signed=True),), SimTypeInt(signed=True), arg_names=("iLow",)),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_tv_active_function_addr=0x1000,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr=None, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    stale_codegen = _DummyCodegen()
    stale_codegen.project = project
    node = CVariable(SimStackVariable(4, 2, base="bp", name="arg_4"), codegen=stale_codegen)

    assert tail_validation_fingerprint_module._expr_fingerprint(node, project) == "stack_slot:SS:BP+0x4:size2"

    active_codegen = _DummyCodegen()
    active_codegen.project = project
    active_codegen.cfunc = SimpleNamespace(addr=0x1000)
    project._inertia_tail_validation_active_codegen = active_codegen

    assert tail_validation_fingerprint_module._expr_fingerprint(node, project) == "stack_arg:iLow:size2:bp+0x4"


def test_tail_validation_boundary_does_not_reuse_stale_expr_cache_after_condition_mutation():
    project = _project()
    codegen = _DummyCodegen()
    lhs = _stack(-2, codegen)
    rhs = _const(10, codegen)
    cond = CBinaryOp("CmpLT", lhs, rhs, codegen=codegen)
    stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    _codegen([stmt], codegen)

    before = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")
    cond.op = "CmpGT"
    after = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")

    assert before != after


def test_contextual_condition_fingerprint_matches_dirty_register_flags_by_register_identity():
    codegen = _DummyCodegen()
    project = codegen.project
    flags_assignment_lhs = CDirtyExpression(SimpleNamespace(varid=10, reg=18, bits=16), codegen=codegen)
    flags_condition_var = CDirtyExpression(SimpleNamespace(varid=20, reg=18, bits=16), codegen=codegen)
    predicate = CBinaryOp(
        "CmpEQ",
        _global(0x134, codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    assignment = CAssignment(
        flags_assignment_lhs,
        CBinaryOp(
            "Or",
            _const(0x1234, codegen),
            CBinaryOp("Shl", predicate, _const(6, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", flags_condition_var, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    root = CStatements(
        [assignment, CIfElse([(condition, CStatements([], codegen=codegen))], None, codegen=codegen)], codegen=codegen
    )

    mapping = build_x86_16_contextual_condition_fingerprints(root, project)

    assert mapping[id(condition)] == "CmpEQ(global:0x134,const:0)"


def _ds_deref(project, linear: int, codegen):
    ds = _reg(project, "ds", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add", CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen), _const(linear, codegen), codegen=codegen
        ),
        codegen=codegen,
    )


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypeShort(False),
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                CTypeCast(
                    SimTypeShort(False),
                    SimTypeShort(False),
                    CBinaryOp(
                        "Add",
                        CUnaryOp("Reference", _stack(stack_offset, codegen), codegen=codegen),
                        _const(addend, codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_tail_validation_summary_collects_observable_effects():
    project = _project()
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CAssignment(_reg(project, "ax", codegen_stub), _const(1, codegen_stub), codegen=codegen_stub),
            CAssignment(_stack(4, codegen_stub), _const(2, codegen_stub), codegen=codegen_stub),
            CAssignment(_global(0x1234, codegen_stub), _const(3, codegen_stub), codegen=codegen_stub),
            CAssignment(_ds_deref(project, 0x234, codegen_stub), _const(4, codegen_stub), codegen=codegen_stub),
            CReturn(
                CFunctionCall("print_dos_string", None, [_const(0x80, codegen_stub)], codegen=codegen_stub),
                codegen=codegen_stub,
            ),
        ],
        codegen_stub,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="coarse")

    assert summary.register_writes == ("reg:ax",)
    assert summary.stack_writes == ("stack:+0x4",)
    assert summary.global_writes == ("global:0x1234",)
    assert summary.segmented_writes == ("deref:ds:0x234",)
    assert summary.helper_calls == ("print_dos_string",)
    assert summary.returns == ("call:print_dos_string(const:128)",)
    assert summary.control_flow_effects == ("return",)


def test_tail_validation_void_return_call_matches_call_then_return():
    project = _project()

    return_call_codegen = _DummyCodegen()
    return_call_codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeBottom(label="void")),
        body=CStatements(
            [
                CReturn(
                    CFunctionCall("Sleep", None, [_const(1, return_call_codegen)], codegen=return_call_codegen),
                    codegen=return_call_codegen,
                )
            ],
            addr=0x4010,
            codegen=return_call_codegen,
        ),
    )

    split_codegen = _DummyCodegen()
    split_codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeBottom(label="void")),
        body=CStatements(
            [
                CExpressionStatement(
                    CFunctionCall("Sleep", None, [_const(1, split_codegen)], codegen=split_codegen),
                    codegen=split_codegen,
                ),
                CReturn(None, codegen=split_codegen),
            ],
            addr=0x4010,
            codegen=split_codegen,
        ),
    )

    return_summary = collect_x86_16_tail_validation_summary(project, return_call_codegen, mode="coarse")
    split_summary = collect_x86_16_tail_validation_summary(project, split_codegen, mode="coarse")

    assert return_summary == split_summary
    assert return_summary.helper_calls == ("name:Sleep",)


def test_tail_validation_void_return_value_does_not_observe_ax_live_out():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeBottom(label="void")),
        body=CStatements(
            [
                CAssignment(ax, _const(7, codegen), codegen=codegen),
                CReturn(ax, codegen=codegen),
            ],
            addr=0x4010,
            codegen=codegen,
        ),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.register_writes == ()
    assert summary.returns == ("none",)


def test_tail_validation_void_return_evidence_from_source_annotation():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeShort(False)),
        body=CStatements(
            [
                CAssignment(ax, _const(7, codegen), codegen=codegen),
                CReturn(ax, codegen=codegen),
            ],
            addr=0x4010,
            codegen=codegen,
        ),
    )
    codegen._inertia_current_function_8616 = SimpleNamespace(
        info={"x86_16_annotations": {"source_lines": ("void DrawTime(int iCurrentRow)",)}}
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.register_writes == ()
    assert summary.returns == ("none",)


def test_tail_validation_legacy_and_canonical_modules_share_identity():
    canonical = importlib.import_module("angr_platforms.X86_16.tail_validation")
    legacy = importlib.import_module("angr_platforms.angr_platforms.X86_16.tail_validation")

    assert legacy is canonical


def test_tail_validation_negative_memory_addr_is_not_counted_as_global():
    project = _project()
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CAssignment(_global(-8, codegen_stub, name="g_-8"), _const(3, codegen_stub), codegen=codegen_stub),
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="coarse")

    assert summary.global_writes == ()
    assert summary.stack_writes == ("stack:-0x8",)


def test_tail_validation_live_out_ignores_nonsemantic_zero_stack_slot_write():
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:+0x0",
            mode="live_out",
            observed_locations={"stack:+0x0"},
        )
        is False
    )
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:+0x4",
            mode="live_out",
            observed_locations={"stack:+0x4"},
        )
        is True
    )
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:-0x2",
            mode="live_out",
            observed_locations={"stack:-0x2"},
        )
        is True
    )
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:-0x4",
            mode="live_out",
            observed_locations={"stack:-0x2"},
        )
        is False
    )


def test_tail_validation_uses_callsite_summary_target_for_unknown_direct_call(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CFunctionCall(None, None, [], codegen=codegen_stub),
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: SimpleNamespace(target_addr=0x104D),
    )
    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls in {("callsite:0x4012",), ("addr:0x104d",)}


def test_tail_validation_context_ignores_wrapper_assignment_before_outer_condition():
    project = _project()
    codegen = _DummyCodegen()
    flags_tmp = _reg(project, "flags", codegen, var_name="flags_tmp")
    predicate = CBinaryOp("CmpEQ", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    wrapped_assignment = CStatements(
        [
            CAssignment(
                flags_tmp,
                CBinaryOp("Mul", predicate, _const(0x40, codegen), codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", flags_tmp, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    body = CStatements(
        [
            wrapped_assignment,
            CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )

    mapping = build_x86_16_contextual_condition_fingerprints(body, project)

    assert mapping == {}


def test_tail_validation_uses_direct_capstone_callsite_fingerprint_when_cfg_callsites_missing(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (), block_addrs_set={0x4010}, project=project)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=(SimpleNamespace(address=0x4012, mnemonic="call"),),
            )
        )
    )
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CFunctionCall(None, None, [], codegen=codegen_stub),
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: None,
    )
    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("callsite:0x4012",)


def test_contextual_call_fingerprints_descend_through_expr_wrappers():
    project = _project()
    codegen = _DummyCodegen()
    wrapped_call = SimpleNamespace(expr=CFunctionCall("InitBars", None, [], codegen=codegen))
    root = CStatements([wrapped_call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, get_call_sites=lambda: (0x4012,))

    fingerprints = build_x86_16_contextual_call_fingerprints(root, project)

    inner_call = wrapped_call.expr
    assert fingerprints == {id(inner_call): "callsite:0x4012"}


def test_tail_validation_fingerprint_normalizes_stack_variable_byte_pair_to_word_slot():
    project = _project()
    codegen = _DummyCodegen()
    expr = CBinaryOp(
        "Or",
        _stack(-0xA, codegen, name="low"),
        CBinaryOp("Mul", _stack(-0x9, codegen, name="high"), _const(0x100, codegen), codegen=codegen),
        codegen=codegen,
    )

    fp = tail_validation_fingerprint_module._expr_fingerprint(expr, project)

    assert fp == "stack:-0xa"


def test_tail_validation_live_out_ignores_consumed_ss_outgoing_arg_store(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )

    before_codegen = _DummyCodegen()
    temp_var = CVariable(SimRegisterVariable(2, 2, name="vvar_67"), codegen=before_codegen)
    _codegen(
        [
            CAssignment(
                _ss_stack_deref(project, -2, -2, before_codegen), _const(97, before_codegen), codegen=before_codegen
            ),
            CAssignment(
                temp_var,
                CBinaryOp("Sub", _stack(-2, before_codegen), _const(2, before_codegen), codegen=before_codegen),
                codegen=before_codegen,
            ),
            CAssignment(
                _reg(project, "ax", before_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [], codegen=before_codegen),
                codegen=before_codegen,
            ),
        ],
        before_codegen,
    )
    before_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    after_codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", after_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [_const(97, after_codegen)], codegen=after_codegen),
                codegen=after_codegen,
            ),
        ],
        after_codegen,
    )
    after_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: SimpleNamespace(target_addr=0x14AE, arg_count=1),
    )

    before = collect_x86_16_tail_validation_summary(project, before_codegen, mode="live_out")
    after = collect_x86_16_tail_validation_summary(project, after_codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.helper_calls == ("addr:0x14ae",)
    assert after.helper_calls == ("addr:0x14ae",)
    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_materialized_call_leftover_outgoing_arg_store(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )

    before_codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _ss_stack_deref(project, -2, -2, before_codegen), _const(97, before_codegen), codegen=before_codegen
            ),
            CAssignment(
                _reg(project, "ax", before_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [_const(97, before_codegen)], codegen=before_codegen),
                codegen=before_codegen,
            ),
        ],
        before_codegen,
    )
    before_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    after_codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", after_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [_const(97, after_codegen)], codegen=after_codegen),
                codegen=after_codegen,
            ),
        ],
        after_codegen,
    )
    after_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: SimpleNamespace(
            target_addr=0x14AE,
            arg_count=1,
            push_arg_sources=(("imm", 97),),
        ),
    )

    before = collect_x86_16_tail_validation_summary(project, before_codegen, mode="live_out")
    after = collect_x86_16_tail_validation_summary(project, after_codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.helper_calls == ("addr:0x14ae",)
    assert after.helper_calls == ("addr:0x14ae",)
    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_canonicalizes_ds_linear_segmented_write_when_global_write_matches():
    segmented = {
        "deref:Add(Mul(reg:ds,const:16),const:2986)",
        "deref:Add(Mul(reg:ss,const:16),const:2986)",
    }
    global_writes = {"global:0xbaa"}

    canonical = tail_validation_module._canonicalize_segmented_write_aliases_8616(segmented, global_writes)

    assert "deref:Add(Mul(reg:ds,const:16),const:2986)" not in canonical
    assert "deref:Add(Mul(reg:ss,const:16),const:2986)" in canonical


def test_tail_validation_compare_treats_linear_ds_byte_writes_as_global_precision_improvement():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(
            "deref:Add(Mul(reg:ds,const:16),const:2986)",
            "deref:Add(Add(Mul(reg:ds,const:16),const:2986),const:1)",
        ),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=("global:0xbaa",),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["global_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_compare_treats_linear_ds_condition_as_global_precision_improvement():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpLE(Dereference(Add(Mul(reg:ds,const:16),const:306)),const:900)",),
        control_flow_effects=("if:CmpNE(Or(global:0x134,Dereference(Add(Mul(reg:ds,const:16),const:306))),const:0)",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpLE(global:0x132,const:900)",),
        control_flow_effects=("if:CmpNE(Or(global:0x134,global:0x132),const:0)",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_flattens_duplicate_or_condition_terms():
    before_condition = "CmpNE(Or(Or(global:0x134,global:0x132),global:0x132),const:0)"
    after_condition = "CmpNE(Or(global:0x134,global:0x132),const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_flattens_equivalent_ss_stack_byte_write_locations():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(
            "deref:Add(Add(Mul(reg:ss,const:16),Add(Add(reg:sp,const:-2),const:-2)),const:1)",
            "deref:Add(Add(Mul(reg:ss,const:16),Add(Add(reg:sp,const:-2),const:-6)),const:1)",
        ),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(
            "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-3)",
            "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-7)",
        ),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_compare_treats_stack_slot_reference_as_same_segmented_write_location():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=("deref:Add(Mul(reg:ss,const:16),Reference(stack_slot:SS:BP-0x8:size1),const:-17)",),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=("deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size1,const:-17)",),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_pairs_named_call_with_matching_target_after_prior_call_is_folded(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012, 0x4018))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        ),
        labels={0x112BA: "_sprintf"},
    )
    codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="retval"),
                CFunctionCall("sprintf", None, [], codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen,
    )

    def _fake_summary(_function, callsite_addr):
        return SimpleNamespace(target_addr={0x4012: 0x10D3, 0x4018: 0x112BA}[callsite_addr])

    monkeypatch.setattr(tail_validation_module, "summarize_x86_16_callsite", _fake_summary)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x112ba",)


def test_tail_validation_live_out_ignores_virtual_offset_ss_stack_frame_store():
    project = _project()
    codegen = _DummyCodegen()
    sp_carrier = CDirtyExpression(SimpleNamespace(varid=24, name="vvar_24"), codegen=codegen)
    raw_stack_store = CAssignment(
        CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
                CBinaryOp("Sub", sp_carrier, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        _const(1, codegen),
        codegen=codegen,
    )
    _codegen(
        [
            raw_stack_store,
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.segmented_writes == ()


def test_tail_validation_prefers_kb_function_for_callsite_summary_over_codegen_stub(monkeypatch):
    project = _project()
    kb_function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: kb_function if addr == 0x4010 else None
        )
    )
    codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [], codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen,
    )
    codegen.cfunc.get_call_sites = lambda: (0x4012,)

    seen = []

    def _fake_summary(function, _callsite_addr):
        seen.append(function)
        return SimpleNamespace(target_addr=0x14AE, arg_count=1)

    monkeypatch.setattr(tail_validation_module, "summarize_x86_16_callsite", _fake_summary)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x14ae",)
    assert seen
    assert all(function is kb_function for function in seen)


def test_tail_validation_live_out_ignores_dynamic_dirty_ss_segment_writes():
    project = _project()
    before_codegen = _DummyCodegen()
    dirty_ss_store = CAssignment(
        CUnaryOp(
            "Dereference",
            CTypeCast(
                SimTypeShort(False),
                SimTypeShort(False),
                CBinaryOp(
                    "Add",
                    CBinaryOp(
                        "Shl", _reg(project, "ss", before_codegen), _const(4, before_codegen), codegen=before_codegen
                    ),
                    CBinaryOp(
                        "Sub",
                        CBinaryOp(
                            "Sub",
                            CDirtyExpression("vvar_85", codegen=before_codegen),
                            _const(2, before_codegen),
                            codegen=before_codegen,
                        ),
                        _const(2, before_codegen),
                        codegen=before_codegen,
                    ),
                    codegen=before_codegen,
                ),
                codegen=before_codegen,
            ),
            codegen=before_codegen,
        ),
        _const(97, before_codegen),
        codegen=before_codegen,
    )
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([dirty_ss_store, CReturn(None, codegen=before_codegen)], before_codegen),
        mode="live_out",
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(None, codegen=after_codegen)], after_codegen),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.segmented_writes == ()
    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_indexed_ss_frame_segment_write_fingerprint():
    assert tail_validation_module._is_dynamic_dirty_ss_location_8616(
        "deref:Add(Mul(reg:ss,const:16),Reference(CIndexedVariable),const:1)"
    )
    assert not tail_validation_module._is_dynamic_dirty_ss_location_8616("deref:Add(Mul(reg:ss,const:16),reg:ax)")


def test_tail_validation_uses_cod_call_name_fingerprint_when_cfg_and_direct_targets_missing(monkeypatch):
    project = _project()
    codegen_stub = _DummyCodegen()
    known_call = CFunctionCall("InitBars", None, [], codegen=codegen_stub)
    unknown_call = CFunctionCall(None, None, [], codegen=codegen_stub)
    codegen = _codegen(
        [
            known_call,
            unknown_call,
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "_function_for_call_context_8616",
        lambda _root, _project: None,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.tail_validation_fingerprint._function_for_call_context_8616",
        lambda _root, _project: None,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.tail_validation_fingerprint._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("InitBars", "InitMenu")),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("codcall:InitBars", "codcall:InitMenu")


def test_tail_validation_diff_ignores_variable_name_churn():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "ax", before_codegen, var_name="tmp_a"),
                    _const(1, before_codegen),
                    codegen=before_codegen,
                ),
                CReturn(_reg(project, "ax", before_codegen, var_name="tmp_a"), codegen=before_codegen),
            ],
            before_codegen,
        ),
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "ax", after_codegen, var_name="tmp_b"),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CReturn(_reg(project, "ax", after_codegen, var_name="tmp_b"), codegen=after_codegen),
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["register_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["returns"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_mode_ignores_unused_temp_writes():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(_reg(project, "ax", before_codegen), codegen=before_codegen)], before_codegen),
        mode="live_out",
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "cx", after_codegen, var_name="tmp_bool"),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CReturn(_reg(project, "ax", after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
        mode="live_out",
    )
    coarse_after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "cx", after_codegen, var_name="tmp_bool"),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CReturn(_reg(project, "ax", after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
        mode="coarse",
    )

    live_out_diff = compare_x86_16_tail_validation_summaries(before, after)
    coarse_diff = compare_x86_16_tail_validation_summaries(before, coarse_after)

    assert live_out_diff["changed"] is False
    assert coarse_diff["changed"] is True
    assert coarse_diff["delta"]["register_writes"] == {"added": ("reg:cx",), "removed": ()}


def test_tail_validation_diff_keeps_global_and_segmented_models_distinct():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(_global(0x7000, before_codegen), codegen=before_codegen)], before_codegen),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CReturn(
                    CBinaryOp(
                        "Or",
                        _ds_deref(project, 0x7000, after_codegen),
                        CBinaryOp(
                            "Mul",
                            _ds_deref(project, 0x7001, after_codegen),
                            _const(0x100, after_codegen),
                            codegen=after_codegen,
                        ),
                        codegen=after_codegen,
                    ),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["returns"]["added"]
    assert diff["delta"]["returns"]["removed"]


def test_tail_validation_diff_treats_segmented_and_global_DoCRT_write_as_equivalent_when_ds_linear_lowering_is_proven():
    project = _project()
    before_codegen = _DummyCodegen()
    before_codegen._inertia_segmented_memory_lowering = {
        "DS": {
            "classification": "const",
            "associated_space": "data",
            "allow_linear_lowering": True,
            "allow_object_lowering": True,
        }
    }
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _ds_deref(project, 0x7000, before_codegen),
                    _const(1, before_codegen),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _global(0x7000, after_codegen),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.global_writes == ("global:0x7000",)
    assert before.segmented_writes == ()
    assert diff["changed"] is False
    assert diff["delta"]["global_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_register_writes_only_used_by_conditions():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [
                        (
                            CBinaryOp(
                                "Sub",
                                _reg(project, "ax", before_codegen),
                                _const(2, before_codegen),
                                codegen=before_codegen,
                            ),
                            CStatements([], codegen=before_codegen),
                        )
                    ],
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="live_out",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "ax", after_codegen),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CIfElse(
                    [
                        (
                            _reg(project, "ax", after_codegen),
                            CStatements([], codegen=after_codegen),
                        )
                    ],
                    codegen=after_codegen,
                ),
            ],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.register_writes == ()
    assert after.register_writes == ()
    assert diff["delta"]["register_writes"] == {"added": (), "removed": ()}


def test_tail_validation_boundary_fingerprint_is_stable_for_unchanged_shape():
    project = _project()
    codegen = _DummyCodegen()
    codegen = _codegen([CReturn(_const(1, codegen), codegen=codegen)], codegen)
    first = fingerprint_x86_16_tail_validation_boundary(project, codegen)
    second = fingerprint_x86_16_tail_validation_boundary(project, codegen)

    assert first == second


def test_tail_validation_cache_descriptor_is_deterministic():
    first = build_x86_16_validation_cache_descriptor(
        "tail_validation.test", {"stage": "postprocess", "mode": "live_out"}
    )
    second = build_x86_16_validation_cache_descriptor(
        "tail_validation.test", {"stage": "postprocess", "mode": "live_out"}
    )

    assert isinstance(first, X86_16ValidationCacheDescriptor)
    assert first == second
    assert first.cache_key == f"{first.namespace}:{first.fingerprint}"


def test_tail_validation_cache_descriptor_handles_non_json_payload_members():
    class _Opaque:
        pass

    first = build_x86_16_validation_cache_descriptor(
        "tail_validation.test",
        {"stage": "postprocess", "opaque": _Opaque()},
    )
    second = build_x86_16_validation_cache_descriptor(
        "tail_validation.test",
        {"stage": "postprocess", "opaque": _Opaque()},
    )

    assert isinstance(first, X86_16ValidationCacheDescriptor)
    assert first == second
    assert first.cache_key == f"{first.namespace}:{first.fingerprint}"


def test_tail_validation_cached_artifact_helper_reuses_shared_key_space():
    cache = {}
    descriptor = build_x86_16_validation_cache_descriptor("tail_validation.test", {"value": 7})

    first = resolve_x86_16_validation_cached_artifact(
        cache=cache,
        descriptor=descriptor,
        build=lambda: {"value": 7, "items": ["a"]},
        clone_on_hit=dict,
        store_value=dict,
    )
    second = resolve_x86_16_validation_cached_artifact(
        cache=cache,
        descriptor=descriptor,
        build=lambda: {"value": 9},
        clone_on_hit=dict,
        store_value=dict,
    )

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert first["cache_key"] == second["cache_key"] == descriptor.cache_key
    assert second["value"] == {"value": 7, "items": ["a"]}


def test_tail_validation_summary_uses_cache_when_boundary_fingerprint_matches():
    project = _project()
    codegen = _DummyCodegen()
    codegen = _codegen([CReturn(_reg(project, "ax", codegen), codegen=codegen)], codegen)

    first = collect_x86_16_tail_validation_summary(project, codegen)
    second = collect_x86_16_tail_validation_summary(project, codegen)

    assert first == second
    assert first is second
    assert codegen._inertia_tail_validation_last_summary_cache_hit is True
    assert codegen._inertia_tail_validation_summary_cache["stats"] == {"hits": 1, "misses": 1}


def test_tail_validation_summary_cache_misses_after_boundary_change():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen = _codegen([CReturn(ax, codegen=codegen)], codegen)

    first = collect_x86_16_tail_validation_summary(project, codegen)
    codegen.cfunc.body.statements.append(CFunctionCall("helper_ping", None, [], codegen=codegen))
    second = collect_x86_16_tail_validation_summary(project, codegen)

    assert first is not second
    assert codegen._inertia_tail_validation_last_summary_cache_hit is False


def test_tail_validation_cached_result_reuses_stage_comparison():
    owner = {}
    project = _project()
    before_codegen = _DummyCodegen()
    before_codegen = _codegen([CReturn(_const(1, before_codegen), codegen=before_codegen)], before_codegen)
    after_codegen = _DummyCodegen()
    after_codegen = _codegen(
        [
            CFunctionCall("helper_ping", None, [], codegen=after_codegen),
            CReturn(_const(1, after_codegen), codegen=after_codegen),
        ],
        after_codegen,
    )
    before_fp = fingerprint_x86_16_tail_validation_boundary(project, before_codegen)
    after_fp = fingerprint_x86_16_tail_validation_boundary(project, after_codegen)
    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen)
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen)

    first = build_x86_16_tail_validation_cached_result(
        owner=owner,
        stage="postprocess",
        mode="live_out",
        before_fingerprint=before_fp,
        after_fingerprint=after_fp,
        before_summary=before_summary,
        after_summary=after_summary,
    )
    second = build_x86_16_tail_validation_cached_result(
        owner=owner,
        stage="postprocess",
        mode="live_out",
        before_fingerprint=before_fp,
        after_fingerprint=after_fp,
        before_summary=before_summary,
        after_summary=after_summary,
    )

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["verdict"] == first["verdict"]


def test_tail_validation_collects_control_flow_effects():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    cond = CBinaryOp("CmpEQ", ax, _const(0, codegen), codegen=codegen)
    codegen = _codegen(
        [
            CIfElse(
                [(cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
                else_node=CStatements([CContinue(codegen=codegen)], codegen=codegen),
                codegen=codegen,
            ),
            CWhileLoop(cond, CStatements([], codegen=codegen), codegen=codegen),
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen)

    assert summary.conditions == ("CmpEQ(reg:ax,const:0)",)
    assert summary.control_flow_effects == (
        "break",
        "continue",
        "if:CmpEQ(reg:ax,const:0)",
        "if:else",
        "while:CmpEQ(reg:ax,const:0)",
    )


def test_tail_validation_boundary_treats_global_byte_pair_as_word_global_condition():
    project = _project()

    before_codegen = _DummyCodegen()
    i_before = _stack(-2, before_codegen, name="i")
    low = CVariable(SimMemoryVariable(0x160, 1, name="mem_0160"), codegen=before_codegen)
    high = CVariable(SimMemoryVariable(0x161, 1, name="mem_0161"), codegen=before_codegen)
    byte_pair = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _const(8, before_codegen), codegen=before_codegen),
        codegen=before_codegen,
    )
    before_cond = CBinaryOp("CmpLT", i_before, byte_pair, codegen=before_codegen)
    before_codegen = _codegen(
        [
            CIfElse(
                [(before_cond, CStatements([CBreak(codegen=before_codegen)], codegen=before_codegen))],
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )

    after_codegen = _DummyCodegen()
    after_cond = CBinaryOp(
        "CmpLT",
        _stack(-2, after_codegen, name="i"),
        _global(0x160, after_codegen, name="cszMenu"),
        codegen=after_codegen,
    )
    after_codegen = _codegen(
        [
            CIfElse(
                [(after_cond, CStatements([CBreak(codegen=after_codegen)], codegen=after_codegen))],
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    assert fingerprint_x86_16_tail_validation_boundary(project, before_codegen) == (
        fingerprint_x86_16_tail_validation_boundary(project, after_codegen)
    )
    assert collect_x86_16_tail_validation_summary(project, before_codegen).control_flow_effects == (
        collect_x86_16_tail_validation_summary(project, after_codegen).control_flow_effects
    )


def test_tail_validation_normalizes_for_loop_break_guard_equivalence():
    project = _project()
    before_codegen = _DummyCodegen()
    before_cond = CBinaryOp(
        "CmpNE",
        _reg(project, "ax", before_codegen),
        _const(0, before_codegen),
        codegen=before_codegen,
    )
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CForLoop(
                    None,
                    before_cond,
                    None,
                    CStatements([], codegen=before_codegen),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="live_out",
    )

    after_codegen = _DummyCodegen()
    after_break_cond = CBinaryOp(
        "CmpEQ",
        _reg(project, "ax", after_codegen),
        _const(0, after_codegen),
        codegen=after_codegen,
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CForLoop(
                    None,
                    _const(1, after_codegen),
                    None,
                    CStatements([CIfBreak(after_break_cond, codegen=after_codegen)], codegen=after_codegen),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("CmpNE(reg:ax,const:0)",)
    assert before.control_flow_effects == ("for:CmpNE(reg:ax,const:0)",)
    assert after.conditions == before.conditions
    assert after.control_flow_effects == before.control_flow_effects


def test_tail_validation_normalizes_boolean_cite_projection_noise():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before_cond = CUnaryOp(
        "Not",
        CITE(
            CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen),
            _const(0, before_codegen),
            _const(1, before_codegen),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    after_cond = CUnaryOp(
        "Not",
        CUnaryOp(
            "Not",
            CBinaryOp("Sub", _reg(project, "ax", after_codegen), _const(2, after_codegen), codegen=after_codegen),
            codegen=after_codegen,
        ),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [(before_cond, CStatements([], codegen=before_codegen))],
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [(after_cond, CStatements([], codegen=after_codegen))],
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("Add(reg:ax,const:-2)",)
    assert after.conditions == ("Add(reg:ax,const:-2)",)


def test_tail_validation_normalizes_zero_flag_compare_projection_noise():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before_cond = CBinaryOp(
        "Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen
    )
    after_cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp(
            "Mul",
            CBinaryOp(
                "CmpEQ",
                CBinaryOp("Sub", _reg(project, "ax", after_codegen), _const(2, after_codegen), codegen=after_codegen),
                _const(0, after_codegen),
                codegen=after_codegen,
            ),
            _const(64, after_codegen),
            codegen=after_codegen,
        ),
        _const(0, after_codegen),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(before_cond, CStatements([], codegen=before_codegen))], codegen=before_codegen)], before_codegen
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(after_cond, CStatements([], codegen=after_codegen))], codegen=after_codegen)], after_codegen
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("Add(reg:ax,const:-2)",)
    assert after.conditions == ("Add(reg:ax,const:-2)",)


def test_tail_validation_normalizes_adjacent_flag_assignment_guard_pairs():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_word = CBinaryOp(
        "Or",
        _reg(project, "si", before_codegen),
        CBinaryOp("Mul", _reg(project, "di", before_codegen), _const(0x100, before_codegen), codegen=before_codegen),
        codegen=before_codegen,
    )
    after_word = CBinaryOp(
        "Or",
        _reg(project, "si", after_codegen),
        CBinaryOp("Mul", _reg(project, "di", after_codegen), _const(0x100, after_codegen), codegen=after_codegen),
        codegen=after_codegen,
    )
    before_predicate = CBinaryOp(
        "CmpEQ",
        CBinaryOp("Add", before_word, _const(1, before_codegen), codegen=before_codegen),
        _const(0, before_codegen),
        codegen=before_codegen,
    )
    after_predicate = CBinaryOp(
        "CmpEQ",
        CBinaryOp("Add", after_word, _const(1, after_codegen), codegen=after_codegen),
        _const(0, after_codegen),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "flags", before_codegen),
                    CBinaryOp("Mul", before_predicate, _const(64, before_codegen), codegen=before_codegen),
                    codegen=before_codegen,
                ),
                CIfElse(
                    [
                        (
                            CUnaryOp(
                                "Not",
                                CBinaryOp(
                                    "CmpEQ",
                                    CBinaryOp(
                                        "And",
                                        _reg(project, "flags", before_codegen),
                                        _const(64, before_codegen),
                                        codegen=before_codegen,
                                    ),
                                    _const(0, before_codegen),
                                    codegen=before_codegen,
                                ),
                                codegen=before_codegen,
                            ),
                            CStatements([], codegen=before_codegen),
                        )
                    ],
                    codegen=before_codegen,
                ),
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(after_predicate, CStatements([], codegen=after_codegen))], codegen=after_codegen)], after_codegen
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("CmpEQ(Add(Or(reg:si,Mul(reg:di,const:256)),const:1),const:0)",)
    assert before.control_flow_effects == ("if:CmpEQ(Add(Or(reg:si,Mul(reg:di,const:256)),const:1),const:0)",)
    assert after.conditions == before.conditions
    assert after.control_flow_effects == before.control_flow_effects


def test_tail_validation_normalizes_ss_stack_dereference_to_stack_write():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _ss_stack_deref(project, -2, 2, before_codegen),
                    _const(7, before_codegen),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="coarse",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _stack(0, after_codegen),
                    _const(7, after_codegen),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
        mode="coarse",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.stack_writes == ("stack:+0x0",)
    assert before.segmented_writes == ()


def test_tail_validation_live_out_ignores_negative_stack_local_writes():
    project = _project()
    codegen = _DummyCodegen()

    summary = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _stack(-12, codegen, name="pos"),
                    _const(7, codegen),
                    codegen=codegen,
                ),
                CReturn(_const(0, codegen), codegen=codegen),
            ],
            codegen,
        ),
    )

    assert summary.stack_writes == ()


def test_tail_validation_keeps_ds_byte_pair_distinct_from_word_global_write():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _ds_deref(project, 0x7002, before_codegen), _const(0x34, before_codegen), codegen=before_codegen
                ),
                CAssignment(
                    _ds_deref(project, 0x7003, before_codegen), _const(0x12, before_codegen), codegen=before_codegen
                ),
            ],
            before_codegen,
        ),
        mode="coarse",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(_global(0x7002, after_codegen), _const(0x1234, after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
        mode="coarse",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["global_writes"] == {"added": ("global:0x7002",), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ("deref:ds:0x7002", "deref:ds:0x7003")}


def test_tail_validation_keeps_ds_word_load_distinct_from_global_word_condition():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_word = CBinaryOp(
        "Or",
        _ds_deref(project, 0x7000, before_codegen),
        CBinaryOp(
            "Mul",
            _ds_deref(project, 0x7001, before_codegen),
            _const(256, before_codegen),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    before_condition = CBinaryOp(
        "CmpEQ",
        _ds_deref(project, 0x7002, before_codegen),
        before_word,
        codegen=before_codegen,
    )
    after_condition = CBinaryOp(
        "CmpEQ",
        _ds_deref(project, 0x7002, after_codegen),
        _global(0x7000, after_codegen),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(before_condition, CStatements([], codegen=before_codegen))], None, codegen=before_codegen)],
            before_codegen,
        ),
        mode="live_out",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(after_condition, CStatements([], codegen=after_codegen))], None, codegen=after_codegen)],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["conditions"]["added"]
    assert diff["delta"]["conditions"]["removed"]
    assert diff["delta"]["control_flow_effects"]["added"]
    assert diff["delta"]["control_flow_effects"]["removed"]


def test_tail_validation_diff_formatter_reports_observable_delta():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(_const(1, before_codegen), codegen=before_codegen)], before_codegen),
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CFunctionCall("helper_ping", None, [], codegen=after_codegen),
                CReturn(_const(1, after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
    )

    formatted = format_x86_16_tail_validation_diff(compare_x86_16_tail_validation_summaries(before, after))

    assert "helper_calls: +helper_ping" in formatted


def test_tail_validation_verdict_builder_includes_stage_mode_and_status():
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "summary_text": "helper_calls: +helper_ping",
    }

    verdict = build_x86_16_tail_validation_verdict("postprocess", validation)

    assert verdict == "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping"


def test_tail_validation_verdict_builder_preserves_non_success_status():
    verdict = build_x86_16_tail_validation_verdict(
        "postprocess",
        {
            "status": "unknown",
            "mode": "live_out",
            "summary_text": "validation metadata was not collected",
        },
    )

    assert verdict == "postprocess whole-tail validation [live_out] unknown: validation metadata was not collected"


def test_tail_validation_snapshot_extracts_known_stage_fields():
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "structuring": {
                    "changed": False,
                    "status": "stable",
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
                    "summary_text": "no observable whole-tail changes",
                    "scope": {"ignored": ("temporary names",)},
                }
            }
        }
    )

    assert snapshot == {
        "structuring": {
            "changed": False,
            "status": "stable",
            "mode": "live_out",
            "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
            "summary_text": "no observable whole-tail changes",
        }
    }


def test_tail_validation_snapshot_preserves_delta_for_aggregate_family_reports():
    delta = {"helper_calls": {"added": ("helper_ping",), "removed": ()}}
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                    "summary_text": "helper_calls: +helper_ping",
                    "delta": delta,
                }
            }
        }
    )

    assert snapshot["postprocess"]["delta"] == delta


def test_tail_validation_snapshot_without_status_or_changed_stays_unknown():
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "postprocess": {
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] unknown: not collected",
                    "summary_text": "not collected",
                }
            }
        }
    )

    assert snapshot == {
        "postprocess": {
            "changed": False,
            "status": "unknown",
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] unknown: not collected",
            "summary_text": "not collected",
        }
    }


def test_tail_validation_snapshot_can_be_persisted_on_codegen_without_function_info():
    codegen = _DummyCodegen()
    persisted = persist_x86_16_tail_validation_snapshot(
        function_info=None,
        codegen=codegen,
        stage="postprocess",
        validation={
            "changed": True,
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            "summary_text": "helper_calls: +helper_ping",
        },
    )

    assert persisted == {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
    }
    assert codegen._inertia_tail_validation_snapshot == {
        "postprocess": {
            "changed": True,
            "status": "changed",
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            "summary_text": "helper_calls: +helper_ping",
        }
    }


def test_tail_validation_snapshot_persists_changed_postprocess_verdict_for_later_consumers():
    function_info = {}
    codegen = _DummyCodegen()
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
    }

    persisted = persist_x86_16_tail_validation_snapshot(
        function_info=function_info,
        codegen=codegen,
        stage="postprocess",
        validation=validation,
    )

    assert persisted == validation
    assert function_info == {"x86_16_tail_validation": {"postprocess": validation}}
    assert extract_x86_16_tail_validation_snapshot(function_info) == {"postprocess": validation}
    assert codegen._inertia_tail_validation_snapshot == {"postprocess": validation}


def test_tail_validation_snapshot_persists_compact_stage_entry_in_function_info():
    function_info = {}
    codegen = _DummyCodegen()
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
        "delta": {
            "added": ["CmpGT(big, fat, delta)"],
            "removed": ["CmpLE(old, fat, delta)"],
        },
        "before_summary": {"conditions": tuple(range(256))},
        "after_summary": {"conditions": tuple(range(256, 512))},
    }

    persist_x86_16_tail_validation_snapshot(
        function_info=function_info,
        codegen=codegen,
        stage="postprocess",
        validation=validation,
    )

    assert function_info == {
        "x86_16_tail_validation": {
            "postprocess": {
                "changed": True,
                "status": "changed",
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                "summary_text": "helper_calls: +helper_ping",
                "delta": {
                    "added": ["CmpGT(big, fat, delta)"],
                    "removed": ["CmpLE(old, fat, delta)"],
                },
            }
        }
    }


def test_tail_validation_snapshot_for_function_run_prefers_complete_project_snapshot():
    project = SimpleNamespace(
        _inertia_last_tail_validation_snapshot={
            "structuring": {"status": "stable", "changed": False},
            "postprocess": {"status": "stable", "changed": False},
        }
    )
    function = SimpleNamespace(
        info={
            "x86_16_tail_validation": {
                "structuring": {
                    "status": "changed",
                    "changed": True,
                    "delta": {"added": list(range(1024))},
                }
            }
        }
    )

    snapshot = tail_validation_snapshot_for_function_run(project, function)

    assert snapshot == {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }


def test_tail_validation_snapshot_passed_rejects_non_stable_statuses():
    snapshot = {"postprocess": {"status": "stable"}}
    assert x86_16_tail_validation_snapshot_passed(snapshot, expected_stages=("postprocess",)) is True
    assert (
        x86_16_tail_validation_snapshot_passed({"postprocess": {"status": "changed"}}, expected_stages=("postprocess",))
        is False
    )
    assert (
        x86_16_tail_validation_snapshot_passed({"postprocess": {"status": "unknown"}}, expected_stages=("postprocess",))
        is False
    )
    assert (
        x86_16_tail_validation_snapshot_passed(
            {"postprocess": {"status": "uncollected"}}, expected_stages=("postprocess",)
        )
        is False
    )


def test_tail_validation_result_passed_only_accepts_stable_or_passed_status():
    assert x86_16_tail_validation_result_passed({"status": "stable"}) is True
    assert x86_16_tail_validation_result_passed({"status": "passed"}) is True
    assert x86_16_tail_validation_result_passed({"changed": False}) is True
    assert x86_16_tail_validation_result_passed({"status": "unknown", "changed": False}) is False
    assert x86_16_tail_validation_result_passed({"status": "uncollected", "changed": False}) is False
    assert x86_16_tail_validation_result_passed({"changed": True}) is False


def test_tail_validation_record_summary_aggregates_stage_status():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "A.COD",
                "proc_name": "_a",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
                },
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                },
            },
            {
                "cod_file": "B.COD",
                "proc_name": "_b",
                "proc_kind": "FAR",
            },
        ]
    )

    assert summary["severity"] == "changed"
    assert summary["changed_function_count"] == 1
    assert summary["coverage_count"] == 2
    assert summary["missing_count"] == 2
    assert summary["unknown_count"] == 0
    assert summary["structuring"]["stable_count"] == 1
    assert summary["structuring"]["unknown_count"] == 0
    assert summary["structuring"]["missing_count"] == 1
    assert summary["structuring"]["coverage_count"] == 1
    assert summary["postprocess"]["changed_count"] == 1
    assert summary["postprocess"]["missing_count"] == 1
    assert summary["postprocess"]["coverage_count"] == 1
    assert summary["postprocess"]["mode_counts"] == {"live_out": 1}
    assert summary["postprocess"]["top_verdicts"] == [
        {"verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping", "count": 1}
    ]


def test_tail_validation_surface_summarizes_headline_rates_and_hotspots():
    surface = build_x86_16_tail_validation_surface(
        {
            "severity": "changed",
            "changed_function_count": 2,
            "structuring": {
                "stable_count": 3,
                "changed_count": 1,
                "unknown_count": 1,
                "missing_count": 0,
                "coverage_count": 5,
                "mode_counts": {"live_out": 4},
                "top_verdicts": [
                    {"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}
                ],
            },
            "postprocess": {
                "stable_count": 2,
                "changed_count": 2,
                "unknown_count": 1,
                "missing_count": 0,
                "coverage_count": 5,
                "mode_counts": {"live_out": 4},
                "top_verdicts": [
                    {"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}
                ],
            },
            "changed_functions": [
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_alloc",
                    "proc_kind": "NEAR",
                    "stage": "postprocess",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper",
                },
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_resize",
                    "proc_kind": "NEAR",
                    "stage": "structuring",
                    "verdict": "structuring whole-tail validation [live_out] changed: guard",
                },
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_resize",
                    "proc_kind": "NEAR",
                    "stage": "postprocess",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper",
                },
            ],
        },
        scanned=5,
    )

    assert surface["headline"] == "whole-tail validation failed across 2 functions"
    assert surface["severity"] == "changed"
    assert surface["merge_gate"] is False
    assert surface["changed_stage_total"] == 3
    assert surface["coverage_count"] == 10
    assert surface["missing_stage_total"] == 0
    assert surface["unknown_stage_total"] == 2
    assert surface["stage_rows"] == [
        {
            "stage": "structuring",
            "changed_count": 1,
            "stable_count": 3,
            "unknown_count": 1,
            "missing_count": 0,
            "coverage_count": 5,
            "changed_rate": 0.2,
            "coverage_rate": 1.0,
            "mode_counts": {"live_out": 4},
            "top_verdicts": [{"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}],
        },
        {
            "stage": "postprocess",
            "changed_count": 2,
            "stable_count": 2,
            "unknown_count": 1,
            "missing_count": 0,
            "coverage_count": 5,
            "changed_rate": 0.4,
            "coverage_rate": 1.0,
            "mode_counts": {"live_out": 4},
            "top_verdicts": [{"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}],
        },
    ]
    assert surface["stage_hotspots"] == [
        {
            "stage": "postprocess",
            "changed_count": 2,
            "changed_rate": 0.4,
            "top_verdicts": [{"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}],
        },
        {
            "stage": "structuring",
            "changed_count": 1,
            "changed_rate": 0.2,
            "top_verdicts": [{"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}],
        },
    ]
    assert surface["top_changed_verdicts"] == [
        {"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2},
        {"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1},
    ]
    assert surface["top_changed_functions"] == [
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_resize",
            "proc_kind": "NEAR",
            "stages": ("postprocess", "structuring"),
            "verdicts": (
                "structuring whole-tail validation [live_out] changed: guard",
                "postprocess whole-tail validation [live_out] changed: helper",
            ),
            "changed_stage_count": 2,
        },
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_alloc",
            "proc_kind": "NEAR",
            "stages": ("postprocess",),
            "verdicts": ("postprocess whole-tail validation [live_out] changed: helper",),
            "changed_stage_count": 1,
        },
    ]


def test_tail_validation_surface_groups_changed_observables_into_families():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DoCRT",
                "proc_kind": "NEAR",
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: global_writes: +global:0x7000; segmented_writes: -deref:ds:0x7000",
                    "delta": {
                        "global_writes": {"added": ("global:0x7000",), "removed": ()},
                        "segmented_writes": {"added": (), "removed": ("deref:ds:0x7000",)},
                    },
                },
            },
            {
                "cod_file": "CARR.COD",
                "proc_name": "_SetGear",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp; control_flow_effects: +if:cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                        "control_flow_effects": {"added": ("if:cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "EGAME11.COD",
                "proc_name": "_strcpyFromDot",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "OUTPUT.COD",
                "proc_name": "_hexdump",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: control_flow_effects: +if:cmp",
                    "delta": {
                        "control_flow_effects": {"added": ("if:cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "PLANES3.COD",
                "proc_name": "_CheckIfCanIntercept",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "START1.COD",
                "proc_name": "_waitMdaCgaStatus",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                    },
                },
            },
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=6)

    assert summary["changed_families"] == [
        {
            "family": "control-flow/guard delta",
            "count": 5,
            "function_count": 5,
            "stages": ("structuring",),
            "examples": (
                {"cod_file": "CARR.COD", "proc_name": "_SetGear", "proc_kind": "NEAR"},
                {"cod_file": "EGAME11.COD", "proc_name": "_strcpyFromDot", "proc_kind": "NEAR"},
                {"cod_file": "OUTPUT.COD", "proc_name": "_hexdump", "proc_kind": "NEAR"},
                {"cod_file": "PLANES3.COD", "proc_name": "_CheckIfCanIntercept", "proc_kind": "NEAR"},
                {"cod_file": "START1.COD", "proc_name": "_waitMdaCgaStatus", "proc_kind": "NEAR"},
            ),
        },
        {
            "family": "segmented/global write delta",
            "count": 1,
            "function_count": 1,
            "stages": ("postprocess",),
            "examples": ({"cod_file": "COCKPIT.COD", "proc_name": "_DoCRT", "proc_kind": "NEAR"},),
        },
    ]
    assert surface["changed_families"] == summary["changed_families"]


def test_tail_validation_record_summary_marks_uncollected_separately_from_unknown():
    summary = summarize_x86_16_tail_validation_records(
        [
            {"cod_file": "A.COD", "proc_name": "_a", "proc_kind": "NEAR"},
            {"cod_file": "B.COD", "proc_name": "_b", "proc_kind": "NEAR"},
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=2)

    assert summary["severity"] == "uncollected"
    assert summary["coverage_count"] == 0
    assert summary["missing_count"] == 4
    assert summary["unknown_count"] == 0
    assert summary["function_status_counts"] == {"uncollected": 2}
    assert summary["uncollected_function_count"] == 2
    assert summary["uncollected_functions"] == [
        {
            "cod_file": "A.COD",
            "proc_name": "_a",
            "proc_kind": "NEAR",
            "status": "uncollected",
            "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
            "exit_kind": None,
            "exit_detail": None,
            "tail_validation_uncollected": False,
        },
        {
            "cod_file": "B.COD",
            "proc_name": "_b",
            "proc_kind": "NEAR",
            "status": "uncollected",
            "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
            "exit_kind": None,
            "exit_detail": None,
            "tail_validation_uncollected": False,
        },
    ]
    assert surface["headline"] == "whole-tail validation not collected across 2 functions"
    assert surface["coverage_count"] == 0
    assert surface["missing_stage_total"] == 4
    assert surface["unknown_stage_total"] == 0
    assert surface["function_status_counts"] == {"uncollected": 2}
    assert surface["uncollected_function_count"] == 2
    assert surface["top_uncollected_functions"] == summary["uncollected_functions"]
    assert surface["consistency_issues"] == ()


def test_tail_validation_partial_surface_uses_failed_headline():
    surface = build_x86_16_tail_validation_surface(
        {
            "severity": "partial",
            "changed_function_count": 0,
            "structuring": {"stable_count": 1, "missing_count": 1, "coverage_count": 1},
            "postprocess": {"stable_count": 1, "missing_count": 1, "coverage_count": 1},
            "changed_functions": [],
            "function_status_counts": {"passed": 1, "uncollected": 1},
            "function_statuses": [],
            "uncollected_functions": [{"cod_file": "B.COD", "proc_name": "_b", "proc_kind": "NEAR"}],
            "unknown_functions": [],
        },
        scanned=2,
    )

    assert surface["headline"] == "whole-tail validation failed across 2 functions"


def test_tail_validation_uncollected_records_fall_back_to_function_name_identity():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "LIFE2.EXE",
                "function_name": "sub_119d3",
                "tail_validation_uncollected": True,
                "exit_kind": "timeout",
                "exit_detail": "Timed out after 5s.",
            }
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)

    assert summary["uncollected_functions"] == [
        {
            "cod_file": "LIFE2.EXE",
            "proc_name": "sub_119d3",
            "proc_kind": None,
            "status": "uncollected",
            "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
            "exit_kind": "timeout",
            "exit_detail": "Timed out after 5s.",
            "tail_validation_uncollected": True,
        }
    ]
    assert surface["top_uncollected_functions"] == summary["uncollected_functions"]
    assert surface["function_statuses"] == summary["function_statuses"]


def test_tail_validation_surface_consistency_checker_reports_counter_drift():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "A.COD",
                "proc_name": "_a",
                "proc_kind": "NEAR",
                "structuring": {"changed": False, "mode": "live_out"},
                "postprocess": {"changed": False, "mode": "live_out"},
            }
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    broken_surface = dict(surface)
    broken_surface["coverage_count"] = 0
    broken_surface["function_status_counts"] = {"uncollected": 1}

    issues = check_x86_16_tail_validation_surface_consistency(summary, broken_surface, scanned=1)

    assert "coverage_count: surface=0 summary=2" in issues
    assert "function_status_counts mismatch" in issues


def test_tail_validation_aggregate_reuses_record_fingerprint_cache():
    records = [
        {
            "cod_file": "A.COD",
            "proc_name": "_a",
            "proc_kind": "NEAR",
            "postprocess": {
                "changed": True,
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper",
            },
        }
    ]

    first = build_x86_16_tail_validation_aggregate(records, scanned=1)
    second = build_x86_16_tail_validation_aggregate(records, scanned=1)

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["summary"] == first["summary"]
    assert second["surface"] == first["surface"]


def test_tail_validation_function_accounting_covers_passed_changed_unknown_and_uncollected():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "A.COD",
                "proc_name": "_passed",
                "proc_kind": "NEAR",
                "structuring": {"changed": False, "mode": "live_out"},
                "postprocess": {"changed": False, "mode": "live_out"},
            },
            {
                "cod_file": "B.COD",
                "proc_name": "_changed",
                "proc_kind": "NEAR",
                "structuring": {"changed": False, "mode": "live_out"},
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                },
            },
            {
                "cod_file": "C.COD",
                "proc_name": "_unknown",
                "proc_kind": "NEAR",
                "structuring": {"mode": "live_out"},
                "postprocess": {"changed": False, "mode": "live_out"},
            },
            {
                "cod_file": "D.COD",
                "proc_name": "_uncollected",
                "proc_kind": "NEAR",
                "tail_validation_uncollected": True,
                "exit_kind": "timeout",
            },
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=4)

    assert summary["function_status_counts"] == {
        "changed": 1,
        "passed": 1,
        "uncollected": 1,
        "unknown": 1,
    }
    assert summary["passed_function_count"] == 1
    assert summary["changed_function_count"] == 1
    assert summary["unknown_function_count"] == 1
    assert summary["uncollected_function_count"] == 1
    assert surface["function_status_counts"] == summary["function_status_counts"]
    assert surface["top_unknown_functions"][0]["proc_name"] == "_unknown"
    assert surface["top_uncollected_functions"][0]["proc_name"] == "_uncollected"


def test_tail_validation_aggregate_marks_missing_records_as_uncollected():
    aggregate = build_x86_16_tail_validation_aggregate([], scanned=1)

    assert aggregate["summary"]["severity"] == "uncollected"
    assert aggregate["summary"]["coverage_count"] == 0
    assert aggregate["summary"]["missing_count"] == 2
    assert aggregate["summary"]["function_status_counts"] == {"uncollected": 1}
    assert aggregate["summary"]["uncollected_function_count"] == 1
    assert aggregate["surface"]["function_status_counts"] == {"uncollected": 1}
    assert aggregate["surface"]["uncollected_function_count"] == 1
    assert aggregate["surface"]["headline"] == "whole-tail validation not collected across 1 functions"


def test_tail_validation_baseline_comparison_distinguishes_match_improve_and_regress():
    summary = {
        "changed_functions": [
            {
                "cod_file": "DOSFUNC.COD",
                "proc_name": "_dos_alloc",
                "proc_kind": "NEAR",
                "stage": "postprocess",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper",
            }
        ]
    }
    baseline = build_x86_16_tail_validation_baseline(summary)

    matched = compare_x86_16_tail_validation_baseline(summary, baseline)
    improved = compare_x86_16_tail_validation_baseline({"changed_functions": []}, baseline)
    regressed = compare_x86_16_tail_validation_baseline(
        {
            "changed_functions": [
                *summary["changed_functions"],
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_resize",
                    "proc_kind": "NEAR",
                    "stage": "structuring",
                    "verdict": "structuring whole-tail validation [live_out] changed: guard",
                },
            ]
        },
        baseline,
    )

    assert matched["status"] == "matches_baseline"
    assert improved["status"] == "improved"
    assert regressed["status"] == "regressed"
    assert len(regressed["unexpected"]) == 1


def test_tail_validation_surface_annotation_includes_baseline_counts():
    surface = annotate_x86_16_tail_validation_surface_with_baseline(
        {"headline": "whole-tail validation failed across 1 functions"},
        {
            "status": "regressed",
            "unexpected": [{"proc_name": "_dos_resize"}],
            "missing": [{"proc_name": "_dos_alloc"}],
        },
    )

    assert surface["baseline_status"] == "regressed"
    assert surface["baseline_unexpected_count"] == 1
    assert surface["baseline_missing_count"] == 1


def test_tail_validation_diff_formatter_reports_no_change_cleanly():
    summary = collect_x86_16_tail_validation_summary(_project(), _codegen([], _DummyCodegen()))

    assert (
        format_x86_16_tail_validation_diff(compare_x86_16_tail_validation_summaries(summary, summary))
        == "no observable whole-tail changes"
    )


def test_tail_validation_scope_description_exposes_whole_tail_boundary():
    desc = describe_x86_16_tail_validation_scope()

    assert desc["preferred_mode"] == "live_out"
    assert desc["modes"] == ("coarse", "live_out")
    assert desc["layers"] == ("structuring", "postprocess")
    assert "helper_calls" in desc["observables"]
    assert "control_flow_effects" in desc["observables"]
    assert "temporary names" in desc["ignored"]


def test_tail_validation_verdict_omits_collection_timing_suffix_by_default(monkeypatch):
    monkeypatch.delenv("INERTIA_DEBUG_TIMING", raising=False)

    verdict = build_x86_16_tail_validation_verdict(
        "postprocess",
        {
            "mode": "live_out",
            "changed": True,
            "summary_text": "register_writes: +reg:ax",
            "timings": {
                "collect_before_ms": 1.25,
                "collect_after_ms": 2.5,
                "compare_ms": 0.75,
                "total_ms": 4.5,
            },
        },
    )

    assert "collect=" not in verdict
    assert "compare=" not in verdict
    assert "tail_validation=" not in verdict


def test_tail_validation_verdict_includes_collection_timing_suffix_when_enabled(monkeypatch):
    monkeypatch.setenv("INERTIA_DEBUG_TIMING", "1")

    verdict = build_x86_16_tail_validation_verdict(
        "postprocess",
        {
            "mode": "live_out",
            "changed": True,
            "summary_text": "register_writes: +reg:ax",
            "timings": {
                "collect_before_ms": 1.25,
                "collect_after_ms": 2.5,
                "compare_ms": 0.75,
                "total_ms": 4.5,
            },
        },
    )

    assert "collect=1.2+2.5ms" in verdict
    assert "compare=0.8ms" in verdict
    assert "tail_validation=4.5ms" in verdict


def test_postprocess_codegen_restores_last_clean_state_on_live_out_delta(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=True,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(state="baseline"), project=project)

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "state changed" if after.state == "bad" else "state stable",
        }

    def _bad_pass(codegen_arg):
        codegen_arg.cfunc.state = "bad"
        return True

    def _later_pass(codegen_arg):
        codegen_arg.cfunc.state = "later"
        return True

    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec("_bad_pass", _bad_pass, False),
            postprocess_stage.DecompilerPostprocessPassSpec("_later_pass", _later_pass, False),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_validation_failure_pass == "_bad_pass"
    assert codegen._inertia_postprocess_validation_failure_error == "state changed"
    assert codegen._inertia_last_postprocess_pass is None


def test_postprocess_codegen_keeps_accepted_changes_when_live_out_stays_stable(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=True,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(state="baseline"), project=project)

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "state changed" if after.state == "bad" else "state stable",
        }

    def _first_pass(codegen_arg):
        codegen_arg.cfunc.state = "accepted-1"
        return True

    def _second_pass(codegen_arg):
        codegen_arg.cfunc.state = "accepted-2"
        return True

    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec("_first_pass", _first_pass, False),
            postprocess_stage.DecompilerPostprocessPassSpec("_second_pass", _second_pass, False),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.state == "accepted-2"
    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_validation_failure_pass is None
    assert codegen._inertia_last_postprocess_pass == "_second_pass"


def test_postprocess_codegen_rejects_non_stable_per_pass_validation_status(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=True,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(state="baseline"), project=project)

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, _after):
        if _after.state == "accepted":
            return {
                "changed": False,
                "status": "unknown",
                "summary_text": "validation metadata missing",
            }
        return {
            "changed": False,
            "status": "stable",
            "summary_text": "state stable",
        }

    def _pass(codegen_arg):
        codegen_arg.cfunc.state = "accepted"
        return True

    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (postprocess_stage.DecompilerPostprocessPassSpec("_pass", _pass, False),),
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_validation_failure_pass == "_pass"
    assert codegen._inertia_postprocess_validation_failure_error == "validation metadata missing"


def test_postprocess_codegen_validates_small_function_typed_conditions(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _typed_condition_pass(_project, codegen_arg):
        calls.append("typed")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "condition changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(postprocess_stage, "_apply_typed_conditions_to_codegen_8616", _typed_condition_pass)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["typed"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_apply_typed_conditions_to_codegen_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_codegen_validates_small_function_global_byte_index_loop(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _global_byte_index_pass(_project, codegen_arg):
        calls.append("global-byte")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "guard changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(postprocess_stage, "_materialize_global_byte_index_sum_loop_8616", _global_byte_index_pass)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["global-byte"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_global_byte_index_sum_loop_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_codegen_validates_small_function_nested_stack_counter(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _nested_counter_pass(_project, codegen_arg):
        calls.append("nested-counter")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "loop guard changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(
        postprocess_stage,
        "_materialize_nested_stack_counter_accumulator_loop_8616",
        _nested_counter_pass,
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["nested-counter"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_nested_stack_counter_accumulator_loop_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_codegen_continues_after_stack_arg_accumulator_validation_delta(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _stack_arg_pass(_project, codegen_arg):
        calls.append("stack-arg")
        codegen_arg.cfunc.state = "bad"
        return True

    def _later_pass(codegen_arg):
        calls.append("later")
        assert codegen_arg.cfunc.state == "baseline"
        return False

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "stack arg loop changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec("_later_after_stack_arg_reject_8616", _later_pass, False),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_materialize_stack_arg_accumulator_loop_8616", _stack_arg_pass)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["stack-arg", "later"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_stack_arg_accumulator_loop_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_mandatory_validation_covers_late_semantic_rewriters():
    expected = {
        "_classify_return_shape_8616",
        "_dead_code_elimination_after_callsite_stack_arguments_8616",
        "_dead_code_elimination_after_flag_prune_8616",
        "_dead_code_elimination_after_stable_stack_final_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
        "_materialize_direct_stack_incdec_instructions_8616",
        "_materialize_direct_stack_incdec_instructions_final_8616",
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
        "_materialize_stable_stack_semantics_bootstrap_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_materialize_stable_stack_semantics_final_8616",
        "_materialize_stable_stack_semantics_postprocess_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_lower_runtime_ss_segment_helpers_to_stack_final_8616",
        "_lower_stable_ss_stack_accesses_8616",
        "_normalize_call_target_names_8616",
        "_normalize_recovered_call_target_names_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_overwritten_flag_assignments_8616",
        "_prune_return_address_stack_arguments_8616",
        "_prune_unused_flag_assignments_8616",
        "_recover_missing_direct_calls_final_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_rerun_stack_lowering_consumers_after_calls_8616",
        "_simplify_structured_expressions_8616",
        "_simplify_structured_expressions_after_call_stack_lowering_8616",
        "_simplify_structured_expressions_after_final_call_materialization_8616",
        "_simplify_structured_expressions_after_stack_lowering_8616",
    }
    expected |= postprocess_stage._OPTIMIZATION_VALIDATION_PASS_NAMES_8616

    assert (
        postprocess_stage._OPTIMIZATION_VALIDATION_PASS_NAMES_8616
        <= postprocess_stage._LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
    )
    assert expected <= postprocess_stage._MANDATORY_VALIDATION_PASS_NAMES_8616
    assert expected <= postprocess_stage._PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616


def test_postprocess_codegen_validates_small_function_after_ss_callsite_args(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _callsite_pass(_project, codegen_arg):
        calls.append("callsite")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "callsite changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
                _callsite_pass,
                True,
            ),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_postprocess_optimization_enabled_8616", lambda: False)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["callsite"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_callsite_stack_arguments_after_ss_lowering_8616" in (
        codegen._inertia_postprocess_rejected_passes
    )


def test_postprocess_codegen_skips_heapsort_debug_regeneration_without_env(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x10970, state="baseline"),
        project=project,
    )
    calls: list[str] = []

    def _apply_word_globals(_project, _codegen):
        return set()

    def _pass(_project, codegen_arg):
        codegen_arg.cfunc.state = "after-callsite"
        return True

    monkeypatch.delenv("INERTIA_DEBUG_HEAPSORT_CALLS", raising=False)
    monkeypatch.delenv("INERTIA_DEBUG_STACK_NOISE", raising=False)
    monkeypatch.setattr(postprocess_stage._globals, "_coalesce_word_global_loads_8616", _apply_word_globals)
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_materialize_callsite_stack_arguments_8616",
                _pass,
                True,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec("_later_pass", lambda _codegen: False, False),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regen") or True
    )
    monkeypatch.setattr(
        postprocess_stage, "_debug_heap_call_lines_8616", lambda *_args, **_kwargs: calls.append("heap")
    )
    monkeypatch.setattr(postprocess_stage, "_debug_stack_noise_8616", lambda *_args, **_kwargs: calls.append("noise"))

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is True
    assert calls == ["regen"]


def test_postprocess_codegen_does_not_regenerate_when_no_pass_changed(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=False,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234), project=project, text="int f(void) { return 0; }")
    calls: list[str] = []
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )

    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(
        postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regen") or True
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []


def test_postprocess_codegen_refuses_large_function_semantic_pass_without_local_validation(monkeypatch):
    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return SimpleNamespace(block_addrs_set=tuple(range(40)), info={})

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234), project=project, text="int f(void) { return 0; }")
    calls: list[str] = []
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _semantic_pass(_codegen):
        calls.append("semantic")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_rewrite_decoded_jcc_conditions_8616",
                _semantic_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert {
        "pass": "_rewrite_decoded_jcc_conditions_8616",
        "reason": postprocess_stage._PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
    } in codegen._inertia_postprocess_refused_passes_8616


def test_postprocess_codegen_refuses_large_function_final_simplifier_without_local_validation(monkeypatch):
    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return SimpleNamespace(block_addrs_set=tuple(range(40)), info={})

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234), project=project, text="int f(void) { return 0; }")
    calls: list[str] = []
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _simplify_pass(_codegen):
        calls.append("simplify")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_simplify_structured_expressions_after_final_call_materialization_8616",
                _simplify_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert {
        "pass": "_simplify_structured_expressions_after_final_call_materialization_8616",
        "reason": postprocess_stage._PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
    } in codegen._inertia_postprocess_refused_passes_8616


def test_postprocess_codegen_refuses_large_function_annotations_without_local_validation(monkeypatch):
    function_record = SimpleNamespace(
        block_addrs_set=tuple(range(40)),
        info={"before": True},
        prototype="old-prototype",
    )

    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return function_record

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions(), labels={0x7000: "old_label"}),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _annotation_pass(_project, codegen_arg):
        calls.append("annotation")
        function_record.info["x86_16_annotations"] = {"stack_vars": {0: {"name": "local_0"}}}
        function_record.prototype = "new-prototype"
        _project.kb.labels[0x7000] = "new_label"
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "condition changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_apply_annotations_8616",
                _annotation_pass,
                True,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert codegen.cfunc.state == "baseline"
    assert function_record.info == {"before": True}
    assert function_record.prototype == "old-prototype"
    assert project.kb.labels == {0x7000: "old_label"}
    assert codegen._inertia_postprocess_validation_failed is False
    assert {
        "pass": "_apply_annotations_8616",
        "reason": postprocess_stage._PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
    } in codegen._inertia_postprocess_refused_passes_8616


def test_postprocess_force_validates_large_function_return_address_prune(monkeypatch):
    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return SimpleNamespace(block_addrs_set=tuple(range(80)), info={})

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []
    monkeypatch.setenv("INERTIA_FORCE_PER_PASS_TV", "1")
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _bad_return_address_prune(_project, codegen_arg):
        calls.append("return-prune")
        codegen_arg.cfunc.state = "bad"
        return True

    def _noop_pointer_memory(_project, _codegen_arg):
        calls.append("pointer-memory")
        return False

    def _bad_annotation(_project, codegen_arg):
        calls.append("annotation")
        codegen_arg.cfunc.state = "bad_annotation"
        return True

    def _bad_dce(_codegen_arg):
        calls.append("dce")
        _codegen_arg.cfunc.state = "bad_dce"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(before, after):
        return {
            "changed": before.state != after.state,
            "summary_text": "state changed" if before.state != after.state else "state stable",
        }

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_prune_return_address_stack_arguments_8616",
                _bad_return_address_prune,
                True,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_apply_annotations_8616",
                _bad_annotation,
                True,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec(
                "optimization:dce",
                _bad_dce,
                False,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_materialize_pointer_memory_idioms_8616",
                _noop_pointer_memory,
                True,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "x86_16_tail_validation_result_passed", lambda result: not result["changed"])
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["return-prune", "annotation", "dce", "pointer-memory"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_rejected_passes == (
        "_prune_return_address_stack_arguments_8616",
        "_apply_annotations_8616",
        "optimization:dce",
    )


def test_postprocess_codegen_validates_small_function_annotations(monkeypatch):
    function_record = SimpleNamespace(
        block_addrs_set=(0x1234,),
        info={"before": True},
        prototype="old-prototype",
    )

    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return function_record

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions(), labels={0x7000: "old_label"}),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _annotation_pass(_project, codegen_arg):
        calls.append("annotation")
        function_record.info["x86_16_annotations"] = {"stack_vars": {0: {"name": "local_0"}}}
        function_record.prototype = "new-prototype"
        _project.kb.labels[0x7000] = "new_label"
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "condition changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_apply_annotations_8616",
                _annotation_pass,
                True,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["annotation"]
    assert codegen.cfunc.state == "baseline"
    assert function_record.info == {"before": True}
    assert function_record.prototype == "old-prototype"
    assert project.kb.labels == {0x7000: "old_label"}
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_apply_annotations_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_complexity_uses_current_function_cached_byte_count():
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = SimpleNamespace(
        _inertia_current_function_8616=SimpleNamespace(
            info={
                "_inertia_function_complexity": {
                    "blocks": 37,
                    "bytes": 379,
                    "source": "bounded_local_blocks",
                }
            }
        )
    )

    complexity = postprocess_stage._postprocess_function_complexity_8616(project, codegen, 0x1000)

    assert complexity.block_count == 37
    assert complexity.byte_count == 379
    assert complexity.source == "current_function:bounded_local_blocks"
    assert complexity.is_expensive_for_local_validation is True


def test_postprocess_refuses_structuring_tail_validation_baseline_without_summary_equivalence_key():
    summary = object()
    codegen = SimpleNamespace(
        _inertia_structuring_tail_validation_artifacts_8616={
            "mode": "live_out",
            "after_fingerprint": ("fp",),
            "after_summary": summary,
        }
    )

    reused = postprocess_stage._structuring_tail_validation_baseline_summary_8616(
        codegen,
        mode="live_out",
        before_fingerprint=("fp",),
    )
    refused = postprocess_stage._structuring_tail_validation_baseline_summary_8616(
        codegen,
        mode="live_out",
        before_fingerprint=("different",),
    )

    assert reused is None
    assert refused is None
    assert codegen._inertia_tail_validation_structuring_baseline_reuse_refused_8616 == 2


def test_postprocess_codegen_refuses_byte_heavy_function_semantic_pass_without_local_validation(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1234),
        project=project,
        text="int f(void) { return 0; }",
        _inertia_current_function_8616=SimpleNamespace(
            info={
                "_inertia_function_complexity": {
                    "blocks": 37,
                    "bytes": 700,
                    "source": "bounded_local_blocks",
                }
            }
        ),
    )
    calls: list[str] = []
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_nested_stack_counter_accumulator_loop_8616",
                "_materialize_stack_arg_accumulator_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _semantic_pass(_codegen):
        calls.append("semantic")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_rewrite_decoded_jcc_conditions_8616",
                _semantic_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert codegen._inertia_postprocess_function_complexity_8616 == {
        "blocks": 37,
        "bytes": 700,
        "source": "current_function:bounded_local_blocks",
        "expensive": True,
    }


def test_tail_validation_compare_summaries_treats_negated_compare_and_inverted_compare_as_stable():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("Not(CmpLE(reg:ax,stack:+0x6))",),
        control_flow_effects=("if:Not(CmpLE(reg:ax,stack:+0x6))",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpGT(reg:ax,stack:+0x6)",),
        control_flow_effects=("if:CmpGT(reg:ax,stack:+0x6)",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_normalizes_void_return_loop_exit_guard_to_loop_condition():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_cond = CBinaryOp(
        "CmpLE",
        _reg(project, "ax", before_codegen),
        _stack(-4, before_codegen, name="goal"),
        codegen=before_codegen,
    )
    after_cond = CBinaryOp(
        "CmpGT",
        _reg(project, "ax", after_codegen),
        _stack(-4, after_codegen, name="goal"),
        codegen=after_codegen,
    )
    before = _codegen(
        [CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen)],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements(
                    [
                        CIfElse(
                            [
                                (
                                    after_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                )
                            ],
                            else_node=None,
                            codegen=after_codegen,
                        )
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_normalizes_void_return_loop_exit_guard_after_call_feeder(monkeypatch):
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_call = CFunctionCall("clock", None, [], codegen=before_codegen)
    after_call = CFunctionCall("clock", None, [], codegen=after_codegen)
    before_cond = CBinaryOp(
        "CmpLE",
        before_call,
        _stack(-4, before_codegen, name="goal"),
        codegen=before_codegen,
    )
    feeder = CAssignment(_reg(project, "ax", after_codegen, var_name="t"), after_call, codegen=after_codegen)
    after_cond = CBinaryOp(
        "CmpGT",
        _reg(project, "ax", after_codegen, var_name="t"),
        _stack(-4, after_codegen, name="goal"),
        codegen=after_codegen,
    )
    before = _codegen(
        [CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen)],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements(
                    [
                        feeder,
                        CIfElse(
                            [
                                (
                                    after_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                )
                            ],
                            else_node=None,
                            codegen=after_codegen,
                        ),
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "build_x86_16_contextual_condition_fingerprints",
        lambda _root, _project: {id(after_cond): "CmpGT(call:clock(),stack_slot:SS:BP-0x4:size2)"},
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_normalizes_multi_branch_void_return_loop_exit_guard(monkeypatch):
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_cond = CBinaryOp(
        "CmpLE",
        CFunctionCall("clock", None, [], codegen=before_codegen),
        _stack(-4, before_codegen, name="goal"),
        codegen=before_codegen,
    )
    first_exit_cond = CBinaryOp(
        "CmpGT",
        _reg(project, "dx", after_codegen),
        _stack(-2, after_codegen, name="goal_hi"),
        codegen=after_codegen,
    )
    second_exit_cond = CBinaryOp(
        "CmpGT",
        _reg(project, "ax", after_codegen),
        _stack(-4, after_codegen, name="goal_lo"),
        codegen=after_codegen,
    )
    before = _codegen(
        [CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen)],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements(
                    [
                        CAssignment(
                            _reg(project, "ax", after_codegen, var_name="t"),
                            CFunctionCall("clock", None, [], codegen=after_codegen),
                            codegen=after_codegen,
                        ),
                        CIfElse(
                            [
                                (
                                    first_exit_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                ),
                                (
                                    second_exit_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                ),
                            ],
                            else_node=None,
                            codegen=after_codegen,
                        ),
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "build_x86_16_contextual_condition_fingerprints",
        lambda _root, _project: {id(first_exit_cond): "CmpGT(call:clock(),stack_slot:SS:BP-0x4:size2)"},
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
    assert diff["status"] == "stable"
