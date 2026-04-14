from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16 import decompiler_postprocess_stage as postprocess_stage
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation import (
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
)


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


def _ds_deref(project, linear: int, codegen):
    ds = _reg(project, "ds", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp("Add", CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen), _const(linear, codegen), codegen=codegen),
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
            CReturn(CFunctionCall("print_dos_string", None, [_const(0x80, codegen_stub)], codegen=codegen_stub), codegen=codegen_stub),
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


def test_tail_validation_diff_ignores_variable_name_churn():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(_reg(project, "ax", before_codegen, var_name="tmp_a"), _const(1, before_codegen), codegen=before_codegen),
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
                CAssignment(_reg(project, "ax", after_codegen, var_name="tmp_b"), _const(1, after_codegen), codegen=after_codegen),
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
                CAssignment(_reg(project, "cx", after_codegen, var_name="tmp_bool"), _const(1, after_codegen), codegen=after_codegen),
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
                CAssignment(_reg(project, "cx", after_codegen, var_name="tmp_bool"), _const(1, after_codegen), codegen=after_codegen),
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
                    [(
                        CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen),
                        CStatements([], codegen=before_codegen),
                    )],
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
                    [(
                        _reg(project, "ax", after_codegen),
                        CStatements([], codegen=after_codegen),
                    )],
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
    first = build_x86_16_validation_cache_descriptor("tail_validation.test", {"stage": "postprocess", "mode": "live_out"})
    second = build_x86_16_validation_cache_descriptor("tail_validation.test", {"stage": "postprocess", "mode": "live_out"})

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
        [CFunctionCall("helper_ping", None, [], codegen=after_codegen), CReturn(_const(1, after_codegen), codegen=after_codegen)],
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
    assert before.conditions == ("Sub(reg:ax,const:2)",)
    assert after.conditions == ("Sub(reg:ax,const:2)",)


def test_tail_validation_normalizes_zero_flag_compare_projection_noise():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before_cond = CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen)
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
        _codegen([CIfElse([(before_cond, CStatements([], codegen=before_codegen))], codegen=before_codegen)], before_codegen),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CIfElse([(after_cond, CStatements([], codegen=after_codegen))], codegen=after_codegen)], after_codegen),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("Sub(reg:ax,const:2)",)
    assert after.conditions == ("Sub(reg:ax,const:2)",)


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
    before_predicate = CBinaryOp("CmpEQ", CBinaryOp("Add", before_word, _const(1, before_codegen), codegen=before_codegen), _const(0, before_codegen), codegen=before_codegen)
    after_predicate = CBinaryOp("CmpEQ", CBinaryOp("Add", after_word, _const(1, after_codegen), codegen=after_codegen), _const(0, after_codegen), codegen=after_codegen)

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
                    [(
                        CUnaryOp(
                            "Not",
                            CBinaryOp(
                                "CmpEQ",
                                CBinaryOp("And", _reg(project, "flags", before_codegen), _const(64, before_codegen), codegen=before_codegen),
                                _const(0, before_codegen),
                                codegen=before_codegen,
                            ),
                            codegen=before_codegen,
                        ),
                        CStatements([], codegen=before_codegen),
                    )],
                    codegen=before_codegen,
                ),
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CIfElse([(after_predicate, CStatements([], codegen=after_codegen))], codegen=after_codegen)], after_codegen),
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
                CAssignment(_ds_deref(project, 0x7002, before_codegen), _const(0x34, before_codegen), codegen=before_codegen),
                CAssignment(_ds_deref(project, 0x7003, before_codegen), _const(0x12, before_codegen), codegen=before_codegen),
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
        _codegen([CIfElse([(before_condition, CStatements([], codegen=before_codegen))], None, codegen=before_codegen)], before_codegen),
        mode="live_out",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CIfElse([(after_condition, CStatements([], codegen=after_codegen))], None, codegen=after_codegen)], after_codegen),
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
        "mode": "live_out",
        "summary_text": "helper_calls: +helper_ping",
    }

    verdict = build_x86_16_tail_validation_verdict("postprocess", validation)

    assert verdict == "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping"


def test_tail_validation_snapshot_extracts_known_stage_fields():
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "structuring": {
                    "changed": False,
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
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
    }
    assert codegen._inertia_tail_validation_snapshot == {
        "postprocess": {
            "changed": True,
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
    assert extract_x86_16_tail_validation_snapshot(function_info) == {"postprocess": validation}
    assert codegen._inertia_tail_validation_snapshot == {"postprocess": validation}


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
                "top_verdicts": [{"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}],
            },
            "postprocess": {
                "stable_count": 2,
                "changed_count": 2,
                "unknown_count": 1,
                "missing_count": 0,
                "coverage_count": 5,
                "mode_counts": {"live_out": 4},
                "top_verdicts": [{"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}],
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

    assert surface["headline"] == "whole-tail validation changed in 2 functions"
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
        {"headline": "whole-tail validation changed in 1 functions"},
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


def test_tail_validation_verdict_includes_collection_timing_suffix():
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

    monkeypatch.setattr(postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set())
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

    monkeypatch.setattr(postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set())
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

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.state == "accepted-2"
    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_validation_failure_pass is None
    assert codegen._inertia_last_postprocess_pass == "_second_pass"
