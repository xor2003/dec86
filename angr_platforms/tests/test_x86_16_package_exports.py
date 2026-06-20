from __future__ import annotations

from types import SimpleNamespace

import angr_platforms.X86_16 as x8616
from angr.analyses.calling_convention import calling_convention as _cc_analysis
from angr.analyses.calling_convention import fact_collector as _cc_fact_collector
from angr.analyses.calling_convention import utils as _cc_utils
from angr.analyses.decompiler.decompiler import Decompiler
from angr_platforms.X86_16 import (
    bootstrap,
    decompiler_postprocess_inventory,
    decompiler_postprocess_stage,
    decompiler_structuring_stage,
    recovery_confidence,
    tail_validation,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16


def test_x86_16_package_exports_source_backends():
    assert "cod_extract" in x8616.__all__
    assert "annotations" in x8616.__all__
    assert "apply_x86_16_metadata_annotations" in x8616.__all__
    assert "corpus_scan" in x8616.__all__
    assert "cod_source_rewrites" in x8616.__all__
    assert "COD_SOURCE_REWRITE_REGISTRY" in x8616.__all__
    assert "apply_cod_source_rewrites" in x8616.__all__
    assert "rewrite_cod_source_stage" in x8616.__all__
    assert "cod_source_rewrite_description" in x8616.__all__
    assert "cod_source_rewrite_names" in x8616.__all__
    assert "cod_source_rewrite_summary" in x8616.__all__
    assert "get_cod_source_rewrite_spec" in x8616.__all__
    assert "compat" in x8616.__all__
    assert "bootstrap" in x8616.__all__
    assert "apply_x86_16_compatibility" in x8616.__all__
    assert "stack_compat" in x8616.__all__
    assert "apply_x86_16_stack_compatibility" in x8616.__all__
    assert "apply_x86_16_bootstrap" in x8616.__all__
    assert "apply_x86_16_decompiler_postprocess" in x8616.__all__
    assert "decompiler_postprocess_inventory" in x8616.__all__
    assert "decompiler_postprocess_utils" in x8616.__all__
    assert "decompiler_postprocess_simplify" in x8616.__all__
    assert "decompiler_structuring_stage" in x8616.__all__
    assert "decompiler_postprocess_flags" in x8616.__all__
    assert "describe_x86_16_decompiler_postprocess_inventory_8616" in x8616.__all__
    assert "validate_x86_16_decompiler_postprocess_inventory_8616" in x8616.__all__
    assert "DecompilerPostprocessPassInventoryItem" in x8616.__all__
    assert "DecompilerPostprocessPassKind8616" in x8616.__all__
    assert "DecompilerPostprocessPassInventoryViolation" in x8616.__all__
    assert "calling_convention_compat" in x8616.__all__
    assert "decompiler_return_compat" in x8616.__all__
    assert "describe_x86_16_decompiler_postprocess_stage" in x8616.__all__
    assert "DecompilerPostprocessPassSpec" in x8616.__all__
    assert "patch_dirty" in x8616.__all__
    assert "typehoon_compat" in x8616.__all__
    assert "alias_model" in x8616.__all__
    assert "alias_domains" in x8616.__all__
    assert "alias_state" in x8616.__all__
    assert "alias_transfer" in x8616.__all__
    assert "widening_alias" in x8616.__all__
    assert "widening_model" in x8616.__all__
    assert "validation_manifest" in x8616.__all__
    assert "readability_set" in x8616.__all__
    assert "readability_goals" in x8616.__all__
    assert "rank_readability_goal_queue" in x8616.__all__
    assert "summarize_readability_focus" in x8616.__all__
    assert "correctness_goals" in x8616.__all__
    assert "milestone_report" in x8616.__all__
    assert "render_x86_16_tail_validation_console_summary" in x8616.__all__
    assert "recovery_manifest" in x8616.__all__
    assert "describe_x86_16_source_backed_rewrite_status" in x8616.__all__
    assert "describe_x86_16_source_backed_rewrite_debt" in x8616.__all__
    assert "describe_x86_16_alias_recovery_api" in x8616.__all__
    assert "describe_x86_16_interrupt_api_surface" in x8616.__all__
    assert "describe_x86_16_interrupt_core_surface" in x8616.__all__
    assert "describe_x86_16_interrupt_lowering_boundary" in x8616.__all__
    assert "describe_x86_16_instruction_metadata_surface" in x8616.__all__
    assert "describe_x86_16_decode_width_matrix" in x8616.__all__
    assert "describe_x86_16_mixed_width_extension_surface" in x8616.__all__
    assert "describe_x86_16_mixed_width_instruction_surface" in x8616.__all__
    assert "describe_x86_16_validation_triage" in x8616.__all__
    assert "describe_x86_16_projection_cleanup_rules" in x8616.__all__
    assert "describe_x86_16_readability_goals" in x8616.__all__
    assert "describe_x86_16_correctness_goals" in x8616.__all__
    assert "describe_x86_16_widening_pipeline" in x8616.__all__
    assert "describe_x86_16_object_recovery_focus" in x8616.__all__
    assert "describe_x86_16_recovery_layers" in x8616.__all__
    assert "describe_x86_16_recovery_confidence_axes" in x8616.__all__
    assert "tail_validation" in x8616.__all__
    assert "X86_16TailValidationSummary" in x8616.__all__
    assert "X86_16ValidationCacheDescriptor" in x8616.__all__
    assert "build_x86_16_tail_validation_aggregate" in x8616.__all__
    assert "build_x86_16_tail_validation_cached_result" in x8616.__all__
    assert "build_x86_16_tail_validation_surface" in x8616.__all__
    assert "build_x86_16_tail_validation_verdict" in x8616.__all__
    assert "check_x86_16_tail_validation_surface_consistency" in x8616.__all__
    assert "build_x86_16_validation_cache_descriptor" in x8616.__all__
    assert "persist_x86_16_tail_validation_snapshot" in x8616.__all__
    assert "extract_x86_16_tail_validation_snapshot" in x8616.__all__
    assert "x86_16_tail_validation_snapshot_passed" in x8616.__all__
    assert "fingerprint_x86_16_tail_validation_boundary" in x8616.__all__
    assert "collect_x86_16_tail_validation_summary" in x8616.__all__
    assert "compare_x86_16_tail_validation_summaries" in x8616.__all__
    assert "format_x86_16_tail_validation_diff" in x8616.__all__
    assert "resolve_x86_16_validation_cached_artifact" in x8616.__all__
    assert "summarize_x86_16_tail_validation_records" in x8616.__all__
    assert "describe_x86_16_tail_validation_scope" in x8616.__all__
    assert "decompiler_postprocess" in x8616.__all__
    assert "decompiler_postprocess_calls" in x8616.__all__
    assert "decompiler_postprocess_globals" in x8616.__all__
    assert "decompiler_postprocess_utils" in x8616.__all__
    assert "decompiler_postprocess_simplify" in x8616.__all__
    assert "decompiler_postprocess_flags" in x8616.__all__
    assert "address_ir" in x8616.__all__
    assert "callsite_summary" in x8616.__all__
    assert "function_summary" in x8616.__all__
    assert "apply_x86_16_decompiler_return_compatibility" in x8616.__all__
    assert "apply_x86_16_calling_convention_compatibility" in x8616.__all__
    assert "decompiler_postprocess_stage" in x8616.__all__


def test_x86_16_decompiler_postprocess_hook_is_idempotent():
    original = Decompiler._decompile

    x8616.apply_x86_16_decompiler_postprocess()
    x8616.apply_x86_16_decompiler_postprocess()

    assert Decompiler._decompile.__name__ == "_decompile_8616"
    assert Decompiler._decompile is not original or original.__name__ == "_decompile_8616"


def test_x86_16_bootstrap_hook_is_idempotent():
    original = Decompiler._decompile

    x8616.apply_x86_16_bootstrap()
    x8616.apply_x86_16_bootstrap()

    assert Decompiler._decompile.__name__ == "_decompile_8616"
    assert Decompiler._decompile is not original or original.__name__ == "_decompile_8616"


def test_x86_16_calling_convention_compatibility_patches_register_sanity():
    x8616.apply_x86_16_calling_convention_compatibility()

    assert _cc_utils.is_sane_register_variable.__name__ == "_is_sane_register_variable_8616"
    assert _cc_analysis.is_sane_register_variable.__name__ == "_is_sane_register_variable_8616"
    assert _cc_fact_collector.is_sane_register_variable.__name__ == "_is_sane_register_variable_8616"
    assert _cc_utils.is_sane_register_variable(Arch86_16(), 0, 2)


def test_x86_16_decompiler_postprocess_registry_order():
    pass_names = [spec.name for spec in decompiler_postprocess_stage.DECOMPILER_POSTPROCESS_PASSES]

    assert pass_names[:6] == [
        "_apply_word_global_types_8616",
        "_apply_annotations_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_return_address_stack_arguments_8616",
        "_prune_unused_unnamed_memory_declarations_8616",
    ]
    assert pass_names.index("_rewrite_decoded_jcc_conditions_8616") < pass_names.index(
        "_rewrite_decoded_jcc_conditions_after_calls_8616"
    )
    assert pass_names.index("_attach_callsite_summaries_8616") < pass_names.index(
        "_materialize_callsite_stack_arguments_8616"
    )
    assert pass_names.index("_classify_return_shape_8616") < pass_names.index("_prune_void_function_return_values_8616")
    assert pass_names[-1] == "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616"


def test_x86_16_decompiler_postprocess_registry_factory_shape():
    rebuilt = decompiler_postprocess_stage._build_decompiler_postprocess_passes()
    assert rebuilt == decompiler_postprocess_stage.DECOMPILER_POSTPROCESS_PASSES


def test_x86_16_decompiler_postprocess_stage_description():
    assert decompiler_postprocess_stage.describe_x86_16_decompiler_postprocess_stage() == tuple(
        (spec.name, spec.needs_project) for spec in decompiler_postprocess_stage.DECOMPILER_POSTPROCESS_PASSES
    )


def test_x86_16_decompiler_postprocess_stage_exports():
    assert "DecompilerPostprocessPassSpec" in decompiler_postprocess_stage.__all__
    assert "DECOMPILER_POSTPROCESS_PASSES" in decompiler_postprocess_stage.__all__
    assert "describe_x86_16_decompiler_postprocess_stage" in decompiler_postprocess_stage.__all__
    assert "apply_x86_16_decompiler_postprocess" in decompiler_postprocess_stage.__all__


def test_x86_16_decompiler_postprocess_inventory_exports():
    assert "DecompilerPostprocessPassInventoryItem" in decompiler_postprocess_inventory.__all__
    assert "DecompilerPostprocessPassKind8616" in decompiler_postprocess_inventory.__all__
    assert "DecompilerPostprocessPassInventoryViolation" in decompiler_postprocess_inventory.__all__
    assert "describe_x86_16_decompiler_postprocess_inventory_8616" in decompiler_postprocess_inventory.__all__
    assert "validate_x86_16_decompiler_postprocess_inventory_8616" in decompiler_postprocess_inventory.__all__


def test_x86_16_decompiler_postprocess_inventory_contract_is_clean():
    assert decompiler_postprocess_inventory.validate_x86_16_decompiler_postprocess_inventory_8616() == ()


def test_x86_16_decompiler_postprocess_inventory_contract_reports_violations(monkeypatch):
    item_cls = decompiler_postprocess_inventory.DecompilerPostprocessPassInventoryItem
    kind = decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616
    fake_inventory = (
        item_cls(
            name="_materialize_bad_8616",
            kind=kind.CLEANUP,
            owner="postprocess orchestration/cleanup",
        ),
        item_cls(
            name="_semantic_generic_owner_8616",
            kind=kind.SEMANTIC_MATERIALIZATION,
            owner="Step 4: classified semantic materialization debt pending owner split",
        ),
        item_cls(
            name="_semantic_generic_owner_8616",
            kind=kind.SEMANTIC_MATERIALIZATION,
            owner="Step 4: classified semantic materialization debt pending owner split",
        ),
        item_cls(
            name="_cleanup_with_counters_8616",
            kind=kind.CLEANUP,
            owner="postprocess orchestration/cleanup",
            required_evidence_counters=("raw_fact_count",),
        ),
    )
    monkeypatch.setattr(
        decompiler_postprocess_inventory,
        "describe_x86_16_decompiler_postprocess_inventory_8616",
        lambda: fake_inventory,
    )

    violations = decompiler_postprocess_inventory.validate_x86_16_decompiler_postprocess_inventory_8616()

    assert {(item.name, item.reason) for item in violations} == {
        ("_materialize_bad_8616", "semantic-looking-name-not-semantic"),
        ("_semantic_generic_owner_8616", "semantic-pass-missing-evidence-counters"),
        ("_semantic_generic_owner_8616", "semantic-pass-generic-owner"),
        ("_semantic_generic_owner_8616", "duplicate-pass-name"),
        ("_cleanup_with_counters_8616", "nonsemantic-pass-has-evidence-counters"),
    }


def test_x86_16_decompiler_postprocess_inventory_classifies_condition_debt():
    inventory = {
        item.name: item for item in decompiler_postprocess_inventory.describe_x86_16_decompiler_postprocess_inventory_8616()
    }
    semantic = decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION

    assert inventory["_apply_typed_conditions_to_codegen_8616"].kind is semantic
    assert "ConditionIR" in inventory["_apply_typed_conditions_to_codegen_8616"].owner
    assert inventory["_rewrite_decoded_jcc_conditions_8616"].kind is semantic
    assert "structuring" in inventory["_rewrite_decoded_jcc_conditions_8616"].owner
    assert inventory["_rewrite_decoded_jcc_conditions_after_calls_8616"].kind is semantic
    assert inventory["_rewrite_flag_condition_pairs_8616"].kind is semantic
    assert "condition semantics" in inventory["_rewrite_flag_condition_pairs_8616"].owner
    assert inventory["_rewrite_flag_bit_value_uses_8616"].kind is semantic
    assert inventory["_fix_interval_guard_conditions_8616"].kind is semantic


def test_x86_16_decompiler_postprocess_inventory_fails_closed_for_semantic_names():
    inventory = tuple(decompiler_postprocess_inventory.describe_x86_16_decompiler_postprocess_inventory_8616())
    semantic = decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION
    semantic_prefixes = (
        "_materialize_",
        "_recover_",
        "_repair_",
        "_rewrite_flag_",
        "_fix_interval_guard_",
    )

    leaked = [item.name for item in inventory if item.name.startswith(semantic_prefixes) and item.kind is not semantic]

    assert leaked == []


def test_x86_16_decompiler_postprocess_inventory_routes_semantic_debt_to_plan_steps():
    inventory = tuple(decompiler_postprocess_inventory.describe_x86_16_decompiler_postprocess_inventory_8616())
    semantic = decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION
    generic_owners = [
        item.name
        for item in inventory
        if item.kind is semantic
        and (
            "owning semantic/alias/lowering/structuring layer" in item.owner
            or item.owner.startswith("Step 4:")
        )
    ]

    assert generic_owners == []
    owners_by_name = {item.name: item.owner for item in inventory}
    assert owners_by_name["_materialize_stable_stack_semantics_early_8616"].startswith("Step 5:")
    assert owners_by_name["_materialize_direct_global_incdec_instructions_8616"].startswith("Step 7:")
    assert owners_by_name["_materialize_callsite_stack_arguments_8616"].startswith("Step 9:")
    assert owners_by_name["_materialize_cfg_selector_return_branches_8616"].startswith("Step 6:")


def test_x86_16_decompiler_postprocess_inventory_requires_semantic_evidence_counters():
    inventory = tuple(decompiler_postprocess_inventory.describe_x86_16_decompiler_postprocess_inventory_8616())
    semantic = decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION
    required = (
        "raw_fact_count",
        "normalized_fact_count",
        "classified_fact_count",
        "materialized_count",
        "failure_count",
    )

    semantic_without_counters = [
        item.name for item in inventory if item.kind is semantic and item.required_evidence_counters != required
    ]
    nonsemantic_with_counters = [
        item.name for item in inventory if item.kind is not semantic and item.required_evidence_counters
    ]

    assert semantic_without_counters == []
    assert nonsemantic_with_counters == []


def test_x86_16_decompiler_postprocess_inventory_keeps_cleanup_categories_distinct():
    inventory = {
        item.name: item for item in decompiler_postprocess_inventory.describe_x86_16_decompiler_postprocess_inventory_8616()
    }

    assert (
        inventory["_dead_code_elimination_after_flag_prune_8616"].kind
        is decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.DCE_WITH_EVIDENCE
    )
    assert (
        inventory["_simplify_structured_expressions_8616"].kind
        is decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.FORMATTING
    )
    assert (
        inventory["_apply_annotations_8616"].kind is decompiler_postprocess_inventory.DecompilerPostprocessPassKind8616.CLEANUP
    )


def test_x86_16_decompiler_postprocess_keeps_wrapper_arg_normalization():
    function = SimpleNamespace(info={"x86_16_decompilation_profile": {"wrapper_like": True}})
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function,
            )
        )
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    pass_names = tuple(
        spec.name for spec in decompiler_postprocess_stage._decompiler_postprocess_passes_for_function(project, codegen)
    )

    required_passes = (
        "_apply_word_global_types_8616",
        "_apply_annotations_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_return_address_stack_arguments_8616",
        "_prune_unused_unnamed_memory_declarations_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_attach_callsite_summaries_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
        "_lower_stable_ss_stack_accesses_8616",
        "_normalize_call_target_names_8616",
    )
    for pass_name in required_passes:
        assert pass_name in pass_names
    assert pass_names.index("_attach_callsite_summaries_8616") < pass_names.index(
        "_materialize_callsite_stack_arguments_8616"
    )


def test_x86_16_decompiler_structuring_stage_exports():
    assert "DecompilerStructuringPassSpec" in decompiler_structuring_stage.__all__
    assert "DECOMPILER_STRUCTURING_PASSES" in decompiler_structuring_stage.__all__
    assert "describe_x86_16_decompiler_structuring_stage" in decompiler_structuring_stage.__all__
    assert "apply_x86_16_decompiler_structuring" in decompiler_structuring_stage.__all__


def test_x86_16_decompiler_structuring_stage_description():
    assert decompiler_structuring_stage.describe_x86_16_decompiler_structuring_stage() == tuple(
        (spec.name, spec.needs_project) for spec in decompiler_structuring_stage.DECOMPILER_STRUCTURING_PASSES
    )


def test_x86_16_tail_validation_exports():
    assert "X86_16TailValidationSummary" in tail_validation.__all__
    assert "X86_16ValidationCacheDescriptor" in tail_validation.__all__
    assert "build_x86_16_tail_validation_aggregate" in tail_validation.__all__
    assert "build_x86_16_tail_validation_cached_result" in tail_validation.__all__
    assert "build_x86_16_tail_validation_surface" in tail_validation.__all__
    assert "build_x86_16_tail_validation_verdict" in tail_validation.__all__
    assert "build_x86_16_validation_cache_descriptor" in tail_validation.__all__
    assert "check_x86_16_tail_validation_surface_consistency" in tail_validation.__all__
    assert "persist_x86_16_tail_validation_snapshot" in tail_validation.__all__
    assert "extract_x86_16_tail_validation_snapshot" in tail_validation.__all__
    assert "x86_16_tail_validation_snapshot_passed" in tail_validation.__all__
    assert "fingerprint_x86_16_tail_validation_boundary" in tail_validation.__all__
    assert "collect_x86_16_tail_validation_summary" in tail_validation.__all__
    assert "compare_x86_16_tail_validation_summaries" in tail_validation.__all__
    assert "format_x86_16_tail_validation_diff" in tail_validation.__all__
    assert "resolve_x86_16_validation_cached_artifact" in tail_validation.__all__
    assert "summarize_x86_16_tail_validation_records" in tail_validation.__all__
    assert "describe_x86_16_tail_validation_scope" in tail_validation.__all__
    assert tail_validation.describe_x86_16_tail_validation_scope()["layers"] == ("structuring", "postprocess")


def test_x86_16_recovery_confidence_module_exports():
    assert "RecoveryEvidence" in recovery_confidence.__all__ or hasattr(recovery_confidence, "RecoveryEvidence")
    assert "describe_x86_16_recovery_confidence_axes" in recovery_confidence.__all__


def test_x86_16_bootstrap_module_exports():
    assert bootstrap.__all__ == ["apply_x86_16_bootstrap"]


def test_x86_16_bootstrap_module_description():
    assert bootstrap.describe_x86_16_bootstrap() == (
        "apply_x86_16_calling_convention_compatibility",
        "apply_x86_16_compatibility",
        "apply_x86_16_decompiler_return_compatibility",
        "apply_x86_16_decompiler_structuring",
        "apply_x86_16_decompiler_postprocess",
    )


def test_x86_16_decompiler_postprocess_pass_specs_are_dataclasses():
    assert all(
        isinstance(spec, decompiler_postprocess_stage.DecompilerPostprocessPassSpec)
        for spec in decompiler_postprocess_stage.DECOMPILER_POSTPROCESS_PASSES
    )
