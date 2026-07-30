PYTHON ?= python
FILES ?=
PYTEST_ARGS ?=
PY_FILES_ALL := $(shell git ls-files '*.py')
PY_FILES := $(filter %.py,$(FILES))
PYTEST_FILES := $(filter angr_platforms/tests/%.py tests/%.py,$(PY_FILES))
PY_CHANGED_FILES := $(shell { git diff --name-only -- '*.py'; git ls-files --others --exclude-standard -- '*.py'; } | sort -u)

.PHONY: quality quality-fast decompiler-check decompiler-check-fast decompiler-check-expanded architecture-check agent-context-check test-ownership-check linters linters-files check-files check-all pytest pytest-files pytest-all ruff ruff-files ruff-all pyright pyright-files pyright-all type-ratchet-files type-ratchet-changed vulture radon test-pipeline test-pipeline-fast test-pipeline-expanded msc6-examples sortdemo-selftest monkeytype-trace monkeytype-stubs monkeytype-apply types

quality: linters type-ratchet-changed decompiler-check

quality-fast: linters type-ratchet-changed decompiler-check-fast

decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline

decompiler-check-fast: architecture-check agent-context-check test-ownership-check test-pipeline-fast

decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded

linters:
	# Pyright scans the full promoted source set; concurrent full-tree linters can exhaust its worker.
	$(MAKE) ruff pyright vulture radon PYTHON="$(PYTHON)"

linters-files:
	$(MAKE) -j3 ruff-files pyright-files type-ratchet-files PYTHON="$(PYTHON)" FILES="$(FILES)"

check-files: linters-files architecture-check agent-context-check test-ownership-check pytest-files

check-all: ruff-all pyright-all type-ratchet-changed architecture-check agent-context-check test-ownership-check pytest-all

QA_TYPED_FILES := \
	monkeytype_config.py \
	angr_platforms/angr_platforms/X86_16/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias_domains.py \
	angr_platforms/angr_platforms/X86_16/alias_state.py \
	angr_platforms/angr_platforms/X86_16/alias_transfer.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py \
	angr_platforms/angr_platforms/X86_16/alias/domains.py \
	angr_platforms/angr_platforms/X86_16/alias/state.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/alias/transfer.py \
	angr_platforms/angr_platforms/X86_16/analysis/__init__.py \
	angr_platforms/angr_platforms/X86_16/analysis/alias.py \
	angr_platforms/angr_platforms/X86_16/analysis/stack_frame_ir.py \
	angr_platforms/angr_platforms/X86_16/analysis_helpers.py \
	angr_platforms/angr_platforms/X86_16/arch_86_16.py \
	angr_platforms/angr_platforms/X86_16/access.py \
	angr_platforms/angr_platforms/X86_16/addressing_helpers.py \
	angr_platforms/angr_platforms/X86_16/address_ir.py \
	angr_platforms/angr_platforms/X86_16/alu_helpers.py \
	angr_platforms/angr_platforms/X86_16/annotations.py \
	angr_platforms/angr_platforms/X86_16/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/condition_trace.py \
	angr_platforms/angr_platforms/X86_16/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/__init__.py \
	angr_platforms/angr_platforms/X86_16/ir/address_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/core.py \
	angr_platforms/angr_platforms/X86_16/ir/effects.py \
	angr_platforms/angr_platforms/X86_16/ir/ir_canonicalize_8616.py \
	angr_platforms/angr_platforms/X86_16/ir/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_function.py \
	angr_platforms/angr_platforms/X86_16/ir/string_effects.py \
	angr_platforms/angr_platforms/X86_16/ir/value_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_addressing.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_import.py \
	angr_platforms/angr_platforms/X86_16/function_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_family_routing.py \
	angr_platforms/angr_platforms/X86_16/function_interface_surface.py \
	angr_platforms/angr_platforms/X86_16/function_summary.py \
	angr_platforms/angr_platforms/X86_16/function_state_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py \
	angr_platforms/angr_platforms/X86_16/stack_probe_fact_trace.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_condition_context.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_routing.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_stack_policy.py \
	angr_platforms/angr_platforms/X86_16/targeted_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/layer_module_status.py \
	angr_platforms/angr_platforms/X86_16/coverage_manifest.py \
	angr_platforms/angr_platforms/X86_16/corpus_scan.py \
	angr_platforms/angr_platforms/X86_16/milestone_report.py \
	angr_platforms/angr_platforms/X86_16/exact_region_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/flair_extract.py \
	angr_platforms/angr_platforms/X86_16/fast_tracer.py \
	angr_platforms/angr_platforms/X86_16/jcc_condition.py \
	angr_platforms/angr_platforms/X86_16/lift_86_16.py \
	angr_platforms/angr_platforms/X86_16/load_dos_mz.py \
	angr_platforms/angr_platforms/X86_16/load_dos_ne.py \
	angr_platforms/angr_platforms/X86_16/lst_extract.py \
	angr_platforms/angr_platforms/X86_16/ne_exe_parse.py \
	angr_platforms/angr_platforms/X86_16/ne_resources.py \
	angr_platforms/angr_platforms/X86_16/recovery_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifacts.py \
	angr_platforms/angr_platforms/X86_16/recovery_confidence.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_cache.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_writer.py \
	angr_platforms/angr_platforms/X86_16/corpus_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py \
	angr_platforms/angr_platforms/X86_16/ir_recovery_summary.py \
	angr_platforms/angr_platforms/X86_16/ir_readiness.py \
	angr_platforms/angr_platforms/X86_16/ir_confidence_markers.py \
	angr_platforms/angr_platforms/X86_16/runtime_trace_refinement.py \
	angr_platforms/angr_platforms/X86_16/structuring_ir_hints.py \
	angr_platforms/angr_platforms/X86_16/structuring_abnormal_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_analysis.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_indirect.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py \
	angr_platforms/angr_platforms/X86_16/structuring_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_snapshot.py \
	angr_platforms/angr_platforms/X86_16/structuring_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_region.py \
	angr_platforms/angr_platforms/X86_16/structuring_codegen.py \
	angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_pass.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py \
	angr_platforms/angr_platforms/X86_16/structured_function_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_artifact.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_lowering.py \
	angr_platforms/angr_platforms/X86_16/string_codegen_override.py \
	angr_platforms/angr_platforms/X86_16/type_array_matching.py \
	angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py \
	angr_platforms/angr_platforms/X86_16/type_structure_merging.py \
	angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py \
	angr_platforms/angr_platforms/X86_16/bootstrap.py \
	angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py \
	angr_platforms/angr_platforms/X86_16/cod_extract.py \
	angr_platforms/angr_platforms/X86_16/cod_known_objects.py \
	angr_platforms/angr_platforms/X86_16/cod_source_rewrites.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb00.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb02_nb04.py \
	angr_platforms/angr_platforms/X86_16/codegen_metadata.py \
	angr_platforms/angr_platforms/X86_16/compiler_helpers.py \
	angr_platforms/angr_platforms/X86_16/cr.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_globals.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py \
	angr_platforms/angr_platforms/X86_16/compat.py \
	angr_platforms/angr_platforms/X86_16/calling_convention_compat.py \
	angr_platforms/angr_platforms/X86_16/render_compat.py \
	angr_platforms/angr_platforms/X86_16/patch_dirty.py \
	angr_platforms/angr_platforms/X86_16/c_ast_utils.py \
	angr_platforms/angr_platforms/X86_16/callee_name_normalization.py \
	angr_platforms/angr_platforms/X86_16/low_memory_regions.py \
	angr_platforms/angr_platforms/X86_16/simos_86_16.py \
	angr_platforms/angr_platforms/X86_16/exception.py \
	angr_platforms/angr_platforms/X86_16/hardware.py \
	angr_platforms/angr_platforms/X86_16/simprocs_io.py \
	angr_platforms/angr_platforms/X86_16/debug.py \
	angr_platforms/angr_platforms/X86_16/dev_io.py \
	angr_platforms/angr_platforms/X86_16/io.py \
	angr_platforms/angr_platforms/X86_16/instruction.py \
	angr_platforms/angr_platforms/X86_16/instr_base.py \
	angr_platforms/angr_platforms/X86_16/instr16.py \
	angr_platforms/angr_platforms/X86_16/instr32.py \
	angr_platforms/angr_platforms/X86_16/parse.py \
	angr_platforms/angr_platforms/X86_16/exec.py \
	angr_platforms/angr_platforms/X86_16/emu.py \
	angr_platforms/angr_platforms/X86_16/emulator.py \
	angr_platforms/angr_platforms/X86_16/eflags.py \
	angr_platforms/angr_platforms/X86_16/memory.py \
	angr_platforms/angr_platforms/X86_16/processor.py \
	angr_platforms/angr_platforms/X86_16/interrupt.py \
	angr_platforms/angr_platforms/X86_16/stack_compat.py \
	angr_platforms/angr_platforms/X86_16/typehoon_compat.py \
	angr_platforms/angr_platforms/X86_16/stack_helpers.py \
	angr_platforms/angr_platforms/X86_16/correctness_goals.py \
	angr_platforms/angr_platforms/X86_16/readability_set.py \
	angr_platforms/angr_platforms/X86_16/readability_goals.py \
	angr_platforms/angr_platforms/X86_16/quality.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_jcc.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_loads.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_typed_conditions.py \
	angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py \
	angr_platforms/angr_platforms/X86_16/tail_validation.py \
	angr_platforms/angr_platforms/X86_16/validation_manifest.py \
	angr_platforms/angr_platforms/X86_16/validation_helper_report.py \
	angr_platforms/angr_platforms/X86_16/validation_summary.py \
	angr_platforms/angr_platforms/X86_16/validation_calls.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow.py \
	angr_platforms/angr_platforms/X86_16/validation_dataflow.py \
	angr_platforms/angr_platforms/X86_16/validation_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_semantics.py \
	angr_platforms/angr_platforms/X86_16/verification_80286.py \
	angr_platforms/angr_platforms/X86_16/turbo_debug_tdinfo.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cases.py \
	angr_platforms/angr_platforms/X86_16/recompilable_checks.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cli_bridge.py \
	angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py \
	angr_platforms/angr_platforms/X86_16/recompilable_subset.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_objects.py \
	angr_platforms/angr_platforms/X86_16/structuring_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouping_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_refusal_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_cross_entry.py \
	angr_platforms/angr_platforms/X86_16/structuring_sequences.py \
	angr_platforms/angr_platforms/X86_16/lowering/__init__.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/c_runtime_header.py \
	angr_platforms/angr_platforms/X86_16/lowering/dead_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_overwrite_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py \
	angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_global_loads.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_argument_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/structured_intrinsics.py \
	angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_c_ast_matching.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_impl.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_result.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_binding.py \
	angr_platforms/angr_platforms/X86_16/pipeline/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/condition_patterns.py \
	angr_platforms/angr_platforms/X86_16/postprocess/cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/simplify.py \
	angr_platforms/angr_platforms/X86_16/postprocess/value_flow.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/const_prop.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/copy_prop.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_setup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/pass_driver.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py \
	angr_platforms/angr_platforms/X86_16/semantics/__init__.py \
	angr_platforms/angr_platforms/X86_16/semantics/alias_query.py \
	angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/binary_call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/branch_target_return.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py \
	angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py \
	angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py \
	angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/compare32_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/control_flow.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_rendering.py \
	angr_platforms/angr_platforms/X86_16/structuring/indexed_stack_ranges.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_exit_return_guards.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/typed_switch_seqnode.py \
	angr_platforms/angr_platforms/X86_16/structuring/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/canonicalize.py \
	angr_platforms/angr_platforms/X86_16/widening_alias.py \
	angr_platforms/angr_platforms/X86_16/widening_model.py \
	angr_platforms/angr_platforms/X86_16/widening/__init__.py \
	angr_platforms/angr_platforms/X86_16/widening/register_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_identity.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py \
	angr_platforms/angr_platforms/X86_16/widening/store_width.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_rules.py \
	angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/errors.py \
	angr_platforms/angr_platforms/X86_16/pipeline/invariants.py \
	angr_platforms/angr_platforms/X86_16/pipeline/linear_guard.py \
	inertia_decompiler/__init__.py \
	inertia_decompiler/acceptance_scorecard.py \
	inertia_decompiler/architecture_runtime_guard.py \
	inertia_decompiler/c_text_cleanup.py \
	inertia_decompiler/cache.py \
	inertia_decompiler/cli.py \
	inertia_decompiler/cli_core.py \
	inertia_decompiler/cli_decompilation.py \
	inertia_decompiler/cli_c_ast_rewrites.py \
	inertia_decompiler/cli_c_text_postprocess.py \
	inertia_decompiler/cli_fallback_decompilation.py \
	inertia_decompiler/cli_function_discovery.py \
	inertia_decompiler/cli_access_object_hints.py \
	inertia_decompiler/cli_access_profiles.py \
	inertia_decompiler/cli_access_traits.py \
	inertia_decompiler/cli_access_trait_rewrite.py \
	inertia_decompiler/cli_access_rewrite_artifact.py \
	inertia_decompiler/cli_arg_parser.py \
	inertia_decompiler/cli_cod_global_statements.py \
	inertia_decompiler/cli_cod_globals.py \
	inertia_decompiler/cli_dead_local_prune.py \
	inertia_decompiler/cli_helper_modeling.py \
	inertia_decompiler/cli_interrupt_modeling.py \
	inertia_decompiler/cli_linear_aliases.py \
	inertia_decompiler/cli_induction_rewrite.py \
	inertia_decompiler/cli_linear_recurrence.py \
	inertia_decompiler/cli_linear_recurrence_rules.py \
	inertia_decompiler/cli_linear_recurrence_state.py \
	inertia_decompiler/cli_mkfp_simplify.py \
	inertia_decompiler/cli_memory_prune.py \
	inertia_decompiler/cli_local_prune.py \
	inertia_decompiler/cli_local_rewrites.py \
	inertia_decompiler/cli_far_pointer_stack.py \
	inertia_decompiler/cli_segmented.py \
	inertia_decompiler/cli_segmented_compare.py \
	inertia_decompiler/cli_segmented_elision.py \
	inertia_decompiler/cli_segmented_load_coalesce.py \
	inertia_decompiler/cli_segmented_lowering.py \
	inertia_decompiler/cli_segmented_store_coalesce.py \
	inertia_decompiler/cli_stack_coalesce.py \
	inertia_decompiler/cli_stack_cvars.py \
	inertia_decompiler/cli_stack_byte_offsets.py \
	inertia_decompiler/cli_stack_locals.py \
	inertia_decompiler/cli_storage_objects.py \
	inertia_decompiler/cli_string_timeout_fallback.py \
	inertia_decompiler/cli_timeout.py \
	inertia_decompiler/cli_output.py \
	inertia_decompiler/cli_word_loads.py \
	inertia_decompiler/cli_word_global_helpers.py \
	inertia_decompiler/default_signature_catalog.py \
	inertia_decompiler/decompile_file_summary.py \
	inertia_decompiler/decompilation_quality.py \
	inertia_decompiler/direct_addr_failure_family.py \
	inertia_decompiler/direct_addr_stage_bundle.py \
	inertia_decompiler/discovery_evidence_project.py \
	inertia_decompiler/disassembly_helpers.py \
	inertia_decompiler/flair_paths.py \
	inertia_decompiler/gdb_client.py \
	inertia_decompiler/gdb_tui.py \
	inertia_decompiler/library_function_classifier.py \
	inertia_decompiler/debug_dos.py \
	inertia_decompiler/debugger_gdb.py \
	inertia_decompiler/debugger_tui.py \
	inertia_decompiler/signature_matching_policy.py \
	inertia_decompiler/msc51_local_hash.py \
	inertia_decompiler/non_optimized_fallback.py \
	inertia_decompiler/packer_detect.py \
	inertia_decompiler/project_loading.py \
	inertia_decompiler/rizin_evidence.py \
	inertia_decompiler/rizin_discovery.py \
	inertia_decompiler/recompile_check.py \
	inertia_decompiler/runtime_support.py \
	inertia_decompiler/sidecar_cache.py \
	inertia_decompiler/sidecar_metadata.py \
	inertia_decompiler/sidecar_policy.py \
	inertia_decompiler/sidecar_parsers.py \
	inertia_decompiler/slice_recovery.py \
	inertia_decompiler/source_sidecar.py \
	inertia_decompiler/tail_validation.py \
	inertia_decompiler/telemetry.py \
	inertia_decompiler/tui_widgets.py \
	inertia_decompiler/variable_recovery_sub_guard.py \
	inertia_decompiler/work_items.py \
	inertia_decompiler/x86_16_exact_slice.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py \
	scripts/agent_context_check.py \
	scripts/batch_decompile_procs.py \
	scripts/build_msc6_examples.py \
	scripts/check_sortd_sidecar_free.py \
	scripts/check_decompiler_architecture.py \
	scripts/import_ultra_quickc_fixtures.py \
	scripts/test_pipeline.py \
	scripts/test_ownership_manifest.py \
	scripts/check_changed_non_test_types.py \
	scripts/sortdemo_decompiler_status.py \
	decompile.py

QA_RUFF_TARGETS := \
	monkeytype_config.py \
	angr_platforms/angr_platforms/X86_16/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias_domains.py \
	angr_platforms/angr_platforms/X86_16/alias_state.py \
	angr_platforms/angr_platforms/X86_16/alias_transfer.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py \
	angr_platforms/angr_platforms/X86_16/alias/domains.py \
	angr_platforms/angr_platforms/X86_16/alias/state.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/alias/transfer.py \
	angr_platforms/angr_platforms/X86_16/analysis/__init__.py \
	angr_platforms/angr_platforms/X86_16/analysis/alias.py \
	angr_platforms/angr_platforms/X86_16/analysis/stack_frame_ir.py \
	angr_platforms/angr_platforms/X86_16/analysis_helpers.py \
	angr_platforms/angr_platforms/X86_16/arch_86_16.py \
	angr_platforms/angr_platforms/X86_16/access.py \
	angr_platforms/angr_platforms/X86_16/addressing_helpers.py \
	angr_platforms/angr_platforms/X86_16/address_ir.py \
	angr_platforms/angr_platforms/X86_16/alu_helpers.py \
	angr_platforms/angr_platforms/X86_16/annotations.py \
	angr_platforms/angr_platforms/X86_16/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/condition_trace.py \
	angr_platforms/angr_platforms/X86_16/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/__init__.py \
	angr_platforms/angr_platforms/X86_16/ir/address_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/core.py \
	angr_platforms/angr_platforms/X86_16/ir/effects.py \
	angr_platforms/angr_platforms/X86_16/ir/ir_canonicalize_8616.py \
	angr_platforms/angr_platforms/X86_16/ir/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_function.py \
	angr_platforms/angr_platforms/X86_16/ir/string_effects.py \
	angr_platforms/angr_platforms/X86_16/ir/value_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_addressing.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_import.py \
	angr_platforms/angr_platforms/X86_16/function_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_family_routing.py \
	angr_platforms/angr_platforms/X86_16/function_interface_surface.py \
	angr_platforms/angr_platforms/X86_16/function_summary.py \
	angr_platforms/angr_platforms/X86_16/function_state_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py \
	angr_platforms/angr_platforms/X86_16/stack_probe_fact_trace.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_condition_context.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_routing.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_stack_policy.py \
	angr_platforms/angr_platforms/X86_16/targeted_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/layer_module_status.py \
	angr_platforms/angr_platforms/X86_16/coverage_manifest.py \
	angr_platforms/angr_platforms/X86_16/corpus_scan.py \
	angr_platforms/angr_platforms/X86_16/milestone_report.py \
	angr_platforms/angr_platforms/X86_16/exact_region_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/flair_extract.py \
	angr_platforms/angr_platforms/X86_16/fast_tracer.py \
	angr_platforms/angr_platforms/X86_16/jcc_condition.py \
	angr_platforms/angr_platforms/X86_16/lift_86_16.py \
	angr_platforms/angr_platforms/X86_16/load_dos_mz.py \
	angr_platforms/angr_platforms/X86_16/load_dos_ne.py \
	angr_platforms/angr_platforms/X86_16/lst_extract.py \
	angr_platforms/angr_platforms/X86_16/ne_exe_parse.py \
	angr_platforms/angr_platforms/X86_16/ne_resources.py \
	angr_platforms/angr_platforms/X86_16/recovery_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifacts.py \
	angr_platforms/angr_platforms/X86_16/recovery_confidence.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_cache.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_writer.py \
	angr_platforms/angr_platforms/X86_16/corpus_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py \
	angr_platforms/angr_platforms/X86_16/ir_recovery_summary.py \
	angr_platforms/angr_platforms/X86_16/ir_readiness.py \
	angr_platforms/angr_platforms/X86_16/ir_confidence_markers.py \
	angr_platforms/angr_platforms/X86_16/runtime_trace_refinement.py \
	angr_platforms/angr_platforms/X86_16/structuring_ir_hints.py \
	angr_platforms/angr_platforms/X86_16/structuring_abnormal_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_analysis.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_indirect.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py \
	angr_platforms/angr_platforms/X86_16/structuring_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_snapshot.py \
	angr_platforms/angr_platforms/X86_16/structuring_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_region.py \
	angr_platforms/angr_platforms/X86_16/structuring_codegen.py \
	angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_pass.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py \
	angr_platforms/angr_platforms/X86_16/structured_function_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_artifact.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_lowering.py \
	angr_platforms/angr_platforms/X86_16/string_codegen_override.py \
	angr_platforms/angr_platforms/X86_16/type_array_matching.py \
	angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py \
	angr_platforms/angr_platforms/X86_16/type_structure_merging.py \
	angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py \
	angr_platforms/angr_platforms/X86_16/bootstrap.py \
	angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py \
	angr_platforms/angr_platforms/X86_16/cod_extract.py \
	angr_platforms/angr_platforms/X86_16/cod_known_objects.py \
	angr_platforms/angr_platforms/X86_16/cod_source_rewrites.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb00.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb02_nb04.py \
	angr_platforms/angr_platforms/X86_16/codegen_metadata.py \
	angr_platforms/angr_platforms/X86_16/compiler_helpers.py \
	angr_platforms/angr_platforms/X86_16/cr.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_globals.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py \
	angr_platforms/angr_platforms/X86_16/compat.py \
	angr_platforms/angr_platforms/X86_16/calling_convention_compat.py \
	angr_platforms/angr_platforms/X86_16/render_compat.py \
	angr_platforms/angr_platforms/X86_16/patch_dirty.py \
	angr_platforms/angr_platforms/X86_16/c_ast_utils.py \
	angr_platforms/angr_platforms/X86_16/callee_name_normalization.py \
	angr_platforms/angr_platforms/X86_16/low_memory_regions.py \
	angr_platforms/angr_platforms/X86_16/simos_86_16.py \
	angr_platforms/angr_platforms/X86_16/exception.py \
	angr_platforms/angr_platforms/X86_16/hardware.py \
	angr_platforms/angr_platforms/X86_16/simprocs_io.py \
	angr_platforms/angr_platforms/X86_16/debug.py \
	angr_platforms/angr_platforms/X86_16/dev_io.py \
	angr_platforms/angr_platforms/X86_16/io.py \
	angr_platforms/angr_platforms/X86_16/instruction.py \
	angr_platforms/angr_platforms/X86_16/instr_base.py \
	angr_platforms/angr_platforms/X86_16/instr16.py \
	angr_platforms/angr_platforms/X86_16/instr32.py \
	angr_platforms/angr_platforms/X86_16/parse.py \
	angr_platforms/angr_platforms/X86_16/exec.py \
	angr_platforms/angr_platforms/X86_16/emu.py \
	angr_platforms/angr_platforms/X86_16/emulator.py \
	angr_platforms/angr_platforms/X86_16/eflags.py \
	angr_platforms/angr_platforms/X86_16/memory.py \
	angr_platforms/angr_platforms/X86_16/processor.py \
	angr_platforms/angr_platforms/X86_16/interrupt.py \
	angr_platforms/angr_platforms/X86_16/stack_compat.py \
	angr_platforms/angr_platforms/X86_16/typehoon_compat.py \
	angr_platforms/angr_platforms/X86_16/stack_helpers.py \
	angr_platforms/angr_platforms/X86_16/correctness_goals.py \
	angr_platforms/angr_platforms/X86_16/readability_set.py \
	angr_platforms/angr_platforms/X86_16/readability_goals.py \
	angr_platforms/angr_platforms/X86_16/quality.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_jcc.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_loads.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_typed_conditions.py \
	angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py \
	angr_platforms/angr_platforms/X86_16/tail_validation.py \
	angr_platforms/angr_platforms/X86_16/validation_manifest.py \
	angr_platforms/angr_platforms/X86_16/validation_helper_report.py \
	angr_platforms/angr_platforms/X86_16/validation_summary.py \
	angr_platforms/angr_platforms/X86_16/validation_calls.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow.py \
	angr_platforms/angr_platforms/X86_16/validation_dataflow.py \
	angr_platforms/angr_platforms/X86_16/validation_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_semantics.py \
	angr_platforms/angr_platforms/X86_16/verification_80286.py \
	angr_platforms/angr_platforms/X86_16/turbo_debug_tdinfo.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cases.py \
	angr_platforms/angr_platforms/X86_16/recompilable_checks.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cli_bridge.py \
	angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py \
	angr_platforms/angr_platforms/X86_16/recompilable_subset.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_objects.py \
	angr_platforms/angr_platforms/X86_16/structuring_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouping_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_refusal_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_cross_entry.py \
	angr_platforms/angr_platforms/X86_16/structuring_sequences.py \
	angr_platforms/angr_platforms/X86_16/lowering/__init__.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/c_runtime_header.py \
	angr_platforms/angr_platforms/X86_16/lowering/dead_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_overwrite_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py \
	angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_global_loads.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_argument_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/structured_intrinsics.py \
	angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_c_ast_matching.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_impl.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_result.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_binding.py \
	angr_platforms/angr_platforms/X86_16/pipeline/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/condition_patterns.py \
	angr_platforms/angr_platforms/X86_16/postprocess/cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/simplify.py \
	angr_platforms/angr_platforms/X86_16/postprocess/value_flow.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/const_prop.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/copy_prop.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_setup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/pass_driver.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py \
	angr_platforms/angr_platforms/X86_16/semantics/__init__.py \
	angr_platforms/angr_platforms/X86_16/semantics/alias_query.py \
	angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/binary_call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/branch_target_return.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py \
	angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py \
	angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py \
	angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/compare32_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/control_flow.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_rendering.py \
	angr_platforms/angr_platforms/X86_16/structuring/indexed_stack_ranges.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_exit_return_guards.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/typed_switch_seqnode.py \
	angr_platforms/angr_platforms/X86_16/structuring/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/canonicalize.py \
	angr_platforms/angr_platforms/X86_16/widening_alias.py \
	angr_platforms/angr_platforms/X86_16/widening_model.py \
	angr_platforms/angr_platforms/X86_16/widening/__init__.py \
	angr_platforms/angr_platforms/X86_16/widening/register_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_identity.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py \
	angr_platforms/angr_platforms/X86_16/widening/store_width.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_rules.py \
	angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/errors.py \
	angr_platforms/angr_platforms/X86_16/pipeline/invariants.py \
	angr_platforms/angr_platforms/X86_16/pipeline/linear_guard.py \
	inertia_decompiler/__init__.py \
	inertia_decompiler/acceptance_scorecard.py \
	inertia_decompiler/architecture_runtime_guard.py \
	inertia_decompiler/c_text_cleanup.py \
	inertia_decompiler/cache.py \
	inertia_decompiler/cli.py \
	inertia_decompiler/cli_core.py \
	inertia_decompiler/cli_decompilation.py \
	inertia_decompiler/cli_c_ast_rewrites.py \
	inertia_decompiler/cli_c_text_postprocess.py \
	inertia_decompiler/cli_fallback_decompilation.py \
	inertia_decompiler/cli_function_discovery.py \
	inertia_decompiler/cli_access_object_hints.py \
	inertia_decompiler/cli_access_profiles.py \
	inertia_decompiler/cli_access_traits.py \
	inertia_decompiler/cli_access_trait_rewrite.py \
	inertia_decompiler/cli_access_rewrite_artifact.py \
	inertia_decompiler/cli_arg_parser.py \
	inertia_decompiler/cli_cod_global_statements.py \
	inertia_decompiler/cli_cod_globals.py \
	inertia_decompiler/cli_dead_local_prune.py \
	inertia_decompiler/cli_helper_modeling.py \
	inertia_decompiler/cli_interrupt_modeling.py \
	inertia_decompiler/cli_linear_aliases.py \
	inertia_decompiler/cli_induction_rewrite.py \
	inertia_decompiler/cli_linear_recurrence.py \
	inertia_decompiler/cli_linear_recurrence_rules.py \
	inertia_decompiler/cli_linear_recurrence_state.py \
	inertia_decompiler/cli_mkfp_simplify.py \
	inertia_decompiler/cli_memory_prune.py \
	inertia_decompiler/cli_local_prune.py \
	inertia_decompiler/cli_local_rewrites.py \
	inertia_decompiler/cli_far_pointer_stack.py \
	inertia_decompiler/cli_segmented.py \
	inertia_decompiler/cli_segmented_compare.py \
	inertia_decompiler/cli_segmented_elision.py \
	inertia_decompiler/cli_segmented_load_coalesce.py \
	inertia_decompiler/cli_segmented_lowering.py \
	inertia_decompiler/cli_segmented_store_coalesce.py \
	inertia_decompiler/cli_stack_coalesce.py \
	inertia_decompiler/cli_stack_cvars.py \
	inertia_decompiler/cli_stack_byte_offsets.py \
	inertia_decompiler/cli_stack_locals.py \
	inertia_decompiler/cli_storage_objects.py \
	inertia_decompiler/cli_string_timeout_fallback.py \
	inertia_decompiler/cli_timeout.py \
	inertia_decompiler/cli_output.py \
	inertia_decompiler/cli_word_loads.py \
	inertia_decompiler/cli_word_global_helpers.py \
	inertia_decompiler/default_signature_catalog.py \
	inertia_decompiler/decompile_file_summary.py \
	inertia_decompiler/decompilation_quality.py \
	inertia_decompiler/direct_addr_failure_family.py \
	inertia_decompiler/direct_addr_stage_bundle.py \
	inertia_decompiler/discovery_evidence_project.py \
	inertia_decompiler/disassembly_helpers.py \
	inertia_decompiler/flair_paths.py \
	inertia_decompiler/gdb_client.py \
	inertia_decompiler/gdb_tui.py \
	inertia_decompiler/library_function_classifier.py \
	inertia_decompiler/debug_dos.py \
	inertia_decompiler/debugger_gdb.py \
	inertia_decompiler/debugger_tui.py \
	inertia_decompiler/signature_matching_policy.py \
	inertia_decompiler/msc51_local_hash.py \
	inertia_decompiler/non_optimized_fallback.py \
	inertia_decompiler/packer_detect.py \
	inertia_decompiler/project_loading.py \
	inertia_decompiler/rizin_evidence.py \
	inertia_decompiler/rizin_discovery.py \
	inertia_decompiler/recompile_check.py \
	inertia_decompiler/runtime_support.py \
	inertia_decompiler/sidecar_cache.py \
	inertia_decompiler/sidecar_metadata.py \
	inertia_decompiler/sidecar_policy.py \
	inertia_decompiler/sidecar_parsers.py \
	inertia_decompiler/slice_recovery.py \
	inertia_decompiler/source_sidecar.py \
	inertia_decompiler/tail_validation.py \
	inertia_decompiler/telemetry.py \
	inertia_decompiler/work_items.py \
	inertia_decompiler/tui_widgets.py \
	inertia_decompiler/variable_recovery_sub_guard.py \
	inertia_decompiler/x86_16_exact_slice.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py \
	scripts/agent_context_check.py \
	scripts/batch_decompile_procs.py \
	scripts/build_msc6_examples.py \
	scripts/check_changed_non_test_types.py \
	scripts/check_decompiler_architecture.py \
	scripts/check_sortd_sidecar_free.py \
	scripts/import_ultra_quickc_fixtures.py \
	scripts/sortdemo_decompiler_status.py \
	scripts/test_pipeline.py \
	scripts/test_ownership_manifest.py \
	decompile.py \
	angr_platforms/tests/test_agent_context_check.py \
	angr_platforms/tests/test_check_changed_non_test_types.py \
	angr_platforms/tests/test_x86_16_cr.py \
	angr_platforms/tests/test_x86_16_exception.py \
	angr_platforms/tests/test_x86_16_hardware.py \
	angr_platforms/tests/test_x86_16_simprocs_io.py \
	angr_platforms/tests/test_x86_16_debug.py \
	angr_platforms/tests/test_x86_16_dev_io.py \
	angr_platforms/tests/test_x86_16_io.py \
	angr_platforms/tests/test_x86_16_emulator.py \
	angr_platforms/tests/test_x86_16_memory.py \
	angr_platforms/tests/test_x86_16_interrupt.py \
	angr_platforms/tests/test_x86_16_lowered_register_carriers.py \
	angr_platforms/tests/test_x86_16_stack_compat.py \
	angr_platforms/tests/test_x86_16_correctness_goals.py \
	angr_platforms/tests/test_x86_16_readability_set.py \
	angr_platforms/tests/test_x86_16_readability_goals.py \
	angr_platforms/tests/test_x86_16_alias_domains.py \
	angr_platforms/tests/test_x86_16_semantics_exports.py \
	angr_platforms/tests/test_x86_16_alias_stack_lowering.py \
		angr_platforms/tests/test_x86_16_alias_state_transfer.py \
		angr_platforms/tests/test_x86_16_c_runtime_header.py \
		angr_platforms/tests/test_x86_16_object_lowering.py \
		angr_platforms/tests/test_x86_16_semantics_alias_query.py \
		angr_platforms/tests/test_x86_16_semantics_evidence_cache.py \
		angr_platforms/tests/test_x86_16_semantics_expression_analysis.py \
		angr_platforms/tests/test_x86_16_address_ir.py \
	angr_platforms/tests/test_x86_16_segment_state.py \
	angr_platforms/tests/test_x86_16_vex_import.py \
	angr_platforms/tests/test_x86_16_condition_rendering.py \
	angr_platforms/tests/test_x86_16_ir_readiness.py \
	angr_platforms/tests/test_x86_16_layer_module_status.py \
	angr_platforms/tests/test_x86_16_coverage_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifacts.py \
	angr_platforms/tests/test_x86_16_function_effect_summary.py \
	angr_platforms/tests/test_x86_16_helper_effect_summary.py \
	angr_platforms/tests/test_x86_16_helper_family_routing.py \
	angr_platforms/tests/test_x86_16_function_interface_surface.py \
	angr_platforms/tests/test_x86_16_function_state_summary.py \
	angr_platforms/tests/test_x86_16_recovery_confidence_helper_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_cache.py \
	angr_platforms/tests/test_x86_16_ir_recovery_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_writer.py \
	angr_platforms/tests/test_x86_16_targeted_recovery_artifact.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsite_prototypes.py \
	angr_platforms/tests/test_build_msc6_examples.py \
	angr_platforms/tests/test_decompile_entrypoint_determinism.py \
	angr_platforms/tests/test_import_ultra_quickc_fixtures.py \
	angr_platforms/tests/test_decompiler_architecture_check.py \
		angr_platforms/tests/test_decompilation_quality.py \
		angr_platforms/tests/test_cli_regeneration.py \
		angr_platforms/tests/test_test_ownership_manifest.py \
		angr_platforms/tests/test_x86_16_call_contracts.py \
		angr_platforms/tests/test_x86_16_call_output_stack_objects.py \
		angr_platforms/tests/test_x86_16_call_return_conditions.py \
		angr_platforms/tests/test_x86_16_callsite_prototype_declarations.py \
		angr_platforms/tests/test_x86_16_condition_lowering.py \
		angr_platforms/tests/test_x86_16_condition_transfer.py \
		angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py \
		angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py \
		angr_platforms/tests/test_x86_16_indexed_stack_ranges.py \
		angr_platforms/tests/test_x86_16_validation_canonicalize.py \
		angr_platforms/tests/test_x86_16_validation_control_flow.py \
		angr_platforms/tests/test_x86_16_validation_dataflow.py \
		angr_platforms/tests/test_x86_16_validation_storage.py \
	angr_platforms/tests/test_x86_16_validation_manifest.py \
	angr_platforms/tests/test_x86_16_validation_helper_report.py \
	angr_platforms/tests/test_x86_16_low_memory_regions.py \
	angr_platforms/tests/test_x86_16_recompilable_source_evidence.py \
	angr_platforms/tests/test_x86_16_recompilable_subset.py \
	angr_platforms/tests/test_x86_16_recompilable_storage_map.py \
		angr_platforms/tests/test_x86_16_recompilable_storage_objects.py \
		angr_platforms/tests/test_x86_16_structuring_grouping_report.py \
		angr_platforms/tests/test_x86_16_structuring_grouped_refusal_report.py \
		angr_platforms/tests/test_x86_16_structuring_condition_materialization.py \
		angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py \
		angr_platforms/tests/test_x86_16_structuring_sequences.py \
		angr_platforms/tests/test_x86_16_dce_optimization.py \
		angr_platforms/tests/test_x86_16_trivial_copy_optimization.py \
		angr_platforms/tests/test_x86_16_widening_copyprop.py \
		angr_platforms/tests/test_x86_16_widening_memory_fold.py \
		angr_platforms/tests/test_x86_16_widening_rules.py \
		angr_platforms/tests/test_x86_16_package_exports.py \
		angr_platforms/tests/test_x86_16_pipeline_contracts.py \
	angr_platforms/tests/test_x86_16_rewrite_boundary.py \
	angr_platforms/tests/test_x86_16_heapsort_widening_regression.py \
	angr_platforms/tests/test_x86_16_global_declarations.py \
	angr_platforms/tests/test_x86_16_direct_stack_update_groups.py \
	angr_platforms/tests/test_x86_16_segmented_global_loads.py \
	angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py \
	angr_platforms/tests/test_x86_16_stack_aggregate_objects.py \
	angr_platforms/tests/test_x86_16_stack_argument_identity.py \
	angr_platforms/tests/test_x86_16_stack_lowering_contracts.py \
	angr_platforms/tests/test_x86_16_decompilation_cache_surface.py \
	angr_platforms/tests/test_check_sortd_sidecar_free.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py \
	angr_platforms/tests/test_x86_16_generated_c_acceptance.py \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py

QA_PYTEST_TARGETS := \
	angr_platforms/tests/test_agent_context_check.py \
	angr_platforms/tests/test_check_changed_non_test_types.py \
	angr_platforms/tests/test_x86_16_callee_name_normalization.py \
	angr_platforms/tests/test_x86_16_cr.py \
	angr_platforms/tests/test_x86_16_exception.py \
	angr_platforms/tests/test_x86_16_hardware.py \
	angr_platforms/tests/test_x86_16_simprocs_io.py \
	angr_platforms/tests/test_x86_16_debug.py \
	angr_platforms/tests/test_x86_16_dev_io.py \
	angr_platforms/tests/test_x86_16_io.py \
	angr_platforms/tests/test_x86_16_emulator.py \
	angr_platforms/tests/test_x86_16_memory.py \
	angr_platforms/tests/test_x86_16_interrupt.py \
	angr_platforms/tests/test_x86_16_stack_compat.py \
	angr_platforms/tests/test_x86_16_correctness_goals.py \
	angr_platforms/tests/test_x86_16_readability_set.py \
	angr_platforms/tests/test_x86_16_readability_goals.py \
	angr_platforms/tests/test_x86_16_alias_domains.py \
	angr_platforms/tests/test_x86_16_semantics_exports.py \
	angr_platforms/tests/test_x86_16_alias_stack_lowering.py \
	angr_platforms/tests/test_x86_16_alias_state_transfer.py \
	angr_platforms/tests/test_x86_16_alu_helpers.py \
	angr_platforms/tests/test_x86_16_c_runtime_header.py \
	angr_platforms/tests/test_x86_16_call_return_selectors.py \
	angr_platforms/tests/test_x86_16_object_lowering.py \
	angr_platforms/tests/test_x86_16_semantics_alias_query.py \
	angr_platforms/tests/test_x86_16_semantics_evidence_cache.py \
	angr_platforms/tests/test_x86_16_semantics_expression_analysis.py \
	angr_platforms/tests/test_x86_16_stack_frame_recovery.py \
	angr_platforms/tests/test_x86_16_segmented_lowering.py \
	angr_platforms/tests/test_x86_16_address_ir.py \
	angr_platforms/tests/test_x86_16_segment_state.py \
	angr_platforms/tests/test_x86_16_vex_import.py \
	angr_platforms/tests/test_x86_16_condition_rendering.py \
	angr_platforms/tests/test_x86_16_ir_readiness.py \
	angr_platforms/tests/test_x86_16_layer_module_status.py \
	angr_platforms/tests/test_x86_16_coverage_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifacts.py \
	angr_platforms/tests/test_x86_16_function_effect_summary.py \
	angr_platforms/tests/test_x86_16_helper_effect_summary.py \
	angr_platforms/tests/test_x86_16_helper_family_routing.py \
	angr_platforms/tests/test_x86_16_function_interface_surface.py \
	angr_platforms/tests/test_x86_16_function_state_summary.py \
	angr_platforms/tests/test_x86_16_recovery_confidence_helper_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_cache.py \
	angr_platforms/tests/test_x86_16_ir_recovery_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_writer.py \
	angr_platforms/tests/test_x86_16_targeted_recovery_artifact.py \
	angr_platforms/tests/test_x86_16_corpus_recovery_artifact.py \
	angr_platforms/tests/test_build_msc6_examples.py \
	angr_platforms/tests/test_decompile_entrypoint_determinism.py \
	angr_platforms/tests/test_import_ultra_quickc_fixtures.py \
	angr_platforms/tests/test_omf_pat_lidata.py \
	angr_platforms/tests/test_decompiler_architecture_check.py \
	angr_platforms/tests/test_decompilation_quality.py \
	angr_platforms/tests/test_cli_regeneration.py \
	angr_platforms/tests/test_check_sortd_sidecar_free.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_test_ownership_manifest.py \
	angr_platforms/tests/test_x86_16_alias_register_mvp.py \
	angr_platforms/tests/test_x86_16_call_contracts.py \
	angr_platforms/tests/test_x86_16_call_output_stack_objects.py \
	angr_platforms/tests/test_x86_16_call_return_conditions.py \
	angr_platforms/tests/test_x86_16_callsite_prototype_declarations.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py \
	angr_platforms/tests/test_x86_16_condition_lowering.py \
	angr_platforms/tests/test_x86_16_condition_transfer.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py \
	angr_platforms/tests/test_x86_16_package_exports.py \
	angr_platforms/tests/test_x86_16_pipeline_contracts.py \
	angr_platforms/tests/test_x86_16_rewrite_boundary.py \
	angr_platforms/tests/test_x86_16_indexed_stack_ranges.py \
	angr_platforms/tests/test_x86_16_validation_canonicalize.py \
	angr_platforms/tests/test_x86_16_validation_control_flow.py \
	angr_platforms/tests/test_x86_16_validation_dataflow.py \
	angr_platforms/tests/test_x86_16_validation_storage.py \
	angr_platforms/tests/test_x86_16_validation_manifest.py \
	angr_platforms/tests/test_x86_16_validation_helper_report.py \
	angr_platforms/tests/test_x86_16_low_memory_regions.py \
	angr_platforms/tests/test_x86_16_recompilable_source_evidence.py \
	angr_platforms/tests/test_x86_16_recompilable_subset.py \
	angr_platforms/tests/test_x86_16_recompilable_storage_map.py \
	angr_platforms/tests/test_x86_16_recompilable_storage_objects.py \
	angr_platforms/tests/test_x86_16_array_matching.py \
	angr_platforms/tests/test_x86_16_struct_merging.py \
	angr_platforms/tests/test_x86_16_structuring_condition_materialization.py \
	angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py \
	angr_platforms/tests/test_x86_16_dce_optimization.py \
	angr_platforms/tests/test_x86_16_trivial_copy_optimization.py \
	angr_platforms/tests/test_x86_16_widening_copyprop.py \
	angr_platforms/tests/test_x86_16_widening_memory_fold.py \
	angr_platforms/tests/test_x86_16_widening_rules.py \
	angr_platforms/tests/test_x86_16_generated_c_acceptance.py \
	angr_platforms/tests/test_x86_16_structuring_grouping_report.py \
	angr_platforms/tests/test_x86_16_structuring_grouped_refusal_report.py \
	angr_platforms/tests/test_x86_16_structuring_sequences.py \
	angr_platforms/tests/test_x86_16_stack_aggregate_objects.py \
	angr_platforms/tests/test_x86_16_stack_argument_identity.py \
	angr_platforms/tests/test_x86_16_stack_lowering_contracts.py \
	angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::test_apply_runtime_segment_lowering_promotes_only_binary_proven_pointer_argument \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py \
	angr_platforms/tests/test_x86_16_heapsort_widening_regression.py \
	angr_platforms/tests/test_x86_16_global_declarations.py \
	angr_platforms/tests/test_x86_16_direct_stack_update_groups.py \
	angr_platforms/tests/test_x86_16_segmented_global_loads.py \
	angr_platforms/tests/test_x86_16_decompilation_cache_surface.py \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_heapsort_callsites_materialized_in_c_order \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_percolateup_materializes_parent_once_and_preserves_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_percolateup_anchor_no_longer_crashes_on_vexvalue_register_resolution \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_acceptance_scorecards_capture_main_sleep_and_percolateup_state \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_reinitbars_preserves_clock_store_loop_and_validation_contract \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_drawtime_materializes_clock_return_to_clfinish_once \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_reinitbars_stable_stack_slot_irow_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initmenu_pause_zero_guard_has_no_raw_flag_carrier \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_insertionsort_word_stores_materialized_without_raw_high_byte_memory \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_drawbar_word_stride_byte_fields_validate_without_indexed_mem_helper_syntax \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_percolatedown_direct_global_increment_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_reinitbars_recurrence_rebound_to_irow \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_call_arguments_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_does_not_pointer_promote_irow2_or_emit_dead_setup_artifacts \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swaps_preserves_binary_proven_global_increment_and_pointer_swap \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_bubblesort_sidecar_free_preserves_direct_ds_row_count \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_exchangesort_sidecar_free_folds_alias_proven_high_byte \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawbar_sidecar_free_materializes_stack_buffer_and_void_return \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawframe_sidecar_free_materializes_segmented_buffer_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_reinitbars_sidecar_free_materializes_indexed_global_copy \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawtime_sidecar_free_materializes_wide_delay_arguments \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_insertionsort_sidecar_free_splits_header_and_rebases_source \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_initmenu_sidecar_free_preserves_calls_and_compiles \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_runmenu_default_direct_path_validates_without_temp_carrier_fallback \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py::test_normalize_call_target_names_drops_detached_angr_callee_func \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py::test_callsite_stats_count_stale_target_rejection \
	angr_platforms/tests/test_x86_16_access_trait_arrays.py \
	angr_platforms/tests/test_x86_16_access_trait_policy.py \
	angr_platforms/tests/test_x86_16_access_trait_strides.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py \
	angr_platforms/tests/test_x86_16_segmented_memory.py \
	angr_platforms/tests/test_x86_16_type_equivalence_classes.py

PYRIGHT_SELECTED_FILES := $(filter $(QA_TYPED_FILES),$(PY_FILES))
PYRIGHT_SKIPPED_FILES := $(filter-out $(QA_TYPED_FILES),$(PY_FILES))
RUFF_SELECTED_FILES := $(filter $(QA_RUFF_TARGETS),$(PY_FILES))
RUFF_SKIPPED_FILES := $(filter-out $(QA_RUFF_TARGETS),$(PY_FILES))
QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))
TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)

pytest:
	INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-4} $(PYTHON) -m pytest -q $(PYTEST_ARGS) $(QA_PYTEST_TARGETS)

pytest-files:
	@manifest_tests="$$( $(PYTHON) scripts/test_ownership_manifest.py $(PY_FILES) )"; \
	selected_tests="$$( \
		for test_target in $$manifest_tests $(PYTEST_FILES); do \
			printf '%s\n' "$$test_target"; \
		done | sort -u | tr '\n' ' ' \
	)"; \
	if [ -n "$$(echo "$$selected_tests" | tr -d '[:space:]')" ]; then \
		INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-4} $(PYTHON) -m pytest -q $(PYTEST_ARGS) $$selected_tests; \
	else \
		echo "pytest-files: no test files selected"; \
	fi

pytest-all:
	$(PYTHON) -m pytest -q $(PYTEST_ARGS)

architecture-check:
	$(PYTHON) scripts/check_decompiler_architecture.py

agent-context-check:
	$(PYTHON) scripts/agent_context_check.py

test-ownership-check:
	$(PYTHON) scripts/test_ownership_manifest.py --check

ruff:
	$(PYTHON) -m ruff check --fix $(QA_RUFF_TARGETS)

ruff-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'ruff-files: no Python files selected'; exit 0)
	@if [ -n "$(strip $(RUFF_SELECTED_FILES))" ]; then \
		$(PYTHON) -m ruff check --fix $(RUFF_SELECTED_FILES); \
	else \
		echo "ruff-files: no promoted Ruff files selected"; \
	fi
	@if [ -n "$(strip $(RUFF_SKIPPED_FILES))" ]; then \
		echo "ruff-files: skipped legacy files not in QA_RUFF_TARGETS: $(RUFF_SKIPPED_FILES)"; \
	fi

ruff-all:
	$(PYTHON) -m ruff check --fix $(PY_FILES_ALL)

pyright:
	$(PYTHON) -m pyright $(QA_TYPED_FILES)

pyright-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'pyright-files: no Python files selected'; exit 0)
	@if [ -n "$(strip $(PYRIGHT_SELECTED_FILES))" ]; then \
		$(PYTHON) -m pyright $(PYRIGHT_SELECTED_FILES); \
	else \
		echo "pyright-files: no promoted typed files selected"; \
	fi
	@if [ -n "$(strip $(PYRIGHT_SKIPPED_FILES))" ]; then \
		echo "pyright-files: skipped legacy files not in QA_TYPED_FILES: $(PYRIGHT_SKIPPED_FILES)"; \
	fi

type-ratchet-files:
	@if [ -z "$(strip $(PY_FILES))" ]; then \
		echo 'type-ratchet-files: no Python files selected'; \
	else \
		$(PYTHON) scripts/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES); \
	fi

type-ratchet-changed:
	@if [ -n "$(strip $(QA_CHANGED_TYPED_FILES))" ]; then \
		$(PYTHON) scripts/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES); \
	else \
		echo "type-ratchet-changed: no changed promoted typed Python files selected"; \
	fi

pyright-all:
	$(PYTHON) -m pyright

vulture:
	$(PYTHON) -m vulture $(QA_TYPED_FILES)

radon:
	$(PYTHON) -m radon cc scripts inertia_decompiler --show-complexity --min C

test-pipeline:
	$(PYTHON) scripts/test_pipeline.py --require-external

test-pipeline-fast:
	$(PYTHON) scripts/test_pipeline.py --tier fast --require-external

test-pipeline-expanded:
	$(PYTHON) scripts/test_pipeline.py --tier expanded --require-external

msc6-examples:
	INERTIA_ENABLE_TAIL_VALIDATION=1 INERTIA_DISABLE_TIMING=1 $(PYTHON) scripts/build_msc6_examples.py --skip-constructs medium_structs,enum_union --decompile-mode functions --decompile-max-functions 0 --decompile-timeout 60 --decompile-run-timeout 600

sortdemo-selftest:
	$(PYTHON) scripts/build_sortdemo_selftest.py --clean

monkeytype-trace:
	$(PYTHON) scripts/collect_monkeytype_pytest.py

monkeytype-stubs:
	$(PYTHON) scripts/export_monkeytype_stubs.py

monkeytype-apply:
	$(PYTHON) scripts/apply_monkeytype_annotations.py

types: monkeytype-trace monkeytype-apply
