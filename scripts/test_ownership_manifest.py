#!/usr/bin/env python3
"""Focused test ownership manifest for changed-file checks.

Layer: Tooling/gates.
Responsibility: map changed files to focused fast ownership tests.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .pytest_source_index import PytestSourceIndex, load_pytest_source_index
else:
    from pytest_source_index import PytestSourceIndex, load_pytest_source_index

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
VALID_OWNERSHIP_TIERS: frozenset[str] = frozenset({"fast"})
FAST_PYTEST_SKIP_CALLS: frozenset[str] = frozenset(
    (
        "pytest.mark.skip",
        "pytest.mark.skipif",
        "pytest.mark.xfail",
        "pytest.skip",
        "pytest.xfail",
    )
)


@dataclass(frozen=True, slots=True)
class TestOwnershipRule:
    """Map a source path prefix to focused pytest targets."""

    owner: str
    paths: tuple[str, ...]
    tests: tuple[str, ...]
    tier: str = "fast"
    fallback: bool = False
    reason: str = ""

    def matches(self, path: str) -> bool:
        """Return whether this rule owns the changed source path."""

        normalized = path.replace("\\", "/")
        return any(normalized == prefix or normalized.startswith(f"{prefix}/") for prefix in self.paths)


@dataclass(frozen=True, slots=True)
class ManifestViolation:
    """Structured ownership-manifest validation failure."""

    owner: str
    target: str
    reason: str

    def format(self) -> str:
        """Render this validation failure for command-line output."""

        return f"{self.owner}: {self.target}: {self.reason}"


TEST_OWNERSHIP_RULES: tuple[TestOwnershipRule, ...] = (
    TestOwnershipRule(
        owner="generated-translation-unit-assembly",
        paths=(
            "inertia_decompiler/cli_batch_c_output.py",
            "inertia_decompiler/generated_external_function_contracts.py",
            "inertia_decompiler/generated_translation_unit_assembly.py",
            "scripts/generated_translation_unit_assembly.py",
        ),
        tests=(
            "angr_platforms/tests/test_cli_batch_c_output.py",
            "angr_platforms/tests/test_generated_translation_unit_assembly.py",
        ),
    ),
    TestOwnershipRule(
        owner="ghidra-function-coverage-diagnostics",
        paths=("scripts/compare_ghidra_function_coverage.py",),
        tests=("angr_platforms/tests/test_compare_ghidra_function_coverage.py",),
    ),
    TestOwnershipRule(
        owner="test-pipeline",
        paths=("scripts/check_sortd_sidecar_free.py", "scripts/test_pipeline.py"),
        tests=(
            "angr_platforms/tests/test_check_sortd_sidecar_free.py",
            "angr_platforms/tests/test_test_pipeline.py",
        ),
    ),
    TestOwnershipRule(
        owner="agent-context-check",
        paths=("scripts/agent_context_check.py",),
        tests=("angr_platforms/tests/test_agent_context_check.py",),
    ),
    TestOwnershipRule(
        owner="test-ownership-manifest",
        paths=(
            "scripts/pytest_assertion_facts.py",
            "scripts/pytest_source_index.py",
            "scripts/test_ownership_manifest.py",
        ),
        tests=(
            "angr_platforms/tests/test_pytest_source_index.py",
            "angr_platforms/tests/test_test_ownership_manifest.py",
        ),
    ),
    TestOwnershipRule(
        owner="pytest-performance-profile",
        paths=(
            "scripts/pytest_inventory_check.py",
            "scripts/pytest_inventory_review.py",
            "scripts/pytest_partition_execution.py",
            "scripts/pytest_partition_plugin.py",
            "scripts/pytest_partitioned.py",
            "scripts/pytest_process_metrics.py",
            "scripts/pytest_profile.py",
            "scripts/pytest_resource_history.py",
            "scripts/pytest_resource_scheduler.py",
            "scripts/pytest_test_inventory.py",
        ),
        tests=(
            "angr_platforms/tests/test_pytest_inventory_check.py",
            "angr_platforms/tests/test_pytest_partitioned.py",
            "angr_platforms/tests/test_pytest_process_metrics.py",
            "angr_platforms/tests/test_pytest_profile.py",
            "angr_platforms/tests/test_pytest_resource_scheduler.py",
        ),
    ),
    TestOwnershipRule(
        owner="type-ratchet",
        paths=("scripts/check_changed_non_test_types.py",),
        tests=("angr_platforms/tests/test_check_changed_non_test_types.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-alias-model-impl",
        paths=("angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_stack_lowering.py",
            "angr_platforms/tests/test_x86_16_alias_api_and_widening_proof.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-fact-transfer",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",),
    ),
    TestOwnershipRule(
        owner="cod-dir-runner",
        paths=("scripts/decompile_cod_dir.py",),
        tests=(
            "angr_platforms/tests/test_decompile_cod_dir_parallelism.py",
            "angr_platforms/tests/test_decompiler_architecture_check.py",
        ),
    ),
    TestOwnershipRule(
        owner="ultra-quickc-fixtures",
        paths=("scripts/import_ultra_quickc_fixtures.py",),
        tests=("angr_platforms/tests/test_import_ultra_quickc_fixtures.py",),
    ),
    TestOwnershipRule(
        owner="architecture-guard",
        paths=(
            "decompile.py",
            "inertia_decompiler/architecture_runtime_guard.py",
            "inertia_decompiler/cli.py",
            "inertia_decompiler/cli_core.py",
            "inertia_decompiler/serial_clean_worker_cli.py",
            "scripts/decompile_cod_dir.py",
            "scripts/check_decompiler_architecture.py",
        ),
        tests=("angr_platforms/tests/test_decompiler_architecture_check.py",),
    ),
    TestOwnershipRule(
        owner="serial-clean-worker-cache",
        paths=(
            "inertia_decompiler/cli_core.py",
            "inertia_decompiler/serial_worker_cache.py",
            "inertia_decompiler/segment_program_layout_reporting.py",
        ),
        tests=(
            "angr_platforms/tests/test_serial_clean_worker_cache.py",
            "angr_platforms/tests/test_segment_program_layout_reporting.py",
        ),
    ),
    TestOwnershipRule(
        owner="function-decompilation-cache-context",
        paths=(
            "inertia_decompiler/cache.py",
            "inertia_decompiler/cache_lock.py",
            "inertia_decompiler/function_cache_context.py",
            "inertia_decompiler/work_items.py",
        ),
        tests=(
            "angr_platforms/tests/test_cache_lock.py",
            "angr_platforms/tests/test_function_cache_context.py",
            "angr_platforms/tests/test_x86_16_decompilation_cache_surface.py",
        ),
    ),
    TestOwnershipRule(
        owner="cli-fork-timeout",
        paths=(
            "inertia_decompiler/fork_timeout.py",
            "inertia_decompiler/runtime_support.py",
        ),
        tests=("angr_platforms/tests/test_fork_timeout.py",),
    ),
    TestOwnershipRule(
        owner="cli-project-loading",
        paths=("inertia_decompiler/project_loading.py",),
        tests=("angr_platforms/tests/test_project_loading_cache.py",),
    ),
    TestOwnershipRule(
        owner="display-catalog-cache",
        paths=(
            "inertia_decompiler/cli_function_discovery.py",
            "inertia_decompiler/discovery_cache_contract.py",
        ),
        tests=("angr_platforms/tests/test_discovery_cache_contract.py",),
    ),
    TestOwnershipRule(
        owner="cli-regeneration",
        paths=(
            "inertia_decompiler/cli_decompilation.py",
            "inertia_decompiler/cli_semantic_rollback.py",
        ),
        tests=(
            "angr_platforms/tests/test_cli_regeneration.py",
            "angr_platforms/tests/test_cli_semantic_rollback.py",
        ),
    ),
    TestOwnershipRule(
        owner="cli-dead-local-prune",
        paths=("inertia_decompiler/cli_dead_local_prune.py",),
        tests=("angr_platforms/tests/test_x86_16_dead_local_prune.py",),
    ),
    TestOwnershipRule(
        owner="cli-timeout-policy",
        paths=("inertia_decompiler/cli_timeout.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_cli.py::test_adaptive_per_byte_timeout_model_scales_from_successes",
            "angr_platforms/tests/test_cli_core_clinic_policy.py",
        ),
    ),
    TestOwnershipRule(
        owner="rizin-discovery",
        paths=("inertia_decompiler/rizin_discovery.py",),
        tests=("angr_platforms/tests/test_rizin_discovery.py",),
    ),
    TestOwnershipRule(
        owner="cli-direct-fallback",
        paths=(
            "inertia_decompiler/cli_core.py",
            "inertia_decompiler/cli_fallback_decompilation.py",
            "angr_platforms/tests/test_x86_16_cli.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_cli.py::"
            "test_direct_addr_project_local_fallback_addr_uses_rebased_function_addr",
            "angr_platforms/tests/test_x86_16_cli.py::test_try_decompile_sidecar_slice_uses_extended_bounded_timeout",
        ),
    ),
    TestOwnershipRule(
        owner="quality-gate",
        paths=("inertia_decompiler/decompilation_quality.py", "angr_platforms/angr_platforms/X86_16/quality.py"),
        tests=(
            "angr_platforms/tests/test_decompilation_quality.py",
            "angr_platforms/tests/test_x86_16_generated_c_acceptance.py",
        ),
    ),
    TestOwnershipRule(
        owner="recompile-check",
        paths=("inertia_decompiler/recompile_check.py",),
        tests=("angr_platforms/tests/test_recompile_check.py",),
    ),
    TestOwnershipRule(
        owner="cod-comment-emitter",
        paths=("angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py",),
        tests=(
            "angr_platforms/tests/test_cod_metadata_output_policy.py::"
            "test_format_cod_comment_block_escapes_trailing_macro_backslash_for_c_comments",
        ),
    ),
    TestOwnershipRule(
        owner="cod-known-objects",
        paths=("angr_platforms/angr_platforms/X86_16/cod_known_objects.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_known_object_catalog_is_exposed",
            "angr_platforms/tests/test_x86_16_cod_regressions.py::"
            "test_cod_overlay_header_known_object_is_pointer_typed",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-runtime-compat",
        paths=("angr_platforms/angr_platforms/X86_16/compat.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_package_exports.py::test_x86_16_package_exports_source_backends",
            "angr_platforms/tests/test_x86_16_package_exports.py::test_x86_16_bootstrap_module_description",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-bootstrap",
        paths=("angr_platforms/angr_platforms/X86_16/bootstrap.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_package_exports.py::test_x86_16_bootstrap_module_exports",
            "angr_platforms/tests/test_x86_16_package_exports.py::test_x86_16_bootstrap_module_description",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-control-registers",
        paths=("angr_platforms/angr_platforms/X86_16/cr.py",),
        tests=("angr_platforms/tests/test_x86_16_cr.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-low-memory-diagnostics",
        paths=("angr_platforms/angr_platforms/X86_16/low_memory_regions.py",),
        tests=("angr_platforms/tests/test_x86_16_low_memory_regions.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-emulator-exceptions",
        paths=("angr_platforms/angr_platforms/X86_16/exception.py",),
        tests=("angr_platforms/tests/test_x86_16_exception.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-hardware-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/hardware.py",),
        tests=("angr_platforms/tests/test_x86_16_hardware.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-simprocs-io",
        paths=("angr_platforms/angr_platforms/X86_16/simprocs_io.py",),
        tests=("angr_platforms/tests/test_x86_16_simprocs_io.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-debug-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/debug.py",),
        tests=("angr_platforms/tests/test_x86_16_debug.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-device-io-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/dev_io.py",),
        tests=("angr_platforms/tests/test_x86_16_dev_io.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-io-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/io.py",),
        tests=("angr_platforms/tests/test_x86_16_io.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-emulator-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/emulator.py",),
        tests=("angr_platforms/tests/test_x86_16_emulator.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-memory-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/memory.py",),
        tests=("angr_platforms/tests/test_x86_16_memory.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-interrupt-runtime",
        paths=("angr_platforms/angr_platforms/X86_16/interrupt.py",),
        tests=("angr_platforms/tests/test_x86_16_interrupt.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-stack-compatibility",
        paths=("angr_platforms/angr_platforms/X86_16/stack_compat.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_compat.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-correctness-goals",
        paths=("angr_platforms/angr_platforms/X86_16/correctness_goals.py",),
        tests=("angr_platforms/tests/test_x86_16_correctness_goals.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-calling-convention-compat",
        paths=("angr_platforms/angr_platforms/X86_16/calling_convention_compat.py",),
        tests=("angr_platforms/tests/test_x86_16_calling_convention_compat.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-stack-parameter-width-lowering",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py",
            "angr_platforms/angr_platforms/X86_16/widening/stack_argument_widths.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_calling_convention_compat.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
            "angr_platforms/tests/test_x86_16_stack_argument_widths.py",
            "angr_platforms/tests/test_x86_16_stack_prototype_promotion.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-interprocedural-storage-contracts",
        paths=(
            "angr_platforms/angr_platforms/X86_16/caller_return_use_contracts.py",
            "angr_platforms/angr_platforms/X86_16/ir/function_ssa_registry.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_collection_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_function_solver.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_flow.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_paths.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_slot_join.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_pipeline.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_application.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_types.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_source_defs.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_defs.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_condition_graph.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_conditions.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_collection_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_materialization.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_collection.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_block.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_flow.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_types.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_defs.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_types.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_collection.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_solver.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_simtypes.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_transaction.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_caller_return_use_contracts.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_defs.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_passthrough.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_cfg.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_split.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_types.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py",
            "angr_platforms/tests/test_x86_16_interprocedural_memory_output_validation.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-wide-stack-condition-structuring",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/condition_fact_arbitration.py",
            "angr_platforms/angr_platforms/X86_16/lowering/condition_argument_type_facts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/condition_argument_types.py",
            "angr_platforms/angr_platforms/X86_16/lowering/condition_scalar_types.py",
            "angr_platforms/angr_platforms/X86_16/lowering/scalar_return_types.py",
            "angr_platforms/angr_platforms/X86_16/lowering/wide_stack_pair_evidence.py",
            "angr_platforms/angr_platforms/X86_16/structuring/branch_return_expressions.py",
            "angr_platforms/angr_platforms/X86_16/structuring/condition_binding.py",
            "angr_platforms/angr_platforms/X86_16/structuring/condition_ownership.py",
            "angr_platforms/angr_platforms/X86_16/structuring/condition_replay.py",
            "angr_platforms/angr_platforms/X86_16/structuring/multi_arm_return_chains.py",
            "angr_platforms/angr_platforms/X86_16/structuring/total_return_suffixes.py",
            "angr_platforms/angr_platforms/X86_16/structuring/wide_call_return_guard_chains.py",
            "angr_platforms/angr_platforms/X86_16/structuring/wide_stack_condition_chains.py",
            "angr_platforms/angr_platforms/X86_16/structuring/wide_stack_single_branches.py",
            "angr_platforms/angr_platforms/X86_16/validation_condition_precision.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_branch_return_expressions.py",
            "angr_platforms/tests/test_x86_16_condition_argument_types.py",
            "angr_platforms/tests/test_x86_16_condition_fact_arbitration.py",
            "angr_platforms/tests/test_x86_16_validation_condition_precision.py",
            "angr_platforms/tests/test_x86_16_msc6_cmp32_regression.py",
            "angr_platforms/tests/test_x86_16_multi_arm_return_chains.py",
            "angr_platforms/tests/test_x86_16_scalar_return_types.py",
            "angr_platforms/tests/test_x86_16_structuring_condition_binding.py",
            "angr_platforms/tests/test_x86_16_structuring_condition_ownership.py",
            "angr_platforms/tests/test_x86_16_structuring_condition_replay.py",
            "angr_platforms/tests/test_x86_16_total_return_suffixes.py",
            "angr_platforms/tests/test_x86_16_wide_call_return_guard_chains.py",
            "angr_platforms/tests/test_x86_16_wide_stack_condition_chains.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-function-pointer-parameter-lowering",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameter_evidence.py",
            "angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameters.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_function_pointer_parameters.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-analysis-helpers",
        paths=("angr_platforms/angr_platforms/X86_16/analysis_helpers.py",),
        tests=("angr_platforms/tests/test_x86_16_calling_convention_compat.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-readability-set",
        paths=("angr_platforms/angr_platforms/X86_16/readability_set.py",),
        tests=("angr_platforms/tests/test_x86_16_readability_set.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-readability-goals",
        paths=("angr_platforms/angr_platforms/X86_16/readability_goals.py",),
        tests=("angr_platforms/tests/test_x86_16_readability_goals.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-exports",
        paths=(
            "angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py",
            "angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_semantics_exports.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-evidence-cache",
        paths=("angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py",),
        tests=("angr_platforms/tests/test_x86_16_semantics_evidence_cache.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-expression-analysis",
        paths=("angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py",),
        tests=("angr_platforms/tests/test_x86_16_semantics_expression_analysis.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-alias-query",
        paths=("angr_platforms/angr_platforms/X86_16/semantics/alias_query.py",),
        tests=("angr_platforms/tests/test_x86_16_semantics_alias_query.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-alu",
        paths=("angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py",),
        tests=("angr_platforms/tests/test_x86_16_alu_helpers.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-condition-recovery",
        paths=("angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py",),
        tests=("angr_platforms/tests/test_x86_16_condition_ir.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-frontend-condition-evidence",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lift_86_16.py",
            "angr_platforms/angr_platforms/X86_16/ir/condition_ir.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_frontend_condition_evidence.py",
            "angr_platforms/tests/test_x86_16_condition_ir.py",
            "angr_platforms/tests/test_x86_16_lifter_condition_cache.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-semantics-stack-frame-recovery",
        paths=("angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_frame_recovery.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-stack-probe-return-facts",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-ss-bp-substitution",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-object-lowering",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py",),
        tests=("angr_platforms/tests/test_x86_16_object_lowering.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-ir-readiness",
        paths=("angr_platforms/angr_platforms/X86_16/ir_readiness.py",),
        tests=("angr_platforms/tests/test_x86_16_ir_readiness.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-layer-module-status",
        paths=("angr_platforms/angr_platforms/X86_16/layer_module_status.py",),
        tests=("angr_platforms/tests/test_x86_16_layer_module_status.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-coverage-manifest",
        paths=("angr_platforms/angr_platforms/X86_16/coverage_manifest.py",),
        tests=("angr_platforms/tests/test_x86_16_coverage_manifest.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recovery-manifest",
        paths=("angr_platforms/angr_platforms/X86_16/recovery_manifest.py",),
        tests=("angr_platforms/tests/test_x86_16_recovery_manifest.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recovery-artifacts",
        paths=("angr_platforms/angr_platforms/X86_16/recovery_artifacts.py",),
        tests=("angr_platforms/tests/test_x86_16_recovery_artifacts.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-function-effect-summary",
        paths=("angr_platforms/angr_platforms/X86_16/function_effect_summary.py",),
        tests=("angr_platforms/tests/test_x86_16_function_effect_summary.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-helper-effect-summary",
        paths=("angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",),
        tests=("angr_platforms/tests/test_x86_16_helper_effect_summary.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-helper-family-routing",
        paths=("angr_platforms/angr_platforms/X86_16/helper_family_routing.py",),
        tests=("angr_platforms/tests/test_x86_16_helper_family_routing.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-function-interface-surface",
        paths=("angr_platforms/angr_platforms/X86_16/function_interface_surface.py",),
        tests=("angr_platforms/tests/test_x86_16_function_interface_surface.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-function-state-summary",
        paths=("angr_platforms/angr_platforms/X86_16/function_state_summary.py",),
        tests=("angr_platforms/tests/test_x86_16_function_state_summary.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recovery-confidence",
        paths=("angr_platforms/angr_platforms/X86_16/recovery_confidence.py",),
        tests=("angr_platforms/tests/test_x86_16_recovery_confidence_helper_summary.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recovery-artifact-cache",
        paths=("angr_platforms/angr_platforms/X86_16/recovery_artifact_cache.py",),
        tests=("angr_platforms/tests/test_x86_16_recovery_artifact_cache.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-ir-recovery-summary",
        paths=("angr_platforms/angr_platforms/X86_16/ir_recovery_summary.py",),
        tests=("angr_platforms/tests/test_x86_16_ir_recovery_summary.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recovery-artifact-manifest",
        paths=("angr_platforms/angr_platforms/X86_16/recovery_artifact_manifest.py",),
        tests=("angr_platforms/tests/test_x86_16_recovery_artifact_manifest.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recovery-artifact-writer",
        paths=("angr_platforms/angr_platforms/X86_16/recovery_artifact_writer.py",),
        tests=("angr_platforms/tests/test_x86_16_recovery_artifact_writer.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-targeted-recovery-artifact",
        paths=("angr_platforms/angr_platforms/X86_16/targeted_recovery_artifact.py",),
        tests=("angr_platforms/tests/test_x86_16_targeted_recovery_artifact.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-corpus-recovery-artifact",
        paths=("angr_platforms/angr_platforms/X86_16/corpus_recovery_artifact.py",),
        tests=("angr_platforms/tests/test_x86_16_corpus_recovery_artifact.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-corpus-scan-timeout",
        paths=("angr_platforms/angr_platforms/X86_16/corpus_scan.py",),
        tests=("angr_platforms/tests/test_x86_16_corpus_scan_timeout.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-alias-stack-lowering-bridge",
        paths=("angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py",),
        tests=("angr_platforms/tests/test_x86_16_alias_stack_lowering.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-alias-domains",
        paths=("angr_platforms/angr_platforms/X86_16/alias/domains.py",),
        tests=("angr_platforms/tests/test_x86_16_alias_domains.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-alias-condition-register-carriers",
        paths=("angr_platforms/angr_platforms/X86_16/alias/condition_register_carriers.py",),
        tests=("angr_platforms/tests/test_x86_16_condition_register_carriers.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-alias-state-transfer",
        paths=(
            "angr_platforms/angr_platforms/X86_16/alias/state.py",
            "angr_platforms/angr_platforms/X86_16/alias/transfer.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_alias_state_transfer.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-condition-rendering",
        paths=("angr_platforms/angr_platforms/X86_16/structuring/condition_rendering.py",),
        tests=("angr_platforms/tests/test_x86_16_condition_rendering.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-condition-lowering",
        paths=("angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py",),
        tests=("angr_platforms/tests/test_x86_16_condition_lowering.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-condition-materialization",
        paths=(
            "angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py",
            "angr_platforms/angr_platforms/X86_16/structuring/multi_arm_condition_ownership.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_structuring_condition_materialization.py",
            "angr_platforms/tests/test_x86_16_structuring_multi_arm_condition_ownership.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-call-output-stack-objects",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_carriers.py",
            "angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_call_execution_frame_carriers.py",
            "angr_platforms/tests/test_x86_16_call_output_stack_objects.py",
            "angr_platforms/tests/test_x86_16_sortd_sleep_regression.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-loop-body-repair",
        paths=("angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py",),
        tests=("angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-switch-loop-tail-breaks",
        paths=(
            "angr_platforms/angr_platforms/X86_16/structuring/switch_loop_tail_breaks.py",
            "angr_platforms/angr_platforms/X86_16/validation_switch_loop_tail_breaks.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_switch_loop_tail_breaks.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-loop-break-jcc",
        paths=("angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py",),
        tests=("angr_platforms/tests/test_x86_16_structuring_loop_break_jcc.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-simple-loop-recovery",
        paths=("angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py",),
        tests=("angr_platforms/tests/test_x86_16_simple_loop_recovery.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-address-ir",
        paths=("angr_platforms/angr_platforms/X86_16/ir/address_ir.py",),
        tests=("angr_platforms/tests/test_x86_16_address_ir.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-segment-contract-ir",
        paths=("angr_platforms/angr_platforms/X86_16/ir/segment_contract.py",),
        tests=("angr_platforms/tests/test_x86_16_segment_contract.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-segment-function-summary",
        paths=("angr_platforms/angr_platforms/X86_16/segment_function_summary.py",),
        tests=("angr_platforms/tests/test_x86_16_segment_function_summary.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-segment-program-layout",
        paths=(
            "angr_platforms/angr_platforms/X86_16/segment_program_layout.py",
            "angr_platforms/angr_platforms/X86_16/segment_program_layout_codec.py",
            "angr_platforms/angr_platforms/X86_16/segment_program_layout_contract.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_segment_program_layout.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-segment-state-ir",
        paths=("angr_platforms/angr_platforms/X86_16/ir/segment_state.py",),
        tests=("angr_platforms/tests/test_x86_16_segment_state.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-segment-stack-restoration",
        paths=(
            "angr_platforms/angr_platforms/X86_16/alias/segment_stack_fragments.py",
            "angr_platforms/angr_platforms/X86_16/alias/segment_stack_restore.py",
            "angr_platforms/angr_platforms/X86_16/ir/segment_state_solver.py",
            "angr_platforms/angr_platforms/X86_16/ir/segment_state_transfer.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_segment_stack_restore.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-vex-import-ir",
        paths=(
            "angr_platforms/angr_platforms/X86_16/ir/block_ownership.py",
            "angr_platforms/angr_platforms/X86_16/ir/vex_import.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_vex_import.py",
            "angr_platforms/tests/test_x86_16_vex_import_cfg_successors.py",
        ),
    ),
    TestOwnershipRule(
        owner="callee-name-normalization",
        paths=("angr_platforms/angr_platforms/X86_16/callee_name_normalization.py",),
        tests=("angr_platforms/tests/test_x86_16_callee_name_normalization.py",),
    ),
    TestOwnershipRule(
        owner="exact-region-diagnostics",
        paths=("angr_platforms/angr_platforms/X86_16/exact_region_diagnostics.py",),
        tests=("angr_platforms/tests/test_x86_16_exact_region_diagnostics.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-frontend-instruction-reachability",
        paths=("angr_platforms/angr_platforms/X86_16/frontend_instruction_reachability.py",),
        tests=("angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py",),
    ),
    TestOwnershipRule(
        owner="exact-instruction-recovery-coverage",
        paths=(
            "angr_platforms/angr_platforms/X86_16/recovery_instruction_coverage.py",
            "angr_platforms/angr_platforms/X86_16/pipeline/recovery_coverage_guard.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_exact_region_diagnostics.py",
            "angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py",
        ),
    ),
    TestOwnershipRule(
        owner="postprocess-inventory",
        paths=("angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_package_exports.py::test_x86_16_decompiler_postprocess_inventory_exports",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_contract_is_clean",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_contract_reports_violations",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_classifies_condition_debt",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_fails_closed_for_semantic_names",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_routes_semantic_debt_to_plan_steps",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_requires_semantic_evidence_counters",
            "angr_platforms/tests/test_x86_16_package_exports.py::"
            "test_x86_16_decompiler_postprocess_inventory_keeps_cleanup_categories_distinct",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-ir-condition-cache-relift",
        paths=("angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py",),
        tests=("angr_platforms/tests/test_x86_16_condition_cache_relift.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-condition-transfer",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_condition_cache_relift.py",
            "angr_platforms/tests/test_x86_16_condition_transfer.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-call-return-selectors",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py",),
        tests=("angr_platforms/tests/test_x86_16_call_return_selectors.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-stack-coordinator",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-stack-from-facts",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa.py",
            "angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/stack_projection_retirement.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",
            "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-dead-register-carriers",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/dead_register_carriers.py",),
        tests=("angr_platforms/tests/test_x86_16_lowered_register_carriers.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-pointer-memory-idioms",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_pointer_memory_idioms.py",
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_return_chain.py::"
            "test_pointer_memory_idiom_postprocess_fallback_refuses_after_lowering_pass",
            "angr_platforms/tests/test_x86_16_structuring_pass_validation.py::"
            "test_structuring_pointer_memory_idiom_owner_records_pass",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-return-compat-counters",
        paths=("angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py",),
        tests=("angr_platforms/tests/test_x86_16_return_compat_counters.py",),
    ),
    TestOwnershipRule(
        owner="msc6-toolchain-lock",
        paths=(
            "scripts/build_msc6_examples.py",
            "scripts/msc6_toolchain_lock.py",
        ),
        tests=("angr_platforms/tests/test_msc6_toolchain_lock.py",),
    ),
    TestOwnershipRule(
        owner="msc6-runtime-gate",
        paths=(
            "scripts/msc6_runtime_gate_artifacts.py",
            "scripts/verify_msc_example_runtime_gate.py",
        ),
        tests=(
            "angr_platforms/tests/test_msc6_runtime_gate_artifacts.py",
            "angr_platforms/tests/test_build_msc6_examples.py::test_runtime_gate_links_generic_runtime_support",
            "angr_platforms/tests/test_build_msc6_examples.py::"
            "test_runtime_gate_decompiles_functions_with_bounded_parallelism",
            "angr_platforms/tests/test_build_msc6_examples.py::test_runtime_gate_decompile_worker_count_is_bounded",
            "angr_platforms/tests/test_build_msc6_examples.py::"
            "test_runtime_gate_worker_control_is_not_forwarded_to_decompiler",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-cod-module-caller-evidence",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/callee_argument_width_evidence.py",
            "inertia_decompiler/cod_module_caller_evidence.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_cod_module_caller_evidence.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-callee-global-object-interface",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_census.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_argument_count_evidence.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_collection.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_evidence.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_interface.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_sources.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_type_surface.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_evidence.py",
            "angr_platforms/angr_platforms/X86_16/lowering/indexed_global_evidence.py",
            "angr_platforms/angr_platforms/X86_16/lowering/near_pointer_type.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_callee_argument_count_evidence.py",
            "angr_platforms/tests/test_x86_16_callee_global_object_interface.py",
            "angr_platforms/tests/test_x86_16_callee_global_object_sources.py",
            "angr_platforms/tests/test_x86_16_callee_pointer_evidence.py",
        ),
    ),
    TestOwnershipRule(
        owner="segmented-global-loads",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/cod_global_identity.py",
            "angr_platforms/angr_platforms/X86_16/lowering/segmented_global_loads.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_cod_global_identity.py",
            "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
            "angr_platforms/tests/test_x86_16_project_type_contracts.py",
            "angr_platforms/tests/test_x86_16_sortd_indexed_aggregate_regression.py",
            "angr_platforms/tests/test_x86_16_sortd_menu_pointer_table.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-direct-global-semantic-facts",
        paths=(
            "angr_platforms/angr_platforms/X86_16/semantics/direct_call_result_storage.py",
            "angr_platforms/angr_platforms/X86_16/semantics/direct_global_ordering.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_project_type_contracts.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-project-global-object-layout",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/project_global_object_layout.py",
            "angr_platforms/angr_platforms/X86_16/widening/global_object_layout.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_global_object_layout.py",
            "angr_platforms/tests/test_x86_16_project_type_contracts.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-segment-global-materialization",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/segment_global_materialization.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
            "angr_platforms/tests/test_x86_16_structuring_pass_validation.py",
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_return_chain.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-segmented",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py",),
        tests=("angr_platforms/tests/test_x86_16_segmented_lowering.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-segmented-runtime",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument.py",
            "angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py",
            "angr_platforms/angr_platforms/X86_16/lowering/stack_pointer_snapshot.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
            "angr_platforms/tests/test_x86_16_stack_pointer_snapshot.py",
        ),
    ),
    TestOwnershipRule(
        owner="c-runtime-header",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/c_runtime_header.py",),
        tests=("angr_platforms/tests/test_x86_16_c_runtime_header.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-software-interrupt-pipeline",
        paths=(
            "angr_platforms/angr_platforms/X86_16/interrupt_contract.py",
            "angr_platforms/angr_platforms/X86_16/ir/vex_control_flow.py",
            "angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_calls.py",
            "angr_platforms/angr_platforms/X86_16/semantics/software_interrupt_inputs.py",
            "angr_platforms/angr_platforms/X86_16/structuring/software_interrupt_returns.py",
            "angr_platforms/angr_platforms/X86_16/validation_interrupt_calls.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_software_interrupt_pipeline.py",
            "angr_platforms/tests/test_x86_16_software_interrupt_validation.py",
            "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_small_cod_byte_condition_logic",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-small-cod-control-flow",
        paths=("angr_platforms/angr_platforms/X86_16/cod_extract.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_cod_extract_control_flow.py",
            "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_small_cod_byte_condition_logic",
        ),
    ),
    TestOwnershipRule(
        owner="real-mode-linear-lowering",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callsite_segment_provenance.py",
            "angr_platforms/angr_platforms/X86_16/lowering/segment_access_coverage.py",
            "angr_platforms/angr_platforms/X86_16/lowering/segment_access_policy.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_consumed_push_lvalues.py",
            "angr_platforms/tests/test_x86_16_segment_access_coverage.py",
            "angr_platforms/tests/test_x86_16_segment_access_policy.py",
            "angr_platforms/tests/test_x86_16_segment_address_policy.py",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_materialize_direct_stack_mov_signed_half_inserts_before_outer_branch_first_use",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_materialize_direct_stack_mov_signed_half_inserts_before_first_stack_use_without_tagged_stmt",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_materialize_direct_stack_mov_arg_copy_inserts_inside_else_after_prior_stack_assignment",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-protected-call-arguments",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/call_argument_state.py",),
        tests=("angr_platforms/tests/test_x86_16_protected_call_arguments.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-stack-aggregate-objects",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py",),
        tests=("angr_platforms/tests/test_x86_16_stack_aggregate_objects.py",),
    ),
    TestOwnershipRule(
        owner="pipeline-contracts",
        paths=("angr_platforms/angr_platforms/X86_16/pipeline/contracts.py",),
        tests=("angr_platforms/tests/test_x86_16_pipeline_contracts.py",),
    ),
    TestOwnershipRule(
        owner="pipeline-invariants",
        paths=("angr_platforms/angr_platforms/X86_16/pipeline/invariants.py",),
        tests=("angr_platforms/tests/test_x86_16_rewrite_boundary.py",),
    ),
    TestOwnershipRule(
        owner="pipeline-architecture-final-emission-guard",
        paths=("angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_architecture_guard_rejects_raw_linear_segment_arithmetic",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_architecture_guard_ignores_forbidden_tokens_inside_comments",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_architecture_guard_rejects_unreachable_call_after_return",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_architecture_guard_rejects_unary_not_shift_precedence_leak",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-semantics",
        paths=("angr_platforms/angr_platforms/X86_16/validation_semantics.py",),
        tests=("angr_platforms/tests/test_x86_16_validation_semantics.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-dataflow",
        paths=(
            "angr_platforms/angr_platforms/X86_16/validation_dataflow.py",
            "angr_platforms/angr_platforms/X86_16/validation_predicates.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_validation_dataflow.py",
            "angr_platforms/tests/test_x86_16_validation_predicates.py",
            "angr_platforms/tests/test_x86_16_validation_virtual_carriers.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-semantic-failures",
        paths=("angr_platforms/angr_platforms/X86_16/validation_semantic_failures.py",),
        tests=("angr_platforms/tests/test_x86_16_validation_semantic_failures.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-call-target-identity",
        paths=("angr_platforms/angr_platforms/X86_16/call_target_identity.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_call_output_stack_objects.py::"
            "test_wide_call_return_condition_binds_direct_callee_from_typed_summary",
            "angr_platforms/tests/test_x86_16_validation_calls.py::"
            "test_required_callsite_validation_matches_rebased_slice_target_identity",
            "angr_platforms/tests/test_x86_16_validation_calls.py::"
            "test_required_callsite_validation_refuses_unrelated_rebased_slice_target",
            "angr_platforms/tests/test_x86_16_tail_validation.py::"
            "test_tail_validation_normalizes_exact_slice_call_target_to_original_addr",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-calls",
        paths=(
            "angr_platforms/angr_platforms/X86_16/validation_calls.py",
            "angr_platforms/angr_platforms/X86_16/validation_call_multiplicity.py",
            "angr_platforms/angr_platforms/X86_16/validation_call_argument_sources.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_validation_calls.py",
            "angr_platforms/tests/test_x86_16_validation_call_multiplicity.py",
            "angr_platforms/tests/test_x86_16_validation_call_argument_sources.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-call-argument-stack-sources",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/call_argument_stack_sources.py",),
        tests=("angr_platforms/tests/test_x86_16_validation_call_argument_sources.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-control-flow",
        paths=(
            "angr_platforms/angr_platforms/X86_16/validation_branch_conditions.py",
            "angr_platforms/angr_platforms/X86_16/validation_condition_identity.py",
            "angr_platforms/angr_platforms/X86_16/validation_control_flow.py",
            "angr_platforms/angr_platforms/X86_16/validation_control_flow_obligations.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_validation_branch_conditions.py",
            "angr_platforms/tests/test_x86_16_validation_control_flow.py",
            "angr_platforms/tests/test_x86_16_validation_loop_condition_ir.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-storage",
        paths=("angr_platforms/angr_platforms/X86_16/validation_storage.py",),
        tests=("angr_platforms/tests/test_x86_16_validation_storage.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-required-memory-effects",
        paths=(
            "angr_platforms/angr_platforms/X86_16/validation_aggregate_storage.py",
            "angr_platforms/angr_platforms/X86_16/validation_required_memory_effects.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_tail_validation_fingerprint.py",
            "angr_platforms/tests/test_x86_16_validation_required_memory_effects.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-lowering-storage-identity-facts",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_validation_storage.py",
            "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
            "test_materialize_direct_global_inc_instruction_from_binary_evidence",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-callsite-prototype-declarations",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py",
            "angr_platforms/angr_platforms/X86_16/lowering/callsite_pointer_tables.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_callsite_prototype_declarations.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
            "angr_platforms/tests/test_x86_16_callsite_pointer_tables.py",
            "angr_platforms/tests/test_x86_16_project_type_contracts.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-signed-global-declarations",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/project_global_signedness.py",
            "angr_platforms/angr_platforms/X86_16/lowering/signed_global_declarations.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_project_type_contracts.py",
            "angr_platforms/tests/test_x86_16_signed_global_declarations.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-return-type-evidence",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py",),
        tests=("angr_platforms/tests/test_x86_16_return_type_evidence.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-unobserved-return-lowering",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/unobserved_returns.py",
            "angr_platforms/angr_platforms/X86_16/lowering/unused_void_return_types.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_return_type_evidence.py",
            "angr_platforms/tests/test_x86_16_terminal_register_return_types.py",
            "angr_platforms/tests/test_x86_16_unused_void_return_types.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-terminal-return-lowering",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_values.py",
            "angr_platforms/angr_platforms/X86_16/lowering/terminal_return_expressions.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_terminal_register_return_values.py",
            "angr_platforms/tests/test_x86_16_terminal_return_expression_scaling.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-stack-memory-ssa",
        paths=(
            "angr_platforms/angr_platforms/X86_16/alias/stack_memory_access_projection.py",
            "angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa.py",
            "angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa_contracts.py",
            "angr_platforms/angr_platforms/X86_16/ir/ssa_memory.py",
            "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_contracts.py",
            "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_ranges.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_ir_memory_byte_ssa.py",
            "angr_platforms/tests/test_x86_16_ir_ssa.py",
            "angr_platforms/tests/test_x86_16_stack_memory_ssa_alias.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-frame-carrier-lowering",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/callee_saved_frame.py",
            "angr_platforms/angr_platforms/X86_16/lowering/frame_prologue_carriers.py",
            "angr_platforms/angr_platforms/X86_16/lowering/physical_registers.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_callee_saved_frame.py",
            "angr_platforms/tests/test_x86_16_canonical_frame_carriers.py",
            "angr_platforms/tests/test_x86_16_terminal_register_return_values.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-terminal-memory-output-semantics",
        paths=(
            "angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_output_contracts.py",
            "angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_outputs.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_terminal_memory_outputs.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-terminal-memory-output-alias",
        paths=(
            "angr_platforms/angr_platforms/X86_16/alias/terminal_memory_outputs.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-terminal-memory-output-widening",
        paths=(
            "angr_platforms/angr_platforms/X86_16/widening/terminal_memory_output_views.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_terminal_memory_output_views.py",
            "angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-interprocedural-memory-output-objects",
        paths=(
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_object_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_objects.py",
            "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_validation.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_interprocedural_memory_output_objects.py",
            "angr_platforms/tests/test_x86_16_interprocedural_memory_output_validation.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py",
            "angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-call-semantics",
        paths=(
            "angr_platforms/angr_platforms/X86_16/semantics/call_output_contracts.py",
            "angr_platforms/angr_platforms/X86_16/semantics/call_outputs.py",
            "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_contracts.py",
            "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_pipeline.py",
            "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effects.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_call_outputs.py",
            "angr_platforms/tests/test_x86_16_call_stack_effects.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-ir-ssa",
        paths=(
            "angr_platforms/angr_platforms/X86_16/ir/ssa.py",
            "angr_platforms/angr_platforms/X86_16/ir/ssa_function.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_ir_ssa.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-indexed-address-evidence",
        paths=(
            "angr_platforms/angr_platforms/X86_16/ir/__init__.py",
            "angr_platforms/angr_platforms/X86_16/ir/core.py",
            "angr_platforms/angr_platforms/X86_16/ir/indexed_address_contracts.py",
            "angr_platforms/angr_platforms/X86_16/ir/indexed_address_evidence.py",
            "angr_platforms/angr_platforms/X86_16/ir/ssa.py",
            "angr_platforms/angr_platforms/X86_16/ir/vex_addressing.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_indexed_address_evidence.py",
            "angr_platforms/tests/test_x86_16_ir_core.py",
            "angr_platforms/tests/test_x86_16_ir_ssa.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-carry-borrow-widening",
        paths=(
            "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_contracts.py",
            "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_destinations.py",
            "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_projection.py",
            "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_sources.py",
            "angr_platforms/angr_platforms/X86_16/alias/storage_fact_join.py",
            "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_stack_storage.py",
            "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_ast.py",
            "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_contracts.py",
            "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_evidence.py",
            "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_placement.py",
            "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignments.py",
            "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_cfg.py",
            "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_contracts.py",
            "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py",
            "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py",
            "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_pipeline.py",
            "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_storage.py",
            "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_values.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_carry_borrow_call_output.py",
            "angr_platforms/tests/test_x86_16_wide_call_output_assignments.py",
            "angr_platforms/tests/test_x86_16_carry_borrow_cfg.py",
            "angr_platforms/tests/test_x86_16_carry_borrow_sources.py",
            "angr_platforms/tests/test_x86_16_carry_borrow_stack_storage.py",
            "angr_platforms/tests/test_x86_16_carry_borrow_widening.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-terminal-register-return-semantics",
        paths=(
            "angr_platforms/angr_platforms/X86_16/semantics/terminal_call_paths.py",
            "angr_platforms/angr_platforms/X86_16/semantics/terminal_register_returns.py",
            "angr_platforms/angr_platforms/X86_16/semantics/terminal_return_passthrough.py",
            "angr_platforms/angr_platforms/X86_16/semantics/terminal_return_storage.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_terminal_call_return_types.py",
            "angr_platforms/tests/test_x86_16_terminal_register_return_semantics.py",
            "angr_platforms/tests/test_x86_16_terminal_return_passthrough.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-stack-memory-object-widening",
        paths=(
            "angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects.py",
            "angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects_contracts.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_stack_memory_object_widening.py",
            "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-dce-optimization",
        paths=(
            "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py",
            "angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_liveness.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_dce_optimization.py",
            "angr_platforms/tests/test_x86_16_dce_lvalue_reads.py",
            "angr_platforms/tests/test_x86_16_local_liveness.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-c-ast-utils",
        paths=("angr_platforms/angr_platforms/X86_16/c_ast_utils.py",),
        tests=("angr_platforms/tests/test_x86_16_c_ast_utils.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-trivial-copy-optimization",
        paths=("angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py",),
        tests=("angr_platforms/tests/test_x86_16_trivial_copy_optimization.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-widening-copyprop",
        paths=("angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py",),
        tests=("angr_platforms/tests/test_x86_16_widening_copyprop.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-widening-memory-fold",
        paths=("angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py",),
        tests=("angr_platforms/tests/test_x86_16_widening_memory_fold.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-stack-subview-projection",
        paths=(
            "angr_platforms/angr_platforms/X86_16/widening/stack_subview_expression.py",
            "angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py",
            "angr_platforms/angr_platforms/X86_16/widening/stack_subview_proof.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_stack_subview_projection.py",
            "angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-widening-rules",
        paths=(
            "angr_platforms/angr_platforms/X86_16/widening/widening_rules.py",
            "angr_platforms/angr_platforms/X86_16/widening/word_projection_recomposition.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_widening_rules.py",),
    ),
    TestOwnershipRule(
        owner="ir-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/ir",),
        tests=("angr_platforms/tests/test_x86_16_ir_core.py",),
        fallback=True,
        reason="unowned IR changes still need core Value/Address/Condition contract coverage",
    ),
    TestOwnershipRule(
        owner="semantics-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/semantics",),
        tests=("angr_platforms/tests/test_x86_16_compare_semantics.py",),
        fallback=True,
        reason="unowned semantics changes still need instruction-effect equivalence coverage",
    ),
    TestOwnershipRule(
        owner="alias-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/alias",),
        tests=("angr_platforms/tests/test_x86_16_alias_api_and_widening_proof.py",),
        fallback=True,
        reason="unowned alias changes still need storage-identity and widening-proof coverage",
    ),
    TestOwnershipRule(
        owner="widening-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/widening",),
        tests=("angr_platforms/tests/test_x86_16_widening_model.py",),
        fallback=True,
        reason="unowned widening changes still need width/value propagation contract coverage",
    ),
    TestOwnershipRule(
        owner="lowering-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/lowering",),
        tests=(
            "angr_platforms/tests/test_x86_16_stack_lowering.py",
            "angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",
        ),
        fallback=True,
        reason="unowned lowering changes still need stack/object materialization contract coverage",
    ),
    TestOwnershipRule(
        owner="structuring-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/structuring",),
        tests=("angr_platforms/tests/test_x86_16_structuring_pass_validation.py",),
        fallback=True,
        reason="unowned structuring changes still need CFG-to-structured-pass validation coverage",
    ),
    TestOwnershipRule(
        owner="pipeline-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/pipeline",),
        tests=("angr_platforms/tests/test_x86_16_pipeline_contracts.py",),
        fallback=True,
        reason="unowned pipeline changes still need ordering and hard-failure contract coverage",
    ),
    TestOwnershipRule(
        owner="analysis-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/analysis",),
        tests=("angr_platforms/tests/test_x86_16_ir_stack_frame.py",),
        fallback=True,
        reason="unowned analysis changes still need stack-frame IR evidence coverage",
    ),
    TestOwnershipRule(
        owner="postprocess-package-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/postprocess",),
        tests=("angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py",),
        fallback=True,
        reason="unowned postprocess changes still need cleanup-only utility coverage",
    ),
    TestOwnershipRule(
        owner="validation-layer-fallback",
        paths=("angr_platforms/angr_platforms/X86_16/validation",),
        tests=("angr_platforms/tests/test_x86_16_validation_canonicalize.py",),
        fallback=True,
        reason="unowned validation changes still need canonical semantic comparison coverage",
    ),
    TestOwnershipRule(
        owner="x86-16-validation-manifest",
        paths=("angr_platforms/angr_platforms/X86_16/validation_manifest.py",),
        tests=("angr_platforms/tests/test_x86_16_validation_manifest.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-validation-helper-report",
        paths=("angr_platforms/angr_platforms/X86_16/validation_helper_report.py",),
        tests=("angr_platforms/tests/test_x86_16_validation_helper_report.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recompilable-source-evidence",
        paths=("angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py",),
        tests=("angr_platforms/tests/test_x86_16_recompilable_source_evidence.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recompilable-subset",
        paths=("angr_platforms/angr_platforms/X86_16/recompilable_subset.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_recompilable_subset.py::"
            "test_x86_16_recompilable_subset_description_is_stable",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-recompilable-storage-map",
        paths=(
            "angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py",
            "angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py",
            "angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_recompilable_storage_map.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-recompilable-storage-objects",
        paths=(
            "angr_platforms/angr_platforms/X86_16/recompilable_cli_bridge.py",
            "angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py",
            "angr_platforms/angr_platforms/X86_16/recompilable_storage_objects.py",
        ),
        tests=("angr_platforms/tests/test_x86_16_recompilable_storage_objects.py",),
    ),
    TestOwnershipRule(
        owner="tail-validation-family",
        paths=(
            "angr_platforms/angr_platforms/X86_16/tail_validation_condition_context.py",
            "angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py",
            "angr_platforms/angr_platforms/X86_16/tail_validation_stack_policy.py",
        ),
        tests=(
            "angr_platforms/tests/test_x86_16_tail_validation.py",
            "angr_platforms/tests/test_x86_16_tail_validation_fingerprint.py",
            "angr_platforms/tests/test_x86_16_tail_validation_routing.py",
        ),
    ),
    TestOwnershipRule(
        owner="tail-validation-routing",
        paths=("angr_platforms/angr_platforms/X86_16/tail_validation_routing.py",),
        tests=("angr_platforms/tests/test_x86_16_tail_validation_routing.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-grouping-report",
        paths=("angr_platforms/angr_platforms/X86_16/structuring_grouping_report.py",),
        tests=("angr_platforms/tests/test_x86_16_structuring_grouping_report.py",),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-stage-boundary",
        paths=("angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_structuring_stage_environment.py",
            "angr_platforms/tests/test_x86_16_structuring_pass_validation.py",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-structuring-grouped-refusal-report",
        paths=("angr_platforms/angr_platforms/X86_16/structuring_grouped_refusal_report.py",),
        tests=("angr_platforms/tests/test_x86_16_structuring_grouped_refusal_report.py",),
    ),
    TestOwnershipRule(
        owner="type-array-matching",
        paths=("angr_platforms/angr_platforms/X86_16/type_array_matching.py",),
        tests=("angr_platforms/tests/test_x86_16_array_matching.py",),
    ),
    TestOwnershipRule(
        owner="type-equivalence-classes",
        paths=("angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py",),
        tests=("angr_platforms/tests/test_x86_16_type_equivalence_classes.py",),
    ),
    TestOwnershipRule(
        owner="type-structure-merging",
        paths=("angr_platforms/angr_platforms/X86_16/type_structure_merging.py",),
        tests=("angr_platforms/tests/test_x86_16_struct_merging.py",),
    ),
    TestOwnershipRule(
        owner="structuring-sequences",
        paths=("angr_platforms/angr_platforms/X86_16/structuring_sequences.py",),
        tests=("angr_platforms/tests/test_x86_16_structuring_sequences.py",),
    ),
    TestOwnershipRule(
        owner="tail-validation",
        paths=("angr_platforms/angr_platforms/X86_16/tail_validation.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_validation_dataflow.py::"
            "test_tail_validation_refuses_def_use_failure_even_when_baseline_already_lost_definition",
            "angr_platforms/tests/test_x86_16_validation_control_flow.py::"
            "test_tail_validation_refuses_duplicate_guard_when_baseline_already_has_it",
            "angr_platforms/tests/test_x86_16_validation_storage.py::"
            "test_tail_validation_refuses_storage_loss_already_present_in_baseline",
            "angr_platforms/tests/test_x86_16_tail_validation.py::"
            "test_tail_validation_compare_suppresses_loop_body_local_stack_write_precision",
            "angr_platforms/tests/test_x86_16_tail_validation.py::"
            "test_tail_validation_compare_suppresses_added_loop_body_local_stack_write_precision",
            "angr_platforms/tests/test_x86_16_tail_validation.py::"
            "test_tail_validation_compare_keeps_loop_body_global_write_delta_observable",
        ),
    ),
    TestOwnershipRule(
        owner="postprocess-bridges",
        paths=(
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_jcc.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_loads.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_typed_conditions.py",
            "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py",
        ),
        tests=(
            "angr_platforms/tests/test_decompiler_architecture_check.py",
            "angr_platforms/tests/test_x86_16_jcc_instruction_reuse.py",
            "angr_platforms/tests/test_x86_16_jcc_typed_condition_order.py",
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py",
        ),
    ),
    TestOwnershipRule(
        owner="postprocess-stage-direct-stack-validation",
        paths=("angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_postprocess_snapshot.py::"
            "test_direct_stack_move_materialization_delta_accepts_evidenced_loop_body_write_precision",
            "angr_platforms/tests/test_x86_16_postprocess_snapshot.py::"
            "test_direct_stack_move_materialization_delta_accepts_for_body_global_high_byte_precision",
            "angr_platforms/tests/test_x86_16_postprocess_snapshot.py::"
            "test_direct_stack_move_materialization_delta_refuses_unrelated_for_body_global_precision",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-postprocess-flags-cleanup",
        paths=("angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py",),
        tests=("angr_platforms/tests/test_x86_16_decompiler_postprocess_flags.py",),
    ),
    TestOwnershipRule(
        owner="postprocess-callsite-arguments",
        paths=("angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
            "test_conservative_call_arg_seed_uses_known_default_for_zero_arg_helper_summary",
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
            "test_materialize_callsite_stack_arguments_refuses_direct_ds_byte_pair_store_prune",
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
            "test_materialize_callsite_stack_arguments_prunes_keep_existing_scalar_byte_pair_stores",
        ),
    ),
    TestOwnershipRule(
        owner="x86-16-runtime-segment-access",
        paths=("angr_platforms/angr_platforms/X86_16/lowering/runtime_segment_access.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_runtime_segment_access.py",
            "angr_platforms/tests/test_x86_16_sortd_indexed_aggregate_regression.py",
            "angr_platforms/tests/test_x86_16_validation_required_memory_effects.py",
            "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
            "test_materialize_callsite_stack_arguments_refuses_direct_ds_byte_pair_store_prune",
        ),
    ),
    TestOwnershipRule(
        owner="sortdemo-regression-promoted-anchors",
        paths=("angr_platforms/tests/test_x86_16_sortdemo_regressions.py",),
        tests=(
            "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::"
            "test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls",
        ),
    ),
)


def _normalize_input_path(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix()


def select_tests_for_files(files: tuple[str, ...]) -> tuple[str, ...]:
    """Return manifest-selected pytest targets for changed files."""
    selected: list[str] = []
    seen: set[str] = set()
    normalized_files = tuple(_normalize_input_path(path) for path in files if path.strip())
    for path in normalized_files:
        primary_rules = tuple(rule for rule in TEST_OWNERSHIP_RULES if rule.matches(path) and not rule.fallback)
        fallback_rules = tuple(rule for rule in TEST_OWNERSHIP_RULES if rule.matches(path) and rule.fallback)
        for rule in primary_rules or fallback_rules:
            if not rule.matches(path):
                continue
            for test in rule.tests:
                if test not in seen:
                    selected.append(test)
                    seen.add(test)
    return tuple(selected)


def _manifest_path_format_reason(path: str) -> str | None:
    """Return a validation reason when a manifest path is not repo-relative POSIX."""

    if not path:
        return "manifest paths must be non-empty"
    if "\\" in path:
        return "manifest paths must use POSIX '/' separators"
    if Path(path).is_absolute():
        return "manifest paths must be repository-relative"
    if path.startswith("./") or path.endswith("/"):
        return "manifest paths must omit leading './' and trailing '/'"
    if any(part in {"", ".", ".."} for part in path.split("/")):
        return "manifest paths must not contain empty, '.', or '..' segments"
    return None


def _pytest_target_path_reason(path: str) -> str | None:
    """Return why a manifest pytest target path is outside the focused test lane."""

    if not path.startswith("angr_platforms/tests/"):
        return "ownership pytest targets must stay under angr_platforms/tests/"
    if not Path(path).name.startswith("test_") or Path(path).suffix != ".py":
        return "ownership pytest targets must name test_*.py files"
    return None


def _fallback_reason_quality_reason(reason: str) -> str | None:
    """Return why a fallback reason is too vague for architectural ownership."""

    normalized = reason.lower()
    if "unowned" not in normalized or "coverage" not in normalized:
        return "fallback ownership reasons must mention unowned scope and coverage"
    return None


def validate_manifest_targets(rules: tuple[TestOwnershipRule, ...] | None = None) -> tuple[ManifestViolation, ...]:
    """Return invalid ownership rules or stale pytest targets."""
    rules = TEST_OWNERSHIP_RULES if rules is None else rules
    violations: list[ManifestViolation] = []
    seen_owners: set[str] = set()
    source_indexes: dict[Path, PytestSourceIndex] = {}
    for rule in rules:
        owner = rule.owner.strip()
        if not owner:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target="<owner>",
                    reason="ownership rule must name a non-empty owner",
                )
            )
        elif owner in seen_owners:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target="<owner>",
                    reason="ownership rule owner names must be unique",
                )
            )
        else:
            seen_owners.add(owner)
        if not rule.paths:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target="<paths>",
                    reason="ownership rule must include at least one source path",
                )
            )
        duplicate_paths = tuple(path for index, path in enumerate(rule.paths) if path in rule.paths[:index])
        for source_path in duplicate_paths:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target=source_path,
                    reason="ownership rule source paths must be unique within the rule",
                )
            )
        for source_path in rule.paths:
            format_reason = _manifest_path_format_reason(source_path)
            if format_reason is not None:
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target=source_path,
                        reason=format_reason,
                    )
                )
        if not rule.tests:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target="<tests>",
                    reason="ownership rule must include at least one pytest target",
                )
            )
        duplicate_tests = tuple(target for index, target in enumerate(rule.tests) if target in rule.tests[:index])
        for target in duplicate_tests:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target=target,
                    reason="ownership rule pytest targets must be unique within the rule",
                )
            )
        for target in rule.tests:
            test_path, _separator, _node_id = target.partition("::")
            format_reason = _manifest_path_format_reason(test_path)
            if format_reason is not None:
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target=target,
                        reason=format_reason,
                    )
                )
            target_path_reason = _pytest_target_path_reason(test_path)
            if target_path_reason is not None:
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target=target,
                        reason=target_path_reason,
                    )
                )
        for source_path in rule.paths:
            if not (REPO_ROOT / source_path).exists():
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target=source_path,
                        reason=f"source path does not exist: {source_path}",
                    )
                )
        if rule.tier not in VALID_OWNERSHIP_TIERS:
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target=rule.tier,
                    reason="focused ownership tests must stay in the fast tier; use test-pipeline tiers for slower coverage",
                )
            )
        if rule.fallback and not rule.reason.strip():
            violations.append(
                ManifestViolation(
                    owner=rule.owner,
                    target="<reason>",
                    reason="fallback ownership rules must explain their fast architectural coverage",
                )
            )
        elif rule.fallback:
            reason_quality = _fallback_reason_quality_reason(rule.reason)
            if reason_quality is not None:
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target="<reason>",
                        reason=reason_quality,
                    )
                )
        for target in rule.tests:
            test_path, _, node_id = target.partition("::")
            absolute_test_path = REPO_ROOT / test_path
            if not absolute_test_path.is_file():
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target=target,
                        reason=f"pytest file does not exist: {test_path}",
                    )
                )
                continue
            source_index = source_indexes.get(absolute_test_path)
            if source_index is None:
                source_index = load_pytest_source_index(absolute_test_path, FAST_PYTEST_SKIP_CALLS)
                source_indexes[absolute_test_path] = source_index
            if node_id and not source_index.has_node(node_id):
                violations.append(
                    ManifestViolation(
                        owner=rule.owner,
                        target=target,
                        reason=f"pytest node does not exist: {node_id}",
                    )
                )
            if rule.tier == "fast":
                for line_no in source_index.skip_xfail_lines(node_id):
                    violations.append(
                        ManifestViolation(
                            owner=rule.owner,
                            target=target,
                            reason=f"fast ownership pytest targets must not use skip/xfail at line {line_no}",
                        )
                    )
    return tuple(violations)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select focused pytest targets for changed files.")
    parser.add_argument("--check", action="store_true", help="validate that manifest pytest target files exist")
    parser.add_argument("files", nargs="*")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Select focused tests or validate the ownership manifest."""

    args = _parse_args(argv)
    if args.check:
        violations = validate_manifest_targets()
        for violation in violations:
            print(violation.format())
        return 1 if violations else 0
    print(" ".join(select_tests_for_files(tuple(args.files))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
