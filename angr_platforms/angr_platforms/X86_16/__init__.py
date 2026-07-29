"""Public package surface for the 16-bit x86 platform support.

Layer: Frontend/runtime package surface.
Responsibility: owns package initialization and public imports for X86_16.
"""

from __future__ import annotations

try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

import sys
from importlib import import_module
from typing import TYPE_CHECKING, Callable

__all__ = [
    "COD_SOURCE_REWRITE_REGISTRY",
    "CODSourceRewriteStatusKind",
    "annotations",
    "apply_x86_16_metadata_annotations",
    "arch_86_16",
    "cod_extract",
    "corpus_scan",
    "corpus_recovery_artifact",
    "structuring_grouped_units",
    "structuring_grouped_graph_builder",
    "structuring_grouped_pass",
    "structuring_cross_entry",
    "cod_source_rewrites",
    "apply_cod_source_rewrites",
    "lift_86_16",
    "load_dos_mz",
    "load_dos_ne",
    "cod_source_rewrite_description",
    "cod_source_rewrite_names",
    "cod_source_rewrite_summary",
    "describe_x86_16_source_backed_rewrite_status",
    "describe_x86_16_source_backed_rewrite_debt",
    "describe_x86_16_cod_known_objects",
    "apply_x86_16_compatibility",
    "stack_compat",
    "apply_x86_16_stack_compatibility",
    "get_cod_source_rewrite_spec",
    "compat",
    "patch_dirty",
    "typehoon_compat",
    "alias_model",
    "alias_domains",
    "alias_state",
    "alias_transfer",
    "address_ir",
    "describe_x86_16_alias_recovery_api",
    "describe_x86_16_interrupt_api_surface",
    "describe_x86_16_interrupt_core_surface",
    "describe_x86_16_interrupt_lowering_boundary",
    "describe_x86_16_instruction_metadata_surface",
    "describe_x86_16_decode_width_matrix",
    "describe_x86_16_mixed_width_extension_surface",
    "describe_x86_16_mixed_width_instruction_surface",
    "describe_x86_16_projection_cleanup_rules",
    "describe_x86_16_readability_goals",
    "rank_readability_goal_queue",
    "summarize_readability_focus",
    "describe_x86_16_correctness_goals",
    "describe_x86_16_validation_triage",
    "simos_86_16",
    "rewrite_cod_source_stage",
    "decompiler_postprocess",
    "decompiler_postprocess_globals",
    "decompiler_postprocess_calls",
    "decompiler_postprocess_utils",
    "decompiler_postprocess_flags",
    "decompiler_postprocess_simplify",
    "callsite_summary",
    "function_summary",
    "decompiler_structuring_stage",
    "widening_alias",
    "widening_model",
    "describe_x86_16_widening_pipeline",
    "describe_x86_16_object_recovery_focus",
    "describe_x86_16_recovery_layers",
    "recovery_artifacts",
    "recovery_artifact_writer",
    "recovery_artifact_cache",
    "recovery_artifact_manifest",
    "recovery_confidence",
    "describe_x86_16_recovery_confidence_axes",
    "summarize_x86_16_function_effects",
    "validation_manifest",
    "readability_set",
    "readability_goals",
    "correctness_goals",
    "milestone_report",
    "render_x86_16_tail_validation_console_summary",
    "recovery_manifest",
    "targeted_recovery_artifact",
    "recompilable_subset",
    "calling_convention_compat",
    "decompiler_return_compat",
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_decompiler_return_compatibility",
    "apply_x86_16_decompiler_postprocess",
    "bootstrap",
    "apply_x86_16_bootstrap",
    "decompiler_postprocess_inventory",
    "decompiler_postprocess_stage",
    "describe_x86_16_decompiler_postprocess_inventory_8616",
    "validate_x86_16_decompiler_postprocess_inventory_8616",
    "describe_x86_16_decompiler_postprocess_stage",
    "describe_x86_16_decompiler_structuring_stage",
    "tail_validation",
    "X86_16TailValidationSummary",
    "X86_16ValidationCacheDescriptor",
    "build_x86_16_tail_validation_aggregate",
    "build_x86_16_tail_validation_surface",
    "build_x86_16_tail_validation_cached_result",
    "build_x86_16_validation_cache_descriptor",
    "check_x86_16_tail_validation_surface_consistency",
    "persist_x86_16_tail_validation_snapshot",
    "extract_x86_16_tail_validation_snapshot",
    "x86_16_tail_validation_snapshot_passed",
    "collect_x86_16_tail_validation_summary",
    "compare_x86_16_tail_validation_summaries",
    "build_x86_16_tail_validation_verdict",
    "fingerprint_x86_16_tail_validation_boundary",
    "format_x86_16_tail_validation_diff",
    "resolve_x86_16_validation_cached_artifact",
    "summarize_x86_16_tail_validation_records",
    "describe_x86_16_tail_validation_scope",
    "DecompilerPostprocessPassInventoryItem",
    "DecompilerPostprocessPassKind8616",
    "DecompilerPostprocessPassMigrationStatus8616",
    "DecompilerPostprocessPassInventoryViolation",
    "DecompilerPostprocessPassSpec",
    "DecompilerStructuringPassSpec",
]

from . import (  # noqa: F401  # noqa: F401
    address_ir,
    alias_domains,
    alias_model,
    alias_state,
    alias_transfer,
    annotations,
    arch_86_16,
    calling_convention_compat,
    callsite_summary,
    cod_extract,
    cod_source_rewrites,
    compat,
    corpus_recovery_artifact,
    corpus_scan,
    correctness_goals,  # noqa: F401
    decompiler_postprocess,
    decompiler_postprocess_calls,
    decompiler_postprocess_flags,
    decompiler_postprocess_globals,
    decompiler_postprocess_simplify,
    decompiler_postprocess_utils,
    decompiler_return_compat,
    function_effect_summary,
    function_summary,
    lift_86_16,
    load_dos_mz,
    load_dos_ne,
    milestone_report,
    patch_dirty,
    readability_goals,  # noqa: F401
    readability_set,
    recompilable_subset,
    recovery_artifact_cache,
    recovery_artifact_manifest,
    recovery_artifact_writer,
    recovery_artifacts,
    recovery_confidence,
    recovery_manifest,
    simos_86_16,
    stack_compat,
    structuring_cross_entry,
    structuring_grouped_graph_builder,
    structuring_grouped_pass,
    structuring_grouped_units,
    tail_validation,
    targeted_recovery_artifact,
    typehoon_compat,
    validation_manifest,
    widening_alias,
    widening_model,
)
from .addressing_helpers import (
    describe_x86_16_decode_width_matrix,  # noqa: F401
    describe_x86_16_mixed_width_extension_surface,  # noqa: F401
    describe_x86_16_mixed_width_instruction_surface,  # noqa: F401
)
from .alias.alias_model_impl import describe_x86_16_alias_recovery_api  # noqa: F401
from .analysis_helpers import (
    describe_x86_16_interrupt_api_surface,  # noqa: F401
    describe_x86_16_interrupt_core_surface,  # noqa: F401
    describe_x86_16_interrupt_lowering_boundary,  # noqa: F401
)
from .annotations import apply_x86_16_metadata_annotations  # noqa: F401
from .calling_convention_compat import apply_x86_16_calling_convention_compatibility  # noqa: F401
from .cod_known_objects import describe_x86_16_cod_known_objects  # noqa: F401
from .cod_source_rewrites import (  # noqa: F401
    COD_SOURCE_REWRITE_REGISTRY,
    CODSourceRewriteStatusKind,
    apply_cod_source_rewrites,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
    get_cod_source_rewrite_spec,
    rewrite_cod_source_stage,
)
from .compat import apply_x86_16_compatibility  # noqa: F401
from .correctness_goals import describe_x86_16_correctness_goals  # noqa: F401
from .decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules  # noqa: F401
from .decompiler_return_compat import apply_x86_16_decompiler_return_compatibility  # noqa: F401
from .function_effect_summary import summarize_x86_16_function_effects  # noqa: F401
from .instruction import describe_x86_16_instruction_metadata_surface  # noqa: F401
from .milestone_report import render_x86_16_tail_validation_console_summary  # noqa: F401
from .readability_goals import (  # noqa: F401
    describe_x86_16_readability_goals,
    rank_readability_goal_queue,
    summarize_readability_focus,
)
from .recovery_confidence import describe_x86_16_recovery_confidence_axes  # noqa: F401
from .recovery_manifest import describe_x86_16_object_recovery_focus, describe_x86_16_recovery_layers  # noqa: F401
from .stack_compat import apply_x86_16_stack_compatibility  # noqa: F401
from .tail_validation import (  # noqa: F401
    X86_16TailValidationSummary,
    X86_16ValidationCacheDescriptor,
    build_x86_16_tail_validation_aggregate,
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_surface,
    build_x86_16_tail_validation_verdict,
    build_x86_16_validation_cache_descriptor,
    check_x86_16_tail_validation_surface_consistency,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    describe_x86_16_tail_validation_scope,
    extract_x86_16_tail_validation_snapshot,
    fingerprint_x86_16_tail_validation_boundary,
    format_x86_16_tail_validation_diff,
    persist_x86_16_tail_validation_snapshot,
    resolve_x86_16_validation_cached_artifact,
    summarize_x86_16_tail_validation_records,
    x86_16_tail_validation_snapshot_passed,
)
from .validation_manifest import describe_x86_16_validation_triage  # noqa: F401
from .widening.stack_widening import describe_x86_16_widening_pipeline  # noqa: F401

if TYPE_CHECKING:
    from . import (  # noqa: F401
        bootstrap,
        decompiler_postprocess_inventory,
        decompiler_postprocess_stage,
        decompiler_structuring_stage,
    )
    from .bootstrap import apply_x86_16_bootstrap  # noqa: F401
    from .decompiler_postprocess_inventory import (  # noqa: F401
        DecompilerPostprocessPassInventoryItem,
        DecompilerPostprocessPassInventoryViolation,
        DecompilerPostprocessPassKind8616,
        DecompilerPostprocessPassMigrationStatus8616,
        describe_x86_16_decompiler_postprocess_inventory_8616,
        validate_x86_16_decompiler_postprocess_inventory_8616,
    )
    from .decompiler_postprocess_stage import (  # noqa: F401
        DecompilerPostprocessPassSpec,
        apply_x86_16_decompiler_postprocess,
        describe_x86_16_decompiler_postprocess_stage,
    )
    from .decompiler_structuring_stage import (  # noqa: F401
        DecompilerStructuringPassSpec,
        describe_x86_16_decompiler_structuring_stage,
    )

_LazyExportLoader = Callable[[], object]


def _load_bootstrap_module() -> object:
    return import_module(".bootstrap", __name__)


def _load_apply_x86_16_bootstrap() -> object:
    from .bootstrap import apply_x86_16_bootstrap

    return apply_x86_16_bootstrap


def _load_decompiler_postprocess_inventory_module() -> object:
    return import_module(".decompiler_postprocess_inventory", __name__)


def _load_decompiler_postprocess_stage_module() -> object:
    return import_module(".decompiler_postprocess_stage", __name__)


def _load_decompiler_structuring_stage_module() -> object:
    return import_module(".decompiler_structuring_stage", __name__)


def _load_decompiler_postprocess_pass_inventory_item() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassInventoryItem

    return DecompilerPostprocessPassInventoryItem


def _load_decompiler_postprocess_pass_kind_8616() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassKind8616

    return DecompilerPostprocessPassKind8616


def _load_decompiler_postprocess_pass_migration_status_8616() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassMigrationStatus8616

    return DecompilerPostprocessPassMigrationStatus8616


def _load_decompiler_postprocess_pass_inventory_violation() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassInventoryViolation

    return DecompilerPostprocessPassInventoryViolation


def _load_decompiler_postprocess_pass_spec() -> object:
    from .decompiler_postprocess_stage import DecompilerPostprocessPassSpec

    return DecompilerPostprocessPassSpec


def _load_apply_x86_16_decompiler_postprocess() -> object:
    from .decompiler_postprocess_stage import apply_x86_16_decompiler_postprocess

    return apply_x86_16_decompiler_postprocess


def _load_describe_x86_16_decompiler_postprocess_inventory_8616() -> object:
    from .decompiler_postprocess_inventory import describe_x86_16_decompiler_postprocess_inventory_8616

    return describe_x86_16_decompiler_postprocess_inventory_8616


def _load_validate_x86_16_decompiler_postprocess_inventory_8616() -> object:
    from .decompiler_postprocess_inventory import validate_x86_16_decompiler_postprocess_inventory_8616

    return validate_x86_16_decompiler_postprocess_inventory_8616


def _load_describe_x86_16_decompiler_postprocess_stage() -> object:
    from .decompiler_postprocess_stage import describe_x86_16_decompiler_postprocess_stage

    return describe_x86_16_decompiler_postprocess_stage


def _load_decompiler_structuring_pass_spec() -> object:
    from .decompiler_structuring_stage import DecompilerStructuringPassSpec

    return DecompilerStructuringPassSpec


def _load_apply_x86_16_decompiler_structuring() -> object:
    from .decompiler_structuring_stage import apply_x86_16_decompiler_structuring

    return apply_x86_16_decompiler_structuring


def _load_describe_x86_16_decompiler_structuring_stage() -> object:
    from .decompiler_structuring_stage import describe_x86_16_decompiler_structuring_stage

    return describe_x86_16_decompiler_structuring_stage


_LAZY_EXPORTS: dict[str, _LazyExportLoader] = {
    "bootstrap": _load_bootstrap_module,
    "apply_x86_16_bootstrap": _load_apply_x86_16_bootstrap,
    "decompiler_postprocess_inventory": _load_decompiler_postprocess_inventory_module,
    "decompiler_postprocess_stage": _load_decompiler_postprocess_stage_module,
    "DecompilerPostprocessPassInventoryItem": _load_decompiler_postprocess_pass_inventory_item,
    "DecompilerPostprocessPassKind8616": _load_decompiler_postprocess_pass_kind_8616,
    "DecompilerPostprocessPassMigrationStatus8616": _load_decompiler_postprocess_pass_migration_status_8616,
    "DecompilerPostprocessPassInventoryViolation": _load_decompiler_postprocess_pass_inventory_violation,
    "DecompilerPostprocessPassSpec": _load_decompiler_postprocess_pass_spec,
    "apply_x86_16_decompiler_postprocess": _load_apply_x86_16_decompiler_postprocess,
    "describe_x86_16_decompiler_postprocess_inventory_8616": (
        _load_describe_x86_16_decompiler_postprocess_inventory_8616
    ),
    "validate_x86_16_decompiler_postprocess_inventory_8616": (
        _load_validate_x86_16_decompiler_postprocess_inventory_8616
    ),
    "describe_x86_16_decompiler_postprocess_stage": _load_describe_x86_16_decompiler_postprocess_stage,
    "decompiler_structuring_stage": _load_decompiler_structuring_stage_module,
    "DecompilerStructuringPassSpec": _load_decompiler_structuring_pass_spec,
    "apply_x86_16_decompiler_structuring": _load_apply_x86_16_decompiler_structuring,
    "describe_x86_16_decompiler_structuring_stage": _load_describe_x86_16_decompiler_structuring_stage,
}


def __getattr__(name: str) -> object:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    value = target()
    globals()[name] = value
    return value


def _alias_x86_16_module_tree() -> None:
    canonical_root = "angr_platforms.X86_16"
    legacy_root = "angr_platforms.angr_platforms.X86_16"
    current_module = sys.modules[__name__]
    sys.modules.setdefault(canonical_root, current_module)
    sys.modules.setdefault(legacy_root, current_module)
    prefixes = (
        (canonical_root, legacy_root),
        (legacy_root, canonical_root),
    )
    for name, module in tuple(sys.modules.items()):
        for source_root, target_root in prefixes:
            if name == source_root:
                sys.modules.setdefault(target_root, module)
            elif name.startswith(source_root + "."):
                sys.modules.setdefault(target_root + name[len(source_root) :], module)


_alias_x86_16_module_tree()

try:
    _bootstrap = __getattr__("apply_x86_16_bootstrap")
    if callable(_bootstrap):
        _bootstrap()
except Exception:
    pass

# Do not wrap Clinic._make_callsites with SIGALRM-based timeouts here.
# Raising out of Clinic causes angr resilience to drop decompilation results
# and return an empty codegen, which is worse than a slow but honest decompile.
