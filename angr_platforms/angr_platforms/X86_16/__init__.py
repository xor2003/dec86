try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

__all__ = [
    "COD_SOURCE_REWRITE_REGISTRY",
    "annotations",
    "apply_x86_16_metadata_annotations",
    "arch_86_16",
    "cod_extract",
    "corpus_scan",
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
    "decompiler_postprocess_utils",
    "decompiler_postprocess_flags",
    "decompiler_postprocess_simplify",
    "decompiler_structuring_stage",
    "widening_alias",
    "widening_model",
    "describe_x86_16_widening_pipeline",
    "describe_x86_16_object_recovery_focus",
    "describe_x86_16_recovery_layers",
    "recovery_confidence",
    "describe_x86_16_recovery_confidence_axes",
    "validation_manifest",
    "readability_set",
    "readability_goals",
    "correctness_goals",
    "milestone_report",
    "recovery_manifest",
    "recompilable_subset",
    "calling_convention_compat",
    "decompiler_return_compat",
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_decompiler_return_compatibility",
    "apply_x86_16_decompiler_postprocess",
    "bootstrap",
    "apply_x86_16_bootstrap",
    "decompiler_postprocess_stage",
    "describe_x86_16_decompiler_postprocess_stage",
    "describe_x86_16_decompiler_structuring_stage",
    "DecompilerPostprocessPassSpec",
    "DecompilerStructuringPassSpec",
]

from . import annotations, arch_86_16, bootstrap, calling_convention_compat, cod_extract, cod_source_rewrites, corpus_scan, decompiler_postprocess, decompiler_postprocess_flags, decompiler_postprocess_globals, decompiler_postprocess_simplify, decompiler_postprocess_stage, decompiler_postprocess_utils, decompiler_return_compat, decompiler_structuring_stage, lift_86_16, load_dos_mz, load_dos_ne, recovery_confidence, simos_86_16  # noqa: F401
from . import alias_domains, alias_model, alias_state, alias_transfer, compat, milestone_report, patch_dirty, readability_set, recovery_manifest, recompilable_subset, stack_compat, typehoon_compat, validation_manifest, widening_alias, widening_model  # noqa: F401
from . import readability_goals  # noqa: F401
from . import correctness_goals  # noqa: F401
from .alias_model import describe_x86_16_alias_recovery_api  # noqa: F401
from .addressing_helpers import describe_x86_16_decode_width_matrix  # noqa: F401
from .addressing_helpers import describe_x86_16_mixed_width_extension_surface  # noqa: F401
from .addressing_helpers import describe_x86_16_mixed_width_instruction_surface  # noqa: F401
from .analysis_helpers import describe_x86_16_interrupt_api_surface  # noqa: F401
from .analysis_helpers import describe_x86_16_interrupt_core_surface  # noqa: F401
from .analysis_helpers import describe_x86_16_interrupt_lowering_boundary  # noqa: F401
from .instruction import describe_x86_16_instruction_metadata_surface  # noqa: F401
from .annotations import apply_x86_16_metadata_annotations  # noqa: F401
from .recovery_manifest import describe_x86_16_object_recovery_focus, describe_x86_16_recovery_layers  # noqa: F401
from .decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules  # noqa: F401
from .decompiler_structuring_stage import DecompilerStructuringPassSpec, apply_x86_16_decompiler_structuring, describe_x86_16_decompiler_structuring_stage  # noqa: F401
from .readability_goals import describe_x86_16_readability_goals, rank_readability_goal_queue, summarize_readability_focus  # noqa: F401
from .correctness_goals import describe_x86_16_correctness_goals  # noqa: F401
from .validation_manifest import describe_x86_16_validation_triage  # noqa: F401
from .widening_model import describe_x86_16_widening_pipeline  # noqa: F401
from .recovery_confidence import describe_x86_16_recovery_confidence_axes  # noqa: F401
from .cod_known_objects import describe_x86_16_cod_known_objects  # noqa: F401
from .cod_source_rewrites import (  # noqa: F401
    COD_SOURCE_REWRITE_REGISTRY,
    apply_cod_source_rewrites,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
    get_cod_source_rewrite_spec,
    rewrite_cod_source_stage,
)
from .bootstrap import apply_x86_16_bootstrap  # noqa: F401
from .calling_convention_compat import apply_x86_16_calling_convention_compatibility  # noqa: F401
from .decompiler_return_compat import apply_x86_16_decompiler_return_compatibility  # noqa: F401
from .stack_compat import apply_x86_16_stack_compatibility  # noqa: F401
from .decompiler_postprocess_stage import DecompilerPostprocessPassSpec, apply_x86_16_decompiler_postprocess, describe_x86_16_decompiler_postprocess_stage  # noqa: F401

try:
    apply_x86_16_bootstrap()
except Exception:
    pass

# Do not wrap Clinic._make_callsites with SIGALRM-based timeouts here.
# Raising out of Clinic causes angr resilience to drop decompilation results
# and return an empty codegen, which is worse than a slow but honest decompile.
