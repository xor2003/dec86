__all__ = [
    "COD_SOURCE_REWRITE_REGISTRY",
    "annotations",
    "arch_86_16",
    "cod_extract",
    "cod_source_rewrites",
    "apply_cod_source_rewrites",
    "lift_86_16",
    "load_dos_mz",
    "cod_source_rewrite_description",
    "cod_source_rewrite_names",
    "cod_source_rewrite_summary",
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
    "simos_86_16",
    "rewrite_cod_source_stage",
    "decompiler_postprocess",
    "decompiler_postprocess_globals",
    "decompiler_postprocess_utils",
    "decompiler_postprocess_flags",
    "decompiler_postprocess_simplify",
    "widening_alias",
    "widening_model",
    "calling_convention_compat",
    "decompiler_return_compat",
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_decompiler_return_compatibility",
    "apply_x86_16_decompiler_postprocess",
    "bootstrap",
    "apply_x86_16_bootstrap",
    "decompiler_postprocess_stage",
    "describe_x86_16_decompiler_postprocess_stage",
    "DecompilerPostprocessPassSpec",
]

from . import annotations, arch_86_16, bootstrap, calling_convention_compat, cod_extract, cod_source_rewrites, decompiler_postprocess, decompiler_postprocess_flags, decompiler_postprocess_globals, decompiler_postprocess_simplify, decompiler_postprocess_stage, decompiler_postprocess_utils, decompiler_return_compat, lift_86_16, load_dos_mz, simos_86_16  # noqa: F401
from . import alias_domains, alias_model, alias_state, alias_transfer, compat, patch_dirty, stack_compat, typehoon_compat, widening_alias, widening_model  # noqa: F401
from .cod_source_rewrites import (  # noqa: F401
    COD_SOURCE_REWRITE_REGISTRY,
    apply_cod_source_rewrites,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
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
