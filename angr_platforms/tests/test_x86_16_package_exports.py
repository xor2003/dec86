from __future__ import annotations

import angr_platforms.X86_16 as x8616
from angr.analyses.decompiler.decompiler import Decompiler
from angr_platforms.X86_16 import bootstrap
from angr_platforms.X86_16 import decompiler_postprocess
from angr_platforms.X86_16 import decompiler_postprocess_stage


def test_x86_16_package_exports_source_backends():
    assert "cod_extract" in x8616.__all__
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
    assert "decompiler_postprocess_utils" in x8616.__all__
    assert "decompiler_postprocess_simplify" in x8616.__all__
    assert "decompiler_postprocess_flags" in x8616.__all__
    assert "calling_convention_compat" in x8616.__all__
    assert "decompiler_return_compat" in x8616.__all__
    assert "describe_x86_16_decompiler_postprocess_stage" in x8616.__all__
    assert "DecompilerPostprocessPassSpec" in x8616.__all__
    assert "patch_dirty" in x8616.__all__
    assert "typehoon_compat" in x8616.__all__
    assert "alias_model" in x8616.__all__
    assert "widening_model" in x8616.__all__
    assert "decompiler_postprocess" in x8616.__all__
    assert "decompiler_postprocess_globals" in x8616.__all__
    assert "decompiler_postprocess_utils" in x8616.__all__
    assert "decompiler_postprocess_simplify" in x8616.__all__
    assert "decompiler_postprocess_flags" in x8616.__all__
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


def test_x86_16_decompiler_postprocess_registry_order():
    assert [spec.func.__name__ for spec in decompiler_postprocess_stage.DECOMPILER_POSTPROCESS_PASSES] == [
        "_apply_word_global_types_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_unused_unnamed_memory_declarations_8616",
        "_apply_annotations_8616",
        "_simplify_boolean_cites_8616",
        "_simplify_structured_expressions_8616",
        "_rewrite_flag_condition_pairs_8616",
        "_prune_unused_flag_assignments_8616",
        "_prune_overwritten_flag_assignments_8616",
        "_fix_interval_guard_conditions_8616",
    ]


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


def test_x86_16_bootstrap_module_exports():
    assert bootstrap.__all__ == ["apply_x86_16_bootstrap"]


def test_x86_16_bootstrap_module_description():
    assert bootstrap.describe_x86_16_bootstrap() == (
        "apply_x86_16_calling_convention_compatibility",
        "apply_x86_16_compatibility",
        "apply_x86_16_decompiler_return_compatibility",
        "apply_x86_16_decompiler_postprocess",
    )


def test_x86_16_decompiler_postprocess_pass_specs_are_dataclasses():
    assert all(
        isinstance(spec, decompiler_postprocess_stage.DecompilerPostprocessPassSpec)
        for spec in decompiler_postprocess_stage.DECOMPILER_POSTPROCESS_PASSES
    )
