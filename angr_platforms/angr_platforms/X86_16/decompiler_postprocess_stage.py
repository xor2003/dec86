from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_simplify as _simplify

__all__ = [
    "DecompilerPostprocessPassSpec",
    "DECOMPILER_POSTPROCESS_PASSES",
    "_build_decompiler_postprocess_passes",
    "describe_x86_16_decompiler_postprocess_stage",
    "apply_x86_16_decompiler_postprocess",
]


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


def _build_decompiler_postprocess_passes():
    return (
        DecompilerPostprocessPassSpec("_apply_word_global_types_8616", _globals._apply_word_global_types_8616, True),
        DecompilerPostprocessPassSpec("_apply_annotations_8616", _post._apply_annotations_8616, True),
        DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            _post._promote_stack_prototype_from_bp_loads_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_return_address_stack_arguments_8616",
            _post._prune_return_address_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_unnamed_memory_declarations_8616",
            _globals._prune_unused_unnamed_memory_declarations_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_boolean_cites_8616",
            _simplify._simplify_boolean_cites_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_function_prototype_arg_names_8616",
            _post._normalize_function_prototype_arg_names_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_classify_return_shape_8616",
            _post._classify_return_shape_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_void_function_return_values_8616",
            _post._prune_void_function_return_values_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dedupe_codegen_variable_names_8616",
            _post._dedupe_codegen_variable_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec("_rewrite_flag_condition_pairs_8616", _flags._rewrite_flag_condition_pairs_8616, False),
        DecompilerPostprocessPassSpec("_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_fix_interval_guard_conditions_8616", _flags._fix_interval_guard_conditions_8616, False),
    )


DECOMPILER_POSTPROCESS_PASSES = _build_decompiler_postprocess_passes()


def _decompiler_postprocess_passes_for_function(project, codegen):
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return DECOMPILER_POSTPROCESS_PASSES

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return DECOMPILER_POSTPROCESS_PASSES

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return DECOMPILER_POSTPROCESS_PASSES

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        return DECOMPILER_POSTPROCESS_PASSES[:10]

    return DECOMPILER_POSTPROCESS_PASSES


def describe_x86_16_decompiler_postprocess_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _postprocess_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    addrs = set()
    addrs |= _globals._coalesce_word_global_loads_8616(project, codegen)
    addrs |= _globals._coalesce_word_global_constant_stores_8616(project, codegen)

    changed = bool(addrs)
    last_changed_pass = None
    codegen._inertia_rewrite_failed = False
    codegen._inertia_rewrite_failure_pass = None
    codegen._inertia_rewrite_failure_error = None
    codegen._inertia_last_postprocess_pass = None
    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
    codegen._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
    for spec in pass_specs:
        try:
            project._inertia_decompiler_stage = f"postprocess:{spec.name}"
            if spec.needs_project:
                spec_changed = spec.func(project, codegen)
            else:
                spec_changed = spec.func(codegen)
        except Exception as ex:  # noqa: BLE001
            codegen._inertia_rewrite_failed = True
            codegen._inertia_rewrite_failure_pass = spec.name
            codegen._inertia_rewrite_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 postprocess pass %s after %s: %s",
                spec.name,
                last_changed_pass or "no earlier rewrite",
                ex,
            )
            break
        if spec_changed:
            changed = True
            last_changed_pass = spec.name
            codegen._inertia_last_postprocess_pass = spec.name
    codegen._inertia_postprocess_changed = changed
    project._inertia_decompiler_stage = "postprocess"
    return changed


def _regenerate_text_safely(codegen, *, context: str) -> bool:
    try:
        codegen.regenerate_text()
    except Exception as ex:
        codegen._inertia_regeneration_failed = True
        codegen._inertia_regeneration_error = str(ex)
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        logging.getLogger(__name__).warning(
            "Skipping 86_16 postprocess regeneration for %s after %s: %s",
            context,
            getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
            ex,
        )
        return False
    codegen._inertia_regeneration_failed = False
    codegen._inertia_regeneration_error = None
    codegen._inertia_regeneration_context = context
    codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
    return True


def _decompile_8616(self):
    _orig_decompiler_decompile = getattr(_decompile_8616, "_orig_decompiler_decompile", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = Decompiler._decompile
        _decompile_8616._orig_decompiler_decompile = _orig_decompiler_decompile
    core_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    _orig_decompiler_decompile(self)
    core_elapsed = time.perf_counter() - core_started
    if self.project.arch.name != "86_16" or self.codegen is None:
        return

    postprocess_started = time.perf_counter()
    changed = _postprocess_codegen_8616(self.project, self.codegen)
    postprocess_elapsed = time.perf_counter() - postprocess_started
    function = getattr(self, "function", None)
    context = f"{getattr(function, 'addr', 'unknown')!r} {getattr(function, 'name', 'unknown')}"
    if changed:
        _regenerate_text_safely(self.codegen, context=context)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, dict):
            postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
            postprocess_info["core_elapsed"] = core_elapsed
            postprocess_info["postprocess_elapsed"] = postprocess_elapsed
            postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
            postprocess_info["rewrite_failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
            postprocess_info["rewrite_failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
            postprocess_info["rewrite_failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
            postprocess_info["regeneration_failed"] = bool(getattr(self.codegen, "_inertia_regeneration_failed", False))
            postprocess_info["regeneration_failure_pass"] = getattr(
                self.codegen,
                "_inertia_regeneration_last_pass",
                None,
            )
            postprocess_info["regeneration_failure_error"] = getattr(
                self.codegen,
                "_inertia_regeneration_error",
                None,
            )
            postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
            postprocess_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
    self.project._inertia_decompiler_stage = "done"


def apply_x86_16_decompiler_postprocess() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        _decompile_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_8616
