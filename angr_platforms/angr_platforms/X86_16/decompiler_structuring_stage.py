from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler

from . import decompiler_postprocess_simplify as _simplify
from . import structuring_analysis as _structuring
from . import structuring_codegen as _codegen
from . import type_equivalence_classes as _type_equiv
from . import type_array_matching as _array_match
from . import type_structure_merging as _struct_merge
from . import segmented_memory_reasoning as _segmented_mem
from . import confidence_and_assumptions as _confidence
from . import structuring_diagnostics as _diagnostics

__all__ = [
    "DecompilerStructuringPassSpec",
    "DECOMPILER_STRUCTURING_PASSES",
    "_build_decompiler_structuring_passes",
    "describe_x86_16_decompiler_structuring_stage",
    "apply_x86_16_decompiler_structuring",
]


@dataclass(frozen=True, slots=True)
class DecompilerStructuringPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


def _build_decompiler_structuring_passes():
    return (
        DecompilerStructuringPassSpec(
            "_region_based_structuring_8616",
            _structuring.apply_region_based_structuring,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structuring_codegen_8616",
            _codegen.apply_structuring_codegen_8616,
            False,
        ),
        # Phase 2: Type Inference and Recovery
        DecompilerStructuringPassSpec(
            "_type_equivalence_classes_8616",
            _type_equiv.apply_x86_16_type_equivalence_classes,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_array_expression_matching_8616",
            _array_match.apply_x86_16_array_expression_matching,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structure_field_merging_8616",
            _struct_merge.apply_x86_16_structure_field_merging,
            False,
        ),
        # Phase 3: Segmented Memory Association Reasoning
        DecompilerStructuringPassSpec(
            "_segmented_memory_reasoning_8616",
            _segmented_mem.apply_x86_16_segmented_memory_reasoning,
            False,
        ),
        # Phase 4: Robustness & Diagnostics
        DecompilerStructuringPassSpec(
            "_confidence_and_assumptions_8616",
            _confidence.apply_x86_16_confidence_and_assumptions,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structuring_diagnostics_8616",
            _diagnostics.apply_x86_16_structuring_diagnostics,
            False,
        ),
    )


DECOMPILER_STRUCTURING_PASSES = _build_decompiler_structuring_passes()


def _decompiler_structuring_passes_for_function(project, codegen):
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return DECOMPILER_STRUCTURING_PASSES

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return DECOMPILER_STRUCTURING_PASSES

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return DECOMPILER_STRUCTURING_PASSES

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        return DECOMPILER_STRUCTURING_PASSES

    return DECOMPILER_STRUCTURING_PASSES


def describe_x86_16_decompiler_structuring_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_STRUCTURING_PASSES)


def _structuring_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    if not bool(getattr(project, "_inertia_structuring_enabled", True)):
        codegen._inertia_structuring_passes = ()
        codegen._inertia_structuring_changed = False
        codegen._inertia_structuring_failed = False
        codegen._inertia_last_structuring_pass = None
        return False

    changed = False
    last_changed_pass = None
    codegen._inertia_structuring_failed = False
    codegen._inertia_structuring_failure_pass = None
    codegen._inertia_structuring_failure_error = None
    codegen._inertia_last_structuring_pass = None
    pass_specs = _decompiler_structuring_passes_for_function(project, codegen)
    codegen._inertia_structuring_passes = tuple(spec.name for spec in pass_specs)
    for spec in pass_specs:
        try:
            project._inertia_decompiler_stage = f"structuring:{spec.name}"
            if spec.needs_project:
                spec_changed = spec.func(project, codegen)
            else:
                spec_changed = spec.func(codegen)
        except Exception as ex:  # noqa: BLE001
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = spec.name
            codegen._inertia_structuring_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 structuring pass %s after %s: %s",
                spec.name,
                last_changed_pass or "no earlier structuring",
                ex,
            )
            break
        if spec_changed:
            changed = True
            last_changed_pass = spec.name
            codegen._inertia_last_structuring_pass = spec.name
    codegen._inertia_structuring_changed = changed
    project._inertia_decompiler_stage = "structuring"
    return changed


def _decompile_structuring_8616(self):
    _orig_decompiler_decompile = getattr(_decompile_structuring_8616, "_orig_decompiler_decompile", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = Decompiler._decompile
        _decompile_structuring_8616._orig_decompiler_decompile = _orig_decompiler_decompile
    structuring_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    _orig_decompiler_decompile(self)
    structuring_elapsed = time.perf_counter() - structuring_started
    if self.project.arch.name != "86_16" or self.codegen is None:
        return

    changed = _structuring_codegen_8616(self.project, self.codegen)
    function = getattr(self, "function", None)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, dict):
            structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
            structuring_info["elapsed"] = structuring_elapsed
            structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
            structuring_info["changed"] = bool(changed)
            structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
            structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
            structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
            structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
            structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
    self.project._inertia_decompiler_stage = "structuring_done"


def apply_x86_16_decompiler_structuring() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_structuring_8616":
        _decompile_structuring_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_structuring_8616
