from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Tuple, Callable

from angr.analyses.decompiler.decompiler import Decompiler

from . import confidence_and_assumptions as _confidence
from . import decompiler_postprocess_simplify as _simplify
from . import ir_confidence_markers as _ir_confidence
from .ir import vex_import as _vex_ir
from . import segmented_memory_reasoning as _segmented_mem
from . import string_instruction_artifact as _string_instruction_artifact
from . import string_instruction_lowering as _string_instruction_lowering
from . import structuring_cross_entry as _cross_entry
from . import structuring_grouped_pass as _grouped_structuring
from . import structuring_codegen as _codegen
from . import structuring_diagnostics as _diagnostics
from . import type_array_matching as _array_match
from . import type_equivalence_classes as _type_equiv
from . import type_structure_merging as _struct_merge
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
)

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


def _build_decompiler_structuring_passes() -> tuple[DecompilerStructuringPassSpec, ...]:
    return (
        DecompilerStructuringPassSpec(
            "_cross_entry_cfg_grouping_8616",
            _cross_entry.apply_x86_16_cross_entry_grouping,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_region_based_structuring_8616",
            _grouped_structuring.apply_grouped_region_based_structuring,
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
        DecompilerStructuringPassSpec(
            "_vex_ir_artifact_8616",
            _vex_ir.apply_x86_16_vex_ir_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_artifact_8616",
            _string_instruction_artifact.apply_x86_16_string_instruction_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_lowering_8616",
            _string_instruction_lowering.apply_x86_16_string_instruction_lowering,
            True,
        ),
        # Phase 3: Segmented Memory Association Reasoning
        DecompilerStructuringPassSpec(
            "_segmented_memory_reasoning_8616",
            _segmented_mem.apply_x86_16_segmented_memory_reasoning,
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
        # Phase 4: Robustness & Diagnostics
        DecompilerStructuringPassSpec(
            "_structuring_diagnostics_8616",
            _diagnostics.apply_x86_16_structuring_diagnostics,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_ir_confidence_markers_8616",
            _ir_confidence.apply_x86_16_ir_confidence_markers,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_confidence_and_assumptions_8616",
            _confidence.apply_x86_16_confidence_and_assumptions,
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
    if not bool(getattr(self.project, "_inertia_tail_validation_enabled", True)):
        changed = _structuring_codegen_8616(self.project, self.codegen)
        function = getattr(self, "function", None) or getattr(self, "func", None)
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
                structuring_info["elapsed"] = structuring_elapsed
                structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
                structuring_info["changed"] = bool(changed)
                structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
                structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
                structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
                structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
                structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
                structuring_info["struct_merging_stats"] = getattr(self.codegen, "_inertia_struct_merging_stats", None)
                structuring_info["struct_merging_changed"] = bool(getattr(self.codegen, "_inertia_struct_merging_changed", False))
        setattr(self.codegen, "_inertia_tail_validation_snapshot", None)
        self.project._inertia_decompiler_stage = "structuring_done"
        return

    validation_mode = "live_out"
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    before_collect_started = time.perf_counter()
    before_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    before_collect_elapsed = time.perf_counter() - before_collect_started
    changed = _structuring_codegen_8616(self.project, self.codegen)
    after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    after_collect_started = time.perf_counter()
    after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    after_collect_elapsed = time.perf_counter() - after_collect_started
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    validation = build_x86_16_tail_validation_cached_result(
        owner=owner if isinstance(owner, MutableMapping) else None,
        stage="structuring",
        mode=validation_mode,
        before_fingerprint=before_fingerprint,
        after_fingerprint=after_fingerprint,
        before_summary=before_summary,
        after_summary=after_summary,
    )
    validation_compare_elapsed = time.perf_counter() - validation_started
    validation_timings = {
        "collect_before_ms": round(before_collect_elapsed * 1000.0, 3),
        "collect_after_ms": round(after_collect_elapsed * 1000.0, 3),
        "compare_ms": round(validation_compare_elapsed * 1000.0, 3),
        "total_ms": round((before_collect_elapsed + after_collect_elapsed + validation_compare_elapsed) * 1000.0, 3),
    }
    validation["timings"] = validation_timings
    validation["verdict"] = build_x86_16_tail_validation_verdict("structuring", validation)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
            structuring_info["elapsed"] = structuring_elapsed
            structuring_info["tail_validation_timings"] = validation_timings
            structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
            structuring_info["changed"] = bool(changed)
            structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
            structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
            structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
            structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
            structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
            structuring_info["tail_validation_verdict"] = validation["verdict"]
            structuring_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
            structuring_info["struct_merging_stats"] = getattr(self.codegen, "_inertia_struct_merging_stats", None)
            structuring_info["struct_merging_changed"] = bool(getattr(self.codegen, "_inertia_struct_merging_changed", False))
            persist_x86_16_tail_validation_snapshot(
                function_info=info,
                codegen=self.codegen,
                stage="structuring",
                validation=validation,
            )
    log = logging.getLogger(__name__)
    if validation["changed"]:
        log.warning("%s", validation["verdict"])
    else:
        log.info("%s", validation["verdict"])
    self.project._inertia_decompiler_stage = "structuring_done"


def apply_x86_16_decompiler_structuring() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_structuring_8616":
        _decompile_structuring_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_structuring_8616
