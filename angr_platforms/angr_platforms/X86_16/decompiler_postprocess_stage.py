from __future__ import annotations

import contextlib
import copy
import logging
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_calls as _calls
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_simplify as _simplify
from . import segmented_memory_reasoning as _segmented_mem
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
)

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
        DecompilerPostprocessPassSpec("_rewrite_flag_condition_pairs_8616", _flags._rewrite_flag_condition_pairs_8616, False),
        DecompilerPostprocessPassSpec("_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_fix_interval_guard_conditions_8616", _flags._fix_interval_guard_conditions_8616, False),
        DecompilerPostprocessPassSpec(
            "_simplify_boolean_cites_8616",
            _simplify._simplify_boolean_cites_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_maybe_eliminate_single_use_temporaries_8616",
            _simplify._maybe_eliminate_single_use_temporaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_lower_stable_ss_stack_accesses_8616",
            _segmented_mem._lower_stable_ss_stack_accesses_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_function_prototype_arg_names_8616",
            _post._normalize_function_prototype_arg_names_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_attach_callsite_summaries_8616",
            _calls._attach_callsite_summaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_prototypes_8616",
            _calls._materialize_callsite_prototypes_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
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
        return DECOMPILER_POSTPROCESS_PASSES[:11]

    return DECOMPILER_POSTPROCESS_PASSES


def describe_x86_16_decompiler_postprocess_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _snapshot_codegen_cfunc(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        return copy.deepcopy(cfunc)
    except Exception:
        return None


def _restore_codegen_cfunc(codegen, snapshot) -> bool:
    if snapshot is None:
        return False
    codegen.cfunc = snapshot
    with contextlib.suppress(Exception):
        setattr(codegen.cfunc, "codegen", codegen)
    for node in _iter_c_nodes_deep_8616(codegen.cfunc):
        with contextlib.suppress(Exception):
            setattr(node, "codegen", codegen)
    return True


def _postprocess_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    accepted_changed = False
    last_changed_pass = None
    codegen._inertia_rewrite_failed = False
    codegen._inertia_rewrite_failure_pass = None
    codegen._inertia_rewrite_failure_error = None
    codegen._inertia_last_postprocess_pass = None
    codegen._inertia_postprocess_validation_failed = False
    codegen._inertia_postprocess_validation_failure_pass = None
    codegen._inertia_postprocess_validation_failure_error = None
    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
    codegen._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
    validation_enabled = bool(getattr(project, "_inertia_tail_validation_enabled", True))
    per_pass_validation_enabled = bool(
        getattr(project, "_inertia_postprocess_per_pass_validation_enabled", False)
    )

    baseline_summary = (
        collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
        if validation_enabled and per_pass_validation_enabled
        else None
    )

    def _apply_step(pass_name: str, step_func) -> bool:
        nonlocal accepted_changed, last_changed_pass
        snapshot = _snapshot_codegen_cfunc(codegen) if per_pass_validation_enabled else None
        try:
            step_changed = bool(step_func())
        except Exception as ex:  # noqa: BLE001
            if per_pass_validation_enabled:
                _restore_codegen_cfunc(codegen, snapshot)
            codegen._inertia_rewrite_failed = True
            codegen._inertia_rewrite_failure_pass = pass_name
            codegen._inertia_rewrite_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 postprocess pass %s after %s: %s",
                pass_name,
                last_changed_pass or "no earlier rewrite",
                ex,
            )
            return False
        if validation_enabled and per_pass_validation_enabled:
            current_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
            validation = compare_x86_16_tail_validation_summaries(baseline_summary, current_summary)
            if validation["changed"]:
                codegen._inertia_postprocess_validation_failed = True
                codegen._inertia_postprocess_validation_failure_pass = pass_name
                codegen._inertia_postprocess_validation_failure_error = validation.get("summary_text")
                _restore_codegen_cfunc(codegen, snapshot)
                return False

        if step_changed:
            accepted_changed = True
            last_changed_pass = pass_name
            codegen._inertia_last_postprocess_pass = pass_name
        return True

    if not _apply_step(
        "_coalesce_word_global_loads_8616",
        lambda: _globals._coalesce_word_global_loads_8616(project, codegen),
    ):
        codegen._inertia_postprocess_changed = accepted_changed
        project._inertia_decompiler_stage = "postprocess"
        return accepted_changed
    if codegen._inertia_postprocess_validation_failed:
        codegen._inertia_postprocess_changed = accepted_changed
        project._inertia_decompiler_stage = "postprocess"
        return accepted_changed
    if not _apply_step(
        "_coalesce_word_global_constant_stores_8616",
        lambda: _globals._coalesce_word_global_constant_stores_8616(project, codegen),
    ):
        codegen._inertia_postprocess_changed = accepted_changed
        project._inertia_decompiler_stage = "postprocess"
        return accepted_changed
    if codegen._inertia_postprocess_validation_failed:
        codegen._inertia_postprocess_changed = accepted_changed
        project._inertia_decompiler_stage = "postprocess"
        return accepted_changed

    for spec in pass_specs:
        project._inertia_decompiler_stage = f"postprocess:{spec.name}"
        if spec.needs_project:
            step = lambda spec=spec: spec.func(project, codegen)
        else:
            step = lambda spec=spec: spec.func(codegen)
        if not _apply_step(spec.name, step):
            break
        if codegen._inertia_postprocess_validation_failed:
            break
    codegen._inertia_postprocess_changed = accepted_changed
    project._inertia_decompiler_stage = "postprocess"
    return accepted_changed


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
    if not bool(getattr(self.project, "_inertia_tail_validation_enabled", True)):
        postprocess_started = time.perf_counter()
        changed = _postprocess_codegen_8616(self.project, self.codegen)
        postprocess_elapsed = time.perf_counter() - postprocess_started
        function = getattr(self, "function", None) or getattr(self, "func", None)
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
                postprocess_info["core_elapsed"] = core_elapsed
                postprocess_info["elapsed"] = postprocess_elapsed
                postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
                postprocess_info["changed"] = bool(changed)
                postprocess_info["failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
                postprocess_info["failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
                postprocess_info["failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
                postprocess_info["validation_failed"] = bool(
                    getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
                )
                postprocess_info["validation_failure_pass"] = getattr(
                    self.codegen, "_inertia_postprocess_validation_failure_pass", None
                )
                postprocess_info["validation_failure_error"] = getattr(
                    self.codegen, "_inertia_postprocess_validation_failure_error", None
                )
                postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
        setattr(self.codegen, "_inertia_tail_validation_snapshot", None)
        self.project._inertia_decompiler_stage = "postprocess_done"
        return

    validation_mode = "live_out"
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    before_collect_started = time.perf_counter()
    before_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    before_collect_elapsed = time.perf_counter() - before_collect_started
    postprocess_started = time.perf_counter()
    changed = _postprocess_codegen_8616(self.project, self.codegen)
    postprocess_elapsed = time.perf_counter() - postprocess_started
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    context = f"{getattr(function, 'addr', 'unknown')!r} {getattr(function, 'name', 'unknown')}"
    if changed:
        _regenerate_text_safely(self.codegen, context=context)
    after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    after_collect_started = time.perf_counter()
    after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    after_collect_elapsed = time.perf_counter() - after_collect_started
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    validation = build_x86_16_tail_validation_cached_result(
        owner=owner if isinstance(owner, MutableMapping) else None,
        stage="postprocess",
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
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    snapshot_function_info = None
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            snapshot_function_info = info
            postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
            postprocess_info["core_elapsed"] = core_elapsed
            postprocess_info["postprocess_elapsed"] = postprocess_elapsed
            postprocess_info["tail_validation_timings"] = validation_timings
            postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
            postprocess_info["rewrite_failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
            postprocess_info["rewrite_failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
            postprocess_info["rewrite_failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
            postprocess_info["validation_failed"] = bool(
                getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
            )
            postprocess_info["validation_failure_pass"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_pass",
                None,
            )
            postprocess_info["validation_failure_error"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_error",
                None,
            )
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
            postprocess_info["tail_validation_verdict"] = validation["verdict"]
            postprocess_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=validation,
    )
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
    log = logging.getLogger(__name__)
    if validation["changed"]:
        log.warning("%s", validation["verdict"])
    else:
        log.info("%s", validation["verdict"])
    self.project._inertia_decompiler_stage = "done"


def apply_x86_16_decompiler_postprocess() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        _decompile_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_8616
