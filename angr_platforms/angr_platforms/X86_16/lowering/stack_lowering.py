from __future__ import annotations

import logging
import os

# Layer: Lowering
# Responsibility: canonical stack/local lowering from typed alias evidence.
# Forbidden: rendered-text parsing and CLI guessing.
from collections.abc import Callable

from ..stack_probe_fact_trace import (
    record_stable_ss_lowering_refusal_8616,
    record_stable_ss_lowering_replacement_8616,
)
from .real_mode_linear import (
    lower_stable_ds_es_linear_global_addresses_8616,
    lower_stable_ds_es_linear_global_dereferences_8616,
    lower_stable_ss_linear_stack_dereferences_8616,
)
from .segmented_memory_lowering import apply_runtime_segment_lowering_8616
from .stack_lowering_impl import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
)
from .stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)

log = logging.getLogger(__name__)


def _record_lowering_change_8616(codegen) -> None:
    if codegen is not None:
        record_stable_ss_lowering_replacement_8616(codegen)


def _initialize_stack_lowering_debug_state_8616(codegen, typed_stack_probe_return_facts) -> int:
    if codegen is None:
        return 0
    codegen._inertia_typed_stack_probe_return_facts = (
        build_typed_stack_probe_return_facts_8616(codegen)
        if typed_stack_probe_return_facts is None
        else typed_stack_probe_return_facts
    )
    codegen._inertia_ss_lowering_refusal_log = []
    debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
    if not isinstance(debug_stats, dict):
        debug_stats = {}
        codegen._inertia_stack_lowering_debug = debug_stats
    debug_stats.setdefault("candidate_text_match_count", 0)
    debug_stats.setdefault("candidate_ast_match_count", 0)
    debug_stats.setdefault("lowering_replacements", 0)
    debug_stats.setdefault("lowering_refusals", 0)
    debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
    return len(getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {})


def _record_stack_lowering_refusal_8616(codegen) -> None:
    debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
    if isinstance(debug_stats, dict):
        debug_stats["lowering_refusals"] = int(debug_stats.get("lowering_refusals", 0) or 0) + 1
        reasons = debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
        reasons["no_codegen_match"] = int(reasons.get("no_codegen_match", 0) or 0) + 1
    record_stable_ss_lowering_refusal_8616(codegen)


def _run_single_stack_lowering_round_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None,
    codegen,
    project,
    typed_fact_count: int,
    lower_global_segment_accesses: bool,
    lower_runtime_segment_accesses: bool,
) -> bool:
    def _impl():
        round_changed = False
        if codegen is not None and lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project):
            _record_lowering_change_8616(codegen)
            round_changed = True
        if (
            lower_global_segment_accesses
            and codegen is not None
            and lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)
        ):
            _record_lowering_change_8616(codegen)
            round_changed = True
        if (
            lower_global_segment_accesses
            and codegen is not None
            and lower_stable_ds_es_linear_global_addresses_8616(codegen, project=project)
        ):
            _record_lowering_change_8616(codegen)
            round_changed = True
            if lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project):
                codegen._inertia_global_deref_after_address_materialized_count = (
                    int(getattr(codegen, "_inertia_global_deref_after_address_materialized_count", 0) or 0) + 1
                )
                _record_lowering_change_8616(codegen)
                round_changed = True
        if (
            lower_runtime_segment_accesses
            and codegen is not None
            and apply_runtime_segment_lowering_8616(
                codegen,
                target=str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat"),
            )
        ):
            _record_lowering_change_8616(codegen)
            round_changed = True
        if lower_stable_ss_stack_accesses is not None:
            lowered = lower_stable_ss_stack_accesses()
            if lowered:
                _record_lowering_change_8616(codegen)
                round_changed = True
            elif codegen is not None and typed_fact_count > 0:
                _record_stack_lowering_refusal_8616(codegen)
        if rewrite_ss_stack_byte_offsets():
            _record_lowering_change_8616(codegen)
            round_changed = True
        if canonicalize_stack_cvars():
            _record_lowering_change_8616(codegen)
            round_changed = True
        return round_changed

    return _impl()


def _emit_stack_lowering_debug_summary_8616(codegen) -> None:
    def _impl():
        if codegen is None:
            return
        refusal_log = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
        if isinstance(refusal_log, list) and refusal_log:
            if not hasattr(codegen, "_inertia_ss_lowering_refusal_summary"):
                codegen._inertia_ss_lowering_refusal_summary = []
            codegen._inertia_ss_lowering_refusal_summary.extend(refusal_log)
        if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            return
        debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(debug_stats, dict):
            log.warning(
                "[stack-lowering] function=%#x stable_stack_fact_count=%d stable_bp_fact_count=%d stack_binding_count=%d candidate_text_match_count=%d candidate_ast_match_count=%d lowering_replacements=%d lowering_refusals=%d reasons=%r",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                int(debug_stats.get("stable_stack_fact_count", 0) or 0),
                int(debug_stats.get("stable_bp_fact_count", 0) or 0),
                int(debug_stats.get("stack_binding_count", 0) or 0),
                int(debug_stats.get("candidate_text_match_count", 0) or 0),
                int(debug_stats.get("candidate_ast_match_count", 0) or 0),
                int(debug_stats.get("lowering_replacements", 0) or 0),
                int(debug_stats.get("lowering_refusals", 0) or 0),
                debug_stats.get("stable_ss_lowering_refusal_reasons", {}),
            )

    return _impl()


def run_stack_lowering_pass_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None = None,
    codegen=None,
    project=None,
    typed_stack_probe_return_facts: dict[int, TypedStackProbeReturnFact8616] | None = None,
    max_rounds: int = 2,
    lower_global_segment_accesses: bool = True,
    lower_runtime_segment_accesses: bool = True,
) -> bool:
    typed_fact_count = _initialize_stack_lowering_debug_state_8616(codegen, typed_stack_probe_return_facts)
    changed = False
    for _ in range(max(max_rounds, 1)):
        round_changed = _run_single_stack_lowering_round_8616(
            rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
            canonicalize_stack_cvars=canonicalize_stack_cvars,
            lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
            codegen=codegen,
            project=project,
            typed_fact_count=typed_fact_count,
            lower_global_segment_accesses=lower_global_segment_accesses,
            lower_runtime_segment_accesses=lower_runtime_segment_accesses,
        )
        if not round_changed:
            break
        changed = True
    _emit_stack_lowering_debug_summary_8616(codegen)
    return changed


__all__ = (
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_materialize_stack_cvar_at_offset",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "TypedStackProbeReturnFact8616",
    "build_typed_stack_probe_return_facts_8616",
    "run_stack_lowering_pass_8616",
)
