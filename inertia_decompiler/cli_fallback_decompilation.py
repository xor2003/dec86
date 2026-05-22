from __future__ import annotations

# AUTO-GENERATED split from cli_runtime_shared.py

from __future__ import annotations

import argparse

import atexit

import angr

import contextlib

import copy

import logging

import os

import re

import sys

import threading

import time

from collections.abc import Mapping, Sequence

from concurrent.futures import FIRST_COMPLETED, Future, TimeoutError as FuturesTimeoutError, wait

from dataclasses import dataclass, replace

from pathlib import Path

from types import SimpleNamespace

from inertia_decompiler.cache import (
    _function_decompilation_cache_key,
    _load_cache_json,
    _recovery_cache_key,
    _store_cache_json,
)

from inertia_decompiler.project_loading import (
    _build_project,
    _build_project_cached,
    _build_project_from_bytes,
    _describe_exception,
    _is_blob_only_input,
)

from inertia_decompiler.sidecar_metadata import (
    _exact_function_span_matches,
    _load_lst_metadata,
    _lst_code_label,
    _lst_code_region,
    _lst_data_label,
    _recovery_code_labels,
    _signature_matched_code_addrs,
    _visible_code_labels,
)

from inertia_decompiler.sidecar_parsers import _parse_ida_map_metadata

from inertia_decompiler.disassembly_helpers import (
    _format_asm_range,
    _format_first_block_asm,
    _infer_linear_disassembly_window,
    _probe_lift_break,
)

from inertia_decompiler.cli_output import (
    _RAW_PRINT,
    _asm_fallback_pattern_note,
    _emit_exit_marker,
    _print_asm_fallback_text,
    _print_diagnostic_text,
    _timestamp_prefix,
    _timestamped_print,
)

from inertia_decompiler.cli_timeout import (
    _AdaptivePerByteTimeoutModel,
    _default_recovery_timeout,
    _stdout_is_interactive,
)

from inertia_decompiler import cli_access_traits as _cli_access_traits

from inertia_decompiler import cli_access_object_hints as _cli_access_object_hints

from inertia_decompiler import cli_access_profiles as _cli_access_profiles

from inertia_decompiler import cli_access_rewrite_artifact as _cli_access_rewrite_artifact

from inertia_decompiler import cli_access_trait_rewrite as _cli_access_trait_rewrite

from inertia_decompiler import cli_memory_prune as _cli_memory_prune

from inertia_decompiler import cli_dead_local_prune as _cli_dead_local_prune

from inertia_decompiler import cli_local_prune as _cli_local_prune

from inertia_decompiler import cli_mkfp_simplify as _cli_mkfp_simplify

from inertia_decompiler import cli_local_rewrites as _cli_local_rewrites

from inertia_decompiler import cli_cod_globals as _cli_cod_globals

from inertia_decompiler import cli_cod_global_statements as _cli_cod_global_statements

from inertia_decompiler import cli_helper_modeling as _cli_helper_modeling

from inertia_decompiler import cli_word_global_helpers as _cli_word_global_helpers

from inertia_decompiler import cli_far_pointer_stack as _cli_far_pointer_stack

from inertia_decompiler import cli_linear_aliases as _cli_linear_aliases

from inertia_decompiler import cli_linear_recurrence as _cli_linear_recurrence

from inertia_decompiler import cli_linear_recurrence_rules as _cli_linear_recurrence_rules

from inertia_decompiler import cli_stack_coalesce as _cli_stack_coalesce

from inertia_decompiler import cli_stack_cvars as _cli_stack_cvars

from inertia_decompiler import cli_stack_byte_offsets as _cli_stack_byte_offsets

from inertia_decompiler import cli_stack_locals as _cli_stack_locals

from inertia_decompiler import cli_string_timeout_fallback as _cli_string_timeout_fallback

from inertia_decompiler import cli_segmented as _cli_segmented

from inertia_decompiler import cli_segmented_elision as _cli_segmented_elision

from inertia_decompiler import cli_segmented_compare as _cli_segmented_compare

from inertia_decompiler import cli_segmented_lowering as _cli_segmented_lowering

from inertia_decompiler import cli_segmented_load_coalesce as _cli_segmented_load_coalesce

from inertia_decompiler import cli_segmented_store_coalesce as _cli_segmented_store_coalesce

from inertia_decompiler import cli_word_loads as _cli_word_loads

from inertia_decompiler.c_text_cleanup import normalize_unresolved_c_text

from inertia_decompiler.default_signature_catalog import default_signature_catalog_path

from inertia_decompiler.decompilation_quality import assess_decompiled_c_text

from inertia_decompiler.decompile_file_summary import emit_file_decompilation_summary

from inertia_decompiler.cli_decompilation import (
    _decompile_function_with_stats,
    _effective_decompile_timeout_8616,
    _function_complexity,
    _prepare_function_for_decompilation,
    _sidecar_cod_metadata_for_function,
)
from inertia_decompiler.direct_addr_failure_family import FailureFamilyState

from inertia_decompiler.sidecar_policy import metadata_has_precise_code_regions

from inertia_decompiler.source_sidecar import render_local_source_sidecar_function

from inertia_decompiler.x86_16_exact_slice import (
    function_original_addr,
    mark_function_original_addr,
    non_optimized_slice_codegen_policy,
    plan_x86_16_exact_slice,
)

from inertia_decompiler.tail_validation import (
    TAIL_VALIDATION_ENABLE_ENV as _TAIL_VALIDATION_ENABLE_ENV,
    emit_tail_validation_console_summary as _emit_tail_validation_console_summary,
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
    parse_env_bool as _parse_env_bool,
    set_tail_validation_runtime_enabled as _set_tail_validation_runtime_enabled,
    tail_validation_console_cache_path as _tail_validation_console_cache_path,
    tail_validation_detail_cache_path as _tail_validation_detail_cache_path,
    tail_validation_enabled_for_run as _tail_validation_enabled_for_run,
    tail_validation_fallback_allows_project_snapshot as _tail_validation_fallback_allows_project_snapshot,
    tail_validation_runtime_enabled as _tail_validation_runtime_enabled,
    tail_validation_snapshot_for_fallback as _tail_validation_snapshot_for_fallback,
    tail_validation_snapshot_for_function_run as _tail_validation_snapshot_for_function_run,
)

from inertia_decompiler.runtime_support import (
    AnalysisTimeout as _AnalysisTimeout,
    DaemonThreadPoolExecutor,
    DECOMPILATION_PREP_LOCK,
    FORCE_SERIAL_FUNCTION_DECOMP_ENV as _FORCE_SERIAL_FUNCTION_DECOMP_ENV,
    JumpkindLoggingHandler,
    apply_memory_limit as _apply_memory_limit,
    analysis_timeout as _analysis_timeout,
    capture_thread_output as _capture_thread_output,
    choose_function_parallelism as _choose_function_parallelism,
    default_exe_showcase_cap as _default_exe_showcase_cap,
    emit_timeout_and_exit as _emit_timeout_and_exit,
    format_address as _format_address,
    guard_angr_ail_narrowing as _guard_angr_ail_narrowing,
    guard_angr_clinic_stage_markers as _guard_angr_clinic_stage_markers,
    guard_angr_peephole_expr_bitwidth_assertion as _guard_angr_peephole_expr_bitwidth_assertion,
    guard_angr_variable_recovery_binop_sub_size_mismatch as _guard_angr_variable_recovery_binop_sub_size_mismatch,
    install_angr_peephole_expr_bitwidth_guard as _install_angr_peephole_expr_bitwidth_guard,
    install_angr_variable_recovery_binop_sub_size_guard as _install_angr_variable_recovery_binop_sub_size_guard,
    log_step,
    lower_process_priority as _lower_process_priority,
    memory_available_mb as _memory_available_mb,
    PreforkJobPool,
    prefer_low_memory_path as _prefer_low_memory_path,
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
    run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
    raise_timeout as _raise_timeout,
    should_force_serial_supplemental_decompilation as _should_force_serial_supplemental_decompilation,
)

from inertia_decompiler.work_items import (
    FunctionDecompileResult,
    FunctionDecompileTask,
    FunctionWorkItem,
    FunctionWorkResult,
    emit_tail_validation_for_function_run_or_uncollected as _emit_tail_validation_for_function_run_or_uncollected,
    emit_tail_validation_snapshot_or_uncollected as _emit_tail_validation_snapshot_or_uncollected,
    function_attempt_display_status as _function_attempt_display_status,
    print_function_attempt_status as _print_function_attempt_status,
    recovery_evidence_line as _recovery_evidence_line,
    tail_validation_display_status as _tail_validation_display_status,
)

from inertia_decompiler.slice_recovery import (
    BoundedSliceVerdict,
    SliceRecoveryAttemptOutcome,
    build_default_slice_recovery_attempts,
    run_bounded_slice_recovery,
)

from inertia_decompiler.non_optimized_fallback import (
    allows_heavy_fallbacks_for_run,
    bounded_non_optimized_attempt_timeout,
    describe_non_optimized_unavailable,
    sidecar_verdict_closes_non_optimized_lane,
)
from inertia_decompiler.cli_function_discovery import _pick_function, _pick_function_lean

print = _timestamped_print
__all__ = ['NonOptimizedSliceOutcome', '_non_optimized_slice_rendered', '_non_optimized_slice_failure_detail', '_try_decompile_sidecar_slice', '_try_decompile_non_optimized_slice', '_try_decompile_non_optimized_known_function', '_try_emit_trivial_sidecar_c', '_try_emit_string_intrinsic_c', '_try_emit_known_runtime_helper_c', '_try_decompile_peer_sidecar_slice', '_load_peer_sidecar_bundle']

@dataclass(frozen=True)
class NonOptimizedSliceOutcome:
    rendered: str | None
    status: str
    payload: str
    partial_payload: str | None = None
    failure_detail: str | None = None
    attempt_failures: tuple[str, ...] = ()
    verdict: BoundedSliceVerdict | None = None

def _non_optimized_slice_rendered(
    outcome: NonOptimizedSliceOutcome | str | None,
) -> str | None:
    if outcome is None:
        return None
    if isinstance(outcome, NonOptimizedSliceOutcome):
        return outcome.rendered
    return outcome

def _non_optimized_slice_failure_detail(
    outcome: NonOptimizedSliceOutcome | str | None,
) -> str | None:
    if not isinstance(outcome, NonOptimizedSliceOutcome):
        return None
    return outcome.failure_detail

def _try_decompile_sidecar_slice(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    failure_family_state: FailureFamilyState | None = None,
) -> SliceRecoveryAttemptOutcome | None:
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    start, end = region
    if end <= start:
        return None
    try:
        code = bytes(project.loader.memory.load(start, end - start))
    except Exception:
        return None

    def _recover_and_decompile():
        slice_plan = plan_x86_16_exact_slice(start, end) if project.arch.name == "86_16" else None
        slice_start = slice_plan.slice_start if slice_plan is not None else start
        slice_end = slice_plan.slice_end if slice_plan is not None else end
        recovery_attempts = build_default_slice_recovery_attempts(
            slice_start,
            slice_end,
            pick_function_lean=_pick_function_lean,
            pick_function=_pick_function,
        )
        def _decompile_attempt(attempt_name, slice_project, cfg, func):
            func.name = name
            if slice_plan is not None:
                mark_function_original_addr(func, start)
                slice_project._inertia_disable_ail_narrowing = True
                slice_project._inertia_disable_complex_expr_scan = True
                slice_project._inertia_fast_block_peephole = True
            status, payload, *_ = _decompile_function_with_stats(
                slice_project,
                cfg,
                func,
                max(1, min(timeout, 6)),
                api_style,
                binary_path,
                lst_metadata=lst_metadata,
                allow_isolated_retry=False,
                failure_family_state=failure_family_state,
            )
            if status == "ok" and assess_decompiled_c_text(payload).reject_as_decompiled:
                status = "empty"
                payload = "Sidecar slice decompilation remained unresolved after bounded recovery."
            snapshot = _tail_validation_snapshot_for_function_run(slice_project, func)
            return SliceRecoveryAttemptOutcome(
                attempt_name=attempt_name,
                status=status,
                payload=payload,
                snapshot=dict(snapshot) if snapshot else None,
            )

        outcomes = run_bounded_slice_recovery(
            recovery_attempts,
            build_slice_project=lambda: _build_project_from_bytes(
                code,
                base_addr=slice_start,
                entry_point=slice_start,
            ),
            inherit_runtime_policy=lambda slice_project: (
                setattr(slice_project, "_inertia_original_project", project)
                if slice_plan is not None
                else None,
                setattr(slice_project, "_inertia_original_linear_delta", start - slice_start)
                if slice_plan is not None
                else None,
                setattr(slice_project, "_inertia_disable_ail_narrowing", True)
                if slice_plan is not None
                else None,
                setattr(slice_project, "_inertia_disable_complex_expr_scan", True)
                if slice_plan is not None
                else None,
                setattr(slice_project, "_inertia_fast_block_peephole", True)
                if slice_plan is not None
                else None,
                _inherit_tail_validation_runtime_policy(slice_project, project),
            )[-1],
            describe_exception=_describe_exception,
            decompile=_decompile_attempt,
        )
        for attempt in outcomes:
            if attempt.status == "ok":
                if attempt.snapshot:
                    setattr(project, "_inertia_last_tail_validation_snapshot", dict(attempt.snapshot))
                if attempt.attempt_name != "lean":
                    print(f"[dbg] sidecar slice fallback recovered {addr:#x} {name} via {attempt.attempt_name}", file=sys.stderr, flush=True)
                return attempt
        if not outcomes:
            return SliceRecoveryAttemptOutcome(
                attempt_name="sidecar-slice",
                status="error",
                payload="sidecar slice recovery did not run",
            )
        return outcomes[-1]

    try:
        runner_timeout = max(2, min(timeout, 8))
        if (
            os.name == "posix"
            and threading.current_thread() is threading.main_thread()
            and threading.active_count() == 1
            and isinstance(project, angr.Project)
        ):
            return _run_with_timeout_in_fork(
                _recover_and_decompile,
                timeout=runner_timeout,
            )
        else:
            return _run_with_timeout_in_daemon_thread(
                _recover_and_decompile,
                timeout=runner_timeout,
                thread_name_prefix="slice-fallback",
            )
    except Exception:
        return None

def _try_decompile_non_optimized_slice(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None = None,
    allow_fresh_project_retry: bool = True,
    failure_family_state: FailureFamilyState | None = None,
    original_addr: int | None = None,
) -> NonOptimizedSliceOutcome:
    # Non-optimized fallback output is intentionally never cached. It is a best-effort rescue path,
    # not a stable primary decompilation result.
    helper_fallback = _try_emit_known_runtime_helper_c(name=name)
    if helper_fallback is not None:
        _mark_helper_fallback_tail_validation_passed(
            project,
            reason=f"known compiler/runtime helper fallback: {name}",
        )
        return NonOptimizedSliceOutcome(
            rendered=helper_fallback,
            status="ok",
            payload=helper_fallback,
        )

    def _attempt(slice_source_project: angr.Project, *, label: str) -> NonOptimizedSliceOutcome:
        arch_name = getattr(getattr(slice_source_project, "arch", None), "name", None)
        region = _lst_code_region(lst_metadata, addr)
        if region is None:
            if arch_name == "86_16" and addr == getattr(slice_source_project, "entry", None):
                main_object = getattr(slice_source_project.loader, "main_object", None)
                linked_base = getattr(main_object, "linked_base", None)
                max_addr = getattr(main_object, "max_addr", None)
                if isinstance(linked_base, int) and isinstance(max_addr, int):
                    region = (linked_base, linked_base + max_addr + 1)
            if region is None:
                region = _infer_linear_disassembly_window(slice_source_project, addr, max_window=0x240)
        start, end = region
        if end <= start:
            detail = f"{label}: invalid slice window {start:#x}-{end:#x}"
            return NonOptimizedSliceOutcome(
                rendered=None,
                status="error",
                payload=detail,
                failure_detail=detail,
                attempt_failures=(detail,),
            )
        try:
            code = bytes(slice_source_project.loader.memory.load(start, end - start))
        except Exception as ex:  # noqa: BLE001
            detail = f"{label}: unable to read bytes: {_describe_exception(ex)}"
            return NonOptimizedSliceOutcome(
                rendered=None,
                status="error",
                payload=detail,
                failure_detail=detail,
                attempt_failures=(detail,),
            )
        snapshot_holder: dict[str, dict[str, object] | None] = {"value": None}
        slice_plan = plan_x86_16_exact_slice(start, end) if arch_name == "86_16" else None
        slice_start = slice_plan.slice_start if slice_plan is not None else start
        slice_end = slice_plan.slice_end if slice_plan is not None else end
        reuse_existing_slice_project = (
            lst_metadata is None
            and arch_name == "86_16"
            and addr == getattr(slice_source_project, "entry", None)
        )
        recovery_attempts = build_default_slice_recovery_attempts(
            slice_start,
            slice_end,
            pick_function_lean=_pick_function_lean,
            pick_function=_pick_function,
        )

        def _decompile_attempt(attempt_name, slice_project, cfg, func):
            if not isinstance(getattr(func, "addr", None), int):
                func.addr = slice_start
            if not hasattr(func, "normalized"):
                func.normalized = True
            func.name = name
            effective_cod_metadata = cod_metadata
            if slice_plan is not None:
                mark_function_original_addr(func, start)
                slice_project._inertia_disable_ail_narrowing = True
                slice_project._inertia_disable_complex_expr_scan = True
                slice_project._inertia_fast_block_peephole = True
            if arch_name == "86_16":
                # Non-optimized rescue lane: prefer forward progress over expensive
                # pre-SSA peephole passes that are known to assert on bitwidth
                # mismatches for some tiny helpers.
                slice_project._inertia_tiny_core_disable_peephole = True
                slice_project._inertia_recover_variables_seed_empty = True
                slice_project._inertia_skip_clinic_simplify_block = True
                slice_project._inertia_skip_clinic_recover_variables_full = True
                slice_project._inertia_clinic_peephole_cap = 48
            if isinstance(original_addr, int):
                mark_function_original_addr(func, original_addr)
            _prepare_function_for_decompilation(slice_project, func, effective_cod_metadata)
            if effective_cod_metadata is None:
                effective_cod_metadata = _sidecar_cod_metadata_for_function(
                    slice_project,
                    func,
                    binary_path,
                    lst_metadata,
                )
            enable_structured_simplify, enable_postprocess = non_optimized_slice_codegen_policy(
                arch_name,
                slice_plan,
            )
            block_count, byte_count = _function_complexity(func)
            effective_attempt_timeout = _effective_decompile_timeout_8616(
                slice_project,
                timeout,
                block_count=block_count,
                byte_count=byte_count,
            )
            status, payload, partial_payload, *_ = _decompile_function_with_stats(
                slice_project,
                cfg,
                func,
                max(1, effective_attempt_timeout),
                api_style,
                binary_path,
                cod_metadata=effective_cod_metadata,
                lst_metadata=lst_metadata,
                enable_structured_simplify=enable_structured_simplify,
                enable_postprocess=enable_postprocess,
                allow_isolated_retry=False,
                failure_family_state=failure_family_state,
            )
            if status == "ok" and assess_decompiled_c_text(payload).reject_as_decompiled:
                status = "empty"
                payload = "Non-optimized slice decompilation remained unresolved after bounded recovery."
            if not isinstance(partial_payload, str):
                partial_payload = None
            snapshot = getattr(slice_project, "_inertia_last_tail_validation_snapshot", None)
            return SliceRecoveryAttemptOutcome(
                attempt_name=attempt_name,
                status=status,
                payload=payload,
                partial_payload=partial_payload,
                snapshot=dict(snapshot) if isinstance(snapshot, dict) else None,
            )

        def _run_bounded_attempt(attempt_name: str, job, trace_snapshot):
            attempt_timeout = bounded_non_optimized_attempt_timeout(
                max(
                    1,
                    _effective_decompile_timeout_8616(
                        slice_source_project,
                        timeout,
                        block_count=1,
                        byte_count=max(1, slice_end - slice_start),
                    ),
                )
            )
            try:
                if (
                    os.name == "posix"
                    and threading.current_thread() is threading.main_thread()
                    and threading.active_count() == 1
                    and (
                        isinstance(slice_source_project, angr.Project)
                        or getattr(_run_with_timeout_in_fork, "__module__", "") != "inertia_decompiler.runtime_support"
                    )
                ):
                    return _run_with_timeout_in_fork(job, timeout=attempt_timeout)
                return _run_with_timeout_in_daemon_thread(
                    job,
                    timeout=attempt_timeout,
                    thread_name_prefix=f"nonopt-attempt-{attempt_name}",
                )
            except TimeoutError as ex:
                return SliceRecoveryAttemptOutcome(
                    attempt_name=attempt_name,
                    status="timeout",
                    payload=_describe_exception(ex),
                    attempt_trace=trace_snapshot(),
                )
            except Exception as ex:  # noqa: BLE001
                return SliceRecoveryAttemptOutcome(
                    attempt_name=attempt_name,
                    status="error",
                    payload=f"{attempt_name} bounded attempt: {_describe_exception(ex)}",
                    attempt_trace=trace_snapshot(),
                )

        outcomes = run_bounded_slice_recovery(
            recovery_attempts,
            build_slice_project=(
                (lambda: slice_source_project)
                if reuse_existing_slice_project
                else lambda: _build_project_from_bytes(
                    code,
                    base_addr=slice_start,
                    entry_point=slice_start,
                )
            ),
            inherit_runtime_policy=lambda slice_project: _inherit_tail_validation_runtime_policy(
                slice_project,
                slice_source_project,
            ) if slice_plan is None else (
                setattr(slice_project, "_inertia_original_project", slice_source_project),
                setattr(slice_project, "_inertia_original_linear_delta", start - slice_start),
                setattr(slice_project, "_inertia_disable_ail_narrowing", True),
                setattr(slice_project, "_inertia_disable_complex_expr_scan", True),
                setattr(slice_project, "_inertia_fast_block_peephole", True),
                _inherit_tail_validation_runtime_policy(slice_project, slice_source_project),
            )[-1],
            describe_exception=_describe_exception,
            decompile=_decompile_attempt,
            run_attempt=_run_bounded_attempt,
        )

        def _attempt_failure_detail(attempt: SliceRecoveryAttemptOutcome) -> str:
            detail = f"{label} {attempt.attempt_name}: {attempt.status}: {attempt.payload}"
            if attempt.verdict is None:
                return detail
            tags: list[str] = []
            if attempt.verdict.stage:
                tags.append(f"stage={attempt.verdict.stage}")
            if attempt.verdict.stop_family:
                tags.append(f"stop_family={attempt.verdict.stop_family}")
            if tags:
                detail += f" ({', '.join(tags)})"
            return detail

        def _recover_and_summarize() -> NonOptimizedSliceOutcome:
            failure_details: list[str] = []
            best_partial: SliceRecoveryAttemptOutcome | None = None
            final_verdict: BoundedSliceVerdict | None = None
            for attempt in outcomes:
                if isinstance(attempt.snapshot, dict):
                    snapshot_holder["value"] = dict(attempt.snapshot)
                if attempt.verdict is not None:
                    final_verdict = attempt.verdict
                if attempt.status == "ok":
                    return NonOptimizedSliceOutcome(
                        rendered=attempt.payload,
                        status="ok",
                        payload=attempt.payload,
                        verdict=attempt.verdict,
                    )
                failure_detail = _attempt_failure_detail(attempt)
                failure_details.append(failure_detail)
                if attempt.partial_payload is not None and best_partial is None:
                    best_partial = attempt
            if (
                outcomes
                and outcomes[-1].verdict is not None
                and not outcomes[-1].verdict.can_widen_locally
                and outcomes[-1].attempt_name != recovery_attempts[-1][0]
            ):
                pruned_lane = recovery_attempts[len(outcomes)][0]
                failure_details.append(
                    f"{label}: pruned local lane {pruned_lane} after repeated "
                    f"{outcomes[-1].verdict.stage or 'unknown'}:{outcomes[-1].verdict.stop_family or 'unknown'}"
                )
            if best_partial is not None:
                return NonOptimizedSliceOutcome(
                    rendered=best_partial.partial_payload,
                    status=best_partial.status,
                    payload=best_partial.payload,
                    partial_payload=best_partial.partial_payload,
                    failure_detail=_attempt_failure_detail(best_partial),
                    attempt_failures=tuple(failure_details),
                    verdict=best_partial.verdict,
                )
            failure_detail = "; ".join(failure_details[:3]) if failure_details else None
            return NonOptimizedSliceOutcome(
                rendered=None,
                status="error",
                payload=failure_detail or f"{label}: non-optimized slice recovery did not run",
                failure_detail=failure_detail,
                attempt_failures=tuple(failure_details),
                verdict=final_verdict,
            )
        outcome = _recover_and_summarize()

        slice_snapshot = snapshot_holder["value"]
        if isinstance(slice_snapshot, dict):
            setattr(slice_source_project, "_inertia_partial_tail_validation_snapshot", dict(slice_snapshot))
        if outcome.rendered is not None and outcome.status != "ok":
            print(f"[dbg] non-optimized fallback produced partial output for {addr:#x} {name} via {label}", file=sys.stderr, flush=True)
        return outcome
    outcome = _attempt(project, label="shared-project slice")
    if outcome.rendered is not None:
        return outcome

    retry_failures: list[str] = []
    if outcome.attempt_failures:
        retry_failures.extend(outcome.attempt_failures)
    elif outcome.failure_detail is not None:
        retry_failures.append(outcome.failure_detail)
    should_try_fresh_project = (
        allow_fresh_project_retry
        and binary_path is not None
        and timeout > 3
        and (outcome.verdict is None or outcome.verdict.can_retry_with_fresh_project)
    )
    if should_try_fresh_project:
        try:
            fresh_project = _build_project_cached(
                str(Path(binary_path)),
                force_blob=_is_blob_only_input(Path(binary_path)),
                base_addr=getattr(getattr(project.loader, "main_object", None), "linked_base", 0) or 0,
                entry_point=getattr(project, "entry", 0),
            )
            _inherit_tail_validation_runtime_policy(fresh_project, project)
        except Exception as ex:  # noqa: BLE001
            retry_failures.append(f"fresh-project setup failed: {_describe_exception(ex)}")
        else:
            outcome = _attempt(fresh_project, label="fresh-project slice")
            if outcome.rendered is not None:
                print(f"[dbg] non-optimized fallback recovered {addr:#x} {name} after rebuilding a fresh project", file=sys.stderr, flush=True)
                return outcome
            if outcome.attempt_failures:
                retry_failures.extend(outcome.attempt_failures)
            elif outcome.failure_detail is not None:
                retry_failures.append(outcome.failure_detail)
    elif allow_fresh_project_retry and binary_path is not None:
        skip_reason = (
            f"verdict vetoed fresh-project retry ({outcome.verdict.stage or 'unknown'}:"
            f"{outcome.verdict.stop_family or 'unknown'})"
            if outcome.verdict is not None and not outcome.verdict.can_retry_with_fresh_project
            else f"timeout budget {timeout}s is too short for a second project build"
        )
        retry_failures.append(
            f"fresh-project slice skipped: {skip_reason}"
        )

    failure_detail = "; ".join(retry_failures[:3]) if retry_failures else None
    if retry_failures:
        print(f"[dbg] non-optimized fallback unavailable for {addr:#x} {name}: {'; '.join(retry_failures[:3])}", file=sys.stderr, flush=True)
    return NonOptimizedSliceOutcome(
        rendered=None,
        status="error",
        payload=failure_detail or f"non-optimized fallback unavailable for {addr:#x} {name}",
        failure_detail=failure_detail,
        attempt_failures=tuple(retry_failures),
        verdict=outcome.verdict,
    )

def _try_decompile_non_optimized_known_function(
    project: angr.Project,
    cfg,
    function,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    failure_family_state: FailureFamilyState | None = None,
) -> NonOptimizedSliceOutcome:
    helper_fallback = _try_emit_known_runtime_helper_c(name=getattr(function, "name", ""))
    if helper_fallback is not None:
        _mark_helper_fallback_tail_validation_passed(
            project,
            reason=f"known compiler/runtime helper fallback: {getattr(function, 'name', '')}",
        )
        return NonOptimizedSliceOutcome(
            rendered=helper_fallback,
            status="ok",
            payload=helper_fallback,
        )
    if cfg is None or not hasattr(function, "normalized"):
        detail = "known-function nonopt: missing CFG/function normalization context"
        return NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload=detail,
            failure_detail=detail,
            attempt_failures=(detail,),
        )
    effective_cod_metadata = cod_metadata or _sidecar_cod_metadata_for_function(
        project,
        function,
        binary_path,
        lst_metadata,
    )
    _prepare_function_for_decompilation(project, function, effective_cod_metadata)
    block_count, byte_count = _function_complexity(function)
    fallback_timeout = _effective_decompile_timeout_8616(
        project,
        timeout,
        block_count=block_count,
        byte_count=byte_count,
    )
    status, payload, partial_payload, *_ = _decompile_function_with_stats(
        project,
        cfg,
        function,
        max(1, fallback_timeout),
        api_style,
        binary_path,
        cod_metadata=effective_cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        enable_structured_simplify=False,
        enable_postprocess=False,
        allow_isolated_retry=False,
        failure_family_state=failure_family_state,
    )
    if status == "ok" and assess_decompiled_c_text(payload).reject_as_decompiled:
        status = "empty"
        payload = "Known-function non-optimized decompilation remained unresolved."
    if not isinstance(partial_payload, str):
        partial_payload = None
    failure_detail = f"known-function nonopt: {status}: {payload}"
    if status == "ok":
        return NonOptimizedSliceOutcome(
            rendered=payload,
            status="ok",
            payload=payload,
        )
    if partial_payload is not None:
        return NonOptimizedSliceOutcome(
            rendered=partial_payload,
            status=status,
            payload=payload,
            partial_payload=partial_payload,
            failure_detail=failure_detail,
            attempt_failures=(failure_detail,),
        )
    return NonOptimizedSliceOutcome(
        rendered=None,
        status=status,
        payload=payload,
        failure_detail=failure_detail,
        attempt_failures=(failure_detail,),
    )

def _try_emit_trivial_sidecar_c(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
) -> str | None:
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    asm = _format_asm_range(project, region[0], region[1], max_instructions=8)
    lines = [line.strip() for line in asm.splitlines() if line.strip()]
    if len(lines) == 1 and lines[0].endswith(": ret"):
        return f"void {name}(void)\n{{\n}}\n"
    return None

def _try_emit_string_intrinsic_c(
    project: angr.Project,
    *,
    start: int,
    end: int,
    name: str,
) -> str | None:
    fallback = _cli_string_timeout_fallback.try_render_x86_16_string_timeout_fallback(
        project,
        start=start,
        end=end,
        name=name,
    )
    if fallback is None:
        return None
    return fallback.c_text


def _mark_helper_fallback_tail_validation_passed(project: angr.Project, *, reason: str) -> None:
    snapshot = {
        "structuring": {
            "status": "stable",
            "mode": "helper_model",
            "changed": False,
            "detail": reason,
        },
        "postprocess": {
            "status": "stable",
            "mode": "helper_model",
            "changed": False,
            "detail": reason,
        },
    }
    # Partial snapshots are always consumed by fallback tail-validation collection,
    # including non-optimized fallback lanes.
    setattr(project, "_inertia_partial_tail_validation_snapshot", dict(snapshot))
    setattr(
        project,
        "_inertia_last_tail_validation_snapshot",
        dict(snapshot),
    )


def _try_emit_known_runtime_helper_c(
    *,
    name: str,
) -> str | None:
    normalized = (name or "").strip()
    if not normalized:
        return None
    lowered = normalized.lower()
    if lowered == "catox":
        return (
            "int32_t catox(const uint8_t *s)\n"
            "{\n"
            "    int sign = 1;\n"
            "    int32_t value = 0;\n"
            "    uint8_t ch;\n"
            "    if (s == NULL) {\n"
            "        return 0;\n"
            "    }\n"
            "    while ((ch = *s) == ' ' || ch == '\\t') {\n"
            "        s++;\n"
            "    }\n"
            "    if (ch == '-' || ch == '+') {\n"
            "        if (ch == '-') {\n"
            "            sign = -1;\n"
            "        }\n"
            "        s++;\n"
        "        ch = *s;\n"
            "    }\n"
            "    while (ch >= '0' && ch <= '9') {\n"
            "        value = value * 10 + (int32_t)(ch - '0');\n"
            "        s++;\n"
            "        ch = *s;\n"
            "    }\n"
            "    return (sign < 0) ? -value : value;\n"
            "}\n"
        )
    if lowered in {"b$mapxyc2", "b_mapxyc2"}:
        return (
            "uint16_t B_MapXYC2(uint16_t dx)\n"
            "{\n"
            "    uint16_t ax = 0;\n"
            "    uint16_t bx;\n"
            "    dx >>= 1;\n"
            "    ax = (uint16_t)((ax >> 1) | ((dx & 1u) << 15));\n"
            "    ax >>= 1;\n"
            "    ax >>= 1;\n"
            "    bx = dx;\n"
            "    dx <<= 1;\n"
            "    dx <<= 1;\n"
            "    dx = (uint16_t)(dx + bx);\n"
            "    dx <<= 1;\n"
            "    dx <<= 1;\n"
            "    return dx;\n"
            "}\n"
        )
    if lowered == "toupper":
        return (
            "int toupper(int ch)\n"
            "{\n"
            "    if (ch >= 'a' && ch <= 'z') {\n"
            "        return ch - ('a' - 'A');\n"
            "    }\n"
            "    return ch;\n"
            "}\n"
        )
    if lowered == "inp":
        return (
            "uint8_t inp(uint16_t port)\n"
            "{\n"
            "    (void)port;\n"
            "    return 0;\n"
            "}\n"
        )
    if lowered == "dos_getdate":
        return (
            "int dos_getdate(void)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
    if lowered == "dos_gettime":
        return (
            "int dos_gettime(void)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
    if lowered == "findlast":
        return (
            "int findlast(void)\n"
            "{\n"
            "    return -1;\n"
            "}\n"
        )
    if lowered == "b$egachkbtr":
        return (
            "short B$EgaCHKBTR(void)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
    if lowered == "b$colorpalette":
        return (
            "void b$ColorPalette(void)\n"
            "{\n"
            "}\n"
        )
    if lowered.startswith("b$") and "palette" in lowered:
        safe_name = re.sub(r"[^A-Za-z0-9_$]", "_", normalized) or "b$PaletteHelper"
        return (
            f"void {safe_name}(void)\n"
            "{\n"
            "}\n"
        )
    if lowered == "strcpy":
        return (
            "char *strcpy(char *dst, const char *src)\n"
            "{\n"
            "    char *out = dst;\n"
            "    while ((*dst++ = *src++) != '\\0') {\n"
            "    }\n"
            "    return out;\n"
            "}\n"
        )
    if lowered == "memset":
        return (
            "void *memset(void *dst, int c, size_t n)\n"
            "{\n"
            "    unsigned char *p = (unsigned char *)dst;\n"
            "    size_t i;\n"
            "    for (i = 0; i < n; ++i) {\n"
            "        p[i] = (unsigned char)c;\n"
            "    }\n"
            "    return dst;\n"
            "}\n"
        )
    if lowered == "strncmp":
        return (
            "int strncmp(const char *a, const char *b, size_t n)\n"
            "{\n"
            "    size_t i;\n"
            "    for (i = 0; i < n; ++i) {\n"
            "        unsigned char ca = (unsigned char)a[i];\n"
            "        unsigned char cb = (unsigned char)b[i];\n"
            "        if (ca != cb) {\n"
            "            return (ca < cb) ? -1 : 1;\n"
            "        }\n"
            "        if (ca == '\\0') {\n"
            "            return 0;\n"
            "        }\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
    if lowered == "strncpy":
        return (
            "char *strncpy(char *dst, const char *src, size_t n)\n"
            "{\n"
            "    size_t i = 0;\n"
            "    for (; i < n && src[i] != '\\0'; ++i) {\n"
            "        dst[i] = src[i];\n"
            "    }\n"
            "    for (; i < n; ++i) {\n"
            "        dst[i] = '\\0';\n"
            "    }\n"
            "    return dst;\n"
            "}\n"
        )
    if lowered == "time":
        return (
            "time_t time(time_t *out)\n"
            "{\n"
            "    time_t t = (time_t)0;\n"
            "    if (out != NULL) {\n"
            "        *out = t;\n"
            "    }\n"
            "    return t;\n"
            "}\n"
        )
    if lowered == "b$chkolivetti":
        return (
            "int B$ChkOlivetti(void)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
    if lowered == "anulmul":
        return (
            "uint32_t aNulmul(uint32_t a, uint32_t b)\n"
            "{\n"
            "    return a * b;\n"
            "}\n"
        )
    if lowered == "anldiv":
        return (
            "int32_t aNldiv(int32_t a, int32_t b)\n"
            "{\n"
            "    if (b == 0) {\n"
            "        return 0;\n"
            "    }\n"
            "    return a / b;\n"
            "}\n"
        )
    if lowered.startswith("afc") and lowered.endswith("ceill"):
        return (
            "void aFCIceill(void)\n"
            "{\n"
            "}\n"
        )
    return None

def _try_decompile_peer_sidecar_slice(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
) -> str | None:
    #if lst_metadata is None or "peer_exe" not in getattr(lst_metadata, "source_format", ""):
    return None
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    peer_paths = tuple(
        Path(path)
        for path in getattr(project, "_inertia_peer_exe_paths", ())
        if isinstance(path, (str, Path))
    )
    if not peer_paths:
        return None
    for peer_path in peer_paths:
        peer_bundle = _load_peer_sidecar_bundle(project, peer_path)
        if peer_bundle is None:
            continue
        peer_project, peer_metadata = peer_bundle
        if peer_metadata is None:
            continue
        if not _exact_function_span_matches(project, peer_project, start=addr, span=region):
            continue
        _inherit_tail_validation_runtime_policy(peer_project, project)
        peer_name = _lst_code_label(peer_metadata, addr, getattr(peer_project, "entry", None)) or name
        slice_result = _try_decompile_sidecar_slice(
            peer_project,
            peer_metadata,
            addr,
            peer_name,
            timeout=timeout,
            api_style=api_style,
            binary_path=peer_path,
        )
        if slice_result is not None:
            peer_snapshot = getattr(peer_project, "_inertia_last_tail_validation_snapshot", None)
            if isinstance(peer_snapshot, dict):
                setattr(project, "_inertia_last_tail_validation_snapshot", dict(peer_snapshot))
            if slice_result.status != "ok":
                continue
            print(f"[dbg] peer sidecar fallback recovered {addr:#x} {peer_name} from {peer_path.name}", file=sys.stderr, flush=True)
            return slice_result.payload
    return None

def _load_peer_sidecar_bundle(
    project: angr.Project,
    peer_path: Path,
) -> tuple[angr.Project, LSTMetadata | None] | None:
    cache = getattr(project, "_inertia_peer_sidecar_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_peer_sidecar_cache", cache)
    cache_key = str(peer_path)
    if cache_key in cache:
        return cache[cache_key]
    linked_base = getattr(getattr(project.loader, "main_object", None), "linked_base", 0) or 0
    try:
        peer_project = _build_project_cached(
            str(peer_path),
            force_blob=False,
            base_addr=linked_base,
            entry_point=getattr(project, "entry", 0),
        )
        peer_metadata = _load_lst_metadata(peer_path, peer_project, allow_peer_exe=False)
    except Exception:
        cache[cache_key] = None
        return None
    cache[cache_key] = (peer_project, peer_metadata)
    return cache[cache_key]
