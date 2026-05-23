# AUTO-GENERATED split from cli_runtime_shared.py

from __future__ import annotations

import argparse

import atexit

import contextlib

import copy

import logging

import os

import re

import sys

import threading

import time

from collections.abc import Mapping, Sequence
from collections import Counter

from concurrent.futures import FIRST_COMPLETED, Future, TimeoutError as FuturesTimeoutError, wait

from dataclasses import dataclass, replace

from pathlib import Path

from types import SimpleNamespace

from angr_platforms.X86_16.cod_extract import (
    extract_cod_function_entries,
    extract_cod_proc_metadata,
    infer_cod_logic_start,
    extract_simple_cod_logic_entries,
    extract_small_two_arg_cod_logic_entries,
    join_cod_entries_with_synthetic_globals,
)
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616

from .cli_c_ast_rewrites import (
    _attach_cod_callee_names,
    _build_cod_positive_bp_alias_map,
    _cod_stack_alias_for_disp,
    _attach_cod_variable_names,
    _synthetic_global_entry,
    _sanitize_cod_identifier,
    _get_or_seed_inertia_alias_state,
    _make_unique_identifier,
    _structured_codegen_node,
    _c_constant_value,
    _normalize_16bit_signed_offset,
    _project_rewrite_cache,
    _CODSourceRewriteSpec,
    _segment_reg_name,
    _classify_segmented_addr_expr,
    _classify_segmented_dereference,
    _match_real_mode_linear_expr,
    _match_segmented_dereference,
    _match_segment_register_based_dereference,
    _strip_segment_scale_from_addr_expr,
    _match_ss_stack_reference,
    _flatten_c_add_terms,
    _resolve_dirty_virtual_expr_8616,
    _match_stack_cvar_and_offset,
    _match_ss_local_plus_const,
    _replace_c_children,
    _iter_c_nodes_deep,
    _same_c_expression,
    _same_c_storage,
    _same_stack_slot_identity,
    _stack_slot_identity_can_join,
    _is_c_constant_int,
    _cite_is_negation,
    _invert_comparison_op,
    _make_inverted_comparison,
    _invert_interval_guard_if_safe,
    _extract_same_zero_compare_expr,
    _extract_zero_flag_source_expr,
    _simplify_zero_flag_comparison,
    _match_high_byte_projection_base,
    _match_adjacent_register_pair_var_expr,
    _match_high_byte_projection_expr,
    _match_high_byte_projection_constant,
    _simplify_boolean_expr,
    _simplify_zero_mul_or_expr,
    _simplify_basic_algebraic_identities,
    _simplify_structured_c_expressions,
    _unwrap_c_casts,
    _match_shift_right_8_expr,
    _match_duplicate_word_increment_shift_expr,
    _match_duplicate_word_base_expr,
    _attach_cod_global_names,
    _attach_cod_global_declaration_names,
    _attach_cod_global_declaration_types,
    _access_trait_field_name,
    _stack_object_name,
    _access_trait_variable_key,
    _access_trait_profile_for_key,
    _WideningMatch,
    _AccessTraitRewriteDecision,
    _build_access_trait_evidence_profiles,
    _analyze_widening_expr,
    _access_trait_member_candidates,
    _should_attach_access_trait_names,
    _attach_access_trait_field_names,
    _attach_pointer_member_names,
    _attach_lst_data_names,
    _normalize_scalar_byte_register_types,
    _attach_segment_register_names,
    _attach_register_names,
    _elide_redundant_segment_pointer_dereferences,
    _collect_access_traits,
    _prune_unused_unnamed_memory_declarations,
    _prune_unused_linear_register_declarations,
    _prune_unused_local_declarations,
    _prune_dead_local_assignments,
    _materialize_missing_stack_local_declarations,
    _dedupe_codegen_variable_names_8616,
    _materialize_missing_register_local_declarations,
    _prune_void_function_return_values,
    _coalesce_far_pointer_stack_expressions,
    _simplify_nested_mk_fp_calls,
    _attach_ss_stack_variables,
    _rewrite_ss_stack_byte_offsets,
    _promote_direct_stack_cvariable,
    _stack_type_for_size,
    _resolve_stack_cvar_at_offset,
    _materialize_stack_cvar_at_offset,
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _resolve_stack_cvar_from_addr_expr,
    _coalesce_direct_ss_local_word_statements,
    _seed_adjacent_byte_pair_aliases,
    _coalesce_linear_recurrence_statements,
    _coalesce_segmented_word_store_statements,
    _run_typed_widening_pass,
    _global_memory_addr,
    _global_load_addr,
    _match_scaled_high_byte,
    _extract_dereference_addr_expr,
    _match_byte_load_addr_expr,
    _match_byte_store_addr_expr,
    _match_shifted_high_byte_addr_expr,
    _match_word_pair_low_addr_expr,
    _split_expr_const_offset,
    _same_expression_list,
    _addr_exprs_are_same,
    _addr_exprs_are_byte_pair,
    _make_word_dereference_from_addr_expr,
    _match_word_dereference_addr_expr,
    _match_word_rhs_from_byte_pair,
    _high_byte_store_addr,
    _synthetic_word_global_variable,
    _coalesce_cod_word_global_loads,
    _coalesce_segmented_word_load_expressions,
    _coalesce_cod_word_global_statements,
    _int21_call_replacements,
    _interrupt_call_replacement_map,
    _dos_helper_declarations,
    _interrupt_helper_declarations,
    _known_helper_declarations,
    _is_staging_local_name,
    _clone_structured_c_value,
    _prune_tiny_wrapper_staging_locals,
)

from .cli_c_text_postprocess import (
    _normalize_anonymous_call_targets,
    _prune_void_function_return_values_text,
    _contains_void_function_definition_text,
    _normalize_function_signature_arg_names,
    _materialize_missing_generic_local_declarations_text,
    _materialize_annotated_cod_declarations_text,
    _source_args_from_cod_source_lines,
    _repair_missing_cod_function_header_text,
    _render_cod_source_function_text,
    _restore_collapsed_cod_source_function_text,
    _dedupe_duplicate_local_declarations_text,
    _normalize_spurious_duplicate_local_suffixes,
    _collapse_duplicate_type_keywords_text,
    _dedupe_adjacent_prototype_lines,
    _sanitize_mangled_autonames_text,
    _prune_trailing_generic_return_text,
    _collapse_annotated_stack_aliases_text,
    _split_top_level_binary,
    _simplify_negated_condition,
    _simplify_condition_line,
    _simplify_x86_16_conditions,
    _split_simple_assignment_conditions,
    _simplify_x86_16_wrapped_stack_offsets,
    _simplify_x86_16_stack_byte_pointers,
    _format_bp_disp,
    _annotate_cod_proc_output,
    _prune_unused_staging_assignments,
    _rewrite_known_helper_signature_text,
    _prune_unused_local_declarations_text,
    _format_known_helper_calls,
    _repair_missing_fallthrough_returns,
    _normalize_boolean_conditions,
    _normalize_mk_fp_segment_names,
    _simplify_x86_16_stack_references,
)

from .cli_decompilation import (
    _apply_binary_specific_annotations,
    _sidecar_cod_metadata_for_function,
    _snapshot_codegen_text,
    _regenerate_codegen_text_safely,
    _emit_optional_source_sidecar_c_block,
    _format_minimal_codegen_output,
    _apply_known_cod_object_annotations,
    _cod_proc_has_call_heavy_helper_profile,
    _decompile_function,
    _function_complexity,
    _direct_call_stub_filter_regions,
    _register_direct_call_target_function_stubs,
    _prepare_function_for_decompilation,
    _function_decompilation_profile,
    _preferred_decompiler_options,
    _preferred_expr_collapse_depth,
    _effective_decompile_timeout_8616,
    _decompile_function_with_stats,
)

from .cli_fallback_decompilation import (
    NonOptimizedSliceOutcome,
    _non_optimized_slice_rendered,
    _non_optimized_slice_failure_detail,
    _try_decompile_sidecar_slice,
    _try_decompile_non_optimized_slice,
    _try_decompile_non_optimized_known_function,
    _try_emit_trivial_sidecar_c,
    _try_emit_string_intrinsic_c,
    _try_decompile_peer_sidecar_slice,
    _load_peer_sidecar_bundle,
)

from .cli_function_discovery import (
    _seed_scan_windows,
    _entry_window_seed_targets,
    _linear_function_seed_targets,
    _looks_like_x86_16_function_prologue,
    _looks_like_x86_16_entry_byte,
    _resolve_x86_16_function_start,
    _resolve_x86_16_call_target,
    _infer_x86_16_linear_region,
    _pick_function,
    _pick_function_lean,
    _x86_16_recovery_windows,
    _x86_16_fast_recovery_windows,
    _recover_cfg,
    _recover_partial_cfg,
    _function_skip_reason,
    _function_recovery_score,
    _function_covered_ranges,
    _addr_in_ranges,
    _candidate_recovery_regions,
    _richest_bounded_recovery_region,
    _recovery_score_good_enough,
    _exact_region_recovery_looks_truncated,
    _count_region_local_functions,
    _function_recovery_truncated,
    _needs_pre_entry_body_supplement,
    _prioritized_pre_entry_follow_on_targets,
    _mark_function_recovery_truncated,
    _recover_candidate_function_pair,
    _interesting_functions,
    _rank_function_cfg_pairs_for_display,
    _expanded_exe_discovery_limit,
    _supplement_cached_seeded_recovery,
    _store_catalog_address_cache,
    _load_catalog_address_cache,
    _supplement_functions_from_prologue_scan,
    _rank_gap_scan_candidate_addrs,
    _rank_prologue_scan_candidate_addrs,
    _relocation_seed_targets,
    _rank_exe_function_seeds,
    _recover_fast_seed_functions,
    _recover_fast_exe_catalog,
    _recover_hidden_sidecar_display_pairs,
    _rank_hidden_sidecar_pairs_for_display_throughput,
    _recover_cached_function_pairs,
    _candidate_recovery_cache_key,
    _lookup_candidate_recovery_cache,
    _store_candidate_recovery_cache,
    _persistent_recovery_attempt_cache_key,
    _lookup_persistent_recovery_timeout,
    _recover_candidate_with_timeout,
    _recover_seeded_exe_functions,
    _direct_recovery_inventory_count,
    _fallback_entry_function,
    _recover_lst_function,
    _recover_ranked_binary_function,
    _make_placeholder_function,
    _is_zero_filled_region,
    _rank_labeled_function_entries,
    _sidecar_label_ranking_cache_key,
    _rank_labeled_function_entries_cached,
    _select_sidecar_showcase_entries,
    _format_sidecar_function_catalog,
    _recover_blob_entry_function,
    _recover_direct_addr_function,
    _recover_lst_function,
)

from .cli_interrupt_modeling import (
    InterruptWrapperCall,
    InterruptWrapperFieldAccess,
    _normalize_interrupt_wrapper_name,
    _interrupt_wrapper_call_kind,
    _interrupt_wrapper_call_signature,
    _interrupt_wrapper_field_path,
    _interrupt_wrapper_field_role,
    _interrupt_wrapper_field_access_summary,
    _interrupt_wrapper_call_text,
    collect_interrupt_wrapper_calls,
    collect_interrupt_wrapper_field_accesses,
    _attach_interrupt_wrapper_callees,
    _interrupt_wrapper_register_state_value,
    _interrupt_wrapper_record_register_write,
    _interrupt_wrapper_helper_call_expr,
    _interrupt_wrapper_result_helper_expr,
    _interrupt_wrapper_result_extract_expr,
    _interrupt_wrapper_result_replacement,
    _interrupt_wrapper_result_expr_replacement,
    _lower_interrupt_wrapper_result_reads,
    _attach_dos_pseudo_callees,
)
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
from inertia_decompiler.recompile_check import check_c_recompiles_8616

from inertia_decompiler.decompile_file_summary import emit_file_decompilation_summary

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
    format_tail_validation_diagnostic as _format_tail_validation_diagnostic,
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
    x86_16_tail_validation_snapshot_passed,
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
    timing_output_enabled as _timing_output_enabled,
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

from inertia_decompiler.direct_addr_failure_family import FailureFamilyState, build_failure_family_snapshot

print = _timestamped_print
__all__ = ['_argument_was_explicit', '_parse_int', '_function_recovery_detail', '_bounded_non_optimized_timeout', '_direct_addr_wall_clock_budget', '_prepare_ranked_binary_preview_items', '_supplement_function_cfg_pairs_with_ranked_preview', '_supplement_function_cfg_pairs_with_seeded_recovery', '_function_work_cache_lookup', '_run_function_work_item', '_function_work_result_for_fork_ipc', '_emit_function_timing_summary', '_helper_name', '_iter_c_nodes', 'main']

def _argument_was_explicit(name: str) -> bool:
    flag = name.strip()
    for token in sys.argv[1:]:
        if token == flag or token.startswith(f"{flag}="):
            return True
    return False

def _parse_int(value: str) -> int:
    return int(value, 0)

def _function_recovery_detail(stage: str | None) -> str | None:
    if stage == "recovery":
        return "during x86-16 function recovery"
    if isinstance(stage, str) and stage.startswith("recovery:"):
        recovery_stage = stage.split(":", 1)[1]
        if recovery_stage == "fast":
            return "during x86-16 function recovery (fast CFGFast)"
        if recovery_stage.startswith("narrow"):
            return "during x86-16 function recovery (narrow CFGFast)"
        if recovery_stage == "full":
            return "during x86-16 function recovery (full CFGFast)"
        return f"during x86-16 function recovery ({recovery_stage})"
    return None

def _bounded_non_optimized_timeout(timeout: int) -> int:
    # The non-optimized slice path is our recovery fallback after bounded
    # function discovery times out. Very small caps cause deterministic
    # failures for medium procedures that need project/slice setup plus
    # decompiler warmup before emitting fallback C.
    return min(max(1, timeout), 20)

def _direct_addr_wall_clock_budget(timeout: int, *, effective_timeout: int | None = None) -> int:
    # One-function direct-address recovery may chain bounded recovery,
    # non-optimized fallback, and final attribution. Keep that lane inside a
    # deterministic wall-clock budget so callers see an explicit timeout class
    # instead of an outer subprocess kill.
    base = max(1, effective_timeout if isinstance(effective_timeout, int) else timeout)
    return max(2, base + _bounded_non_optimized_timeout(base) + 2)

def _prepare_ranked_binary_preview_items(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    max_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> list[FunctionWorkItem]:
    if max_count <= 0 or not ranked_binary_offsets:
        return []

    preview_items: list[FunctionWorkItem] = []
    selected_addrs: set[int] = set()
    quick_timeout = min(timeout, 2)
    probe_budget = min(len(ranked_binary_offsets), max(max_count * 6, 12))

    for addr in ranked_binary_offsets[:probe_budget]:
        try:
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
            ):
                function_cfg, function = _run_with_timeout_in_fork(
                    lambda addr=addr: _recover_ranked_binary_function(
                        project,
                        addr,
                        f"sub_{addr:x}",
                        timeout=quick_timeout,
                        window=window,
                        low_memory=low_memory,
                    ),
                    timeout=quick_timeout + 1,
                )
            else:
                function_cfg, function = _run_with_timeout_in_daemon_thread(
                    lambda addr=addr: _recover_ranked_binary_function(
                        project,
                        addr,
                        f"sub_{addr:x}",
                        timeout=quick_timeout,
                        window=window,
                        low_memory=low_memory,
                    ),
                    timeout=quick_timeout + 1,
                    thread_name_prefix="ranked-preview",
                )
        except Exception as ex:
            logging.getLogger(__name__).debug("ranked preview item creation failed: %s", ex)
            continue
        preview_items.append(
            FunctionWorkItem(
                index=len(preview_items) + 1,
                function_cfg=function_cfg,
                function=function,
            )
        )
        selected_addrs.add(addr)
        if len(preview_items) >= max_count:
            return preview_items

    for addr in ranked_binary_offsets:
        if addr in selected_addrs:
            continue
        preview_items.append(
            FunctionWorkItem(
                index=len(preview_items) + 1,
                function_cfg=None,
                function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
            )
        )
        if len(preview_items) >= max_count:
            break
    return preview_items

def _supplement_function_cfg_pairs_with_ranked_preview(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    ranked_binary_offsets: Sequence[int],
    *,
    target_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> list[tuple[object, object]]:
    if target_count <= 0 or len(function_cfg_pairs) >= target_count or not ranked_binary_offsets:
        return function_cfg_pairs

    supplemented = list(function_cfg_pairs)
    seen_addrs = {
        getattr(function, "addr", None)
        for _cfg, function in supplemented
        if isinstance(getattr(function, "addr", None), int)
    }
    preview_items = _prepare_ranked_binary_preview_items(
        project,
        ranked_binary_offsets,
        max_count=target_count,
        timeout=timeout,
        window=window,
        low_memory=low_memory,
    )
    for item in preview_items:
        addr = getattr(item.function, "addr", None)
        if item.function_cfg is None or not isinstance(addr, int) or addr in seen_addrs:
            continue
        supplemented.append((item.function_cfg, item.function))
        seen_addrs.add(addr)
        if len(supplemented) >= target_count:
            break
    return supplemented

def _supplement_function_cfg_pairs_with_seeded_recovery(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    timeout: int,
    target_count: int,
) -> list[tuple[object, object]]:
    if target_count <= 0 or len(function_cfg_pairs) >= target_count:
        return function_cfg_pairs

    supplemented = list(function_cfg_pairs)
    seen_addrs = {
        getattr(function, "addr", None)
        for _cfg, function in supplemented
        if isinstance(getattr(function, "addr", None), int)
    }
    seeded_pairs = _recover_seeded_exe_functions(
        project,
        timeout=timeout,
        limit=target_count,
    )
    for function_cfg, function in seeded_pairs:
        addr = getattr(function, "addr", None)
        if not isinstance(addr, int) or addr in seen_addrs:
            continue
        supplemented.append((function_cfg, function))
        seen_addrs.add(addr)
        if len(supplemented) >= target_count:
            break
    return supplemented

def _function_work_cache_lookup(
    item: FunctionWorkItem,
    *,
    binary_path: Path | None,
    timeout: int,
    api_style: str,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None, bool, list[str]]:
    function_project = getattr(item.function, "project", None)
    tail_validation_enabled = (
        _tail_validation_runtime_enabled(function_project) if function_project is not None else True
    )
    expected_validation_stages = []
    if tail_validation_enabled:
        expected_validation_stages = ["structuring"]
        if enable_postprocess:
            expected_validation_stages.append("postprocess")
    cache_key = _function_decompilation_cache_key(
        binary_path=binary_path,
        function_addr=getattr(item.function, "addr", 0),
        function_name=str(getattr(item.function, "name", "")) or None,
        api_style=api_style,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
    )
    cached_result = _load_cache_json("function_decompile", cache_key) if cache_key is not None else None
    if cached_result is not None:
        cached_status = str(cached_result.get("status", "error"))
        cached_tail_validation = cached_result.get("tail_validation")
        if cached_status != "ok":
            return (
                None,
                (
                    f"[dbg] ignoring cached failed function result for {getattr(item.function, 'addr', 0):#x} "
                    f"{getattr(item.function, 'name', 'sub')} status={cached_status}; "
                    "only successful decompilation results are cached\n"
                ),
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        if (not tail_validation_enabled) or x86_16_tail_validation_snapshot_passed(
            cached_tail_validation if isinstance(cached_tail_validation, dict) else None,
            expected_stages=expected_validation_stages,
        ):
            cache_validation_status = (
                "uncollected"
                if not tail_validation_enabled
                else _tail_validation_display_status(cached_tail_validation if isinstance(cached_tail_validation, dict) else None)
            )
            return (
                FunctionWorkResult(
                    index=item.index,
                    status=cached_status,
                    payload=str(cached_result.get("payload", "")),
                    partial_payload=None,
                    debug_output=(
                        f"[dbg] cache hit for {getattr(item.function, 'addr', 0):#x} "
                        f"{getattr(item.function, 'name', 'sub')} "
                        f"validation={cache_validation_status}\n"
                    ),
                    function=item.function,
                    function_cfg=item.function_cfg,
                    tail_validation=dict(cached_tail_validation) if isinstance(cached_tail_validation, dict) else None,
                    elapsed=float(cached_result["elapsed"]) if isinstance(cached_result.get("elapsed"), (int, float)) else None,
                    from_cache=True,
                    block_count=int(cached_result["block_count"]) if isinstance(cached_result.get("block_count"), int) else None,
                    byte_count=int(cached_result["byte_count"]) if isinstance(cached_result.get("byte_count"), int) else None,
                ),
                "",
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        cache_bypass_reason = _tail_validation_display_status(
            cached_tail_validation if isinstance(cached_tail_validation, dict) else None
        )
        return (
            None,
            (
                f"[dbg] cache bypass for {getattr(item.function, 'addr', 0):#x} "
                f"{getattr(item.function, 'name', 'sub')} validation={cache_bypass_reason}\n"
            ),
            cache_key,
            tail_validation_enabled,
            expected_validation_stages,
        )
    return None, "", cache_key, tail_validation_enabled, expected_validation_stages

def _run_function_work_item(
    item: FunctionWorkItem,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
    lst_metadata: LSTMetadata | None,
    enable_structured_simplify: bool,
    enable_postprocess: bool = True,
    force_isolated_project: bool = False,
    allow_isolated_retry: bool = True,
) -> FunctionWorkResult:
    cached_work_result, cache_bypass_debug, cache_key, tail_validation_enabled, expected_validation_stages = (
        _function_work_cache_lookup(
            item,
            binary_path=binary_path,
            timeout=timeout,
            api_style=api_style,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
        )
    )
    if cached_work_result is not None:
        return cached_work_result

    cache_key = cache_key or _function_decompilation_cache_key(
        binary_path=binary_path,
        function_addr=getattr(item.function, "addr", 0),
        function_name=str(getattr(item.function, "name", "")) or None,
        api_style=api_style,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
    )

    decompile_project = item.function.project
    decompile_cfg = item.function_cfg
    decompile_function = item.function
    failure_family_state = FailureFamilyState()

    if isinstance(getattr(decompile_function, "name", None), str):
        helper_outcome = _try_decompile_non_optimized_known_function(
            decompile_project,
            decompile_cfg,
            decompile_function,
            timeout=max(1, min(timeout, 2)),
            api_style=api_style,
            binary_path=binary_path,
            lst_metadata=lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            failure_family_state=failure_family_state,
        )
        helper_c = _non_optimized_slice_rendered(helper_outcome)
        if helper_c is not None:
            helper_snapshot = _tail_validation_snapshot_for_fallback(
                decompile_project,
                decompile_function,
                allow_project_fallback=False,
            )
            return FunctionWorkResult(
                index=item.index,
                status="ok",
                payload=helper_c,
                partial_payload=None,
                debug_output="",
                function=item.function,
                function_cfg=item.function_cfg,
                tail_validation=helper_snapshot,
                elapsed=0.0,
                block_count=None,
                byte_count=None,
            )

    def _run_local(project_obj, cfg_obj, function_obj) -> tuple[str, str, str | None, str, dict[str, object] | None, float, int, int]:
        with _capture_thread_output() as (stdout_buf, stderr_buf):
            status, payload, partial_payload, block_count, byte_count, elapsed = _decompile_function_with_stats(
                project_obj,
                cfg_obj,
                function_obj,
                timeout,
                api_style,
                binary_path,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                lst_metadata=lst_metadata,
                enable_structured_simplify=enable_structured_simplify,
                enable_postprocess=enable_postprocess,
                allow_isolated_retry=allow_isolated_retry,
                failure_family_state=failure_family_state,
            )
        debug_output_local = stdout_buf.getvalue()
        err_output = stderr_buf.getvalue()
        if err_output:
            debug_output_local += err_output
        tail_snapshot_local = _tail_validation_snapshot_for_function_run(project_obj, function_obj)
        if os.environ.get("INERTIA_DEBUG_TAIL_SNAPSHOT"):
            logging.getLogger(__name__).warning(
                "tail snapshot function=%#x name=%s snapshot=%r",
                getattr(function_obj, "addr", -1) or -1,
                getattr(function_obj, "name", "sub"),
                tail_snapshot_local,
            )
        return status, payload, partial_payload, debug_output_local, tail_snapshot_local, elapsed, block_count, byte_count

    fork_isolated_eligible = (
        force_isolated_project
        and os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
        and decompile_cfg is not None
    )
    if fork_isolated_eligible:
        try:
            status, payload, partial_payload, debug_output, tail_validation_snapshot, elapsed, block_count, byte_count = _run_with_timeout_in_fork(
                lambda: _run_local(decompile_project, decompile_cfg, decompile_function),
                timeout=max(1, timeout) + 1,
            )
        except Exception as ex:
            logging.getLogger(__name__).warning("fork-isolated decompilation failed: %s", ex)
            fork_isolated_eligible = False

    if force_isolated_project and not fork_isolated_eligible and binary_path is not None and isinstance(getattr(item.function, "addr", None), int):
        main_object = getattr(getattr(item.function, "project", None), "loader", None)
        main_object = getattr(main_object, "main_object", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        if isinstance(linked_base, int) and isinstance(max_addr, int):
            try:
                isolated_project = _build_project_cached(
                    str(binary_path),
                    force_blob=False,
                    base_addr=linked_base,
                    entry_point=getattr(item.function.project, "entry", linked_base),
                )
                _inherit_tail_validation_runtime_policy(isolated_project, item.function.project)
                isolated_cfg, isolated_function = _recover_candidate_function_pair(
                    isolated_project,
                    candidate_addr=item.function.addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=lst_metadata,
                    project_entry=isolated_project.entry,
                    region_span=max(0x180, _function_complexity(item.function)[1] + 0x80),
                )
                decompile_project = isolated_project
                decompile_cfg = isolated_cfg
                decompile_function = isolated_function
            except Exception as ex:
                logging.getLogger(__name__).warning("isolated project/function set up failed: %s", ex)
                pass

    if not fork_isolated_eligible:
        status, payload, partial_payload, debug_output, tail_validation_snapshot, elapsed, block_count, byte_count = _run_local(
            decompile_project,
            decompile_cfg,
            decompile_function,
        )
    if cache_bypass_debug:
        debug_output = f"{cache_bypass_debug}{debug_output}"
    status, acceptance_blocker = _validated_generated_c_acceptance_8616(
        status=status,
        payload=payload,
        tail_validation_snapshot=tail_validation_snapshot,
        tail_validation_enabled=tail_validation_enabled,
        expected_validation_stages=expected_validation_stages,
        c_target=getattr(decompile_project, "_inertia_c_target", "portable-flat"),
    )
    if acceptance_blocker is not None:
        payload = acceptance_blocker
        partial_payload = None
    tail_validation_passed = status == "ok"
    if cache_key is not None and tail_validation_passed:
        _store_cache_json(
            "function_decompile",
            cache_key,
            {
                "status": status,
                "payload": payload,
                "tail_validation": tail_validation_snapshot,
                "tail_validation_passed": tail_validation_passed,
                "elapsed": elapsed,
                "block_count": block_count,
                "byte_count": byte_count,
            },
        )
    return FunctionWorkResult(
        index=item.index,
        status=status,
        payload=payload,
        partial_payload=partial_payload,
        debug_output=debug_output,
        function=item.function,
        function_cfg=item.function_cfg,
        tail_validation=tail_validation_snapshot,
        elapsed=elapsed,
        block_count=block_count,
        byte_count=byte_count,
        same_family_retry_stops=failure_family_state.same_family_retry_stops,
        fallback_family_labels=failure_family_state.fallback_family_labels,
    )

def _function_work_result_for_fork_ipc(result: FunctionWorkResult) -> FunctionWorkResult:
    # angr Function/CFG objects are not reliable pickle payloads. The parent still owns
    # canonical references for emission and fallback attribution.
    return replace(result, function=None, function_cfg=None)


def _tail_validation_passes_lenient(
    snapshot: dict[str, object] | None,
    *,
    expected_stages: list[str],
) -> bool:
    """Return True only when every expected stage is present and stable."""
    if not isinstance(snapshot, dict):
        return False
    for stage_name in expected_stages:
        entry = snapshot.get(stage_name)
        if not isinstance(entry, Mapping):
            return False
        status = entry.get("status")
        if isinstance(status, str) and status:
            if status != "stable":
                return False
            continue
        if bool(entry.get("changed", False)):
            return False
    return True


def _validated_generated_c_acceptance_8616(
    *,
    status: str,
    payload: str,
    tail_validation_snapshot: dict[str, object] | None,
    tail_validation_enabled: bool,
    expected_validation_stages: list[str] | tuple[str, ...],
    c_target: str = "portable-flat",
) -> tuple[str, str | None]:
    def _dump_validation_failed_payload(detail: str) -> None:
        if not isinstance(payload, str) or not payload.strip():
            return
        try:
            from pathlib import Path
            import hashlib
            import time

            root = Path("angr_platforms/.cache/validation_failed_payloads")
            root.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha1(payload.encode("utf-8", errors="ignore")).hexdigest()[:12]
            stamp = int(time.time())
            out = root / f"payload_{stamp}_{digest}.c"
            out.write_text(payload, encoding="utf-8")
            print(f"[tail-validation] failed payload artifact: {out}", file=sys.stderr)
        except Exception:
            return

    def _validation_fail(detail: str) -> tuple[str, str]:
        _mark_tail_validation_failed_with_blocker_8616(
            tail_validation_snapshot,
            detail,
            stage="postprocess",
        )
        print("[tail-validation] whole-tail validation failed across 1 functions", file=sys.stderr)
        print(f"[tail-validation] acceptance-gate detail: {detail}", file=sys.stderr)
        _dump_validation_failed_payload(detail)
        sys.stderr.flush()
        return "validation_failed", detail

    if status != "ok":
        return status, None
    if not isinstance(payload, str) or not payload.strip():
        return _validation_fail("No emitted C body.")
    quality = assess_decompiled_c_text(payload)
    if quality.reject_as_decompiled:
        marker_summary = ", ".join(quality.markers[:3]) if quality.markers else "unresolved"
        if len(quality.markers) > 3:
            marker_summary += ", ..."
        return _validation_fail(f"Final quality guard rejected emitted C ({marker_summary}).")
    if not tail_validation_enabled:
        return _validation_fail("Tail validation disabled.")
    if not _tail_validation_passes_lenient(
        tail_validation_snapshot,
        expected_stages=list(expected_validation_stages),
    ):
        display_status = _tail_validation_display_status(tail_validation_snapshot)
        stage_details: list[str] = []
        snapshot_dict = tail_validation_snapshot if isinstance(tail_validation_snapshot, dict) else {}
        for stage_name in expected_validation_stages:
            entry = snapshot_dict.get(stage_name)
            if not isinstance(entry, Mapping):
                stage_details.append(f"{stage_name}=missing")
                continue
            changed = entry.get("changed")
            status = entry.get("status")
            if isinstance(status, str) and status:
                stage_details.append(f"{stage_name}={status}")
            elif isinstance(changed, bool):
                stage_details.append(f"{stage_name}={'changed' if changed else 'stable'}")
            else:
                stage_details.append(f"{stage_name}=unclassified")
        detail = "; ".join(stage_details) if stage_details else "no stage data"
        return _validation_fail(f"Tail validation {display_status} ({detail}).")
    if c_target == "portable-flat":
        recompilation = check_c_recompiles_8616(payload, target=c_target)
        if not recompilation.passed:
            stderr = (recompilation.stderr or recompilation.stdout or "").strip()
            lines = stderr.splitlines()
            detail = lines[0] if lines else "gcc syntax check failed"
            if len(lines) > 1:
                detail += "; " + "; ".join(line.strip() for line in lines[1:3] if line.strip())
            source_path = getattr(recompilation, "source_path", None)
            if isinstance(source_path, str) and source_path:
                detail = f"{detail} [source: {source_path}]"
            return _validation_fail(f"gcc syntax check failed: {detail}")
    missing_calls = _missing_expected_calls_from_embedded_evidence_8616(payload)
    if missing_calls:
        return _validation_fail("Missing source-evidenced calls in emitted C: " + ", ".join(missing_calls[:6]))
    missing_multiplicity = _missing_expected_call_multiplicity_8616(payload)
    if missing_multiplicity:
        return _validation_fail(
            "Missing source-evidenced call multiplicity in emitted C: " + ", ".join(missing_multiplicity[:6])
        )
    arg_class = _arg_class_violations_8616(payload)
    if arg_class:
        return _validation_fail("Source-evidenced pointer/value argument class mismatch: " + ", ".join(arg_class[:6]))
    call_order = _call_order_gate_violations_8616(payload)
    if call_order:
        return _validation_fail("Source-evidenced call order mismatch/missing: " + ", ".join(call_order[:6]))
    if _loop_presence_violation_8616(payload):
        return _validation_fail("Source-evidenced loop structure missing from emitted C.")
    if _side_effect_floor_violation_8616(payload):
        return _validation_fail("Source-evidenced side-effect floor not met (missing non-prologue calls).")
    if _stack_slot_evidence_violation_8616(payload):
        return _validation_fail("Stack-slot evidence present but emitted C lacks clear stack materialization.")
    return "ok", None


def _mark_tail_validation_failed_with_blocker_8616(
    snapshot: dict[str, object] | None,
    detail: str,
    *,
    stage: str = "postprocess",
) -> None:
    if not isinstance(snapshot, dict):
        return
    entry = snapshot.get(stage)
    if not isinstance(entry, dict):
        entry = {}
        snapshot[stage] = entry
    entry["changed"] = True
    entry["status"] = "changed"
    entry["mode"] = entry.get("mode", "live_out")
    entry["summary_text"] = str(detail)
    entry["verdict"] = f"{stage} whole-tail validation [live_out] changed: {detail}"


_EMBEDDED_CALLS_RE = re.compile(r"(?m)^\s*\*\s*calls\s*=\s*(.+?)\s*$")
_CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_ORIGINAL_C_START_RE = re.compile(r"(?m)^\s*///\s*C source:\s*$")
_ORIGINAL_C_END_RE = re.compile(r"(?m)^\s*///\s*Assembly:\s*$")
_COD_BP_ANNOT_RE = re.compile(r"(?m)^\s*\*\s*\[bp[^\]]+\]\s*=")


def _strip_comment_blocks_8616(text: str) -> str:
    out = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    lines = []
    for line in out.splitlines():
        if line.lstrip().startswith("///"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _missing_expected_calls_from_embedded_evidence_8616(emitted_c: str) -> list[str]:
    if not isinstance(emitted_c, str) or not emitted_c:
        return []
    m = _EMBEDDED_CALLS_RE.search(emitted_c)
    if m is None:
        return []
    raw = m.group(1)
    expected = []
    for token in [part.strip() for part in raw.split(",")]:
        if not token:
            continue
        name = token.lstrip("_")
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            continue
        # Ignore compiler/runtime scaffolding helpers.
        if name in {"aNchkstk"}:
            continue
        expected.append(name)
    if not expected:
        return []
    clean = _extract_function_body_text_8616(_strip_comment_blocks_8616(emitted_c))
    found = set(_CALL_TOKEN_RE.findall(clean))
    missing = [name for name in expected if name not in found]
    return missing


def _extract_original_c_comment_block_8616(emitted_c: str) -> str:
    start = _ORIGINAL_C_START_RE.search(emitted_c)
    if start is None:
        return ""
    end = _ORIGINAL_C_END_RE.search(emitted_c, start.end())
    segment = emitted_c[start.end() : end.start() if end is not None else len(emitted_c)]
    lines: list[str] = []
    for raw in segment.splitlines():
        stripped = raw.strip()
        if stripped.startswith("///"):
            lines.append(stripped[3:].strip())
    return "\n".join(lines)


def _call_counts_from_text_8616(text: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for name in _CALL_TOKEN_RE.findall(text or ""):
        if name in {"if", "for", "while", "switch", "return"}:
            continue
        counts[name] += 1
    return counts


def _extract_original_call_evidence_lines_8616(original_c: str) -> str:
    """Keep only code-like lines from embedded original-C evidence.

    This avoids counting prose/commentary tokens such as "HeapSort (...)" that
    appear in descriptive text blocks.
    """
    lines: list[str] = []
    for raw in (original_c or "").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(("/*", "*", "//")):
            continue
        # Prefer executable-style call evidence lines.
        if "(" in stripped and ")" in stripped and ";" in stripped:
            lines.append(stripped)
    return "\n".join(lines)


def _missing_expected_call_multiplicity_8616(emitted_c: str) -> list[str]:
    original_c = _extract_original_c_comment_block_8616(emitted_c)
    if not original_c:
        return []
    expected_counts = _call_counts_from_text_8616(_extract_original_call_evidence_lines_8616(original_c))
    if not expected_counts:
        return []
    function_name = _extract_emitted_function_name_8616(emitted_c)
    actual_counts = _call_counts_from_text_8616(
        _extract_function_body_text_8616(_strip_comment_blocks_8616(emitted_c))
    )
    missing: list[str] = []
    for name, needed in expected_counts.items():
        if name in {"aNchkstk"}:
            continue
        # Recursive call multiplicity is structurally unstable across equivalent
        # if/else lowering forms; keep presence/order gates, but do not enforce
        # exact multiplicity for self-calls.
        if isinstance(function_name, str) and name == function_name:
            continue
        have = int(actual_counts.get(name, 0))
        if have < needed:
            missing.append(f"{name}({have}/{needed})")
    return missing


def _extract_function_body_text_8616(emitted_c: str) -> str:
    clean = _strip_comment_blocks_8616(emitted_c)
    m = re.search(r"\{", clean)
    if m is None:
        return clean
    return clean[m.start() :]


def _expected_call_order_from_original_8616(emitted_c: str) -> list[str]:
    original_c = _extract_original_c_comment_block_8616(emitted_c)
    if not original_c:
        return []
    original_c = _extract_original_call_evidence_lines_8616(original_c)
    function_name = _extract_emitted_function_name_8616(emitted_c)
    order: list[str] = []
    for name in _CALL_TOKEN_RE.findall(original_c):
        if name in {"if", "for", "while", "switch", "return", "aNchkstk"}:
            continue
        if isinstance(function_name, str) and name == function_name:
            continue
        if not order or order[-1] != name:
            order.append(name)
    return order


def _extract_emitted_function_name_8616(emitted_c: str) -> str | None:
    if not isinstance(emitted_c, str) or not emitted_c:
        return None
    header = emitted_c.split("{", 1)[0]
    m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$", header, flags=re.MULTILINE)
    if m is None:
        return None
    name = m.group(1)
    if name in {"if", "for", "while", "switch", "return"}:
        return None
    return name


def _call_order_gate_violations_8616(emitted_c: str) -> list[str]:
    expected_order = _expected_call_order_from_original_8616(emitted_c)
    if len(expected_order) < 2:
        return []
    body = _extract_function_body_text_8616(emitted_c)
    current_pos = -1
    missing_or_reordered: list[str] = []
    for name in expected_order:
        search_from = current_pos + 1 if current_pos >= 0 else 0
        pos = body.find(f"{name}(", search_from)
        if pos < 0:
            missing_or_reordered.append(name)
            continue
        current_pos = pos
    return missing_or_reordered


def _loop_presence_violation_8616(emitted_c: str) -> bool:
    original_c = _extract_original_c_comment_block_8616(emitted_c)
    if not original_c:
        return False
    expected_loops = sum(original_c.count(tok) for tok in ("for(", "for (", "while(", "while ("))
    if expected_loops <= 0:
        return False
    body = _extract_function_body_text_8616(emitted_c)
    actual_loops = sum(body.count(tok) for tok in ("for(", "for (", "while(", "while ("))
    if actual_loops <= 0:
        # Structured loop lowering may emit explicit back-edges instead of
        # textual while/for forms; accept obvious back-edge notation as loop
        # evidence rather than hard-failing.
        if "goto " in body or re.search(r"\bLABEL_[A-Za-z0-9_]+\s*:", body):
            return False
        function_name = _extract_emitted_function_name_8616(emitted_c)
        if isinstance(function_name, str) and f"{function_name}(" in body:
            return False
    return actual_loops < expected_loops


def _side_effect_floor_violation_8616(emitted_c: str) -> bool:
    # If evidence says function has multiple non-prologue calls, body must retain
    # at least one non-prologue call.
    expected_calls = _EMBEDDED_CALLS_RE.search(emitted_c)
    if expected_calls is None:
        return False
    raw = expected_calls.group(1)
    names = [t.strip().lstrip("_") for t in raw.split(",") if t.strip()]
    names = [n for n in names if n and n != "aNchkstk"]
    if len(names) < 1:
        return False
    body = _extract_function_body_text_8616(emitted_c)
    has_non_prologue = any(f"{name}(" in body for name in set(names))
    return not has_non_prologue


def _stack_slot_evidence_violation_8616(emitted_c: str) -> bool:
    # If COD annotations describe bp-based slots, emitted C should contain either
    # arg_/local_ variables or explicit typed parameters.
    has_bp_annotations = _COD_BP_ANNOT_RE.search(emitted_c) is not None
    if not has_bp_annotations:
        return False
    body = _extract_function_body_text_8616(emitted_c)
    if "arg_" in body or "local_" in body:
        return False
    # Accept ordinary named parameters as stack materialization evidence.
    header = emitted_c.split("{", 1)[0]
    return "(" in header and ")" in header and re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", header) is None


def _arg_class_violations_8616(emitted_c: str) -> list[str]:
    # Minimal, evidence-based: from original C comment, if call shows '&' in args
    # but emitted call has no pointer-like argument, flag it.
    original_c = _extract_original_c_comment_block_8616(emitted_c)
    if not original_c:
        return []
    body = _extract_function_body_text_8616(emitted_c)
    violations: list[str] = []
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", original_c):
        name, args = m.group(1), m.group(2)
        if name in {"if", "for", "while", "switch", "return"}:
            continue
        expects_ptr = "&" in args
        if not expects_ptr:
            continue
        call_m = re.search(rf"\b{name}\s*\(([^)]*)\)", body)
        if call_m is None:
            continue
        emitted_args = call_m.group(1)
        pointer_like = ("&" in emitted_args) or ("SEG_PTR(" in emitted_args)
        if not pointer_like:
            violations.append(name)
    return violations


def _print_stop_on_first_failure_8616(function, result: FunctionWorkResult) -> None:
    display_addr = function_original_addr(function)
    print(
        f"/* stop: function {display_addr:#x} {getattr(function, 'name', 'sub')} "
        f"status={getattr(result, 'status', 'error')} blocker={getattr(result, 'payload', '')} */"
    )

def _emit_function_timing_summary(
    function_tasks: Sequence[FunctionWorkItem],
    result_map: Mapping[int, FunctionWorkResult],
    *,
    limit: int = 5,
) -> None:
    rows: list[tuple[float, int, int, str, str]] = []
    for item in function_tasks:
        result = result_map.get(item.index)
        if result is not None and getattr(result, "from_cache", False):
            continue
        elapsed = getattr(result, "elapsed", None) if result is not None else None
        if not isinstance(elapsed, (int, float)) or elapsed <= 0:
            continue
        function = item.function
        rows.append(
            (
                float(elapsed),
                item.index,
                int(getattr(function, "addr", 0)),
                str(getattr(function, "name", "sub")),
                _function_attempt_display_status(result),
            )
        )
    if not rows:
        return
    rows.sort(key=lambda row: (-row[0], row[1]))
    shown = rows[: max(1, limit)]
    print(f"summary: slowest function attempt(s), top {len(shown)}:")
    for elapsed, _index, addr, name, status in shown:
        print(f"summary:   {addr:#x} {name}: {elapsed:.2f}s status={status}")

def _helper_name(project: angr.Project, addr: int) -> str | None:
    proc = project.hooked_by(addr)
    if proc is None:
        return None
    name = getattr(proc, "INT_NAME", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(proc, "display_name", None)
    if isinstance(name, str) and name:
        return name
    return proc.__class__.__name__

def _iter_c_nodes(node):
    yield node
    if isinstance(node, structured_c.CStatements):
        for stmt in node.statements:
            yield from _iter_c_nodes(stmt)
        return
    for attr in ("lhs", "rhs", "expr", "condition", "true_node", "false_node", "stmt", "callee_target"):
        if hasattr(node, attr):
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if value is not None and type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                yield from _iter_c_nodes(value)
    if hasattr(node, "args"):
        try:
            args = getattr(node, "args")
        except Exception:
            args = None
        if args:
            for arg in args:
                if type(arg).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                    yield from _iter_c_nodes(arg)

def _fork_unavailable_reason() -> str:
    live_threads = [
        thread.name
        for thread in threading.enumerate()
        if thread is not threading.current_thread() and thread.is_alive()
    ]
    if live_threads:
        return f"{len(live_threads)} live helper thread(s): {', '.join(live_threads[:4])}"
    return f"threading.active_count()={threading.active_count()}"


def _remember_fallback_tail_validation(
    project: angr.Project,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    item: FunctionWorkItem,
    *,
    function=None,
    allow_project_fallback: bool = True,
) -> dict[str, object]:
    target_function = function if function is not None else item.function
    snapshot = _tail_validation_snapshot_for_fallback(
        project,
        target_function,
        allow_project_fallback=allow_project_fallback,
    )
    fallback_tail_validation_by_index[item.index] = snapshot
    return snapshot



def _emit_function_result(
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    *,
    project: angr.Project,
    args: Any,
    lst_metadata: Any,
    cod_metadata: Any,
    synthetic_globals: Any,
    precise_sidecar_regions: bool,
    allow_heavy_fallbacks: bool,
    interactive_stdout: bool,
    use_serial_fork_per_function: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
) -> tuple[int, int]:
    decompiled_local = 0
    failed_local = 0
    attempt_status_printed = False
    if result.debug_output:
        print(result.debug_output, end="" if result.debug_output.endswith("\n") else "\n")
    function = item.function
    print(f"\n/* == function {function.addr:#x} {function.name} == */")
    if getattr(result, "failure_stage", None):
        print(f"/* stage: {result.failure_stage} */")
    failure_family_snapshot = build_failure_family_snapshot(
        status=getattr(result, "status", None),
        failure_stage=getattr(result, "failure_stage", None),
        fallback_kind="file_sweep",
        tail_validation_verdict=_tail_validation_display_status(getattr(result, "tail_validation", None)),
        artifact_path=f"{function.addr:#x}:{function.name}",
    )
    print(f"/* failure family: {failure_family_snapshot.label()} */")
    if args.show_asm:
        print("/* -- asm -- */")
        print(_format_first_block_asm(project, function.addr))
    emitted_problem = False
    if result.status == "ok":
        if x86_16_tail_validation_snapshot_passed(result.tail_validation):
            decompiled_local += 1
            _print_function_attempt_status(
                function,
                attempt="decompiled",
                validation_snapshot=result.tail_validation,
            )
            _emit_optional_source_sidecar_c_block(
                args.binary,
                item.function.name,
                result.payload,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="/* -- c -- */",
            )
            return decompiled_local, failed_local
        _print_function_attempt_status(
            function,
            attempt="decompiled",
            validation_snapshot=result.tail_validation,
        )
        print("/* problem: validation=uncollected */")
        print("/* decompiled output produced without full tail-validation snapshot; trying fallback lanes */")
        attempt_status_printed = True
        emitted_problem = True

    if result.partial_payload:
        _print_function_attempt_status(
            function,
            attempt=_function_attempt_display_status(result),
            validation_snapshot=result.tail_validation,
        )
        attempt_status_printed = True
        print(f"/* problem: {result.status} */")
        _print_diagnostic_text(result.payload)
        _emit_optional_source_sidecar_c_block(args.binary, item.function.name, result.partial_payload, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (partial timeout) -- */")
        emitted_problem = True

    skip_heavy_fallbacks_for_result = bool(getattr(result, "skip_heavy_fallbacks", False))

    slice_result: SliceRecoveryAttemptOutcome | None = None
    if allow_heavy_fallbacks and precise_sidecar_regions and not skip_heavy_fallbacks_for_result:
        slice_result = _try_decompile_sidecar_slice(
            project,
            lst_metadata,
            function.addr,
            function.name,
            timeout=args.timeout,
            api_style=args.api_style,
            binary_path=args.binary,
        )
    if slice_result is not None and slice_result.status == "ok":
        fallback_snapshot = _remember_fallback_tail_validation(project, fallback_tail_validation_by_index,
            item,
            allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
        )
        if x86_16_tail_validation_snapshot_passed(fallback_snapshot):
            decompiled_local += 1
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            _emit_optional_source_sidecar_c_block(args.binary, item.function.name, slice_result.payload, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (sidecar slice fallback) -- */")
            return decompiled_local, failed_local
        _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
        print("/* problem: sidecar slice fallback validation=uncollected; continuing fallback lanes */")

    nonopt_result: NonOptimizedSliceOutcome | str | None = None
    known_nonopt_result: NonOptimizedSliceOutcome | str | None = None
    function_project = getattr(function, "project", project)
    using_rebased_function_slice = function_project is not project
    function_lst_metadata = None if using_rebased_function_slice else lst_metadata
    if result.partial_payload is None:
        known_nonopt_result = _try_decompile_non_optimized_known_function(
            function_project,
            item.function_cfg,
            function,
            timeout=_bounded_non_optimized_timeout(args.timeout),
            api_style=args.api_style,
            binary_path=args.binary,
            lst_metadata=function_lst_metadata,
            cod_metadata=cod_metadata,
        )
        if function_project is not project:
            for attr_name in (
                "_inertia_partial_tail_validation_snapshot",
                "_inertia_last_tail_validation_snapshot",
            ):
                attr_value = getattr(function_project, attr_name, None)
                if isinstance(attr_value, dict):
                    setattr(project, attr_name, dict(attr_value))
    known_nonopt_c = _non_optimized_slice_rendered(known_nonopt_result)
    if known_nonopt_c is not None:
        decompiled_local += 1
        fallback_snapshot = _remember_fallback_tail_validation(
            project,
            fallback_tail_validation_by_index,
            item,
            function=function,
            allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
        )
        _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
        if not emitted_problem:
            print(f"/* problem: {result.status} */")
            _print_diagnostic_text(result.payload)
        _emit_optional_source_sidecar_c_block(
            args.binary,
            item.function.name,
            known_nonopt_c,
            alternate_source_c=bool(args.alternate_source_c),
            c_header="/* -- c (non-optimized fallback) -- */",
        )
        return decompiled_local, failed_local

    nonopt_skip_reason: str | None = None
    if not allow_heavy_fallbacks or skip_heavy_fallbacks_for_result:
        sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
        string_c = None
        if result.partial_payload is None:
            if sidecar_region is not None:
                string_c = _try_emit_string_intrinsic_c(
                    project,
                    start=sidecar_region[0],
                    end=sidecar_region[1],
                    name=function.name,
                )
            else:
                start, end = _infer_linear_disassembly_window(project, function.addr)
                string_c = _try_emit_string_intrinsic_c(project, start=start, end=end, name=function.name)
        if string_c is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(project, fallback_tail_validation_by_index,
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            if not emitted_problem:
                print(f"/* problem: {result.status} */")
                _print_diagnostic_text(result.payload)
            nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=allow_heavy_fallbacks,
                skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
                interactive_stdout=interactive_stdout,
                max_functions=args.max_functions,
                addr_requested=args.addr is not None,
                result_status=result.status,
                failure_stage=getattr(result, "failure_stage", None),
                nonopt_failure_detail=None,
            )
            if nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(args.binary, item.function.name, string_c, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (string intrinsic fallback) -- */")
            return decompiled_local, failed_local
        asm_fallback = (
            _format_asm_range(project, sidecar_region[0], sidecar_region[1])
            if sidecar_region is not None
            else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
        )
        failed_local += 1
        if not attempt_status_printed:
            _print_function_attempt_status(
                function,
                attempt=_function_attempt_display_status(result),
                validation_snapshot=result.tail_validation,
            )
        if result.partial_payload is not None:
            if emitted_problem:
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
            return decompiled_local, failed_local
        if result.status == "empty":
            if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
                print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
            else:
                print(f"/* -- {result.status} -- */")
                _print_diagnostic_text(result.payload)
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
            return decompiled_local, failed_local
        print(f"/* -- {result.status} -- */")
        _print_diagnostic_text(result.payload)
        print("/* -- lift break probe -- */")
        _print_diagnostic_text(_probe_lift_break(project, function.addr))
        print("/* -- asm fallback -- */")
        _print_asm_fallback_text(asm_fallback)
        return decompiled_local, failed_local

    if precise_sidecar_regions:
        peer_sidecar_c = _try_decompile_peer_sidecar_slice(
            project,
            lst_metadata,
            function.addr,
            function.name,
            timeout=args.timeout,
            api_style=args.api_style,
            binary_path=args.binary,
        )
        if peer_sidecar_c is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(project, fallback_tail_validation_by_index,
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("peer_sidecar"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            _emit_optional_source_sidecar_c_block(args.binary, item.function.name, peer_sidecar_c, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (peer sidecar fallback) -- */")
            return decompiled_local, failed_local

        trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, function.addr, function.name)
        if trivial_c is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(project, fallback_tail_validation_by_index,
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            _emit_optional_source_sidecar_c_block(args.binary, item.function.name, trivial_c, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (trivial sidecar fallback) -- */")
            return decompiled_local, failed_local
    if (
        result.partial_payload is None
        and (precise_sidecar_regions or args.addr is not None)
        and known_nonopt_c is None
        and not sidecar_verdict_closes_non_optimized_lane(
            slice_result.verdict if slice_result is not None else None
        )
    ):
        nonopt_result = _try_decompile_non_optimized_slice(
            function_project if using_rebased_function_slice else project,
            function.addr,
            function.name,
            timeout=_bounded_non_optimized_timeout(args.timeout),
            api_style=args.api_style,
            binary_path=args.binary,
            lst_metadata=function_lst_metadata,
            cod_metadata=cod_metadata,
            allow_fresh_project_retry=not use_serial_fork_per_function,
        )
        if function_project is not project:
            for attr_name in (
                "_inertia_partial_tail_validation_snapshot",
                "_inertia_last_tail_validation_snapshot",
            ):
                attr_value = getattr(function_project, attr_name, None)
                if isinstance(attr_value, dict):
                    setattr(project, attr_name, dict(attr_value))
    elif slice_result is not None and sidecar_verdict_closes_non_optimized_lane(slice_result.verdict):
        print(
            "/* non-optimized fallback unavailable: "
            f"sidecar slice already closed the lane ({slice_result.verdict.stage}:{slice_result.verdict.stop_family}) */"
        )
    nonopt_c = _non_optimized_slice_rendered(nonopt_result)
    if nonopt_c is not None:
        decompiled_local += 1
        fallback_snapshot = _remember_fallback_tail_validation(project, fallback_tail_validation_by_index,
            item,
            allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
        )
        _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
        if not emitted_problem:
            print(f"/* problem: {result.status} */")
            _print_diagnostic_text(result.payload)
        _emit_optional_source_sidecar_c_block(args.binary, item.function.name, nonopt_c, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (non-optimized fallback) -- */")
        return decompiled_local, failed_local

    sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
    string_c = None
    if sidecar_region is not None:
        string_c = _try_emit_string_intrinsic_c(
            project,
            start=sidecar_region[0],
            end=sidecar_region[1],
            name=function.name,
        )
    else:
        start, end = _infer_linear_disassembly_window(project, function.addr)
        string_c = _try_emit_string_intrinsic_c(project, start=start, end=end, name=function.name)
    if string_c is not None:
        decompiled_local += 1
        fallback_snapshot = _remember_fallback_tail_validation(project, fallback_tail_validation_by_index,
            item,
            allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
        )
        _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
        if not emitted_problem:
            print(f"/* problem: {result.status} */")
            _print_diagnostic_text(result.payload)
        nonopt_skip_reason = describe_non_optimized_unavailable(
            allow_heavy_fallbacks=allow_heavy_fallbacks,
            skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
            interactive_stdout=interactive_stdout,
            max_functions=args.max_functions,
            addr_requested=args.addr is not None,
            result_status=result.status,
            failure_stage=getattr(result, "failure_stage", None),
            nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
        )
        if nonopt_skip_reason is not None:
            print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
        _emit_optional_source_sidecar_c_block(args.binary, item.function.name, string_c, alternate_source_c=bool(args.alternate_source_c), c_header="/* -- c (string intrinsic fallback) -- */")
        return decompiled_local, failed_local
    asm_fallback = (
        _format_asm_range(project, sidecar_region[0], sidecar_region[1])
        if sidecar_region is not None
        else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
    )
    failed_local += 1
    for _diag_line in _format_tail_validation_diagnostic(
        result.tail_validation,
        function_addr=function.addr,
        function_name=function.name,
        block_count=getattr(result, 'block_count', None),
        byte_count=getattr(result, 'byte_count', None),
        exit_kind=result.status,
        exit_detail=result.payload,
    ):
        print(_diag_line)
    if not attempt_status_printed:
        _print_function_attempt_status(
            function,
            attempt=_function_attempt_display_status(result),
            validation_snapshot=result.tail_validation,
        )
    if result.status == "empty":
        if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
            print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
        else:
            if emitted_problem:
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
                return decompiled_local, failed_local
            print(f"/* -- {result.status} -- */")
            _print_diagnostic_text(result.payload)
            print("/* -- asm fallback -- */")
            _print_asm_fallback_text(asm_fallback)
    else:
        if emitted_problem:
            print("/* -- lift break probe -- */")
            _print_diagnostic_text(_probe_lift_break(project, function.addr))
            print("/* -- asm fallback -- */")
            _print_asm_fallback_text(asm_fallback)
            return decompiled_local, failed_local
        print(f"/* -- {result.status} -- */")
        _print_diagnostic_text(result.payload)
        print("/* -- lift break probe -- */")
        _print_diagnostic_text(_probe_lift_break(project, function.addr))
        print("/* -- asm fallback -- */")
        _print_asm_fallback_text(asm_fallback)
    return decompiled_local, failed_local

def main(argv: list[str] | None = None) -> int:
    from .cli_arg_parser import _build_cli_argument_parser

    parser = _build_cli_argument_parser()
    args = parser.parse_args(argv)
    timeout_was_explicit = _argument_was_explicit("--timeout")

    _lower_process_priority()
    _apply_memory_limit(args.max_memory_mb)

    print(f"/* loading: {args.binary} */", flush=True)
    runtime_header = render_c_runtime_header_8616(args.c_target)
    if runtime_header:
        print(runtime_header, end="" if runtime_header.endswith("\n") else "\n", flush=True)
    function_label = None
    cod_metadata = None
    synthetic_globals = None
    lst_metadata = None
    prefer_fast_recovery = False
    effective_signature_catalog = args.signature_catalog
    if effective_signature_catalog is None:
        effective_signature_catalog = default_signature_catalog_path()
    if args.proc is not None:
        entries = extract_cod_function_entries(args.binary, args.proc, args.proc_kind)
        cod_metadata = extract_cod_proc_metadata(args.binary, args.proc, args.proc_kind)
        # --proc builds a synthetic single-procedure blob, so entry recovery can
        # start with the lean CFG path even when the procedure is not helper-call
        # heavy. Falling back to full CFGFast first makes some small COD procs
        # spend the entire timeout before decompilation begins.
        prefer_fast_recovery = True
        selected_entries = extract_small_two_arg_cod_logic_entries(entries)
        if selected_entries is None:
            selected_entries = extract_simple_cod_logic_entries(entries)
        if selected_entries is None:
            logic_start = infer_cod_logic_start(entries)
            proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(entries, start_offset=logic_start)
        else:
            proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(selected_entries)
        project = _build_project_from_bytes(
            proc_code,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
        setattr(project, "_inertia_c_target", args.c_target)
        _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        function_label = args.proc
        if args.addr is None:
            args.addr = args.entry_point
        args.window = max(len(proc_code), 1)
    else:
        project = _build_project(
            args.binary,
            force_blob=args.blob,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
        setattr(project, "_inertia_c_target", args.c_target)
        setattr(project, "_inertia_trace_c_stages", bool(args.trace_c_stages))
        _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
        lst_metadata = _load_lst_metadata(
            args.binary,
            project,
            pat_backend=args.pat_backend,
            signature_catalog=effective_signature_catalog,
        )
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        if lst_metadata is None:
            print("/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis and quick function-entry scans. */")
        print(_recovery_evidence_line(args.binary, lst_metadata))
    setattr(project, "_inertia_trace_c_stages", bool(args.trace_c_stages))
    low_memory_path = _prefer_low_memory_path()
    interactive_stdout = _stdout_is_interactive()
    precise_sidecar_regions = metadata_has_precise_code_regions(lst_metadata)
    if args.addr is not None:
        print("/* recovering function... */", flush=True)
        direct_budget_timeout = args.timeout
        if project.arch.name == "86_16":
            direct_budget_timeout = max(direct_budget_timeout, 24)
        direct_addr_deadline = time.monotonic() + _direct_addr_wall_clock_budget(
            args.timeout,
            effective_timeout=direct_budget_timeout,
        )
        budget_fallback_addr: int | None = None
        budget_fallback_name: str | None = None

        def _emit_budget_exhausted_sidecar_asm_fallback_or_timeout(detail: str) -> None:
            if precise_sidecar_regions and budget_fallback_addr is not None and lst_metadata is not None:
                sidecar_region = _lst_code_region(lst_metadata, budget_fallback_addr)
                if sidecar_region is not None:
                    code_name = (
                        _lst_code_label(lst_metadata, sidecar_region[0], project.entry)
                        or budget_fallback_name
                        or f"sub_{budget_fallback_addr:x}"
                    )
                    print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        SimpleNamespace(addr=sidecar_region[0], name=code_name),
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                        binary_path=args.binary,
                    )
                    print("\n/* == asm fallback == */")
                    print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
                    sys.stdout.flush()
                    sys.stderr.flush()
                    os._exit(4)
            _emit_timeout_and_exit(args.timeout, detail)

        def _remaining_direct_addr_budget() -> int:
            return max(0, int(direct_addr_deadline - time.monotonic()))

        def _enforce_direct_addr_budget_timeout(*, recovery_detail: str | None = None) -> None:
            if _remaining_direct_addr_budget() > 0:
                return
            detail = recovery_detail
            if detail is None:
                detail = "after exhausting direct-address recovery budget"
            _emit_budget_exhausted_sidecar_asm_fallback_or_timeout(detail)

        try:
            def _recover_target_function():
                return _recover_direct_addr_function(
                    project,
                    args.addr,
                    timeout=args.timeout,
                    window=args.window,
                    function_label=function_label,
                    lst_metadata=lst_metadata,
                    low_memory_path=low_memory_path,
                    prefer_fast_recovery=prefer_fast_recovery,
                )

            direct_recovery_timeout = (
                max(1, min(args.timeout, 6))
                if args.proc is not None
                else _default_recovery_timeout(args.timeout, explicit_timeout=timeout_was_explicit)
            )
            direct_recovery_timeout = max(1, min(direct_recovery_timeout, _remaining_direct_addr_budget() or 1))
            cfg, func = _run_with_timeout_in_daemon_thread(
                _recover_target_function,
                timeout=direct_recovery_timeout,
                thread_name_prefix="recovery",
            )
        except _AnalysisTimeout:
            _enforce_direct_addr_budget_timeout()
            sidecar_region = _lst_code_region(lst_metadata, args.addr) if lst_metadata is not None else None
            if precise_sidecar_regions and sidecar_region is not None:
                code_name = _lst_code_label(lst_metadata, sidecar_region[0], project.entry) or f"sub_{args.addr:x}"
                slice_result = _try_decompile_sidecar_slice(
                    project,
                    lst_metadata,
                    sidecar_region[0],
                    code_name,
                    timeout=max(1, min(args.timeout, _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                )
                if slice_result is not None and slice_result.status == "ok":
                    fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                    print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        fallback_function,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        code_name,
                        slice_result.payload,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c == */",
                    )
                    return 0
                _enforce_direct_addr_budget_timeout()
                nonopt_result: NonOptimizedSliceOutcome | str | None = _try_decompile_non_optimized_slice(
                    project,
                    sidecar_region[0],
                    code_name,
                    timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=lst_metadata,
                    cod_metadata=cod_metadata,
                )
                nonopt_c = _non_optimized_slice_rendered(nonopt_result)
                if nonopt_c is not None:
                    fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                    print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        fallback_function,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        code_name,
                        nonopt_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (non-optimized fallback) == */",
                    )
                    return 0
                string_c = _try_emit_string_intrinsic_c(
                    project,
                    start=sidecar_region[0],
                    end=sidecar_region[1],
                    name=code_name,
                )
                if string_c is not None:
                    print("/* Function recovery timed out; emitted generic string-intrinsic fallback from sidecar bounds. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        SimpleNamespace(addr=sidecar_region[0], name=code_name),
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        code_name,
                        string_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (string intrinsic fallback) == */",
                    )
                    return 0
                print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                    binary_path=args.binary,
                )
                print("\n/* == asm fallback == */")
                print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
                return 4
            nonopt_result: NonOptimizedSliceOutcome | str | None = None
            _enforce_direct_addr_budget_timeout()
            nonopt_result = _try_decompile_non_optimized_slice(
                project,
                args.addr,
                function_label or f"sub_{args.addr:x}",
                timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
            )
            nonopt_c = _non_optimized_slice_rendered(nonopt_result)
            if nonopt_c is not None:
                fallback_function = SimpleNamespace(addr=args.addr, name=function_label or f"sub_{args.addr:x}")
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {args.addr:#x} {function_label or f'sub_{args.addr:x}'} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    fallback_function.name,
                    nonopt_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
            fallback_function = SimpleNamespace(addr=args.addr, name=function_label or f"sub_{args.addr:x}")
            start, end = _infer_linear_disassembly_window(project, args.addr)
            string_c = _try_emit_string_intrinsic_c(
                project,
                start=start,
                end=end,
                name=fallback_function.name,
            )
            if string_c is not None:
                print("/* Function recovery timed out; emitted generic string-intrinsic fallback. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {args.addr:#x} {fallback_function.name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=args.binary,
                )
                nonopt_skip_reason = describe_non_optimized_unavailable(
                    allow_heavy_fallbacks=True,
                    skip_heavy_fallbacks_for_result=False,
                    interactive_stdout=interactive_stdout,
                    max_functions=args.max_functions,
                    addr_requested=args.addr is not None,
                    result_status="timeout",
                    failure_stage=None,
                    nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
                )
                if nonopt_skip_reason is not None:
                    print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    fallback_function.name,
                    string_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            asm_fallback = _format_asm_range(project, start, end)
            recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
            if recovery_detail is None:
                recovery_detail = "during x86-16 function recovery (direct-address path)"
            print(f"/* timeout: function {args.addr:#x} {function_label or f'sub_{args.addr:x}'} */")
            _stored_snapshot = getattr(project, '_inertia_last_tail_validation_snapshot', None)
            if isinstance(_stored_snapshot, dict) and _stored_snapshot:
                for _diag_line in _format_tail_validation_diagnostic(
                    _stored_snapshot,
                    function_addr=args.addr,
                    function_name=function_label or f"sub_{args.addr:x}",
                    exit_kind="timeout",
                    exit_detail=recovery_detail,
                ):
                    print(_diag_line)
            _emit_timeout_and_exit(args.timeout, recovery_detail)
        except FuturesTimeoutError:
            _enforce_direct_addr_budget_timeout()
            sidecar_region = _lst_code_region(lst_metadata, args.addr) if lst_metadata is not None else None
            if precise_sidecar_regions and sidecar_region is not None:
                code_name = _lst_code_label(lst_metadata, sidecar_region[0], project.entry) or f"sub_{args.addr:x}"
                slice_result = _try_decompile_sidecar_slice(
                    project,
                    lst_metadata,
                    sidecar_region[0],
                    code_name,
                    timeout=max(1, min(args.timeout, _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                )
                if slice_result is not None and slice_result.status == "ok":
                    fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                    print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        fallback_function,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        code_name,
                        slice_result.payload,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c == */",
                    )
                    return 0
                _enforce_direct_addr_budget_timeout()
                nonopt_result: NonOptimizedSliceOutcome | str | None = _try_decompile_non_optimized_slice(
                    project,
                    sidecar_region[0],
                    code_name,
                    timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=lst_metadata,
                    cod_metadata=cod_metadata,
                )
                nonopt_c = _non_optimized_slice_rendered(nonopt_result)
                if nonopt_c is not None:
                    fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                    print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        fallback_function,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        code_name,
                        nonopt_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (non-optimized fallback) == */",
                    )
                    return 0
                string_c = _try_emit_string_intrinsic_c(
                    project,
                    start=sidecar_region[0],
                    end=sidecar_region[1],
                    name=code_name,
                )
                if string_c is not None:
                    print("/* Function recovery timed out; emitted generic string-intrinsic fallback from sidecar bounds. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        SimpleNamespace(addr=sidecar_region[0], name=code_name),
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        code_name,
                        string_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (string intrinsic fallback) == */",
                    )
                    return 0
                print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                    binary_path=args.binary,
                )
                print("\n/* == asm fallback == */")
                print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
                return 4
            nonopt_result: NonOptimizedSliceOutcome | str | None = None
            if precise_sidecar_regions:
                _enforce_direct_addr_budget_timeout()
                nonopt_result = _try_decompile_non_optimized_slice(
                    project,
                    args.addr,
                    function_label or f"sub_{args.addr:x}",
                    timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=lst_metadata,
                    cod_metadata=cod_metadata,
                )
            nonopt_c = _non_optimized_slice_rendered(nonopt_result)
            if nonopt_c is not None:
                fallback_function = SimpleNamespace(addr=args.addr, name=function_label or f"sub_{args.addr:x}")
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {args.addr:#x} {function_label or f'sub_{args.addr:x}'} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    fallback_function.name,
                    nonopt_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
            fallback_function = SimpleNamespace(addr=args.addr, name=function_label or f"sub_{args.addr:x}")
            start, end = _infer_linear_disassembly_window(project, args.addr)
            string_c = _try_emit_string_intrinsic_c(
                project,
                start=start,
                end=end,
                name=fallback_function.name,
            )
            if string_c is not None:
                print("/* Function recovery timed out; emitted generic string-intrinsic fallback. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {args.addr:#x} {fallback_function.name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=args.binary,
                )
                nonopt_skip_reason = describe_non_optimized_unavailable(
                    allow_heavy_fallbacks=True,
                    skip_heavy_fallbacks_for_result=False,
                    interactive_stdout=interactive_stdout,
                    max_functions=args.max_functions,
                    addr_requested=args.addr is not None,
                    result_status="timeout",
                    failure_stage=None,
                    nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
                )
                if nonopt_skip_reason is not None:
                    print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    fallback_function.name,
                    string_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            asm_fallback = _format_asm_range(project, start, end)
            recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
            if recovery_detail is None:
                recovery_detail = "during x86-16 function recovery (direct-address path)"
            print(f"/* timeout: function {args.addr:#x} {function_label or f'sub_{args.addr:x}'} */")
            _stored_snapshot = getattr(project, '_inertia_last_tail_validation_snapshot', None)
            if isinstance(_stored_snapshot, dict) and _stored_snapshot:
                for _diag_line in _format_tail_validation_diagnostic(
                    _stored_snapshot,
                    function_addr=args.addr,
                    function_name=function_label or f"sub_{args.addr:x}",
                    exit_kind="timeout",
                    exit_detail=recovery_detail,
                ):
                    print(_diag_line)
            _emit_timeout_and_exit(args.timeout, recovery_detail)
        except Exception as ex:
            recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
            if recovery_detail is None:
                print(f"/* Function recovery failed: {ex} */")
            else:
                print(f"/* Function recovery failed {recovery_detail}: {ex} */")
            print("\n/* == lift break probe == */")
            print(_probe_lift_break(project, args.addr))
            print("\n/* == first block asm == */")
            print(_format_first_block_asm(project, args.addr))
            print("\n/* == non-optimized disassembly == */")
            start, end = _infer_linear_disassembly_window(project, args.addr)
            print(_format_asm_range(project, start, end))
            return 5

        if (
            precise_sidecar_regions
            and lst_metadata is not None
            and project.arch.name == "86_16"
            and args.addr is not None
        ):
            try:
                sidecar_region = _lst_code_region(lst_metadata, args.addr)
                block_count, byte_count = _function_complexity(func)
                if (
                    sidecar_region is not None
                    and isinstance(sidecar_region[0], int)
                    and (block_count <= 3 or byte_count <= 24)
                ):
                    sidecar_addr = sidecar_region[0]
                    code_name = _lst_code_label(lst_metadata, sidecar_addr, project.entry) or f"sub_{sidecar_addr:x}"
                    cfg2, func2 = _recover_lst_function(
                        project,
                        lst_metadata,
                        sidecar_addr if lst_metadata.absolute_addrs else sidecar_addr - project.entry,
                        code_name,
                        timeout=max(1, min(args.timeout, 6)),
                        window=args.window,
                        low_memory=low_memory_path,
                    )
                    if func2 is not None:
                        cfg, func = cfg2, func2
                        mark_function_original_addr(func, args.addr)
            except Exception:
                pass

        if function_label is not None:
            func.name = function_label
        elif lst_metadata is not None:
            code_name = lst_metadata.code_labels.get(function_original_addr(func))
            if code_name is not None:
                func.name = code_name
        direct_project = getattr(func, "project", project)
        setattr(direct_project, "_inertia_trace_c_stages", bool(args.trace_c_stages))
        _apply_binary_specific_annotations(
            direct_project,
            args.binary,
            lst_metadata,
            func_addr=function_original_addr(func),
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )

        print(f"/* binary: {args.binary} */")
        print(f"/* arch: {project.arch.name} */")
        print(f"/* entry: {project.entry:#x} */")
        print(f"/* function: {function_original_addr(func):#x} {func.name} */")

        if args.show_asm:
            print("\n/* == asm == */")
            print(_format_first_block_asm(direct_project, func.addr))

        print("/* decompiling... */", flush=True)
        direct_tail_validation_snapshot: dict[str, object] | None = None
        direct_failure_family_state = FailureFamilyState()
        try:
            def direct_decompile_job():
                result = _decompile_function_with_stats(
                    direct_project,
                    cfg,
                    func,
                    args.timeout,
                    args.api_style,
                    args.binary,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
                    lst_metadata=lst_metadata,
                    failure_family_state=direct_failure_family_state,
                )
                snapshot = _tail_validation_snapshot_for_function_run(direct_project, func)
                project_fb = getattr(direct_project, '_inertia_last_tail_validation_snapshot', None)
                func_info_tv = None
                func_info = getattr(func, 'info', None)
                if isinstance(func_info, dict):
                    func_info_tv = func_info.get('x86_16_tail_validation')
                merged_statuses = (
                    {k: v.get("status") if isinstance(v, dict) else type(v).__name__ for k, v in snapshot.items()}
                    if isinstance(snapshot, dict)
                    else "N/A"
                )
                print(
                    f"[dbg] direct_decompile_job snapshot: project_fb_stages={list(project_fb.keys()) if isinstance(project_fb, dict) else 'NOT_DICT'} func_info_tv_stages={list(func_info_tv.keys()) if isinstance(func_info_tv, dict) else type(func_info_tv).__name__ if func_info_tv is not None else 'None'} merged_stages={list(snapshot.keys()) if isinstance(snapshot, dict) else 'NOT_DICT'} merged_statuses={merged_statuses}",
                    file=sys.stderr,
                    flush=True,
                )
                return (
                    *result,
                    snapshot,
                    FailureFamilyState(
                        previous_snapshot=direct_failure_family_state.previous_snapshot,
                        candidate_snapshot=direct_failure_family_state.candidate_snapshot,
                        new_proof_seen=direct_failure_family_state.new_proof_seen,
                        repeat_detected=direct_failure_family_state.repeat_detected,
                    ),
                )

            # The inner decompilation path already enforces the analysis deadline.
            # Give the forked direct-address wrapper a few extra seconds to merge
            # tail-validation snapshots and serialize the result back to the parent.
            _direct_blocks, _direct_bytes = _function_complexity(func)
            _direct_effective_timeout = _effective_decompile_timeout_8616(
                direct_project,
                args.timeout,
                block_count=_direct_blocks,
                byte_count=_direct_bytes,
            )
            direct_decompile_timeout = max(1, _direct_effective_timeout) + 5
            direct_decompile_timeout = max(1, min(direct_decompile_timeout, _remaining_direct_addr_budget() or 1))
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
            ):
                status, payload, partial_payload, *direct_extra = _run_with_timeout_in_fork(
                    direct_decompile_job,
                    timeout=direct_decompile_timeout,
                )
            else:
                status, payload, partial_payload, *direct_extra = _run_with_timeout_in_daemon_thread(
                    direct_decompile_job,
                    timeout=direct_decompile_timeout,
                    thread_name_prefix="direct-decomp",
                )
            for extra in direct_extra:
                if isinstance(extra, dict):
                    direct_tail_validation_snapshot = dict(extra)
                elif isinstance(extra, FailureFamilyState):
                    direct_failure_family_state.previous_snapshot = extra.previous_snapshot
                    direct_failure_family_state.candidate_snapshot = extra.candidate_snapshot
                    direct_failure_family_state.new_proof_seen = extra.new_proof_seen
                    direct_failure_family_state.repeat_detected = extra.repeat_detected
        except FuturesTimeoutError:
            status = "timeout"
            payload = f"Timed out after {args.timeout}s."
            partial_payload = None
        except TimeoutError as ex:
            status = "timeout"
            payload = _describe_exception(ex) or f"Timed out after {args.timeout}s."
            partial_payload = None
        direct_item = FunctionWorkItem(index=1, function_cfg=cfg, function=func)
        direct_result = FunctionWorkResult(
            index=1,
            status=status,
            payload=payload,
            debug_output="",
            function=func,
            function_cfg=cfg,
            partial_payload=partial_payload,
            tail_validation=direct_tail_validation_snapshot or _tail_validation_snapshot_for_function_run(direct_project, func),
        )
        direct_status, direct_blocker = _validated_generated_c_acceptance_8616(
            status=direct_result.status,
            payload=direct_result.payload,
            tail_validation_snapshot=direct_result.tail_validation,
            tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
            expected_validation_stages=["structuring", "postprocess"],
            c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
        )
        if direct_status != direct_result.status or direct_blocker is not None:
            direct_result = replace(
                direct_result,
                status=direct_status,
                payload=direct_blocker if direct_blocker is not None else direct_result.payload,
                partial_payload=None if direct_blocker is not None else direct_result.partial_payload,
            )
            if direct_status == "validation_failed" and isinstance(direct_result.tail_validation, dict):
                setattr(direct_project, "_inertia_forced_tail_validation_snapshot", dict(direct_result.tail_validation))
        direct_failure_family_snapshot = build_failure_family_snapshot(
            status=direct_result.status,
            failure_stage=getattr(direct_result, "failure_stage", None),
            fallback_kind="direct_addr",
            tail_validation_verdict=_tail_validation_display_status(direct_result.tail_validation),
            artifact_path=f"{func.addr:#x}:{func.name}",
        )
        budget_fallback_addr = function_original_addr(func)
        budget_fallback_name = func.name
        print(f"[dbg] direct failure family: {direct_failure_family_snapshot.label()}")
        if direct_result.status == "error":
            _print_stop_on_first_failure_8616(func, direct_result)
            return 6
        if direct_result.status != "ok":
            def _missing_call_count(payload_text: str) -> int:
                if not isinstance(payload_text, str) or not payload_text.strip():
                    return 10**9
                return len(_missing_expected_calls_from_embedded_evidence_8616(payload_text))

            # Evidence-first retry: a repeated direct run can produce a strictly
            # better semantic candidate. Keep the one with fewer missing
            # source-evidenced calls before entering heavy fallback fan-out.
            if direct_result.status == "validation_failed":
                try:
                    retry_status, retry_payload, retry_partial, *retry_extra = _run_with_timeout_in_daemon_thread(
                        direct_decompile_job,
                        timeout=max(1, min(args.timeout, 30)),
                        thread_name_prefix="direct-decomp-retry",
                    )
                    retry_tail_validation = None
                    for extra in retry_extra:
                        if isinstance(extra, dict):
                            retry_tail_validation = dict(extra)
                    retry_result = FunctionWorkResult(
                        index=1,
                        status=retry_status,
                        payload=retry_payload,
                        debug_output="",
                        function=func,
                        function_cfg=cfg,
                        partial_payload=retry_partial,
                        tail_validation=retry_tail_validation or _tail_validation_snapshot_for_function_run(direct_project, func),
                    )
                    retry_checked_status, retry_blocker = _validated_generated_c_acceptance_8616(
                        status=retry_result.status,
                        payload=retry_result.payload,
                        tail_validation_snapshot=retry_result.tail_validation,
                        tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                        expected_validation_stages=["structuring", "postprocess"],
                        c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                    )
                    if retry_checked_status != retry_result.status or retry_blocker is not None:
                        retry_result = replace(
                            retry_result,
                            status=retry_checked_status,
                            payload=retry_blocker if retry_blocker is not None else retry_result.payload,
                            partial_payload=None if retry_blocker is not None else retry_result.partial_payload,
                        )
                    current_missing = _missing_call_count(direct_result.payload)
                    retry_missing = _missing_call_count(retry_result.payload)
                    if retry_result.status == "ok" or retry_missing < current_missing:
                        direct_result = retry_result
                except Exception:
                    pass

            _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address decompilation budget")
            direct_display_addr = function_original_addr(func)
            using_rebased_direct_slice = direct_project is not project
            slice_result = None
            sidecar_closed_nonopt = False
            known_nonopt_result: NonOptimizedSliceOutcome | str | None = None
            # Cap heavy fallback fan-out per function to keep direct-addr mode
            # deterministic and prevent minute-long retry storms.
            heavy_fallback_budget = 2 if direct_result.status == "validation_failed" else 4

            def _consume_heavy_fallback_budget() -> bool:
                nonlocal heavy_fallback_budget
                if heavy_fallback_budget <= 0:
                    return False
                heavy_fallback_budget -= 1
                return True

            def _accept_direct_fallback_payload(payload_text: str) -> bool:
                snapshot = _tail_validation_snapshot_for_function_run(direct_project, func)
                checked_status, checked_blocker = _validated_generated_c_acceptance_8616(
                    status="ok",
                    payload=payload_text,
                    tail_validation_snapshot=snapshot,
                    tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                )
                if checked_status == "ok":
                    return True
                print(
                    f"[dbg] rejected direct fallback payload: {checked_status} "
                    f"detail={checked_blocker or 'n/a'}",
                    file=sys.stderr,
                    flush=True,
                )
                return False

            exact_retry_blocked = direct_failure_family_state.repeat_detected and not direct_failure_family_state.new_proof_seen
            if direct_result.status == "empty":
                # Allow one non-optimized known-function lane even when the
                # optimized lane repeats an "empty" family; this is often a
                # recoverable clinic/core failure class for helper routines.
                exact_retry_blocked = False
            if (
                direct_result.status == "validation_failed"
                and precise_sidecar_regions
                and not using_rebased_direct_slice
                and lst_metadata is not None
            ):
                sidecar_region = _lst_code_region(lst_metadata, direct_display_addr)
                if sidecar_region is not None:
                    try:
                        sidecar_addr = sidecar_region[0]
                        code_name = _lst_code_label(lst_metadata, sidecar_addr, project.entry) or func.name
                        side_cfg, side_func = _recover_lst_function(
                            project,
                            lst_metadata,
                            sidecar_addr if lst_metadata.absolute_addrs else sidecar_addr - project.entry,
                            code_name,
                            timeout=max(2, min(args.timeout, 8)),
                            window=args.window,
                            low_memory=low_memory_path,
                        )
                        side_status, side_payload, *_ = _decompile_function_with_stats(
                            project,
                            side_cfg,
                            side_func,
                            max(2, min(args.timeout, 8)),
                            args.api_style,
                            args.binary,
                            cod_metadata=cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            allow_isolated_retry=False,
                            failure_family_state=direct_failure_family_state,
                        )
                        if side_status == "ok":
                            _emit_tail_validation_for_function_run_or_uncollected(
                                project,
                                side_cfg,
                                side_func,
                                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                                binary_path=args.binary,
                            )
                            side_tail = _tail_validation_snapshot_for_function_run(project, side_func)
                            side_status_checked, _side_blocker = _validated_generated_c_acceptance_8616(
                                status=side_status,
                                payload=side_payload,
                                tail_validation_snapshot=side_tail,
                                tail_validation_enabled=_tail_validation_runtime_enabled(project),
                                expected_validation_stages=["structuring", "postprocess"],
                                c_target=getattr(project, "_inertia_c_target", "portable-flat"),
                            )
                            if side_status_checked != "ok":
                                side_status = side_status_checked
                        if side_status == "ok":
                            _emit_optional_source_sidecar_c_block(
                                args.binary,
                                side_func.name,
                                side_payload,
                                alternate_source_c=bool(args.alternate_source_c),
                                c_header="\n/* == c (sidecar slice fallback) == */",
                            )
                            if _accept_direct_fallback_payload(side_payload):
                                return 0
                    except Exception:
                        pass
                _early_slice = _try_decompile_sidecar_slice(
                    project,
                    lst_metadata,
                    direct_display_addr,
                    func.name,
                    timeout=max(2, min(args.timeout, _remaining_direct_addr_budget() or 2)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    failure_family_state=direct_failure_family_state,
                )
                if _early_slice is not None and _early_slice.status == "ok":
                    _emit_tail_validation_for_function_run_or_uncollected(
                        direct_project,
                        cfg,
                        func,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                        binary_path=args.binary,
                    )
                    if _accept_direct_fallback_payload(_early_slice.payload):
                        _emit_optional_source_sidecar_c_block(
                            args.binary,
                            func.name,
                            _early_slice.payload,
                            alternate_source_c=bool(args.alternate_source_c),
                            c_header="\n/* == c (sidecar slice fallback) == */",
                        )
                        return 0
            allow_known_nonopt = (
                (not exact_retry_blocked)
                or (direct_result.status in {"timeout", "validation_failed"})
            )
            if partial_payload is None:
                if allow_known_nonopt:
                    if not _consume_heavy_fallback_budget():
                        allow_known_nonopt = False
                if allow_known_nonopt:
                    _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                    known_nonopt_result = _try_decompile_non_optimized_known_function(
                        direct_project,
                        cfg,
                        func,
                        timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                        api_style=args.api_style,
                        binary_path=args.binary,
                        lst_metadata=None if using_rebased_direct_slice else lst_metadata,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        failure_family_state=direct_failure_family_state,
                    )
            known_nonopt_c = _non_optimized_slice_rendered(known_nonopt_result)
            if known_nonopt_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    direct_project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                if _accept_direct_fallback_payload(known_nonopt_c):
                    print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                    print("/* Falling back to known-function non-optimized decompilation. */")
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        known_nonopt_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (non-optimized fallback) == */",
                    )
                    return 0
            _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
            generic_nonopt_result = None
            if _consume_heavy_fallback_budget():
                generic_nonopt_result = _try_decompile_non_optimized_slice(
                    direct_project,
                    direct_display_addr,
                    func.name,
                    timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=None if using_rebased_direct_slice else lst_metadata,
                    cod_metadata=cod_metadata,
                    allow_fresh_project_retry=False,
                    failure_family_state=direct_failure_family_state,
                    original_addr=direct_display_addr,
                )
            generic_nonopt_c = _non_optimized_slice_rendered(generic_nonopt_result)
            if generic_nonopt_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    direct_project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                if _accept_direct_fallback_payload(generic_nonopt_c):
                    print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                    print("/* Falling back to non-optimized slice decompilation. */")
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        generic_nonopt_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (non-optimized fallback) == */",
                    )
                    return 0
            exact_retry_blocked = direct_failure_family_state.repeat_detected and not direct_failure_family_state.new_proof_seen
            if direct_result.status == "validation_failed":
                # Validation-failed direct lane is frequently under-recovered
                # semantics. Allow exact sidecar retry even when the failure
                # family repeats so richer bounded slices can be considered.
                exact_retry_blocked = False
            if precise_sidecar_regions and not using_rebased_direct_slice:
                if not exact_retry_blocked:
                    _dbg_region = _lst_code_region(lst_metadata, direct_display_addr) if lst_metadata is not None else None
                    print(
                        f"[dbg] sidecar slice gate: precise={precise_sidecar_regions} rebased={using_rebased_direct_slice} blocked={exact_retry_blocked} addr={direct_display_addr:#x} region={_dbg_region}",
                        file=sys.stderr,
                        flush=True,
                    )
                    _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                    sidecar_attempted = False
                    if _consume_heavy_fallback_budget():
                        sidecar_attempted = True
                        slice_result = _try_decompile_sidecar_slice(
                            project,
                            lst_metadata,
                            direct_display_addr,
                            func.name,
                            timeout=max(1, min(args.timeout, _remaining_direct_addr_budget() or 1)),
                            api_style=args.api_style,
                            binary_path=args.binary,
                            failure_family_state=direct_failure_family_state,
                        )
                    if sidecar_attempted and slice_result is None:
                        print("[dbg] sidecar slice attempt returned None", file=sys.stderr, flush=True)
            if slice_result is not None:
                if slice_result.status != "ok":
                    print(
                        f"[dbg] sidecar slice attempt status={slice_result.status} payload={getattr(slice_result, 'payload', None)}",
                        file=sys.stderr,
                        flush=True,
                    )
                    sidecar_closed_nonopt = sidecar_verdict_closes_non_optimized_lane(slice_result.verdict)
                    slice_result = None
                else:
                    _emit_tail_validation_for_function_run_or_uncollected(
                        direct_project,
                        cfg,
                        func,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                        binary_path=args.binary,
                    )
                    if _accept_direct_fallback_payload(slice_result.payload):
                        _emit_optional_source_sidecar_c_block(
                            args.binary,
                            func.name,
                            slice_result.payload,
                            alternate_source_c=bool(args.alternate_source_c),
                            c_header="\n/* == c (sidecar slice fallback) == */",
                        )
                        return 0
            if precise_sidecar_regions and not using_rebased_direct_slice:
                peer_sidecar_c = _try_decompile_peer_sidecar_slice(
                    project,
                    lst_metadata,
                    direct_display_addr,
                    func.name,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                )
                if peer_sidecar_c is not None:
                    _emit_tail_validation_for_function_run_or_uncollected(
                        direct_project,
                        cfg,
                        func,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("peer_sidecar"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        peer_sidecar_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (peer sidecar fallback) == */",
                    )
                    return 0
                trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, direct_display_addr, func.name)
                if trivial_c is not None:
                    _emit_tail_validation_for_function_run_or_uncollected(
                        direct_project,
                        cfg,
                        func,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
                        binary_path=args.binary,
                    )
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        trivial_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (trivial sidecar fallback) == */",
                    )
                    return 0
            nonopt_result: NonOptimizedSliceOutcome | str | None = None
            if (
                partial_payload is None
                and known_nonopt_c is None
                and (precise_sidecar_regions or using_rebased_direct_slice)
                and not sidecar_closed_nonopt
                and not (direct_failure_family_state.repeat_detected and not direct_failure_family_state.new_proof_seen)
                and _consume_heavy_fallback_budget()
            ):
                _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                nonopt_result = _try_decompile_non_optimized_slice(
                    direct_project if using_rebased_direct_slice else project,
                    func.addr,
                    func.name,
                    timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=None if using_rebased_direct_slice else lst_metadata,
                    cod_metadata=cod_metadata,
                    allow_fresh_project_retry=False,
                    failure_family_state=direct_failure_family_state,
                    original_addr=direct_display_addr,
                )
            nonopt_c = _non_optimized_slice_rendered(nonopt_result)
            if nonopt_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    direct_project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                if _accept_direct_fallback_payload(nonopt_c):
                    print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                    print("/* Falling back to non-optimized slice decompilation. */")
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        nonopt_c,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (non-optimized fallback) == */",
                    )
                    return 0
            if partial_payload is not None:
                _emit_tail_validation_snapshot_or_uncollected(
                    cfg,
                    func,
                    direct_result.tail_validation,
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    func.name,
                    partial_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (partial timeout) == */",
                )
                return 0
            sidecar_region = None
            if lst_metadata is not None and not using_rebased_direct_slice:
                sidecar_region = _lst_code_region(lst_metadata, direct_display_addr)
            linear_window = None if sidecar_region is not None else _infer_linear_disassembly_window(direct_project, func.addr)
            string_c = _try_emit_string_intrinsic_c(
                direct_project,
                start=sidecar_region[0] if sidecar_region is not None else linear_window[0],
                end=sidecar_region[1] if sidecar_region is not None else linear_window[1],
                name=func.name,
            )
            if string_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    direct_project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=args.binary,
                )
                print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                print("/* Falling back to generic string-intrinsic recovery. */")
                nonopt_skip_reason = describe_non_optimized_unavailable(
                    allow_heavy_fallbacks=True,
                    skip_heavy_fallbacks_for_result=False,
                    interactive_stdout=interactive_stdout,
                    max_functions=args.max_functions,
                    addr_requested=args.addr is not None,
                    result_status=direct_result.status,
                    failure_stage=None,
                    nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
                )
                if nonopt_skip_reason is not None:
                    print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    func.name,
                    string_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            _emit_tail_validation_for_function_run_or_uncollected(
                direct_project,
                cfg,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                binary_path=args.binary,
            )
            asm_fallback = (
                _format_asm_range(project, sidecar_region[0], sidecar_region[1])
                if sidecar_region is not None
                else _format_asm_range(project, *_infer_linear_disassembly_window(project, func.addr))
            )
            print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
            print("/* Falling back to non-optimized disassembly. */")
            nonopt_failure_detail = _non_optimized_slice_failure_detail(nonopt_result)
            if nonopt_failure_detail is not None:
                print(f"/* non-optimized fallback failed: {nonopt_failure_detail} */")
            for _diag_line in _format_tail_validation_diagnostic(
                direct_result.tail_validation,
                function_addr=func.addr,
                function_name=func.name,
                block_count=getattr(direct_result, 'block_count', None),
                byte_count=getattr(direct_result, 'byte_count', None),
                exit_kind=direct_result.status,
                exit_detail=direct_result.payload,
            ):
                print(_diag_line)
            print("\n/* == lift break probe == */")
            print(_probe_lift_break(project, func.addr))
            print("\n/* == asm fallback == */")
            print(asm_fallback)
            return 6 if status == "error" else 4

        _emit_tail_validation_console_summary([direct_item], {1: direct_result}, binary_path=args.binary)
        _emit_optional_source_sidecar_c_block(
            args.binary,
            func.name,
            payload,
            alternate_source_c=bool(args.alternate_source_c),
            c_header="\n/* == c == */",
        )
        return 0

    print("/* discovering likely functions... */", flush=True)
    cfg = None
    function_cfg_pairs: list[tuple[object, object]] = []
    ranked_binary_offsets: list[int] = []
    labeled_offsets: list[tuple[int, str]] = []
    ranked_labeled_total = 0
    total_functions = 0
    shown_total = 0
    direct_inventory_total: int | None = None
    prefer_ranked_hidden_sidecar_full_queue = False
    visible_code_labels = _visible_code_labels(lst_metadata)
    recovery_code_labels = _recovery_code_labels(lst_metadata) if lst_metadata is not None else {}
    include_library_functions = bool(getattr(args, "include_library_functions", False))
    if include_library_functions and lst_metadata is not None:
        visible_code_labels = dict(getattr(lst_metadata, "code_labels", {}) or {})
        recovery_code_labels = dict(visible_code_labels)
    elif lst_metadata is not None and not visible_code_labels and recovery_code_labels:
        # Sidecar has only signature/library labels. Use them as bounded catalog
        # instead of speculative ranked scans that are often noisy on packed EXEs.
        include_library_functions = True
        visible_code_labels = dict(recovery_code_labels)
        print("/* sidecar provides only signature labels; auto-enabling library-labeled function catalog for stable recovery. */")
    seed_code_labels = visible_code_labels or recovery_code_labels
    skipped_signature_labels = (
        len(getattr(lst_metadata, "code_labels", {})) - len(visible_code_labels) if lst_metadata is not None else 0
    )
    if low_memory_path:
        print("/* Low-memory mode: using a smaller, safer function-discovery pass. */")
    packed_exe = None if args.proc is not None else getattr(project, "_inertia_packed_exe", None)
    if lst_metadata is not None and visible_code_labels:
        try:
            ranking_start = time.perf_counter()
            labeled_offsets, ranking_cache_hit = _rank_labeled_function_entries_cached(
                project,
                list(seed_code_labels.items()),
                lst_metadata,
            )
            ranking_elapsed_ms = (time.perf_counter() - ranking_start) * 1000.0
            print(
                f"/* sidecar label ranking prepared {len(labeled_offsets)} entries in "
                f"{ranking_elapsed_ms:.1f}ms{' (cache hit)' if ranking_cache_hit else ''}. */"
            )
            ranked_labeled_total = len(labeled_offsets)
            if args.max_functions > 0:
                labeled_offsets = labeled_offsets[: args.max_functions]
        except Exception as ex:
            print(f"/* Listing-backed function catalog setup failed: {ex} */")
            print("\n/* == entry asm == */")
            print(_format_first_block_asm(project, project.entry))
            return 5
    else:
        catalog_error: Exception | None = None
        deferred_exe_display_cap = (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and args.max_functions > 0
        )
        if args.addr is None and args.binary.suffix.lower() == ".exe":
            ranked_seed_discovery_enabled = os.environ.get(
                "INERTIA_ENABLE_RANKED_EXE_DISCOVERY", ""
            ).strip().lower() in {"1", "true", "yes", "on"}
            ranked_binary_offsets = _rank_exe_function_seeds(project) if ranked_seed_discovery_enabled else []
            direct_inventory_total = len(ranked_binary_offsets) if ranked_binary_offsets else None
        discovery_limit = (
            _expanded_exe_discovery_limit(args.max_functions)
            if deferred_exe_display_cap
            else (args.max_functions if args.max_functions > 0 else None)
        )
        if lst_metadata is not None and not visible_code_labels:
            if recovery_code_labels:
                print(
                    "/* Signature-matched library labels available as bounded hints; "
                    "recovering binary-owned functions from direct call/prologue evidence before generic CFG recovery. */"
                )
            if args.max_functions <= 0 and ranked_binary_offsets:
                prefer_ranked_hidden_sidecar_full_queue = True
                total_functions = len(ranked_binary_offsets)
                shown_total = len(ranked_binary_offsets)
                print(
                    "/* hidden-sidecar EXE: queueing ranked direct-binary function candidates for full decompilation "
                    "without waiting for whole-program CFG recovery. */"
                )
            if deferred_exe_display_cap and ranked_binary_offsets:
                # Hidden-sidecar EXEs only have signature/library labels. Do not
                # spend time pre-recovering a capped preview here; queue ranked
                # binary-owned candidates and recover each one in the streaming
                # serial lane so the first function can be emitted sooner.
                prefer_ranked_hidden_sidecar_full_queue = True
                total_functions = len(ranked_binary_offsets)
                shown_total = min(len(ranked_binary_offsets), args.max_functions)
                print(
                    "/* hidden-sidecar EXE: using ranked direct-binary function candidates; "
                    "recovering selected functions lazily for streaming output. */"
                )
            try:
                if not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
                    function_cfg_pairs = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_seeded_exe_functions(
                            project,
                            timeout=min(max(4, args.timeout), 8),
                            limit=discovery_limit,
                            return_addrs=True,
                        ),
                        timeout=min(max(4, args.timeout + 2), 8),
                        thread_name_prefix="seed-catalog",
                    )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex
                function_cfg_pairs = [] if not function_cfg_pairs else function_cfg_pairs
                seeded_catalog_addrs = []
            else:
                seeded_catalog_addrs = []
                if isinstance(function_cfg_pairs, tuple):
                    function_cfg_pairs, seeded_catalog_addrs = function_cfg_pairs
            if function_cfg_pairs and not total_functions:
                total_functions = len(seeded_catalog_addrs)
                shown_total = len(function_cfg_pairs)

        prefer_bounded_catalog = (
            lst_metadata is None
            and project.arch.name == "86_16"
            and args.binary.suffix.lower() == ".exe"
        )
        cached_catalog_addrs = (
            _load_catalog_address_cache(project, args.binary)
            if prefer_bounded_catalog
            else []
        )
        if cached_catalog_addrs:
            print("/* using cached discovered function addresses before running new control-flow recovery. */")
            function_cfg_pairs = _recover_cached_function_pairs(
                project,
                addrs=cached_catalog_addrs,
                timeout=min(max(4, args.timeout), 8),
                limit=discovery_limit,
            )
            if function_cfg_pairs:
                try:
                    display_cache_key = _recovery_cache_key(
                        binary_path=args.binary,
                        kind="display_catalog_addrs",
                        extra={
                            "entry": getattr(project, "entry", None),
                            "arch": getattr(getattr(project, "arch", None), "name", None),
                        },
                    )
                    function_cfg_pairs, cached_catalog_addrs = _run_with_timeout_in_daemon_thread(
                        lambda: _supplement_cached_seeded_recovery(
                            project,
                            function_cfg_pairs,
                            list(cached_catalog_addrs),
                            region_span=0x120,
                            per_function_timeout=1,
                            limit=discovery_limit,
                            cache_key=display_cache_key,
                        ),
                        timeout=min(max(1, args.timeout), 2),
                        thread_name_prefix="cached-display-supplement",
                    )
                except FuturesTimeoutError:
                    pass
                total_functions = len(cached_catalog_addrs)
                shown_total = len(function_cfg_pairs)

        if prefer_bounded_catalog and not function_cfg_pairs:
            try:
                function_cfg_pairs = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_fast_exe_catalog(
                        project,
                        timeout=args.timeout,
                        window=args.window,
                        low_memory=low_memory_path,
                        limit=discovery_limit if discovery_limit is not None else 16,
                    ),
                    timeout=min(max(2, args.timeout), 8),
                    thread_name_prefix="fast-catalog",
                )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex
                print("/* Quick EXE function discovery timed out; falling back to a bounded control-flow recovery pass. */")
                function_cfg_pairs = []
            if function_cfg_pairs:
                total_functions = len(function_cfg_pairs)
                shown_total = len(function_cfg_pairs)

        if prefer_bounded_catalog and not function_cfg_pairs:
            print(
                "/* No helper metadata for this x86-16 EXE; first trying a small scan near program entry before whole-program control-flow recovery. */"
            )
            if not function_cfg_pairs:
                try:
                    cfg = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_partial_cfg(
                            project,
                            window=args.window,
                            low_memory=low_memory_path,
                        ),
                        timeout=args.timeout,
                        thread_name_prefix="catalog-fallback",
                    )
                except Exception as ex:  # noqa: BLE001
                    catalog_error = ex

        if cfg is None and not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
            if prefer_bounded_catalog:
                print("/* Small entry-area recovery failed; attempting whole-program control-flow recovery as a last resort. */")
            try:
                cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_cfg(
                        project,
                        args.binary,
                        base_addr=args.base_addr,
                        window=args.window,
                        low_memory=low_memory_path,
                    ),
                    timeout=args.timeout,
                    thread_name_prefix="catalog",
                )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex

        if (
            cfg is None
            and not function_cfg_pairs
            and project.arch.name == "86_16"
            and not prefer_bounded_catalog
            and not prefer_ranked_hidden_sidecar_full_queue
        ):
            print(
                "/* Whole-program function discovery failed; attempting a smaller entry-area recovery pass. */"
            )
            try:
                cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_partial_cfg(
                        project,
                        window=args.window,
                        low_memory=low_memory_path,
                    ),
                    timeout=args.timeout,
                    thread_name_prefix="catalog-fallback",
                )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex

        if cfg is None and not function_cfg_pairs:
            fast_seed_pairs: list[tuple[object, object]] = []
            print("/* Whole-program control-flow recovery failed; attempting a quick function-entry scan fallback. */")
            fast_seed_pairs = _recover_fast_seed_functions(
                project,
                timeout=min(max(4, args.timeout), 8),
                limit=discovery_limit,
            )
            if fast_seed_pairs:
                function_cfg_pairs = fast_seed_pairs
                total_functions = len(function_cfg_pairs)
                shown_total = len(function_cfg_pairs)
                cfg = None
            elif prefer_ranked_hidden_sidecar_full_queue:
                pass
            elif (
                not prefer_ranked_hidden_sidecar_full_queue
                and (
                args.addr is None
                and args.binary.suffix.lower() == ".exe"
                and ranked_binary_offsets
                )
            ):
                print(
                    "/* Falling back to ranked direct-binary function addresses; "
                    "recovering only the shown subset lazily. */"
                )
            else:
                detail = "Timed out" if isinstance(catalog_error, FuturesTimeoutError) else _describe_exception(catalog_error) if catalog_error is not None else "Unknown failure"
                print(f"/* Function catalog recovery failed: {detail} */")
                if packed_exe is not None:
                    print(f"/* hint: {args.binary.name} looks packed ({packed_exe}); startup-stub output may be the current limit. */")
                print("\n/* == lift break probe == */")
                print(_probe_lift_break(project, project.entry))
                print("\n/* == entry asm == */")
                print(_format_first_block_asm(project, project.entry))
                print("\n/* == non-optimized disassembly == */")
                start, end = _infer_linear_disassembly_window(project, project.entry)
                print(_format_asm_range(project, start, end))
                return 5

    if skipped_signature_labels > 0:
        print(f"/* skipping {skipped_signature_labels} signature-matched function(s) by default. */")
    elif include_library_functions and lst_metadata is not None:
        print("/* including signature/library-labeled functions as requested. */")

    if cfg is not None:
        if function_label is not None and project.entry in cfg.functions:
            cfg.functions[project.entry].name = function_label
        elif lst_metadata is not None:
            for addr, func in cfg.functions.items():
                code_name = _lst_code_label(lst_metadata, addr, project.entry)
                if code_name is not None:
                    func.name = code_name

    if lst_metadata is not None and visible_code_labels:
        total_functions = ranked_labeled_total or len(labeled_offsets)
        shown_total = len(labeled_offsets)
    elif not function_cfg_pairs and cfg is not None:
        limit = args.max_functions if args.max_functions > 0 else None
        defer_limit_until_after_seed_ranking = (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
        )
        functions, total_functions = _interesting_functions(cfg, limit=None if defer_limit_until_after_seed_ranking else limit)
        shown_total = len(functions)
        function_cfg_pairs = [(cfg, function) for function in functions]
        if args.addr is None and args.binary.suffix.lower() == ".exe":
            seeded_pairs, seeded_addrs = _recover_seeded_exe_functions(
                project,
                timeout=min(max(4, args.timeout // 2), 8),
                limit=None if (limit is None or defer_limit_until_after_seed_ranking) else max(0, limit - shown_total),
                return_addrs=True,
            )
            if seeded_pairs:
                seen_existing = {function.addr for function in functions}
                seeded_pairs = _rank_function_cfg_pairs_for_display(project, seeded_pairs)
                for function_cfg, function in seeded_pairs:
                    if function.addr in seen_existing:
                        continue
                    function_cfg_pairs.append((function_cfg, function))
                    seen_existing.add(function.addr)
                function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
                if limit is not None and defer_limit_until_after_seed_ranking:
                    function_cfg_pairs = function_cfg_pairs[:limit]
                shown_total = len(function_cfg_pairs)
                total_functions = max(total_functions, len(seen_existing | set(seeded_addrs)))
                project._inertia_supplemental_scan_used = True
            elif limit is not None and defer_limit_until_after_seed_ranking:
                function_cfg_pairs = function_cfg_pairs[:limit]
                shown_total = len(function_cfg_pairs)
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and shown_total <= 1
        ):
            supplemental_pairs = _supplement_functions_from_prologue_scan(
                project,
                {function.addr for function in functions},
            )
            if supplemental_pairs:
                function_cfg_pairs.extend(supplemental_pairs)
                function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
                shown_total = len(function_cfg_pairs)
                total_functions = max(total_functions, shown_total)
                project._inertia_supplemental_scan_used = True
    elif (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and ranked_binary_offsets
    ):
        shown_total = len(ranked_binary_offsets)
        if args.max_functions > 0:
            shown_total = min(shown_total, args.max_functions)

    sidecar_preview_limit = None
    if (
        lst_metadata is not None
        and visible_code_labels
        and interactive_stdout
        and args.max_functions > 0
        and total_functions > args.max_functions
    ):
        sidecar_preview_limit = args.max_functions
    if lst_metadata is not None and visible_code_labels:
        print("/* == known function catalog (sidecar-backed) == */")
        print(_format_sidecar_function_catalog(lst_metadata, limit=sidecar_preview_limit))
        if sidecar_preview_limit is not None and total_functions > sidecar_preview_limit:
            print(
                f"/* catalog preview limited to first {sidecar_preview_limit} entries for responsiveness. */"
            )

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and function_cfg_pairs
        and len(function_cfg_pairs) > 1
        and not (
            lst_metadata is not None
            and not visible_code_labels
            and ranked_binary_offsets
            and args.max_functions > 0
        )
    ):
        function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is not None
        and not visible_code_labels
        and args.max_functions > 0
        and function_cfg_pairs
        and len(function_cfg_pairs) < args.max_functions
        and ranked_binary_offsets
    ):
        function_cfg_pairs = _supplement_function_cfg_pairs_with_seeded_recovery(
            project,
            function_cfg_pairs,
            timeout=args.timeout,
            target_count=args.max_functions,
        )
        function_cfg_pairs = _supplement_function_cfg_pairs_with_ranked_preview(
            project,
            function_cfg_pairs,
            ranked_binary_offsets,
            target_count=args.max_functions,
            timeout=args.timeout,
            window=args.window,
            low_memory=low_memory_path,
        )
        function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
        shown_total = len(function_cfg_pairs)
    uncapped_function_cfg_pairs = list(function_cfg_pairs)
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and len(function_cfg_pairs) > args.max_functions
    ):
        function_cfg_pairs = function_cfg_pairs[: args.max_functions]
        shown_total = len(function_cfg_pairs)

    print(f"/* binary: {args.binary} */")
    print(f"/* arch: {project.arch.name} */")
    print(f"/* entry: {project.entry:#x} */")
    if direct_inventory_total is not None:
        print(f"/* info: direct-binary recovery found {direct_inventory_total} likely non-library function entries */")
        total_functions = max(total_functions, direct_inventory_total)
    print(f"/* functions queued for decompilation: {total_functions} */")

    if args.max_functions > 0 and total_functions > shown_total:
        print(
            f"/* showing first {shown_total} functions because --max-functions={args.max_functions}; "
            "raise it or omit the option to decompile all queued functions */"
        )

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is None
        and uncapped_function_cfg_pairs
    ):
        _store_catalog_address_cache(project, args.binary, uncapped_function_cfg_pairs)

    function_tasks: list[FunctionWorkItem] = []
    result_map: dict[int, FunctionWorkResult] = {}
    fallback_tail_validation_by_index: dict[int, dict[str, object]] = {}
    if lst_metadata is not None and visible_code_labels:
        for index, (offset, name) in enumerate(labeled_offsets, start=1):
            placeholder = _make_placeholder_function(project, offset, name)
            function_tasks.append(FunctionWorkItem(index=index, function_cfg=None, function=placeholder))
    elif (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and not function_cfg_pairs
        and ranked_binary_offsets
    ):
        preview_addrs = ranked_binary_offsets
        if (
            lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and args.max_functions <= 0
        ):
            function_tasks = [
                FunctionWorkItem(
                    index=index,
                    function_cfg=None,
                    function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                )
                for index, addr in enumerate(preview_addrs, start=1)
            ]
            shown_total = len(function_tasks)
        else:
            if args.max_functions > 0:
                preview_addrs = preview_addrs[: args.max_functions]
            elif interactive_stdout and len(preview_addrs) > 24:
                preview_addrs = preview_addrs[: _default_exe_showcase_cap(len(preview_addrs), args.timeout)]
            shown_total = len(preview_addrs)
            if lst_metadata is not None and not visible_code_labels:
                function_tasks = [
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    )
                    for index, addr in enumerate(preview_addrs, start=1)
                ]
            else:
                function_tasks = _prepare_ranked_binary_preview_items(
                    project,
                    ranked_binary_offsets,
                    max_count=shown_total,
                    timeout=args.timeout,
                    window=args.window,
                    low_memory=low_memory_path,
                )
    else:
        for index, (function_cfg, function) in enumerate(function_cfg_pairs, start=1):
            function_tasks.append(FunctionWorkItem(index=index, function_cfg=function_cfg, function=function))
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and ranked_binary_offsets
            and args.max_functions <= 0
        ):
            existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            function_tasks = []
            for index, addr in enumerate(ranked_binary_offsets, start=1):
                existing = existing_by_addr.get(addr)
                if existing is not None:
                    function_tasks.append(
                        FunctionWorkItem(
                            index=index,
                            function_cfg=existing.function_cfg,
                            function=existing.function,
                        )
                    )
                    continue
                function_tasks.append(
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    )
                )
            shown_total = len(function_tasks)
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and ranked_binary_offsets
            and args.max_functions > 0
        ):
            existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            replacement_tasks: list[FunctionWorkItem] = []
            for index, addr in enumerate(ranked_binary_offsets[: args.max_functions], start=1):
                existing = existing_by_addr.get(addr)
                if existing is not None:
                    replacement_tasks.append(
                        FunctionWorkItem(
                            index=index,
                            function_cfg=existing.function_cfg,
                            function=existing.function,
                        )
                    )
                    continue
                replacement_tasks.append(
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    )
                )
            function_tasks = replacement_tasks
            shown_total = len(function_tasks)

    selection_target = "decompilation" if args.max_functions <= 0 and args.addr is None else "display"
    print(f"/* info: selected {shown_total} function(s) for {selection_target} */")

    workers = _choose_function_parallelism(len(function_tasks))
    if lst_metadata is not None and visible_code_labels:
        workers = 1
    if any(item.function_cfg is None for item in function_tasks):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is not None
        and not visible_code_labels
    ):
        workers = 1
    if (
        getattr(project, "_inertia_supplemental_scan_used", False)
        and _should_force_serial_supplemental_decompilation(len(function_tasks))
    ):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and args.max_functions <= 2
    ):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and project.arch.name == "86_16"
        and include_library_functions
    ):
        workers = 1
    forced_serial_function_decomp = (
        os.environ.get(_FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {"1", "true", "yes", "on"}
    )
    use_serial_fork_per_function = (
        workers <= 1
        and args.addr is None
        and type(project).__module__.startswith("angr.")
        and not (
            args.binary.suffix.lower() == ".exe"
            and project.arch.name == "86_16"
            and include_library_functions
        )
        and os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
    )
    if workers > 1:
        print(f"/* parallel function decompilation: {workers} workers, shared imports */")
    elif use_serial_fork_per_function:
        print("/* parallel function decompilation: disabled; using isolated serial fork/COW workers to bound RAM */")
    elif forced_serial_function_decomp:
        print("/* parallel function decompilation: disabled (forced serial) */")
    else:
        print("/* parallel function decompilation: disabled (RAM pressure or single function) */")
    force_isolated_function_projects = (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and project.arch.name == "86_16"
    )

    if force_isolated_function_projects:
        print("/* parallel x86-16 decompilation: using one fresh analysis project per shown function for stability. */")

    allow_heavy_fallbacks = allows_heavy_fallbacks_for_run(
        interactive_stdout=interactive_stdout,
        max_functions=args.max_functions,
        addr_requested=args.addr is not None,
    )

    if workers <= 1:
        decompiled = 0
        failed = 0
        emitted_indexes: set[int] = set()
        recover_timeout = _default_recovery_timeout(args.timeout, explicit_timeout=timeout_was_explicit)
        adaptive_timeout_model = _AdaptivePerByteTimeoutModel(
            args.timeout,
            explicit_timeout=timeout_was_explicit,
            margin=1.5,
        )
        allow_isolated_retry_in_function_tasks = True
        for item in function_tasks:
            result = result_map.get(item.index)
            if result is None:
                active_item = item
                if item.function_cfg is None:
                    recovery_mode = "lst" if lst_metadata is not None and visible_code_labels else "ranked"
                    recovery_cache_key = None
                    cached_work_result, _cache_bypass_debug, _cache_key, _tail_enabled, _expected_stages = (
                        _function_work_cache_lookup(
                            item,
                            binary_path=args.binary,
                            timeout=args.timeout,
                            api_style=args.api_style,
                            enable_structured_simplify=True,
                            enable_postprocess=True,
                        )
                    )
                    if cached_work_result is not None:
                        result = cached_work_result
                    if result is None:
                        cached_recovery_result, recovery_cache_bypass_debug, recovery_cache_key = (
                            _lookup_persistent_recovery_timeout(
                                binary_path=args.binary,
                                addr=item.function.addr,
                                mode=recovery_mode,
                                window=args.window,
                                low_memory=low_memory_path,
                                timeout=recover_timeout,
                            )
                        )
                        if cached_recovery_result is not None:
                            result = replace(
                                cached_recovery_result,
                                index=item.index,
                                function=item.function,
                                function_cfg=None,
                            )
                    try:
                        if result is not None:
                            pass
                        elif lst_metadata is not None and visible_code_labels:
                            print(
                                f"[dbg] recovery worker: start {item.function.addr:#x} {item.function.name} "
                                f"mode=lst recovery_timeout={recover_timeout}s"
                            )
                            if (
                                os.name == "posix"
                                and threading.current_thread() is threading.main_thread()
                                and threading.active_count() == 1
                            ):
                                try:
                                    function_cfg, function = _run_with_timeout_in_fork(
                                        lambda offset=item.function.addr, name=item.function.name: _recover_lst_function(
                                            project,
                                            lst_metadata,
                                            offset,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                    )
                                except (FuturesTimeoutError, TimeoutError):
                                    raise
                                except Exception:
                                    function_cfg, function = _run_with_timeout_in_daemon_thread(
                                        lambda offset=item.function.addr, name=item.function.name: _recover_lst_function(
                                            project,
                                            lst_metadata,
                                            offset,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                        thread_name_prefix="lst-recover",
                                    )
                            else:
                                function_cfg, function = _run_with_timeout_in_daemon_thread(
                                    lambda offset=item.function.addr, name=item.function.name: _recover_lst_function(
                                        project,
                                        lst_metadata,
                                        offset,
                                        name,
                                        timeout=recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    ),
                                    timeout=recover_timeout + 1,
                                    thread_name_prefix="lst-recover",
                                )
                        else:
                            print(
                                f"[dbg] recovery worker: start {item.function.addr:#x} {item.function.name} "
                                f"mode=ranked recovery_timeout={recover_timeout}s"
                            )
                            if (
                                os.name == "posix"
                                and threading.current_thread() is threading.main_thread()
                                and threading.active_count() == 1
                            ):
                                try:
                                    function_cfg, function = _run_with_timeout_in_fork(
                                        lambda addr=item.function.addr, name=item.function.name: _recover_ranked_binary_function(
                                            project,
                                            addr,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                    )
                                except (FuturesTimeoutError, TimeoutError):
                                    raise
                                except Exception:
                                    function_cfg, function = _run_with_timeout_in_daemon_thread(
                                        lambda addr=item.function.addr, name=item.function.name: _recover_ranked_binary_function(
                                            project,
                                            addr,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                        thread_name_prefix="ranked-recover",
                                    )
                            else:
                                function_cfg, function = _run_with_timeout_in_daemon_thread(
                                    lambda addr=item.function.addr, name=item.function.name: _recover_ranked_binary_function(
                                        project,
                                        addr,
                                        name,
                                        timeout=recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    ),
                                    timeout=recover_timeout + 1,
                                    thread_name_prefix="ranked-recover",
                                )
                        if result is None:
                            active_item = FunctionWorkItem(
                                index=item.index,
                                function_cfg=function_cfg,
                                function=function,
                            )
                    except (FuturesTimeoutError, TimeoutError):
                        payload = (
                            f"Timed out while recovering {item.function.name} at {item.function.addr:#x} "
                            f"(stage=recovery timeout={recover_timeout}s mode={recovery_mode})."
                        )
                        result = FunctionWorkResult(
                            index=item.index,
                            status="timeout",
                            payload=payload,
                            debug_output=recovery_cache_bypass_debug,
                            function=item.function,
                            function_cfg=None,
                            skip_heavy_fallbacks=True,
                            elapsed=float(recover_timeout),
                            failure_stage=f"recovery:{recovery_mode}",
                        )
                    except Exception as ex:
                        result = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=f"Recovery failed for {item.function.name} at {item.function.addr:#x}: {_describe_exception(ex)}",
                            debug_output="",
                            function=item.function,
                            function_cfg=None,
                            failure_stage=f"recovery:{recovery_mode}",
                        )
                if result is None:
                    if active_item.function_cfg is None:
                        result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=(
                                f"Recovery failed to produce a function CFG for "
                                f"{item.function.name} at {item.function.addr:#x}."
                            ),
                            debug_output="",
                            function=item.function,
                            function_cfg=None,
                            failure_stage=f"recovery:{recovery_mode}",
                        )
                        result = result_map[item.index]
                        if item.index not in emitted_indexes:
                            d, f = _emit_function_result(item, result)
                            decompiled += d
                            failed += f
                            emitted_indexes.add(item.index)
                        continue
                    _block_count, byte_count = _function_complexity(active_item.function)
                    decompile_timeout = adaptive_timeout_model.timeout_for_byte_count(byte_count)
                    decompile_timeout = _effective_decompile_timeout_8616(
                        active_item.function.project,
                        decompile_timeout,
                        block_count=_block_count,
                        byte_count=byte_count,
                    )
                    if (
                        use_serial_fork_per_function
                        and threading.current_thread() is threading.main_thread()
                        and threading.active_count() == 1
                    ):
                        hard_timeout = max(2, decompile_timeout + 2)
                        print(
                            f"[dbg] isolated function worker: start {active_item.function.addr:#x} "
                            f"{active_item.function.name} requested_timeout={decompile_timeout}s hard_timeout={hard_timeout}s"
                        )
                        isolated_start = time.perf_counter()
                        try:
                            result = _run_with_timeout_in_fork(
                                lambda active_item=active_item: _function_work_result_for_fork_ipc(
                                    _run_function_work_item(
                                        active_item,
                                        timeout=decompile_timeout,
                                        api_style=args.api_style,
                                        binary_path=args.binary,
                                        cod_metadata=cod_metadata,
                                        synthetic_globals=synthetic_globals,
                                        lst_metadata=lst_metadata,
                                        enable_structured_simplify=True,
                                        force_isolated_project=force_isolated_function_projects,
                                        allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                                    )
                                ),
                                timeout=hard_timeout,
                            )
                            result = replace(result, function=active_item.function, function_cfg=active_item.function_cfg)
                        except TimeoutError as ex:
                            payload = (
                                f"Timed out while decompiling {item.function.name} at {item.function.addr:#x} "
                                f"(stage=decompilation requested_timeout={decompile_timeout}s hard_timeout={hard_timeout}s): "
                                f"{_describe_exception(ex)}"
                            )
                            result = FunctionWorkResult(
                                index=item.index,
                                status="timeout",
                                payload=payload,
                                debug_output="",
                                function=active_item.function,
                                function_cfg=active_item.function_cfg,
                                skip_heavy_fallbacks=True,
                                elapsed=time.perf_counter() - isolated_start,
                                failure_stage="decompilation",
                            )
                        except Exception as ex:
                            result = FunctionWorkResult(
                                index=item.index,
                                status="error",
                                payload=f"Isolated per-function run failed for {item.function.name} at {item.function.addr:#x}: {_describe_exception(ex)}",
                                debug_output="",
                                function=active_item.function,
                                function_cfg=active_item.function_cfg,
                                elapsed=time.perf_counter() - isolated_start,
                                failure_stage="decompilation",
                            )
                    elif use_serial_fork_per_function:
                        result = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=(
                                f"Isolated per-function fork unavailable for {active_item.function.name} "
                                f"at {active_item.function.addr:#x}: {_fork_unavailable_reason()}. "
                                "Refusing in-process decompilation to preserve the hard timeout."
                            ),
                            debug_output="",
                            function=active_item.function,
                            function_cfg=active_item.function_cfg,
                            skip_heavy_fallbacks=True,
                            failure_stage="decompilation_setup",
                        )
                    else:
                        result = _run_function_work_item(
                            active_item,
                            timeout=decompile_timeout,
                            api_style=args.api_style,
                            binary_path=args.binary,
                            cod_metadata=cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            enable_structured_simplify=True,
                            force_isolated_project=force_isolated_function_projects,
                            allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                        )
                if result is not None and result.status == "ok":
                    byte_count = getattr(result, "byte_count", None)
                    elapsed = getattr(result, "elapsed", None)
                    if isinstance(byte_count, int) and isinstance(elapsed, (int, float)):
                        adaptive_timeout_model.observe_success(byte_count, float(elapsed))
                result_map[item.index] = result
                if result is not None and item.index not in emitted_indexes:
                    d, f = _emit_function_result(item, result,
                        project=project,
                        args=args,
                        lst_metadata=lst_metadata,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        precise_sidecar_regions=precise_sidecar_regions,
                        allow_heavy_fallbacks=allow_heavy_fallbacks,
                        interactive_stdout=interactive_stdout,
                        use_serial_fork_per_function=use_serial_fork_per_function,
                        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                    )
                    decompiled += d
                    failed += f
                    emitted_indexes.add(item.index)
                    if f and args.addr is not None:
                        _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
                        return 2
        attempted = sum(1 for item in function_tasks if result_map.get(item.index) is not None)
        attempted_target = "selected" if args.max_functions <= 0 and args.addr is None else "displayed"
        print(f"/* info: decompilation attempted for {attempted}/{shown_total} {attempted_target} function(s) */")
        for item in function_tasks:
            if item.index in emitted_indexes:
                continue
            result = result_map.get(item.index)
            if result is None:
                continue
            d, f = _emit_function_result(item, result)
            decompiled += d
            failed += f
        for index, snapshot in fallback_tail_validation_by_index.items():
            existing = result_map.get(index)
            if existing is not None:
                result_map[index] = replace(existing, tail_validation=snapshot)
        total_shown = shown_total
        _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
        summary_target = "selected functions" if args.max_functions <= 0 and args.addr is None else "shown functions"
        print(f"\nsummary: decompiled {decompiled}/{total_shown} {summary_target}")
        timed_out = sum(1 for result in result_map.values() if getattr(result, "status", None) == "timeout")
        if timed_out:
            print(f"summary: {timed_out} discovered function(s) timed out during decompilation")
        if failed:
            print(f"summary: {failed} functions fell back to asm/details")
        same_family_retry_stops = sum(getattr(result, "same_family_retry_stops", 0) for result in result_map.values())
        fallback_family_labels = sorted(
            {
                label
                for result in result_map.values()
                for label in getattr(result, "fallback_family_labels", ())
                if label
            },
            key=lambda item: (item.casefold(), item),
        )
        dead_setup_candidates = 0
        dead_setup_pruned = 0
        dead_setup_refused = 0
        dead_setup_escaped = 0
        for result in result_map.values():
            function_obj = getattr(result, "function", None)
            info = getattr(function_obj, "info", None)
            if not isinstance(info, dict):
                continue
            ds = info.get("x86_16_dead_setup")
            if not isinstance(ds, dict):
                continue
            dead_setup_candidates += int(ds.get("dead_setup_candidates", 0) or 0)
            dead_setup_pruned += int(ds.get("dead_setup_pruned", 0) or 0)
            dead_setup_refused += int(ds.get("dead_setup_refused", 0) or 0)
            dead_setup_escaped += int(ds.get("dead_setup_escaped", 0) or 0)
        emit_file_decompilation_summary(
            project,
            lst_metadata,
            shown_total=total_shown,
            decompiled=decompiled,
            failed=failed,
            skipped_signature_labels=skipped_signature_labels,
            same_family_retry_stops=same_family_retry_stops,
            fallback_family_labels=fallback_family_labels,
            dead_setup_candidates=dead_setup_candidates,
            dead_setup_pruned=dead_setup_pruned,
            dead_setup_refused=dead_setup_refused,
            dead_setup_escaped=dead_setup_escaped,
        )
        if _timing_output_enabled():
            _emit_function_timing_summary(function_tasks, result_map)
        return 0 if decompiled else 2
    else:
        decompiled = 0
        failed = 0
        emitted_indexes: set[int] = set()
        allow_isolated_retry_for_parallel_tasks = (
            interactive_stdout
            or args.max_functions <= 0
            or args.addr is not None
        )
        use_prefork_function_pool = (
            force_isolated_function_projects
            and os.name == "posix"
            and threading.current_thread() is threading.main_thread()
            and threading.active_count() == 1
        )
        if use_prefork_function_pool:
            task_by_index = {
                item.index: item
                for item in function_tasks
                if item.function_cfg is not None
            }

            def _prefork_worker(task_index: int) -> FunctionWorkResult:
                item = task_by_index[task_index]
                return _run_function_work_item(
                    item,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
                    lst_metadata=lst_metadata,
                    enable_structured_simplify=True,
                    force_isolated_project=force_isolated_function_projects,
                    allow_isolated_retry=allow_isolated_retry_for_parallel_tasks,
                )

            pool = PreforkJobPool(
                max_workers=workers,
                worker_func=_prefork_worker,
                name_prefix="func-prefork",
            )
            try:
                for task_index, payload in pool.run_unordered(
                    [(item.index, item.index) for item in function_tasks if item.function_cfg is not None]
                ):
                    if task_index is None:
                        continue
                    item = task_by_index[task_index]
                    if isinstance(payload, Exception):
                        result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=str(payload),
                            debug_output="",
                            function=item.function,
                            function_cfg=item.function_cfg,
                            elapsed=float(args.timeout),
                        )
                    else:
                        result_map[item.index] = payload
                    result = result_map.get(item.index)
                    if result is not None and item.index not in emitted_indexes:
                        d, f = _emit_function_result(
                            item,
                            result,
                            project=project,
                            args=args,
                            lst_metadata=lst_metadata,
                            cod_metadata=cod_metadata,
                            synthetic_globals=synthetic_globals,
                            precise_sidecar_regions=precise_sidecar_regions,
                            allow_heavy_fallbacks=allow_heavy_fallbacks,
                            interactive_stdout=interactive_stdout,
                            use_serial_fork_per_function=use_serial_fork_per_function,
                            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                        )
                        decompiled += d
                        failed += f
                        emitted_indexes.add(item.index)
                        if f and args.addr is not None:
                            _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
                            return 2
            finally:
                pool.shutdown()
        else:
            executor = DaemonThreadPoolExecutor(max_workers=workers, thread_name_prefix="func")
            try:
                future_map = {
                    executor.submit(
                        _run_function_work_item,
                        item,
                        timeout=args.timeout,
                        api_style=args.api_style,
                        binary_path=args.binary,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        lst_metadata=lst_metadata,
                        enable_structured_simplify=True,
                        force_isolated_project=force_isolated_function_projects,
                        allow_isolated_retry=allow_isolated_retry_for_parallel_tasks,
                    ): item
                    for item in function_tasks
                    if item.function_cfg is not None
                }
                pending = set(future_map)
                deadlines = {future: time.monotonic() + max(1, args.timeout) for future in future_map}
                has_expired_futures = False
                while pending:
                    done, _ = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
                    if done:
                        for future in done:
                            item = future_map[future]
                            try:
                                result_map[item.index] = future.result()
                            except Exception as ex:
                                result_map[item.index] = FunctionWorkResult(
                                    index=item.index,
                                    status="error",
                                    payload=str(ex),
                                    debug_output="",
                                    function=item.function,
                                    function_cfg=item.function_cfg,
                                )
                            result = result_map.get(item.index)
                            if result is not None and item.index not in emitted_indexes:
                                d, f = _emit_function_result(
                                    item,
                                    result,
                                    project=project,
                                    args=args,
                                    lst_metadata=lst_metadata,
                                    cod_metadata=cod_metadata,
                                    synthetic_globals=synthetic_globals,
                                    precise_sidecar_regions=precise_sidecar_regions,
                                    allow_heavy_fallbacks=allow_heavy_fallbacks,
                                    interactive_stdout=interactive_stdout,
                                    use_serial_fork_per_function=use_serial_fork_per_function,
                                    fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                                )
                                decompiled += d
                                failed += f
                                emitted_indexes.add(item.index)
                                if f and args.addr is not None:
                                    _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
                                    return 2
                            pending.discard(future)
                    now = time.monotonic()
                    expired = [future for future in pending if now >= deadlines[future]]
                    for future in expired:
                        item = future_map[future]
                        if future.done():
                            try:
                                result_map[item.index] = future.result()
                            except Exception as ex:
                                result_map[item.index] = FunctionWorkResult(
                                    index=item.index,
                                    status="error",
                                    payload=str(ex),
                                    debug_output="",
                                    function=item.function,
                                    function_cfg=item.function_cfg,
                                )
                            result = result_map.get(item.index)
                            if result is not None and item.index not in emitted_indexes:
                                d, f = _emit_function_result(
                                    item,
                                    result,
                                    project=project,
                                    args=args,
                                    lst_metadata=lst_metadata,
                                    cod_metadata=cod_metadata,
                                    synthetic_globals=synthetic_globals,
                                    precise_sidecar_regions=precise_sidecar_regions,
                                    allow_heavy_fallbacks=allow_heavy_fallbacks,
                                    interactive_stdout=interactive_stdout,
                                    use_serial_fork_per_function=use_serial_fork_per_function,
                                    fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                                )
                                decompiled += d
                                failed += f
                                emitted_indexes.add(item.index)
                                if f and args.addr is not None:
                                    _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
                                    return 2
                            pending.discard(future)
                            continue
                        result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="timeout",
                            payload=f"Timed out after {args.timeout}s.",
                            debug_output="",
                            function=item.function,
                            function_cfg=item.function_cfg,
                            elapsed=float(args.timeout),
                        )
                        has_expired_futures = True
                        pending.discard(future)
            finally:
                executor.shutdown(wait=not has_expired_futures, cancel_futures=True)

    attempted = sum(1 for item in function_tasks if result_map.get(item.index) is not None)
    attempted_target = "selected" if args.max_functions <= 0 and args.addr is None else "displayed"
    print(f"/* info: decompilation attempted for {attempted}/{shown_total} {attempted_target} function(s) */")
    for item in function_tasks:
        if item.index in emitted_indexes:
            continue
        result = result_map.get(item.index)
        if result is None:
            continue
        d, f = _emit_function_result(item, result)
        decompiled += d
        failed += f
    for index, snapshot in fallback_tail_validation_by_index.items():
        existing = result_map.get(index)
        if existing is not None:
            result_map[index] = replace(existing, tail_validation=snapshot)

    total_shown = shown_total
    _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
    summary_target = "selected functions" if args.max_functions <= 0 and args.addr is None else "shown functions"
    print(f"\nsummary: decompiled {decompiled}/{total_shown} {summary_target}")
    timed_out = sum(1 for result in result_map.values() if getattr(result, "status", None) == "timeout")
    if timed_out:
        print(f"summary: {timed_out} discovered function(s) timed out during decompilation")
    if failed:
        print(f"summary: {failed} functions fell back to asm/details")
    same_family_retry_stops = sum(getattr(result, "same_family_retry_stops", 0) for result in result_map.values())
    fallback_family_labels = sorted(
        {
            label
            for result in result_map.values()
            for label in getattr(result, "fallback_family_labels", ())
            if label
        },
        key=lambda item: (item.casefold(), item),
    )
    dead_setup_candidates = 0
    dead_setup_pruned = 0
    dead_setup_refused = 0
    dead_setup_escaped = 0
    for result in result_map.values():
        function_obj = getattr(result, "function", None)
        info = getattr(function_obj, "info", None)
        if not isinstance(info, dict):
            continue
        ds = info.get("x86_16_dead_setup")
        if not isinstance(ds, dict):
            continue
        dead_setup_candidates += int(ds.get("dead_setup_candidates", 0) or 0)
        dead_setup_pruned += int(ds.get("dead_setup_pruned", 0) or 0)
        dead_setup_refused += int(ds.get("dead_setup_refused", 0) or 0)
        dead_setup_escaped += int(ds.get("dead_setup_escaped", 0) or 0)
    emit_file_decompilation_summary(
        project,
        lst_metadata,
        shown_total=total_shown,
        decompiled=decompiled,
        failed=failed,
        skipped_signature_labels=skipped_signature_labels,
        same_family_retry_stops=same_family_retry_stops,
        fallback_family_labels=fallback_family_labels,
        dead_setup_candidates=dead_setup_candidates,
        dead_setup_pruned=dead_setup_pruned,
        dead_setup_refused=dead_setup_refused,
        dead_setup_escaped=dead_setup_escaped,
    )
    if _timing_output_enabled():
        _emit_function_timing_summary(function_tasks, result_map)
    return 0 if decompiled else 2
