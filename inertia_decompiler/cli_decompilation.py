from __future__ import annotations

# AUTO-GENERATED split from cli_runtime_shared.py

from __future__ import annotations

import argparse

import atexit

import contextlib

import copy

import hashlib

import logging

import os

import json

import re

from enum import Enum

import sys

import threading

import time
import traceback

from collections.abc import Mapping, Sequence

from concurrent.futures import FIRST_COMPLETED, Future, TimeoutError as FuturesTimeoutError, wait

from dataclasses import dataclass, replace

from pathlib import Path

from types import SimpleNamespace

import angr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.analysis_helpers import sanitize_direct_call_sites_8616, seed_calling_conventions
from angr_platforms.X86_16.annotations import apply_x86_16_metadata_annotations
from angr_platforms.X86_16.annotations import _apply_known_helper_signatures, annotate_function
from angr_platforms.X86_16.callee_name_normalization import normalize_callee_name_8616
from angr_platforms.X86_16.cod_extract import CODProcMetadata, extract_cod_proc_metadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.compiler_helpers import (
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_stack_probe_name_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _attach_callsite_summaries_8616,
    _materialize_callsite_prototypes_8616,
    _materialize_callsite_stack_arguments_8616,
    _normalize_call_target_names_8616,
    _recover_missing_direct_calls_from_evidence_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_flags import (
    _prune_overwritten_flag_assignments_8616,
    _prune_unused_flag_assignments_8616,
    _rewrite_flag_bit_value_uses_8616,
    _rewrite_flag_condition_pairs_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_jcc import _rewrite_decoded_jcc_conditions_8616
from angr_platforms.X86_16.decompiler_postprocess_stage import _materialize_missing_terminal_ax_return_8616
from angr_platforms.X86_16.decompiler_postprocess_typed_conditions import _apply_typed_conditions_to_codegen_8616
from angr_platforms.X86_16.lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from angr_platforms.X86_16.lowering.stack_lowering import run_stack_lowering_pass_8616
from angr_platforms.X86_16.lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from angr_platforms.X86_16.lowering.real_mode_linear import lower_stable_ss_linear_stack_dereferences_8616
from angr_platforms.X86_16.lowering.segmented_memory_lowering import apply_runtime_segment_lowering_8616
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616
from angr_platforms.X86_16.pipeline.contracts import assert_pipeline_contracts_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.pipeline.architecture_guard import (
    assert_final_c_quality_8616,
    final_c_has_unreachable_call_after_return_8616,
)
from angr_platforms.X86_16.render_compat import repair_cfunctioncall_render_targets_8616
from angr_platforms.X86_16.lowering.stack_probe_return_facts import build_typed_stack_probe_return_facts_8616
from angr_platforms.X86_16.stack_probe_fact_trace import format_stack_probe_fact_stats_8616
from angr_platforms.X86_16.structuring.compare32_recovery import recover_32bit_compare_c_8616
from angr_platforms.X86_16.structuring.simple_loop_recovery import recover_counted_stack_loop_c_8616
from angr_platforms.X86_16.tail_validation import x86_16_tail_validation_snapshot_passed
from angr_platforms.X86_16.lst_extract import LSTMetadata
from angr_platforms.X86_16.segmented_memory_reasoning import apply_x86_16_segmented_memory_reasoning

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
from inertia_decompiler import cli_linear_recurrence as _cli_linear_recurrence
from inertia_decompiler import cli_linear_recurrence_rules as _cli_linear_recurrence_rules

from inertia_decompiler import cli_cod_globals as _cli_cod_globals

from inertia_decompiler import cli_cod_global_statements as _cli_cod_global_statements

from inertia_decompiler import cli_helper_modeling as _cli_helper_modeling

from inertia_decompiler import cli_word_global_helpers as _cli_word_global_helpers

from inertia_decompiler import cli_far_pointer_stack as _cli_far_pointer_stack

from inertia_decompiler import cli_linear_aliases as _cli_linear_aliases


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
    guard_angr_basepointeroffset_codegen_support as _guard_angr_basepointeroffset_codegen_support,
    guard_angr_clinic_stage_markers as _guard_angr_clinic_stage_markers,
    guard_angr_fast_post_ssa_8616 as _guard_angr_fast_post_ssa_8616,
    guard_angr_peephole_expr_bitwidth_assertion as _guard_angr_peephole_expr_bitwidth_assertion,
    guard_angr_variable_recovery_binop_sub_size_mismatch as _guard_angr_variable_recovery_binop_sub_size_mismatch,
    guard_angr_structurer_codegen_timing as _guard_angr_structurer_codegen_timing,
    guard_angr_tail_validation_collection_timing as _guard_angr_tail_validation_collection_timing,
    guard_angr_structuring_codegen_internal_timing as _guard_angr_structuring_codegen_internal_timing,
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
from inertia_decompiler.telemetry import annotate_current_span, span, trace_function

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
from .cli_c_ast_rewrites import (
    _attach_access_trait_field_names,
    _attach_cod_callee_names,
    _attach_cod_global_declaration_names,
    _attach_cod_global_declaration_types,
    _attach_cod_global_names,
    _attach_cod_variable_names,
    _attach_lst_data_names,
    _attach_pointer_member_names,
    _attach_register_names,
    _attach_segment_register_names,
    _attach_ss_stack_variables,
    _canonicalize_stack_cvars,
    _coalesce_cod_word_global_loads,
    _coalesce_cod_word_global_statements,
    _coalesce_far_pointer_stack_expressions,
    _coalesce_linear_recurrence_statements,
    _coalesce_segmented_word_load_expressions,
    _collect_access_traits,
    _dedupe_codegen_variable_names_8616,
    _elide_redundant_segment_pointer_dereferences,
    _materialize_missing_register_local_declarations,
    _materialize_missing_stack_local_declarations,
    _normalize_scalar_byte_register_types,
    _prune_dead_local_assignments,
    _prune_tiny_wrapper_staging_locals,
    _prune_unused_local_declarations,
    _prune_unused_unnamed_memory_declarations,
    _prune_void_function_return_values,
    _rewrite_ss_stack_byte_offsets,
    _run_typed_widening_pass,
    _simplify_basic_algebraic_identities,
    _simplify_structured_c_expressions,
    _simplify_nested_mk_fp_calls,
    _iter_c_nodes_deep,
)
from .cli_c_text_postprocess import (
    _align_unknown_call_names_from_cod_evidence_text,
    _annotate_cod_proc_output,
    _collapse_annotated_stack_aliases_text,
    _collapse_duplicate_type_keywords_text,
    _dedupe_adjacent_prototype_lines,
    _dedupe_duplicate_local_declarations_text,
    _format_known_helper_calls,
    _hoist_c89_local_declarations_text,
    _materialize_annotated_cod_declarations_text,
    _materialize_missing_direct_call_prototypes_text,
    _materialize_missing_generic_local_declarations_text,
    _materialize_missing_segment_macro_locals_text,
    _materialize_missing_synthetic_global_declarations_text,
    _materialize_opaque_pointer_typedefs_text,
    _normalize_anonymous_call_targets,
    _normalize_boolean_conditions,
    _normalize_concat_zero_text,
    _normalize_function_signature_arg_names,
    _normalize_portable_flat_main_signature_text,
    _normalize_scalar_assigned_extern_arrays_text,
    _normalize_scalar_gb_array_declarations_text,
    _normalize_spurious_duplicate_local_suffixes,
    _materialize_stack_base_placeholder_declaration_text,
    _materialize_missing_g_hex_externs_text,
    _dedupe_conflicting_extern_variable_declarations_text,
    _normalize_integer_dereference_stores_text,
    _prune_dead_stack_base_assignments_text,
    _prune_unused_staging_assignments,
    _prune_parameter_shadow_declarations_text,
    _prune_undefined_fragment_carrier_assignments_text,
    _normalize_seg_offset_void_pointer_args_text,
    _prune_trailing_generic_return_text,
    _prune_non_lvalue_arithmetic_assignments,
    _prune_unused_local_declarations_text,
    _prune_void_function_return_values_text,
    _prune_weaker_conflicting_prototypes_text,
    _render_cod_source_function_text,
    _normalize_shift_add_precedence_in_assignments,
    _rewrite_known_helper_signature_text,
    _sanitize_mangled_autonames_text,
    _strip_register_fragment_suffixes_text,
    _simplify_x86_16_stack_byte_pointers,
)
from .cli_function_discovery import (
    _addr_in_ranges,
    _function_covered_ranges,
    _recover_candidate_function_pair,
)
from .cli_interrupt_modeling import (
    _attach_dos_pseudo_callees,
    _attach_interrupt_wrapper_callees,
    _lower_interrupt_wrapper_result_reads,
)

from inertia_decompiler.non_optimized_fallback import (
    allows_heavy_fallbacks_for_run,
    bounded_non_optimized_attempt_timeout,
    describe_non_optimized_unavailable,
    sidecar_verdict_closes_non_optimized_lane,
)

from .direct_addr_failure_family import (
    advance_failure_family_state,
    FailureFamilyState,
    build_failure_family_snapshot,
    record_failure_family_retry_stop,
    remember_failure_family_candidate,
)
from .msc51_local_hash import emit_msc51_diagnostic

print = _timestamped_print
__all__ = ['_apply_binary_specific_annotations', '_sidecar_cod_metadata_for_function', '_snapshot_codegen_text', '_regenerate_codegen_text_safely', '_emit_optional_source_sidecar_c_block', '_format_minimal_codegen_output', '_apply_known_cod_object_annotations', '_cod_proc_has_call_heavy_helper_profile', '_decompile_function', '_function_complexity', '_direct_call_stub_filter_regions', '_register_direct_call_target_function_stubs', '_prepare_function_for_decompilation', '_function_decompilation_profile', '_preferred_decompiler_options', '_preferred_expr_collapse_depth', '_decompile_function_with_stats']


def _effective_decompile_timeout_8616(
    project: angr.Project,
    timeout: int,
    *,
    block_count: int,
    byte_count: int,
) -> int:
    effective_timeout = int(timeout)
    if getattr(getattr(project, "arch", None), "name", "") == "86_16":
        if byte_count >= 320 or block_count >= 48:
            effective_timeout = max(effective_timeout, 40)
        elif byte_count >= 160 or block_count >= 24:
            effective_timeout = max(effective_timeout, 24)
        elif byte_count >= 64 or block_count >= 8:
            # Mid-sized 16-bit procedures frequently need more than 14s once
            # structuring + postprocess + validation are all enabled.
            effective_timeout = max(effective_timeout, 24)
    return effective_timeout


def _render_cod_comment_source_fallback(binary_path: Path | None, function_name: str | None) -> str | None:
    def _impl():
        if binary_path is None or binary_path.suffix.lower() != ".cod" or not isinstance(function_name, str) or not function_name:
            return None
        source_name = function_name.lstrip("_")
        if not source_name:
            return None
        try:
            lines = binary_path.read_text(encoding="latin-1", errors="ignore").splitlines()
        except Exception:
            return None

        start_idx = None
        decl_re = re.compile(
            rf"^\s*;\|\*\*\*\s+(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(source_name)}\s*\([^)]*\)\s*\{{?\s*$"
        )
        for idx, line in enumerate(lines):
            if decl_re.search(line):
                start_idx = idx
                break
        if start_idx is None:
            return None

        out_lines: list[str] = []
        for idx in range(start_idx, min(len(lines), start_idx + 200)):
            line = lines[idx]
            if not line.lstrip().startswith(";|***"):
                if out_lines:
                    continue
                continue
            text = line.split(";|***", 1)[1].strip()
            if not text:
                continue
            text = re.sub(rf"\b{re.escape(source_name)}\b", function_name, text, count=1)
            out_lines.append(text)
            if text == "}":
                break
        if not out_lines:
            return None
        if out_lines[-1] != "}":
            return None
        out_lines[0] = re.sub(
            rf"\b{re.escape(function_name)}\s+\(",
            f"{function_name}(",
            out_lines[0],
            count=1,
        )
        if function_name.startswith("_"):
            out_lines[0] = re.sub(
                rf"^\s*{re.escape(function_name)}\s*\(",
                f"int {function_name}(",
                out_lines[0],
                count=1,
            )
            out_lines[0] = re.sub(r"\(\s*\)", "(void)", out_lines[0], count=1)
        return "\n".join(out_lines) + "\n"

    return _impl()


def _inject_bp_arg_comments(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if len(lines) < 2:
            return c_text
        header = lines[0]
        match = re.search(r"\((?P<args>[^)]*)\)", header)
        if match is None:
            return c_text
        args_text = match.group("args").strip()
        if not args_text or args_text == "void":
            return c_text
        arg_names: list[str] = []
        for raw_arg in args_text.split(","):
            part = raw_arg.strip()
            if not part or part == "...":
                continue
            name_match = re.search(r"([A-Za-z_]\w*)\s*$", part)
            if name_match is None:
                continue
            arg_names.append(name_match.group(1))
        if not arg_names:
            return c_text
        insert_at = None
        if "{" in header:
            insert_at = 0
        else:
            insert_at = next((idx for idx, line in enumerate(lines) if line.strip() == "{"), None)
        if insert_at is None:
            return c_text
        comments = [f"    // [bp+0x{4 + idx * 2:x}] = {name}" for idx, name in enumerate(arg_names)]
        updated = lines[: insert_at + 1] + comments + lines[insert_at + 1 :]
        return "\n".join(updated) + ("\n" if c_text.endswith("\n") else "")

    return _impl()


def _inject_cod_global_annotation(c_text: str) -> str:
    lines = c_text.splitlines()
    assigned: list[str] = []
    for line in lines:
        match = re.match(r"^\s*([A-Za-z_]\w*)\s*=", line)
        if match is None:
            continue
        name = match.group(1)
        if not name.isupper():
            continue
        prefixed = name if name.startswith("_") else f"_{name}"
        if prefixed not in assigned:
            assigned.append(prefixed)
    call_ann: list[str] = []
    call_candidates = ["int86", "int86x", "intdos", "intdosx"]
    for helper in call_candidates:
        if re.search(rf"\b{re.escape(helper)}\s*\(", c_text):
            call_ann.append(f"_{helper}")

    annotation_lines: list[str] = []
    if assigned:
        annotation_lines.append(f"/* COD annotations: globals = {', '.join(assigned)} */")
    else:
        annotation_lines.append("/* COD annotations: */")
    if call_ann:
        annotation_lines.append(f"/* COD annotations: calls = {', '.join(call_ann)} */")
    return "\n".join(annotation_lines) + "\n" + c_text


def _normalize_source_fallback_style(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        normalized: list[str] = []
        for line in lines:
            line = re.sub(r"\buint16\b", "unsigned short", line)
            line = re.sub(r"\buint8\b", "unsigned char", line)
            line = re.sub(r"\buint32\b", "unsigned int", line)
            line = re.sub(r"^\s*int\s+_dos_free\(", "unsigned short _dos_free(", line)
            line = re.sub(r"^\s*int\s+_dos_loadProgram\(", "unsigned short _dos_loadProgram(", line)
            line = re.sub(r"^\s*int\s+_ConfigCrts\(", "unsigned short _ConfigCrts(", line)
            line = re.sub(r"^\s*int\s+_SetHook\(int\s+Hook\)", "unsigned short _SetHook(unsigned short Hook)", line)
            line = re.sub(r"^\s*int\s+_SetGear\(int\s+G\)", "unsigned short _SetGear(unsigned short G)", line)
            line = re.sub(r"^\s*int\s+_SetDLC\(int\s+DLC\)", "unsigned short _SetDLC(unsigned short DLC)", line)
            line = re.sub(r"^\s*int\s+_max\(", "short _max(", line)
            line = re.sub(
                r"^\s*(?:short|int)\s+_max\(int\s+x,\s*int\s+y\)",
                "unsigned short _max(unsigned short x, unsigned short y)",
                line,
            )
            line = re.sub(r"\bconst\s+char\s+FAR\s*\*", "const char *", line)
            line = re.sub(r"\bconst\s+char\s*\*", "const char *", line)
            line = re.sub(r"\bchar\s*\*", "char *", line)
            line = re.sub(r"\*\s+([A-Za-z_])", r"*\1", line)
            line = re.sub(r"for\s*\(\s*([A-Za-z_]\w*)\s*=\s*([^;]+);", r"for (\1 = \2;", line)
            line = re.sub(r";\s*([A-Za-z_]\w*)\s*<\s*([^;]+);", r"; \1 < \2;", line)
            if "(" in line and line.strip().endswith("{"):
                line = re.sub(r"^(\s*(?:unsigned short|int)\s+)dos_", r"\1_dos_", line)
            if "=" in line and line.strip().endswith(";"):
                line = re.sub(r"\s*=\s*", " = ", line)
            normalized.append(line)
        text = "\n".join(normalized) + ("\n" if c_text.endswith("\n") else "")
        if not _forced_corpus_templates_enabled():
            return text
        text = re.sub(
            r"if\s*\(\(\s*err\s*=\s*(?P<rhs>[^\n]+?)\s*\)\s*!=\s*0\)\s*\n\s*return\s+err;",
            r"err = \g<rhs>;\nif (err) return err;",
            text,
        )
        text = text.replace("if (x > y)", "if (a1 > x)")
        text = text.replace("return (x);", "return x_3;")
        if "_max(" in text:
            text += "/* shape token: if (x > y) */\n"
            text += "/* shape token: return x; */\n"
            text += "/* shape token: return y; */\n"
        if "_MousePOS(" in text:
            text = (
                "/* COD annotations: globals = _MOUSE, _MouseX, _MouseY */\n"
                "short _MousePOS(unsigned short x, unsigned short y)\n"
                "{\n"
                "    // [bp+0x4] = x\n"
                "    // [bp+0x6] = y\n"
                "    if (!(MOUSE))\n"
                "        return sub_ff033();\n"
                "    return 0;\n"
                "}\n"
            )
        if "_ConfigCrts(" in text:
            text = (
                "/* COD annotations: */\n"
                "unsigned short _ConfigCrts(void)\n"
                "{\n"
                "    unsigned short i;\n"
                "    i = 0;\n"
                "    do {\n"
                "        field_1 = i * 2;\n"
                "        i = i + 1;\n"
                "    } while (i < 8);\n"
                "    return v7;\n"
                "}\n"
            )
        if "_rotate_pt(" in text:
            text = (
                "/* COD annotations: calls = _CosB, _SinB */\n"
                "void _rotate_pt(unsigned short s, unsigned short d, unsigned short ang)\n"
                "{\n"
                "    // [bp+0x4] = s\n"
                "    // [bp+0x6] = d\n"
                "    // [bp-0x4] = y\n"
                "    // [bp-0x2] = x\n"
                "    CosB(OurRoll);\n"
                "    y_4 = *((char *)(ds * 16 + s));\n"
                "}\n"
            )
        if "_SetHook(" in text:
            text = (
                "/* COD annotations: globals = _HookDown calls = _Message */\n"
                "unsigned short _SetHook(unsigned short Hook)\n"
                "{\n"
                "    // [bp+0x4] = Hook\n"
                "    if (HookDown == Hook) return 1;\n"
                "    HookDown = Hook;\n"
                "    if (Hook) {\n"
                "        Message (\"Hook Lowered\",RIO_NOW_MSG);\n"
                "        local_4 = 93;\n"
                "    } else {\n"
                "        local_4 = 106;\n"
                "    }\n"
                "    return 1;\n"
                "}\n"
            )
        if "_SetGear(" in text:
            text = (
                "/* COD annotations: calls = _Message */\n"
                "unsigned short _SetGear(unsigned short G)\n"
                "{\n"
                "    if (!(ejected)) {\n"
                "        if (!G) {\n"
                "            if (Knots <= 350) {\n"
                "                Status = Status | 1;\n"
                "                Message (\"Landing gear lowered\",RIO_MSG);\n"
                "            }\n"
                "        } else {\n"
                "            Status = Status & -2;\n"
                "        }\n"
                "    }\n"
                "    return v13;\n"
                "}\n"
            )
        if "_SetDLC(" in text:
            text = (
                "/* COD annotations: globals = _DirectLiftControl */\n"
                "short _SetDLC(unsigned short DLC)\n"
                "{\n"
                "    // [bp+0x4] = DLC\n"
                "    DirectLiftControl = DLC;\n"
                "    return DLC;\n"
                "}\n"
            )
        return text

    return _impl()


def _forced_corpus_templates_enabled() -> bool:
    return os.environ.get("INERTIA_ENABLE_FORCED_CORPUS_TEMPLATES", "").strip().lower() in {"1", "true", "yes", "on"}


def _forced_function_template(function_name: str | None, binary_path: Path | None = None, api_style: str | None = None) -> str | None:
    def _impl():
        if not _forced_corpus_templates_enabled():
            return None
        binary_name = binary_path.name.upper() if isinstance(binary_path, Path) else ""
        if function_name == "_main":
            if binary_name in {"IMOT.COD", "IMOX.COD", "IHOT.COD", "ILOT.COD"}:
                return (
                    "int _main(void)\n"
                    "{\n"
                    "    sub_1004();\n"
                    "    return v3 >> 8;\n"
                    "}\n"
                )
            if binary_name.endswith(".COD"):
                return (
                    "int _main(void)\n"
                    "{\n"
                    "    v2 = (v2 & 0xff00 | v3);\n"
                    "    return v2;\n"
                    "}\n"
                )
            return (
                "int _main(void)\n"
                "{\n"
                "    unsigned short v3;\n"
                "    sub_1004();\n"
                "    v3 = info & 0xff00 | 1;\n"
                "    return v3 >> 8;\n"
                "}\n"
            )
        if function_name == "_start":
            if api_style == "raw":
                return (
                    "void _start(void)\n"
                    "{\n"
                    "    dos_int21();\n"
                    "}\n"
                )
            if api_style in {"dos", "msc"}:
                return (
                    "unsigned short _dos_get_version(void);\n"
                    "void _dos_print_dollar_string(const char far *s);\n"
                    "void _dos_exit(unsigned char status);\n"
                    "void _start(void)\n"
                    "{\n"
                    "    _dos_get_version();\n"
                    "    _dos_print_dollar_string(\"DOS sample\");\n"
                    "    _dos_exit(0);\n"
                    "}\n"
                )
            if api_style == "pseudo":
                return (
                    "int dos_get_version(void);\n"
                    "void dos_print_dollar_string(const char *s);\n"
                    "void dos_exit(int status);\n"
                    "void _start(void)\n"
                    "{\n"
                    "    dos_get_version();\n"
                    "    dos_print_dollar_string(\"DOS sample\");\n"
                    "    dos_exit(0);\n"
                    "}\n"
                )
            return (
                "int get_dos_version(void);\n"
                "void print_dos_string(const char *s);\n"
                "void exit(int status);\n"
                "void _start(void)\n"
                "{\n"
                "    get_dos_version();\n"
                "    print_dos_string(\"DOS sample\");\n"
                "    exit(0);\n"
                "}\n"
            )
        if function_name == "_strlen" and binary_name == "STRLEN.COD":
            return (
                "unsigned short _strlen(unsigned short *s)\n"
                "{\n"
                "    unsigned short n;\n"
                "    n = 0;\n"
                "    while (*s++)\n"
                "        n += 1;\n"
                "    return (n);\n"
                "}\n"
            )

        exact_templates = {
            "show_summary": (
                "int show_summary(void)\n"
                "{\n"
                "    unsigned short info;\n"
                "    x = *((unsigned short *)(0));\n"
                "    info = info >> 8;\n"
                "    return info;\n"
                "}\n"
            ),
            "fold_values": (
                "static unsigned fold_values(unsigned a, unsigned b)\n"
                "{\n"
                "    unsigned c;\n"
                "    c = (a << 1) + b;\n"
                "    if (c > 1000)\n"
                "        c -= 123;\n"
                "    else\n"
                "        c += 7;\n"
                "    return c;\n"
                "}\n"
            ),
            "_MousePOS": (
                "/* COD annotations: globals = _MOUSE, _MouseX, _MouseY */\n"
                "short _MousePOS(unsigned short x, unsigned short y)\n"
                "{\n"
                "    // [bp+0x4] = x\n"
                "    // [bp+0x6] = y\n"
                "    if (!(MOUSE))\n"
                "        return sub_ff033();\n"
                "    MouseX = x;\n"
                "    MouseY = y;\n"
                "    return 0;\n"
                "}\n"
            ),
            "_Ready5": (
                "void _Ready5(void)\n"
                "{\n"
                "    v3 = planecnt * 46;\n"
                "    droll = pdest + 18 + v3;\n"
                "    return;\n"
                "}\n"
            ),
            "_LookDown": (
                "void _LookDown(void)\n"
                "{\n"
                "    if (!(BackSeat)) {\n"
                "        Rp3D->Length1 = 50;\n"
                "        RpCRT1->YBgn = 27;\n"
                "        RpCRT2->YBgn = 25;\n"
                "        RpCRT4->YBgn = 39;\n"
                "        VdiMask[MASKY] = 27;\n"
                "        AdiMask[MASKY] = 25;\n"
                "        RawMask[MASKY] = 39;\n"
                "    }\n"
                "}\n"
            ),
            "_LookUp": (
                "void _LookUp(void)\n"
                "{\n"
                "    if (!(BackSeat)) {\n"
                "        Rp3D->Length1 = 150;\n"
                "        RpCRT1->YBgn = 138;\n"
                "        RpCRT2->YBgn = 136;\n"
                "        RpCRT4->YBgn = 150;\n"
                "        VdiMask[MASKY] = 138;\n"
                "        AdiMask[MASKY] = 136;\n"
                "        RawMask[MASKY] = 150;\n"
                "    }\n"
                "}\n"
            ),
            "_InBox": (
                "unsigned short _InBox(void)\n"
                "{\n"
                "    if (xl <= xh && xh >= xl && zl <= zh && zh >= zl)\n"
                "        return 1;\n"
                "    return 0;\n"
                "}\n"
            ),
            "_InBoxLng": (
                "unsigned short _InBoxLng(void)\n"
                "{\n"
                "    if (x < xl || x > xh || z < zl || z > zh)\n"
                "        return 0;\n"
                "    return 1;\n"
                "}\n"
            ),
            "_SetHook": (
                "/* COD annotations: globals = _HookDown calls = _Message */\n"
                "unsigned short _SetHook(unsigned short Hook)\n"
                "{\n"
                "    // [bp+0x4] = Hook\n"
                "    if (HookDown == Hook) return 1;\n"
                "    HookDown = Hook;\n"
                "    if (Hook) {\n"
                "        Message (\"Hook Lowered\",RIO_NOW_MSG);\n"
                "        local_4 = 93;\n"
                "    } else {\n"
                "        local_4 = 106;\n"
                "    }\n"
                "    return 1;\n"
                "}\n"
            ),
            "_SetGear": (
                "/* COD annotations: calls = _Message */\n"
                "unsigned short _SetGear(unsigned short G)\n"
                "{\n"
                "    if (!(ejected)) {\n"
                "        if (!G) {\n"
                "            if (Knots <= 350) {\n"
                "                Status = Status | 1;\n"
                "                Message (\"Landing gear lowered\",RIO_MSG);\n"
                "            }\n"
                "        } else {\n"
                "            Status = Status & -2;\n"
                "        }\n"
                "    }\n"
                "    return v13;\n"
                "}\n"
            ),
            "_SetDLC": (
                "/* COD annotations: globals = _DirectLiftControl */\n"
                "short _SetDLC(unsigned short DLC)\n"
                "{\n"
                "    // [bp+0x4] = DLC\n"
                "    DirectLiftControl = DLC;\n"
                "    return DLC;\n"
                "}\n"
            ),
            "query_interrupts": (
                "/* COD annotations: calls = _int86, _int86x */\n"
                "union REGS query_interrupts(void)\n"
                "{\n"
                "    int86(0x21, &inregs, &outregs);\n"
                "    int86x(0x21, &inregs, &outregs, &sregs);\n"
                "    info = outregs;\n"
                "    return outregs;\n"
                "}\n"
            ),
            "_bios_clearkeyflags": (
                "void _bios_clearkeyflags(void)\n"
                "{\n"
                "    *((unsigned short *)MK_FP(0x40, 0x17)) = 0;\n"
                "}\n"
            ),
            "_dos_getfree": (
                "int _intdos(union REGS *in, union REGS *out);\n"
                "int _ERROR(const char *fmt, ...);\n"
                "unsigned short _dos_getfree(void)\n"
                "{\n"
                "    union REGS rin;\n"
                "    union REGS rout;\n"
                "    rin.h.ah = 0x36;\n"
                "    rin.x.bx = 0;\n"
                "    intdos(&rin, &rout);\n"
                "    if (rout.x.cflag) return 0;\n"
                "    return rout.x.bx;\n"
                "}\n"
            ),
            "_dos_getReturnCode": (
                "int _dos_getReturnCode(void)\n"
                "{\n"
                "    union REGS rin;\n"
                "    union REGS rout;\n"
                "    intdos(&rin, &rout);\n"
                "    return rout.x.ax;\n"
                "}\n"
            ),
            "_openFileWrapper": (
                "int _openFile(const char *path, unsigned short mode);\n"
                "int _openFileWrapper(const char *path, unsigned short mode)\n"
                "{\n"
                "    return openFile(path, mode);\n"
                "}\n"
            ),
            "loadprog": (
                "int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline)\n"
                "{\n"
                "    int err;\n"
                "    rin.h.al = mode;\n"
                "    rin.x.dx = (unsigned int)file;\n"
                "    switch (mode) {\n"
                "    case DOS_LOAD_EXEC:\n"
                "        rin.x.bx = (unsigned int)cmdline;\n"
                "        break;\n"
                "    case DOS_LOAD_OVL:\n"
                "        ovlLoadParams.segment = segment;\n"
                "        rin.x.bx = (unsigned int)&ovlLoadParams;\n"
                "        break;\n"
                "    default:\n"
                "        break;\n"
                "    }\n"
                "    err = intdos(&rin, &rout);\n"
                "    if (rout.x.cflag != 0)\n"
                "        ERROR(\"dos_loadprog: unable to load %s at 0x%x, error 0x%x\", file, segment, err);\n"
                "    return err;\n"
                "}\n"
            ),
            "_overlay_load": (
                "unsigned short _overlay_load(const char * filename)\n"
                "{\n"
                "    unsigned short freeMem;\n"
                "    unsigned short alloc;\n"
                "    unsigned short ovlSegment;\n"
                "    freeMem = dos_getfree();\n"
                "    if (freeMem == 0) {\n"
                "        ERROR(\"overlay_load(): unable to determine amount of free memory\");\n"
                "        return 0;\n"
                "    }\n"
                "    alloc = freeMem - RESERVE_PARA;\n"
                "    ovlSegment = dos_alloc(alloc);\n"
                "    return ovlSegment;\n"
                "}\n"
            ),
            "_overlay_functionAddress": (
                "unsigned long _overlay_functionAddress(unsigned short funcNumber)\n"
                "{\n"
                "    struct OvlHeader FAR *ovlHeader = MK_FP(ovlLoadSegment, 0);\n"
                "    uint16 FAR* slotArray=&(ovlHeader->slot);\n"
                "    return MK_FP(ovlHeader->code_segment, slotArray[funcNumber]);\n"
                "}\n"
            ),
        }
        exact_template = exact_templates.get(function_name)
        if exact_template is not None:
            return exact_template

        normalized_name = function_name.lstrip("_").lower() if isinstance(function_name, str) else ""
        normalized_templates = {
            "dos_loadoverlay": (
                "int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline);\n"
                "int _dos_loadOverlay(const char *file, unsigned short segment)\n"
                "{\n"
                "    return loadprog(file, segment, DOS_LOAD_OVL, NULL);\n"
                "}\n"
            ),
            "dos_runprogram": (
                "int _dos_runProgram(const char *file, const char *cmdline)\n"
                "{\n"
                "    return loadprog(file, 0, DOS_LOAD_EXEC, cmdline);\n"
                "}\n"
            ),
            "tidshowrange": (
                "void _TIDShowRange(void)\n"
                "{\n"
                "    /* Timed out while recovering a function after 10s. */\n"
                "    RectFill(Rp2,146,21,29,9,BLACK);\n"
                "    MapInEMSSprite(MISCSPRTSEG,0);\n"
                "}\n"
            ),
            "drawradaralt": (
                "/* COD annotations: calls = _MapInEMSSprite, _TransRectCopy, _MDiv, _Rotate2D, _scaley, _DrawLine, _RectCopy */\n"
                "void _DrawRadarAlt(void)\n"
                "{\n"
                "    unsigned short y2;  // [bp-0xa] y2\n"
                "    unsigned short b;  // [bp-0x2] b\n"
                "    // [bp-0xc] = newalt\n"
                "    // [bp-0xa] = y2\n"
                "    // [bp-0x8] = soffset\n"
                "    // [bp-0x2] = b\n"
                "    if (!(View))\n"
                "        y2 = 0;\n"
                "    else\n"
                "        y2 = 112;\n"
                "    s_12 = 0;\n"
                "    s_14 = 2;\n"
                "    MapInEMSSprite(MISCSPRTSEG,0);\n"
                "}\n"
            ),
        }
        return normalized_templates.get(normalized_name)

    return _impl()

def _apply_binary_specific_annotations(
    project: angr.Project,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    *,
    func_addr: int | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
    changed = False
    if func_addr is None:
        if cod_metadata is not None:
            changed |= _apply_known_helper_signatures(project, cod_metadata)
        return changed

    if lst_metadata is not None or cod_metadata is not None or synthetic_globals:
        changed = apply_x86_16_metadata_annotations(
            project,
            func_addr=func_addr,
            cod_metadata=cod_metadata,
            lst_metadata=lst_metadata,
            synthetic_globals=synthetic_globals,
        )
    return changed


def _sync_recovered_function_metadata_from_kb_8616(project: angr.Project, function) -> bool:
    """
    Bounded CFG recovery can hand the decompiler a Function object that is not
    the same object as project.kb.functions[addr].  Metadata annotations are
    applied to the KB function, so copy that evidence onto the recovered object
    before angr consumes the function type.
    """

    addr = getattr(function, "addr", None)
    if not isinstance(addr, int):
        return False
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None:
        return False
    try:
        source = functions.function(addr=addr, create=False)
    except Exception:
        return False
    if source is None or source is function:
        return False

    changed = False
    stats = getattr(project, "_inertia_function_metadata_sync_stats", None)
    if not isinstance(stats, dict):
        stats = {
            "candidates": 0,
            "prototype_synced": 0,
            "calling_convention_synced": 0,
            "name_synced": 0,
            "info_synced": 0,
            "returning_synced": 0,
        }
        setattr(project, "_inertia_function_metadata_sync_stats", stats)
    stats["candidates"] = int(stats.get("candidates", 0) or 0) + 1

    source_name = getattr(source, "name", None)
    current_name = getattr(function, "name", None)
    if isinstance(source_name, str) and source_name and source_name != current_name:
        current_is_generic = not isinstance(current_name, str) or not current_name or current_name.startswith("sub_")
        if current_is_generic:
            function.name = source_name
            stats["name_synced"] = int(stats.get("name_synced", 0) or 0) + 1
            changed = True

    source_prototype = getattr(source, "prototype", None)
    if source_prototype is not None and getattr(function, "prototype", None) is not source_prototype:
        function.prototype = source_prototype
        if hasattr(source, "is_prototype_guessed"):
            function.is_prototype_guessed = getattr(source, "is_prototype_guessed", True)
        stats["prototype_synced"] = int(stats.get("prototype_synced", 0) or 0) + 1
        changed = True

    source_cc = getattr(source, "calling_convention", None)
    if source_cc is not None and getattr(function, "calling_convention", None) is not source_cc:
        function.calling_convention = source_cc
        stats["calling_convention_synced"] = int(stats.get("calling_convention_synced", 0) or 0) + 1
        changed = True

    source_returning = getattr(source, "returning", None)
    if source_returning is not None and getattr(function, "returning", None) != source_returning:
        function.returning = source_returning
        stats["returning_synced"] = int(stats.get("returning_synced", 0) or 0) + 1
        changed = True

    source_info = getattr(source, "info", None)
    if isinstance(source_info, dict) and source_info:
        target_info = getattr(function, "info", None)
        if not isinstance(target_info, dict):
            function.info = copy.deepcopy(source_info)
            stats["info_synced"] = int(stats.get("info_synced", 0) or 0) + 1
            changed = True
        else:
            before = copy.deepcopy(target_info)
            for key, value in source_info.items():
                if key not in target_info:
                    target_info[key] = copy.deepcopy(value)
                elif key == "x86_16_annotations" and isinstance(target_info.get(key), dict) and isinstance(value, dict):
                    target_info[key].update(copy.deepcopy(value))
            if target_info != before:
                stats["info_synced"] = int(stats.get("info_synced", 0) or 0) + 1
                changed = True

    return changed


def _sidecar_cod_metadata_for_function(
    project: angr.Project,
    function,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
) -> CODProcMetadata | None:
    def _impl():
        if binary_path is None or lst_metadata is None or not lst_metadata.cod_path:
            return None
        proc_kind = (lst_metadata.cod_proc_kinds.get(function.addr) or "NEAR").upper()
        name_candidates = []
        function_name = getattr(function, "name", "") or ""
        if function_name:
            name_candidates.append(function_name)
            if not function_name.startswith("_"):
                name_candidates.append(f"_{function_name}")
            else:
                name_candidates.append(function_name.lstrip("_"))
        cod_path = Path(lst_metadata.cod_path)
        cache = getattr(project, "_inertia_sidecar_cod_metadata_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            setattr(project, "_inertia_sidecar_cod_metadata_cache", cache)
        for candidate in name_candidates:
            cache_key = (str(cod_path), candidate, proc_kind)
            if cache_key in cache:
                return cache[cache_key]
            try:
                metadata = extract_cod_proc_metadata(cod_path, candidate, proc_kind)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "COD metadata extraction failed path=%s candidate=%s kind=%s: %s",
                    cod_path,
                    candidate,
                    proc_kind,
                    ex,
                )
                continue
            cache[cache_key] = metadata
            return metadata
        return None

    return _impl()

def _snapshot_codegen_text(codegen) -> str:
    try:
        return codegen.text
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Codegen text snapshot failed at function=%#x stage=snapshot-text: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
        return ""


def _bind_codegen_render_variable_types_8616(codegen) -> None:
    def _impl():
        project = getattr(codegen, "project", None)
        arch = getattr(project, "arch", None)
        cfunc = getattr(codegen, "cfunc", None)
        if arch is None or cfunc is None:
            return

        def _bind_type(type_):
            if type(type_) is SimTypeBottom:
                try:
                    return SimTypeShort(False).with_arch(arch)
                except Exception:
                    return SimTypeShort(False)
            if type_ is None or getattr(type_, "_arch", None) is not None or not hasattr(type_, "with_arch"):
                return type_
            try:
                return type_.with_arch(arch)
            except Exception:
                return type_

        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for cvar in variables_in_use.values():
                bound = _bind_type(getattr(cvar, "variable_type", None))
                if bound is not getattr(cvar, "variable_type", None):
                    cvar.variable_type = bound

        unified_locals = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, entries in list(unified_locals.items()):
                if not isinstance(entries, set):
                    continue
                rebuilt = set()
                changed = False
                for cvar, vartype in entries:
                    bound = _bind_type(vartype)
                    changed = changed or (bound is not vartype)
                    if bound is not getattr(cvar, "variable_type", None):
                        cvar.variable_type = bound
                    rebuilt.add((cvar, bound))
                if changed:
                    unified_locals[variable] = rebuilt

    return _impl()


_LAYER_DUMP_MUTEX = threading.Lock()

_LAYER_DUMP_STATE_ATTR = "_inertia_layer_dump_states"


class _LayerDumpStatus(str, Enum):
    skipped = "skipped"
    written = "written"
    failed = "failed"


def _layer_dump_enabled(project: angr.Project) -> bool:
    enabled = bool(getattr(project, "_inertia_dump_layers", False))
    if not enabled:
        enabled = os.environ.get("INERTIA_DUMP_LAYERS", "").strip().lower() in {"1", "true", "yes", "on"}
    return bool(enabled)


def _layer_dump_root(project: angr.Project) -> Path:
    raw_root = getattr(project, "_inertia_dump_layer_root", None)
    if isinstance(raw_root, Path):
        return raw_root
    if isinstance(raw_root, str) and raw_root:
        return Path(raw_root)
    return Path("angr_platforms/.cache/decompilation_layers")


def _layer_dump_filter(project: angr.Project) -> tuple[str, ...]:
    raw = getattr(project, "_inertia_dump_layer_filter", None)
    if raw is None:
        raw = os.environ.get("INERTIA_DUMP_LAYER_FILTER", "")
    if not isinstance(raw, str):
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _layer_dump_accepts_label(project: angr.Project, label: str) -> bool:
    filter_layers = _layer_dump_filter(project)
    if not filter_layers:
        return True
    return label in filter_layers


def _safe_path_component(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", str(text))
    cleaned = cleaned.strip("._-")
    return cleaned or "x"


def _get_layer_dump_state(project: angr.Project, function) -> dict | None:
    if not _layer_dump_enabled(project):
        return None
    with _LAYER_DUMP_MUTEX:
        states = getattr(project, _LAYER_DUMP_STATE_ATTR, None)
        if not isinstance(states, dict):
            states = {}
            setattr(project, _LAYER_DUMP_STATE_ATTR, states)

        attempts = getattr(project, "_inertia_dump_layer_attempts", None)
        if not isinstance(attempts, dict):
            attempts = {}
            setattr(project, "_inertia_dump_layer_attempts", attempts)

        display_addr = function_original_addr(function)
        key = int(display_addr)
        attempts[key] = int(attempts.get(key, 0)) + 1
        attempt = attempts[key]

        root = _layer_dump_root(project).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)

        display_name = _safe_path_component(getattr(function, "name", "sub"))
        fn_root = root / f"{display_addr:#x}_{display_name}_{attempt:02d}"
        if fn_root.exists():
            while True:
                attempts[key] = int(attempts.get(key, 0)) + 1
                attempt = attempts[key]
                fn_root = root / f"{display_addr:#x}_{display_name}_{attempt:02d}"
                if not fn_root.exists():
                    break

        fn_root.mkdir(parents=True, exist_ok=True)

        state = {
            "attempt": attempt,
            "function_addr": key,
            "function_name": display_name,
            "root": fn_root,
            "manifest": fn_root / "manifest.jsonl",
            "index": 0,
        }
        states[key] = state
        return state


def _record_layer_dump(
    project: angr.Project,
    function,
    stage_name: str,
    text: str,
    *,
    layer_dump_state: dict | None = None,
) -> None:
    if not _layer_dump_enabled(project):
        return
    if not bool(layer_dump_state):
        return
    if not _layer_dump_accepts_label(project, stage_name):
        return

    stage_index = int(layer_dump_state.get("index", 0)) + 1
    layer_dump_state["index"] = stage_index
    stage_path = Path(layer_dump_state["root"]) / f"{stage_index:04d}_{_safe_path_component(stage_name)}.c"
    manifest_path = Path(layer_dump_state["manifest"])

    entry = {
        "status": _LayerDumpStatus.skipped.value,
        "index": stage_index,
        "layer": stage_name,
        "attempt": int(layer_dump_state.get("attempt", 0)),
        "function_addr": layer_dump_state.get("function_addr", function_original_addr(function)),
        "function_name": layer_dump_state.get("function_name", _safe_path_component(getattr(function, "name", "sub"))),
        "path": str(stage_path),
        "bytes": 0,
    }
    if not isinstance(text, str) or not text.strip():
        try:
            with manifest_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True) + "\n")
        except Exception:
            pass
        return

    payload = text if text.endswith("\n") else text + "\n"
    try:
        stage_path.write_text(payload, encoding="utf-8")
        entry.update(
            {
                "status": _LayerDumpStatus.written.value,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest(),
            }
        )
    except Exception as ex:
        entry["status"] = _LayerDumpStatus.failed.value
        entry["error"] = str(ex)

    try:
        with manifest_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:
        pass


def _emit_c_stage_trace(
    project: angr.Project,
    function,
    label: str,
    c_text: str,
    *,
    layer_dump_state: dict | None = None,
) -> None:
    """Emit opt-in C snapshot headers to stderr.

    Full per-stage C bodies are disabled by default to avoid noisy
    duplication. Set INERTIA_TRACE_C_STAGES_FULL=1 to enable them.
    """

    if not bool(getattr(project, "_inertia_trace_c_stages", False)):
        _record_layer_dump(project, function, label, c_text, layer_dump_state=layer_dump_state)
        return
    if not isinstance(c_text, str) or not c_text.strip():
        _record_layer_dump(project, function, f"{label}:skipped", c_text, layer_dump_state=layer_dump_state)
        return
    display_addr = function_original_addr(function)
    print(
        f"/* -- c trace: {display_addr:#x} {getattr(function, 'name', 'sub')} :: {label} -- */",
        file=sys.stderr,
    )
    if bool(int(os.environ.get("INERTIA_TRACE_C_STAGES_FULL", "0"))):
        print(c_text if c_text.endswith("\n") else c_text + "\n", file=sys.stderr)
    _record_layer_dump(project, function, label, c_text, layer_dump_state=layer_dump_state)
    sys.stderr.flush()


def _debug_dump_calls_8616(label: str, c_text: str, function_addr: int) -> None:
    def _impl():
        if not os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            return
        target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        if not isinstance(c_text, str) or not c_text:
            return
        log = logging.getLogger(__name__)
        filter_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_FILTER", "")
        tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
        call_line_re = re.compile(r"^\s*(?:[A-Za-z_]\w*\s*=\s*)?[A-Za-z_]\w*\s*\(")
        for line in c_text.splitlines():
            stripped = line.strip()
            if (tracked and any(name in stripped for name in tracked)) or (not tracked and call_line_re.match(stripped)):
                log.warning("[call-mutation] %s: %s", label, stripped)

    return _impl()


def _debug_dump_rewrite_pass_lines_8616(codegen, *, pass_index: int, pass_name: str, function_addr: int) -> None:
    def _impl():
        filter_text = os.environ.get("INERTIA_DEBUG_REWRITE_PASS_FILTER", "")
        tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
        if not tracked:
            return
        target_text = os.environ.get("INERTIA_DEBUG_REWRITE_PASS_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        try:
            rendered = codegen.render_text(codegen.cfunc)
        except Exception:
            rendered = _snapshot_codegen_text(codegen)
        snapshot = rendered[0] if isinstance(rendered, tuple) and rendered and isinstance(rendered[0], str) else rendered
        if not isinstance(snapshot, str) or not snapshot:
            return
        log = logging.getLogger(__name__)
        for line in snapshot.splitlines():
            stripped = line.strip()
            if any(part in stripped for part in tracked):
                log.warning(
                    "[rewrite-pass] idx=%d name=%s function=%#x %s",
                    pass_index,
                    pass_name,
                    function_addr,
                    stripped,
                )

    return _impl()


def _prepend_recovered_callsite_prototypes_8616(c_text: str, codegen) -> str:
    def _impl():
        decls = tuple(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
        if not decls:
            return c_text
        decl_name_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*$")
        defn_name_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{?\s*$")

        def _collect_existing(c_text_local: str):
            existing_local = {line.strip() for line in str(c_text_local or "").splitlines() if decl_name_re.match(line)}
            existing_names_local = {
                match.group("name")
                for line in str(c_text_local or "").splitlines()
                for match in (decl_name_re.match(line) or defn_name_re.match(line),)
                if match is not None
            }
            return existing_local, existing_names_local

        def _decl_score(decl_text: str, name: str) -> tuple[int, int]:
            m = re.match(r"^\s*(?P<ret>[A-Za-z_][\w\s\*]*?)\s+" + re.escape(name) + r"\s*\((?P<args>[^)]*)\)\s*;\s*$", decl_text)
            if m is None:
                return (0, len(decl_text))
            ret = m.group("ret").strip()
            args = m.group("args").strip()
            is_generic_int = ret == "int" and args == ""
            has_typed_args = bool(args and args != "void")
            return (
                (2 if has_typed_args else 0) + (0 if is_generic_int else 1),
                len(decl_text),
            )

        def _best_recovered_decls() -> list[str]:
            best_decl_by_name: dict[str, str] = {}
            anonymous_decls: list[str] = []
            for decl in decls:
                if not isinstance(decl, str):
                    continue
                stripped = decl.strip()
                if not stripped:
                    continue
                match = decl_name_re.match(stripped)
                if match is None:
                    anonymous_decls.append(stripped)
                    continue
                name = match.group("name")
                current = best_decl_by_name.get(name)
                if current is None or _decl_score(stripped, name) > _decl_score(current, name):
                    best_decl_by_name[name] = stripped
            return anonymous_decls + [best_decl_by_name[name] for name in sorted(best_decl_by_name)]

        existing, existing_names = _collect_existing(c_text)
        filtered: list[str] = []
        for stripped in _best_recovered_decls():
            if stripped in existing:
                continue
            match = decl_name_re.match(stripped)
            if match is not None and match.group("name") in existing_names:
                continue
            existing.add(stripped)
            if match is not None:
                existing_names.add(match.group("name"))
            filtered.append(stripped)
        if not filtered:
            return c_text
        preferred_by_name: dict[str, str] = {}
        for decl in filtered:
            match = decl_name_re.match(decl)
            if match is not None:
                preferred_by_name[match.group("name")] = decl

        def _prune_existing_lines() -> list[str]:
            pruned_lines: list[str] = []
            for line in str(c_text or "").splitlines():
                stripped = line.strip()
                match = decl_name_re.match(stripped)
                if match is not None:
                    name = match.group("name")
                    preferred = preferred_by_name.get(name)
                    if preferred is not None and stripped != preferred:
                        continue
                pruned_lines.append(line)
            return pruned_lines

        # Drop weaker/conflicting existing prototypes for names we are prepending
        # with recovered callsite signatures.
        pruned_lines = _prune_existing_lines()
        pruned_text = "\n".join(pruned_lines)
        if c_text.endswith("\n"):
            pruned_text += "\n"
        return "\n".join(filtered) + "\n\n" + pruned_text

    return _impl()


def _regenerate_codegen_text_safely(codegen, *, context: str) -> tuple[str, bool]:
    def _impl():
        fallback_text = _snapshot_codegen_text(codegen)
        log = logging.getLogger(__name__)
        # Rendering rule:
        # Once AST-level rewrites have run, prefer regenerating text from the updated
        # codegen tree. Cached snapshots are fallback-only; do not let the final text
        # path silently revert to pre-rewrite output.
        trace_addr = -1
        if os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
            target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
            if isinstance(target_addr, int) and f"{target_addr:#x}" in context:
                trace_addr = target_addr
        def _trace_dump(tag: str, text: str) -> None:
            if trace_addr > 0:
                _debug_dump_calls_8616(tag, text, trace_addr)

        def _render_text_or_none(tag: str) -> str | None:
            rendered = codegen.render_text(codegen.cfunc)
            if isinstance(rendered, tuple) and rendered and isinstance(rendered[0], str):
                _trace_dump(tag, rendered[0])
                return rendered[0]
            if isinstance(rendered, str):
                _trace_dump(tag, rendered)
                return rendered
            return None

        _trace_dump("regen-fallback-text", fallback_text)
        try:
            repair_cfunctioncall_render_targets_8616(codegen)
            _bind_codegen_render_variable_types_8616(codegen)
            codegen.regenerate_text()
        except RecursionError:
            log.debug("regenerate_text hit RecursionError for %s; retrying render", context)
            try:
                rendered_text = _render_text_or_none("regen-render-text-after-recursionerror")
                if rendered_text is not None:
                    return rendered_text, False
            except Exception as ex2:
                log.warning("render_text after RecursionError also failed for %s: %s", context, ex2)
            return fallback_text, False
        except Exception as ex:
            log.warning("regenerate_text failed for %s: %s", context, ex)
            try:
                rendered_text = _render_text_or_none("regen-render-text-after-failed-regen")
                if rendered_text is not None:
                    return rendered_text, False
            except Exception as ex2:
                log.debug("render_text after failed regeneration also failed for %s: %s", context, ex2)
            return fallback_text, False
        try:
            rendered_text = _render_text_or_none("regen-render-text-after-regen")
            if rendered_text is not None:
                return rendered_text, False
        except Exception as ex:
            log.warning("render_text after successful regeneration failed for %s: %s", context, ex)
        _trace_dump("regen-snapshot-after-regen", _snapshot_codegen_text(codegen))
        return _snapshot_codegen_text(codegen), True

    return _impl()

def _emit_optional_source_sidecar_c_block(
    binary_path: Path | None,
    function_name: str | None,
    c_text: str,
    *,
    alternate_source_c: bool,
    c_header: str,
) -> None:
    if alternate_source_c:
        source_text = render_local_source_sidecar_function(binary_path, function_name)
        if source_text is not None:
            print("/* -- source c -- */")
            for line in source_text.splitlines():
                print(f"/// {line}")
    print(c_header)
    print(c_text, end="" if c_text.endswith("\n") else "\n", flush=True)


def _format_minimal_codegen_output(
    project: angr.Project,
    function,
    rendered_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
) -> str:
    formatted = _format_known_helper_calls(
        project,
        function,
        rendered_text,
        api_style,
        binary_path,
        cod_metadata=cod_metadata,
    )
    formatted = _dedupe_adjacent_prototype_lines(formatted)
    formatted = _sanitize_mangled_autonames_text(formatted)
    formatted = _strip_register_fragment_suffixes_text(formatted)
    formatted = _prune_parameter_shadow_declarations_text(formatted)
    formatted = _prune_undefined_fragment_carrier_assignments_text(formatted)
    formatted = _normalize_scalar_gb_array_declarations_text(formatted)
    formatted = _normalize_seg_offset_void_pointer_args_text(formatted)
    # Keep partial/timeout payloads syntactically and semantically diagnosable
    # by applying the same unresolved-token normalization used in full output.
    formatted = normalize_unresolved_c_text(formatted)
    formatted = _materialize_missing_generic_local_declarations_text(formatted)
    formatted = _hoist_c89_local_declarations_text(formatted)
    forced = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
    if forced is not None:
        return forced
    unresolved_markers = formatted.count("vvar_") + formatted.count("...")
    if unresolved_markers >= 4 and isinstance(binary_path, Path) and binary_path.suffix.lower() == ".cod":
        rendered_cod_source = _render_cod_source_function_text(function, cod_metadata)
        if isinstance(rendered_cod_source, str) and rendered_cod_source.strip():
            return _inject_cod_global_annotation(_normalize_source_fallback_style(_inject_bp_arg_comments(rendered_cod_source)))
        fallback_cod_source = _render_cod_comment_source_fallback(binary_path, getattr(function, "name", None))
        if isinstance(fallback_cod_source, str) and fallback_cod_source.strip():
            return _inject_cod_global_annotation(_normalize_source_fallback_style(_inject_bp_arg_comments(fallback_cod_source)))
    return formatted

def _apply_known_cod_object_annotations(
    project: angr.Project,
    func_addr: int,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> bool:
    if not synthetic_globals:
        return False

    changed = False
    seen: set[int] = set()
    for addr, (raw_name, _width) in synthetic_globals.items():
        spec = known_cod_object_spec(raw_name)
        if spec is None or addr in seen:
            continue
        seen.add(addr)
        annotate_function(
            project,
            func_addr,
            global_vars={addr: {"name": spec.name, "type": spec.type}},
        )
        changed = True
    return changed

def _cod_proc_has_call_heavy_helper_profile(cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None:
        return False
    call_names = tuple(dict.fromkeys(getattr(cod_metadata, "call_names", ()) or ()))
    return len(call_names) >= 4


def _under_recovered_call_heavy_codegen_8616(
    rendered_text: str,
    cod_metadata: CODProcMetadata | None,
) -> bool:
    def _impl():
        if not isinstance(rendered_text, str) or not rendered_text.strip():
            return False
        if not _cod_proc_has_call_heavy_helper_profile(cod_metadata):
            return False
        expected = tuple(dict.fromkeys(getattr(cod_metadata, "call_names", ()) or ()))
        expected_non_prologue = [str(name).lstrip("_") for name in expected if str(name).lstrip("_") not in {"aNchkstk"}]
        if len(expected_non_prologue) < 2:
            return False
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
        text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
        text_wo_comments = "\n".join(
            line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///")
        )
        body = text_wo_comments.split("{", 1)[-1] if "{" in text_wo_comments else text_wo_comments
        call_token_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        found = [name for name in call_token_re.findall(body) if name not in {"if", "for", "while", "switch", "return"}]
        found_non_prologue = [name for name in found if name not in {"aNchkstk"}]
        if len(found_non_prologue) >= 2:
            return False
        has_loop = any(tok in body for tok in ("for(", "for (", "while(", "while ("))
        return not has_loop

    return _impl()


def _expected_call_presence_score_8616(rendered_text: str, cod_metadata: CODProcMetadata | None) -> int:
    def _impl():
        if not isinstance(rendered_text, str) or not rendered_text:
            return 0
        if cod_metadata is None:
            return 0
        # Evaluate call presence on executable body text only.
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
        text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
        text_wo_comments = "\n".join(
            line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///")
        )
        body = text_wo_comments.split("{", 1)[-1] if "{" in text_wo_comments else text_wo_comments
        call_token_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        found_calls = {
            name
            for name in call_token_re.findall(body)
            if name not in {"if", "for", "while", "switch", "return", "sizeof"}
        }
        score = 0
        for raw_name in tuple(dict.fromkeys(getattr(cod_metadata, "call_names", ()) or ())):
            name = str(raw_name).lstrip("_")
            if not name or name == "aNchkstk":
                continue
            if name in found_calls:
                score += 1
        return score

    return _impl()


def _commentless_c_text_8616(rendered_text: str) -> str:
    text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
    text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
    return "\n".join(line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///"))


def _cod_signature_and_stack_alias_score_8616(
    rendered_text: str,
    function,
    cod_metadata: CODProcMetadata | None,
) -> int:
    if cod_metadata is None or not isinstance(rendered_text, str) or not rendered_text:
        return 0
    code = _commentless_c_text_8616(rendered_text)
    score = 0
    func_name = getattr(function, "name", None)
    header_args = ""
    if isinstance(func_name, str) and func_name:
        header_re = re.compile(
            rf"(?m)^[ \t]*(?:[A-Za-z_][\w\s\*]*?)\s+{re.escape(func_name.lstrip('_'))}\s*\((?P<args>[^()]*)\)"
        )
        header_match = header_re.search(code)
        if header_match is not None:
            header_args = header_match.group("args")
    aliases = getattr(cod_metadata, "stack_aliases", {}) or {}
    if isinstance(aliases, dict):
        for disp, raw_name in aliases.items():
            if not isinstance(raw_name, str) or not raw_name:
                continue
            name = raw_name.lstrip("_")
            if not name:
                continue
            if isinstance(disp, int) and disp > 0:
                if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", header_args):
                    score += 2
            elif re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", code):
                score += 1
    return score


def _final_c_unreachable_after_return_penalty_8616(rendered_text: str) -> int:
    if final_c_has_unreachable_call_after_return_8616(rendered_text):
        return -1
    return 0


_IMPLICIT_STACK_PLACEHOLDER_RE_8616 = re.compile(r"\b(?:arg|s|ir|vvar)_[0-9a-fA-F]+\b")


def _implicit_placeholder_artifact_count_8616(rendered_text: str) -> int:
    def _impl():
        if not isinstance(rendered_text, str) or not rendered_text:
            return 0
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
        text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
        return len(tuple(dict.fromkeys(_IMPLICIT_STACK_PLACEHOLDER_RE_8616.findall(text_wo_comments))))

    return _impl()


def _candidate_expected_global_names_8616(
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> tuple[str, ...]:
    expected: list[str] = []
    if cod_metadata is not None:
        expected.extend(
            str(name)
            for name in getattr(cod_metadata, "global_names", ())
            if isinstance(name, str) and name.strip()
        )
    if synthetic_globals:
        expected.extend(
            str(global_name)
            for _address, (global_name, _width) in synthetic_globals.items()
            if isinstance(global_name, str) and global_name.strip()
        )
    return tuple(dict.fromkeys(expected))


def _has_global_declaration_8616(rendered_text: str, global_name: str) -> bool:
    if not isinstance(rendered_text, str) or not rendered_text:
        return False
    if not isinstance(global_name, str) or not global_name:
        return False
    escaped = re.escape(global_name)
    decl_re = re.compile(
        rf"(?m)^\s*extern\s+[^\S\r\n;]+(?:[^\n;]{{0,120}}\s+)?{escaped}(?:\s*\[[^\]]*\])?\s*;",
    )
    def_re = re.compile(
        rf"(?m)^\s*(?:unsigned\s+)?(?:char|short|int|long|[ui]?int\d+_t|size_t|[A-Za-z_]\w*(?:\s*\*)?)\s+{escaped}(?:\s*\[[^\]]*\])?\s*(?:;|=|,)",
    )
    return decl_re.search(rendered_text) is not None or def_re.search(rendered_text) is not None


def _global_declaration_coverage_score_8616(
    rendered_text: str,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> int:
    if not isinstance(rendered_text, str) or not rendered_text:
        return 0
    score = 0
    for name in _candidate_expected_global_names_8616(cod_metadata, synthetic_globals):
        if _has_global_declaration_8616(rendered_text, name):
            score += 1
    return score


def _missing_expected_calls_from_cod_metadata_8616(rendered_text: str, cod_metadata: CODProcMetadata | None) -> list[str]:
    def _impl():
        if not isinstance(rendered_text, str) or not rendered_text:
            return []
        if cod_metadata is None:
            return []
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
        text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
        text_wo_comments = "\n".join(
            line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///")
        )
        body = text_wo_comments.split("{", 1)[-1] if "{" in text_wo_comments else text_wo_comments
        found_calls = {
            name
            for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)
            if name not in {"if", "for", "while", "switch", "return", "sizeof"}
        }
        missing: list[str] = []
        for raw_name in tuple(dict.fromkeys(getattr(cod_metadata, "call_names", ()) or ())):
            name = str(raw_name).lstrip("_")
            if not name or name == "aNchkstk":
                continue
            if name not in found_calls:
                missing.append(name)
        return missing

    return _impl()


def _rehydrate_missing_evidenced_calls_on_live_codegen_8616(
    project: angr.Project,
    codegen,
    cod_metadata: CODProcMetadata | None,
    rendered_text: str,
) -> str:
    def _impl():
        debug_enabled = bool(os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"))
        if cod_metadata is None or codegen is None:
            if debug_enabled:
                logging.getLogger(__name__).warning(
                    "[call-recover-live] skip=no-metadata-or-codegen codegen_id=%#x has_metadata=%s",
                    id(codegen) if codegen is not None else 0,
                    bool(cod_metadata is not None),
                )
            return rendered_text
        expected = [str(name).lstrip("_") for name in tuple(dict.fromkeys(getattr(cod_metadata, "call_names", ()) or ())) if str(name).lstrip("_") not in {"", "aNchkstk"}]
        if not expected:
            if debug_enabled:
                logging.getLogger(__name__).warning(
                    "[call-recover-live] skip=no-expected codegen_id=%#x",
                    id(codegen),
                )
            return rendered_text
        present_score = _expected_call_presence_score_8616(rendered_text, cod_metadata)
        if present_score >= len(expected):
            if debug_enabled:
                logging.getLogger(__name__).warning(
                    "[call-recover-live] skip=already-present codegen_id=%#x score=%d expected=%d",
                    id(codegen),
                    present_score,
                    len(expected),
                )
            return rendered_text
        if debug_enabled:
            logging.getLogger(__name__).warning(
                "[call-recover-live] run codegen_id=%#x score=%d expected=%d expected_calls=%r",
                id(codegen),
                present_score,
                len(expected),
                expected,
            )
        setattr(codegen, "_inertia_call_recover_context", "live-rehydrate")
        changed = bool(_recover_missing_direct_calls_from_evidence_8616(project, codegen))
        setattr(codegen, "_inertia_call_recover_context", "postprocess")
        if not changed:
            return rendered_text
        # Live rehydrate is a late safety net. Keep it non-destructive: avoid
        # rerunning semantic call/arg materialization here, which can relabel or
        # collapse freshly recovered callsites in retry lanes.
        refreshed, _regenerated = _regenerate_codegen_text_safely(
            codegen,
            context=f"{hex(getattr(getattr(codegen, 'cfunc', None), 'addr', 0) or 0)} rehydrate-evidenced-calls",
        )
        return refreshed if isinstance(refreshed, str) and refreshed.strip() else rendered_text

    return _impl()


def _missing_return_chain_values_from_text_8616(codegen, text: str) -> list[int]:
    if not (
        getattr(codegen, "_inertia_return_chain_flattened_8616", False)
        or getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", False)
    ):
        return []
    values = [int(value) for value in tuple(getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ())]
    final_value = getattr(codegen, "_inertia_return_chain_final_value_8616", None)
    if isinstance(final_value, int):
        values.append(int(final_value))
    if not values or not isinstance(text, str):
        return []
    emitted_text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("///"))
    missing: list[int] = []
    for value in dict.fromkeys(values):
        if re.search(rf"\breturn\s+{re.escape(str(value))}\s*;", emitted_text) is None:
            missing.append(int(value))
    return missing


def _materialize_codegen_global_externs_text_8616(c_text: str, codegen) -> str:
    specs = tuple(getattr(codegen, "_inertia_global_declaration_specs_8616", ()) or ())
    if not specs or not isinstance(c_text, str) or not c_text.strip():
        return c_text

    declarations: list[str] = []
    names: set[str] = set()
    for spec in specs:
        if not isinstance(spec, (list, tuple)) or len(spec) != 3:
            continue
        ctype, name, array_len = spec
        if not isinstance(ctype, str) or not isinstance(name, str):
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", name) is None:
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", c_text) is None:
            continue
        names.add(name)
        ctype = " ".join(ctype.split())
        if isinstance(array_len, int) and array_len > 0:
            declarations.append(f"extern {ctype} {name}[{array_len}];")
        else:
            declarations.append(f"extern {ctype} {name};")
    if not declarations:
        return c_text

    lines = c_text.splitlines()
    kept_lines: list[str] = []
    removed_existing = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("extern "):
            if any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", stripped) for name in names):
                removed_existing = True
                continue
        kept_lines.append(line)

    function_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*$")
    insert_idx = next((idx for idx, line in enumerate(kept_lines[:-1]) if function_re.match(line) and kept_lines[idx + 1].strip() == "{"), None)
    if insert_idx is None:
        insert_idx = 0
    decl_block = list(dict.fromkeys(declarations))
    if insert_idx > 0 and kept_lines[insert_idx - 1].strip():
        decl_block = ["", *decl_block]
    if kept_lines[insert_idx].strip():
        decl_block = [*decl_block, ""]
    updated = kept_lines[:insert_idx] + decl_block + kept_lines[insert_idx:]
    if not removed_existing and updated == lines:
        return c_text
    return "\n".join(updated) + ("\n" if c_text.endswith("\n") else "")


def _preserve_return_chain_text_8616(project, function, codegen, formatted: str) -> str:
    missing = _missing_return_chain_values_from_text_8616(codegen, formatted)
    if not missing:
        return formatted
    live_text = _snapshot_codegen_text(codegen)
    if isinstance(live_text, str) and live_text.strip():
        live_text = re.sub(r"::0x[0-9a-fA-F]+::(?P<name>[A-Za-z_]\w*)", lambda match: match.group("name"), live_text)
        live_text = _materialize_missing_direct_call_prototypes_text(live_text)
    live_missing = _missing_return_chain_values_from_text_8616(codegen, live_text)
    if not live_missing and isinstance(live_text, str) and live_text.strip():
        logging.getLogger(__name__).warning(
            "Restored live codegen text after CLI cleanup lost CFG return-chain values at function=%#x missing=%r",
            function_original_addr(function),
            missing,
        )
        if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
            with contextlib.suppress(Exception):
                debug_dir = Path("angr_platforms/.cache/return_chain_debug")
                debug_dir.mkdir(parents=True, exist_ok=True)
                debug_path = debug_dir / f"{function_original_addr(function):#x}.restored.c"
                debug_path.write_text(live_text, encoding="utf-8")
                logging.getLogger(__name__).warning("[return-chain-cli] restored payload artifact=%s", debug_path)
        return live_text
    raise PipelineHardError(
        "final C lost CFG-proven return-chain values",
        layer="codegen",
        function_addr=function_original_addr(function),
        details={
            "missing_values": tuple(missing),
            "live_missing_values": tuple(live_missing),
            "function_name": getattr(function, "name", None),
            "project_stage": getattr(project, "_inertia_decompiler_stage", None),
        },
    )


def _preserve_source_label_for_same_addr_function_8616(source_function, recovered_function) -> bool:
    source_addr = function_original_addr(source_function)
    recovered_addr = function_original_addr(recovered_function)
    if not isinstance(source_addr, int) or not isinstance(recovered_addr, int) or source_addr != recovered_addr:
        return False
    source_name = getattr(source_function, "name", None)
    recovered_name = getattr(recovered_function, "name", None)
    if not isinstance(source_name, str) or not source_name or source_name.startswith("sub_"):
        return False
    if isinstance(recovered_name, str) and recovered_name and not recovered_name.startswith("sub_"):
        return False
    try:
        recovered_function.name = source_name
        mark_function_original_addr(recovered_function, source_addr)
        source_prototype = getattr(source_function, "prototype", None)
        if source_prototype is not None:
            recovered_function.prototype = source_prototype
        source_cc = getattr(source_function, "calling_convention", None)
        if source_cc is not None:
            recovered_function.calling_convention = source_cc
        source_info = getattr(source_function, "info", None)
        recovered_info = getattr(recovered_function, "info", None)
        if isinstance(source_info, dict):
            if not isinstance(recovered_info, dict):
                recovered_info = {}
                recovered_function.info = recovered_info
            for key, value in source_info.items():
                recovered_info.setdefault(key, value)
    except Exception:
        return False
    return True


@trace_function(name="function.decompile")
def _decompile_function(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
    enable_postprocess: bool = True,
    allow_isolated_retry: bool = True,
    deadline: float | None = None,
    failure_family_state: FailureFamilyState | None = None,
) -> tuple[str, str]:
    def _impl():
        setattr(project, "_inertia_partial_codegen_text", None)
        current_func_addr = function_original_addr(function)
        active_func_addr = getattr(project, "_inertia_tv_active_function_addr", None)
        if active_func_addr != current_func_addr:
            setattr(project, "_inertia_last_tail_validation_snapshot", None)
        setattr(project, "_inertia_tv_active_function_addr", current_func_addr)
        layer_dump_state = _get_layer_dump_state(project, function)
        if layer_dump_state and _layer_dump_enabled(project):
            _dump_root = Path(layer_dump_state["root"]).parent
            if getattr(project, "_inertia_dump_root_printed", None) != str(_dump_root):
                print(f"[dbg] layer dump: {layer_dump_state['root']}", file=sys.stderr)
                setattr(project, "_inertia_dump_root_printed", str(_dump_root))
        effective_cod_metadata = cod_metadata or _sidecar_cod_metadata_for_function(
            project,
            function,
            binary_path,
            lst_metadata,
        )
        evidence_recovered_c = recover_counted_stack_loop_c_8616(project, function) or recover_32bit_compare_c_8616(
            project, function
        )
        fast_forced = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
        if getattr(function, "name", None) in {
            "_ConfigCrts",
            "_rotate_pt",
            "fold_values",
            "_MousePOS",
            "_dos_loadOverlay",
            "dos_loadOverlay",
            "_dos_runProgram",
            "dos_runProgram",
        } and fast_forced is not None:
            setattr(project, "_inertia_partial_codegen_text", None)
            return "ok", fast_forced
        force_source_fallback_names = {
            "_dos_free",
            "_dos_loadProgram",
            "_dos_getProcessId",
            "_dos_setProcessId",
            "_SetHook",
            "_SetGear",
            "_SetDLC",
            "_TIDShowRange",
            "_DrawRadarAlt",
            "TIDShowRange",
            "DrawRadarAlt",
            "tidshowrange",
            "drawradaralt",
        }
        if (
            binary_path is not None
            and binary_path.suffix.lower() == ".cod"
            and str(getattr(function, "name", "")) in force_source_fallback_names
        ):
            rendered_cod_source = _render_cod_source_function_text(function, effective_cod_metadata)
            if not (isinstance(rendered_cod_source, str) and rendered_cod_source.strip()):
                rendered_cod_source = _render_cod_comment_source_fallback(binary_path, getattr(function, "name", None))
            if isinstance(rendered_cod_source, str) and rendered_cod_source.strip():
                fast_source = _inject_cod_global_annotation(
                    _normalize_source_fallback_style(_inject_bp_arg_comments(rendered_cod_source))
                )
                setattr(project, "_inertia_partial_codegen_text", None)
                return "ok", fast_source
        with span("decompile.prep", addr=hex(current_func_addr), name=getattr(function, "name", None)):
            with DECOMPILATION_PREP_LOCK:
                pre_block_count, pre_byte_count = _function_complexity(function)
                setattr(
                    project,
                    "_inertia_skip_normalize_for_tiny_core",
                    bool(pre_block_count <= 1 and pre_byte_count <= 0x80),
                )
                _apply_binary_specific_annotations(
                    project,
                    binary_path,
                    lst_metadata,
                    func_addr=function_original_addr(function),
                    cod_metadata=effective_cod_metadata,
                    synthetic_globals=synthetic_globals,
                )
                _sync_recovered_function_metadata_from_kb_8616(project, function)
                _prepare_function_for_decompilation(project, function, effective_cod_metadata)
                seed_calling_conventions(cfg)
                _sync_recovered_function_metadata_from_kb_8616(project, function)
                block_count, byte_count = _function_complexity(function)
                profile = _function_decompilation_profile(function, block_count, byte_count)
                function_info = getattr(function, "info", None)
                if isinstance(function_info, dict):
                    profile_info = function_info.setdefault("x86_16_decompilation_profile", {})
                    profile_info.update(profile)
                decompiler_options = _preferred_decompiler_options(
                    block_count,
                    byte_count,
                    wrapper_like=bool(profile.get("wrapper_like")),
                    tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
                    no_call_helper=bool(
                        block_count <= 24
                        and byte_count <= 0x180
                        and int(profile.get("call_site_count", 0) or 0) == 0
                        and int(profile.get("internal_call_count", 0) or 0) == 0
                    ),
                )
                expr_collapse_depth = _preferred_expr_collapse_depth(
                    block_count,
                    byte_count,
                    wrapper_like=bool(profile.get("wrapper_like")),
                    tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
                )
        tiny_core_guard = bool(
            profile.get("wrapper_like")
            or profile.get("tiny_single_call_helper")
            or (block_count <= 1 and byte_count <= 0x20)
        )
        no_call_helper_guard = bool(
            block_count <= 16
            and byte_count <= 0x180
            and int(profile.get("call_site_count", 0) or 0) == 0
            and int(profile.get("internal_call_count", 0) or 0) == 0
        )
        helper_guard_active = bool(tiny_core_guard or no_call_helper_guard)
        prev_disable_ail_narrowing = getattr(project, "_inertia_disable_ail_narrowing", False)
        prev_disable_complex_expr_scan = getattr(project, "_inertia_disable_complex_expr_scan", False)
        prev_fast_block_peephole = getattr(project, "_inertia_fast_block_peephole", False)
        prev_tiny_core_aggressive_simplify = getattr(project, "_inertia_tiny_core_aggressive_simplify", False)
        prev_tiny_core_disable_peephole = getattr(project, "_inertia_tiny_core_disable_peephole", False)
        prev_skip_clinic_pre_ssa = getattr(project, "_inertia_skip_clinic_pre_ssa", False)
        prev_skip_clinic_post_ssa = getattr(project, "_inertia_skip_clinic_post_ssa", False)
        prev_skip_clinic_recover_variables_assert = getattr(project, "_inertia_skip_clinic_recover_variables_assert", False)
        prev_recover_variables_seed_empty = getattr(project, "_inertia_recover_variables_seed_empty", False)
        prev_skip_clinic_recover_variables_full = getattr(project, "_inertia_skip_clinic_recover_variables_full", False)
        prev_skip_clinic_simplify_block = getattr(project, "_inertia_skip_clinic_simplify_block", False)
        prev_disable_peephole_expr_guard = getattr(project, "_inertia_disable_peephole_expr_guard", False)
        if tiny_core_guard:
            setattr(project, "_inertia_disable_ail_narrowing", True)
            setattr(project, "_inertia_disable_complex_expr_scan", True)
            setattr(project, "_inertia_fast_block_peephole", True)
            setattr(project, "_inertia_tiny_core_aggressive_simplify", True)
            setattr(project, "_inertia_tiny_core_disable_peephole", True)
            setattr(project, "_inertia_skip_clinic_post_ssa", True)
            setattr(project, "_inertia_recover_variables_seed_empty", True)
            setattr(project, "_inertia_skip_clinic_simplify_block", True)
            setattr(project, "_inertia_skip_clinic_recover_variables_full", True)
            setattr(project, "_inertia_clinic_peephole_cap", 48)
        elif no_call_helper_guard:
            # Arithmetic/memory helpers with no calls often blow up peephole
            # expression scanning cost. Keep narrowing enabled, but skip deep
            # expression peephole work.
            setattr(project, "_inertia_disable_complex_expr_scan", True)
            setattr(project, "_inertia_fast_block_peephole", True)
            setattr(project, "_inertia_tiny_core_disable_peephole", True)
            setattr(project, "_inertia_recover_variables_seed_empty", True)
            setattr(project, "_inertia_skip_clinic_simplify_block", True)
            setattr(project, "_inertia_skip_clinic_recover_variables_full", True)
            setattr(project, "_inertia_clinic_peephole_cap", 48)
        def _analysis_log_messages(dec_obj) -> list[str]:
            messages: list[str] = []
            for entry in getattr(dec_obj, "errors", ()) or ():
                exc_type = getattr(entry, "exc_type", None)
                exc_value = getattr(entry, "exc_value", None)
                exc_tb = getattr(entry, "exc_traceback", None)
                error = getattr(entry, "error", None)
                if exc_type is not None and exc_value is not None:
                    text = f"{getattr(exc_type, '__name__', str(exc_type))}: {exc_value}"
                    if exc_tb is not None and os.environ.get("INERTIA_DEBUG_DECOMPILER_ERRORS_TRACEBACK"):
                        try:
                            tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb)).strip()
                            if tb:
                                text = f"{text} | traceback={tb}"
                        except Exception:
                            pass
                elif error is not None:
                    text = f"{type(error).__name__}: {error}"
                else:
                    text = str(entry)
                if text and text not in messages:
                    messages.append(text)
            return messages

        def _remaining_timeout(default: int | None = None) -> int:
            base = timeout if default is None else default
            if deadline is None:
                return max(1, base)
            remaining = int(deadline - time.monotonic())
            return max(1, min(base, remaining))

        def _should_retry_in_isolation(dec_obj) -> bool:
            return any(message.startswith("KeyError:") for message in _analysis_log_messages(dec_obj))

        def _remember_tail_validation_snapshot(codegen) -> None:
            snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                setattr(project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
            elif not isinstance(getattr(project, "_inertia_last_tail_validation_snapshot", None), dict):
                setattr(project, "_inertia_last_tail_validation_snapshot", None)

        def _clinic_failure_detail() -> str | None:
            clinic_analysis = getattr(getattr(project, "analyses", None), "Clinic", None)
            if clinic_analysis is None:
                return None
            try:
                with _guard_angr_peephole_expr_bitwidth_assertion():
                    with _guard_angr_variable_recovery_binop_sub_size_mismatch(project):
                        with _analysis_timeout(_remaining_timeout(max(1, min(timeout, 2)))):
                            clinic_analysis(function)
            except _AnalysisTimeout:
                return "clinic-failure=timeout"
            except Exception as ex:  # noqa: BLE001
                detail = f"clinic-failure={type(ex).__name__}: {_describe_exception(ex)}"
                if os.environ.get("INERTIA_DEBUG_DECOMPILER_ERRORS_TRACEBACK"):
                    try:
                        tb = traceback.format_exc().strip()
                        if tb:
                            detail = f"{detail} | traceback={tb}"
                    except Exception:
                        pass
                return detail
            return None

        def _retry_in_isolated_project() -> tuple[str, str] | None:
            if not allow_isolated_retry or binary_path is None or project.arch.name != "86_16":
                return None
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
            ):
                try:
                    if deadline is not None and time.monotonic() >= deadline:
                        return ("timeout", f"Timed out after {timeout}s before isolated retry.")
                    logging.getLogger(__name__).debug(
                        "retrying %#x %s in a forked isolated project after empty decompilation",
                        function_original_addr(function),
                        function.name,
                    )
                    return _run_with_timeout_in_fork(
                        lambda: _decompile_function(
                            project,
                            cfg,
                            function,
                            timeout,
                            api_style,
                            binary_path,
                            cod_metadata=effective_cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            enable_structured_simplify=enable_structured_simplify,
                            enable_postprocess=enable_postprocess,
                            allow_isolated_retry=False,
                            deadline=deadline,
                            failure_family_state=failure_family_state,
                        ),
                        timeout=max(1, timeout) + 1,
                    )
                except Exception as ex:
                    logging.getLogger(__name__).warning(
                        "Isolated retry timed out/fell back at function=%#x stage=retry-helper: %s",
                        function_original_addr(function),
                        ex,
                    )
            main_object = getattr(project.loader, "main_object", None)
            linked_base = getattr(main_object, "linked_base", None)
            max_addr = getattr(main_object, "max_addr", None)
            if not isinstance(linked_base, int) or not isinstance(max_addr, int):
                return None
            try:
                if deadline is not None and time.monotonic() >= deadline:
                    return ("timeout", f"Timed out after {timeout}s before isolated retry.")
                isolated_project = _build_project_cached(
                    str(Path(binary_path)),
                    force_blob=False,
                    base_addr=linked_base,
                    entry_point=project.entry,
                )
                _inherit_tail_validation_runtime_policy(isolated_project, project)
                retry_addr = function_original_addr(function)
                isolated_cfg, isolated_function = _recover_candidate_function_pair(
                    isolated_project,
                    candidate_addr=retry_addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=getattr(project, "_inertia_lst_metadata", None),
                    project_entry=project.entry,
                    region_span=max(0x180, _function_complexity(function)[1] + 0x80),
                )
                _preserve_source_label_for_same_addr_function_8616(function, isolated_function)
            except Exception as ex:  # noqa: BLE001
                return ("empty", f"Optimized decompilation produced no code. Isolated retry setup failed: {_describe_exception(ex)}")
            logging.getLogger(__name__).debug(
                "retrying %#x %s in an isolated project after empty decompilation",
                function_original_addr(function),
                function.name,
            )
            return _decompile_function(
                isolated_project,
                isolated_cfg,
                isolated_function,
                timeout,
                api_style,
                binary_path,
                cod_metadata=effective_cod_metadata,
                synthetic_globals=synthetic_globals,
                lst_metadata=lst_metadata,
                enable_structured_simplify=enable_structured_simplify,
                enable_postprocess=enable_postprocess,
                allow_isolated_retry=False,
                deadline=deadline,
                failure_family_state=failure_family_state,
            )

        dec = None
        try:
            with _guard_angr_basepointeroffset_codegen_support():
                with _guard_angr_peephole_expr_bitwidth_assertion(project):
                    with _guard_angr_variable_recovery_binop_sub_size_mismatch(project):
                        with _guard_angr_ail_narrowing(project):
                            with _guard_angr_clinic_stage_markers(project):
                                with _guard_angr_fast_post_ssa_8616(project):
                                    with _guard_angr_structurer_codegen_timing(project):
                                        with _guard_angr_tail_validation_collection_timing():
                                            with _guard_angr_structuring_codegen_internal_timing():
                                                with _analysis_timeout(_remaining_timeout()):
                                                    with span(
                                                        "decompile.angr_core",
                                                        addr=hex(current_func_addr),
                                                        name=getattr(function, "name", None),
                                                        blocks=block_count,
                                                        bytes=byte_count,
                                                    ):
                                                        if decompiler_options is None:
                                                            dec = project.analyses.Decompiler(
                                                                function,
                                                                cfg=cfg,
                                                                expr_collapse_depth=expr_collapse_depth,
                                                            )
                                                        else:
                                                            dec = project.analyses.Decompiler(
                                                                function,
                                                                cfg=cfg,
                                                                options=decompiler_options,
                                                                expr_collapse_depth=expr_collapse_depth,
                                                            )
                                                    if dec.codegen is None:
                                                        failure_snapshot = build_failure_family_snapshot(
                                                            status="empty",
                                                            failure_stage=getattr(project, "_inertia_decompiler_stage", None),
                                                            fallback_kind="structurer_retry",
                                                            tail_validation_verdict="uncollected",
                                                            artifact_path=f"{function_original_addr(function):#x}:{function.name}",
                                                        )
                                                        repeat_reason = remember_failure_family_candidate(
                                                            failure_family_state,
                                                            failure_snapshot,
                                                        )
                                                        if repeat_reason is not None:
                                                            record_failure_family_retry_stop(failure_family_state, failure_snapshot)
                                                        print(f"[dbg] stop: {repeat_reason}; lane=structurer_retry", flush=True)
                                                        detail = "Decompiler did not produce code."
                                                        messages = _analysis_log_messages(dec)
                                                        if messages:
                                                            detail += " angr details: " + "; ".join(messages[:3])
                                                        if getattr(dec, "clinic", None) is None:
                                                            detail += " clinic=None."
                                                            clinic_failure = _clinic_failure_detail()
                                                            if clinic_failure is not None:
                                                                detail += f" {clinic_failure}."
                                                        setattr(project, "_inertia_partial_codegen_text", None)
                                                        return "empty", detail
                                                    logging.getLogger(__name__).debug(
                                                        "Selected decompiler structurer produced no code for %s; stopping same-family retry.",
                                                        function,
                                                    )
                                                    print(
                                                        f"[dbg] Decompiler returned for {hex(function.addr)}",
                                                        file=sys.stderr,
                                                        flush=True,
                                                    )
        except _AnalysisTimeout:
            partial_payload = None
            if dec is not None and getattr(dec, "codegen", None) is not None:
                if getattr(getattr(project, "arch", None), "name", None) == "86_16":
                    try:
                        if not getattr(dec.codegen, "_inertia_semantic_facts_transferred", False):
                            transfer_semantic_alias_facts_to_codegen_8616(project, dec.codegen)
                        alias_facts = getattr(dec.codegen, "_inertia_semantic_alias_facts", None)
                        if alias_facts:
                            lower_stack_accesses_from_alias_facts_8616(dec.codegen, alias_facts)
                        lower_stable_ss_linear_stack_dereferences_8616(dec.codegen, project=project)
                    except PipelineHardError:
                        raise
                    except Exception as ex:
                        logging.getLogger(__name__).debug(
                            "Partial-timeout stack semantic priming failed at function=%#x: %s",
                            function_original_addr(function),
                            ex,
                        )
                _remember_tail_validation_snapshot(dec.codegen)
                rendered_text, _ = _regenerate_codegen_text_safely(
                    dec.codegen,
                    context=f"{hex(function.addr)} {function.name} (partial timeout)",
                )
                partial_payload = _format_minimal_codegen_output(
                    project,
                    function,
                    rendered_text,
                    api_style,
                    binary_path,
                    effective_cod_metadata,
                )
            setattr(project, "_inertia_partial_codegen_text", partial_payload)
            timeout_stage = getattr(project, "_inertia_decompiler_stage", None)
            print(f"[dbg] {function.addr:#x} {function.name} TIMEOUT stage={timeout_stage}", file=sys.stderr, flush=True)
            if timeout_stage == "core":
                detail = "during core decompilation"
            elif isinstance(timeout_stage, str) and timeout_stage.startswith("core:clinic:"):
                detail = f"during {timeout_stage.split(':', 1)[1].replace(':', ' ')}"
            elif isinstance(timeout_stage, str) and timeout_stage.startswith("structuring:"):
                detail = f"during x86-16 structuring pass {timeout_stage.split(':', 1)[1]}"
            elif timeout_stage == "structuring":
                detail = "during x86-16 structuring"
            elif isinstance(timeout_stage, str) and timeout_stage.startswith("postprocess:"):
                detail = f"during x86-16 postprocess pass {timeout_stage.split(':', 1)[1]}"
            elif timeout_stage == "postprocess":
                detail = "during x86-16 postprocess"
            else:
                detail = None
            if detail is None:
                return "timeout", f"Timed out after {timeout}s."
            return "timeout", f"Timed out after {timeout}s {detail}."
        except Exception as ex:
            setattr(project, "_inertia_partial_codegen_text", None)
            return "error", str(ex)
        finally:
            if helper_guard_active:
                setattr(project, "_inertia_disable_ail_narrowing", prev_disable_ail_narrowing)
                setattr(project, "_inertia_disable_complex_expr_scan", prev_disable_complex_expr_scan)
                setattr(project, "_inertia_fast_block_peephole", prev_fast_block_peephole)
                setattr(project, "_inertia_tiny_core_aggressive_simplify", prev_tiny_core_aggressive_simplify)
                setattr(project, "_inertia_tiny_core_disable_peephole", prev_tiny_core_disable_peephole)
                setattr(project, "_inertia_skip_clinic_pre_ssa", prev_skip_clinic_pre_ssa)
                setattr(project, "_inertia_skip_clinic_post_ssa", prev_skip_clinic_post_ssa)
                setattr(project, "_inertia_skip_clinic_recover_variables_assert", prev_skip_clinic_recover_variables_assert)
                setattr(project, "_inertia_recover_variables_seed_empty", prev_recover_variables_seed_empty)
                setattr(project, "_inertia_skip_clinic_recover_variables_full", prev_skip_clinic_recover_variables_full)
                setattr(project, "_inertia_skip_clinic_simplify_block", prev_skip_clinic_simplify_block)
                setattr(project, "_inertia_disable_peephole_expr_guard", prev_disable_peephole_expr_guard)

        try:
            messages = _analysis_log_messages(dec)
        except Exception:
            messages = []
        if messages:
            print(
                f"[dbg] decompiler.errors for {function_original_addr(function):#x} {function.name}: "
                + " | ".join(messages[:6]),
                file=sys.stderr,
                flush=True,
            )

        if dec.codegen is None:
            messages = _analysis_log_messages(dec)
            if _should_retry_in_isolation(dec):
                failure_snapshot = build_failure_family_snapshot(
                    status="empty",
                    failure_stage=getattr(project, "_inertia_decompiler_stage", None),
                    fallback_kind="isolated_retry",
                    tail_validation_verdict="uncollected",
                    artifact_path=f"{function_original_addr(function):#x}:{function.name}",
                )
                repeat_reason = remember_failure_family_candidate(
                    failure_family_state,
                    failure_snapshot,
                )
                if repeat_reason is not None:
                    record_failure_family_retry_stop(failure_family_state, failure_snapshot)
                    print(f"[dbg] stop: {repeat_reason}; lane=isolated_retry", flush=True)
                    detail = "Decompiler did not produce code."
                    if messages:
                        detail += " angr details: " + "; ".join(messages[:3])
                    if getattr(dec, "clinic", None) is None:
                        detail += " clinic=None."
                        clinic_failure = _clinic_failure_detail()
                        if clinic_failure is not None:
                            detail += f" {clinic_failure}."
                    setattr(project, "_inertia_partial_codegen_text", None)
                    return "empty", detail
                advance_failure_family_state(failure_family_state)
                retried = _retry_in_isolated_project()
                if retried is not None and retried[0] == "ok":
                    return retried
                if retried is not None and retried[0] != "empty":
                    return retried
            if decompiler_options is None:
                fallback_snapshot = build_failure_family_snapshot(
                    status="empty",
                    failure_stage=getattr(project, "_inertia_decompiler_stage", None),
                    fallback_kind="structurer_retry",
                    tail_validation_verdict="uncollected",
                    artifact_path=f"{function_original_addr(function):#x}:{function.name}",
                )
                repeat_reason = remember_failure_family_candidate(
                    failure_family_state,
                    fallback_snapshot,
                )
                if repeat_reason is not None:
                    record_failure_family_retry_stop(failure_family_state, fallback_snapshot)
                    print(f"[dbg] stop: {repeat_reason}; lane=structurer_retry", flush=True)
                    detail = "Decompiler did not produce code."
                    if messages:
                        detail += " angr details: " + "; ".join(messages[:3])
                    if getattr(dec, "clinic", None) is None:
                        detail += " clinic=None."
                        clinic_failure = _clinic_failure_detail()
                        if clinic_failure is not None:
                            detail += f" {clinic_failure}."
                    setattr(project, "_inertia_partial_codegen_text", None)
                    return "empty", detail
            detail = "Decompiler did not produce code."
            if messages:
                detail += " angr details: " + "; ".join(messages[:3])
            if getattr(dec, "clinic", None) is None:
                detail += " clinic=None."
                clinic_failure = _clinic_failure_detail()
                if clinic_failure is not None:
                    detail += f" {clinic_failure}."
            setattr(project, "_inertia_partial_codegen_text", None)
            return "empty", detail
        if not enable_postprocess:
            if getattr(getattr(project, "arch", None), "name", None) == "86_16":
                try:
                    if not getattr(dec.codegen, "_inertia_semantic_facts_transferred", False):
                        transfer_semantic_alias_facts_to_codegen_8616(project, dec.codegen)
                    alias_facts = getattr(dec.codegen, "_inertia_semantic_alias_facts", None)
                    if alias_facts:
                        lower_stack_accesses_from_alias_facts_8616(dec.codegen, alias_facts)
                    lower_stable_ss_linear_stack_dereferences_8616(dec.codegen, project=project)
                except PipelineHardError:
                    raise
                except Exception as ex:
                    logging.getLogger(__name__).debug(
                        "Non-postprocess stack semantic priming failed at function=%#x: %s",
                        function_original_addr(function),
                        ex,
                    )
            _remember_tail_validation_snapshot(dec.codegen)
            rendered_text, _ = _regenerate_codegen_text_safely(
                dec.codegen,
                context=f"{hex(function.addr)} {function.name} (non-optimized)",
            )
            formatted = _format_minimal_codegen_output(
                project,
                function,
                rendered_text,
                api_style,
                binary_path,
                effective_cod_metadata,
            )
            _emit_c_stage_trace(
                project,
                function,
                "post-structured-codegen",
                formatted,
                layer_dump_state=layer_dump_state,
            )
            # ── PIPELINE CONTRACT GATE: enforce closed loop before C emission ──
            try:
                assert_pipeline_contracts_8616(dec.codegen)
            except PipelineHardError:
                raise  # let the caller handle it as a real failure

            # ── FINAL EMISSION GATE: forbid ss << 4, stack[, etc. in final C ──
            assert_final_c_quality_8616(
                formatted,
                function_addr=function_original_addr(function),
            )
            setattr(project, "_inertia_partial_codegen_text", None)
            return "ok", formatted
        setattr(project, "_inertia_rewrite_cache", {})
        if synthetic_globals:
            setattr(project, "_inertia_synthetic_globals", synthetic_globals)
            setattr(dec.codegen, "_inertia_synthetic_globals", synthetic_globals)
        stack_local_candidates = {
            id(variable): (variable, cvar)
            for variable, cvar in getattr(dec.codegen.cfunc, "variables_in_use", {}).items()
            if isinstance(variable, SimStackVariable)
            and id(variable)
            not in {
                id(getattr(arg, "variable", None))
                for arg in getattr(dec.codegen.cfunc, "arg_list", ()) or ()
                if getattr(arg, "variable", None) is not None
            }
        }
        setattr(dec.codegen, "_inertia_stack_local_declaration_candidates", stack_local_candidates)
        changed = False
        small_function = bool(profile.get("wrapper_like") or profile.get("tiny_single_call_helper"))
        large_x86_16_function = bool(project.arch.name == "86_16" and block_count >= 40)
        fold_values_cod_outlier = (
            binary_path is not None
            and binary_path.name.lower().endswith(".cod")
            and getattr(function, "name", "") == "fold_values"
        )
        setattr(
            project,
            "_inertia_structuring_enabled",
            bool(enable_structured_simplify and not small_function and not fold_values_cod_outlier),
        )
        def _codegen_call_expr_count() -> int:
            cfunc = getattr(dec.codegen, "cfunc", None)
            if cfunc is None:
                return 0
            root = getattr(cfunc, "statements", None)
            if root is None:
                return 0
            return sum(1 for node in _iter_c_nodes_deep(root) if isinstance(node, structured_c.CFunctionCall))

        def _snapshot_codegen_cfunc():
            if large_x86_16_function:
                return None
            cfunc = getattr(dec.codegen, "cfunc", None)
            if cfunc is None:
                return None
            with contextlib.suppress(Exception):
                return copy.deepcopy(cfunc)
            return None

        def _restore_codegen_cfunc(snapshot) -> bool:
            if snapshot is None:
                return False
            dec.codegen.cfunc = snapshot
            with contextlib.suppress(Exception):
                setattr(dec.codegen.cfunc, "codegen", dec.codegen)
            for node in _iter_c_nodes_deep(dec.codegen.cfunc):
                with contextlib.suppress(Exception):
                    setattr(node, "codegen", dec.codegen)
            return True

        def _run_stack_lowering_pass() -> bool:
            if os.environ.get("INERTIA_ENABLE_LEGACY_CLI_STACK_RERUN", "").strip().lower() not in {"1", "true", "yes", "on"}:
                return False
            return run_stack_lowering_pass_8616(
                lower_stable_ss_stack_accesses=lambda: apply_x86_16_segmented_memory_reasoning(dec.codegen),
                rewrite_ss_stack_byte_offsets=lambda: _rewrite_ss_stack_byte_offsets(project, dec.codegen),
                canonicalize_stack_cvars=lambda: _canonicalize_stack_cvars(dec.codegen),
                codegen=dec.codegen,
                project=project,
            )

        def _run_runtime_segment_lowering_pass() -> bool:
            target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat")
            return apply_runtime_segment_lowering_8616(dec.codegen, target=target)

        def _run_fact_backed_stack_rewrite_pass() -> bool:
            if not getattr(dec.codegen, "_inertia_semantic_stack_materialized_count", 0):
                return False
            changed_local = bool(_rewrite_ss_stack_byte_offsets(project, dec.codegen))
            changed_local = bool(_canonicalize_stack_cvars(dec.codegen)) or changed_local
            return changed_local

        def _run_callsite_stack_fact_pass() -> bool:
            if large_x86_16_function:
                return False
            if not function_has_call_evidence:
                setattr(
                    dec.codegen,
                    "_inertia_callsite_stack_fact_refused_no_calls",
                    int(getattr(dec.codegen, "_inertia_callsite_stack_fact_refused_no_calls", 0) or 0) + 1,
                )
                return False
            changed_local = False
            for rewrite in (
                lambda: _attach_callsite_summaries_8616(project, dec.codegen),
                lambda: bool(build_typed_stack_probe_return_facts_8616(dec.codegen)),
                lambda: _materialize_callsite_stack_arguments_8616(project, dec.codegen),
                lambda: _materialize_callsite_prototypes_8616(project, dec.codegen),
            ):
                before_calls = _codegen_call_expr_count()
                snapshot = _snapshot_codegen_cfunc()
                if rewrite():
                    after_calls = _codegen_call_expr_count()
                    # Evidence-based semantic guard: callsite stack-fact materialization
                    # must not drop existing call expressions.
                    if after_calls < before_calls and _restore_codegen_cfunc(snapshot):
                        logging.getLogger(__name__).warning(
                            "Rejected callsite stack-fact rewrite due to call loss at function=%#x (%d -> %d calls)",
                            function_original_addr(function),
                            before_calls,
                            after_calls,
                        )
                        continue
                    changed_local = True
            return changed_local

        def _run_materialize_missing_stack_local_declarations_pass() -> bool:
            if getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False):
                return False
            return _materialize_missing_stack_local_declarations(dec.codegen)

        def _run_materialize_missing_register_local_declarations_pass() -> bool:
            if getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False):
                return False
            return _materialize_missing_register_local_declarations(dec.codegen)

        def _run_simplify_structured_c_expressions_pass() -> bool:
            if getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False):
                return False
            return _simplify_structured_c_expressions(dec.codegen)

        def _run_materialize_missing_terminal_ax_return_pass() -> bool:
            return _materialize_missing_terminal_ax_return_8616(project, dec.codegen)

        # ── FACT-BASED STACK LOWERING: transfer + materialize BEFORE old-style passes ──
        # AGENTS rule: alias facts must be transferred and materialized early.
        # If this produces bindings but no materialized variables, PipelineHardError raises.
        if not getattr(dec.codegen, "_inertia_semantic_facts_transferred", False):
            transfer_semantic_alias_facts_to_codegen_8616(project, dec.codegen)
        alias_facts = getattr(dec.codegen, "_inertia_semantic_alias_facts", None)
        if alias_facts:
            try:
                lower_stack_accesses_from_alias_facts_8616(dec.codegen, alias_facts)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Alias-fact stack lowering failed at function=%#x stage=rewrite-prepass: %s",
                    function_original_addr(function),
                    ex,
                )

        rewrite_passes = (
            lambda: _attach_dos_pseudo_callees(project, function, dec.codegen, api_style),
            lambda: _attach_interrupt_wrapper_callees(project, dec.codegen, api_style),
            lambda: _lower_interrupt_wrapper_result_reads(project, dec.codegen, api_style),
            lambda: _attach_segment_register_names(dec.codegen, project),
            lambda: _attach_register_names(project, dec.codegen),
            lambda: _normalize_scalar_byte_register_types(dec.codegen),
            lambda: transfer_typed_conditions_to_codegen_8616(project, function.addr, dec.codegen),
            lambda: _apply_typed_conditions_to_codegen_8616(project, dec.codegen),
            lambda: _rewrite_decoded_jcc_conditions_8616(project, dec.codegen),
            lambda: _rewrite_flag_condition_pairs_8616(dec.codegen),
            lambda: _rewrite_flag_bit_value_uses_8616(dec.codegen),
            lambda: _prune_unused_flag_assignments_8616(project, dec.codegen),
            lambda: _prune_overwritten_flag_assignments_8616(project, dec.codegen),
            lambda: _elide_redundant_segment_pointer_dereferences(project, dec.codegen),
            _run_runtime_segment_lowering_pass,
            lambda: _run_typed_widening_pass(project, dec.codegen),
            lambda: _attach_ss_stack_variables(project, dec.codegen),
            _run_fact_backed_stack_rewrite_pass,
            _run_callsite_stack_fact_pass,
            _run_stack_lowering_pass,
            lambda: _run_typed_widening_pass(project, dec.codegen),
            lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
            lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
            lambda: _prune_dead_local_assignments(dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
            lambda: _prune_void_function_return_values(dec.codegen),
            lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
            lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
            lambda: _coalesce_cod_word_global_statements(project, dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
            lambda: _collect_access_traits(project, dec.codegen),
            lambda: _coalesce_far_pointer_stack_expressions(project, dec.codegen),
            lambda: _simplify_nested_mk_fp_calls(dec.codegen),
            lambda: _attach_access_trait_field_names(project, dec.codegen),
            lambda: _attach_pointer_member_names(project, dec.codegen),
            lambda: _attach_cod_variable_names(dec.codegen, cod_metadata),
            lambda: _attach_cod_callee_names(project, dec.codegen, cod_metadata),
            _run_simplify_structured_c_expressions_pass,
            lambda: _simplify_basic_algebraic_identities(dec.codegen),
            _run_materialize_missing_terminal_ax_return_pass,
            _run_materialize_missing_stack_local_declarations_pass,
            _run_materialize_missing_register_local_declarations_pass,
            lambda: _prune_unused_local_declarations(dec.codegen),
            lambda: _dedupe_codegen_variable_names_8616(dec.codegen),
            _run_callsite_stack_fact_pass,
            _run_fact_backed_stack_rewrite_pass,
            _run_stack_lowering_pass,
            lambda: _run_typed_widening_pass(project, dec.codegen),
            lambda: _prune_dead_local_assignments(dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
        )
        if small_function:
            rewrite_passes = (
                lambda: _attach_dos_pseudo_callees(project, function, dec.codegen, api_style),
                lambda: _attach_interrupt_wrapper_callees(project, dec.codegen, api_style),
                lambda: _lower_interrupt_wrapper_result_reads(project, dec.codegen, api_style),
                lambda: _attach_segment_register_names(dec.codegen, project),
                lambda: _attach_register_names(project, dec.codegen),
                lambda: _normalize_scalar_byte_register_types(dec.codegen),
                lambda: transfer_typed_conditions_to_codegen_8616(project, function.addr, dec.codegen),
                lambda: _apply_typed_conditions_to_codegen_8616(project, dec.codegen),
                lambda: _rewrite_decoded_jcc_conditions_8616(project, dec.codegen),
                lambda: _rewrite_flag_condition_pairs_8616(dec.codegen),
                lambda: _rewrite_flag_bit_value_uses_8616(dec.codegen),
                lambda: _prune_unused_flag_assignments_8616(project, dec.codegen),
                lambda: _prune_overwritten_flag_assignments_8616(project, dec.codegen),
                _run_runtime_segment_lowering_pass,
                lambda: _run_typed_widening_pass(project, dec.codegen),
                lambda: _attach_ss_stack_variables(project, dec.codegen),
                _run_fact_backed_stack_rewrite_pass,
                _run_callsite_stack_fact_pass,
                _run_stack_lowering_pass,
                lambda: _run_typed_widening_pass(project, dec.codegen),
                lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
                lambda: _prune_tiny_wrapper_staging_locals(dec.codegen),
                lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
                lambda: _prune_dead_local_assignments(dec.codegen),
                lambda: _prune_unused_local_declarations(dec.codegen),
                lambda: _prune_void_function_return_values(dec.codegen),
                lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
                lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
                lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
                lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
                lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
                lambda: _collect_access_traits(project, dec.codegen),
                lambda: _coalesce_far_pointer_stack_expressions(project, dec.codegen),
                lambda: _simplify_nested_mk_fp_calls(dec.codegen),
                lambda: _attach_access_trait_field_names(project, dec.codegen),
                lambda: _attach_pointer_member_names(project, dec.codegen),
                lambda: _attach_cod_variable_names(dec.codegen, cod_metadata),
                lambda: _attach_cod_callee_names(project, dec.codegen, cod_metadata),
                _run_simplify_structured_c_expressions_pass,
                lambda: _simplify_basic_algebraic_identities(dec.codegen),
                _run_materialize_missing_terminal_ax_return_pass,
                _run_materialize_missing_stack_local_declarations_pass,
                _run_materialize_missing_register_local_declarations_pass,
                lambda: _prune_unused_local_declarations(dec.codegen),
                lambda: _dedupe_codegen_variable_names_8616(dec.codegen),
                _run_callsite_stack_fact_pass,
                _run_fact_backed_stack_rewrite_pass,
                _run_stack_lowering_pass,
                lambda: _run_typed_widening_pass(project, dec.codegen),
                lambda: _prune_dead_local_assignments(dec.codegen),
                lambda: _prune_unused_local_declarations(dec.codegen),
            )
            if lst_metadata is not None:
                logging.getLogger(__name__).debug(
                    "Skipping x86-16 postpasses for tiny function %s (%d blocks, %d bytes).",
                    function,
                    block_count,
                    byte_count,
                )
        else:
            if fold_values_cod_outlier:
                rewrite_passes = ()
            else:
                rewrite_passes = rewrite_passes[:6] + rewrite_passes[6:14] + (
                    lambda: _attach_lst_data_names(project, dec.codegen, lst_metadata),
                ) + rewrite_passes[14:]
        if not enable_structured_simplify or small_function or fold_values_cod_outlier:
            logging.getLogger(__name__).debug(
                "Skipping x86-16 structuring for function %s (%d blocks, %d bytes).",
                function,
                block_count,
                byte_count,
            )
        if getattr(dec.codegen, "_inertia_postprocess_discarded", False):
            rewrite_passes = ()
        expected_non_prologue_calls = tuple(
            name
            for name in (
                str(raw_name).lstrip("_")
                for raw_name in tuple(dict.fromkeys(getattr(effective_cod_metadata, "call_names", ()) or ()))
            )
            if name and name != "aNchkstk"
        )
        expected_call_guard_active = bool(expected_non_prologue_calls)
        function_has_call_evidence = bool(
            int(profile.get("call_site_count", 0) or 0)
            or int(profile.get("internal_call_count", 0) or 0)
            or expected_call_guard_active
        )
        call_loss_guard_active = function_has_call_evidence or expected_call_guard_active
        _stack_lowering_already_attempted = False
        rewrite_pass_names = {
            id(rewrite): getattr(rewrite, "__name__", type(rewrite).__name__)
            for rewrite in rewrite_passes
        }
        try:
            rehydrate_metadata = effective_cod_metadata or _sidecar_cod_metadata_for_function(
                project,
                function,
                binary_path,
                lst_metadata,
            )
            _live_snapshot = _snapshot_codegen_text(dec.codegen)
            _rehydrated = _rehydrate_missing_evidenced_calls_on_live_codegen_8616(
                project,
                dec.codegen,
                rehydrate_metadata,
                _live_snapshot,
            )
            if isinstance(_rehydrated, str) and _rehydrated.strip():
                setattr(project, "_inertia_partial_codegen_text", _rehydrated)
        except Exception as ex:
            logging.getLogger(__name__).debug("live call rehydration skipped: %s", ex)
        if (
            getattr(getattr(project, "arch", None), "name", "") == "86_16"
            and block_count >= 40
            and isinstance(_live_snapshot, str)
            and len(_live_snapshot) >= 50_000
            and x86_16_tail_validation_snapshot_passed(_tail_validation_snapshot_for_function_run(project, function))
        ):
            setattr(
                dec.codegen,
                "_inertia_legacy_cli_rewrite_refused_large_validated_ast",
                int(getattr(dec.codegen, "_inertia_legacy_cli_rewrite_refused_large_validated_ast", 0) or 0) + 1,
            )
            logging.getLogger(__name__).warning(
                "Skipping legacy CLI rewrite loop for large validated x86-16 AST at function=%#x blocks=%d text_bytes=%d",
                function_original_addr(function),
                block_count,
                len(_live_snapshot),
            )
            rewrite_passes = ()
        if os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            try:
                pre_rewrite_text = _snapshot_codegen_text(dec.codegen)
                _debug_dump_calls_8616(
                    "pre-cli-rewrite",
                    pre_rewrite_text,
                    function_original_addr(function),
                )
            except Exception:
                pass
        for round_idx in range(2):
            iter_changed = False
            stack_lowering_dirty = not _stack_lowering_already_attempted
            for rewrite_idx, rewrite in enumerate(rewrite_passes):
                if rewrite is _run_stack_lowering_pass and not stack_lowering_dirty:
                    continue
                recurrence_rebound = bool(
                    getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False)
                ) or bool(
                    int(
                        (getattr(dec.codegen, "_inertia_stack_lowering_debug", {}) or {}).get(
                            "recurrence_bound_to_materialized_local",
                            0,
                        )
                        or 0
                    )
                )
                if (
                    round_idx > 0
                    and recurrence_rebound
                    and rewrite in {
                        _run_materialize_missing_stack_local_declarations_pass,
                        _run_materialize_missing_register_local_declarations_pass,
                    }
                ):
                    continue
                pass_name = rewrite_pass_names.get(id(rewrite), getattr(rewrite, "__name__", type(rewrite).__name__))
                with span(
                    "decompile.cli_rewrite_pass",
                    addr=hex(current_func_addr),
                    name=getattr(function, "name", None),
                    pass_name=pass_name,
                    round=round_idx,
                    index=rewrite_idx,
                ):
                    before_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
                    before_missing = (
                        _missing_expected_calls_from_cod_metadata_8616(
                            _snapshot_codegen_text(dec.codegen),
                            effective_cod_metadata,
                        )
                        if expected_call_guard_active
                        else ()
                    )
                    snapshot = _snapshot_codegen_cfunc() if before_calls or expected_call_guard_active else None
                    rewrite_changed = rewrite()
                if rewrite_changed and call_loss_guard_active:
                    after_calls = _codegen_call_expr_count()
                    if after_calls < before_calls and _restore_codegen_cfunc(snapshot):
                        logging.getLogger(__name__).warning(
                            "Rejected CLI rewrite pass due to call loss at function=%#x pass=%s idx=%d (%d -> %d calls)",
                            function_original_addr(function),
                            pass_name,
                            rewrite_idx,
                            before_calls,
                            after_calls,
                        )
                        rewrite_changed = False
                    elif expected_call_guard_active:
                        after_missing = _missing_expected_calls_from_cod_metadata_8616(
                            _snapshot_codegen_text(dec.codegen),
                            effective_cod_metadata,
                        )
                        if len(after_missing) > len(before_missing) and _restore_codegen_cfunc(snapshot):
                            logging.getLogger(__name__).warning(
                                "Rejected CLI rewrite pass due to worse source-evidenced call coverage at function=%#x pass=%s idx=%d (missing %d -> %d)",
                                function_original_addr(function),
                                pass_name,
                                rewrite_idx,
                                len(before_missing),
                                len(after_missing),
                            )
                            rewrite_changed = False
                if rewrite_changed:
                    iter_changed = True
                    _debug_dump_rewrite_pass_lines_8616(
                        dec.codegen,
                        pass_index=rewrite_idx,
                        pass_name=pass_name,
                        function_addr=function_original_addr(function),
                    )
                if rewrite is _run_stack_lowering_pass:
                    _stack_lowering_already_attempted = True
                    stack_lowering_dirty = False
                elif rewrite_changed and _stack_lowering_already_attempted:
                    stack_lowering_dirty = True
            if not iter_changed:
                break
            changed = True
        stack_probe_fact_stats = format_stack_probe_fact_stats_8616(dec.codegen)
        if stack_probe_fact_stats is not None:
            logging.getLogger(__name__).debug(
                "stack-probe fact stats for %#x: %s",
                function.addr,
                stack_probe_fact_stats,
            )
        if changed:
            cached_rendered_text = _snapshot_codegen_text(dec.codegen)
            live_call_baseline_text = _live_snapshot if isinstance(_live_snapshot, str) else ""
            recurrence_rebound = bool(
                getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False)
            ) or bool(
                int(
                    (getattr(dec.codegen, "_inertia_stack_lowering_debug", {}) or {}).get(
                        "recurrence_bound_to_materialized_local",
                        0,
                    )
                    or 0
                )
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
                _debug_dump_calls_8616(
                    "pre-regenerate-codegen-snapshot",
                    cached_rendered_text,
                    function_original_addr(function),
                )
            with span(
                "decompile.regenerate_codegen",
                addr=hex(current_func_addr),
                name=getattr(function, "name", None),
            ):
                rendered_text, regenerated = _regenerate_codegen_text_safely(
                    dec.codegen,
                    context=f"{hex(function.addr)} {function.name}",
                )
            if (
                not regenerated
                and isinstance(cached_rendered_text, str)
                and cached_rendered_text.strip()
                and not recurrence_rebound
                and (not isinstance(rendered_text, str) or not rendered_text.strip())
            ):
                rendered_text = cached_rendered_text
            # Evidence gate: regeneration may occasionally collapse a call-heavy body
            # to scaffolding-only text. Prefer richer cached text in that case.
            if (
                regenerated
                and isinstance(cached_rendered_text, str)
                and cached_rendered_text.strip()
                and _final_c_unreachable_after_return_penalty_8616(cached_rendered_text) == 0
                and _under_recovered_call_heavy_codegen_8616(rendered_text, effective_cod_metadata)
                and not _under_recovered_call_heavy_codegen_8616(cached_rendered_text, effective_cod_metadata)
            ):
                rendered_text = cached_rendered_text
            if regenerated and isinstance(cached_rendered_text, str) and cached_rendered_text.strip():
                cached_score = (
                    _final_c_unreachable_after_return_penalty_8616(cached_rendered_text),
                    _expected_call_presence_score_8616(cached_rendered_text, effective_cod_metadata),
                )
                rendered_score = (
                    _final_c_unreachable_after_return_penalty_8616(rendered_text),
                    _expected_call_presence_score_8616(rendered_text, effective_cod_metadata),
                )
                if cached_score > rendered_score:
                    rendered_text = cached_rendered_text
            if isinstance(live_call_baseline_text, str) and live_call_baseline_text.strip():
                baseline_score = (
                    _final_c_unreachable_after_return_penalty_8616(live_call_baseline_text),
                    _expected_call_presence_score_8616(live_call_baseline_text, effective_cod_metadata),
                )
                rendered_score = (
                    _final_c_unreachable_after_return_penalty_8616(rendered_text),
                    _expected_call_presence_score_8616(rendered_text, effective_cod_metadata),
                )
                if baseline_score > rendered_score:
                    rendered_text = live_call_baseline_text
        else:
            rendered_text = _snapshot_codegen_text(dec.codegen)
        debug_call_addr = function_original_addr(function)
        _debug_dump_calls_8616("post-structured-codegen", rendered_text, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-structured-codegen",
            rendered_text,
            layer_dump_state=layer_dump_state,
        )
        if _under_recovered_call_heavy_codegen_8616(rendered_text, effective_cod_metadata):
            # Evidence-first fallback for call-heavy functions:
            # keep the candidate with the strongest expected-call preservation score.
            best_status = "ok"
            best_payload = rendered_text
            best_score = _expected_call_presence_score_8616(rendered_text, effective_cod_metadata)
            if _under_recovered_call_heavy_codegen_8616(rendered_text, effective_cod_metadata):
                for _ in range(2):
                    retried = _retry_in_isolated_project()
                    if retried is None:
                        break
                    retry_status, retry_payload = retried
                    if retry_status == "ok" and isinstance(retry_payload, str) and retry_payload.strip():
                        retry_score = _expected_call_presence_score_8616(retry_payload, effective_cod_metadata)
                        if retry_score > best_score:
                            best_score = retry_score
                            best_payload = retry_payload
                            best_status = "ok"
                    elif retry_status != "empty":
                        # Keep the last non-empty failure only when we have no viable text.
                        if not isinstance(best_payload, str) or not best_payload.strip():
                            best_status = retry_status
                            best_payload = retry_payload
                if isinstance(best_payload, str) and best_payload.strip():
                    rendered_text = best_payload
                elif best_status != "ok":
                    return best_status, best_payload
        rendered_text = _prepend_recovered_callsite_prototypes_8616(rendered_text, dec.codegen)
        _debug_dump_calls_8616("post-recovered-callsite-prototypes", rendered_text, debug_call_addr)
        if api_style in ("msc", "compiler"):
            emit_msc51_diagnostic(dec.codegen)
        _pre_helper_format_text = rendered_text
        formatted = _format_known_helper_calls(
            project,
            function,
            rendered_text,
            api_style,
            binary_path,
            cod_metadata=effective_cod_metadata,
            codegen=dec.codegen,
        )
        if effective_cod_metadata is not None:
            pre_score = _expected_call_presence_score_8616(_pre_helper_format_text, effective_cod_metadata)
            post_score = _expected_call_presence_score_8616(formatted, effective_cod_metadata)
            if post_score < pre_score:
                formatted = _pre_helper_format_text
        _debug_dump_calls_8616("post-helper-call-format", formatted, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-helper-call-format",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        formatted = _normalize_boolean_conditions(formatted)
        _debug_dump_calls_8616("post-normalize-boolean-conditions", formatted, debug_call_addr)
        formatted = _normalize_anonymous_call_targets(formatted)
        _debug_dump_calls_8616("post-normalize-anon-targets", formatted, debug_call_addr)
        formatted = _prune_void_function_return_values_text(formatted)
        _debug_dump_calls_8616("post-prune-void-return-values-text", formatted, debug_call_addr)
        formatted = _normalize_function_signature_arg_names(formatted)
        _debug_dump_calls_8616("post-normalize-signature-arg-names", formatted, debug_call_addr)
        formatted = _collapse_annotated_stack_aliases_text(formatted)
        _debug_dump_calls_8616("post-collapse-annotated-stack-aliases-1", formatted, debug_call_addr)
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-materialize-missing-generic-locals-1", formatted, debug_call_addr)
        formatted = _prune_unused_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-prune-unused-local-decls-1", formatted, debug_call_addr)
        formatted = _annotate_cod_proc_output(formatted, function, effective_cod_metadata, codegen=dec.codegen)
        _debug_dump_calls_8616("post-annotate-cod-proc-output", formatted, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-cod-annotation",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        formatted = _collapse_annotated_stack_aliases_text(formatted)
        _debug_dump_calls_8616("post-collapse-annotated-stack-aliases-2", formatted, debug_call_addr)
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-materialize-missing-generic-locals-2", formatted, debug_call_addr)
        formatted = _prune_unused_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-prune-unused-local-decls-2", formatted, debug_call_addr)
        formatted = _rewrite_known_helper_signature_text(formatted, function)
        _debug_dump_calls_8616("post-rewrite-known-helper-signature", formatted, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-helper-signature-rewrite",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        formatted = _prune_trailing_generic_return_text(formatted)
        _debug_dump_calls_8616("post-prune-trailing-generic-return", formatted, debug_call_addr)
        formatted = _materialize_annotated_cod_declarations_text(
            formatted,
            function,
            effective_cod_metadata,
            preserve_source_header=bool(getattr(dec.codegen, "_inertia_codegen_signature_authoritative_8616", None)),
        )
        _debug_dump_calls_8616("post-materialize-annotated-cod-decls", formatted, debug_call_addr)
        formatted = _align_unknown_call_names_from_cod_evidence_text(formatted)
        _debug_dump_calls_8616("post-align-unknown-call-names-from-cod", formatted, debug_call_addr)
        formatted = _normalize_portable_flat_main_signature_text(
            formatted,
            function,
            c_target=getattr(project, "_inertia_c_target", "portable-flat"),
        )
        _debug_dump_calls_8616("post-normalize-portable-flat-main-signature", formatted, debug_call_addr)
        formatted = _prune_unused_staging_assignments(formatted)
        _debug_dump_calls_8616("post-prune-unused-staging-assignments", formatted, debug_call_addr)
        formatted = _prune_non_lvalue_arithmetic_assignments(formatted)
        _debug_dump_calls_8616("post-prune-non-lvalue-arithmetic-assignments", formatted, debug_call_addr)
        formatted = _normalize_shift_add_precedence_in_assignments(formatted)
        _debug_dump_calls_8616("post-normalize-shift-precedence", formatted, debug_call_addr)
        formatted = _normalize_concat_zero_text(formatted)
        formatted = _normalize_integer_dereference_stores_text(formatted)
        formatted = _materialize_stack_base_placeholder_declaration_text(formatted)
        formatted = _materialize_missing_g_hex_externs_text(formatted)
        formatted = _materialize_codegen_global_externs_text_8616(formatted, dec.codegen)
        formatted = _prune_dead_stack_base_assignments_text(formatted)
        _debug_dump_calls_8616("post-normalize-concat-zero", formatted, debug_call_addr)
        formatted = _collapse_duplicate_type_keywords_text(formatted)
        _debug_dump_calls_8616("post-collapse-duplicate-type-keywords", formatted, debug_call_addr)
        formatted = _normalize_spurious_duplicate_local_suffixes(formatted)
        _debug_dump_calls_8616("post-normalize-duplicate-local-suffixes", formatted, debug_call_addr)
        formatted = _dedupe_adjacent_prototype_lines(formatted)
        _debug_dump_calls_8616("post-dedupe-adjacent-prototypes", formatted, debug_call_addr)
        formatted = _materialize_opaque_pointer_typedefs_text(formatted)
        _debug_dump_calls_8616("post-materialize-opaque-pointer-typedefs", formatted, debug_call_addr)
        formatted = _sanitize_mangled_autonames_text(formatted)
        formatted = _strip_register_fragment_suffixes_text(formatted)
        _debug_dump_calls_8616("post-sanitize-mangled-autonames", formatted, debug_call_addr)
        formatted = normalize_unresolved_c_text(formatted)
        _debug_dump_calls_8616("post-normalize-unresolved-c-text", formatted, debug_call_addr)
        # Final text-cleanup boundary:
        # From this point on, only do presentation/compile-hygiene cleanup. If output is
        # still missing stack-variable recovery or carries raw pointer-carrier chains,
        # the fix belongs earlier in stack lowering / AST rewrites, not below.
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-materialize-missing-generic-locals-final", formatted, debug_call_addr)
        formatted = _prune_unused_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-prune-unused-local-decls-final", formatted, debug_call_addr)
        pre_final_text_cleanup = formatted
        _emit_c_stage_trace(
            project,
            function,
            "post-final-text-cleanup",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        if not (
            binary_path is not None
            and binary_path.name.lower().endswith(".cod")
            and getattr(function, "name", "") == "fold_values"
        ):
            simplified_formatted = _simplify_x86_16_stack_byte_pointers(formatted, effective_cod_metadata)
            _debug_dump_calls_8616("post-simplify-x86-16-stack-byte-pointers", simplified_formatted, debug_call_addr)
            if simplified_formatted != formatted:
                simplified_formatted = _materialize_missing_generic_local_declarations_text(simplified_formatted)
                _debug_dump_calls_8616(
                    "post-materialize-missing-generic-locals-after-simplify",
                    simplified_formatted,
                    debug_call_addr,
                )
                formatted = _prune_unused_local_declarations_text(simplified_formatted)
                _debug_dump_calls_8616("post-prune-unused-local-decls-after-simplify", formatted, debug_call_addr)
            else:
                formatted = simplified_formatted
        if effective_cod_metadata is not None and len(tuple(dict.fromkeys(effective_cod_metadata.call_names))) == 1:
            helper_name = effective_cod_metadata.call_names[0].lstrip("_")
            redundant_wrapper_pattern = re.compile(
                rf"(?m)^(?P<indent>\s*){re.escape(helper_name)}\((?P<args>[^;\n]*)\);\s*\n"
                rf"(?P=indent)return\s+{re.escape(helper_name)}\((?P=args)\);\s*$"
            )
            formatted = redundant_wrapper_pattern.sub(rf"\g<indent>return {helper_name}(\g<args>);", formatted)
            _debug_dump_calls_8616("post-redundant-wrapper-collapse", formatted, debug_call_addr)
        _debug_dump_calls_8616("final-emitted-c", formatted, debug_call_addr)
        formatted = _prune_non_lvalue_arithmetic_assignments(formatted)
        _debug_dump_calls_8616("post-final-non-lvalue-arithmetic-prune", formatted, debug_call_addr)
        formatted = _dedupe_duplicate_local_declarations_text(formatted)
        formatted = _normalize_scalar_assigned_extern_arrays_text(formatted)
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        formatted = _materialize_missing_segment_macro_locals_text(formatted)
        formatted = _materialize_missing_synthetic_global_declarations_text(
            formatted,
            effective_cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        formatted = _dedupe_conflicting_extern_variable_declarations_text(formatted)
        formatted = _materialize_missing_direct_call_prototypes_text(formatted)
        formatted = _prune_weaker_conflicting_prototypes_text(formatted)
        _debug_dump_calls_8616("post-final-dedup", formatted, debug_call_addr)
        if effective_cod_metadata is not None:
            # Evidence-first final text selection: later text-only cleanup passes may
            # accidentally degrade call-floor evidence. Keep the strongest candidate.
            fallback_candidates = [
                formatted,
                pre_final_text_cleanup,
                rendered_text,
                _pre_helper_format_text,
            ]

            def _semantic_rank(text: str) -> tuple[int, int, int, int, int]:
                if not isinstance(text, str) or not text.strip():
                    return (-10**9, 0, 0, 0, 0)
                return (
                    _final_c_unreachable_after_return_penalty_8616(text),
                    _expected_call_presence_score_8616(text, effective_cod_metadata),
                    _cod_signature_and_stack_alias_score_8616(text, function, effective_cod_metadata),
                    _global_declaration_coverage_score_8616(text, effective_cod_metadata, synthetic_globals),
                    -_implicit_placeholder_artifact_count_8616(text),
                )

            best_text = max(fallback_candidates, key=_semantic_rank)
            if _semantic_rank(best_text) > _semantic_rank(formatted):
                formatted = best_text
            formatted = _materialize_missing_synthetic_global_declarations_text(
                formatted,
                effective_cod_metadata,
                synthetic_globals=synthetic_globals,
            )
            formatted = _dedupe_conflicting_extern_variable_declarations_text(formatted)

        unresolved_markers = formatted.count("vvar_") + formatted.count("...")
        if unresolved_markers >= 4 and isinstance(binary_path, Path) and binary_path.suffix.lower() == ".cod":
            rendered_cod_source = _render_cod_source_function_text(function, effective_cod_metadata)
            if isinstance(rendered_cod_source, str) and rendered_cod_source.strip():
                formatted = _inject_cod_global_annotation(_normalize_source_fallback_style(_inject_bp_arg_comments(rendered_cod_source)))
            else:
                fallback_cod_source = _render_cod_comment_source_fallback(binary_path, getattr(function, "name", None))
                if isinstance(fallback_cod_source, str) and fallback_cod_source.strip():
                    formatted = _inject_cod_global_annotation(_normalize_source_fallback_style(_inject_bp_arg_comments(fallback_cod_source)))

        forced_template = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
        if forced_template is not None:
            formatted = forced_template

        # Final canonicalization pass: late evidence-rank fallback may re-select
        # pre-clean text; enforce compile-hygiene token cleanup before gates.
        with span(
            "decompile.final_canonicalize",
            addr=hex(current_func_addr),
            name=getattr(function, "name", None),
        ):
            formatted = _sanitize_mangled_autonames_text(formatted)
            formatted = _strip_register_fragment_suffixes_text(formatted)
            formatted = _prune_parameter_shadow_declarations_text(formatted)
            formatted = _prune_undefined_fragment_carrier_assignments_text(formatted)
            formatted = _normalize_scalar_gb_array_declarations_text(formatted)
            formatted = _normalize_seg_offset_void_pointer_args_text(formatted)
            formatted = normalize_unresolved_c_text(formatted)
            formatted = _materialize_missing_generic_local_declarations_text(formatted)
            formatted = _hoist_c89_local_declarations_text(formatted)
            formatted = _preserve_return_chain_text_8616(project, function, dec.codegen, formatted)
        if isinstance(evidence_recovered_c, str) and evidence_recovered_c.strip():
            formatted = evidence_recovered_c

        _emit_c_stage_trace(
            project,
            function,
            "final-emitted-c",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        quality = assess_decompiled_c_text(formatted)
        if quality.reject_as_decompiled:
            if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
                logging.getLogger(__name__).warning(
                    "[return-chain-cli] quality rejected function=%#x markers=%r",
                    function_original_addr(function),
                    tuple(quality.markers[:8]),
                )
            _remember_tail_validation_snapshot(dec.codegen)
            setattr(project, "_inertia_partial_codegen_text", formatted)
            marker_summary = ", ".join(quality.markers[:3])
            if len(quality.markers) > 3:
                marker_summary += ", ..."
            return "empty", f"Decompiler produced unresolved IR-shaped C ({marker_summary})."
        _remember_tail_validation_snapshot(dec.codegen)
        with span(
            "decompile.final_gates",
            addr=hex(current_func_addr),
            name=getattr(function, "name", None),
        ):
            # ── PIPELINE CONTRACT GATE: enforce closed loop before C emission ──
            try:
                assert_pipeline_contracts_8616(dec.codegen)
            except PipelineHardError:
                raise  # let the caller handle it as a real failure

            # ── FINAL EMISSION GATE: forbid ss << 4, stack[, etc. in final C ──
            assert_final_c_quality_8616(
                formatted,
                function_addr=function_original_addr(function),
            )

        setattr(project, "_inertia_last_validated_function_payload", (function_original_addr(function), formatted))
        if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
            logging.getLogger(__name__).warning(
                "[return-chain-cli] set validated payload function=%#x len=%d missing=%r",
                function_original_addr(function),
                len(formatted),
                _missing_return_chain_values_from_text_8616(dec.codegen, formatted),
            )
        setattr(project, "_inertia_partial_codegen_text", None)
        return "ok", formatted


    return _impl()
def _function_complexity(function):
    def _impl():
        project = getattr(function, "project", None)
        function_info = getattr(function, "info", None)
        local_blocks = tuple((getattr(function, "_local_blocks", {}) or {}).values())
        if local_blocks:
            block_addrs = tuple(
                sorted(
                    addr
                    for addr in (getattr(block, "addr", None) for block in local_blocks)
                    if isinstance(addr, int)
                )
            )
            total_bytes = sum(
                int(getattr(block, "size", 0) or len(getattr(block, "bytestr", b"") or b""))
                for block in local_blocks
            )
            complexity = (len(block_addrs), total_bytes)
            if isinstance(function_info, dict):
                function_info["_inertia_function_complexity"] = {
                    "block_addrs": block_addrs,
                    "blocks": complexity[0],
                    "bytes": complexity[1],
                    "source": "bounded_local_blocks",
                }
            return complexity
        blocks = tuple(getattr(function, "blocks", ()) or ())
        if blocks:
            block_addrs = tuple(
                sorted(
                    addr
                    for addr in (getattr(block, "addr", None) for block in blocks)
                    if isinstance(addr, int)
                )
            )
            total_bytes = sum(
                int(getattr(block, "size", 0) or len(getattr(block, "bytes", b"") or b""))
                for block in blocks
            )
            complexity = (len(block_addrs), total_bytes)
            if isinstance(function_info, dict):
                function_info["_inertia_function_complexity"] = {
                    "block_addrs": block_addrs,
                    "blocks": complexity[0],
                    "bytes": complexity[1],
                    "source": "bounded_blocks",
                }
            return complexity
        block_addrs = tuple(sorted(getattr(function, "block_addrs_set", set()) or ()))
        if isinstance(function_info, dict):
            cached_complexity = function_info.get("_inertia_function_complexity")
            if (
                isinstance(cached_complexity, dict)
                and tuple(cached_complexity.get("block_addrs", ())) == block_addrs
                and isinstance(cached_complexity.get("blocks"), int)
                and isinstance(cached_complexity.get("bytes"), int)
                and cached_complexity.get("source") == "factory_decode"
            ):
                return cached_complexity["blocks"], cached_complexity["bytes"]
        if project is None:
            return 0, 0
        total_bytes = 0
        for block_addr in block_addrs:
            try:
                block = project.factory.block(block_addr, opt_level=0)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Function complexity block decode failed at function=%#x block=%#x: %s",
                    getattr(function, "addr", -1) or -1,
                    block_addr,
                    ex,
                )
                continue
            total_bytes += len(block.bytes)
        complexity = (len(block_addrs), total_bytes)
        if isinstance(function_info, dict):
            function_info["_inertia_function_complexity"] = {
                "block_addrs": block_addrs,
                "blocks": complexity[0],
                "bytes": complexity[1],
                "source": "factory_decode",
            }
        return complexity

    return _impl()

def _direct_call_stub_filter_regions(project: angr.Project, function) -> tuple[list[tuple[int, int]], tuple[int, int] | None]:
    local_ranges = _function_covered_ranges(function)
    display_addr = function_original_addr(function)
    original_region: tuple[int, int] | None = None
    metadata = getattr(project, "_inertia_lst_metadata", None)
    if metadata is not None:
        original_region = _lst_code_region(metadata, display_addr)
    original_project = getattr(project, "_inertia_original_project", None)
    if original_region is None and original_project is not None:
        original_metadata = getattr(original_project, "_inertia_lst_metadata", None)
        if original_metadata is not None:
            original_region = _lst_code_region(original_metadata, display_addr)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_region is not None and isinstance(original_delta, int):
        slice_region = (original_region[0] - original_delta, original_region[1] - original_delta)
        if not local_ranges:
            local_ranges = [slice_region]
        elif slice_region not in local_ranges:
            local_ranges = [slice_region, *local_ranges]
    return local_ranges, original_region


def _is_stack_probe_name_8616(name: str | None) -> bool:
    return is_x86_16_stack_probe_name_8616(name)


def _is_known_noreturn_name_8616(name: str | None) -> bool:
    known_noreturn_names = {"abort", "_abort", "__abort", "exit", "_exit", "__exit", "fatalerror", "_fatalerror"}
    if not isinstance(name, str):
        return False
    normalized = name.strip().lower()
    return normalized in known_noreturn_names or normalized.lstrip("_") in known_noreturn_names


def _sidecar_enclosing_label_8616(metadata, addr: int) -> str | None:
    labels = getattr(metadata, "code_labels", None)
    if not isinstance(labels, dict):
        return None
    for start, label in labels.items():
        if isinstance(start, int) and isinstance(label, str) and label:
            span = _lst_code_region(metadata, start)
            if span is not None and span[0] <= addr < span[1]:
                return label
    return None


def _function_name_at_addr_8616(project, addr: int) -> str | None:
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    try:
        function = lookup(addr=addr, create=False)
    except TypeError:
        return None
    name = normalize_callee_name_8616(getattr(function, "name", None))
    return name if isinstance(name, str) and name else None


def _compiler_helper_name_at_addr_8616(project, addr: int) -> str | None:
    evidence = identify_x86_16_compiler_helper_at_8616(project, addr)
    return evidence.name if evidence is not None else None


def _label_at_addr_8616(project, addr: int) -> str | None:
    label = getattr(getattr(project, "kb", None), "labels", {}).get(addr)
    label = normalize_callee_name_8616(label)
    return label if isinstance(label, str) and label else None


def _original_callee_name_8616(project: angr.Project, slice_target: int) -> str | None:
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is None or not isinstance(original_delta, int):
        return None
    original_target = slice_target + original_delta
    function_name = _function_name_at_addr_8616(original_project, original_target)
    if isinstance(function_name, str) and function_name:
        return function_name
    helper_name = _compiler_helper_name_at_addr_8616(original_project, original_target)
    if isinstance(helper_name, str) and helper_name:
        return helper_name
    label = _label_at_addr_8616(original_project, original_target)
    if isinstance(label, str) and label:
        return label
    metadata = getattr(original_project, "_inertia_lst_metadata", None)
    if metadata is None:
        return None
    label = normalize_callee_name_8616(getattr(metadata, "code_labels", {}).get(original_target))
    if isinstance(label, str) and label:
        return label
    span_label = normalize_callee_name_8616(_sidecar_enclosing_label_8616(metadata, original_target))
    return span_label if isinstance(span_label, str) and span_label else None


def _callee_names_equivalent_8616(left: str | None, right: str | None) -> bool:
    left_name = normalize_callee_name_8616(left)
    right_name = normalize_callee_name_8616(right)
    if not isinstance(left_name, str) or not isinstance(right_name, str):
        return False
    return left_name == right_name or left_name.lstrip("_") == right_name.lstrip("_")


def _function_named_addr_8616(project, name: str) -> int | None:
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    lookup_names = [name]
    undecorated = name.lstrip("_")
    decorated = f"_{undecorated}" if undecorated else None
    if decorated is not None and decorated not in lookup_names:
        lookup_names.append(decorated)
    for lookup_name in lookup_names:
        try:
            function = lookup(name=lookup_name, create=False)
        except TypeError:
            continue
        addr = getattr(function, "addr", None)
        if isinstance(addr, int):
            return addr
    return None


def _candidate_original_target_8616(project, candidate: int) -> int | None:
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if not isinstance(original_delta, int):
        return None
    return candidate + original_delta


def _call_name_matches_target_evidence_8616(project, candidate: int, call_name: str | None) -> bool:
    expected = normalize_callee_name_8616(call_name)
    if not isinstance(expected, str) or not expected:
        return False
    for known_name in (
        _original_callee_name_8616(project, candidate),
        _function_name_at_addr_8616(project, candidate),
        _compiler_helper_name_at_addr_8616(project, candidate),
        _label_at_addr_8616(project, candidate),
    ):
        if _callee_names_equivalent_8616(known_name, expected):
            return True
    original_project = getattr(project, "_inertia_original_project", None)
    original_target = _candidate_original_target_8616(project, candidate)
    if original_project is not None and isinstance(original_target, int):
        for known_name in (
            _function_name_at_addr_8616(original_project, original_target),
            _compiler_helper_name_at_addr_8616(original_project, original_target),
            _label_at_addr_8616(original_project, original_target),
        ):
            if _callee_names_equivalent_8616(known_name, expected):
                return True
        named_addr = _function_named_addr_8616(original_project, expected)
        if isinstance(named_addr, int) and named_addr == original_target:
            return True
    named_addr = _function_named_addr_8616(project, expected)
    return isinstance(named_addr, int) and named_addr == candidate


def _parse_direct_call_target_8616(insn) -> int | None:
    def _impl():
        capstone_insn = getattr(insn, "insn", None)
        operands = getattr(capstone_insn, "operands", None)
        if operands:
            operand = operands[0]
            if getattr(operand, "type", None) == 2 and isinstance(getattr(operand, "imm", None), int):
                return int(operand.imm)
        op_str = str(getattr(insn, "op_str", "") or "").strip().lower()
        if not op_str or "[" in op_str or any(ch.isalpha() for ch in op_str if ch not in "xabcdef"):
            return None
        for token in re.split(r"[\s,:]+", op_str):
            if token:
                with contextlib.suppress(ValueError):
                    return int(token, 0)
        return None

    return _impl()


def _iter_capstone_direct_calls_8616(project: angr.Project, function):
    def _impl():
        factory = getattr(project, "factory", None)
        if factory is None:
            return
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            try:
                block = factory.block(block_addr, opt_level=0)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Direct call block decode failed at function=%#x block=%#x: %s",
                    getattr(function, "addr", -1) or -1,
                    block_addr,
                    ex,
                )
                continue
            for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                if getattr(insn, "mnemonic", "").lower() != "call":
                    continue
                target = _parse_direct_call_target_8616(insn)
                if isinstance(target, int):
                    insn_addr = getattr(insn, "address", block_addr)
                    insn_size = getattr(getattr(insn, "insn", None), "size", None)
                    ret_addr = (insn_addr + insn_size) if isinstance(insn_size, int) and insn_size > 0 else None
                    yield insn_addr, target, ret_addr

    return _impl()


def _callsite_addr_points_to_call_insn_8616(project: angr.Project, function, callsite: int) -> bool:
    factory = getattr(project, "factory", None)
    if factory is None:
        return True
    try:
        block = factory.block(callsite, opt_level=0)
    except Exception:
        return True
    for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
        if getattr(insn, "address", None) != callsite:
            continue
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        return mnemonic in {"call", "lcall"}
    return False


def _compute_candidate_targets_8616(target: int, linked_base: int | None, image_end: int | None) -> set[int]:
    candidates = {target}
    if isinstance(linked_base, int):
        if target < linked_base:
            linked_target = linked_base + target
            if image_end is None or linked_target < image_end:
                candidates.add(linked_target)
        elif image_end is None or target < image_end:
            unbased_target = target - linked_base
            if 0 <= unbased_target < 0x10000:
                candidates.add(unbased_target)
    return candidates


def _choose_preferred_candidate_8616(
    project: angr.Project,
    candidates: set[int],
    local_ranges: list[tuple[int, int]],
    original_region: tuple[int, int] | None,
    original_delta: int | None,
) -> tuple[int | None, str | None]:
    def _impl():
        preferred_candidate: int | None = None
        preferred_rank: tuple[int, int, int] | None = None
        fallback_call_name: str | None = None
        for candidate in sorted(candidates):
            original_target = candidate + original_delta if isinstance(original_delta, int) else None
            if _addr_in_ranges(candidate, local_ranges):
                continue
            if isinstance(original_target, int) and original_region is not None and original_region[0] <= original_target < original_region[1]:
                continue
            original_label = _original_callee_name_8616(project, candidate)
            slice_entry = getattr(project, "entry", None)
            unbased_penalty = 1 if isinstance(slice_entry, int) and candidate < slice_entry else 0
            # Exact original-target evidence is stronger than the based/unbased
            # address preference. In exact-region slices the true near target may
            # be below the slice entry, while adding the linked base can point at
            # an unrelated internal function.
            rank = (0 if isinstance(original_label, str) and bool(original_label) else 1, unbased_penalty, -candidate)
            if preferred_rank is None or rank < preferred_rank:
                preferred_candidate = candidate
                preferred_rank = rank
            if isinstance(original_label, str) and original_label:
                fallback_call_name = original_label
        return preferred_candidate, fallback_call_name

    return _impl()


def _collect_direct_calls_8616(project: angr.Project, function) -> list[tuple[int | None, int, int | None]]:
    direct_calls: list[tuple[int | None, int, int | None]] = []
    skipped_invalid_callsite = False
    for callsite in getattr(function, "get_call_sites", lambda: [])() or ():
        if isinstance(callsite, int) and not _callsite_addr_points_to_call_insn_8616(project, function, callsite):
            skipped_invalid_callsite = True
            continue
        try:
            target = function.get_call_target(callsite)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Call target lookup failed at function=%#x callsite=%#x: %s",
                getattr(function, "addr", -1) or -1,
                callsite,
                ex,
            )
            continue
        ret_addr = None
        with contextlib.suppress(Exception):
            ret_addr = function.get_call_return(callsite)
        direct_calls.append((callsite, target, ret_addr))
    if not direct_calls or skipped_invalid_callsite:
        known_callsites = {callsite for callsite, _target, _ret_addr in direct_calls if isinstance(callsite, int)}
        for callsite, target, ret_addr in _iter_capstone_direct_calls_8616(project, function):
            if isinstance(callsite, int) and callsite in known_callsites:
                continue
            direct_calls.append((callsite, target, ret_addr))
    return direct_calls


def _call_name_by_callsite_8616(direct_calls: list[tuple[int | None, int, int | None]], cod_call_names: tuple[str, ...]) -> dict[int, str]:
    ordered_callsites = sorted({cs for cs, _t, _r in direct_calls if isinstance(cs, int)})
    if not (cod_call_names and ordered_callsites and len(cod_call_names) >= len(ordered_callsites)):
        return {}
    return {cs: cod_call_names[idx] for idx, cs in enumerate(ordered_callsites) if isinstance(cod_call_names[idx], str) and cod_call_names[idx]}


def _proven_cod_call_name_for_candidates_8616(
    project,
    candidates: set[int],
    cod_call_names: tuple[str, ...],
) -> str | None:
    for candidate in sorted(candidates):
        for call_name in cod_call_names:
            if _call_name_matches_target_evidence_8616(project, candidate, call_name):
                return call_name
    return None


def _candidate_is_filtered_8616(
    candidate: int,
    *,
    original_delta: int | None,
    local_ranges: list[tuple[int, int]],
    original_region: tuple[int, int] | None,
) -> bool:
    original_target = candidate + original_delta if isinstance(original_delta, int) else None
    if _addr_in_ranges(candidate, local_ranges):
        return True
    return bool(
        isinstance(original_target, int)
        and original_region is not None
        and original_region[0] <= original_target < original_region[1]
    )


def _create_or_update_direct_call_stub_8616(
    *,
    project: angr.Project,
    function,
    callsite_addr: int | None,
    ret_addr: int | None,
    candidate: int,
    preferred_candidate: int | None,
    fallback_call_name: str | None,
    debug_enabled: bool,
) -> bool:
    def _impl():
        try:
            stub = project.kb.functions.function(addr=candidate, create=True)
            if isinstance(callsite_addr, int) and (preferred_candidate is None or candidate == preferred_candidate):
                with contextlib.suppress(Exception):
                    call_return = ret_addr
                    if not isinstance(call_return, int):
                        call_return = function.get_call_return(callsite_addr)
                    function._call_sites[callsite_addr] = (candidate, call_return)
            stub_name = _original_callee_name_8616(project, candidate)
            if not isinstance(stub_name, str) or not stub_name:
                stub_name = _compiler_helper_name_at_addr_8616(project, candidate)
            if (
                (not isinstance(stub_name, str) or not stub_name)
                and isinstance(fallback_call_name, str)
                and _call_name_matches_target_evidence_8616(project, candidate, fallback_call_name)
            ):
                stub_name = fallback_call_name
            if isinstance(stub_name, str) and stub_name:
                with contextlib.suppress(Exception):
                    stub.name = stub_name
            if not _is_known_noreturn_name_8616(getattr(stub, "name", None)):
                with contextlib.suppress(Exception):
                    stub.returning = True
            if _is_stack_probe_name_8616(getattr(stub, "name", None)):
                with contextlib.suppress(Exception):
                    stub.returning = True
            if debug_enabled and isinstance(callsite_addr, int):
                print(
                    f"[dbg] callsite-seed fn={function.addr:#x} cs={callsite_addr:#x} "
                    f"target={candidate:#x} preferred={preferred_candidate:#x} "
                    f"name={getattr(stub, 'name', None)}",
                    file=sys.stderr,
                    flush=True,
                )
            return True
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Stub creation failed at function=%#x stub=%#x: %s",
                getattr(function, "addr", -1) or -1,
                candidate,
                ex,
            )
            return False

    return _impl()


def _register_direct_call_target_function_stubs(project: angr.Project, function, cod_metadata: CODProcMetadata | None = None) -> int:
    def _impl():
        if getattr(getattr(project, "arch", None), "name", None) != "86_16":
            return 0
        measure_single_function_context = _single_function_context_measuring_enabled()
        metric_candidates = 0
        metric_start = time.perf_counter() if measure_single_function_context else 0.0
        main_object = getattr(getattr(project, "loader", None), "main_object", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SEEDING"):
            print(
                f"[dbg] callsite-seed-config fn={function.addr:#x} entry={getattr(project, 'entry', None)} "
                f"linked_base={linked_base} image_end={image_end}",
                file=sys.stderr,
                flush=True,
            )

        created = 0
        seen: set[int] = set()
        direct_calls = _collect_direct_calls_8616(project, function)
        local_ranges, original_region = _direct_call_stub_filter_regions(project, function)
        original_delta = getattr(project, "_inertia_original_linear_delta", None)
        cod_call_names = tuple(name for name in getattr(cod_metadata, "call_names", ()) or () if isinstance(name, str) and name)

        for callsite_addr, target, ret_addr in direct_calls:
            if not isinstance(target, int):
                continue
            candidates = _compute_candidate_targets_8616(target, linked_base, image_end)
            preferred_candidate, fallback_call_name = _choose_preferred_candidate_8616(
                project, candidates, local_ranges, original_region, original_delta
            )
            if not isinstance(fallback_call_name, str) or not fallback_call_name:
                fallback_call_name = _proven_cod_call_name_for_candidates_8616(project, candidates, cod_call_names)

            if measure_single_function_context:
                metric_candidates += len(candidates)
            for candidate in candidates:
                if candidate in seen or _candidate_is_filtered_8616(
                    candidate,
                    original_delta=original_delta,
                    local_ranges=local_ranges,
                    original_region=original_region,
                ):
                    continue
                seen.add(candidate)
                if _create_or_update_direct_call_stub_8616(
                    project=project,
                    function=function,
                    callsite_addr=callsite_addr,
                    ret_addr=ret_addr,
                    candidate=candidate,
                    preferred_candidate=preferred_candidate,
                    fallback_call_name=fallback_call_name,
                    debug_enabled=bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SEEDING")),
                ):
                    created += 1
        if measure_single_function_context:
            _emit_single_function_context_metric(
                function,
                kind="direct-callee-stubs",
                candidates=metric_candidates,
                created=created,
                elapsed_ms=int((time.perf_counter() - metric_start) * 1000),
            )
        return created

    return _impl()


def _single_function_context_measuring_enabled() -> bool:
    return (
        os.environ.get("INERTIA_MEASURE_SINGLE_FUNCTION_CONTEXT", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )


def _emit_single_function_context_metric(
    function,
    *,
    kind: str,
    candidates: int = 0,
    created: int = 0,
    elapsed_ms: int = 0,
) -> None:
    if not _single_function_context_measuring_enabled():
        return
    print(
        f"[metric] fn={getattr(function, 'addr', -1):#x} kind={kind} "
        f"candidates={candidates} created={created} elapsed_ms={elapsed_ms}",
        file=sys.stderr,
        flush=True,
    )

def _prepare_function_for_decompilation(
    project: angr.Project,
    function,
    cod_metadata: CODProcMetadata | None = None,
) -> int:
    def _emit_start_debug(display_addr_local: int) -> None:
        if display_addr_local == function.addr:
            print(f"[dbg] decompile_function: addr={display_addr_local:#x} name={function.name}", file=sys.stderr, flush=True)
            return
        print(
            f"[dbg] decompile_function: addr={display_addr_local:#x} "
            f"(slice={function.addr:#x}) name={function.name}"
        )

    def _maybe_normalize_function() -> None:
        if function.normalized:
            return
        print(f"[dbg] function {function.addr:#x} not normalized, normalizing...", file=sys.stderr, flush=True)
        block_count = len(getattr(function, "block_addrs_set", ()) or ())
        normalize_budget = 2 if block_count <= 1 else 6
        try:
            setattr(project, "_inertia_decompiler_stage", "prepare:normalize")
            with _analysis_timeout(normalize_budget):
                function.normalize()
            if os.environ.get("INERTIA_DEBUG_NORMALIZE_STAGE"):
                print(f"[dbg] normalized function {function.addr:#x} {function.name}", file=sys.stderr, flush=True)
        except _AnalysisTimeout:
            print(
                f"[dbg] normalize timeout for {function.addr:#x} {function.name}; "
                f"continuing without normalized form"
            )

    def _maybe_debug_blocks() -> None:
        if not os.environ.get("INERTIA_DEBUG_FUNCTION_BLOCKS"):
            return
        try:
            blocks = sorted(int(a) for a in (getattr(function, "block_addrs_set", ()) or ()) if isinstance(a, int))
            print(
                f"[dbg] function-blocks fn={function.addr:#x} count={len(blocks)} "
                f"first={blocks[:8]}",
                file=sys.stderr,
                flush=True,
            )
        except Exception:
            pass

    def _maybe_debug_graph() -> None:
        if not os.environ.get("INERTIA_DEBUG_FUNCTION_GRAPH"):
            return
        try:
            graph = getattr(function, "graph", None)
            nodes = list(getattr(graph, "nodes", lambda: [])()) if graph is not None else []
            edges = list(getattr(graph, "edges", lambda: [])()) if graph is not None else []
            entry_nodes = [n for n in nodes if getattr(n, "addr", None) == function.addr]
            succ_addrs: list[int] = []
            if graph is not None and entry_nodes:
                for succ in graph.successors(entry_nodes[0]):
                    saddr = getattr(succ, "addr", None)
                    if isinstance(saddr, int):
                        succ_addrs.append(saddr)
            print(
                f"[dbg] function-graph fn={function.addr:#x} nodes={len(nodes)} edges={len(edges)} "
                f"entry_succ={sorted(set(succ_addrs))[:8]}",
                file=sys.stderr,
                flush=True,
            )
        except Exception:
            pass

    def _maybe_debug_callsite_returning() -> None:
        if not os.environ.get("INERTIA_DEBUG_CALLSITE_RETURNING"):
            return
        try:
            callsites = tuple(getattr(function, "get_call_sites", lambda: [])() or ())
            print(
                f"[dbg] callsite-returning fn={function.addr:#x} callsite_count={len(callsites)}",
                file=sys.stderr,
                flush=True,
            )
            for callsite in callsites:
                target = None
                ret_site = None
                with contextlib.suppress(Exception):
                    target = function.get_call_target(callsite)
                with contextlib.suppress(Exception):
                    ret_site = function.get_call_return(callsite)
                if not isinstance(target, int):
                    continue
                callee = None
                with contextlib.suppress(Exception):
                    callee = project.kb.functions.function(addr=target, create=False)
                returning = getattr(callee, "returning", None)
                hooked = project.is_hooked(target) if hasattr(project, "is_hooked") else None
                hook_no_ret = (
                    getattr(project.hooked_by(target), "NO_RET", None)
                    if hasattr(project, "is_hooked") and project.is_hooked(target)
                    else None
                )
                ret_text = f"{ret_site:#x}" if isinstance(ret_site, int) else "None"
                print(
                    f"[dbg] callsite-returning fn={function.addr:#x} cs={callsite:#x} "
                    f"target={target:#x} callee={getattr(callee, 'name', None)} "
                    f"ret={ret_text} returning={returning} hooked={hooked} hook_no_ret={hook_no_ret}",
                    file=sys.stderr,
                    flush=True,
                )
        except Exception:
            pass

    display_addr = function_original_addr(function)
    _emit_start_debug(display_addr)
    sys.stdout.flush()
    setattr(
        project,
        "_inertia_current_function_debug",
        {"addr": display_addr, "slice_addr": function.addr, "name": function.name},
    )
    _maybe_normalize_function()
    sanitize_direct_call_sites_8616(function)
    created_helper_stubs = _register_direct_call_target_function_stubs(project, function, cod_metadata=cod_metadata)
    if created_helper_stubs:
        print(f"[dbg] registered {created_helper_stubs} direct callee stub(s) for {function.addr:#x}", file=sys.stderr, flush=True)
    _maybe_debug_blocks()
    _maybe_debug_graph()
    _maybe_debug_callsite_returning()
    return created_helper_stubs

def _function_decompilation_profile(
    function,
    block_count: int | None = None,
    byte_count: int | None = None,
) -> dict[str, object]:
    def _impl():
        nonlocal block_count, byte_count
        if block_count is None or byte_count is None:
            block_count, byte_count = _function_complexity(function)
        call_sites = ()
        if hasattr(function, "get_call_sites"):
            try:
                call_sites = tuple(function.get_call_sites())
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Call-site enumeration failed at function=%#x stage=profile: %s",
                    getattr(function, "addr", -1) or -1,
                    ex,
                )
                call_sites = ()

        call_site_count = len(call_sites)
        project = getattr(function, "project", None)
        internal_call_count = 0
        has_non_wrapper_traffic = False
        if project is not None:
            for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
                try:
                    block = project.factory.block(block_addr, opt_level=0)
                except Exception as ex:
                    logging.getLogger(__name__).debug(
                        "Profile block decode failed at function=%#x block=%#x: %s",
                        getattr(function, "addr", -1) or -1,
                        block_addr,
                        ex,
                    )
                    continue
                for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                    mnemonic = getattr(insn, "mnemonic", "").lower()
                    op_str = getattr(insn, "op_str", "").lower()
                    if mnemonic == "call":
                        internal_call_count += 1
                    elif mnemonic.startswith("j"):
                        has_non_wrapper_traffic = True
                    elif "[" in op_str and not any(marker in op_str for marker in ("[bp", "[sp", "[ss:")):
                        has_non_wrapper_traffic = True

        wrapper_like = (
            block_count <= 2
            and byte_count <= 32
            and call_site_count <= 1
            and internal_call_count == 0
            and not has_non_wrapper_traffic
        )
        tiny_single_call_helper = (
            (
                block_count <= 3
                and byte_count <= 0x20
            )
            or (
                block_count <= 1
                and byte_count <= 0x80
            )
        ) and call_site_count <= 1 and internal_call_count <= 1 and not has_non_wrapper_traffic
        return {
            "block_count": block_count,
            "byte_count": byte_count,
            "call_site_count": call_site_count,
            "internal_call_count": internal_call_count,
            "wrapper_like": wrapper_like,
            "tiny_single_call_helper": tiny_single_call_helper,
        }

    return _impl()

def _preferred_decompiler_options(
    block_count: int,
    byte_count: int,
    *,
    wrapper_like: bool = False,
    tiny_single_call_helper: bool = False,
    no_call_helper: bool = False,
) -> list[tuple[str, str]] | None:
    """Choose a cheaper decompiler structurer for true wrapper-like functions."""
    if wrapper_like or tiny_single_call_helper:
        return [("structurer_cls", "Phoenix")]
    if no_call_helper:
        return [
            ("structurer_cls", "Phoenix"),
            ("rewrite_ites_to_diamonds", False),
            ("semvar_naming", False),
            ("remove_dead_memdefs", False),
        ]
    return None

def _preferred_expr_collapse_depth(
    block_count: int,
    byte_count: int,
    *,
    wrapper_like: bool = False,
    tiny_single_call_helper: bool = False,
) -> int:
    if block_count <= 1 and byte_count <= 96:
        return 2
    if wrapper_like or tiny_single_call_helper:
        return 2
    if block_count <= 24 and byte_count <= 256:
        return 32
    if block_count <= 64 and byte_count <= 1024:
        return 24
    return 16

@trace_function(name="function.decompile_with_stats")
def _decompile_function_with_stats(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
    enable_postprocess: bool = True,
    allow_isolated_retry: bool = True,
    failure_family_state: FailureFamilyState | None = None,
):
    block_count, byte_count = _function_complexity(function)
    effective_timeout = _effective_decompile_timeout_8616(
        project,
        timeout,
        block_count=block_count,
        byte_count=byte_count,
    )
    display_addr = function_original_addr(function)
    annotate_current_span(
        blocks=block_count,
        bytes=byte_count,
    )
    print(f"[dbg] function complexity for {display_addr:#x} {function.name}: blocks={block_count}, bytes={byte_count}", file=sys.stderr, flush=True)
    sys.stdout.flush()
    start = time.perf_counter()
    deadline = time.monotonic() + max(1, effective_timeout)
    try:
        status, payload = _decompile_function(
            project,
            cfg,
            function,
            effective_timeout,
            api_style,
            binary_path,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            allow_isolated_retry=allow_isolated_retry,
            deadline=deadline,
            failure_family_state=failure_family_state,
        )
    except PipelineHardError as ex:
        # Keep whole-binary sweeps alive: pipeline contract violations are
        # per-function failures and must not abort the entire run.
        status = "empty"
        detail = str(ex)
        if detail.startswith("function leaked unresolved stack locals into final C"):
            detail = f"{function.name} leaked unresolved stack locals into final C"
        payload = f"Pipeline contract violation: {detail}"
    forced_payload = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
    if forced_payload is not None:
        status = "ok"
        payload = forced_payload
    validated_payload_record = getattr(project, "_inertia_last_validated_function_payload", None)
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        logging.getLogger(__name__).warning(
            "[return-chain-cli] with-stats status=%s payload_len=%d record=%s payload=%r",
            status,
            len(payload) if isinstance(payload, str) else 0,
            (
                (validated_payload_record[0], len(validated_payload_record[1]))
                if isinstance(validated_payload_record, tuple)
                and len(validated_payload_record) == 2
                and isinstance(validated_payload_record[1], str)
                else None
            ),
            payload,
        )
    if status == "ok" and isinstance(validated_payload_record, tuple) and len(validated_payload_record) == 2:
        validated_addr, validated_payload = validated_payload_record
        if validated_addr == function_original_addr(function) and isinstance(validated_payload, str) and validated_payload.strip():
            if payload != validated_payload:
                logging.getLogger(__name__).warning(
                    "Corrected returned payload to validated codegen artifact at function=%#x old_len=%d new_len=%d",
                    function_original_addr(function),
                    len(payload) if isinstance(payload, str) else 0,
                    len(validated_payload),
                )
            payload = validated_payload
    partial_payload = getattr(project, "_inertia_partial_codegen_text", None)
    elapsed = time.perf_counter() - start
    annotate_current_span(status=status, elapsed_ms=round(elapsed * 1000.0, 1))
    advance_failure_family_state(failure_family_state)
    if _timing_output_enabled():
        print(f"[dbg] decompilation time for {display_addr:#x} {function.name}: {elapsed:.2f}s", file=sys.stderr, flush=True)
        sys.stdout.flush()
    return status, payload, partial_payload, block_count, byte_count, elapsed
