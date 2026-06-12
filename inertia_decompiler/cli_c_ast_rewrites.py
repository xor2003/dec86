from __future__ import annotations

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

from concurrent.futures import FIRST_COMPLETED, Future, TimeoutError as FuturesTimeoutError, wait

from dataclasses import dataclass, replace

from pathlib import Path

from types import SimpleNamespace

import angr
from angr.analyses.decompiler import structured_codegen
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.analysis_helpers import (
    collect_dos_int21_calls,
    collect_interrupt_service_calls,
    dos_helper_declarations,
    interrupt_service_addr,
    interrupt_service_declarations,
    preferred_known_helper_signature_decl,
    render_dos_int21_call,
    render_interrupt_call,
)
from angr_platforms.X86_16.annotations import _normalize_bp_disp, annotate_function
from angr_platforms.X86_16.alias.alias_model_impl import (
    _CopyAliasState,
    _StackPointerAliasState,
    _stack_slot_identity_for_variable,
)
from angr_platforms.X86_16.alias.state import AliasState
from angr_platforms.X86_16.alias_domains import DomainKey, register_pair_name
from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.cod_source_rewrites import rewrite_cod_proc_from_source as _rewrite_cod_proc_from_source
from angr_platforms.X86_16.lowering.segmented_lowering import _SegmentedAccess
from angr_platforms.X86_16.lst_extract import LSTMetadata
from angr_platforms.X86_16.widening.register_widening import (
    can_join_adjacent_register_slices,
    join_adjacent_register_slices,
)
from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices
from angr_platforms.X86_16.semantics.alias_query import _storage_domain_for_expr, _storage_domain_for_variable, describe_alias_storage

structured_c = structured_codegen.c

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
from inertia_decompiler.cli_linear_recurrence_state import LinearRecurrenceState as _LinearRecurrenceState

_AccessTraitEvidenceProfile = _cli_access_profiles.AccessTraitEvidenceProfile
_AccessTraitStrideEvidence = _cli_access_profiles.AccessTraitStrideEvidence

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

print = _timestamped_print
__all__ = ['_attach_cod_callee_names', '_build_cod_positive_bp_alias_map', '_cod_stack_alias_for_disp', '_attach_cod_variable_names', '_synthetic_global_entry', '_sanitize_cod_identifier', '_get_or_seed_inertia_alias_state', '_make_unique_identifier', '_structured_codegen_node', '_c_constant_value', '_normalize_16bit_signed_offset', '_project_rewrite_cache', '_CODSourceRewriteSpec', '_segment_reg_name', '_classify_segmented_addr_expr', '_classify_segmented_dereference', '_match_real_mode_linear_expr', '_match_segmented_dereference', '_match_segment_register_based_dereference', '_strip_segment_scale_from_addr_expr', '_match_ss_stack_reference', '_flatten_c_add_terms', '_resolve_dirty_virtual_expr_8616', '_match_stack_cvar_and_offset', '_match_ss_local_plus_const', '_replace_c_children', '_iter_c_nodes_deep', '_same_c_expression', '_same_c_storage', '_same_stack_slot_identity', '_stack_slot_identity_can_join', '_is_c_constant_int', '_cite_is_negation', '_invert_comparison_op', '_make_inverted_comparison', '_invert_interval_guard_if_safe', '_extract_same_zero_compare_expr', '_extract_zero_flag_source_expr', '_simplify_zero_flag_comparison', '_match_high_byte_projection_base', '_match_adjacent_register_pair_var_expr', '_match_high_byte_projection_expr', '_match_high_byte_projection_constant', '_simplify_boolean_expr', '_simplify_zero_mul_or_expr', '_simplify_basic_algebraic_identities', '_simplify_structured_c_expressions', '_unwrap_c_casts', '_match_shift_right_8_expr', '_match_duplicate_word_increment_shift_expr', '_match_duplicate_word_base_expr', '_attach_cod_global_names', '_attach_cod_global_declaration_names', '_attach_cod_global_declaration_types', '_access_trait_field_name', '_stack_object_name', '_access_trait_variable_key', '_access_trait_profile_for_key', '_WideningMatch', '_AccessTraitRewriteDecision', '_build_access_trait_evidence_profiles', '_analyze_widening_expr', '_access_trait_member_candidates', '_should_attach_access_trait_names', '_attach_access_trait_field_names', '_attach_pointer_member_names', '_attach_lst_data_names', '_normalize_scalar_byte_register_types', '_attach_segment_register_names', '_attach_register_names', '_elide_redundant_segment_pointer_dereferences', '_collect_access_traits', '_prune_unused_unnamed_memory_declarations', '_prune_unused_linear_register_declarations', '_prune_unused_local_declarations', '_prune_dead_local_assignments', '_materialize_missing_stack_local_declarations', '_dedupe_codegen_variable_names_8616', '_materialize_missing_register_local_declarations', '_prune_void_function_return_values', '_coalesce_far_pointer_stack_expressions', '_simplify_nested_mk_fp_calls', '_attach_ss_stack_variables', '_rewrite_ss_stack_byte_offsets', '_promote_direct_stack_cvariable', '_stack_type_for_size', '_resolve_stack_cvar_at_offset', '_materialize_stack_cvar_at_offset', '_canonicalize_stack_cvar_expr', '_canonicalize_stack_cvars', '_resolve_stack_cvar_from_addr_expr', '_coalesce_direct_ss_local_word_statements', '_seed_adjacent_byte_pair_aliases', '_coalesce_linear_recurrence_statements', '_coalesce_segmented_word_store_statements', '_run_typed_widening_pass', '_global_memory_addr', '_global_load_addr', '_match_scaled_high_byte', '_extract_dereference_addr_expr', '_match_byte_load_addr_expr', '_match_byte_store_addr_expr', '_match_shifted_high_byte_addr_expr', '_match_word_pair_low_addr_expr', '_split_expr_const_offset', '_same_expression_list', '_addr_exprs_are_same', '_addr_exprs_are_byte_pair', '_make_word_dereference_from_addr_expr', '_match_word_dereference_addr_expr', '_match_word_rhs_from_byte_pair', '_high_byte_store_addr', '_synthetic_word_global_variable', '_coalesce_cod_word_global_loads', '_coalesce_segmented_word_load_expressions', '_coalesce_cod_word_global_statements', '_int21_call_replacements', '_interrupt_call_replacement_map', '_dos_helper_declarations', '_interrupt_helper_declarations', '_known_helper_declarations', '_is_staging_local_name', '_clone_structured_c_value', '_prune_tiny_wrapper_staging_locals']

def _helper_name(project, addr: int) -> str | None:
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

def _attach_cod_callee_names(project: angr.Project, codegen, cod_metadata: CODProcMetadata | None) -> bool:
    def _impl():
        if cod_metadata is None or not cod_metadata.call_names or getattr(codegen, "cfunc", None) is None:
            return False

        call_nodes = [
            node
            for node in _iter_c_nodes_deep(codegen.cfunc.statements)
            if isinstance(node, structured_c.CFunctionCall)
            and (
                getattr(node, "callee_func", None) is None
                or getattr(node.callee_func, "name", "").startswith("sub_")
                or getattr(node.callee_func, "name", "") == "CallReturn"
            )
        ]
        if not call_nodes:
            return False

        changed = False
        for node, call_name in zip(call_nodes, cod_metadata.call_names):
            callee_func = getattr(node, "callee_func", None)
            if callee_func is None:
                target = getattr(node, "callee_target", None)
                if isinstance(target, int):
                    callee_func = project.kb.functions.function(addr=target)
                    node.callee_func = callee_func
            if callee_func is None:
                continue
            if getattr(callee_func, "name", None) != call_name:
                callee_func.name = call_name
                changed = True
            decl = preferred_known_helper_signature_decl(call_name)
            if decl is not None:
                annotate_function(
                    project,
                    callee_func.addr,
                    name=call_name,
                    c_decl=decl,
                )
        return changed

    return _impl()

def _build_cod_positive_bp_alias_map(
    bp_disps: list[int], cod_metadata: CODProcMetadata | None
) -> dict[int, str]:
    def _impl():
        if cod_metadata is None:
            return {}

        meta_positive = sorted((disp, name) for disp, name in cod_metadata.stack_aliases.items() if disp > 0)
        if not meta_positive:
            return {}

        var_positive = sorted(disp for disp in bp_disps if disp > 0)
        if not var_positive:
            return {}

        alias_map: dict[int, str] = {}
        for disp in var_positive:
            direct = cod_metadata.stack_aliases.get(disp)
            if direct is not None:
                alias_map[disp] = direct

        unmatched_var_positive = [disp for disp in var_positive if disp not in alias_map]
        unused_meta_positive = [item for item in meta_positive if item[1] not in alias_map.values()]
        if len(unmatched_var_positive) <= len(unused_meta_positive):
            for disp, (_, name) in zip(unmatched_var_positive, unused_meta_positive):
                alias_map[disp] = name

        return alias_map

    return _impl()

def _cod_stack_alias_for_disp(
    disp: int,
    cod_metadata: CODProcMetadata | None,
    *,
    positive_aliases: dict[int, str] | None = None,
    normalized_aliases: dict[int, str] | None = None,
) -> str | None:
    if cod_metadata is None:
        return None
    if disp < 0:
        alias = cod_metadata.stack_aliases.get(disp)
        if alias is not None:
            return alias
    if normalized_aliases is not None:
        alias = normalized_aliases.get(disp)
        if alias is not None:
            return alias
    if disp > 0 and positive_aliases is not None:
        alias = positive_aliases.get(disp)
        if alias is not None:
            return alias
    return cod_metadata.stack_aliases.get(disp)


def _build_cod_normalized_bp_alias_map(cod_metadata: CODProcMetadata | None) -> dict[int, str]:
    if cod_metadata is None:
        return {}
    aliases = getattr(cod_metadata, "stack_aliases", None)
    if not isinstance(aliases, dict):
        return {}
    normalized: dict[int, str] = {}
    for bp_disp, alias in aliases.items():
        if isinstance(bp_disp, int) and isinstance(alias, str) and alias:
            normalized.setdefault(_normalize_bp_disp(bp_disp), alias)
    return normalized


def _collect_cod_name_ownership(codegen) -> tuple[set[str], dict[str, int]]:
    def _impl():
        used_names: set[str] = set()
        name_owner_offsets: dict[str, int] = {}
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", {})
        for variable, cvar in variables_in_use.items():
            if _stack_slot_identity_for_variable(variable) is None:
                continue
            current_name = getattr(variable, "name", None)
            if isinstance(current_name, str) and current_name:
                offset = getattr(variable, "offset", None)
                if not isinstance(offset, int) or offset not in {0, 2}:
                    used_names.add(current_name)
                    name_owner_offsets[current_name] = offset if isinstance(offset, int) else 0
            unified = getattr(cvar, "unified_variable", None)
            unified_name = getattr(unified, "name", None)
            if isinstance(unified_name, str) and unified_name:
                offset = getattr(variable, "offset", None)
                if not isinstance(offset, int) or offset not in {0, 2}:
                    used_names.add(unified_name)
                    name_owner_offsets[unified_name] = offset if isinstance(offset, int) else 0
        return used_names, name_owner_offsets

    return _impl()


def _ordered_stack_identity_variables(codegen) -> list[tuple[object, object]]:
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", {})
    return sorted(
        [
            (variable, cvar)
            for variable, cvar in variables_in_use.items()
            if _stack_slot_identity_for_variable(variable) is not None
        ],
        key=lambda item: (
            0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
            getattr(item[0], "offset", 0) if isinstance(getattr(item[0], "offset", 0), int) else 0,
            -getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
            getattr(item[0], "name", "") or "",
        ),
    )


def _ordered_stack_identity_nodes(codegen) -> list[tuple[object, object]]:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return []
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        variables_in_use = {}
        cfunc.variables_in_use = variables_in_use

    nodes: dict[tuple[object, object, object], tuple[object, object]] = {}
    for variable, cvar in variables_in_use.items():
        if _stack_slot_identity_for_variable(variable) is None:
            continue
        nodes[(
            getattr(variable, "offset", None),
            getattr(variable, "size", None),
            getattr(variable, "base", None),
        )] = (variable, cvar)

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    for node in _iter_c_nodes_deep(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if _stack_slot_identity_for_variable(variable) is None:
            continue
        key = (
            getattr(variable, "offset", None),
            getattr(variable, "size", None),
            getattr(variable, "base", None),
        )
        nodes.setdefault(key, (variable, node))
        if variable not in variables_in_use:
            variables_in_use[variable] = node

    return sorted(
        nodes.values(),
        key=lambda item: (
            0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
            getattr(item[0], "offset", 0) if isinstance(getattr(item[0], "offset", 0), int) else 0,
            -getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
            getattr(item[0], "name", "") or "",
        ),
    )


def _apply_generic_unified_name_for_param_slot(variable, cvar, cod_metadata: CODProcMetadata | None) -> bool:
    def _impl():
        disp = getattr(variable, "offset", None)
        if not (isinstance(disp, int) and disp in {0, 2}):
            return False
        if cod_metadata is not None and disp in getattr(cod_metadata, "stack_aliases", {}):
            return False
        changed = False
        unified = getattr(cvar, "unified_variable", None)
        unified_name = getattr(unified, "name", None)
        if isinstance(unified_name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", unified_name):
            if getattr(variable, "name", None) != unified_name:
                variable.name = unified_name
                changed = True
            if unified is not None and getattr(unified, "name", None) != unified_name:
                unified.name = unified_name
                changed = True
            if getattr(cvar, "name", None) != unified_name:
                try:
                    cvar.name = unified_name
                except Exception:
                    pass
                else:
                    changed = True
        return changed

    return _impl()


def _resolve_alias_collision_name(
    alias: str,
    disp: int | None,
    used_names: set[str],
    name_owner_offsets: dict[str, int],
) -> str:
    if alias not in used_names:
        used_names.add(alias)
        name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
        return alias
    owner_offset = name_owner_offsets.get(alias)
    if owner_offset == disp:
        used_names.add(alias)
        name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
        return alias
    if isinstance(disp, int) and disp > 2 and owner_offset in {0, 2}:
        used_names.add(alias)
        name_owner_offsets[alias] = disp
        return alias
    alias = _make_unique_identifier(alias, used_names)
    name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
    return alias

def _attach_cod_variable_names(codegen, cod_metadata: CODProcMetadata | None) -> bool:
    def _impl():
        if cod_metadata is None or not cod_metadata.stack_aliases or getattr(codegen, "cfunc", None) is None:
            return False

        positive_aliases = _build_cod_positive_bp_alias_map(
            [
                getattr(variable, "offset", None)
                for variable in getattr(codegen.cfunc, "variables_in_use", {})
                if _stack_slot_identity_for_variable(variable) is not None
                and isinstance(getattr(variable, "offset", None), int)
            ],
            cod_metadata,
        )
        normalized_aliases = _build_cod_normalized_bp_alias_map(cod_metadata)

        changed = False
        used_names, name_owner_offsets = _collect_cod_name_ownership(codegen)
        ordered_variables = _ordered_stack_identity_nodes(codegen)
        for variable, cvar in ordered_variables:
            if _stack_slot_identity_for_variable(variable) is None:
                continue
            disp = getattr(variable, "offset", None)
            if disp is None:
                continue
            alias = _cod_stack_alias_for_disp(
                disp,
                cod_metadata,
                positive_aliases=positive_aliases,
                normalized_aliases=normalized_aliases,
            )
            if alias is None:
                continue
            current_name = getattr(variable, "name", None)
            if isinstance(current_name, str) and current_name and current_name == alias:
                used_names.add(current_name)
                name_owner_offsets[current_name] = disp if isinstance(disp, int) else 0
                continue
            if (
                isinstance(current_name, str)
                and current_name.startswith(f"{alias}_")
                and name_owner_offsets.get(current_name) == (disp if isinstance(disp, int) else 0)
            ):
                used_names.add(current_name)
                name_owner_offsets[current_name] = disp if isinstance(disp, int) else 0
                continue
            if _apply_generic_unified_name_for_param_slot(variable, cvar, cod_metadata):
                changed = True
                continue
            alias = _resolve_alias_collision_name(alias, disp, used_names, name_owner_offsets)

            if getattr(variable, "name", None) != alias:
                variable.name = alias
                changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != alias:
                unified.name = alias
                changed = True

        return changed

    return _impl()

def _synthetic_global_entry(
    synthetic_globals: dict[int, tuple[str, int]] | None, addr: int
) -> tuple[str, int] | None:
    if not synthetic_globals:
        return None
    entry = synthetic_globals.get(addr)
    if entry is None:
        return None
    if isinstance(entry, tuple):
        return entry
    return entry, 1

def _sanitize_cod_identifier(name: str) -> str:
    name = name.lstrip("_")
    if name.startswith("$") and "_" in name:
        name = name.rsplit("_", 1)[-1]
    name = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not name:
        return "data"
    if name[0].isdigit():
        return f"g_{name}"
    return name

def _get_or_seed_inertia_alias_state(codegen):
    def _impl():
        alias_state = getattr(codegen, "_inertia_alias_state", None)
        if alias_state is None:
            alias_state = getattr(getattr(codegen, "cfunc", None), "_inertia_alias_state", None)
        if alias_state is not None:
            return alias_state

        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return None

        alias_state = AliasState()
        seeded = False
        for variable in getattr(cfunc, "variables_in_use", {}):
            if not isinstance(variable, SimRegisterVariable):
                continue
            pair_name = register_pair_name(getattr(variable, "name", None))
            if pair_name is None:
                reg = getattr(variable, "reg", None)
                size = getattr(variable, "size", 0) or 0
                if isinstance(reg, int) and size in {1, 2}:
                    pair_names = ("ax", "cx", "dx", "bx")
                    pair_index = reg // 2
                    if 0 <= pair_index < len(pair_names):
                        pair_name = pair_names[pair_index]
            if pair_name is None:
                continue
            alias_state.bump_domain(DomainKey("reg", pair_name.upper()))
            seeded = True

        if not seeded:
            return None
        setattr(codegen, "_inertia_alias_state", alias_state)
        with contextlib.suppress(AttributeError):
            setattr(cfunc, "_inertia_alias_state", alias_state)
        return alias_state

    return _impl()

def _make_unique_identifier(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate

def _structured_codegen_node(value) -> bool:
    return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")


def _structured_slot_names_8616(value) -> tuple[str, ...]:
    def _impl():
        attrs: list[str] = []
        if type(value) is object:
            return ()

        for cls in type(value).mro():
            slots = getattr(cls, "__slots__", ())
            if not slots:
                continue
            if isinstance(slots, str):
                slots = (slots,)
            for slot in slots:
                if isinstance(slot, str) and not slot.startswith("_") and slot != "codegen":
                    attrs.append(slot)

        if hasattr(value, "__dict__"):
            attrs.extend(
                attr
                for attr in value.__dict__.keys()
                if isinstance(attr, str) and not attr.startswith("_") and attr != "codegen"
            )

        # Preserve deterministic traversal order and avoid duplicates when
        # inherited slots repeat between classes.
        seen = set()
        ordered: list[str] = []
        for attr in attrs:
            if attr in seen:
                continue
            seen.add(attr)
            ordered.append(attr)
        return tuple(ordered)

    return _impl()


def _iter_c_node_children_8616(value, seen_values: set[int] | None = None):
    def _impl():
        nonlocal seen_values
        if seen_values is None:
            seen_values = set()

        stack = [value]
        while stack:
            current = stack.pop()
            try:
                current_id = id(current)
            except Exception:
                continue
            if current_id in seen_values:
                continue
            seen_values.add(current_id)

            if _structured_codegen_node(current):
                yield current
                continue

            if isinstance(current, (str, bytes)):
                continue

            if isinstance(current, dict):
                try:
                    items = tuple(current.values())
                except Exception:
                    continue
                stack.extend(items)
                continue

            if isinstance(current, (list, tuple, set)):
                try:
                    items = tuple(current)
                except Exception:
                    continue
                stack.extend(items)
                continue

            if hasattr(current, "__iter__"):
                try:
                    stack.extend(tuple(current))
                except Exception:
                    continue

    return _impl()


def _c_constant_value(node) -> int | None:
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None

def _normalize_16bit_signed_offset(offset: int) -> int:
    wrapped = offset & 0xFFFF
    if wrapped >= 0x8000:
        return wrapped - 0x10000
    return wrapped

def _project_rewrite_cache(project: angr.Project) -> dict[str, dict[int, object]]:
    cache = getattr(project, "_inertia_rewrite_cache", None)
    if cache is None:
        cache = {}
        setattr(project, "_inertia_rewrite_cache", cache)
    return cache

class _CODSourceRewriteSpec:
    name: str
    header_regex: str
    rewritten: str
    required_lines: tuple[str, ...] = ()

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        return _rewrite_cod_proc_from_source(
            c_text,
            metadata,
            header_regex=self.header_regex,
            rewritten=self.rewritten,
            required_lines=self.required_lines,
        )

def _segment_reg_name(node, project: angr.Project) -> str | None:
    return _cli_segmented._segment_reg_name(node, project, project_rewrite_cache=_project_rewrite_cache)

def _classify_segmented_addr_expr(node, project: angr.Project) -> _SegmentedAccess | None:
    return _cli_segmented._classify_segmented_addr_expr(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        match_stack_cvar_and_offset=_match_stack_cvar_and_offset,
        normalize_16bit_signed_offset=_normalize_16bit_signed_offset,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
    )

def _classify_segmented_dereference(node, project: angr.Project) -> _SegmentedAccess | None:
    return _cli_segmented._classify_segmented_dereference(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
    )

def _match_real_mode_linear_expr(node, project: angr.Project) -> tuple[str | None, int | None]:
    return _cli_segmented._match_real_mode_linear_expr(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
    )

def _match_segmented_dereference(node, project: angr.Project) -> tuple[str | None, int | None]:
    return _cli_segmented._match_segmented_dereference(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        classify_segmented_dereference=_classify_segmented_dereference,
    )

def _match_segment_register_based_dereference(node, project: angr.Project):
    return _cli_segmented_lowering._match_segment_register_based_dereference(
        node,
        project,
        classify_segmented_dereference=_classify_segmented_dereference,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        segment_reg_name=_segment_reg_name,
    )

def _strip_segment_scale_from_addr_expr(addr_expr, project: angr.Project):
    return _cli_segmented_lowering._strip_segment_scale_from_addr_expr(
        addr_expr,
        project,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        segment_reg_name=_segment_reg_name,
    )

def _match_ss_stack_reference(node, project: angr.Project):
    return _cli_segmented_lowering._match_ss_stack_reference(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        classify_segmented_dereference=_classify_segmented_dereference,
    )

def _flatten_c_add_terms(node, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    key = id(node)
    if key in seen:
        return [node]
    seen.add(key)
    if isinstance(node, structured_c.CTypeCast):
        return _flatten_c_add_terms(node.expr, seen)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_c_add_terms(node.lhs, seen) + _flatten_c_add_terms(node.rhs, seen)
    return [node]

def _resolve_dirty_virtual_expr_8616(node):
    def _impl():
        dirty = getattr(node, "dirty", None)
        if dirty is None:
            return None
        varid = getattr(dirty, "varid", None)
        if not isinstance(varid, int):
            return None
        codegen = getattr(node, "codegen", None)
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return None

        target_name = f"vvar_{varid}"
        matches = []
        for stmt in _iter_c_nodes_deep(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_name = getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
            if lhs_name != target_name:
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                return None
        return matches[0] if len(matches) == 1 else None

    return _impl()

def _match_stack_cvar_and_offset(node, _seen: set[int] | None = None):
    def _impl():
        nonlocal _seen, node
        if _seen is None:
            _seen = set()
        node = _unwrap_c_casts(node)
        key = id(node)
        if key in _seen:
            return None
        _seen.add(key)

        resolved_dirty = _resolve_dirty_virtual_expr_8616(node)
        if resolved_dirty is not None:
            return _match_stack_cvar_and_offset(resolved_dirty, _seen)

        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable) and _stack_slot_identity_for_variable(variable) is not None:
                return node, 0
            return None

        if isinstance(node, structured_c.CIndexedVariable):
            base = _match_stack_cvar_and_offset(node.variable, _seen)
            index = _c_constant_value(_unwrap_c_casts(node.index))
            if base is None or index is None:
                return None
            base_cvar, offset = base
            return base_cvar, _normalize_16bit_signed_offset(offset + index)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = _unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CVariable):
                variable = getattr(operand, "variable", None)
                if isinstance(variable, SimStackVariable) and _stack_slot_identity_for_variable(variable) is not None:
                    return operand, 0
            return None

        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = _match_stack_cvar_and_offset(node.lhs, _seen)
            rhs = _match_stack_cvar_and_offset(node.rhs, _seen)
            lhs_const = _c_constant_value(_unwrap_c_casts(node.lhs))
            rhs_const = _c_constant_value(_unwrap_c_casts(node.rhs))

            if lhs is not None and rhs_const is not None:
                base, offset = lhs
                return base, _normalize_16bit_signed_offset(offset + (rhs_const if node.op == "Add" else -rhs_const))
            if rhs is not None and lhs_const is not None:
                base, offset = rhs
                return base, _normalize_16bit_signed_offset(offset + lhs_const)
            return None

        return None

    return _impl()

def _match_ss_local_plus_const(node, project: angr.Project):
    cache = _project_rewrite_cache(project).setdefault("ss_local_plus_const", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        cache[key] = None
        return None
    extra_offset = _normalize_16bit_signed_offset(classified.extra_offset)
    result = (classified.cvar, extra_offset)
    cache[key] = (classified.cvar, extra_offset)
    return result


_CHILD_SCALAR_ATTRS = (
    "lhs",
    "rhs",
    "expr",
    "operand",
    "addr",
    "data",
    "guard",
    "condition",
    "cond",
    "initializer",
    "iterator",
    "body",
    "iffalse",
    "iftrue",
    "callee_target",
    "else_node",
    "retval",
)
_CHILD_LIST_ATTRS = ("args", "operands", "statements")


def _replace_scalar_child_attrs(
    current,
    transform,
    node_stack: list[object],
    *,
    should_process_child: callable | None = None,
) -> bool:
    changed = False
    for attr in _CHILD_SCALAR_ATTRS:
        if not hasattr(current, attr):
            continue
        if callable(should_process_child) and not should_process_child(current, attr):
            continue
        try:
            value = getattr(current, attr)
        except Exception:
            _AST_REWRITE_LOGGER.warning(
                "cli_c_ast_rewrites._replace_c_children: failed to read node attribute %s on %r",
                attr,
                current,
                exc_info=True,
            )
            continue
        if not _structured_codegen_node(value):
            continue
        new_value = transform(value)
        if new_value is not value:
            setattr(current, attr, new_value)
            changed = True
            continue
        node_stack.append(value)
    return changed


def _replace_list_child_attrs(
    current,
    transform,
    node_stack: list[object],
    *,
    should_process_child: callable | None = None,
) -> bool:
    def _impl():
        changed = False
        for attr in _CHILD_LIST_ATTRS:
            if not hasattr(current, attr):
                continue
            if callable(should_process_child) and not should_process_child(current, attr):
                continue
            try:
                items = getattr(current, attr)
            except Exception:
                _AST_REWRITE_LOGGER.debug(
                    "cli_c_ast_rewrites._replace_c_children: failed to read iterable node attribute %s on %r",
                    attr,
                    current,
                    exc_info=True,
                )
                continue
            if not items:
                continue
            new_items = []
            list_changed = False
            for item in items:
                if not _structured_codegen_node(item):
                    new_items.append(item)
                    continue
                new_item = transform(item)
                if new_item is not item:
                    list_changed = True
                if new_item is item and _structured_codegen_node(new_item):
                    node_stack.append(new_item)
                new_items.append(new_item)
            if list_changed:
                setattr(current, attr, new_items)
                changed = True
        return changed

    return _impl()


def _replace_condition_pairs(
    current,
    transform,
    node_stack: list[object],
    *,
    should_process_child: callable | None = None,
) -> bool:
    def _impl():
        if callable(should_process_child) and not should_process_child(current, "condition_and_nodes"):
            return False
        if not hasattr(current, "condition_and_nodes"):
            return False
        try:
            pairs = getattr(current, "condition_and_nodes")
        except Exception:
            _AST_REWRITE_LOGGER.debug(
                "cli_c_ast_rewrites._replace_c_children: failed to read condition_and_nodes on %r",
                current,
                exc_info=True,
            )
            return False
        if not pairs:
            return False
        new_pairs = []
        pair_changed = False
        for cond, body in pairs:
            new_cond = transform(cond) if _structured_codegen_node(cond) else cond
            new_body = transform(body) if _structured_codegen_node(body) else body
            if new_cond is not cond or new_body is not body:
                pair_changed = True
            if new_cond is cond and _structured_codegen_node(new_cond):
                node_stack.append(new_cond)
            if new_body is body and _structured_codegen_node(new_body):
                node_stack.append(new_body)
            new_pairs.append((new_cond, new_body))
        if not pair_changed:
            return False
        setattr(current, "condition_and_nodes", new_pairs)
        return True

    return _impl()


def _replace_c_children(
    node,
    transform,
    seen: set[int] | None = None,
    *,
    should_process_child: callable | None = None,
) -> bool:
    if seen is None:
        seen = set()
    if not _structured_codegen_node(node):
        return False

    node_stack: list[object] = [node]
    changed = False
    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        scalar_changed = _replace_scalar_child_attrs(
            current,
            transform,
            node_stack,
            should_process_child=should_process_child,
        )
        list_changed = _replace_list_child_attrs(
            current,
            transform,
            node_stack,
            should_process_child=should_process_child,
        )
        pair_changed = _replace_condition_pairs(
            current,
            transform,
            node_stack,
            should_process_child=should_process_child,
        )
        changed = changed or scalar_changed or list_changed or pair_changed

    return changed

def _iter_c_nodes_deep(node, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    if not _structured_codegen_node(node):
        return
    # Iterative walk avoids recursion overflow on degenerate structured-IR inputs.
    node_stack = [node]
    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in _structured_slot_names_8616(current):
            try:
                value = getattr(current, attr)
            except Exception:
                continue
            for item in _iter_c_node_children_8616(value, set()):
                if _structured_codegen_node(item):
                    node_stack.append(item)

def _same_c_expression(lhs, rhs, seen_pairs: set[tuple[int, int]] | None = None) -> bool:
    def _impl():
        nonlocal seen_pairs
        if type(lhs) is not type(rhs):
            return False

        if seen_pairs is None:
            seen_pairs = set()
        pair = (id(lhs), id(rhs))
        if pair in seen_pairs:
            return True
        seen_pairs.add(pair)

        if isinstance(lhs, structured_c.CConstant):
            return lhs.value == rhs.value

        if isinstance(lhs, structured_c.CTypeCast):
            return _same_c_expression(lhs.expr, rhs.expr, seen_pairs)

        if isinstance(lhs, structured_c.CUnaryOp):
            return lhs.op == rhs.op and _same_c_expression(lhs.operand, rhs.operand, seen_pairs)

        if isinstance(lhs, structured_c.CBinaryOp):
            return (
                lhs.op == rhs.op
                and _same_c_expression(lhs.lhs, rhs.lhs, seen_pairs)
                and _same_c_expression(lhs.rhs, rhs.rhs, seen_pairs)
            )

        if isinstance(lhs, structured_c.CFunctionCall):
            if getattr(lhs, "callee_target", None) != getattr(rhs, "callee_target", None):
                return False
            if getattr(lhs, "callee_func", None) != getattr(rhs, "callee_func", None):
                return False
            lhs_args = list(getattr(lhs, "args", ()) or ())
            rhs_args = list(getattr(rhs, "args", ()) or ())
            if len(lhs_args) != len(rhs_args):
                return False
            return all(_same_c_expression(larg, rarg, seen_pairs) for larg, rarg in zip(lhs_args, rhs_args))

        if type(lhs).__name__ == "CDirtyExpression":
            lhs_dirty = getattr(lhs, "dirty", None)
            rhs_dirty = getattr(rhs, "dirty", None)
            for attr in ("varid", "idx", "reg_offset", "reg", "bits"):
                lhs_value = getattr(lhs_dirty, attr, None)
                rhs_value = getattr(rhs_dirty, attr, None)
                if lhs_value is not None or rhs_value is not None:
                    return lhs_value == rhs_value
            return getattr(lhs, "idx", None) == getattr(rhs, "idx", None)

        if isinstance(lhs, structured_c.CVariable):
            lvar = getattr(lhs, "variable", None)
            rvar = getattr(rhs, "variable", None)
            if type(lvar) is not type(rvar):
                return False
            if isinstance(lvar, SimRegisterVariable):
                return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
            if isinstance(lvar, SimStackVariable):
                return (
                    getattr(lvar, "base", None) == getattr(rvar, "base", None)
                    and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
                    and getattr(lvar, "size", None) == getattr(rvar, "size", None)
                )
            if isinstance(lvar, SimMemoryVariable):
                return (
                    getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
                    and getattr(lvar, "size", None) == getattr(rvar, "size", None)
                )
            return lvar == rvar

        return lhs is rhs

    return _impl()

def _same_c_storage(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False

    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    if type(lvar) is not type(rvar):
        return False

    if isinstance(lvar, SimRegisterVariable):
        return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
    if isinstance(lvar, SimStackVariable):
        return (
            getattr(lvar, "base", None) == getattr(rvar, "base", None)
            and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
        )
    if isinstance(lvar, SimMemoryVariable):
        return getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
    return lvar == rvar

def _same_stack_slot_identity_var(lhs_var, rhs_var) -> bool:
    lhs_identity = _stack_slot_identity_for_variable(lhs_var)
    rhs_identity = _stack_slot_identity_for_variable(rhs_var)
    return lhs_identity is not None and rhs_identity is not None and lhs_identity == rhs_identity

def _stack_slot_identity_can_join_var(lhs_var, rhs_var) -> bool:
    lhs_identity = _stack_slot_identity_for_variable(lhs_var)
    rhs_identity = _stack_slot_identity_for_variable(rhs_var)
    if lhs_identity is None or rhs_identity is None:
        return False
    return lhs_identity.can_join(rhs_identity)

def _same_stack_slot_identity(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    return _same_stack_slot_identity_var(lvar, rvar)

def _stack_slot_identity_can_join(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    return _stack_slot_identity_can_join_var(lvar, rvar)

def _is_c_constant_int(node, value: int) -> bool:
    return isinstance(node, structured_c.CConstant) and isinstance(node.value, int) and node.value == value

def _cite_is_negation(node) -> bool:
    return type(node).__name__ == "CITE" and _is_c_constant_int(node.iftrue, 0) and _is_c_constant_int(node.iffalse, 1)

def _invert_comparison_op(op: str) -> str | None:
    return {
        "==": "!=",
        "!=": "==",
        ">": "<=",
        "<": ">=",
        ">=": "<",
        "<=": ">",
    }.get(op)

def _make_inverted_comparison(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    inverted = _invert_comparison_op(node.op)
    if inverted is None:
        return None
    return structured_c.CBinaryOp(
        inverted,
        node.lhs,
        node.rhs,
        type=getattr(node, "type", None),
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )

def _invert_interval_guard_if_safe(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "LogicalAnd":
        return None

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)
    if not isinstance(lhs, structured_c.CBinaryOp) or not isinstance(rhs, structured_c.CBinaryOp):
        return None

    if lhs.op not in {">", ">=", "CmpGT", "CmpGE"}:
        return None
    if rhs.op not in {"<", "<=", "CmpLT", "CmpLE"}:
        return None
    if not _same_c_expression(lhs.rhs, rhs.rhs):
        return None

    inverted_lhs = _make_inverted_comparison(lhs, codegen)
    inverted_rhs = _make_inverted_comparison(rhs, codegen)
    if inverted_lhs is None or inverted_rhs is None:
        return None
    return structured_c.CBinaryOp(
        "LogicalAnd",
        inverted_lhs,
        inverted_rhs,
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )

def _extract_same_zero_compare_expr(node):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "CmpEQ":
        return None

    if _is_c_constant_int(node.rhs, 0):
        return node.lhs
    if _is_c_constant_int(node.lhs, 0):
        return node.rhs
    return None

def _extract_zero_flag_source_expr(node):
    def _impl():
        if isinstance(node, structured_c.CBinaryOp):
            if node.op == "Mul":
                pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
                for maybe_logic, maybe_scale in pairs:
                    if not _is_c_constant_int(maybe_scale, 64):
                        continue
                    source_expr = _extract_same_zero_compare_expr(maybe_logic)
                    if source_expr is not None:
                        return source_expr
                    if not isinstance(maybe_logic, structured_c.CBinaryOp) or maybe_logic.op != "LogicalAnd":
                        continue
                    lhs_expr = _extract_same_zero_compare_expr(maybe_logic.lhs)
                    rhs_expr = _extract_same_zero_compare_expr(maybe_logic.rhs)
                    if lhs_expr is not None and rhs_expr is not None and _same_c_expression(lhs_expr, rhs_expr):
                        return lhs_expr

            for attr in ("lhs", "rhs"):
                child = getattr(node, attr, None)
                if _structured_codegen_node(child):
                    extracted = _extract_zero_flag_source_expr(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(node, structured_c.CUnaryOp):
            child = getattr(node, "operand", None)
            if _structured_codegen_node(child):
                return _extract_zero_flag_source_expr(child)

        elif isinstance(node, structured_c.CTypeCast):
            child = getattr(node, "expr", None)
            if _structured_codegen_node(child):
                return _extract_zero_flag_source_expr(child)

        return None

    return _impl()

def _simplify_zero_flag_comparison(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _is_c_constant_int(node.rhs, 0):
        expr = node.lhs
    elif _is_c_constant_int(node.lhs, 0):
        expr = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr(expr)
    if source_expr is None:
        return node

    if node.op == "CmpEQ":
        return source_expr

    return structured_c.CUnaryOp("Not", source_expr, codegen=codegen)

def _match_high_byte_projection_base(expr):
    def _impl():
        nonlocal expr
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
            return None
        if _c_constant_value(_unwrap_c_casts(expr.rhs)) != 8:
            return None
        inner = _unwrap_c_casts(expr.lhs)
        if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
            return None
        for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
            const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
            other = _unwrap_c_casts(maybe_other)
            if const_value is None or const_value & 0xFF:
                continue
            if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
                lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
                rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
                if lhs_mask == 0xFF or rhs_mask == 0xFF:
                    return other
        return None

    return _impl()

def _match_adjacent_register_pair_var_expr(low_expr, high_expr, codegen):
    def _impl():
        nonlocal high_expr
        if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
                if scale not in {8, 0x100}:
                    continue
                high_expr = _unwrap_c_casts(maybe_inner)
                break
        if not isinstance(low_expr, structured_c.CVariable) or not isinstance(high_expr, structured_c.CVariable):
            return None
        low_var = getattr(low_expr, "variable", None)
        high_var = getattr(high_expr, "variable", None)
        if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
            return None
        if getattr(low_var, "size", None) != 1 or getattr(high_var, "size", None) != 1:
            return None
        alias_state = _get_or_seed_inertia_alias_state(codegen)
        if alias_state is None:
            return None
        analysis = analyze_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        if not analysis.ok:
            return None
        proof = getattr(analysis, "proof", None)
        if proof is None:
            return None
        if getattr(proof, "register_pair", None) is None:
            return None
        if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
            return None
        if getattr(proof, "left_version", None) != getattr(proof, "right_version", None):
            return None
        if not can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=analysis.proof):
            return None
        return join_adjacent_register_slices(low_expr, high_expr, codegen, alias_state=alias_state, proof=proof)

    return _impl()

def _match_high_byte_projection_expr(expr):
    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(expr.rhs)) != 8:
        return None
    inner = _unwrap_c_casts(expr.lhs)
    if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "And":
        return None
    lhs_mask = _c_constant_value(_unwrap_c_casts(inner.lhs))
    rhs_mask = _c_constant_value(_unwrap_c_casts(inner.rhs))
    if lhs_mask == 0xFF00 or rhs_mask == 0xFF00:
        return expr
    return None

def _match_high_byte_projection_constant(node):
    def _impl():
        nonlocal node
        node = _unwrap_c_casts(node)
        if isinstance(node, structured_c.CBinaryOp) and node.op == "And":
            for maybe_inner, maybe_mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_mask)) == 0xFF:
                    inner_val = _match_high_byte_projection_constant(maybe_inner)
                    if inner_val is not None:
                        return inner_val
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
            return None
        shift = _c_constant_value(_unwrap_c_casts(node.rhs))
        inner = _unwrap_c_casts(node.lhs)
        if shift != 8 or not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
            return None
        for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
            const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
            other = _unwrap_c_casts(maybe_other)
            if const_value is None or const_value & 0xFF:
                continue
            if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
                lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
                rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
                if lhs_mask == 0xFF or rhs_mask == 0xFF:
                    return (const_value >> 8) & 0xFF
        return None

    return _impl()

def _simplify_boolean_expr(node, codegen):
    def _impl():
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Not":
            operand = _unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Not":
                return operand.operand
            if isinstance(operand, structured_c.CBinaryOp) and operand.op == "And":
                return structured_c.CBinaryOp(
                    "CmpEQ",
                    operand,
                    structured_c.CConstant(
                        0,
                        getattr(operand, "type", None) or SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                    tags=getattr(node, "tags", None),
                )
            if isinstance(operand, structured_c.CBinaryOp) and operand.op == "Sub":
                lhs_const = _c_constant_value(_unwrap_c_casts(operand.lhs))
                rhs_const = _c_constant_value(_unwrap_c_casts(operand.rhs))
                if rhs_const is not None:
                    return structured_c.CBinaryOp(
                        "CmpEQ",
                        operand.lhs,
                        structured_c.CConstant(
                            rhs_const,
                            getattr(operand.rhs, "type", None) or getattr(operand, "type", None) or SimTypeShort(False),
                            codegen=codegen,
                        ),
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
                if lhs_const is not None:
                    return structured_c.CBinaryOp(
                        "CmpEQ",
                        operand.rhs,
                        structured_c.CConstant(
                            lhs_const,
                            getattr(operand.lhs, "type", None) or getattr(operand, "type", None) or SimTypeShort(False),
                            codegen=codegen,
                        ),
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
            if isinstance(operand, structured_c.CBinaryOp):
                inverted = _make_inverted_comparison(operand, codegen)
                if inverted is not None:
                    return inverted

        simplified = _simplify_zero_flag_comparison(node, codegen)
        if simplified is not node:
            return simplified

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Not" and _cite_is_negation(node.operand):
            inverted = _make_inverted_comparison(node.operand.cond, codegen)
            return inverted if inverted is not None else node.operand.cond

        interval_guard = _invert_interval_guard_if_safe(node, codegen)
        if interval_guard is not None:
            return interval_guard

        if _cite_is_negation(node):
            cond = node.cond
            inverted = _make_inverted_comparison(cond, codegen)
            if inverted is not None:
                return inverted

        return node

    return _impl()

def _simplify_zero_mul_or_expr(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return node

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)

    def is_zero_mul(expr):
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Mul":
            return False
        return _c_constant_value(_unwrap_c_casts(expr.lhs)) == 0 or _c_constant_value(_unwrap_c_casts(expr.rhs)) == 0

    if _c_constant_value(lhs) == 0:
        return node.rhs
    if _c_constant_value(rhs) == 0:
        return node.lhs
    if is_zero_mul(lhs):
        return node.rhs
    if is_zero_mul(rhs):
        return node.lhs
    return node

def _simplify_basic_algebraic_identities(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp):
            return node

        lhs = _unwrap_c_casts(node.lhs)
        rhs = _unwrap_c_casts(node.rhs)

        if node.op == "Xor" and _same_c_expression(lhs, rhs):
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
            return structured_c.CConstant(0, type_, codegen=codegen)

        if node.op == "Sub" and _c_constant_value(rhs) == 0:
            return node.lhs

        if node.op == "Add":
            if _c_constant_value(lhs) == 0:
                return node.rhs
            if _c_constant_value(rhs) == 0:
                return node.lhs

        if node.op == "Or":
            if _c_constant_value(lhs) == 0:
                return node.rhs
            if _c_constant_value(rhs) == 0:
                return node.lhs

        # MS C (16-bit) rejects shifting raw pointer expressions (e.g. &x >> 8).
        # In the 16-bit pipeline these are high-byte projections of offset-like
        # values, so make the integer projection explicit at the AST layer.
        if node.op == "Shr" and _c_constant_value(rhs) == 8:
            lhs_raw = _unwrap_c_casts(node.lhs)
            if isinstance(lhs_raw, structured_c.CUnaryOp) and lhs_raw.op in {"Reference", "AddressOf"}:
                cast_lhs = structured_c.CTypeCast(
                    SimTypeShort(False),
                    node.lhs,
                    codegen=codegen,
                )
                return structured_c.CBinaryOp(
                    "Shr",
                    cast_lhs,
                    node.rhs,
                    codegen=codegen,
                    tags=getattr(node, "tags", None),
                )

        high_byte_constant = _match_high_byte_projection_constant(node)
        if high_byte_constant is not None:
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeChar()
            return structured_c.CConstant(high_byte_constant, type_, codegen=codegen)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children(root, transform):
        changed = True

    return changed


def _collect_protected_deref_expr_ids(root) -> set[int]:
    protected_ids: set[int] = set()

    def _protect_addr_expr_nodes(expr) -> None:
        if not _structured_codegen_node(expr):
            return
        for protected_node in _iter_c_nodes_deep(expr):
            protected_ids.add(id(protected_node))

    for walk_node in _iter_c_nodes_deep(root):
        if not isinstance(walk_node, structured_c.CUnaryOp) or walk_node.op != "Dereference":
            if isinstance(walk_node, structured_c.CFunctionCall):
                callee_target = getattr(walk_node, "callee_target", None)
                callee_func = getattr(walk_node, "callee_func", None)
                callee_name = callee_target if isinstance(callee_target, str) else getattr(callee_func, "name", None)
                if isinstance(callee_name, str) and callee_name in {
                    "SEG_PTR",
                    "SEG_U8",
                    "SEG_U16",
                    "SEG_U32",
                    "MEM_U8",
                    "MEM_U16",
                    "MEM_U32",
                }:
                    args = tuple(getattr(walk_node, "args", ()) or ())
                    if len(args) >= 2:
                        _protect_addr_expr_nodes(args[1])
            continue
        _protect_addr_expr_nodes(_extract_dereference_addr_expr(walk_node))
    return protected_ids


def _is_linear_register_temp_var(cvar) -> bool:
    return isinstance(cvar, structured_c.CVariable) and isinstance(getattr(cvar, "name", None), str) and re.fullmatch(
        r"(?:v\d+|vvar_\d+|ir_\d+)",
        getattr(cvar, "name", ""),
    ) is not None

def _simplify_structured_c_expressions(codegen) -> bool:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None or getattr(cfunc, "statements", None) is None:
            return False

        protected_dereference_addr_expr_ids = _collect_protected_deref_expr_ids(getattr(cfunc, "statements", None))

        def _collect_high_byte_temp_constants(node):
            aliases: dict[int, int] = {}
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp_var(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
                    continue
                for maybe_const, maybe_other in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
                    const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                    if const_value is None or const_value & 0xFF:
                        continue
                    aliases[id(getattr(walk_node.lhs, "variable", None))] = const_value >> 8
                    break
            return aliases

        def _collect_shift_extract_aliases(node):
            aliases: dict[int, tuple[object, int]] = {}
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp_var(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Shr":
                    continue
                shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                base = _unwrap_c_casts(rhs.lhs)
                if shift is None or not isinstance(shift, int):
                    continue
                if not isinstance(base, structured_c.CBinaryOp) or base.op != "And":
                    continue
                mask_lhs = _c_constant_value(_unwrap_c_casts(base.lhs))
                mask_rhs = _c_constant_value(_unwrap_c_casts(base.rhs))
                inner = None
                if mask_lhs == 0xFF00:
                    inner = base.rhs
                elif mask_rhs == 0xFF00:
                    inner = base.lhs
                if inner is None:
                    continue
                aliases[id(getattr(walk_node.lhs, "variable", None))] = (inner, shift)
            return aliases

        def _collect_mask_shift_aliases(node):
            aliases: dict[int, tuple[object, int, int]] = {}
            for _ in range(4):
                changed = False
                for walk_node in _iter_c_nodes_deep(node):
                    if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                        continue
                    if not _is_linear_register_temp_var(walk_node.lhs):
                        continue
                    lhs_var = getattr(walk_node.lhs, "variable", None)
                    if lhs_var is None:
                        continue
                    key = id(lhs_var)
                    rhs = _unwrap_c_casts(walk_node.rhs)
                    alias = None

                    if isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "And":
                        lhs_const = _c_constant_value(_unwrap_c_casts(rhs.lhs))
                        rhs_const = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                        if lhs_const is not None:
                            alias = (rhs.rhs, lhs_const, 0)
                        elif rhs_const is not None:
                            alias = (rhs.lhs, rhs_const, 0)

                    elif isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "Shr":
                        shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                        shifted = _unwrap_c_casts(rhs.lhs)
                        if isinstance(shifted, structured_c.CVariable) and isinstance(shift, int):
                            parent = aliases.get(id(getattr(shifted, "variable", None)))
                            if parent is not None:
                                base_expr, mask, base_shift = parent
                                alias = (base_expr, mask, base_shift + shift)

                    if alias is None:
                        continue
                    if aliases.get(key) != alias:
                        aliases[key] = alias
                        changed = True
                if not changed:
                    break
            return aliases

        def _collect_copy_aliases(node):
            aliases: dict[int, _CopyAliasState] = {}
            for _ in range(3):
                changed = False
                for walk_node in _iter_c_nodes_deep(node):
                    if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                        continue
                    if not _is_linear_register_temp_var(walk_node.lhs):
                        continue
                    rhs = _unwrap_c_casts(walk_node.rhs)
                    if not isinstance(rhs, structured_c.CVariable):
                        continue
                    lhs_var = getattr(walk_node.lhs, "variable", None)
                    rhs_var = getattr(rhs, "variable", None)
                    if lhs_var is None or rhs_var is None:
                        continue
                    key = id(lhs_var)
                    rhs_domain = _storage_domain_for_expr(rhs)
                    if rhs_domain.is_mixed():
                        continue
                    parent_state = aliases.get(id(rhs_var))
                    rhs_state = _CopyAliasState(rhs_domain, parent_state.expr if parent_state is not None else rhs, needs_synthesis=parent_state.needs_synthesis if parent_state is not None else False)
                    current = aliases.get(key)
                    if current is None:
                        aliases[key] = rhs_state
                        changed = True
                        continue
                    merged = current.merge(rhs_state)
                    if merged != current:
                        aliases[key] = merged
                        changed = True
                if not changed:
                    break
            return aliases

        def _extract_linear_delta(expr):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
                return None, int(expr.value)
            if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
                return expr, 0

            left_base, left_delta = _extract_linear_delta(expr.lhs)
            right_base, right_delta = _extract_linear_delta(expr.rhs)
            if left_base is not None and right_base is not None:
                if _same_c_expression(left_base, right_base) and expr.op == "Add":
                    return left_base, left_delta + right_delta
                return expr, 0
            if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
                duplicate_word_base = _match_duplicate_word_base_expr(expr, resolve_copy_alias_expr)
                if duplicate_word_base is not None:
                    return duplicate_word_base, 0
            if left_base is not None:
                if expr.op == "Add":
                    return left_base, left_delta + right_delta
                return left_base, left_delta - right_delta
            if right_base is not None:
                if expr.op == "Add":
                    return right_base, left_delta + right_delta
                return expr, 0
            if expr.op == "Add":
                return None, left_delta + right_delta
            return None, left_delta - right_delta

        def _fold_simple_add_constants(node):
            node = _unwrap_c_casts(node)
            if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
                return node

            def _collect_add_terms(expr):
                terms = []
                stack = [_unwrap_c_casts(expr)]
                seen: set[int] = set()
                while stack:
                    current = _unwrap_c_casts(stack.pop())
                    key = id(current)
                    if key in seen:
                        terms.append(current)
                        continue
                    seen.add(key)
                    if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
                        stack.append(current.rhs)
                        stack.append(current.lhs)
                    else:
                        terms.append(current)
                return terms

            terms = _collect_add_terms(node)
            if len(terms) > 8:
                return node
            const_total = 0
            const_type = None
            base_terms = []
            for term in terms:
                const_value = _c_constant_value(term)
                if const_value is not None:
                    const_total += const_value
                    const_type = const_type or getattr(term, "type", None)
                    continue
                base_terms.append(term)

            if len(base_terms) != 1 or not terms:
                return node

            base_expr = base_terms[0]
            if const_total == 0:
                return base_expr

            if const_type is None:
                const_type = getattr(base_expr, "type", None) or getattr(node, "type", None) or SimTypeShort(False)
            return structured_c.CBinaryOp(
                "Add" if const_total > 0 else "Sub",
                base_expr,
                structured_c.CConstant(
                    const_total if const_total > 0 else -const_total,
                    const_type,
                    codegen=getattr(node, "codegen", None),
                ),
                codegen=getattr(node, "codegen", None),
            )

        def _build_linear_expr(base_expr, delta, codegen):
            if delta == 0:
                return base_expr
            op = "Add" if delta > 0 else "Sub"
            magnitude = delta if delta > 0 else -delta
            return structured_c.CBinaryOp(
                op,
                base_expr,
                structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )

        def _normalize_protected_add_constant_tail(node):
            if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
                return node
            lhs = _unwrap_c_casts(node.lhs)
            rhs = _unwrap_c_casts(node.rhs)
            if isinstance(lhs, structured_c.CBinaryOp) and lhs.op == "Add":
                lhs_lhs = _unwrap_c_casts(lhs.lhs)
                lhs_rhs = _unwrap_c_casts(lhs.rhs)
                if (
                    _c_constant_value(lhs_rhs) is not None
                    and _c_constant_value(rhs) is None
                    and isinstance(rhs, structured_c.CBinaryOp)
                ):
                    return structured_c.CBinaryOp(
                        "Add",
                        structured_c.CBinaryOp("Add", lhs_lhs, rhs, codegen=codegen),
                        lhs_rhs,
                        codegen=codegen,
                    )
            return node

        variable_use_counts: dict[int, int] = {}
        for walk_node in _iter_c_nodes_deep(cfunc.statements):
            if not isinstance(walk_node, structured_c.CVariable):
                continue
            variable = getattr(walk_node, "variable", None)
            if variable is not None:
                variable_use_counts[id(variable)] = variable_use_counts.get(id(variable), 0) + 1

        high_byte_aliases: dict[int, int] = {}
        shift_extract_aliases: dict[int, tuple[object, int]] = {}
        mask_shift_aliases: dict[int, tuple[object, int, int]] = {}
        copy_aliases: dict[int, _CopyAliasState] = {}
        linear_aliases: dict[int, object] = {}
        dereference_backed_linear_temps: set[int] = set()
        memory_backed_linear_temps: set[int] = set()
        _no_match = object()
        adjacent_byte_pair_cache: dict[tuple[int, int], object] = {}
        word_plus_minus_one_cache: dict[int, object] = {}
        widening_match_cache: dict[int, object] = {}

        def _alias_storage_key(expr):
            facts = describe_alias_storage(expr)
            return facts.identity

        def _resolve_copy_alias_expr(node, seen: set[int] | None = None):
            current = _unwrap_c_casts(node)
            if seen is None:
                seen = set()
            current_key = id(current)
            if current_key in seen:
                return current
            seen.add(current_key)
            while isinstance(current, structured_c.CVariable):
                variable = getattr(current, "variable", None)
                if variable is None:
                    break
                key = id(variable)
                if key in seen:
                    break
                seen.add(key)
                alias = copy_aliases.get(key)
                if alias is None:
                    storage_key = _alias_storage_key(current)
                    if storage_key is not None:
                        alias = copy_aliases.get(storage_key)
                if alias is None:
                    break
                if not alias.can_inline():
                    break
                # Inline a structural copy so later child rewrites do not mutate the
                # original statement that defined the alias.
                current = _unwrap_c_casts(_clone_structured_c_value(alias.expr))
            if isinstance(current, structured_c.CTypeCast):
                inner = _resolve_copy_alias_expr(current.expr, seen)
                if inner is not current.expr:
                    return structured_c.CTypeCast(None, current.type, inner, codegen=getattr(current, "codegen", None))
                return current
            if isinstance(current, structured_c.CUnaryOp):
                operand = _resolve_copy_alias_expr(current.operand, seen)
                if operand is not current.operand:
                    return structured_c.CUnaryOp(current.op, operand, codegen=getattr(current, "codegen", None))
                return current
            if isinstance(current, structured_c.CBinaryOp):
                lhs = _resolve_copy_alias_expr(current.lhs, seen)
                rhs = _resolve_copy_alias_expr(current.rhs, seen)
                if lhs is not current.lhs or rhs is not current.rhs:
                    return structured_c.CBinaryOp(current.op, lhs, rhs, codegen=getattr(current, "codegen", None))
            return current

        def _expr_is_safe_inline_candidate(expr):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
                return True
            if isinstance(expr, structured_c.CTypeCast):
                return _expr_is_safe_inline_candidate(expr.expr)
            if isinstance(expr, structured_c.CUnaryOp):
                return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(expr.operand)
            if isinstance(expr, structured_c.CBinaryOp):
                if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                    return False
                return _expr_is_safe_inline_candidate(expr.lhs) and _expr_is_safe_inline_candidate(expr.rhs)
            return False

        def _expr_is_copy_alias_candidate(expr):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
                return True
            if isinstance(expr, structured_c.CTypeCast):
                return _expr_is_copy_alias_candidate(expr.expr)
            return False

        def _expr_contains_dereference(expr) -> bool:
            for walk_node in _iter_c_nodes_deep(expr):
                if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
                    return True
            return False

        def _collect_dereference_backed_linear_temps(node):
            aliases: set[int] = set()
            for _ in range(4):
                changed = False
                for walk_node in _iter_c_nodes_deep(node):
                    if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                        continue
                    if not _is_linear_register_temp_var(walk_node.lhs):
                        continue
                    lhs_var = getattr(walk_node.lhs, "variable", None)
                    if lhs_var is None:
                        continue
                    key = id(lhs_var)
                    if key in aliases:
                        continue
                    rhs = _unwrap_c_casts(walk_node.rhs)
                    if _expr_contains_dereference(rhs):
                        aliases.add(key)
                        changed = True
                        continue
                    if not isinstance(rhs, structured_c.CVariable):
                        continue
                    rhs_var = getattr(rhs, "variable", None)
                    if rhs_var is not None and id(rhs_var) in aliases:
                        aliases.add(key)
                        changed = True
                if not changed:
                    break
            return aliases

        def _collect_memory_backed_linear_temps(node):
            aliases: set[int] = set()
            for _ in range(4):
                changed = False
                for walk_node in _iter_c_nodes_deep(node):
                    if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                        continue
                    if not _is_linear_register_temp_var(walk_node.lhs):
                        continue
                    lhs_var = getattr(walk_node.lhs, "variable", None)
                    if lhs_var is None:
                        continue
                    key = id(lhs_var)
                    if key in aliases:
                        continue
                    rhs = _unwrap_c_casts(walk_node.rhs)
                    rhs_var = getattr(rhs, "variable", None) if isinstance(rhs, structured_c.CVariable) else None
                    if isinstance(rhs_var, SimMemoryVariable):
                        aliases.add(key)
                        changed = True
                        continue
                    if rhs_var is not None and id(rhs_var) in aliases:
                        aliases.add(key)
                        changed = True
                if not changed:
                    break
            return aliases

        def _expr_uses_dereference_backed_temp(expr, backed_ids: set[int]) -> bool:
            if not backed_ids:
                return False
            for walk_node in _iter_c_nodes_deep(expr):
                if not isinstance(walk_node, structured_c.CVariable):
                    continue
                variable = getattr(walk_node, "variable", None)
                if variable is not None and id(variable) in backed_ids:
                    return True
            return False

        def _expr_uses_memory_backed_temp(expr, backed_ids: set[int]) -> bool:
            if not backed_ids:
                return False
            for walk_node in _iter_c_nodes_deep(expr):
                if not isinstance(walk_node, structured_c.CVariable):
                    continue
                variable = getattr(walk_node, "variable", None)
                if variable is not None and id(variable) in backed_ids:
                    return True
            return False

        def _stack_name_root(name: str | None) -> str | None:
            if not isinstance(name, str) or not name:
                return None
            match = re.fullmatch(r"(?P<root>.*?)(?:_(?P<suffix>\d+))?", name)
            if match is None:
                return name
            suffix = match.group("suffix")
            root = match.group("root")
            if suffix is None:
                return root
            return root if root else name

        def _collect_far_pointer_stack_aliases(node):
            groups: dict[str, dict[str, list[tuple[structured_c.CVariable, object]]]] = {}

            def _expr_contains_generated_temp(expr) -> bool:
                for walk in _iter_c_nodes_deep(expr):
                    if not isinstance(walk, structured_c.CVariable):
                        continue
                    name = getattr(walk, "name", None)
                    if isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name):
                        return True
                return False

            def _expr_mentions_stack_root(expr, root: str) -> bool:
                for walk in _iter_c_nodes_deep(expr):
                    if not isinstance(walk, structured_c.CVariable):
                        continue
                    variable = getattr(walk, "variable", None)
                    if not isinstance(variable, SimStackVariable):
                        continue
                    if _stack_name_root(getattr(variable, "name", None)) == root:
                        return True
                return False

            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if not isinstance(lhs_var, SimStackVariable):
                    continue
                root = _stack_name_root(getattr(lhs_var, "name", None))
                if root is None:
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if _c_constant_value(rhs) is None and not _expr_is_safe_inline_candidate(rhs):
                    continue
                if _expr_contains_generated_temp(rhs):
                    continue
                bucket = groups.setdefault(root, {"zero": [], "source": []})
                if _c_constant_value(rhs) == 0:
                    bucket["zero"].append((walk_node.lhs, rhs))
                else:
                    bucket["source"].append((walk_node.lhs, rhs))

            def _source_score(_cvar, expr) -> tuple[int, int, int]:
                expr = _unwrap_c_casts(expr)
                variable = getattr(expr, "variable", None)
                name = getattr(variable, "name", None) or getattr(expr, "name", None)
                generic_name = isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None
                if isinstance(variable, SimStackVariable):
                    return (0 if not generic_name else 2, getattr(variable, "offset", 0), getattr(variable, "size", 0))
                if isinstance(variable, SimMemoryVariable):
                    return (0 if not generic_name else 2, getattr(variable, "addr", 0), getattr(variable, "size", 0))
                if isinstance(variable, SimRegisterVariable):
                    return (3 if generic_name else 1, getattr(variable, "reg", 0), getattr(variable, "size", 0))
                if isinstance(expr, structured_c.CConstant):
                    return (4, int(expr.value) if isinstance(expr.value, int) else 0, 0)
                return (4, 0, 0)

            aliases: dict[int, object] = {}
            for root, parts in groups.items():
                if not parts["zero"] or not parts["source"]:
                    continue
                source_expr = None
                for cvar, rhs in sorted(parts["source"], key=lambda item: _source_score(item[0], item[1])):
                    variable = getattr(cvar, "variable", None)
                    if not isinstance(variable, SimStackVariable):
                        continue
                    if _stack_name_root(getattr(variable, "name", None)) != root:
                        continue
                    if _expr_mentions_stack_root(rhs, root):
                        continue
                    source_expr = rhs
                    break
                if source_expr is None:
                    continue
                for cvar, _rhs in parts["zero"]:
                    variable = getattr(cvar, "variable", None)
                    if not isinstance(variable, SimStackVariable):
                        continue
                    aliases[id(variable)] = source_expr
            return aliases

        def _match_adjacent_byte_pair_var_expr(low_expr, high_expr):
            key = (id(low_expr), id(high_expr))
            if key in adjacent_byte_pair_cache:
                cached = adjacent_byte_pair_cache[key]
                return None if cached is _no_match else cached
            low_expr = _resolve_copy_alias_expr(low_expr)
            high_expr = _resolve_copy_alias_expr(high_expr)

            if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
                for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                    scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
                    if scale not in {8, 0x100}:
                        continue
                    high_expr = _resolve_copy_alias_expr(maybe_inner)
                    break

            low_var = getattr(low_expr, "variable", None) if isinstance(low_expr, structured_c.CVariable) else None
            high_var = getattr(high_expr, "variable", None) if isinstance(high_expr, structured_c.CVariable) else None
            if not isinstance(low_var, SimMemoryVariable) or not isinstance(high_var, SimMemoryVariable):
                adjacent_byte_pair_cache[key] = _no_match
                return None
            # Global/object recovery owns DS/ES data-space objects. The structured
            # simplifier must not synthesize a bare word object from adjacent byte
            # globals here, because that late semantic jump can corrupt split byte
            # store sequences into unresolved address-valued stores.
            adjacent_byte_pair_cache[key] = _no_match
            return None

        def _match_word_plus_minus_one_expr(node):
            key = id(node)
            if key in word_plus_minus_one_cache:
                cached = word_plus_minus_one_cache[key]
                return None if cached is _no_match else cached
            node = _unwrap_c_casts(node)
            if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
                word_plus_minus_one_cache[key] = _no_match
                return None

            def _strip_byte_cast(expr):
                expr = _unwrap_c_casts(expr)
                if isinstance(expr, structured_c.CTypeCast):
                    type_ = getattr(expr, "type", None)
                    if getattr(type_, "size", None) == 8:
                        return _unwrap_c_casts(expr.expr)
                return expr

            def _match_masked_high_word(expr):
                expr = _unwrap_c_casts(expr)
                if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "And":
                    return None
                for maybe_word, maybe_mask in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                    if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 0xFF00:
                        continue
                    return _unwrap_c_casts(maybe_word)
                return None

            def _match_duplicate_word_base(expr):
                expr = _unwrap_c_casts(expr)
                if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
                    return None
                for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                    low_expr = _resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
                    high_expr = _unwrap_c_casts(maybe_high)
                    if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
                        continue
                    for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                            continue
                        inner_expr = _resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))
                        if _same_c_expression(low_expr, inner_expr):
                            return low_expr
                return None

            for masked_expr, delta_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                base_expr = _match_masked_high_word(masked_expr)
                duplicate_word_base = None
                if base_expr is None:
                    duplicate_word_base = _match_duplicate_word_base(masked_expr)
                    base_expr = duplicate_word_base
                    if base_expr is None:
                        continue
                delta_expr = _unwrap_c_casts(delta_expr)
                constant_delta = _c_constant_value(delta_expr)
                if node.op == "Add" and isinstance(constant_delta, int):
                    return structured_c.CBinaryOp(
                        "Add",
                        base_expr,
                        structured_c.CConstant(constant_delta, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
                    continue
                low_expr, const_expr = delta_expr.lhs, delta_expr.rhs
                if duplicate_word_base is not None and _c_constant_value(_unwrap_c_casts(const_expr)) == 1:
                    return structured_c.CBinaryOp(
                        "Add" if delta_expr.op == "Add" else "Sub",
                        base_expr,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                if _c_constant_value(_unwrap_c_casts(low_expr)) is None and _c_constant_value(_unwrap_c_casts(const_expr)) is None:
                    continue
                if _same_c_expression(_strip_byte_cast(low_expr), base_expr) and _c_constant_value(_unwrap_c_casts(const_expr)) == 1:
                    return structured_c.CBinaryOp(
                        "Add" if delta_expr.op == "Add" else "Sub",
                        base_expr,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                if _same_c_expression(_strip_byte_cast(const_expr), base_expr) and _c_constant_value(_unwrap_c_casts(low_expr)) == 1:
                    return structured_c.CBinaryOp(
                        "Add" if delta_expr.op == "Add" else "Sub",
                        base_expr,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )

            word_plus_minus_one_cache[key] = _no_match
            return None

        def _analyze_widening_expr_cached(node):
            key = id(node)
            if key in widening_match_cache:
                cached = widening_match_cache[key]
                return None if cached is _no_match else cached
            result = _analyze_widening_expr(
                node,
                _resolve_copy_alias_expr,
                _match_high_byte_projection_base,
            )
            widening_match_cache[key] = result if result is not None else _no_match
            return result

        def _match_linear_word_delta_expr(node):
            analysis = _analyze_widening_expr_cached(node)
            if analysis is None or analysis.kind != "linear":
                return None
            if analysis.delta == 0:
                return analysis.base_expr
            delta = analysis.delta
            base_expr = analysis.base_expr
            op = "Add" if delta > 0 else "Sub"
            magnitude = delta if delta > 0 else -delta
            return structured_c.CBinaryOp(
                op,
                base_expr,
                structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )

        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp_var(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op not in {"Add", "Sub"}:
                    continue
                resolved_rhs = _resolve_copy_alias_expr(rhs)
                linear_rhs = _match_linear_word_delta_expr(resolved_rhs)
                if linear_rhs is None:
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                if linear_aliases.get(key) != linear_rhs:
                    linear_aliases[key] = linear_rhs
                    changed = True
            if not changed:
                break

        def _match_high_byte_preserving_word_expr(node):
            analysis = _analyze_widening_expr_cached(node)
            if analysis is None or analysis.kind != "high_byte_preserving":
                return None
            return structured_c.CBinaryOp(
                "Add",
                analysis.base_expr,
                structured_c.CConstant(analysis.delta, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )

        def _memory_backed_widening_base(node) -> bool:
            if _expr_uses_dereference_backed_temp(node, dereference_backed_linear_temps):
                return True
            analysis = _analyze_widening_expr_cached(node)
            if analysis is None:
                return False
            base_expr = _resolve_copy_alias_expr(_unwrap_c_casts(analysis.base_expr))
            if isinstance(base_expr, structured_c.CVariable) and isinstance(getattr(base_expr, "variable", None), SimMemoryVariable):
                return True
            return isinstance(base_expr, structured_c.CUnaryOp) and base_expr.op == "Dereference"

        def _make_mk_fp(segment_expr, offset_expr):
            return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=codegen)

        def _is_dead_stack_address_init(stmt) -> bool:
            if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
                return False
            lhs_var = getattr(stmt.lhs, "variable", None)
            if not isinstance(lhs_var, SimStackVariable) or _stack_slot_identity_for_variable(lhs_var) is None:
                return False
            if variable_use_counts.get(id(lhs_var), 0) != 1:
                return False
            rhs = stmt.rhs
            if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Reference":
                return False
            operand = rhs.operand
            if not isinstance(operand, structured_c.CVariable):
                return False
            ref_var = getattr(operand, "variable", None)
            return isinstance(ref_var, SimStackVariable) and _stack_slot_identity_for_variable(ref_var) is not None

        def _is_redundant_self_copy(stmt) -> bool:
            if not isinstance(stmt, structured_c.CAssignment):
                return False
            lhs = _unwrap_c_casts(stmt.lhs)
            rhs = _unwrap_c_casts(stmt.rhs)
            if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
                return False
            lhs_var = getattr(lhs, "variable", None)
            rhs_var = getattr(rhs, "variable", None)
            if lhs_var is None or rhs_var is None or lhs_var is not rhs_var:
                return False
            return _is_linear_register_temp_var(lhs)

        def _flatten_bitwise_terms(expr, op):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, structured_c.CBinaryOp) and expr.op == op:
                return _flatten_bitwise_terms(expr.lhs, op) + _flatten_bitwise_terms(expr.rhs, op)
            return [expr]

        def _rewrite_and_over_or(node):
            if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
                return None
            for or_expr, const_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                or_expr = _unwrap_c_casts(or_expr)
                const_value = _c_constant_value(_unwrap_c_casts(const_expr))
                if const_value is None or not isinstance(or_expr, structured_c.CBinaryOp) or or_expr.op != "Or":
                    continue
                for and_expr, inner_const_expr in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                    inner_const = _c_constant_value(_unwrap_c_casts(inner_const_expr))
                    if inner_const is None or not isinstance(and_expr, structured_c.CBinaryOp) or and_expr.op != "And":
                        continue
                    for inner_base, inner_mask_expr in ((and_expr.lhs, and_expr.rhs), (and_expr.rhs, and_expr.lhs)):
                        inner_mask = _c_constant_value(_unwrap_c_casts(inner_mask_expr))
                        if inner_mask is None:
                            continue
                        left = structured_c.CBinaryOp(
                            "And",
                            _unwrap_c_casts(inner_base),
                            structured_c.CConstant(const_value, SimTypeShort(False), codegen=codegen),
                            codegen=codegen,
                        )
                        right_const = inner_const & const_value
                        if right_const == 0:
                            return left
                        right = structured_c.CConstant(right_const, SimTypeShort(False), codegen=codegen)
                        return structured_c.CBinaryOp("Or", left, right, codegen=codegen)
            return None

        def transform(node):
            if isinstance(node, structured_c.CTypeCast):
                target_type = getattr(node, "type", None)
                rendered = str(target_type) if target_type is not None else ""
                if "[" in rendered and isinstance(node.expr, structured_c.CVariable):
                    return node.expr
                if "[" in rendered and not isinstance(node.expr, structured_c.CConstant):
                    return node.expr

            if isinstance(node, structured_c.CBinaryOp):
                if id(node) in protected_dereference_addr_expr_ids:
                    return _normalize_protected_add_constant_tail(node)
                memory_backed_source = _expr_uses_memory_backed_temp(node, memory_backed_linear_temps)
                if memory_backed_source:
                    lhs = _unwrap_c_casts(node.lhs)
                    rhs = _unwrap_c_casts(node.rhs)
                else:
                    lhs = _resolve_copy_alias_expr(_unwrap_c_casts(node.lhs))
                    rhs = _resolve_copy_alias_expr(_unwrap_c_casts(node.rhs))
                try:
                    resolved = structured_c.CBinaryOp(node.op, lhs, rhs, codegen=codegen)
                except ValueError:
                    # Keep original node when angr cannot resolve operand sizes for
                    # transient synthetic types lacking arch context.
                    return node
                resolved_contains_dereference = _expr_contains_dereference(resolved)
                dereference_backed_source = _expr_uses_dereference_backed_temp(node, dereference_backed_linear_temps)
                storage_backed_source = dereference_backed_source or memory_backed_source
                if node.op in {"Add", "Or"}:
                    if not storage_backed_source:
                        widened = _match_adjacent_byte_pair_var_expr(lhs, rhs)
                        if widened is None:
                            widened = _match_adjacent_byte_pair_var_expr(rhs, lhs)
                        if widened is not None:
                            return widened
                        widened = _match_adjacent_register_pair_var_expr(lhs, rhs, codegen)
                        if widened is None:
                            widened = _match_adjacent_register_pair_var_expr(rhs, lhs, codegen)
                        if widened is not None:
                            return widened
                    if node.op == "Add":
                        if isinstance(lhs, structured_c.CVariable) and isinstance(getattr(lhs, "variable", None), SimStackVariable):
                            if _c_constant_value(rhs) is not None:
                                alias_expr = far_pointer_aliases.get(id(getattr(lhs, "variable", None)))
                                if alias_expr is not None:
                                    return _make_mk_fp(alias_expr, rhs)
                        if isinstance(rhs, structured_c.CVariable) and isinstance(getattr(rhs, "variable", None), SimStackVariable):
                            if _c_constant_value(lhs) is not None:
                                alias_expr = far_pointer_aliases.get(id(getattr(rhs, "variable", None)))
                                if alias_expr is not None:
                                    return _make_mk_fp(alias_expr, lhs)
                    if not resolved_contains_dereference and not storage_backed_source:
                        if not _memory_backed_widening_base(node):
                            delta = _match_word_plus_minus_one_expr(node)
                            if delta is not None:
                                return delta
                            linear = _match_linear_word_delta_expr(node)
                            if linear is not None:
                                return linear
                            high_update = _match_high_byte_preserving_word_expr(node)
                            if high_update is not None:
                                return high_update
                if node.op in {"Add", "Sub"}:
                    if not resolved_contains_dereference and not storage_backed_source:
                        if not _memory_backed_widening_base(resolved):
                            linear = _match_linear_word_delta_expr(resolved)
                            if linear is not None:
                                return linear
                if isinstance(lhs, structured_c.CConstant) and isinstance(rhs, structured_c.CConstant):
                    if isinstance(lhs.value, int) and isinstance(rhs.value, int):
                        result = None
                        if node.op == "Add":
                            result = lhs.value + rhs.value
                        elif node.op == "Sub":
                            result = lhs.value - rhs.value
                        elif node.op == "Mul":
                            result = lhs.value * rhs.value
                        elif node.op == "And":
                            result = lhs.value & rhs.value
                        elif node.op == "Or":
                            result = lhs.value | rhs.value
                        elif node.op == "Xor":
                            result = lhs.value ^ rhs.value
                        elif node.op == "Shl":
                            result = lhs.value << rhs.value
                        elif node.op == "Shr":
                            result = lhs.value >> rhs.value
                        if result is not None:
                            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                            return structured_c.CConstant(result, type_, codegen=codegen)
                rewritten_and = _rewrite_and_over_or(node)
                if rewritten_and is not None:
                    return rewritten_and
                if node.op in {"And", "Or"}:
                    terms = _flatten_bitwise_terms(node, node.op)
                    const_value = None
                    const_type = None
                    non_constants = []
                    for term in terms:
                        value = _c_constant_value(term)
                        if value is None:
                            non_constants.append(term)
                            continue
                        const_type = getattr(term, "type", None) or const_type
                        if const_value is None:
                            const_value = value
                        elif node.op == "And":
                            const_value &= value
                        else:
                            const_value |= value
                    if len(terms) > 2 or len(non_constants) != len(terms):
                        rebuilt_terms = list(non_constants)
                        if const_value is not None:
                            if not ((node.op == "And" and const_value == -1) or (node.op == "Or" and const_value == 0)):
                                rebuilt_terms.append(
                                    structured_c.CConstant(
                                        const_value,
                                        const_type or getattr(node, "type", None) or SimTypeShort(False),
                                        codegen=codegen,
                                    )
                                )
                        if not rebuilt_terms:
                            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                            return structured_c.CConstant(const_value if const_value is not None else 0, type_, codegen=codegen)
                        result = rebuilt_terms[0]
                        for term in rebuilt_terms[1:]:
                            result = structured_c.CBinaryOp(node.op, result, term, codegen=codegen)
                        return result
                if node.op in {"Add", "Or", "Xor"}:
                    if _c_constant_value(lhs) == 0:
                        return node.rhs
                    if _c_constant_value(rhs) == 0:
                        return node.lhs
                if node.op == "Sub":
                    if _c_constant_value(rhs) == 0:
                        return node.lhs
                if node.op == "Add":
                    folded = _fold_simple_add_constants(node)
                    if folded is not node:
                        return folded
                if node.op == "Sub":
                    base_expr, delta = _extract_linear_delta(node)
                    if base_expr is not None:
                        rebuilt = _build_linear_expr(base_expr, delta, codegen)
                        if not _same_c_expression(rebuilt, node):
                            return rebuilt
                if node.op in {"And", "Or"} and _same_c_expression(lhs, rhs):
                    return lhs
                if node.op == "Xor" and _same_c_expression(lhs, rhs):
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
                if node.op == "Mul":
                    for maybe_inner, maybe_other in ((lhs, rhs), (rhs, lhs)):
                        if _c_constant_value(maybe_other) is None:
                            continue
                        inner = _unwrap_c_casts(maybe_inner)
                        if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "And":
                            continue
                        if _c_constant_value(_unwrap_c_casts(inner.rhs)) != 0xFF:
                            continue
                        shifted = _match_high_byte_projection_expr(inner.lhs)
                        if shifted is None:
                            continue
                        return structured_c.CBinaryOp(
                            "Mul",
                            shifted,
                            maybe_other,
                            codegen=codegen,
                        )
                    if _c_constant_value(lhs) == 0 or _c_constant_value(rhs) == 0:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                        if type_ is not None:
                            return structured_c.CConstant(0, type_, codegen=codegen)
                    if _c_constant_value(lhs) == 1:
                        return node.rhs
                    if _c_constant_value(rhs) == 1:
                        return node.lhs
                if node.op == "And":
                    if _c_constant_value(lhs) == 0 or _c_constant_value(rhs) == 0:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                        if type_ is not None:
                            return structured_c.CConstant(0, type_, codegen=codegen)
                    for maybe_inner, maybe_mask in ((lhs, rhs), (rhs, lhs)):
                        if _c_constant_value(maybe_mask) == 0xFF and isinstance(maybe_inner, structured_c.CVariable):
                            variable = getattr(maybe_inner, "variable", None)
                            if variable is not None:
                                var_key = id(variable)
                                if (
                                    var_key in high_byte_aliases
                                    or var_key in shift_extract_aliases
                                    or var_key in mask_shift_aliases
                                ):
                                    return maybe_inner
                        if (
                            _c_constant_value(maybe_mask) == 0xFF
                            and isinstance(maybe_inner, structured_c.CBinaryOp)
                            and maybe_inner.op == "Shr"
                            and _is_c_constant_int(_unwrap_c_casts(maybe_inner.rhs), 8)
                            and isinstance(_unwrap_c_casts(maybe_inner.lhs), structured_c.CBinaryOp)
                            and _unwrap_c_casts(maybe_inner.lhs).op == "And"
                        ):
                            return maybe_inner
                        if _c_constant_value(maybe_mask) != 0xFF:
                            continue
                        projection = _match_high_byte_projection_expr(maybe_inner)
                        if projection is not None:
                            return projection
                        const_high = _match_high_byte_projection_constant(maybe_inner)
                        if const_high is not None:
                            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                            return structured_c.CConstant(const_high, type_, codegen=codegen)
                        if isinstance(maybe_inner, structured_c.CVariable):
                            alias = mask_shift_aliases.get(id(getattr(maybe_inner, "variable", None)))
                            if alias is not None:
                                base_expr, mask, total_shift = alias
                                if mask == 0xFF00:
                                    simplified = structured_c.CBinaryOp(
                                        "Shr",
                                        base_expr,
                                        structured_c.CConstant(total_shift, SimTypeShort(False), codegen=codegen),
                                        codegen=codegen,
                                    )
                                    base_type = getattr(getattr(base_expr, "type", None), "size", None)
                                    if total_shift == 8 and base_type == 16:
                                        return simplified
                                    return structured_c.CBinaryOp(
                                        "And",
                                        simplified,
                                        structured_c.CConstant(0xFF, SimTypeShort(False), codegen=codegen),
                                        codegen=codegen,
                                    )
                        inner = _unwrap_c_casts(maybe_inner)
                        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Shr":
                            shift = _c_constant_value(_unwrap_c_casts(inner.rhs))
                            shifted = _unwrap_c_casts(inner.lhs)
                            if isinstance(shifted, structured_c.CVariable):
                                alias = shift_extract_aliases.get(id(getattr(shifted, "variable", None)))
                                if alias is not None and isinstance(shift, int):
                                    base_expr, base_shift = alias
                                    total_shift = base_shift + shift
                                    simplified = structured_c.CBinaryOp(
                                        "Shr",
                                        base_expr,
                                        structured_c.CConstant(total_shift, SimTypeShort(False), codegen=codegen),
                                        codegen=codegen,
                                    )
                                    base_type = getattr(getattr(base_expr, "type", None), "size", None)
                                    if total_shift == 8 and base_type == 16:
                                        return simplified
                                    return structured_c.CBinaryOp(
                                        "And",
                                        simplified,
                                        structured_c.CConstant(0xFF, SimTypeShort(False), codegen=codegen),
                                        codegen=codegen,
                                    )
                simplified_or = _simplify_zero_mul_or_expr(node, codegen)
                if simplified_or is not node:
                    return simplified_or
                if node.op == "Shr":
                    if isinstance(lhs, structured_c.CBinaryOp) and lhs.op == "Shr":
                        inner_shift = _c_constant_value(_unwrap_c_casts(lhs.rhs))
                        outer_shift = _c_constant_value(rhs)
                        if isinstance(inner_shift, int) and isinstance(outer_shift, int):
                            return structured_c.CBinaryOp(
                                "Shr",
                                lhs.lhs,
                                structured_c.CConstant(inner_shift + outer_shift, SimTypeShort(False), codegen=codegen),
                                codegen=codegen,
                            )
                    if _is_c_constant_int(rhs, 8) and isinstance(lhs, structured_c.CVariable):
                        alias = high_byte_aliases.get(id(getattr(lhs, "variable", None)))
                        if alias is not None:
                            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                            return structured_c.CConstant(alias, type_, codegen=codegen)
                if lhs is not node.lhs or rhs is not node.rhs:
                    return resolved
            simplified = _simplify_boolean_expr(node, codegen)
            if simplified is not node:
                return simplified
            if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
                if _same_c_expression(node.lhs, node.rhs):
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
            if isinstance(node, structured_c.CAssignment) and _is_redundant_self_copy(node):
                return structured_c.CConstant(0, getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None), codegen=codegen)
            return node

        def prune_dead_stack_address_inits(node) -> bool:
            changed = False
            if isinstance(node, structured_c.CStatements):
                new_statements = []
                for stmt in node.statements:
                    if _is_dead_stack_address_init(stmt):
                        changed = True
                        continue
                    if _is_redundant_self_copy(stmt):
                        changed = True
                        continue
                    if prune_dead_stack_address_inits(stmt):
                        changed = True
                    new_statements.append(stmt)
                if changed or new_statements != node.statements:
                    node.statements = new_statements
            elif isinstance(node, structured_c.CIfElse):
                for _cond, body in node.condition_and_nodes:
                    if prune_dead_stack_address_inits(body):
                        changed = True
                if node.else_node is not None and prune_dead_stack_address_inits(node.else_node):
                    changed = True
            return changed

        root = codegen.cfunc.statements
        changed = False
        for _ in range(3):
            iter_changed = False
            high_byte_aliases = _collect_high_byte_temp_constants(root)
            shift_extract_aliases = _collect_shift_extract_aliases(root)
            mask_shift_aliases = _collect_mask_shift_aliases(root)
            copy_aliases = _collect_copy_aliases(root)
            dereference_backed_linear_temps = _collect_dereference_backed_linear_temps(root)
            memory_backed_linear_temps = _collect_memory_backed_linear_temps(root)
            far_pointer_aliases = _collect_far_pointer_stack_aliases(root)
            new_root = transform(root)
            if new_root is not root:
                codegen.cfunc.statements = new_root
                root = new_root
                iter_changed = True
            if _replace_c_children(root, transform):
                iter_changed = True
            if prune_dead_stack_address_inits(root):
                iter_changed = True
            changed |= iter_changed
            if not iter_changed:
                break
        return changed

    return _impl()

def _unwrap_c_casts(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node

def _match_shift_right_8_expr(node):
    def _impl():
        nonlocal node
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
            return None
        lhs = _unwrap_c_casts(node.lhs)
        rhs = _unwrap_c_casts(node.rhs)
        if _is_c_constant_int(rhs, 8):
            if (
                isinstance(lhs, structured_c.CBinaryOp)
                and lhs.op == "And"
                and _is_c_constant_int(_unwrap_c_casts(lhs.rhs), 0xFF)
            ):
                or_expr = _unwrap_c_casts(lhs.lhs)
                if isinstance(or_expr, structured_c.CBinaryOp) and or_expr.op == "Or":
                    for maybe_masked, maybe_const in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                        const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                        if not isinstance(const_value, int):
                            continue
                        if const_value & 0xFF00 == const_value and const_value & 0xFF == 0:
                            return structured_c.CConstant((const_value >> 8) & 0xFF, SimTypeChar(), codegen=getattr(node, "codegen", None))
            return lhs
        if _is_c_constant_int(lhs, 8):
            return rhs
        return None

    return _impl()

def _match_duplicate_word_increment_shift_expr(node, resolve_copy_alias_expr, codegen):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(node.rhs)) != 8:
        return None

    lhs = _unwrap_c_casts(node.lhs)
    if not isinstance(lhs, structured_c.CBinaryOp) or lhs.op not in {"Add", "Sub"}:
        return None

    def _match_duplicate_word_base(expr):
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
            return None
        for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            low_expr = resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
            high_expr = _unwrap_c_casts(maybe_high)
            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
                continue
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                    continue
                if _same_c_expression(low_expr, resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))):
                    return low_expr
        return None

    for maybe_word, maybe_const in ((lhs.lhs, lhs.rhs), (lhs.rhs, lhs.lhs)):
        if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
            continue
        base_expr = _match_duplicate_word_base(maybe_word)
        if base_expr is None:
            continue
        return structured_c.CBinaryOp(
            "Add" if lhs.op == "Add" else "Sub",
            base_expr,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    return None

def _match_duplicate_word_base_expr(node, resolve_copy_alias_expr):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None

    for maybe_low, maybe_high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_expr = resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
        high_expr = _unwrap_c_casts(maybe_high)
        if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
            continue
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                continue
            if _same_c_expression(low_expr, resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))):
                return low_expr

    return None

def _attach_cod_global_names(project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                linear = getattr(variable, "addr", None)
                symbol = _synthetic_global_entry(synthetic_globals, linear) if isinstance(linear, int) else None
                if symbol is not None:
                    type_ = getattr(node, "variable_type", None)
                    if type_ is None:
                        return node
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    key = (linear, size)
                    existing = created.get(key)
                    if existing is not None:
                        return existing
                    name, _width = symbol
                    name = _sanitize_cod_identifier(name)
                    cvar = structured_c.CVariable(
                        SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
                        variable_type=type_,
                        codegen=codegen,
                    )
                    created[key] = cvar
                    return cvar

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            addr_expr = _extract_dereference_addr_expr(node)
            addr_value = _c_constant_value(_unwrap_c_casts(addr_expr)) if addr_expr is not None else None
            symbol = _synthetic_global_entry(synthetic_globals, addr_value) if isinstance(addr_value, int) else None
            if symbol is not None:
                type_ = getattr(node, "type", None)
                if type_ is None:
                    return node
                bits = getattr(type_, "size", None)
                size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                key = (addr_value, size)
                existing = created.get(key)
                if existing is not None:
                    return existing
                name, _width = symbol
                name = _sanitize_cod_identifier(name)
                cvar = structured_c.CVariable(
                    SimMemoryVariable(addr_value, size, name=name, region=codegen.cfunc.addr),
                    variable_type=type_,
                    codegen=codegen,
                )
                created[key] = cvar
                return cvar

        seg_name, linear = _match_segmented_dereference(node, project)
        symbol = _synthetic_global_entry(synthetic_globals, linear)
        if seg_name != "ds" or symbol is None:
            return node

        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        bits = getattr(type_, "size", None)
        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        key = (linear, size)
        existing = created.get(key)
        if existing is not None:
            return existing

        name, _width = symbol
        name = _sanitize_cod_identifier(name)
        cvar = structured_c.CVariable(
            SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
            variable_type=type_,
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed

def _attach_cod_global_declaration_names(codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    def _impl():
        if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
            return False

        changed = False

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimMemoryVariable):
                continue
            symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
            if symbol is None:
                continue
            raw_name, _width = symbol
            name = _sanitize_cod_identifier(raw_name)
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            if getattr(cvar, "name", None) != name:
                cvar.name = name
                changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != name:
                unified.name = name
                changed = True

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                if not isinstance(variable, SimMemoryVariable):
                    continue
                symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
                if symbol is None:
                    continue
                raw_name, _width = symbol
                name = _sanitize_cod_identifier(raw_name)
                new_entries = set()
                for cvariable, vartype in cvar_and_vartypes:
                    if getattr(cvariable, "name", None) != name:
                        cvariable.name = name
                        changed = True
                    new_entries.add((cvariable, vartype))
                if new_entries != cvar_and_vartypes:
                    unified_locals[variable] = new_entries
                    changed = True

        return changed

    return _impl()

def _attach_cod_global_declaration_types(codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    def _impl():
        if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
            return False

        short_type = SimTypeShort(False)
        char_type = SimTypeChar(False)
        changed = False

        def _desired_global_spec(variable) -> tuple[object | None, int | None, str | None]:
            symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
            if symbol is None:
                return None, None, None
            raw_name, width = symbol
            known_spec = known_cod_object_spec(raw_name)
            if known_spec is not None:
                return known_spec.type, known_spec.size, known_spec.name
            if width == 1:
                return char_type, 1, None
            if width >= 2:
                return short_type, 2, None
            return None, None, None

        def _apply_type_and_size(variable, cvar, new_type, new_size) -> bool:
            local_changed = False
            if new_size is not None and getattr(variable, "size", None) != new_size:
                variable.size = new_size
                local_changed = True
            if getattr(cvar, "variable_type", None) != new_type:
                cvar.variable_type = new_type
                local_changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and new_size is not None and getattr(unified, "size", None) != new_size:
                try:
                    unified.size = new_size
                    local_changed = True
                except Exception:
                    pass
            return local_changed

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimMemoryVariable):
                continue
            new_type, new_size, target_name = _desired_global_spec(variable)
            if new_type is None:
                continue
            changed = _apply_type_and_size(variable, cvar, new_type, new_size) or changed
            unified = getattr(cvar, "unified_variable", None)
            if target_name is not None:
                if getattr(variable, "name", None) != target_name:
                    variable.name = target_name
                    changed = True
                if getattr(cvar, "name", None) != target_name:
                    cvar.name = target_name
                    changed = True
                if unified is not None and getattr(unified, "name", None) != target_name:
                    unified.name = target_name
                    changed = True

        for cextern in getattr(codegen, "cexterns", ()) or ():
            variable = getattr(cextern, "variable", None)
            if not isinstance(variable, SimMemoryVariable):
                continue
            new_type, new_size, _ = _desired_global_spec(variable)
            if new_type is None:
                continue
            if new_size is not None and getattr(variable, "size", None) != new_size:
                variable.size = new_size
                changed = True
            if getattr(cextern, "variable_type", None) != new_type:
                cextern.variable_type = new_type
                changed = True

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                if not isinstance(variable, SimMemoryVariable):
                    continue
                new_type, new_size, _ = _desired_global_spec(variable)
                if new_type is None:
                    continue
                if new_size is not None and getattr(variable, "size", None) != new_size:
                    variable.size = new_size
                    changed = True
                new_entries = {(cvariable, new_type) for cvariable, _vartype in cvar_and_vartypes}
                if new_entries != cvar_and_vartypes:
                    unified_locals[variable] = new_entries
                    changed = True

        return changed

    return _impl()

def _access_trait_field_name(offset: int, size: int) -> str:
    return f"field_{offset:x}"

def _stack_object_name(offset: int) -> str:
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"

def _access_trait_variable_key(variable) -> tuple[object, ...] | None:
    if isinstance(variable, SimRegisterVariable):
        return ("reg", getattr(variable, "reg", None))
    if isinstance(variable, SimStackVariable):
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return None
        return ("stack", identity.base, getattr(variable, "offset", None), getattr(variable, "region", None))
    if isinstance(variable, SimMemoryVariable):
        return ("mem", getattr(variable, "addr", None))
    return None

def _access_trait_profile_for_key(
    evidence_profiles: Mapping[tuple[object, ...], "_AccessTraitEvidenceProfile"],
    base_key: tuple[object, ...],
) -> "_AccessTraitEvidenceProfile | None":
    return _cli_access_profiles.access_trait_profile_for_key(evidence_profiles, base_key)

@dataclass(frozen=True)
class _WideningMatch:
    kind: str
    base_expr: object
    delta: int = 0

@dataclass(frozen=True)
class _AccessTraitRewriteDecision:
    base_key: tuple[object, ...]
    profile: _AccessTraitEvidenceProfile

    def _inner(self) -> _cli_access_profiles.AccessTraitRewriteDecision:
        return _cli_access_profiles.AccessTraitRewriteDecision(self.base_key, self.profile)

    def should_rename_stack(self) -> bool:
        return self._inner().should_rename_stack()

    def preferred_kind(self) -> str | None:
        return self._inner().preferred_kind()

    def candidate_field_names(self) -> tuple[str, ...]:
        return self._inner().candidate_field_names(_access_trait_field_name)

def _build_access_trait_evidence_profiles(
    traits: dict[str, dict[tuple[object, ...], object]]
) -> dict[tuple[object, ...], _AccessTraitEvidenceProfile]:
    return _cli_access_profiles.build_access_trait_evidence_profiles(traits)

def _analyze_widening_expr(
    node,
    resolve_copy_alias_expr,
    match_high_byte_projection_base,
):
    def _impl():
        nonlocal node
        node = resolve_copy_alias_expr(_unwrap_c_casts(node))

        def _extract(expr, seen: set[int] | None = None, depth: int = 0):
            if depth > 64:
                return expr, 0
            expr = resolve_copy_alias_expr(_unwrap_c_casts(expr))
            if seen is None:
                seen = set()
            key = id(expr)
            if key in seen:
                return expr, 0
            seen.add(key)
            if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
                return None, int(expr.value)
            if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
                duplicate_word_base = _match_duplicate_word_base_expr(expr, resolve_copy_alias_expr)
                if duplicate_word_base is not None:
                    return duplicate_word_base, 0
            if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
                return expr, 0

            left_base, left_delta = _extract(expr.lhs, seen, depth + 1)
            right_base, right_delta = _extract(expr.rhs, seen, depth + 1)
            if isinstance(left_base, structured_c.CBinaryOp) and left_base.op == "Or":
                duplicate_word_base = _match_duplicate_word_base_expr(left_base, resolve_copy_alias_expr)
                if duplicate_word_base is None:
                    return expr, 0
                left_base = duplicate_word_base
            if isinstance(right_base, structured_c.CBinaryOp) and right_base.op == "Or":
                duplicate_word_base = _match_duplicate_word_base_expr(right_base, resolve_copy_alias_expr)
                if duplicate_word_base is None:
                    return expr, 0
                right_base = duplicate_word_base
            if left_base is not None and right_base is not None:
                if _same_c_expression(left_base, right_base) and expr.op == "Add":
                    return left_base, left_delta + right_delta
                return expr, 0
            if left_base is not None:
                if expr.op == "Add":
                    return left_base, left_delta + right_delta
                return left_base, left_delta - right_delta
            if right_base is not None:
                if expr.op == "Add":
                    return right_base, left_delta + right_delta
                return expr, 0
            if expr.op == "Add":
                return None, left_delta + right_delta
            return None, left_delta - right_delta

        base_expr, delta = _extract(node)
        if base_expr is not None and isinstance(delta, int) and delta != 0:
            return _WideningMatch("linear", base_expr, delta)

        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return None

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_expr = _unwrap_c_casts(low_expr)
            high_expr = _unwrap_c_casts(high_expr)
            if not isinstance(low_expr, structured_c.CBinaryOp) or low_expr.op != "And":
                continue

            base_expr = None
            for maybe_word, maybe_mask in ((low_expr.lhs, low_expr.rhs), (low_expr.rhs, low_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 255:
                    continue
                base_expr = _unwrap_c_casts(maybe_word)
                break
            if base_expr is None:
                continue

            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op != "Mul":
                continue

            for maybe_delta, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                    continue
                delta_expr = _unwrap_c_casts(maybe_delta)
                if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
                    continue

                for maybe_inner, maybe_const in ((delta_expr.lhs, delta_expr.rhs), (delta_expr.rhs, delta_expr.lhs)):
                    if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
                        continue
                    if match_high_byte_projection_base(maybe_inner) is None:
                        continue
                    if not _same_c_expression(_unwrap_c_casts(maybe_inner), base_expr):
                        continue
                    return _WideningMatch("high_byte_preserving", base_expr, 0x100)

        return None

    return _impl()

def _access_trait_member_candidates(traits: dict[str, dict[tuple[object, ...], int]]) -> dict[tuple[object, ...], list[tuple[int, int, int]]]:
    return _cli_access_profiles.access_trait_member_candidates(traits)

def _should_attach_access_trait_names(codegen) -> bool:
    return _cli_access_trait_rewrite._should_attach_access_trait_names(
        codegen,
        has_access_rewrite_artifact=lambda current_codegen: _cli_access_rewrite_artifact.has_access_rewrite_artifact(
            getattr(current_codegen, "project", None),
            getattr(getattr(current_codegen, "cfunc", None), "addr", None),
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
                traits,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            ),
        ),
    )

def _attach_access_trait_field_names(project: angr.Project, codegen) -> bool:
    return _cli_access_trait_rewrite._attach_access_trait_field_names(
        project,
        codegen,
        should_attach_access_trait_names=_should_attach_access_trait_names,
        load_access_rewrite_artifact=lambda current_project, function_addr: _cli_access_rewrite_artifact.load_access_rewrite_artifact(
            current_project,
            function_addr,
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
                traits,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            ),
        ),
        stable_access_object_hint_for_key=_cli_access_object_hints._stable_access_object_hint_for_key,
        access_trait_variable_key=_access_trait_variable_key,
        stack_object_name=_stack_object_name,
        access_trait_field_name=_access_trait_field_name,
        replace_c_children=_replace_c_children,
    )

def _attach_pointer_member_names(project: angr.Project, codegen) -> bool:
    return _cli_access_trait_rewrite._attach_pointer_member_names(
        project,
        codegen,
        should_attach_access_trait_names=_should_attach_access_trait_names,
        load_access_rewrite_artifact=lambda current_project, function_addr: _cli_access_rewrite_artifact.load_access_rewrite_artifact(
            current_project,
            function_addr,
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
                traits,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            ),
        ),
        stable_access_object_hint_for_key=_cli_access_object_hints._stable_access_object_hint_for_key,
        access_trait_variable_key=_access_trait_variable_key,
        access_trait_field_name=_access_trait_field_name,
        replace_c_children=_replace_c_children,
    )

def _attach_lst_data_names(project: angr.Project, codegen, lst_metadata: LSTMetadata | None) -> bool:
    if lst_metadata is None or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    temp_const_aliases: dict[int, int] = {}

    def is_linear_temp(cvar) -> bool:
        return (
            isinstance(cvar, structured_c.CVariable)
            and isinstance(getattr(cvar, "name", None), str)
            and re.fullmatch(r"v\d+", getattr(cvar, "name", "")) is not None
        )

    def collect_temp_aliases() -> None:
        aliases: dict[int, int] = {}
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not is_linear_temp(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                value = None
                if isinstance(rhs, structured_c.CConstant) and isinstance(rhs.value, int):
                    value = rhs.value
                elif isinstance(rhs, structured_c.CVariable):
                    value = aliases.get(id(getattr(rhs, "variable", None)))
                if value is None:
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                if aliases.get(key) != value:
                    aliases[key] = value
                    changed = True
            if not changed:
                break
        temp_const_aliases.update(aliases)

    def resolved_constant_value(node, seen_nodes: set[int] | None = None) -> int | None:
        node = _unwrap_c_casts(node)
        if seen_nodes is None:
            seen_nodes = set()
        key = id(node)
        if key in seen_nodes:
            return None
        seen_nodes.add(key)
        constant = _c_constant_value(node)
        if constant is not None:
            return constant
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if variable is not None:
                return temp_const_aliases.get(id(variable))
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = resolved_constant_value(node.lhs, seen_nodes)
            rhs = resolved_constant_value(node.rhs, seen_nodes)
            if lhs is not None and rhs is not None:
                return lhs + rhs if node.op == "Add" else lhs - rhs
        return None

    collect_temp_aliases()

    def make_data_var(offset: int, size: int, label: str):
        key = (offset, size)
        existing = created.get(key)
        if existing is not None:
            return existing
        cvar = structured_c.CVariable(
            SimMemoryVariable(offset, size, name=_sanitize_cod_identifier(label), region=codegen.cfunc.addr),
            variable_type=SimTypeChar(False) if size == 1 else SimTypeShort(False),
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                addr = getattr(variable, "addr", None)
                label = lst_metadata.data_labels.get(addr) if isinstance(addr, int) else None
                if label is not None and isinstance(addr, int):
                    type_ = getattr(node, "variable_type", None)
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    return make_data_var(addr, size, label)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            operand = node.operand
            if isinstance(operand, structured_c.CTypeCast):
                operand = operand.expr

            seg_name = None
            linear = 0
            saw_segment = False
            other_terms: list[object] = []
            for term in _flatten_c_add_terms(operand):
                inner = _unwrap_c_casts(term)
                if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                    for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                            continue
                        name = _segment_reg_name(_unwrap_c_casts(maybe_seg), project)
                        if name is not None:
                            seg_name = name
                            saw_segment = True
                            break
                    if saw_segment:
                        continue

                const_value = resolved_constant_value(inner)
                if const_value is not None:
                    linear += const_value
                    continue

                other_terms.append(inner)

            if seg_name == "ds" and not other_terms:
                label = _lst_data_label(lst_metadata, linear)
                if label is not None:
                    type_ = getattr(node, "type", None)
                    if type_ is not None:
                        bits = getattr(type_, "size", None)
                        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                        return make_data_var(linear, size, label)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed

def _normalize_scalar_byte_register_types(codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        target_type = SimTypeChar(False)
        changed = False

        def _is_stable_byte_register(expr) -> bool:
            facts = describe_alias_storage(expr)
            domain = facts.domain
            return (
                domain.space == "register"
                and domain.width == 8
                and not domain.is_unknown()
                and not domain.is_mixed()
                and not facts.needs_synthesis()
                and facts.identity is not None
            )

        def _set_variable_type(node, type_) -> bool:
            if not hasattr(node, "variable_type"):
                return False
            if getattr(node, "variable_type", None) == type_:
                return False
            try:
                node.variable_type = type_
            except Exception:
                return False
            return True

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimRegisterVariable):
                continue
            if getattr(variable, "size", None) != 1:
                continue
            if not _is_stable_byte_register(cvar):
                continue
            current_type = getattr(cvar, "variable_type", None)
            if current_type != target_type and _set_variable_type(cvar, target_type):
                changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and _set_variable_type(unified, target_type):
                changed = True

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                if not isinstance(variable, SimRegisterVariable):
                    continue
                if getattr(variable, "size", None) != 1:
                    continue
                new_entries = {
                    (
                        cvariable,
                        target_type if _is_stable_byte_register(cvariable) else vartype,
                    )
                    for cvariable, vartype in cvar_and_vartypes
                }
                if new_entries != cvar_and_vartypes:
                    unified_locals[variable] = new_entries
                    changed = True

        for node in _iter_c_nodes_deep(getattr(codegen.cfunc, "statements", None)):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = getattr(node, "variable", None)
            if not isinstance(variable, SimRegisterVariable):
                continue
            if getattr(variable, "size", None) != 1:
                continue
            if not _is_stable_byte_register(node):
                continue
            if getattr(node, "variable_type", None) != target_type:
                changed = _set_variable_type(node, target_type) or changed
            unified = getattr(node, "unified_variable", None)
            if unified is not None and hasattr(unified, "variable_type") and _set_variable_type(unified, target_type):
                changed = True

        return changed

    return _impl()

def _attach_segment_register_names(codegen, project: angr.Project | None = None) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        desired_names = {"cs", "ds", "es", "ss", "fs", "gs"}
        changed = False

        def reg_name(variable) -> str | None:
            if not isinstance(variable, SimRegisterVariable):
                return None
            if project is not None:
                name = project.arch.register_names.get(getattr(variable, "reg", None))
                if name in desired_names:
                    return name
            name = getattr(variable, "name", None)
            if isinstance(name, str) and name in desired_names:
                return name
            return None

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            name = reg_name(variable)
            if name is None:
                continue
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != name:
                unified.name = name
                changed = True

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                name = reg_name(variable)
                if name is None:
                    continue
                new_entries = set()
                for cvariable, vartype in cvar_and_vartypes:
                    new_entries.add((cvariable, vartype))
                if new_entries != cvar_and_vartypes:
                    unified_locals[variable] = new_entries
                    changed = True

        return changed

    return _impl()

def _attach_register_names(project: angr.Project, codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        register_names = getattr(getattr(project, "arch", None), "register_names", None)
        registers = getattr(getattr(project, "arch", None), "registers", None)
        if not isinstance(register_names, dict):
            return False
        if not isinstance(registers, dict):
            registers = {}

        def is_generic_name(name: object) -> bool:
            return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None

        changed = False

        def register_name(variable) -> str | None:
            if not isinstance(variable, SimRegisterVariable):
                return None
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                for name, (offset, reg_size) in registers.items():
                    if offset == reg and reg_size == size:
                        return name
            name = register_names.get(reg)
            if not isinstance(name, str) or not name:
                return None
            return name

        def maybe_rename(variable, cvar, name: str) -> None:
            nonlocal changed
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            if getattr(cvar, "name", None) != name:
                try:
                    cvar.name = name
                except Exception:
                    pass
                else:
                    changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != name:
                unified.name = name
                changed = True

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            name = register_name(variable)
            if name is None:
                continue
            if not any(
                is_generic_name(candidate)
                for candidate in (
                    getattr(variable, "name", None),
                    getattr(cvar, "name", None),
                    getattr(getattr(cvar, "unified_variable", None), "name", None),
                )
            ):
                continue
            maybe_rename(variable, cvar, name)

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, cvar_and_vartypes in list(unified_locals.items()):
                name = register_name(variable)
                if name is None:
                    continue
                if not any(
                    is_generic_name(candidate)
                    for candidate in (
                        getattr(variable, "name", None),
                        *(getattr(cvar, "name", None) for cvar, _vartype in cvar_and_vartypes),
                    )
                ):
                    continue
                for cvar, _vartype in cvar_and_vartypes:
                    maybe_rename(variable, cvar, name)

        return changed

    return _impl()

def _elide_redundant_segment_pointer_dereferences(project: angr.Project, codegen) -> bool:
    return _cli_segmented_elision._elide_redundant_segment_pointer_dereferences(
        project,
        codegen,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        classify_segmented_dereference=_classify_segmented_dereference,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        segment_reg_name=_segment_reg_name,
        match_segment_register_based_dereference=_match_segment_register_based_dereference,
        strip_segment_scale_from_addr_expr=_strip_segment_scale_from_addr_expr,
        same_c_storage=_same_c_storage,
        replace_c_children=_replace_c_children,
    )

def _collect_access_traits(project: angr.Project, codegen) -> bool:
    return _cli_access_traits._collect_access_traits(
        project,
        codegen,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        classify_segmented_dereference=_classify_segmented_dereference,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
        access_trait_variable_key=_access_trait_variable_key,
        AccessTraitStrideEvidence=_AccessTraitStrideEvidence,
    )

def _prune_unused_unnamed_memory_declarations(codegen) -> bool:
    return _cli_memory_prune._prune_unused_unnamed_memory_declarations(
        codegen,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

def _prune_unused_linear_register_declarations(codegen) -> bool:
    return _cli_local_prune._prune_unused_linear_register_declarations(
        codegen,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

def _prune_unused_local_declarations(codegen) -> bool:
    return _cli_local_prune._prune_unused_local_declarations(
        codegen,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        describe_alias_storage=describe_alias_storage,
    )

def _prune_dead_local_assignments(codegen) -> bool:
    return _cli_dead_local_prune._prune_dead_local_assignments(
        codegen,
        structured_codegen_node=_structured_codegen_node,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        unwrap_c_casts=_unwrap_c_casts,
        describe_alias_storage=describe_alias_storage,
    )

def _materialize_missing_stack_local_declarations(codegen) -> bool:
    return _cli_local_rewrites._materialize_missing_stack_local_declarations(
        codegen,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
        stack_type_for_size=_stack_type_for_size,
        replace_c_children=_replace_c_children,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

def _dedupe_codegen_variable_names_8616(codegen) -> bool:
    return _cli_local_rewrites._dedupe_codegen_variable_names_8616(
        codegen,
        make_unique_identifier=_make_unique_identifier,
    )

def _materialize_missing_register_local_declarations(codegen) -> bool:
    return _cli_local_rewrites._materialize_missing_register_local_declarations(
        codegen,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
        stack_type_for_size=_stack_type_for_size,
        structured_codegen_node=_structured_codegen_node,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

def _prune_void_function_return_values(codegen) -> bool:
    return _cli_local_rewrites._prune_void_function_return_values(
        codegen,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

def _coalesce_far_pointer_stack_expressions(project: angr.Project, codegen) -> bool:
    return _cli_far_pointer_stack._coalesce_far_pointer_stack_expressions(
        project,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        segment_reg_name=_segment_reg_name,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
        ),
        access_trait_variable_key=_access_trait_variable_key,
        replace_c_children=_replace_c_children,
        describe_alias_storage=describe_alias_storage,
    )

def _simplify_nested_mk_fp_calls(codegen) -> bool:
    return _cli_mkfp_simplify._simplify_nested_mk_fp_calls(
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        replace_c_children=_replace_c_children,
    )

def _attach_ss_stack_variables(project: angr.Project, codegen) -> bool:
    return _cli_stack_locals._attach_ss_stack_variables(
        project,
        codegen,
        match_ss_stack_reference=_match_ss_stack_reference,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        replace_c_children=_replace_c_children,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
    )

def _rewrite_ss_stack_byte_offsets(project: angr.Project, codegen) -> bool:
    return _cli_stack_byte_offsets._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        replace_c_children=_replace_c_children,
        c_constant_value=_c_constant_value,
        flatten_c_add_terms=_flatten_c_add_terms,
        classify_segmented_dereference=_classify_segmented_dereference,
        strip_segment_scale_from_addr_expr=_strip_segment_scale_from_addr_expr,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
        materialize_stack_cvar_at_offset=_materialize_stack_cvar_at_offset,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
        stack_pointer_alias_state=_StackPointerAliasState,
    )

def _promote_direct_stack_cvariable(codegen, cvar, size: int, type_) -> bool:
    return _cli_stack_locals._promote_direct_stack_cvariable(codegen, cvar, size, type_)

def _stack_type_for_size(size: int):
    return _cli_stack_locals._stack_type_for_size(size)

def _resolve_stack_cvar_at_offset(codegen, offset: int, *, preferred_size: int | None = None):
    return _cli_stack_cvars._resolve_stack_cvar_at_offset(
        codegen,
        offset,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
        preferred_size=preferred_size,
    )

def _materialize_stack_cvar_at_offset(codegen, offset: int, size: int = 2):
    return _cli_stack_cvars._materialize_stack_cvar_at_offset(
        codegen,
        offset,
        size,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
    )

def _canonicalize_stack_cvar_expr(
    expr,
    codegen,
    active_expr_ids: set[int] | None = None,
    analysis_context: dict[str, object] | None = None,
):
    return _cli_stack_cvars._canonicalize_stack_cvar_expr(
        expr,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        materialize_stack_cvar_at_offset=_materialize_stack_cvar_at_offset,
        active_expr_ids=active_expr_ids,
        analysis_context=analysis_context,
    )

def _canonicalize_stack_cvars(codegen) -> bool:
    return _cli_stack_cvars._canonicalize_stack_cvars(
        codegen,
        replace_c_children=_replace_c_children,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
    )

def _resolve_stack_cvar_from_addr_expr(project: angr.Project, codegen, addr_expr):
    return _cli_stack_cvars._resolve_stack_cvar_from_addr_expr(
        project,
        codegen,
        addr_expr,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        materialize_stack_cvar_at_offset=_materialize_stack_cvar_at_offset,
        stack_type_for_size=_stack_type_for_size,
    )

def _coalesce_direct_ss_local_word_statements(project: angr.Project, codegen) -> bool:
    return _cli_stack_coalesce._coalesce_direct_ss_local_word_statements(
        project,
        codegen,
        match_ss_local_plus_const=_match_ss_local_plus_const,
        match_shift_right_8_expr=_match_shift_right_8_expr,
        stack_slot_identity_can_join=_stack_slot_identity_can_join,
        same_c_expression=_same_c_expression,
        unwrap_c_casts=_unwrap_c_casts,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
        match_byte_store_addr_expr=_match_byte_store_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=_resolve_stack_cvar_from_addr_expr,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
    )

def _seed_adjacent_byte_pair_aliases(project: angr.Project, codegen) -> dict[int, object]:
    return _cli_linear_aliases._seed_adjacent_byte_pair_aliases(
        project,
        codegen,
        structured_codegen_node=_structured_codegen_node,
        unwrap_c_casts=_unwrap_c_casts,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        make_word_dereference_from_addr_expr=_make_word_dereference_from_addr_expr,
    )

def _coalesce_linear_recurrence_statements(project: angr.Project, codegen) -> bool:
    return _cli_linear_recurrence._coalesce_linear_recurrence_statements(
        project,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        structured_codegen_node=_structured_codegen_node,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        same_c_expression=_same_c_expression,
        c_constant_value=_c_constant_value,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
        seed_adjacent_byte_pair_aliases=_seed_adjacent_byte_pair_aliases,
        describe_alias_storage=describe_alias_storage,
        analyze_widening_expr=_analyze_widening_expr,
        match_high_byte_projection_base=_match_high_byte_projection_base,
        match_duplicate_word_base_expr=_match_duplicate_word_base_expr,
        match_duplicate_word_increment_shift_expr=_match_duplicate_word_increment_shift_expr,
        same_stack_slot_identity_var=_same_stack_slot_identity_var,
        rules=_cli_linear_recurrence_rules,
    )

def _coalesce_segmented_word_store_statements(project: angr.Project, codegen) -> bool:
    return _cli_segmented_store_coalesce._coalesce_segmented_word_store_statements(
        project,
        codegen,
        match_ss_local_plus_const=_match_ss_local_plus_const,
        match_word_rhs_from_byte_pair=_match_word_rhs_from_byte_pair,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
        stack_slot_identity_can_join=_stack_slot_identity_can_join,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
        match_byte_store_addr_expr=_match_byte_store_addr_expr,
        match_shift_right_8_expr=_match_shift_right_8_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=_resolve_stack_cvar_from_addr_expr,
        make_word_dereference_from_addr_expr=_make_word_dereference_from_addr_expr,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        describe_alias_storage=describe_alias_storage,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        same_c_expression=_same_c_expression,
    )

def _run_typed_widening_pass(project: angr.Project, codegen) -> bool:
    return _cli_segmented_store_coalesce.run_typed_widening_pass_8616(
        project,
        codegen,
        coalesce_direct_ss_local_word_statements=_coalesce_direct_ss_local_word_statements,
        coalesce_segmented_word_store_statements=_coalesce_segmented_word_store_statements,
        promote_stack_slots_from_instruction_widths=lambda current_project, current_codegen: (
            _cli_segmented_store_coalesce.promote_stack_slots_from_instruction_widths_8616(
                current_project,
                current_codegen,
                resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
                promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
                stack_type_for_size=_stack_type_for_size,
            )
        ),
    )

def _global_memory_addr(node) -> int | None:
    return _cli_word_loads._global_memory_addr(node)

def _global_load_addr(node, project: angr.Project) -> int | None:
    return _cli_word_loads._global_load_addr(node, project)

def _match_scaled_high_byte(node, project: angr.Project) -> int | None:
    return _cli_word_loads._match_scaled_high_byte(
        node,
        project,
        c_constant_value=_c_constant_value,
        global_load_addr=_global_load_addr,
    )

def _extract_dereference_addr_expr(node):
    return _cli_word_loads._extract_dereference_addr_expr(node)

def _match_byte_load_addr_expr(node):
    return _cli_word_loads._match_byte_load_addr_expr(
        node,
        unwrap_c_casts=_unwrap_c_casts,
    )

def _match_byte_store_addr_expr(node):
    return _cli_word_loads._match_byte_store_addr_expr(node)

def _match_shifted_high_byte_addr_expr(node):
    return _cli_word_loads._match_shifted_high_byte_addr_expr(
        node,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
    )

def _match_word_pair_low_addr_expr(node, project: angr.Project):
    return _cli_word_loads._match_word_pair_low_addr_expr(
        node,
        project,
        unwrap_c_casts=_unwrap_c_casts,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        match_shifted_high_byte_addr_expr=_match_shifted_high_byte_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
    )

def _split_expr_const_offset(node):
    return _cli_segmented_compare._split_expr_const_offset(
        node,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
    )

def _same_expression_list(lhs_terms, rhs_terms) -> bool:
    return _cli_segmented_compare._same_expression_list(
        lhs_terms,
        rhs_terms,
        same_c_expression=_same_c_expression,
    )

def _addr_exprs_are_same(low_addr_expr, high_addr_expr, project: angr.Project) -> bool:
    return _cli_segmented_compare._addr_exprs_are_same(
        low_addr_expr,
        high_addr_expr,
        project,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        same_c_expression=_same_c_expression,
        split_expr_const_offset=_split_expr_const_offset,
        same_expression_list=_same_expression_list,
    )

def _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project: angr.Project | None = None) -> bool:
    return _cli_segmented_compare._addr_exprs_are_byte_pair(
        low_addr_expr,
        high_addr_expr,
        project,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        stack_slot_identity_can_join_var=_stack_slot_identity_can_join_var,
        split_expr_const_offset=_split_expr_const_offset,
        same_expression_list=_same_expression_list,
    )

def _make_word_dereference_from_addr_expr(codegen, project: angr.Project, addr_expr):
    return _cli_word_loads._make_word_dereference_from_addr_expr(codegen, project, addr_expr)

def _match_word_dereference_addr_expr(node):
    return _cli_word_loads._match_word_dereference_addr_expr(node)


def _word_from_constant_byte_pair(low_unwrapped, high_unwrapped, codegen):
    if not (
        isinstance(low_unwrapped, structured_c.CConstant)
        and isinstance(low_unwrapped.value, int)
        and isinstance(high_unwrapped, structured_c.CConstant)
        and isinstance(high_unwrapped.value, int)
    ):
        return None
    return _canonicalize_stack_cvar_expr(
        structured_c.CConstant(
            (low_unwrapped.value & 0xFF) | ((high_unwrapped.value & 0xFF) << 8),
            SimTypeShort(False),
            codegen=codegen,
        ),
        codegen,
    )


def _word_from_adjacent_memory_bytes(low_unwrapped, high_unwrapped, codegen):
    def _impl():
        low_mem_addr = _global_memory_addr(low_unwrapped)
        high_mem_addr = _global_memory_addr(high_unwrapped)
        if not (
            isinstance(low_unwrapped, structured_c.CVariable)
            and isinstance(high_unwrapped, structured_c.CVariable)
            and isinstance(getattr(low_unwrapped, "variable", None), SimMemoryVariable)
            and isinstance(getattr(high_unwrapped, "variable", None), SimMemoryVariable)
            and low_mem_addr is not None
            and high_mem_addr == low_mem_addr + 1
        ):
            return None
        if not analyze_adjacent_storage_slices(low_unwrapped, high_unwrapped).ok:
            return None
        low_var = getattr(low_unwrapped, "variable", None)
        name = getattr(low_var, "name", None) if isinstance(low_var, SimMemoryVariable) else None
        if not isinstance(name, str) or not name or re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
            return None
        return _canonicalize_stack_cvar_expr(
            structured_c.CVariable(
                SimMemoryVariable(low_mem_addr, 2, name=_sanitize_cod_identifier(name), region=codegen.cfunc.addr),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            codegen,
        )

    return _impl()


def _word_from_shifted_high_expr(low_rhs, high_rhs, low_unwrapped, codegen, project: angr.Project):
    def _safe_type_size(node) -> int | None:
        try:
            return getattr(getattr(node, "type", None), "size", None)
        except ValueError:
            return None

    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is None:
        return None
    shifted_source = _unwrap_c_casts(shifted_source)
    low_bits = _safe_type_size(low_unwrapped)
    if (
        _same_c_expression(_unwrap_c_casts(low_rhs), shifted_source)
        and (isinstance(low_unwrapped, (structured_c.CVariable, structured_c.CConstant)) or low_bits == 16)
    ):
        return _canonicalize_stack_cvar_expr(low_rhs, codegen)
    low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
    word_addr_expr = _match_word_dereference_addr_expr(shifted_source)
    if low_addr_expr is not None and word_addr_expr is not None and _addr_exprs_are_same(low_addr_expr, word_addr_expr, project):
        return _canonicalize_stack_cvar_expr(shifted_source, codegen)
    return None


def _word_from_pair_low_addr(low_unwrapped, high_rhs, codegen, project: angr.Project):
    low_pair_addr = _match_word_pair_low_addr_expr(low_unwrapped, project)
    if low_pair_addr is None:
        return None
    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is None:
        return None
    word_addr_expr = _match_word_dereference_addr_expr(_unwrap_c_casts(shifted_source))
    if word_addr_expr is None or not _addr_exprs_are_same(low_pair_addr, word_addr_expr, project):
        return None
    return _canonicalize_stack_cvar_expr(
        _make_word_dereference_from_addr_expr(codegen, project, low_pair_addr),
        codegen,
    )


def _word_from_byte_pair_addr_match(low_unwrapped, high_rhs, codegen, project: angr.Project):
    low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
    high_addr_expr = _match_shifted_high_byte_addr_expr(high_rhs)
    if low_addr_expr is None or high_addr_expr is None:
        return None
    if not _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
        return None
    return _canonicalize_stack_cvar_expr(
        _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
        codegen,
    )


def _word_from_widening_shift_match(low_rhs, high_rhs, codegen):
    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is None:
        return None
    shifted_source = _unwrap_c_casts(shifted_source)
    low_expr = _unwrap_c_casts(low_rhs)
    analysis = _analyze_widening_expr(shifted_source, lambda expr: expr, lambda expr: expr)
    if analysis is not None and analysis.kind == "linear" and analysis.delta in {1, -1}:
        if _same_c_expression(low_expr, analysis.base_expr):
            return _canonicalize_stack_cvar_expr(shifted_source, codegen)
    if _same_c_expression(low_expr, shifted_source):
        return _canonicalize_stack_cvar_expr(shifted_source, codegen)
    return None


def _match_word_rhs_from_byte_pair(low_rhs, high_rhs, codegen, project: angr.Project):
    low_unwrapped = _unwrap_c_casts(low_rhs)
    high_unwrapped = _unwrap_c_casts(high_rhs)
    result = _word_from_constant_byte_pair(low_unwrapped, high_unwrapped, codegen)
    if result is not None:
        return result
    result = _word_from_adjacent_memory_bytes(low_unwrapped, high_unwrapped, codegen)
    if result is not None:
        return result
    result = _word_from_shifted_high_expr(low_rhs, high_rhs, low_unwrapped, codegen, project)
    if result is not None:
        return result
    result = _word_from_pair_low_addr(low_unwrapped, high_rhs, codegen, project)
    if result is not None:
        return result
    result = _word_from_byte_pair_addr_match(low_unwrapped, high_rhs, codegen, project)
    if result is not None:
        return result
    result = _word_from_widening_shift_match(low_rhs, high_rhs, codegen)
    if result is not None:
        return result
    return None

def _high_byte_store_addr(node, project: angr.Project) -> int | None:
    return _cli_word_loads._high_byte_store_addr(
        node,
        project,
        classify_segmented_dereference=_classify_segmented_dereference,
    )

def _synthetic_word_global_variable(
    codegen, synthetic_globals: dict[int, tuple[str, int]] | None, addr: int, created: dict[int, structured_c.CVariable] | None = None
):
    return _cli_word_global_helpers._synthetic_word_global_variable(
        codegen,
        synthetic_globals,
        addr,
        synthetic_global_entry=_synthetic_global_entry,
        sanitize_cod_identifier=_sanitize_cod_identifier,
        created=created,
    )

def _coalesce_cod_word_global_loads(
    project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    return _cli_cod_globals._coalesce_cod_word_global_loads(
        project,
        codegen,
        synthetic_globals,
        collect_access_traits=_collect_access_traits,
        build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
        ),
        global_load_addr=_global_load_addr,
        match_scaled_high_byte=_match_scaled_high_byte,
        synthetic_word_global_variable=_synthetic_word_global_variable,
        replace_c_children=_replace_c_children,
    )

def _coalesce_segmented_word_load_expressions(project: angr.Project, codegen) -> bool:
    return _cli_segmented_load_coalesce._coalesce_segmented_word_load_expressions(
        project,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        replace_c_children=_replace_c_children,
        structured_codegen_node=_structured_codegen_node,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        match_shifted_high_byte_addr_expr=_match_shifted_high_byte_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        resolve_stack_cvar_from_addr_expr=_resolve_stack_cvar_from_addr_expr,
        make_word_dereference_from_addr_expr=_make_word_dereference_from_addr_expr,
        describe_alias_storage=describe_alias_storage,
    )

def _coalesce_cod_word_global_statements(
    project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    return _cli_cod_global_statements._coalesce_cod_word_global_statements(
        project,
        codegen,
        synthetic_globals,
        global_memory_addr=_global_memory_addr,
        high_byte_store_addr=_high_byte_store_addr,
        synthetic_word_global_variable=_synthetic_word_global_variable,
    )

def _int21_call_replacements(project: angr.Project, function, api_style: str, binary_path: Path | None) -> list[str]:
    return _cli_helper_modeling._int21_call_replacements(
        project,
        function,
        api_style,
        binary_path,
        collect_dos_int21_calls=collect_dos_int21_calls,
        render_dos_int21_call=render_dos_int21_call,
    )

def _interrupt_call_replacement_map(project: angr.Project, function, api_style: str, binary_path: Path | None) -> dict[str, str]:
    return _cli_helper_modeling._interrupt_call_replacement_map(
        project,
        function,
        api_style,
        binary_path,
        collect_interrupt_service_calls=collect_interrupt_service_calls,
        render_interrupt_call=render_interrupt_call,
        helper_name=_helper_name,
        interrupt_service_addr=interrupt_service_addr,
    )

def _dos_helper_declarations(function, api_style: str, binary_path: Path | None) -> list[str]:
    return _cli_helper_modeling._dos_helper_declarations(
        function,
        api_style,
        binary_path,
        collect_dos_int21_calls=collect_dos_int21_calls,
        dos_helper_declarations=dos_helper_declarations,
    )

def _interrupt_helper_declarations(function, api_style: str, binary_path: Path | None) -> list[str]:
    return _cli_helper_modeling._interrupt_helper_declarations(
        function,
        api_style,
        binary_path,
        collect_interrupt_service_calls=collect_interrupt_service_calls,
        interrupt_service_declarations=interrupt_service_declarations,
    )

def _known_helper_declarations(cod_metadata: CODProcMetadata | None) -> list[str]:
    return _cli_helper_modeling._known_helper_declarations(
        cod_metadata,
        preferred_known_helper_signature_decl=preferred_known_helper_signature_decl,
    )

def _is_staging_local_name(name: str | None) -> bool:
    return isinstance(name, str) and re.fullmatch(r"s_[0-9a-fA-F]+", name) is not None

def _clone_structured_c_value(value, memo: dict[int, object] | None = None):
    def _impl():
        nonlocal memo
        if memo is None:
            memo = {}

        if not _structured_codegen_node(value):
            if isinstance(value, list):
                return [_clone_structured_c_value(item, memo) for item in value]
            if isinstance(value, tuple):
                return tuple(_clone_structured_c_value(item, memo) for item in value)
            if isinstance(value, dict):
                return {
                    _clone_structured_c_value(key, memo): _clone_structured_c_value(item, memo)
                    for key, item in value.items()
                }
            return value

        value_id = id(value)
        if value_id in memo:
            return memo[value_id]

        clone = copy.copy(value)
        memo[value_id] = clone

        slot_names: list[str] = []
        for cls in type(value).__mro__:
            slots = getattr(cls, "__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            slot_names.extend(slots)

        for attr in dict.fromkeys(slot_names):
            if attr == "codegen" or not hasattr(value, attr):
                continue
            try:
                child = getattr(value, attr)
            except Exception:
                continue
            cloned_child = _clone_structured_c_value(child, memo)
            if cloned_child is not child:
                try:
                    setattr(clone, attr, cloned_child)
                except Exception:
                    continue

        return clone

    return _impl()


def _collect_staging_wrapper_summary(statements: list[object]) -> tuple[int, dict[int, object], set[int], bool]:
    def _impl():
        call_count = 0
        staging_replacements: dict[int, object] = {}
        staging_variable_ids: set[int] = set()
        non_staging_logic = False
        for stmt in statements:
            if isinstance(stmt, structured_c.CExpressionStatement) and isinstance(stmt.expr, structured_c.CFunctionCall):
                call_count += 1
            elif isinstance(stmt, structured_c.CFunctionCall):
                call_count += 1
            if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
                if not (
                    isinstance(stmt, (structured_c.CFunctionCall, structured_c.CReturn))
                    or (
                        isinstance(stmt, structured_c.CExpressionStatement)
                        and isinstance(getattr(stmt, "expr", None), structured_c.CFunctionCall)
                    )
                ):
                    non_staging_logic = True
                continue
            variable = getattr(stmt.lhs, "variable", None)
            if not _is_staging_local_name(getattr(variable, "name", None)):
                continue
            staging_variable_ids.add(id(variable))
            staging_replacements[id(variable)] = _clone_structured_c_value(stmt.rhs)
        return call_count, staging_replacements, staging_variable_ids, non_staging_logic

    return _impl()


def _rewrite_staging_statements(
    statements: list[object], staging_replacements: dict[int, object], staging_variable_ids: set[int]
) -> tuple[list[object], bool]:
    changed = False

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            replacement = staging_replacements.get(id(variable))
            if replacement is not None:
                return replacement
        return node

    new_statements = []
    for stmt in statements:
        if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
            variable = getattr(stmt.lhs, "variable", None)
            if id(variable) in staging_variable_ids:
                changed = True
                continue
        if _structured_codegen_node(stmt) and _replace_c_children(stmt, transform):
            changed = True
        new_statements.append(stmt)
    return new_statements, changed


def _remove_unused_staging_vars_from_maps(codegen, staging_variable_ids: set[int], used_variables: set[int]) -> bool:
    changed = False
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if id(variable) in staging_variable_ids and id(variable) not in used_variables:
                del variables_in_use[variable]
                changed = True
    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if id(variable) in staging_variable_ids and id(variable) not in used_variables:
                del unified_locals[variable]
                changed = True
    return changed


def _prune_tiny_wrapper_staging_locals(codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False
        root = getattr(codegen.cfunc, "statements", None)
        if not isinstance(root, structured_c.CStatements):
            return False

        statements = list(root.statements)
        if not statements:
            return False
        if any(isinstance(stmt, (structured_c.CIfElse, structured_c.CWhileLoop)) for stmt in statements):
            return False

        call_count, staging_replacements, staging_variable_ids, non_staging_logic = _collect_staging_wrapper_summary(statements)

        if call_count != 1 or not staging_replacements or non_staging_logic:
            return False

        new_statements, changed = _rewrite_staging_statements(statements, staging_replacements, staging_variable_ids)

        if len(new_statements) != len(statements):
            root.statements = new_statements

        used_variables: set[int] = set()
        for node in _iter_c_nodes_deep(root):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))

        changed = _remove_unused_staging_vars_from_maps(codegen, staging_variable_ids, used_variables) or changed
        return changed

    return _impl()

# Missing symbols during split:
# - _SegmentedAccess
# - _SegmentAssociationState
_AST_REWRITE_LOGGER = logging.getLogger(__name__)
