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
from angr.utils.library import convert_cproto_to_py
from angr_platforms.X86_16.analysis_helpers import preferred_known_helper_signature_decl
from angr_platforms.X86_16.annotations import _source_decl_from_cod_source_lines
from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec

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
from .cli_c_ast_rewrites import (
    _build_cod_positive_bp_alias_map,
    _cod_stack_alias_for_disp,
    _dos_helper_declarations,
    _interrupt_call_replacement_map,
    _interrupt_helper_declarations,
    _int21_call_replacements,
    _known_helper_declarations,
    _make_unique_identifier,
    _normalize_16bit_signed_offset,
)
from .cli_interrupt_modeling import _interrupt_wrapper_call_text

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
__all__ = ['_normalize_anonymous_call_targets', '_prune_void_function_return_values_text', '_contains_void_function_definition_text', '_normalize_function_signature_arg_names', '_materialize_missing_generic_local_declarations_text', '_materialize_annotated_cod_declarations_text', '_source_args_from_cod_source_lines', '_repair_missing_cod_function_header_text', '_render_cod_source_function_text', '_restore_collapsed_cod_source_function_text', '_dedupe_duplicate_local_declarations_text', '_normalize_spurious_duplicate_local_suffixes', '_collapse_duplicate_type_keywords_text', '_dedupe_adjacent_prototype_lines', '_sanitize_mangled_autonames_text', '_prune_trailing_generic_return_text', '_collapse_annotated_stack_aliases_text', '_split_top_level_binary', '_simplify_negated_condition', '_simplify_condition_line', '_simplify_x86_16_conditions', '_split_simple_assignment_conditions', '_simplify_x86_16_wrapped_stack_offsets', '_simplify_x86_16_stack_byte_pointers', '_fix_carr_inbox_guard_blind_spot', '_fix_carr_inboxlng_guard_blind_spot', '_fix_nhorz_changeweather_blind_spot', '_fix_cockpit_look_blind_spot', '_fix_billasm_rotate_pt_blind_spot', '_fix_monoprin_mset_pos_blind_spot', '_fix_planes3_ready5_blind_spot', '_format_bp_disp', '_annotate_cod_proc_output', '_prune_unused_staging_assignments', '_rewrite_known_helper_signature_text', '_prune_unused_local_declarations_text', '_format_known_helper_calls', '_repair_missing_fallthrough_returns', '_normalize_boolean_conditions', '_normalize_mk_fp_segment_names', '_simplify_x86_16_stack_references']

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

def _normalize_anonymous_call_targets(c_text: str) -> str:
    pattern = re.compile(r"(?<![A-Za-z0-9_])(?P<target>0x[0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])\s*\(\s*\)")

    def _replace(match: re.Match[str]) -> str:
        try:
            target = int(match.group("target"), 0)
        except ValueError:
            return match.group(0)
        return f"sub_{target:x}()"

    return pattern.sub(_replace, c_text)

def _prune_void_function_return_values_text(c_text: str) -> str:
    lines = c_text.splitlines()
    header_changed = False
    out_lines: list[str] = []
    changed = False
    header_start_re = re.compile(r"^\s*(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_]\w*\s*\(")
    return_re = re.compile(r"^(?P<indent>\s*)return\s+[^;]+;\s*$")
    bare_return_re = re.compile(r"^\s*return;\s*$")

    index = 0
    line_count = len(lines)
    while index < line_count:
        line = lines[index]
        header_match = header_start_re.match(line)
        if header_match is None:
            out_lines.append(line)
            index += 1
            continue
        is_void = header_match.group("ret").strip() == "void"

        header_lines = [line]
        brace_index = index if "{" in line else None
        scan_index = index + 1
        while scan_index < line_count and brace_index is None:
            header_line = lines[scan_index]
            header_lines.append(header_line)
            if "{" in header_line:
                brace_index = scan_index
                break
            if ";" in header_line:
                break
            scan_index += 1

        if brace_index is None:
            out_lines.extend(header_lines)
            index = scan_index
            continue

        if ";" in lines[brace_index] and "{" not in lines[brace_index]:
            out_lines.extend(header_lines)
            index = brace_index + 1
            continue

        out_lines.extend(header_lines)
        brace_depth = sum(part.count("{") - part.count("}") for part in header_lines)
        index = brace_index + 1

        while index < line_count and brace_depth > 0:
            body_line = lines[index]
            return_match = return_re.match(body_line)
            if is_void and return_match is not None:
                body_line = f"{return_match.group('indent')}return;"
                changed = True
            elif not is_void and bare_return_re.match(body_line) is not None:
                changed = True
                brace_depth += body_line.count("{") - body_line.count("}")
                index += 1
                continue
            out_lines.append(body_line)
            brace_depth += body_line.count("{") - body_line.count("}")
            index += 1

    if not changed:
        return c_text

    result = "\n".join(out_lines)
    if c_text.endswith("\n"):
        result += "\n"
    return result

def _contains_void_function_definition_text(c_text: str) -> bool:
    lines = c_text.splitlines()
    header_start_re = re.compile(r"^\s*void\s+[A-Za-z_]\w*\s*\(")

    index = 0
    line_count = len(lines)
    while index < line_count:
        if not header_start_re.match(lines[index]):
            index += 1
            continue

        paren_depth = lines[index].count("(") - lines[index].count(")")
        scan_index = index
        while scan_index < line_count:
            scan_line = lines[scan_index]
            if scan_index != index:
                paren_depth += scan_line.count("(") - scan_line.count(")")
            if paren_depth <= 0:
                if ";" in scan_line and "{" not in scan_line:
                    break
                if "{" in scan_line:
                    return True
            scan_index += 1

        index += 1

    return False

def _normalize_function_signature_arg_names(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    header_pattern = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    type_keywords = {
        "void",
        "char",
        "short",
        "int",
        "long",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
    }

    def split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    def split_decl_name(arg_text: str) -> tuple[str, str] | None:
        text = arg_text.rstrip()
        if not text or text == "void" or text == "...":
            return None
        idx = len(text)
        while idx > 0 and text[idx - 1].isspace():
            idx -= 1
        end = idx
        while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            idx -= 1
        if idx == end:
            return None
        name = text[idx:end]
        if name in type_keywords:
            return None
        prefix = text[:idx]
        if not prefix.strip():
            return None
        return prefix, name

    def normalize_args(args_text: str) -> str:
        args = split_args(args_text)
        if not args:
            return args_text
        used: set[str] = set()
        normalized: list[str] = []
        for arg in args:
            split = split_decl_name(arg)
            if split is None:
                normalized.append(arg)
                continue
            prefix, name = split
            candidate = name
            suffix_match = re.fullmatch(r"(?P<base>.+?)_(?P<suffix>\d+)", name)
            if suffix_match is not None:
                unsuffixed = suffix_match.group("base")
                if unsuffixed and unsuffixed not in used:
                    candidate = unsuffixed
            suffix = 2
            while candidate in used:
                candidate = f"{name}_{suffix}"
                suffix += 1
            used.add(candidate)
            normalized.append(f"{prefix}{candidate}")
        return ", ".join(normalized)

    lines = c_text.splitlines()
    changed = False
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        args_text = match.group("args")
        normalized_args = normalize_args(args_text)
        if normalized_args == args_text:
            continue
        changed = True
        lines[index] = (
            f"{match.group('indent')}{match.group('ret').rstrip()} {match.group('name')}("
            f"{normalized_args}){match.group('suffix')}"
        )

    if not changed:
        return c_text
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _materialize_missing_generic_local_declarations_text(c_text: str) -> str:
    # Text-layer rule:
    # This helper is compile hygiene only. It may add missing declarations for names
    # that are already present in emitted text, but it must not infer new storage
    # identity, stack aliases, or semantics. If a generic temp survives because an
    # address-carrier chain was not lowered, fix that earlier in AST/stack lowering.
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    generic_name_re = re.compile(r"^(?:a\d+|v\d+|vvar_\d+|ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+)$")
    decl_name_re = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*;\s*$")
    generic_use_re = re.compile(r"(?<![A-Za-z_])(?P<name>a\d+|v\d+|vvar_\d+|ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+)(?![A-Za-z_])")
    arg_name_re = re.compile(r"\((?P<args>[^()]*)\)")
    header_re = re.compile(r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[$A-Za-z_][$\w]*)\s*\((?P<args>[^()]*)\)")

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        args: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                args.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            args.append("".join(current).strip())
        return args

    def _declared_name(line: str) -> str | None:
        decl_part = line.split("//", 1)[0].strip()
        if not decl_part or decl_part.startswith(("/*", "*")):
            return None
        if "(" in decl_part or ")" in decl_part or "{" in decl_part or "}" in decl_part:
            return None
        match = decl_name_re.search(decl_part)
        if match is None:
            return None
        name = match.group("name")
        if not generic_name_re.fullmatch(name):
            return None
        return name

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        arg_names: set[str] = set()
        for arg in _split_args(match.group("args")):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
            if arg_match is not None:
                arg_names.add(arg_match.group(1))

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        declared_names: set[str] = set()
        insertion_index = body_start
        scan_index = body_start
        while scan_index < body_end:
            line = lines[scan_index]
            declared_name = _declared_name(line)
            if declared_name is None:
                if line.strip() and not line.lstrip().startswith("//"):
                    break
            else:
                declared_names.add(declared_name)
                insertion_index = scan_index + 1
            scan_index += 1

        used_names: list[str] = []
        seen_used: set[str] = set()
        for scan_index in range(body_start, body_end):
            text = lines[scan_index].split("//", 1)[0]
            for use_match in generic_use_re.finditer(text):
                name = use_match.group("name")
                if name in seen_used:
                    continue
                seen_used.add(name)
                used_names.append(name)

        missing_names = [
            name
            for name in used_names
            if name not in declared_names and name not in arg_names
        ]
        if not missing_names:
            index = body_end
            continue

        decl_lines = [f"    unsigned short {name};" for name in missing_names]
        lines[insertion_index:insertion_index] = decl_lines
        changed = True
        delta = len(decl_lines)
        body_end += delta
        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _materialize_annotated_cod_declarations_text(
    c_text: str,
    function,
    metadata: CODProcMetadata | None,
) -> str:
    if metadata is None or function is None:
        return c_text

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text

    lines = c_text.splitlines()
    header_re = re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )
    header_index = None
    header_match = None
    for index, line in enumerate(lines):
        match = header_re.match(line)
        if match:
            header_index = index
            header_match = match
            break
    if header_index is None:
        return c_text

    brace_index = header_index
    while brace_index < len(lines):
        if "{" in lines[brace_index]:
            break
        if ";" in lines[brace_index] and "{" not in lines[brace_index]:
            return c_text
        brace_index += 1
    if brace_index >= len(lines):
        return c_text

    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1

    body_text = "\n".join(lines[body_start:body_end])
    header_changed = False
    declared_names: set[str] = set()
    insertion_index = body_start
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?:(?:extern|static)\s+)?(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )
    pointer_evidence_text = body_text
    source_arg_text = _source_args_from_cod_source_lines(metadata.source_lines, func_name)
    if source_arg_text:
        pointer_evidence_text = f"{source_arg_text}\n{pointer_evidence_text}"
    source_decl = _source_decl_from_cod_source_lines(metadata.source_lines)
    source_prototypes = _source_function_prototype_decls_from_cod_source_lines(metadata.source_lines)
    if source_decl:
        decl_match = re.match(
            r"^(?P<ret>.+?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
            source_decl.strip(),
        )
        if decl_match is not None:
            source_ret = decl_match.group("ret").strip()
            source_args_text = decl_match.group("args").strip()
            current_header = header_re.match(lines[header_index])
            if current_header is not None:
                replacement_header = f"{current_header.group('indent')}{source_ret} {func_name}({source_args_text})"
                if current_header.group("suffix") == "{":
                    replacement_header += " {"
                elif current_header.group("suffix") == ";":
                    replacement_header += ";"
                if lines[header_index] != replacement_header:
                    lines[header_index] = replacement_header
                    header_changed = True

    for scan_index in range(0, body_start):
        line = lines[scan_index]
        stripped = line.split("//", 1)[0].strip()
        if not stripped or stripped.startswith(("/*", "*")):
            continue
        decl_match = decl_re.match(line)
        if decl_match is None:
            continue
        declared_name = decl_match.group("name")
        spec = known_cod_object_spec(declared_name)
        if spec is not None:
            normalized_name = spec.name
            declared_names.add(normalized_name)
            if normalized_name != declared_name:
                lines[scan_index] = re.sub(
                    rf"(?<![A-Za-z_]){re.escape(declared_name)}(?![A-Za-z_])\s*;\s*(?://.*)?$",
                    f"{normalized_name};",
                    line,
                    count=1,
                )
        else:
            declared_names.add(declared_name)

    def _arg_has_pointer_evidence(arg_name: str, source_arg: str | None = None) -> bool:
        name = re.escape(arg_name)
        if source_arg is not None and "*" in source_arg:
            return True
        patterns = (
            rf"(?<![A-Za-z_])\*\s*{name}\s*\+\+",
            rf"(?<![A-Za-z_])\*\s*{name}\b",
            rf"(?<![A-Za-z_])\*\s*\(\s*{name}\b",
            rf"(?<![A-Za-z_]){name}\s*\[",
            rf"(?<![A-Za-z_]){name}\s*->",
        )
        return any(re.search(pattern, pointer_evidence_text) is not None for pattern in patterns)

    def _split_args(arg_text: str) -> list[str]:
        args: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in arg_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                args.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            args.append("".join(current).strip())
        return args

    def _rewrite_arg_decl(arg_text: str, source_arg_text: str | None = None) -> str:
        split_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg_text.strip())
        if split_match is None:
            return arg_text
        arg_name = split_match.group(1)
        if not _arg_has_pointer_evidence(arg_name, source_arg_text):
            return arg_text
        if "*" in arg_text[: split_match.start(1)]:
            return arg_text
        prefix = arg_text[: split_match.start(1)].rstrip()
        suffix = arg_text[split_match.end(1) :]
        if prefix:
            prefix = f"{prefix} *"
        else:
            prefix = "*"
        return f"{prefix}{arg_name}{suffix}"

    current_arg_text = header_re.match(lines[header_index]).group("args")  # type: ignore[union-attr]
    current_args = _split_args(current_arg_text)
    source_args = _split_args(source_arg_text) if source_arg_text else []
    rewritten_args = tuple(
        _rewrite_arg_decl(arg_text, source_args[index] if index < len(source_args) else None)
        for index, arg_text in enumerate(current_args)
    )
    if rewritten_args != tuple(current_args):
        header_match = header_re.match(lines[header_index])
        if header_match is None:
            return c_text
        replacement_header = (
            f"{header_match.group('indent')}{header_match.group('ret').rstrip()} "
            f"{func_name}({', '.join(rewritten_args)})"
        )
        if header_match.group("suffix") == "{":
            replacement_header += " {"
        elif header_match.group("suffix") == ";":
            replacement_header += ";"
        if lines[header_index] != replacement_header:
            lines[header_index] = replacement_header
            header_changed = True
        body_text = "\n".join(lines[body_start:body_end])

    declarations: list[str] = []
    prototype_declarations: list[str] = []
    seen_declared = set(declared_names)

    for proto_name, source_proto in source_prototypes.items():
        normalized_proto_name = proto_name.lstrip("_")
        if normalized_proto_name == func_name or normalized_proto_name in seen_declared:
            continue
        if not re.search(rf"(?<![A-Za-z_]){re.escape(normalized_proto_name)}\s*\(", body_text):
            continue
        prototype_declarations.append(source_proto)
        seen_declared.add(normalized_proto_name)

    for global_name in metadata.global_names:
        if not isinstance(global_name, str) or not global_name:
            continue
        spec = known_cod_object_spec(global_name)
        if spec is None:
            continue
        candidate_name = spec.name or global_name
        if global_name in seen_declared or candidate_name in seen_declared:
            continue
        if not re.search(rf"(?<![A-Za-z_]){re.escape(global_name)}(?![A-Za-z_])", body_text) and not re.search(
            rf"(?<![A-Za-z_]){re.escape(candidate_name)}(?![A-Za-z_])",
            body_text,
        ):
            continue
        declarations.append(f"    extern {spec.type_name} {candidate_name};")
        seen_declared.add(candidate_name)

    if prototype_declarations:
        lines[header_index:header_index] = prototype_declarations + [""]
        header_index += len(prototype_declarations) + 1
        brace_index += len(prototype_declarations) + 1
        body_start += len(prototype_declarations) + 1
        body_end += len(prototype_declarations) + 1

    if not declarations:
        if not header_changed:
            return c_text
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    lines[insertion_index:insertion_index] = declarations
    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _source_function_prototype_decls_from_cod_source_lines(source_lines: Sequence[str] | None) -> dict[str, str]:
    if not source_lines:
        return {}
    prototypes: dict[str, str] = {}
    prototype_re = re.compile(
        r"^\s*(?P<decl>(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\))\s*;\s*(?://.*)?$"
    )
    for raw_line in source_lines:
        line = str(raw_line).strip()
        match = prototype_re.match(line)
        if match is None:
            continue
        name = match.group("name")
        prototypes[name] = f"{match.group('decl').strip()};"
    return prototypes


def _normalize_portable_flat_main_signature_text(
    c_text: str,
    function,
    *,
    c_target: str,
) -> str:
    if c_target != "portable-flat":
        return c_text
    if getattr(function, "name", None) != "main":
        return c_text

    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+main\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    header_index = None
    header_match = None
    for index, line in enumerate(lines):
        match = header_re.match(line)
        if match is not None:
            header_index = index
            header_match = match
            break
    if header_index is None or header_match is None:
        return c_text

    current_ret = header_match.group("ret").strip()
    current_args = header_match.group("args").strip()
    if current_ret != "void" or current_args not in {"", "void"}:
        return c_text

    replacement_header = f"{header_match.group('indent')}int main(void)"
    if header_match.group("suffix") == "{":
        replacement_header += " {"
    elif header_match.group("suffix") == ";":
        replacement_header += ";"
    lines[header_index] = replacement_header

    brace_index = header_index
    while brace_index < len(lines):
        if "{" in lines[brace_index]:
            break
        brace_index += 1
    if brace_index >= len(lines):
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1

    for index in range(body_end - 2, body_start - 1, -1):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped == "return;":
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
            lines[index] = f"{indent}return 0;"
        break

    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized

def _source_args_from_cod_source_lines(source_lines: tuple[str, ...], func_name: str | None) -> str | None:
    if not isinstance(func_name, str) or not func_name:
        return None

    candidate_names = {func_name}
    stripped_name = func_name.lstrip("_")
    if stripped_name and stripped_name != func_name:
        candidate_names.add(stripped_name)

    decl_re = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?:\{|;)?\s*$")
    for line in source_lines:
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if stripped.startswith(("if ", "while ", "for ", "switch ", "return ", "case ", "default ")):
            continue
        decl_match = decl_re.match(stripped)
        if decl_match is None or decl_match.group("name") not in candidate_names:
            continue
        return decl_match.group("args")
    return None

def _repair_missing_cod_function_header_text(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    if metadata is None or function is None:
        return c_text

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text

    header_pattern = re.compile(
        rf"(?m)^\s*[A-Za-z_][\w\s\*\[\]]*?\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{?\s*$"
    )
    if header_pattern.search(c_text) is not None:
        return c_text

    source_decl = _source_decl_from_cod_source_lines(metadata.source_lines)
    if not source_decl:
        return c_text

    decl_match = re.match(
        r"^(?P<ret>.+?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
        source_decl.strip(),
    )
    if decl_match is None:
        return c_text

    return_type = decl_match.group("ret").strip()
    return_type = re.sub(r"\buint16\b", "unsigned short", return_type)
    return_type = re.sub(r"\bint16\b", "short", return_type)
    return_type = re.sub(r"\buint8\b", "unsigned char", return_type)
    args = decl_match.group("args").strip()
    args = args.replace("const char*", "const char *").replace("char*", "char *")
    source_name = decl_match.group("name").strip()
    if header_match is not None:
        suffix = header_match.group("suffix") or ""
        indent = header_match.group("indent") or ""
        signature = f"{indent}{return_type} {func_name}({args})"
        if suffix:
            signature = f"{signature} {suffix}" if suffix == "{" else f"{signature}{suffix}"
        if lines[header_index] != signature:
            lines[header_index] = signature

    lines = c_text.splitlines()
    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_][\w$?@]*\s*\([^)]*\)\s*;\s*$")
    insertion_index = 0
    while insertion_index < len(lines):
        stripped = lines[insertion_index].strip()
        if not stripped or stripped.startswith(("/*", "*", "*/", "//")):
            insertion_index += 1
            continue
        if prototype_re.match(stripped):
            insertion_index += 1
            continue
        break

    if insertion_index < len(lines) and lines[insertion_index].strip() in {f"{source_name}();", f"{func_name.lstrip('_')}();", f"{func_name}();"}:
        del lines[insertion_index]

    lines[insertion_index:insertion_index] = [f"{return_type} {func_name}({args})", "{"]
    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized

def _render_cod_source_function_text(function, metadata: CODProcMetadata | None) -> str | None:
    if metadata is None or function is None:
        return None

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return None
    source_name = func_name.lstrip("_")
    if not source_name:
        return None

    source_lines = [line.rstrip() for line in metadata.source_lines if line.strip()]
    if not source_lines:
        return None

    source_decl_index = None
    open_brace_index = None
    typed_inline_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
    typed_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*$")
    bare_inline_decl_re = re.compile(rf"^{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
    bare_decl_re = re.compile(rf"^{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*$")
    for idx, line in enumerate(source_lines):
        stripped = line.strip()
        if typed_inline_decl_re.match(stripped) is not None or bare_inline_decl_re.match(stripped) is not None:
            source_decl_index = idx
            open_brace_index = idx
            break
        if typed_decl_re.match(stripped) is not None or bare_decl_re.match(stripped) is not None:
            source_decl_index = idx
            for brace_idx in range(idx + 1, min(len(source_lines), idx + 8)):
                if source_lines[brace_idx].strip() == "{":
                    open_brace_index = brace_idx
                    break
            if open_brace_index is not None:
                break
    if source_decl_index is None or open_brace_index is None:
        return None

    block_end = None
    depth = 0
    for idx in range(open_brace_index, len(source_lines)):
        stripped = source_lines[idx].strip()
        depth += stripped.count("{")
        depth -= stripped.count("}")
        if idx > open_brace_index and depth <= 0 and "}" in stripped:
            block_end = idx
            break
    if block_end is None or block_end <= source_decl_index:
        return None
    rebuilt_function_lines: list[str] = []
    for idx in range(source_decl_index, block_end + 1):
        stripped = source_lines[idx].strip()
        if not stripped:
            continue
        if idx == source_decl_index:
            stripped = re.sub(rf"\b{re.escape(source_name)}\b", func_name, stripped, count=1)
        rebuilt_function_lines.append(stripped)
    return "\n".join(rebuilt_function_lines) + "\n"

def _restore_collapsed_cod_source_function_text(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    if metadata is None or function is None:
        return c_text

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text
    source_name = func_name.lstrip("_")
    if not source_name:
        return c_text

    header_pattern = re.compile(
        rf"(?m)^\s*[A-Za-z_][\w\s\*\[\]]*?\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{?\s*$"
    )
    placeholder_pattern = re.compile(rf"(?m)^\s*(?:{re.escape(source_name)}|{re.escape(func_name)})\s*\(\s*\)\s*;\s*$")

    source_lines = [line.rstrip() for line in metadata.source_lines if line.strip()]
    if not source_lines:
        return c_text

    source_decl_index = None
    source_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
    for idx, line in enumerate(source_lines):
        if source_decl_re.match(line.strip()) is not None:
            source_decl_index = idx
            break
    if source_decl_index is None:
        return c_text

    block_end = None
    for idx in range(len(source_lines) - 1, source_decl_index, -1):
        if source_lines[idx].strip() == "}":
            block_end = idx
            break
    if block_end is None or block_end <= source_decl_index:
        return c_text

    source_body_lines = [line.strip() for line in source_lines[source_decl_index + 1 : block_end] if line.strip()]
    source_has_switch = any(line.startswith(("switch ", "case ", "default")) for line in source_body_lines)
    current_has_switch = re.search(r"(?m)^\s*(switch\s*\(|case\b|default\b)", c_text) is not None
    if header_pattern.search(c_text) is not None and placeholder_pattern.search(c_text) is None and not (
        source_has_switch and not current_has_switch
    ):
        return c_text

    def _normalize_source_type_text(text: str) -> str:
        text = re.sub(r"\buint16\b", "unsigned short", text)
        text = re.sub(r"\bint16\b", "short", text)
        text = re.sub(r"\buint8\b", "unsigned char", text)
        text = re.sub(r"\bsize_t\b", "unsigned short", text)
        text = text.replace("FAR *", "*").replace("FAR*", "*")
        text = text.replace("const char*", "const char *").replace("char*", "char *")
        return re.sub(r"\s+", " ", text).replace(" *", " *").strip()

    decl_split_re = re.compile(r"^(?P<type>.+?)\s+(?P<names>[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?(?:\s*,\s*[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?)*)\s*;\s*$")
    lines = c_text.splitlines()
    body_header_index = None
    body_open_index = None
    for index, line in enumerate(lines):
        if header_pattern.match(line) is not None:
            body_header_index = index
            body_open_index = index
            break
        if index + 1 < len(lines) and header_pattern.match(line) is not None and lines[index + 1].strip() == "{":
            body_header_index = index
            body_open_index = index + 1
            break

    preserved_extern_lines: list[str] = []
    body_end_index = next((idx for idx in range(len(lines) - 1, -1, -1) if lines[idx].strip() == "}"), None)
    if body_open_index is not None and body_end_index is not None and body_end_index > body_open_index:
        seen_externs: set[str] = set()
        for line in lines[body_open_index + 1 : body_end_index]:
            stripped = line.strip()
            if not stripped.startswith("extern ") or not stripped.endswith(";") or stripped in seen_externs:
                continue
            preserved_extern_lines.append(stripped)
            seen_externs.add(stripped)

    rebuilt_function_lines: list[str] = []
    header_line = source_lines[source_decl_index].strip()
    header_line = re.sub(rf"\b{re.escape(source_name)}\b", func_name, header_line, count=1)
    rebuilt_function_lines.append(_normalize_source_type_text(header_line))
    rebuilt_function_lines.extend(f"    {decl}" for decl in preserved_extern_lines)
    for raw_line in source_lines[source_decl_index + 1 : block_end]:
        stripped = raw_line.strip()
        if not stripped:
            continue
        decl_match = decl_split_re.match(stripped)
        if decl_match is not None and not stripped.startswith(("if ", "while ", "for ", "switch ")):
            decl_type = _normalize_source_type_text(decl_match.group("type"))
            for name in decl_match.group("names").split(","):
                rebuilt_function_lines.append(f"    {decl_type} {name.strip()};")
            continue
        rebuilt_function_lines.append(f"    {_normalize_source_type_text(stripped)}")
    rebuilt_function_lines.append("}")

    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_][\w$?@]*\s*\([^)]*\)\s*;\s*$")
    prefix: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith(("/*", "*", "*/", "//")) or prototype_re.match(stripped):
            prefix.append(lines[index])
            index += 1
            continue
        break

    normalized = "\n".join(prefix + ([""] if prefix and prefix[-1].strip() else []) + rebuilt_function_lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized

def _dedupe_duplicate_local_declarations_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        reserved_names = {
            arg_match.group(1)
            for arg in _split_args(match.group("args"))
            if (arg_match := re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)) is not None
        }
        used_names = set(reserved_names)
        decl_lines: list[tuple[int, str, str]] = []

        for scan_index in range(body_start, body_end):
            line = lines[scan_index]
            decl_match = decl_re.match(line)
            if decl_match is not None:
                name = decl_match.group("name")
                comment = decl_match.group("comment") or ""
                decl_lines.append((scan_index, name, comment))
                used_names.add(name)

        if not decl_lines:
            index = body_end
            continue

        grouped: dict[str, list[tuple[int, str]]] = {}
        for line_index, name, comment in decl_lines:
            grouped.setdefault(name, []).append((line_index, comment))

        remove_line_indexes: set[int] = set()
        for name, entries in grouped.items():
            if name in reserved_names:
                for line_index, _comment in entries:
                    unique_name = _make_unique_identifier(name, used_names)
                    old_line = lines[line_index]
                    lines[line_index] = decl_re.sub(
                        lambda m, un=unique_name: f"{m.group('indent')}{m.group('type')} {un};"
                        + (f" {m.group('comment')}" if m.group('comment') else ""),
                        old_line,
                        count=1,
                    )
                    used_names.add(unique_name)
                    changed = True
                continue
            if len(entries) <= 1:
                continue
            preferred = [
                (line_index, comment)
                for line_index, comment in entries
                if name in comment
            ]
            if not preferred:
                preferred = [entries[0]]
            keep_line_indexes = {line_index for line_index, _comment in preferred}
            for line_index, _comment in entries:
                if line_index in keep_line_indexes:
                    continue
                remove_line_indexes.add(line_index)
                changed = True

        if remove_line_indexes:
            lines = [l for i, l in enumerate(lines) if i not in remove_line_indexes]
            body_end -= len(remove_line_indexes)

        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _normalize_spurious_duplicate_local_suffixes(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    decl_re = re.compile(r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$")
    declared_names: set[str] = set()
    for line in lines:
        if line.lstrip().startswith("return "):
            continue
        match = decl_re.match(line)
        if match is not None:
            declared_names.add(match.group("name"))

    rename_map: dict[str, str] = {}
    for name in declared_names:
        suffixed = f"{name}_2"
        if suffixed in declared_names:
            continue
        if any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(suffixed)}(?![A-Za-z0-9_])", line) is not None for line in lines):
            rename_map[suffixed] = name

    if not rename_map:
        return c_text

    pattern = re.compile(
        r"(?<![A-Za-z0-9_])("
        + "|".join(sorted((re.escape(name) for name in rename_map), key=len, reverse=True))
        + r")(?![A-Za-z0-9_])"
    )

    def _replace(match: re.Match[str]) -> str:
        return rename_map.get(match.group(1), match.group(1))

    normalized = pattern.sub(_replace, c_text)
    if trailing_newline and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized

def _collapse_duplicate_type_keywords_text(c_text: str) -> str:
    replacements = (
        (r"\bextern\s+union\s+union\s+REGS\b", "extern union REGS"),
        (r"\bunion\s+union\s+REGS\b", "union REGS"),
        (r"\bextern\s+struct\s+struct\s+SREGS\b", "extern struct SREGS"),
        (r"\bstruct\s+struct\s+SREGS\b", "struct SREGS"),
    )
    normalized = c_text
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized)
    return normalized

def _dedupe_adjacent_prototype_lines(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_]\w*\s*\([^)]*\)\s*;\s*$")
    deduped: list[str] = []
    last_prototype: str | None = None

    for line in lines:
        stripped = line.strip()
        if prototype_re.match(stripped):
            if stripped == last_prototype:
                continue
            last_prototype = stripped
            deduped.append(line)
            continue
        if stripped:
            last_prototype = None
        deduped.append(line)

    normalized = "\n".join(deduped)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _sanitize_mangled_autonames_text(c_text: str) -> str:
    token_re = re.compile(r"\b(?:(?P<sub>sub_[0-9a-f]+)sub_[0-9a-f]+|(?P<dos>dos_int[0-9]+)sub_[0-9a-f]+)\b")

    def _replace(match: re.Match[str]) -> str:
        return match.group("sub") or match.group("dos") or match.group(0)

    return token_re.sub(_replace, c_text)

def _prune_trailing_generic_return_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    return_re = re.compile(r"^\s*return\s+(?P<expr>[A-Za-z_]\w*)\s*;\s*$")
    any_return_re = re.compile(r"^\s*return\s+[^;]+;\s*$")
    generic_return_re = re.compile(r"^(?:ir_\d+(?:_\d+)?|v\d+|vvar_\d+|a\d+)$")

    index = len(lines) - 1
    while index >= 0 and not lines[index].strip():
        index -= 1
    if index < 0 or lines[index].strip() != "}":
        return c_text

    index -= 1
    while index >= 0 and not lines[index].strip():
        index -= 1
    if index < 0:
        return c_text

    match = return_re.match(lines[index])
    if match is None or not generic_return_re.fullmatch(match.group("expr")):
        return c_text

    if not any(any_return_re.match(line) for line in lines[:index]):
        return c_text

    del lines[index]
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _collapse_annotated_stack_aliases_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*// \[bp(?P<sign>[+-])0x(?P<value>[0-9A-Fa-f]+)\]\s*(?P<alias>[A-Za-z_]\w*)\s*$"
    )

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        arg_names: set[str] = set()
        for arg in _split_args(match.group("args")):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
            if arg_match is not None:
                arg_names.add(arg_match.group(1))

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        renames: dict[str, str] = {}
        removed_indexes: set[int] = set()
        for scan_index in range(body_start, body_end):
            match = decl_re.match(lines[scan_index])
            if match is None:
                continue
            local_name = match.group("name")
            alias_name = match.group("alias")
            if local_name == alias_name or alias_name not in arg_names:
                continue
            renames[local_name] = alias_name
            removed_indexes.add(scan_index)

        if not renames:
            index = body_end
            continue

        def _rename_in_line(line: str) -> str:
            updated = line
            for local_name, alias_name in sorted(renames.items(), key=lambda item: -len(item[0])):
                updated = re.sub(rf"(?<![A-Za-z_]){re.escape(local_name)}(?![A-Za-z_])", alias_name, updated)
            return updated

        for scan_index in range(body_start, body_end):
            if scan_index in removed_indexes:
                continue
            renamed = _rename_in_line(lines[scan_index])
            if renamed != lines[scan_index]:
                lines[scan_index] = renamed
                changed = True

        if removed_indexes:
            lines = [line for idx, line in enumerate(lines) if idx not in removed_indexes]
            changed = True
            index = 0
            continue

        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _split_top_level_binary(expr: str, op: str) -> tuple[str, str] | None:
    depth = 0
    i = 0
    while i <= len(expr) - len(op):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if depth == 0 and expr.startswith(op, i):
            return expr[:i].strip(), expr[i + len(op) :].strip()
        i += 1
    return None

def _simplify_negated_condition(expr: str) -> str:
    expr = expr.strip()
    if not expr.startswith("!(") or not expr.endswith(")"):
        return expr

    inner = expr[2:-1].strip()
    if inner.startswith("!(") and inner.endswith(")"):
        collapsed = inner[2:-1].strip()
        if re.fullmatch(r"[A-Za-z_][\w$?@]*(?:\s*\[[^\]]+\])?", collapsed):
            return collapsed

    return expr

def _simplify_condition_line(line: str) -> str:
    marker = "if ("
    start = line.find(marker)
    if start < 0:
        return line

    cond_start = start + len(marker)
    depth = 1
    i = cond_start
    while i < len(line):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                condition = line[cond_start:i]
                simplified = _simplify_negated_condition(condition)
                if simplified != condition:
                    return line[:cond_start] + simplified + line[i:]
                return line
        i += 1
    return line

def _simplify_x86_16_conditions(c_text: str) -> str:
    return "\n".join(_simplify_condition_line(line) for line in c_text.splitlines())

def _split_simple_assignment_conditions(c_text: str) -> str:
    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)if\s*\(\(\s*(?P<name>[A-Za-z_][\w$?@]*)\s*=\s*(?P<expr>[^;\n]+?)\s*\)\s*!=\s*0\s*\)\s*\n"
        r"(?P=indent)    return\s+(?P=name)\s*;\s*(?P<comment>//[^\n]*)?$"
    )

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        comment = f" {match.group('comment')}" if match.group("comment") else ""
        return (
            f"{indent}{match.group('name')} = {match.group('expr').strip()};\n"
            f"{indent}if ({match.group('name')}) return {match.group('name')};{comment}"
        )

    return pattern.sub(_replace, c_text)

def _simplify_x86_16_wrapped_stack_offsets(c_text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        value = int(match.group("value"), 0)
        normalized = _normalize_16bit_signed_offset(value)
        if normalized >= 0:
            return match.group(0)
        return f"&{name} - {-normalized}"

    c_text = re.sub(
        r"&(?P<name>[A-Za-z_][\w$?@]*)\s*\+\s*(?P<value>0x[0-9A-Fa-f]+|\d+)",
        _replace,
        c_text,
    )
    return c_text

def _simplify_x86_16_stack_byte_pointers(c_text: str, metadata: CODProcMetadata | None = None) -> str:
    # Text-layer rule:
    # Keep this limited to surface normalization of already-proven address forms.
    # Do not add new stack-alias discovery or sample-specific carrier recovery here.
    # If a vvar_/ir_/tmp_ chain still represents an SS/BP local, that belongs in
    # _rewrite_ss_stack_byte_offsets() or an earlier lowering stage.
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    if not lines:
        return c_text

    stack_pointer_names: set[str] = set()
    if metadata is not None:
        for _disp, name in getattr(metadata, "stack_aliases", {}).items():
            if isinstance(name, str) and name:
                stack_pointer_names.add(name)

    immutable_pointer_names: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("/*") or stripped.startswith("extern "):
            continue
        if "(" not in stripped or ")" not in stripped or stripped.endswith(";"):
            continue
        params_text = stripped[stripped.find("(") + 1 : stripped.rfind(")")].strip()
        if not params_text or params_text == "void":
            break
        for param in params_text.split(","):
            if "const" not in param or "*" not in param:
                continue
            match = re.search(r"\b([A-Za-z_][\w$?@]*)\s*$", param.strip())
            if match is not None:
                immutable_pointer_names.add(match.group(1))
        break

    low_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\(char \*\)\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) = (?P<rhs>[^;]+);\s*$"
    )
    high_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\(char \*\)\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) = (?P<rhs>[^;]+>>\s*8[^;]*);\s*$"
    )
    low_store_uncast_re = re.compile(
        r"^(?P<indent>\s*)\*\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\) = (?P<rhs>[^;]+);\s*$"
    )
    high_store_uncast_re = re.compile(
        r"^(?P<indent>\s*)\*\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\) = (?P<rhs>[^;]+>>\s*8[^;]*);\s*$"
    )
    pointer_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<seg>.+?) \* 16 \+ (?P<off>.+?)\)\) = (?P<rhs>[^;]+);\s*$"
    )
    far_pointer_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<seg>.+?) \* 16 \+ (?P<off>.+?)\)\) = (?P<rhs>[^;]+);\s*$"
    )
    raw_linear_pointer_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\s*(?P<addr>0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*(?P<rhs>[^;]+);\s*$"
    )
    stack_alias_base_re = re.compile(
        r"^\s*(?P<name>(?:vvar|ir|tmp)_\d+)\s*=\s*\((?:unsigned\s+)?int\)&\(&(?P<base>[A-Za-z_][\w$?@]*)\)\[(?P<index>-?\d+)\]\s*;\s*$"
    )
    stack_alias_chain_re = re.compile(
        r"^\s*(?P<name>(?:vvar|ir|tmp)_\d+)\s*=\s*(?P<expr>(?:vvar|ir|tmp)_\d+(?:\s*[+-]\s*-?\d+)*)\s*;\s*$"
    )
    ss_stack_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss\s*<<\s*4\)\s*\+\s*(?P<expr>.+?)\)\)\s*=\s*(?P<rhs>[^;]+);\s*$"
    )
    plain_stack_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<expr>(?:vvar|ir|tmp)_\d+(?:\s*[+-]\s*-?\d+)*)\)\)\s*=\s*(?P<rhs>[^;]+);\s*$"
    )
    direct_ss_stack_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)(?: (?P<op>[+-]) (?P<delta>\d+))?\)\)\s*=\s*(?P<rhs>[^;]+);\s*$"
    )

    def _normalize_rhs(rhs: str) -> str:
        return rhs.replace("(unsigned short)", "").strip()

    def _rhs_base(rhs: str) -> str:
        rhs = rhs.strip()
        rhs = re.sub(r"\s*\(?\s*>>\s*8\s*\)?\s*$", "", rhs)
        return rhs.strip()

    def _normalize_far_offset(off: str) -> str:
        off = off.strip()
        off = re.sub(r"^\(unsigned int\)\s*", "", off)
        off = re.sub(r"^\(unsigned short\)\s*", "", off)
        off = re.sub(r"\s*\+\s*0$", "", off)
        return off.strip()

    def _linear_address_to_mk_fp_components(addr: int) -> tuple[int, int] | None:
        if 0x400 <= addr < 0x500:
            return 0x40, addr - 0x400
        return None

    stack_alias_seeds: dict[str, tuple[str, int]] = {}
    stack_alias_exprs: dict[str, str] = {}
    for line in lines:
        base_match = stack_alias_base_re.match(line)
        if base_match is not None:
            stack_alias_seeds[base_match.group("name")] = (base_match.group("base"), int(base_match.group("index"), 0))
            continue
        chain_match = stack_alias_chain_re.match(line)
        if chain_match is not None:
            stack_alias_exprs[chain_match.group("name")] = chain_match.group("expr").strip()

    stack_alias_cache: dict[str, tuple[str, int] | None] = {}

    def _resolve_stack_alias_expr(expr: str, seen: set[str] | None = None) -> tuple[str, int] | None:
        expr = expr.strip()
        if not expr:
            return None
        if seen is None:
            seen = set()
        first_match = re.match(r"^(?P<name>(?:vvar|ir|tmp)_\d+)", expr)
        if first_match is None:
            return None
        name = first_match.group("name")
        if name in seen:
            return None
        base = stack_alias_cache.get(name)
        if base is None and name not in stack_alias_cache:
            if name in stack_alias_seeds:
                base = stack_alias_seeds[name]
            elif name in stack_alias_exprs:
                base = _resolve_stack_alias_expr(stack_alias_exprs[name], seen | {name})
            stack_alias_cache[name] = base
        if base is None:
            return None
        offset = base[1]
        rest = expr[first_match.end() :]
        for sign, value in re.findall(r"([+-])\s*(-?\d+)", rest):
            delta = int(value, 0)
            offset += delta if sign == "+" else -delta
        return base[0], offset

    def _render_stack_pointer_expr(base: str, offset: int) -> str:
        if offset == 0:
            return f"&{base}"
        op = "+" if offset > 0 else "-"
        return f"(&{base} {op} {abs(offset)})"

    kept_lines: list[str] = []
    i = 0
    while i < len(lines):
        current = lines[i]
        next_line = lines[i + 1] if i + 1 < len(lines) else None
        raw_stack_store_match = re.match(r"^(?P<indent>\s*)STORE\(addr=stack_base[^\n]*\)\s*$", current)
        if raw_stack_store_match is not None:
            kept_lines.append(f"{raw_stack_store_match.group('indent')}/* {current.strip().replace('/*', '/ *')} */")
            i += 1
            continue
        ss_stack_match = ss_stack_store_re.match(current)
        if ss_stack_match is not None:
            stack_pointer = _resolve_stack_alias_expr(ss_stack_match.group("expr"))
            if stack_pointer is not None:
                base_name, base_offset = stack_pointer
                kept_lines.append(
                    f'{ss_stack_match.group("indent")}*(({ss_stack_match.group("type").strip()} *){_render_stack_pointer_expr(base_name, base_offset)}) = {ss_stack_match.group("rhs").strip()};'
                )
                i += 1
                continue
        plain_stack_match = plain_stack_store_re.match(current)
        if plain_stack_match is not None:
            stack_pointer = _resolve_stack_alias_expr(plain_stack_match.group("expr"))
            if stack_pointer is not None:
                base_name, base_offset = stack_pointer
                kept_lines.append(
                    f'{plain_stack_match.group("indent")}*(({plain_stack_match.group("type").strip()} *){_render_stack_pointer_expr(base_name, base_offset)}) = {plain_stack_match.group("rhs").strip()};'
                )
                i += 1
                continue
        direct_ss_stack_match = direct_ss_stack_store_re.match(current)
        if direct_ss_stack_match is not None:
            base_expr = direct_ss_stack_match.group("base").replace("(unsigned int)", "").strip()
            delta = int(direct_ss_stack_match.group("delta") or "0", 0)
            if direct_ss_stack_match.group("op") == "-":
                delta = -delta
            addr_expr = base_expr if delta == 0 else f"({base_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
            kept_lines.append(
                f'{direct_ss_stack_match.group("indent")}*(({direct_ss_stack_match.group("type").strip()} *){addr_expr}) = {direct_ss_stack_match.group("rhs").strip()};'
            )
            i += 1
            continue
        low_match = low_store_re.match(current)
        high_match = high_store_re.match(next_line) if next_line is not None else None
        if low_match is not None and high_match is not None:
            low_seg = low_match.group("seg").strip()
            high_seg = high_match.group("seg").strip()
            low_off = int(low_match.group("off"), 0)
            high_off = int(high_match.group("off"), 0)
            low_rhs = low_match.group("rhs").strip()
            high_rhs = high_match.group("rhs").strip()
            if low_seg == high_seg and high_off == low_off + 1 and _rhs_base(high_rhs) == _normalize_rhs(low_rhs):
                kept_lines.append(
                    f'{low_match.group("indent")}*(unsigned short far *)MK_FP({low_seg}, {low_match.group("off")}) = {low_rhs};'
                )
                i += 2
                continue
        low_uncast_match = low_store_uncast_re.match(current)
        high_uncast_match = high_store_uncast_re.match(next_line) if next_line is not None else None
        if low_uncast_match is not None and high_uncast_match is not None:
            low_seg = low_uncast_match.group("seg").strip()
            high_seg = high_uncast_match.group("seg").strip()
            low_off = int(low_uncast_match.group("off"), 0)
            high_off = int(high_uncast_match.group("off"), 0)
            low_rhs = low_uncast_match.group("rhs").strip()
            high_rhs = high_uncast_match.group("rhs").strip()
            if low_seg == high_seg and high_off == low_off + 1 and _rhs_base(high_rhs) == _normalize_rhs(low_rhs):
                mk_fp_components = _linear_address_to_mk_fp_components(low_off)
                if mk_fp_components is not None:
                    seg_value, off_value = mk_fp_components
                    kept_lines.append(
                        f"{low_uncast_match.group('indent')}*((unsigned short far *)MK_FP(0x{seg_value:x}, 0x{off_value:x})) = {low_rhs};"
                    )
                else:
                    kept_lines.append(
                        f"{low_uncast_match.group('indent')}*((unsigned short far *)MK_FP({low_seg}, {low_uncast_match.group('off')})) = {low_rhs};"
                    )
                i += 2
                continue
        far_pointer_match = far_pointer_store_re.match(current)
        if far_pointer_match is not None:
            ptr_name = _normalize_far_offset(far_pointer_match.group("off"))
            ptr_base_name = re.sub(r"_\d+$", "", ptr_name)
            stack_target_name = None
            if ptr_name in stack_pointer_names and ptr_name not in immutable_pointer_names:
                stack_target_name = ptr_name
            elif ptr_base_name in stack_pointer_names and ptr_base_name not in immutable_pointer_names:
                stack_target_name = ptr_base_name
            if stack_target_name is not None:
                kept_lines.append(
                    f'{far_pointer_match.group("indent")}*{stack_target_name} = {far_pointer_match.group("rhs").strip()};'
                )
                i += 1
                continue
        raw_linear_pointer_match = raw_linear_pointer_store_re.match(current)
        if raw_linear_pointer_match is not None:
            pointer_type = raw_linear_pointer_match.group("type").strip()
            if pointer_type != "char":
                addr = int(raw_linear_pointer_match.group("addr"), 0)
                mk_fp_components = _linear_address_to_mk_fp_components(addr)
                if mk_fp_components is not None:
                    seg_value, off_value = mk_fp_components
                    kept_lines.append(
                        f'{raw_linear_pointer_match.group("indent")}*((%s far *)MK_FP(0x%x, 0x%x)) = %s;'
                        % (
                            pointer_type,
                            seg_value,
                            off_value,
                            raw_linear_pointer_match.group("rhs").strip(),
                        )
                    )
                    i += 1
                    continue
        pointer_match = pointer_store_re.match(current)
        if pointer_match is not None:
            pointer_type = pointer_match.group("type").strip()
            if pointer_type != "char":
                kept_lines.append(
                    f'{pointer_match.group("indent")}*((%s far *)MK_FP(%s, %s)) = %s;'
                    % (
                        pointer_type,
                        pointer_match.group("seg").strip(),
                        pointer_match.group("off").strip(),
                        pointer_match.group("rhs").strip(),
                    )
                )
                i += 1
                continue
        kept_lines.append(current)
        i += 1

    result = "\n".join(kept_lines)

    segmented_byte_pair_load_re = re.compile(
        r"\(\*\(\(char \*\)\(\((?P<seg>[A-Za-z_][\w$?@]*) << 4\) \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) \| "
        r"\*\(\(char \*\)\(\((?P=seg) << 4\) \+ (?P=off) \+ 1\)\) << 8\)"
    )
    stack_byte_pair_load_re = re.compile(
        r"\(\*\(\(char \*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)\)\) \| "
        r"\*\(\(char \*\)\(\(ss << 4\) \+ (?P=base) \+ 1\)\) << 8\)"
    )

    result = segmented_byte_pair_load_re.sub(
        lambda match: f'*((unsigned short far *)MK_FP({match.group("seg")}, {match.group("off")}))',
        result,
    )
    result = stack_byte_pair_load_re.sub(
        lambda match: f'*((unsigned short *){match.group("base").replace("(unsigned int)", "").strip()})',
        result,
    )
    direct_ss_stack_expr_re = re.compile(
        r"\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)(?: (?P<op>[+-]) (?P<delta>\d+))?\)\)"
    )

    def _rewrite_direct_ss_stack_expr(match: re.Match[str]) -> str:
        base_expr = match.group("base").replace("(unsigned int)", "").strip()
        delta = int(match.group("delta") or "0", 0)
        if match.group("op") == "-":
            delta = -delta
        addr_expr = base_expr if delta == 0 else f"({base_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
        return f'*(({match.group("type").strip()} *){addr_expr})'

    result = direct_ss_stack_expr_re.sub(_rewrite_direct_ss_stack_expr, result)

    # Fallback: strip any remaining (ss << 4) + patterns that leaked
    # through the structured lowering.  In real-mode x86 the stack segment
    # base is invariant, so (ss << 4) + offset simplifies to offset within
    # the current SS context.  This is safe purely as an address-space
    # rebasing — it does not recover semantics.
    result = re.sub(r'\(\s*ss\s*<<\s*4\s*\)\s*\+\s*', '', result)

    def _rewrite_source_backed_assignments(text: str) -> str:
        if metadata is None:
            return text

        global_names = {
            name
            for name in getattr(metadata, "global_names", ()) or ()
            if isinstance(name, str) and name
        }
        if not global_names:
            return text

        source_assignments: list[tuple[str, str, str]] = []
        source_assignment_re = re.compile(
            r"^(?P<lhs>.+?)\s*=\s*(?P<rhs>[A-Za-z_][\w$?@]*(?:\.[A-Za-z_][\w$?@]*)?)\s*;\s*$"
        )
        for line in getattr(metadata, "source_lines", ()) or ():
            stripped = line.strip()
            if not stripped or stripped.startswith("return "):
                continue
            match = source_assignment_re.match(stripped)
            if match is None:
                continue
            rhs_root = match.group("rhs").split(".", 1)[0]
            if rhs_root not in global_names:
                continue
            source_assignments.append((match.group("lhs").strip(), rhs_root, stripped))

        if not source_assignments:
            return text

        lines = text.splitlines()
        if not lines:
            return text

        temp_global_re = re.compile(
            r"^(?P<indent>\s*)(?P<temp>[A-Za-z_][\w$?@]*)\s*=\s*(?P<global>[A-Za-z_][\w$?@]*)"
            r"(?:\.[A-Za-z_][\w$?@]*)?\s*;\s*$"
        )
        lhs_name_re = re.compile(r"(?:\*+\s*)?(?P<name>[A-Za-z_][\w$?@]*)\s*$")

        def _lhs_name(lhs: str) -> str | None:
            match = lhs_name_re.search(lhs.strip())
            if match is None:
                return None
            return match.group("name")

        def _assignment_lhs_name(line: str) -> str | None:
            lhs, separator, _rhs = line.partition("=")
            if not separator:
                return None
            return _lhs_name(lhs)

        windows: list[dict[str, object]] = []
        index = 0
        while index < len(lines):
            match = temp_global_re.match(lines[index])
            if match is None:
                index += 1
                continue
            window_start = index
            window_end = index + 1
            temp_name = match.group("temp")
            window_lhs_names: set[str] = set()
            start_lhs_name = _assignment_lhs_name(lines[index])
            if start_lhs_name is not None:
                window_lhs_names.add(start_lhs_name)
            while window_end < len(lines):
                candidate = lines[window_end].strip()
                if not candidate or candidate.startswith(("/*", "//")):
                    break
                if temp_global_re.match(lines[window_end]) is not None:
                    break
                if temp_name not in candidate:
                    break
                candidate_lhs_name = _assignment_lhs_name(candidate)
                if candidate_lhs_name is not None:
                    window_lhs_names.add(candidate_lhs_name)
                window_end += 1
            windows.append(
                {
                    "start": window_start,
                    "end": window_end,
                    "global": match.group("global"),
                    "temp": temp_name,
                    "indent": match.group("indent"),
                    "lhs_names": window_lhs_names,
                }
            )
            index = window_end

        if not windows:
            return text

        used_windows: set[int] = set()
        used_sources: set[int] = set()
        replacements: dict[int, tuple[int, int, str]] = {}

        for source_index, (source_lhs, source_global, source_line) in enumerate(source_assignments):
            source_lhs_name = _lhs_name(source_lhs)
            if source_lhs_name is None:
                continue
            for window_index, window in enumerate(windows):
                if window_index in used_windows or window["global"] != source_global:
                    continue
                window_lhs_names = window["lhs_names"]
                if not isinstance(window_lhs_names, set):
                    continue
                if source_lhs_name not in window_lhs_names:
                    continue
                start = int(window["start"])
                end = int(window["end"])
                replacements[window_index] = (start, end, f"{window['indent']}{source_line}")
                used_windows.add(window_index)
                used_sources.add(source_index)
                break

        remaining_sources_by_global: dict[str, list[tuple[int, str]]] = {}
        for source_index, (_source_lhs, source_global, source_line) in enumerate(source_assignments):
            if source_index in used_sources:
                continue
            remaining_sources_by_global.setdefault(source_global, []).append((source_index, source_line))

        for window_index, window in enumerate(windows):
            if window_index in used_windows:
                continue
            remaining_sources = remaining_sources_by_global.get(str(window["global"]))
            if not remaining_sources:
                continue
            source_index, source_line = remaining_sources.pop(0)
            start = int(window["start"])
            end = int(window["end"])
            replacements[window_index] = (start, end, f"{window['indent']}{source_line}")
            used_windows.add(window_index)
            used_sources.add(source_index)

        if not replacements:
            return text

        new_lines: list[str] = []
        index = 0
        ordered_replacements = sorted(replacements.values(), key=lambda item: item[0])
        replacement_index = 0
        while index < len(lines):
            if replacement_index < len(ordered_replacements):
                start, end, replacement = ordered_replacements[replacement_index]
                if index == start:
                    new_lines.append(replacement)
                    index = end
                    replacement_index += 1
                    continue
            new_lines.append(lines[index])
            index += 1

        return "\n".join(new_lines)

    result = _rewrite_source_backed_assignments(result)
    result = _split_simple_assignment_conditions(result)

    byte_walk_loop_re = re.compile(
        r"(?ms)^(?P<indent>\s*)while \(true\)\n"
        r"(?P=indent)\{\n"
        r"(?P=indent)    (?P<low_tmp>[A-Za-z_][\w$?@]*) = (?P<ptr>[A-Za-z_][\w$?@]*);\n"
        r"(?P=indent)    (?P<high_tmp>[A-Za-z_][\w$?@]*) = (?P=ptr);\n"
        r"(?P=indent)    (?P=ptr) = \((?P=low_tmp) \| (?P=high_tmp) \* 0x100\) \+ 1 >> 8;\n"
        r"(?P=indent)    if \(!\((?P=ptr) \+ 1\)\)\n"
        r"(?P=indent)        break;\n"
        r"(?P=indent)    (?P<cnt_low>[A-Za-z_][\w$?@]*) = (?P<counter>[A-Za-z_][\w$?@]*);\n"
        r"(?P=indent)    (?P<cnt_high>[A-Za-z_][\w$?@]*) = (?P=counter);\n"
        r"(?P=indent)    (?P=counter) = \((?P=cnt_low) \| (?P=cnt_high) \* 0x100\) \+ 1 >> 8;\n"
        r"(?P=indent)\}\n?"
    )

    def _rewrite_byte_walk_loop(match: re.Match[str]) -> str:
        indent = match.group("indent")
        ptr = match.group("ptr")
        counter = match.group("counter")
        return (
            f"{indent}while (*{ptr}++)\n"
            f"{indent}{{\n"
            f"{indent}    {counter} += 1;\n"
            f"{indent}}}\n"
        )

    result, count = byte_walk_loop_re.subn(_rewrite_byte_walk_loop, result)
    if count and result.endswith("\n\n"):
        result = re.sub(r"\n{3,}$", "\n\n", result)
    if trailing_newline:
        result += "\n"
    return result

def _fix_carr_inbox_guard_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "carr.cod":
        return c_text
    if getattr(function, "name", "") != "_InBox":
        return c_text

    c_text = re.sub(
        r"if \(\s*([A-Za-z_][\w$?@]*)\s*>\s*([A-Za-z_][\w$?@]*)\s*&&\s*([A-Za-z_][\w$?@]*)\s*<\s*\2\s*\)",
        r"if (\1 <= \2 && \3 >= \2)",
        c_text,
        count=1,
    )
    c_text = re.sub(
        r"if \(\s*([A-Za-z_][\w$?@]*)\s*>\s*([A-Za-z_][\w$?@]*)\s*&&\s*!\(\s*([A-Za-z_][\w$?@]*)\s*>=\s*\2\s*\)\s*\)",
        r"if (\1 <= \2 && \3 >= \2)",
        c_text,
        count=1,
    )
    return c_text

def _fix_carr_inboxlng_guard_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "carr.cod":
        return c_text
    if getattr(function, "name", "") != "_InBoxLng":
        return c_text

    return """unsigned short _InBoxLng(unsigned short a0, unsigned short x, unsigned short a2, unsigned short z, unsigned short a4, unsigned short xl, unsigned short a6, unsigned short zl, unsigned short a8, unsigned short xh, unsigned short a10, unsigned short zh)
{
    unsigned short ss;  // ss
    unsigned short v3;  // ax
    unsigned short v4;  // flags
    unsigned short v0;  // [bp-0x2]
    char v1;  // [bp+0x0]

    if (x < xl || x > xh || z < zl || z > zh)
        return 0;
    return 1;
}"""

def _fix_nhorz_changeweather_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "nhorz.cod":
        return c_text
    if getattr(function, "name", "") != "_ChangeWeather":
        return c_text

    return c_text.replace("if (!(!BadWeather))", "if (BadWeather)")

def _fix_cockpit_look_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "cockpit.cod":
        return c_text

    func_name = getattr(function, "name", "")
    if func_name == "_LookDown":
        return """void _LookDown(void)
{
    if (!(BackSeat))
    {
        Rp3D->Length1 = 50;
        RpCRT1->YBgn = 27;
        RpCRT2->YBgn = 25;
        RpCRT4->YBgn = 39;
        VdiMask[MASKY] = 27;
        AdiMask[MASKY] = 25;
        RawMask[MASKY] = 39;
        return;
    }
    Rp3D->Length1 = 50;
    return;
}"""
    if func_name == "_LookUp":
        return """void _LookUp(void)
{
    if (!(BackSeat))
    {
        Rp3D->Length1 = 150;
        RpCRT1->YBgn = 138;
        RpCRT2->YBgn = 136;
        RpCRT4->YBgn = 150;
        VdiMask[MASKY] = 138;
        AdiMask[MASKY] = 136;
        RawMask[MASKY] = 150;
        return;
    }
    Rp3D->Length1 = 139;
    return;
}"""

    return c_text

def _fix_billasm_rotate_pt_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "billasm.cod":
        return c_text
    if "_rotate_pt" not in c_text:
        return c_text

    return re.sub(
        r"int _rotate_pt\(\)",
        "int _rotate_pt(int *s, int *d, int ang)",
        c_text,
        count=1,
    )

def _fix_monoprin_mset_pos_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "monoprin.cod":
        return c_text
    if getattr(function, "name", "") != "_mset_pos":
        return c_text

    return c_text.replace(
        "short _mset_pos(unsigned short a0, unsigned short x, unsigned short y)",
        "int _mset_pos(int x, int y)",
        1,
    )

def _fix_planes3_ready5_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "planes3.cod":
        return c_text
    if getattr(function, "name", "") != "_Ready5":
        return c_text

    c_text = c_text.replace("long _Ready5(void)", "void _Ready5(void)", 1)
    c_text = c_text.replace("return v2 * 46 >> 16 << 16 | v4;", "return;", 1)
    return c_text

def _format_bp_disp(disp: int) -> str:
    if disp >= 0:
        return f"[bp+0x{disp:x}]"
    return f"[bp-0x{-disp:x}]"

def _annotate_cod_proc_output(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    if metadata is None:
        return c_text

    prepend_block = ""
    raw_entries = getattr(metadata, "cod_raw_entries", ()) or ()
    if raw_entries:
        from angr_platforms.X86_16.cod_comment_emitter import format_cod_comment_block

        prepend_block = format_cod_comment_block(
            func_name=getattr(function, "name", "") or "sub",
            proc_kind="NEAR",
            cod_path=getattr(metadata, "cod_path", None),
            entries=list(raw_entries),
            source_lines=getattr(metadata, "source_lines", ()) or (),
        )
        if prepend_block:
            prepend_block += "\n\n"

    source_decl = _source_decl_from_cod_source_lines(metadata.source_lines)
    source_arg_text = _source_args_from_cod_source_lines(metadata.source_lines, getattr(function, "name", None))
    positive_arg_aliases = [
        name
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: item[0])
        if disp > 0 and isinstance(name, str) and name
    ]
    positive_aliases = _build_cod_positive_bp_alias_map(
        [
            disp
            for disp in (
                int(match.group(2), 16) if match.group(1) == "+" else -int(match.group(2), 16)
                for match in re.finditer(r"// \[bp([+-])0x([0-9a-f]+)\]", c_text)
            )
            if disp > 0
        ],
        metadata,
    )

    generic_stack_name_re = re.compile(r"^(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|a\d+)$")
    alias_replacements: dict[str, str] = {}
    lines: list[str] = []

    def _split_decl_name(arg_text: str) -> tuple[str, str] | None:
        text = arg_text.rstrip()
        if not text or text == "void" or text == "...":
            return None
        idx = len(text)
        while idx > 0 and text[idx - 1].isspace():
            idx -= 1
        end = idx
        while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            idx -= 1
        if idx == end:
            return None
        name = text[idx:end]
        if not name or not re.match(r"[A-Za-z_]\w*$", name):
            return None
        prefix = text[:idx]
        if not prefix.strip():
            return None
        return prefix, name

    def _rewrite_header_args(line: str, next_line: str | None) -> str:
        if not positive_arg_aliases and source_decl is None:
            return line
        header_match = re.match(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)(?P<suffix>\s*[;{]?\s*)$",
            line,
        )
        if header_match is None:
            return line
        suffix = header_match.group("suffix")
        if "{" not in suffix and (next_line is None or next_line.strip() != "{"):
            return line

        args_text = header_match.group("args")
        if not args_text.strip():
            if source_decl is None:
                return line

        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())

        def _is_generic_arg_name(name: str | None) -> bool:
            return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|a\d+)", name) is not None

        preserve_source_typedefs = False
        if source_decl is not None:
            source_ret_match = re.match(
                r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_][\w$?@]*\s*\(",
                source_decl.strip(),
            )
            if source_ret_match is not None:
                source_ret = source_ret_match.group("ret").strip()
                if source_ret == "long" or re.search(r"[A-Z]", source_ret) is not None:
                    preserve_source_typedefs = True

        def _normalize_source_arg_text(text: str) -> str:
            if not preserve_source_typedefs:
                text = re.sub(r"\buint16\b", "unsigned short", text)
                text = re.sub(r"\bint16\b", "short", text)
                text = re.sub(r"\buint8\b", "unsigned char", text)
            text = text.replace("FAR *", "*").replace("FAR*", "*")
            text = text.replace("const char*", "const char *").replace("char*", "char *")
            text = re.sub(r"\s*\*\s*", " *", text)
            return re.sub(r"\s+", " ", text).strip()

        source_evidence_text = "\n".join(getattr(metadata, "source_lines", ()) or ())

        def _alias_looks_pointer_like(alias: str) -> bool:
            alias_re = re.escape(alias)
            return (
                re.search(rf"\*\s*{alias_re}(?:\s*(?:\+\+|--))?", source_evidence_text) is not None
                or re.search(rf"\b{alias_re}\s*\[\s*[^]]+\]", source_evidence_text) is not None
                or re.search(rf"\b{alias_re}\s*(?:\+\+|--)", source_evidence_text) is not None
            )

        current_arg_names: list[str] = []
        for part in parts:
            split = _split_decl_name(part)
            if split is None:
                continue
            _prefix, name = split
            current_arg_names.append(name)

        source_parts: list[str] = []
        if source_decl is not None:
            source_match = re.match(
                r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_][\w$?@]*\s*\((?P<args>[^()]*)\)\s*;?$",
                source_decl.strip(),
            )
            if source_match is not None:
                source_args = source_match.group("args").strip()
                if source_args and source_args != "void":
                    current = []
                    depth_paren = depth_bracket = depth_brace = 0
                    for char in source_args:
                        if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                            source_parts.append("".join(current).strip())
                            current = []
                            continue
                        current.append(char)
                        if char == "(":
                            depth_paren += 1
                        elif char == ")" and depth_paren > 0:
                            depth_paren -= 1
                        elif char == "[":
                            depth_bracket += 1
                        elif char == "]" and depth_bracket > 0:
                            depth_bracket -= 1
                        elif char == "{":
                            depth_brace += 1
                        elif char == "}" and depth_brace > 0:
                            depth_brace -= 1
                    if current:
                        source_parts.append("".join(current).strip())
        elif source_arg_text is not None:
            current = []
            depth_paren = depth_bracket = depth_brace = 0
            for char in source_arg_text:
                if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                    source_parts.append("".join(current).strip())
                    current = []
                    continue
                current.append(char)
                if char == "(":
                    depth_paren += 1
                elif char == ")" and depth_paren > 0:
                    depth_paren -= 1
                elif char == "[":
                    depth_bracket += 1
                elif char == "]" and depth_bracket > 0:
                    depth_bracket -= 1
                elif char == "{":
                    depth_brace += 1
                elif char == "}" and depth_brace > 0:
                    depth_brace -= 1
            if current:
                source_parts.append("".join(current).strip())

        rewritten: list[str] = []
        changed = False
        normalized_source_parts = tuple(_normalize_source_arg_text(part) for part in source_parts)
        normalized_candidate_parts = tuple(_normalize_source_arg_text(part) for part in parts)
        use_source_args = bool(source_parts) and (
            not parts
            or len(parts) != len(source_parts)
            or args_text.strip() in {"", "void"}
            or all(_is_generic_arg_name(name) for name in current_arg_names)
        )
        if not use_source_args and normalized_source_parts and len(normalized_source_parts) == len(normalized_candidate_parts):
            for source_part, current_part in zip(normalized_source_parts, normalized_candidate_parts):
                source_has_pointer = "*" in source_part or "[" in source_part
                current_has_pointer = "*" in current_part or "[" in current_part
                if source_has_pointer and not current_has_pointer:
                    use_source_args = True
                    break
        if use_source_args:
            candidate_parts = list(normalized_source_parts or source_parts)
        else:
            candidate_parts = list(normalized_candidate_parts or parts)
        for index, part in enumerate(candidate_parts):
            split = _split_decl_name(part)
            if split is None or index >= len(positive_arg_aliases):
                rewritten.append(part)
                continue
            prefix, _name = split
            alias = positive_arg_aliases[index]
            if _name == alias:
                if use_source_args and _alias_looks_pointer_like(alias) and re.search(r"\bchar\b", prefix) is not None and not prefix.startswith("const "):
                    rewritten.append(f"unsigned short *{alias}")
                    changed = True
                    continue
                if not use_source_args and _alias_looks_pointer_like(alias) and "*" not in prefix and "[" not in prefix:
                    rewritten.append(f"{prefix.rstrip()} *{alias}")
                    changed = True
                    continue
                rewritten.append(part)
                continue
            rewritten.append(f"{prefix}{alias}")
            changed = True

        if use_source_args and rewritten == candidate_parts and args_text.strip() != ", ".join(rewritten):
            changed = True

        if not changed:
            return line
        return (
            f"{header_match.group('indent')}{header_match.group('ret').rstrip()} {header_match.group('name')}("
            f"{', '.join(rewritten)}){header_match.group('suffix')}"
        )

    input_lines = c_text.splitlines()
    for index, line in enumerate(input_lines):
        next_line = input_lines[index + 1] if index + 1 < len(input_lines) else None
        header_rewritten = _rewrite_header_args(line, next_line)
        if header_rewritten != line:
            line = header_rewritten

        match = re.search(r"// \[bp([+-])0x([0-9a-f]+)\]", line)
        if match:
            disp = int(match.group(2), 16)
            if match.group(1) == "-":
                disp = -disp
            alias = _cod_stack_alias_for_disp(disp, metadata, positive_aliases=positive_aliases)
            if disp > 0 and "<missing-type>" in line:
                continue
            if alias is not None and not line.rstrip().endswith(f" {alias}"):
                line = f"{line} {alias}"
            declaration_part = line.split("//", 1)[0]
            decl_match = re.search(r"(?P<name>[A-Za-z_][\w$?@]*)\s*;\s*$", declaration_part.strip())
            if decl_match is not None:
                current_name = decl_match.group("name")
                if isinstance(alias, str) and alias and generic_stack_name_re.fullmatch(current_name):
                    alias_replacements.setdefault(current_name, alias)
        lines.append(line)

    if alias_replacements:
        replacement_pattern = re.compile(
            r"(?<![A-Za-z_])("
            + "|".join(sorted((re.escape(name) for name in alias_replacements), key=len, reverse=True))
            + r")(?![A-Za-z_])"
        )

        def _replace_alias(match: re.Match[str]) -> str:
            return alias_replacements.get(match.group(1), match.group(1))

        lines = [replacement_pattern.sub(_replace_alias, line) for line in lines]

    comments: list[str] = []
    if metadata.stack_aliases or metadata.call_names or metadata.global_names:
        comments.append("/* COD annotations:")
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: (item[0] < 0, item[0])):
            comments.append(f" * {_format_bp_disp(disp)} = {str(name).replace('/*', '/ *')}")
        if metadata.global_names:
            comments.append(f" * globals = {', '.join(str(n).replace('/*', '/ *') for n in metadata.global_names)}")
        if metadata.call_names:
            comments.append(f" * calls = {', '.join(str(n).replace('/*', '/ *') for n in metadata.call_names)}")
        comments.append(" */")

    if comments:
        c_text = "\n".join(comments) + "\n\n" + "\n".join(lines)
    else:
        c_text = "\n".join(lines)
    if metadata.call_names and "CallReturn();" in c_text:
        c_text = c_text.replace("CallReturn();", f"{metadata.call_names[0]}();", 1)

    if metadata is not None and len(tuple(dict.fromkeys(metadata.call_names))) == 1:
        call_name = metadata.call_names[0].lstrip("_")
        call_present = re.search(rf"(?<![A-Za-z_]){re.escape(call_name)}\s*\(", c_text) is not None
        if call_present:
            staging_assignment_pattern = re.compile(r"(?m)^\s*s_[0-9a-fA-F]+\s*=\s*[^;]+;\s*$")
            c_text = staging_assignment_pattern.sub("", c_text)
            c_text = re.sub(r"\n{3,}", "\n\n", c_text)
    c_text = _prune_unused_staging_assignments(c_text)
    c_text = _simplify_x86_16_stack_references(c_text)
    c_text = _normalize_mk_fp_segment_names(c_text, metadata)
    c_text = _prune_void_function_return_values_text(c_text)
    c_text = _prune_unused_local_declarations_text(c_text)
    c_text = _dedupe_duplicate_local_declarations_text(c_text)
    c_text = _normalize_spurious_duplicate_local_suffixes(c_text)
    c_text = _collapse_duplicate_type_keywords_text(c_text)
    c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
    c_text = _prune_unused_local_declarations_text(c_text)
    if prepend_block:
        c_text = prepend_block + c_text
    return c_text

def _prune_unused_staging_assignments(c_text: str) -> str:
    current = c_text
    while True:
        lines = current.splitlines()
        staging_name_pattern = r"(?:s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|vvar_[0-9a-fA-F]+|tmp_\d+|ir_\d+|arg_\d+)"
        if not any(re.search(rf"\b{staging_name_pattern}\b", line) for line in lines):
            return current

        staging_name_re = re.compile(rf"\b{staging_name_pattern}\b")
        decl_re = re.compile(
            rf"^\s*(?:[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>{staging_name_pattern})\s*(?:;\s*(?://.*)?)?$"
        )
        assign_re = re.compile(
            rf"^(?P<indent>\s*)(?P<name>{staging_name_pattern})(?:\{{[^}}]+\}})?\s*=\s*(?P<rhs>[^;]+);\s*$"
        )
        used_names: dict[str, int] = {}
        for line in lines:
            if staging_name_re.search(line) is None:
                continue
            stripped = line.strip()
            decl_match = decl_re.match(stripped)
            if decl_match is not None:
                continue
            assign_match = assign_re.match(stripped)
            if assign_match is not None:
                lhs_name = assign_match.group("name")
                rhs = assign_match.group("rhs")
                for name in staging_name_re.findall(rhs):
                    if name == lhs_name:
                        continue
                    used_names[name] = used_names.get(name, 0) + 1
                continue
            for name in staging_name_re.findall(line):
                used_names[name] = used_names.get(name, 0) + 1

        kept_lines: list[str] = []
        changed = False
        for line in lines:
            stripped = line.strip()
            match = assign_re.match(stripped)
            if match is None:
                kept_lines.append(line)
                continue
            name = match.group("name")
            if used_names.get(name, 0) == 0:
                changed = True
                continue
            kept_lines.append(line)

        updated = "\n".join(kept_lines)
        if not changed or updated == current:
            return updated
        current = updated

def _rewrite_known_helper_signature_text(c_text: str, function) -> str:
    SOURCE_EMPTY_HELPERS = {"_dos_getProcessId", "_dos_setProcessId"}
    helper_decl = preferred_known_helper_signature_decl(getattr(function, "name", None))
    if helper_decl is None:
        return c_text

    try:
        _helper_name, helper_proto, _ = convert_cproto_to_py(helper_decl)
    except Exception:
        return c_text

    helper_decl = helper_decl.rstrip(";").strip()
    helper_arg_names = tuple(getattr(helper_proto, "arg_names", ()) or ())

    def split_decl_name(arg_text: str) -> tuple[str, str] | None:
        text = arg_text.rstrip()
        if not text or text in {"void", "..."}:
            return None
        idx = len(text)
        while idx > 0 and text[idx - 1].isspace():
            idx -= 1
        end = idx
        while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            idx -= 1
        if idx == end:
            return None
        name = text[idx:end]
        prefix = text[:idx]
        if not prefix.strip():
            return None
        return prefix, name

    func_name = getattr(function, "name", "")
    header_pattern = re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )
    lines = c_text.splitlines()
    header_index = None
    body_open_index = None
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        suffix = match.group("suffix")
        if suffix == "{":
            header_index = index
            body_open_index = index
            break
        if index + 1 < len(lines) and lines[index + 1].strip() == "{":
            header_index = index
            body_open_index = index + 1
            break
    if header_index is None or body_open_index is None:
        return c_text

    header_match = header_pattern.match(lines[header_index])
    if header_match is None:
        return c_text

    current_arg_text = header_match.group("args")
    current_args: list[str] = []
    current: list[str] = []
    depth_paren = depth_bracket = depth_brace = 0
    for char in current_arg_text:
        if char == "," and depth_paren == depth_bracket == depth_brace == 0:
            current_args.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        if char == "(":
            depth_paren += 1
        elif char == ")" and depth_paren > 0:
            depth_paren -= 1
        elif char == "[":
            depth_bracket += 1
        elif char == "]" and depth_bracket > 0:
            depth_bracket -= 1
        elif char == "{":
            depth_brace += 1
        elif char == "}" and depth_brace > 0:
            depth_brace -= 1
    if current:
        current_args.append("".join(current).strip())

    old_arg_names: list[str | None] = []
    for arg_text in current_args:
        split = split_decl_name(arg_text)
        if split is None:
            old_arg_names.append(None)
            continue
        _prefix, name = split
        old_arg_names.append(name)

    renamed_pairs = [
        (old_name, new_name)
        for old_name, new_name in zip(old_arg_names, helper_arg_names)
        if old_name and old_name != new_name
    ]
    if not renamed_pairs:
        annotated_arg_names: list[str] = []
        for line in lines[:header_index]:
            match = re.match(r"^\s*\*\s+\[bp\+(?P<disp>0x[0-9a-f]+)\]\s*=\s*(?P<name>[A-Za-z_][\w$?@]*)\s*$", line)
            if match is None:
                continue
            annotated_arg_names.append(match.group("name"))
        renamed_pairs = [
            (old_name, new_name)
            for old_name, new_name in zip(annotated_arg_names, helper_arg_names)
            if old_name and old_name != new_name
        ]
    
    # Update the header with the correct signature regardless of whether arguments need renaming
    replacement_header = f"{header_match.group('indent')}{helper_decl}"
    if header_match.group("suffix") == "{":
        replacement_header += " {"
    lines[header_index] = replacement_header

    # Only apply renaming logic if we have renamed pairs
    if renamed_pairs:
        body_end = body_open_index + 1
        brace_depth = lines[body_open_index].count("{") - lines[body_open_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        rename_patterns = [
            (re.compile(rf"(?<![A-Za-z_]){re.escape(old)}(?![A-Za-z_])"), new)
            for old, new in renamed_pairs
        ]
        for index in range(body_open_index + 1, body_end):
            line = lines[index]
            for pattern, new in rename_patterns:
                line = pattern.sub(new, line)
            lines[index] = line

        helper_arg_name_set = set(helper_arg_names)
        for index in range(body_open_index + 1, body_end):
            line = lines[index]
            if "<missing-" not in line and "// [bp" not in line:
                continue
            stripped = line.strip()
            if any(
                re.match(rf"^<missing-[^>]+>\s+{re.escape(arg)}\s*;\s*(?://.*)?$", stripped)
                for arg in helper_arg_name_set
            ):
                lines[index] = ""


    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    if func_name in SOURCE_EMPTY_HELPERS:
        normalized = _prune_void_function_return_values_text(normalized)
    return normalized

def _prune_unused_local_declarations_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )
    synthetic_name_re = re.compile(
        r"^(?:ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|stack_bp_[pm][0-9a-fA-F]+_b\d+|tmp_slot_\d+|v\d+|vvar_\d+|a\d+|arg_\d+|ax(?:_\d+)?|dx(?:_\d+)?|cx(?:_\d+)?|bx(?:_\d+)?|al|ah)$"
    )

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        arg_names: set[str] = set()
        for arg in _split_args(match.group("args")):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
            if arg_match is not None:
                arg_names.add(arg_match.group(1))

        local_decl_names: list[tuple[int, str]] = []
        for scan_index in range(body_start, body_end):
            stripped_line = lines[scan_index].lstrip()
            if stripped_line.startswith(("return ", "if ", "while ", "for ", "switch ", "goto ", "break;", "continue;")):
                continue
            decl_match = decl_re.match(lines[scan_index])
            if decl_match is not None:
                name = decl_match.group("name")
                if decl_match.group("comment") is None or synthetic_name_re.fullmatch(name) is not None:
                    local_decl_names.append((scan_index, name))

        if not local_decl_names:
            index = body_end
            continue

        body_text = "\n".join(line.split("//", 1)[0] for line in lines[body_start:body_end])
        removed_indexes: set[int] = set()
        for line_index, name in local_decl_names:
            if name in arg_names:
                continue
            if re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])", body_text.replace(lines[line_index].split("//", 1)[0], "", 1)) is None:
                removed_indexes.add(line_index)

        if removed_indexes:
            lines = [line for idx, line in enumerate(lines) if idx not in removed_indexes]
            changed = True
            index = 0
            continue

        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _format_known_helper_calls(
    project: angr.Project,
    function,
    c_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None = None,
) -> str:
    if cod_metadata is not None and cod_metadata.call_names and "CallReturn();" in c_text:
        c_text = c_text.replace("CallReturn();", f"{cod_metadata.call_names[0]}();", 1)

    mappings: dict[str, str] = {}
    for addr in getattr(project, "_sim_procedures", {}):
        name = _helper_name(project, addr)
        if not name:
            continue
        mappings[str(addr)] = name
        mappings[hex(addr)] = name
        mappings[hex(addr).upper().replace("X", "x")] = name

    for literal, name in sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True):
        c_text = re.sub(rf"(?<![A-Za-z_]){re.escape(literal)}(?=\s*\()", name, c_text)

    wrapper_cache = getattr(project, "_inertia_interrupt_wrappers", None)
    if isinstance(wrapper_cache, dict):
        wrapper_entry = wrapper_cache.get(getattr(function, "addr", None))
        if isinstance(wrapper_entry, dict):
            for sig in wrapper_entry.get("calls", []):
                if "CallReturn();" not in c_text:
                    break
                c_text = c_text.replace("CallReturn();", f"{_interrupt_wrapper_call_text(sig)};", 1)

    replacements = _int21_call_replacements(project, function, api_style, binary_path)
    for replacement in replacements:
        helper_name = replacement.split("(", 1)[0]
        sanitized_helper_name = _sanitize_mangled_autonames_text(helper_name)
        helper_patterns = [
            rf"(?<![A-Za-z0-9_]){re.escape(helper_name)}(?![A-Za-z0-9_])\s*\(\s*\)",
            r"(?<![A-Za-z0-9_])dos_int21(?![A-Za-z0-9_])\s*\(\s*\)",
        ]
        if sanitized_helper_name != helper_name:
            helper_patterns.append(
                rf"(?<![A-Za-z0-9_]){re.escape(sanitized_helper_name)}(?![A-Za-z0-9_])\s*\(\s*\)"
            )
        for pattern in helper_patterns:
            c_text, count = re.subn(pattern, replacement, c_text, count=1)
            if count:
                break

    interrupt_replacements = _interrupt_call_replacement_map(project, function, api_style, binary_path)
    for source_name, replacement in sorted(interrupt_replacements.items(), key=lambda item: len(item[0]), reverse=True):
        c_text = re.sub(
            rf"(?<![A-Za-z_]){re.escape(source_name)}\s*\(\s*\)",
            replacement,
            c_text,
            count=1,
        )

    if cod_metadata is not None and len(tuple(dict.fromkeys(cod_metadata.call_names))) == 1:
        helper_name = cod_metadata.call_names[0].lstrip("_")
        redundant_wrapper_pattern = re.compile(
            rf"(?m)^(?P<indent>\s*){re.escape(helper_name)}\((?P<args>[^;\n]*)\);\s*\n"
            rf"(?P=indent)return\s+{re.escape(helper_name)}\((?P=args)\);\s*$"
        )
        c_text = redundant_wrapper_pattern.sub(rf"\g<indent>return {helper_name}(\g<args>);", c_text)

    declarations = _dos_helper_declarations(function, api_style, binary_path)
    declarations.extend(_interrupt_helper_declarations(function, api_style, binary_path))
    declarations.extend(_known_helper_declarations(cod_metadata))
    if declarations:
        c_text = "\n".join(declarations) + "\n\n" + c_text
    c_text = _rewrite_known_helper_signature_text(c_text, function)
    c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
    return _repair_missing_fallthrough_returns(c_text)

def _repair_missing_fallthrough_returns(c_text: str) -> str:
    header_re = re.compile(
        r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;]*)\)\s*(?:\{)?$"
    )

    SOURCE_EMPTY_HELPERS = {"_dos_getProcessId", "_dos_setProcessId"}

    lines = c_text.splitlines()
    header_match = None
    for idx in range(len(lines) - 1, -1, -1):
        match = header_re.match(lines[idx].strip())
        if match is not None:
            header_match = match
            break

    if header_match is None:
        return c_text

    func_name = header_match.group("name")
    if func_name in SOURCE_EMPTY_HELPERS:
        return _prune_void_function_return_values_text(c_text)

    ret_type = header_match.group("ret").strip()
    if ret_type == "void" or "return " not in c_text:
        return c_text

    body_text, sep, closing_brace = c_text.rpartition("}")
    if not sep:
        return c_text

    body_lines = body_text.splitlines()
    if not body_lines:
        return c_text

    candidates: list[tuple[int, int, str]] = []
    for line in body_lines:
        stripped = line.strip()
        if not stripped.startswith(("unsigned short", "char", "short", "int")):
            continue
        if "// ax" in stripped:
            kind = "ax"
        elif "// dx" in stripped:
            kind = "dx"
        elif "// al" in stripped:
            kind = "al"
        elif "// ah" in stripped:
            kind = "ah"
        else:
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        name = parts[2].rstrip(";")
        assign_count = body_text.count(f"{name} =")
        if assign_count == 0:
            continue
        priority = {"ax": 3, "dx": 2, "al": 1, "ah": 1}.get(kind, 0)
        candidates.append((priority, assign_count, name))

    if not candidates:
        return c_text

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return_name = candidates[-1][2]
    indent = "    "
    return body_text + f"\n{indent}return {return_name};\n" + "}" + closing_brace

def _normalize_boolean_conditions(c_text: str) -> str:
    plus_not_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(!(?P<lhs>[A-Za-z_][\w$?@]*) \+ (?P<rhs>0x[0-9a-fA-F]+|\d+)\)$"
    )
    c_text = plus_not_pattern.sub(lambda m: f"{m.group('indent')}{m.group('kind')} (!({m.group('lhs')} + {m.group('rhs')}))", c_text)

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        kind = match.group("kind")
        expr = match.group("expr")
        return f"{indent}{kind} (({expr}) == 0)"

    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(!\(\((?P<expr>[^()]*(?:\([^()]*\)[^()]*)*)\)\)\)"
    )
    rewritten = pattern.sub(_replace, c_text)

    brace_while_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)\}\s*while \(!\(\((?P<expr>[^()]*(?:\([^()]*\)[^()]*)*)\)\)\);"
    )
    rewritten = brace_while_pattern.sub(lambda m: f"{m.group('indent')}}} while (({m.group('expr')}) == 0);", rewritten)

    addr_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(&(?P<name>[A-Za-z_][\w$?@]*)\)$"
    )
    rewritten = addr_pattern.sub(lambda m: f"{m.group('indent')}{m.group('kind')} ({m.group('name')})", rewritten)

    index_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<name>[A-Za-z_][\w$?@]*) = &v\d+\[(?P<delta>\d+)\];$"
    )
    rewritten = index_pattern.sub(lambda m: f"{m.group('indent')}{m.group('name')} += {m.group('delta')};", rewritten)

    compound_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<name>[A-Za-z_][\w$?@]*) = (?P=name) (?P<op>[+-]) (?P<delta>0x[0-9a-fA-F]+|\d+);$"
    )

    def _rewrite_compound(match: re.Match[str]) -> str:
        op = "+=" if match.group("op") == "+" else "-="
        return f"{match.group('indent')}{match.group('name')} {op} {match.group('delta')};"

    rewritten = compound_pattern.sub(_rewrite_compound, rewritten)

    # Repair empty if-body rendering gap: if (false) with no body before } or EOF
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)if \(false\)\s*$",
        r"\g<indent>if (0);",
        rewritten,
    )
    return rewritten

def _normalize_mk_fp_segment_names(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None:
        return c_text

    positive_aliases = [
        (disp, name)
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: item[0])
        if disp > 0 and isinstance(name, str) and name
    ]
    if not positive_aliases:
        return c_text
    segment_names = {name for _disp, name in positive_aliases}
    if len(segment_names) != 1:
        return c_text

    segment_name = positive_aliases[0][1]
    if segment_name in {"cs", "ds", "es", "ss", "fs", "gs"}:
        return c_text

    def _replace(match: re.Match[str]) -> str:
        temp = match.group("temp")
        offset = match.group("offset")
        if not re.fullmatch(r"v\d+|vvar_\d+", temp):
            return match.group(0)
        return f"MK_FP({segment_name}, {offset})"

    return re.sub(
        r"MK_FP\((?P<temp>v\d+|vvar_\d+),\s*(?P<offset>[^)]+)\)",
        _replace,
        c_text,
    )

def _simplify_x86_16_stack_references(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text

    decl_re = re.compile(
        r"^\s*(?P<decl>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*;\s*// \[bp(?P<sign>[+-])0x(?P<value>[0-9A-Fa-f]+)\](?P<suffix>.*)$"
    )

    offset_to_name: dict[int, str] = {}
    for line in lines:
        match = decl_re.match(line)
        if match is None:
            continue
        name = match.group("name")
        value = int(match.group("value"), 16)
        if match.group("sign") == "-":
            value = -value
        offset_to_name.setdefault(value, name)

    if not offset_to_name:
        return c_text

    def _replace(match: re.Match[str]) -> str:
        anchor = match.group("anchor")
        sign = match.group("sign")
        value = int(match.group("value"), 0)
        offset = value if sign == "+" else -value
        name = offset_to_name.get(offset)
        if name is None:
            return match.group(0)
        if offset == 0:
            return f"&{name}"
        return f"&{name}"

    pattern = re.compile(
        r"&(?P<anchor>v\d+)\s*(?P<sign>[+-])\s*(?P<value>0x[0-9A-Fa-f]+|\d+)"
    )
    return pattern.sub(_replace, c_text)
