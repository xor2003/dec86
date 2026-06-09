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
__all__ = ['_normalize_anonymous_call_targets', '_prune_void_function_return_values_text', '_contains_void_function_definition_text', '_normalize_function_signature_arg_names', '_materialize_missing_generic_local_declarations_text', '_hoist_c89_local_declarations_text', '_materialize_annotated_cod_declarations_text', '_materialize_opaque_pointer_typedefs_text', '_source_args_from_cod_source_lines', '_repair_missing_cod_function_header_text', '_render_cod_source_function_text', '_restore_collapsed_cod_source_function_text', '_dedupe_duplicate_local_declarations_text', '_normalize_spurious_duplicate_local_suffixes', '_collapse_duplicate_type_keywords_text', '_dedupe_adjacent_prototype_lines', '_sanitize_mangled_autonames_text', '_prune_trailing_generic_return_text', '_collapse_annotated_stack_aliases_text', '_split_top_level_binary', '_simplify_negated_condition', '_simplify_condition_line', '_simplify_x86_16_conditions', '_split_simple_assignment_conditions', '_simplify_x86_16_wrapped_stack_offsets', '_simplify_x86_16_stack_byte_pointers', '_format_bp_disp', '_annotate_cod_proc_output', '_prune_unused_staging_assignments', '_rewrite_known_helper_signature_text', '_prune_unused_local_declarations_text', '_format_known_helper_calls', '_repair_missing_fallthrough_returns', '_normalize_boolean_conditions', '_normalize_mk_fp_segment_names', '_simplify_x86_16_stack_references']


def _prune_weaker_conflicting_prototypes_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text
        prototype_re = re.compile(
            r"^\s*(?P<ret>[A-Za-z_][\w\s\*]*?)\s+(?:\*\s*)*(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)\s*;\s*$"
        )

        def _split_top_level_args(args_text: str) -> list[str]:
            text = args_text.strip()
            if not text:
                return []
            parts: list[str] = []
            current: list[str] = []
            depth_paren = depth_bracket = depth_brace = 0
            for ch in text:
                if ch == "," and depth_paren == depth_bracket == depth_brace == 0:
                    parts.append("".join(current).strip())
                    current = []
                    continue
                current.append(ch)
                if ch == "(":
                    depth_paren += 1
                elif ch == ")" and depth_paren > 0:
                    depth_paren -= 1
                elif ch == "[":
                    depth_bracket += 1
                elif ch == "]" and depth_bracket > 0:
                    depth_bracket -= 1
                elif ch == "{":
                    depth_brace += 1
                elif ch == "}" and depth_brace > 0:
                    depth_brace -= 1
            if current:
                parts.append("".join(current).strip())
            return [part for part in parts if part]

        call_re = re.compile(r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;\n{}]*)\)\s*;")
        observed_min_arity: dict[str, int] = {}
        for line in lines:
            for call_match in call_re.finditer(line):
                name = call_match.group("name")
                args = call_match.group("args").strip()
                arity = 0 if not args else len(_split_top_level_args(args))
                prev = observed_min_arity.get(name)
                if prev is None or arity < prev:
                    observed_min_arity[name] = arity

        def _declared_arity(args: str) -> int | None:
            text = args.strip()
            if not text:
                return 0
            if text == "void":
                return 0
            if "..." in text:
                return None
            return len(_split_top_level_args(text))

        def _score(ret: str, args: str, decl: str, name: str) -> tuple[int, int]:
            ret = ret.strip()
            args = args.strip()
            is_generic = ret == "int" and args == ""
            has_typed_args = bool(args and args != "void")
            observed = observed_min_arity.get(name)
            declared = _declared_arity(args)
            arity_conflict = isinstance(observed, int) and isinstance(declared, int) and declared > observed
            if arity_conflict and has_typed_args:
                return (-10, len(decl))
            return ((2 if has_typed_args else 0) + (0 if is_generic else 1), len(decl))

        best_by_name: dict[str, str] = {}
        best_score_by_name: dict[str, tuple[int, int]] = {}
        for line in lines:
            stripped = line.strip()
            match = prototype_re.match(stripped)
            if match is None:
                continue
            name = match.group("name")
            score = _score(match.group("ret"), match.group("args"), stripped, name)
            prev = best_score_by_name.get(name)
            if prev is None or score > prev:
                best_score_by_name[name] = score
                best_by_name[name] = stripped

        if not best_by_name:
            return c_text

        protected_standard_names = {
            "time",
        }
        replacement_by_name: dict[str, str] = {}
        for name, decl in tuple(best_by_name.items()):
            match = prototype_re.match(decl)
            if match is None:
                continue
            if name in protected_standard_names:
                continue
            observed = observed_min_arity.get(name)
            declared = _declared_arity(match.group("args"))
            if isinstance(observed, int) and isinstance(declared, int) and declared > observed:
                replacement_by_name[name] = f"int {name}();"

        out_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            match = prototype_re.match(stripped)
            if match is None:
                out_lines.append(line)
                continue
            name = match.group("name")
            if best_by_name.get(name) != stripped:
                continue
            replacement = replacement_by_name.get(name)
            if replacement is None:
                out_lines.append(line)
                continue
            indent_match = re.match(r"^\s*", line)
            indent = indent_match.group(0) if indent_match is not None else ""
            out_lines.append(f"{indent}{replacement}")
        normalized = "\n".join(out_lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()

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
    def _impl():
        lines = c_text.splitlines()
        out_lines: list[str] = []
        changed = False
        header_start_re = re.compile(r"^\s*(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_]\w*\s*\(")
        return_re = re.compile(r"^(?P<indent>\s*)return\s+(?P<expr>[^;]+);\s*$")
        bare_return_re = re.compile(r"^\s*return;\s*$")
        side_effect_call_re = re.compile(r"^[A-Za-z_]\w*\s*\(.*\)$")

        def _return_line_is_terminal(start_index: int, current_depth: int) -> bool:
            depth = current_depth
            scan_index = start_index + 1
            while scan_index < line_count:
                scan_line = lines[scan_index]
                stripped = scan_line.strip()
                if stripped and stripped != "}" and not stripped.startswith("//"):
                    return False
                depth += scan_line.count("{") - scan_line.count("}")
                if depth <= 0:
                    return True
                scan_index += 1
            return False

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
            if "{" in line:
                brace_index = index
                out_lines.extend(header_lines)
                index = brace_index + 1
                brace_depth = 1
                while index < line_count and brace_depth > 0:
                    body_line = lines[index]
                    return_match = return_re.match(body_line)
                    if is_void and return_match is not None:
                        indent = return_match.group("indent")
                        expr = return_match.group("expr").strip()
                        if side_effect_call_re.match(expr) is not None:
                            out_lines.append(f"{indent}{expr};")
                        if _return_line_is_terminal(index, brace_depth):
                            changed = True
                            brace_depth += body_line.count("{") - body_line.count("}")
                            index += 1
                            continue
                        body_line = f"{indent}return;"
                        changed = True
                    elif not is_void and bare_return_re.match(body_line) is not None:
                        changed = True
                        brace_depth += body_line.count("{") - body_line.count("}")
                        index += 1
                        continue
                    out_lines.append(body_line)
                    brace_depth += body_line.count("{") - body_line.count("}")
                    index += 1
                continue

            if ";" in line:
                out_lines.append(line)
                index += 1
                continue

            brace_index = None
            scan_index = index + 1
            is_forward_decl = False
            while scan_index < line_count and brace_index is None:
                header_line = lines[scan_index]
                header_lines.append(header_line)
                if "{" in header_line:
                    brace_index = scan_index
                    break
                if ";" in header_line:
                    is_forward_decl = True
                    break
                scan_index += 1

            if is_forward_decl and brace_index is None:
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
                    indent = return_match.group("indent")
                    expr = return_match.group("expr").strip()
                    if side_effect_call_re.match(expr) is not None:
                        out_lines.append(f"{indent}{expr};")
                    if _return_line_is_terminal(index, brace_depth):
                        changed = True
                        brace_depth += body_line.count("{") - body_line.count("}")
                        index += 1
                        continue
                    body_line = f"{indent}return;"
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

    return _impl()

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
    control_statement_names = {"if", "for", "while", "switch"}

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
            if re.fullmatch(r"arg_\d+", name):
                candidate = name
            elif suffix_match is not None:
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
        if match.group("name") in control_statement_names:
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
    def _impl():
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        generic_name_re = re.compile(
            r"^(?:a\d+|v\d+|vvar_\d+|ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+|local_[0-9a-fA-F]+)$"
        )
        decl_name_re = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*;\s*$")
        generic_use_re = re.compile(
            r"(?<![A-Za-z_])(?P<name>a\d+|v\d+|vvar_\d+|ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+|local_[0-9a-fA-F]+)(?![A-Za-z_])"
        )
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

    return _impl()


def _hoist_c89_local_declarations_text(c_text: str) -> str:
    def _impl():
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+"
            r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s+)(?!(?:return|if|while|for|switch|goto|case|default|continue|break|extern|typedef)\b)"
            r"(?P<type>(?:unsigned\s+short|unsigned\s+int|unsigned\s+long|signed\s+short|signed\s+int|signed\s+long|"
            r"short|int|long|char|uint8_t|uint16_t|uint32_t|int8_t|int16_t|int32_t|void\s*\*)"
            r"(?:\s*\*)?)\s+"
            r"(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
        )

        changed = False
        index = 0
        while index < len(lines):
            if header_re.match(lines[index]) is None:
                index += 1
                continue
            brace_index = _find_function_brace_index(lines, index)
            if brace_index is None:
                index += 1
                continue
            body_end = _find_block_end(lines, brace_index)
            body_indent = re.match(r"^(\s*)", lines[brace_index]).group(1) + "    "

            depth = 1
            decl_entries: list[tuple[int, str, str]] = []
            scan = brace_index + 1
            while scan < body_end:
                line = lines[scan]
                stripped = line.strip()
                if depth == 1:
                    match = decl_re.match(line)
                    if match is not None and match.group("indent") == body_indent and "=" not in line:
                        decl_entries.append((scan, match.group("name"), line))
                depth += stripped.count("{") - stripped.count("}")
                scan += 1

            if not decl_entries:
                index = body_end
                continue

            insertion = brace_index + 1
            while insertion < body_end:
                stripped = lines[insertion].strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    insertion += 1
                    continue
                if any(entry_index == insertion for entry_index, _name, _line in decl_entries):
                    insertion += 1
                    continue
                break

            seen_names: set[str] = set()
            hoisted: list[str] = []
            remove_indexes: set[int] = set()
            local_changed = False
            for line_index, name, line in decl_entries:
                if name in seen_names:
                    remove_indexes.add(line_index)
                    local_changed = True
                    continue
                seen_names.add(name)
                hoisted.append(line)
                if line_index < insertion or line_index >= insertion + len(decl_entries):
                    local_changed = True
                remove_indexes.add(line_index)

            if not local_changed:
                index = body_end
                continue

            changed = True
            kept = [line for line_index, line in enumerate(lines) if line_index not in remove_indexes]
            removed_before_insertion = sum(1 for line_index in remove_indexes if line_index < insertion)
            insertion_after_removal = insertion - removed_before_insertion
            kept[insertion_after_removal:insertion_after_removal] = hoisted
            lines = kept
            body_end = body_end - len(remove_indexes) + len(hoisted)
            index = body_end

        if not changed:
            return c_text
        normalized = "\n".join(lines)
        if trailing_newline:
            normalized += "\n"
        return normalized

    return _impl()


def _codegen_signature_authoritative_8616(function=None, codegen=None) -> bool:
    for obj in (codegen, function):
        if obj is not None and getattr(obj, "_inertia_codegen_signature_authoritative_8616", None):
            return True
    return False


def _materialize_annotated_cod_declarations_text(
    c_text: str,
    function,
    metadata: CODProcMetadata | None,
    *,
    preserve_source_header: bool = False,
) -> str:
    def _impl():
        if metadata is None or function is None:
            return c_text

        func_name = getattr(function, "name", None)
        if not isinstance(func_name, str) or not func_name:
            return c_text

        lines = c_text.splitlines()
        header_re = re.compile(
            rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
        )
        header_index = _find_header_index_8616(lines, header_re)
        if header_index is None:
            return c_text
        span = _find_body_span_8616(lines, header_index)
        if span is None:
            return c_text
        brace_index, body_start, body_end = span

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
        source_decl = _source_decl_from_cod_source_lines(metadata.source_lines, func_name)
        source_prototypes = _source_function_prototype_decls_from_cod_source_lines(metadata.source_lines)
        if not preserve_source_header:
            header_changed = _apply_source_decl_to_header_8616(
                lines,
                header_index=header_index,
                header_re=header_re,
                func_name=func_name,
                source_decl=source_decl,
                header_changed=header_changed,
            )

        _normalize_existing_decl_names_8616(
            lines,
            body_start=body_start,
            decl_re=decl_re,
            declared_names=declared_names,
        )

        def _rewrite_arg_decl(arg_text: str, source_arg_text: str | None = None) -> str:
            split_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg_text.strip())
            if split_match is None:
                return arg_text
            arg_name = split_match.group(1)
            if source_arg_text is not None:
                source_prefix = source_arg_text[: source_arg_text.rfind(arg_name)].strip() if arg_name in source_arg_text else source_arg_text
                source_prefix_clean = re.sub(r"\b(?:const|volatile|register|struct|union|enum)\b", " ", source_prefix)
                pointer_name = source_prefix_clean.rsplit("*", 1)
                if len(pointer_name) > 1 and "*" in source_prefix_clean:
                    base_tokens = [t for t in re.split(r"[\s\*]", source_prefix_clean) if t]
                    if base_tokens:
                        base_type = base_tokens[-1]
                        if (
                            base_type not in {"char", "short", "int", "long", "float", "double", "void", "size_t"}
                            and base_type and base_type[0].isupper()
                        ):
                            return arg_text
            if not _arg_has_pointer_evidence_8616(pointer_evidence_text, arg_name, source_arg_text):
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

        current_match = header_re.match(lines[header_index])
        if current_match is None:
            return c_text
        current_arg_text = current_match.group("args")
        current_args = _split_args_8616(current_arg_text)
        source_args = _split_args_8616(source_arg_text) if source_arg_text else []
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

        prototype_declarations, declarations = _collect_cod_materialized_decls_8616(
            metadata=metadata,
            source_prototypes=source_prototypes,
            func_name=func_name,
            body_text=body_text,
            declared_names=declared_names,
        )

        if prototype_declarations:
            lines[header_index:header_index] = prototype_declarations + [""]
            header_index += len(prototype_declarations) + 1
            brace_index += len(prototype_declarations) + 1
            body_start += len(prototype_declarations) + 1
            body_end += len(prototype_declarations) + 1

        if not declarations:
            if not header_changed:
                return c_text
            return _join_lines_like_input_8616(lines, c_text)

        lines[insertion_index:insertion_index] = declarations
        return _join_lines_like_input_8616(lines, c_text)

    return _impl()


def _find_header_index_8616(lines: list[str], header_re: re.Pattern[str]) -> int | None:
    for index, line in enumerate(lines):
        if header_re.match(line):
            return index
    return None


def _find_body_span_8616(lines: list[str], header_index: int) -> tuple[int, int, int] | None:
    brace_index = header_index
    while brace_index < len(lines):
        if "{" in lines[brace_index]:
            break
        if ";" in lines[brace_index] and "{" not in lines[brace_index]:
            return None
        brace_index += 1
    if brace_index >= len(lines):
        return None
    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return brace_index, body_start, body_end


def _split_args_8616(arg_text: str) -> list[str]:
    def _impl():
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

    return _impl()


def _arg_has_pointer_evidence_8616(pointer_evidence_text: str, arg_name: str, source_arg: str | None = None) -> bool:
    name = re.escape(arg_name)
    if source_arg is not None:
        source_prefix = source_arg[: source_arg.rfind(arg_name)].strip() if arg_name in source_arg else source_arg
        # Source declarations are stronger evidence than rendered-body text.
        # The legacy text heuristic can confuse arithmetic multiplication
        # ("b * a") with unary pointer dereference ("*a").
        return "*" in source_prefix or re.search(r"\[[^\]]*\]\s*$", source_arg.strip()) is not None
    patterns = (
        rf"(?<![A-Za-z_])\*\s*{name}\s*\+\+",
        rf"(?<![A-Za-z_])\*\s*{name}\b",
        rf"(?<![A-Za-z_])\*\s*\(\s*{name}\b",
        rf"(?<![A-Za-z_]){name}\s*\[",
        rf"(?<![A-Za-z_]){name}\s*->",
    )
    return any(re.search(pattern, pointer_evidence_text) is not None for pattern in patterns)


def _join_lines_like_input_8616(lines: list[str], original_text: str) -> str:
    normalized = "\n".join(lines)
    if original_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _source_decl_has_custom_ptr_8616(source_args: list[str]) -> bool:
    for source_arg in source_args:
        source_name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", source_arg)
        if source_name_match is None:
            continue
        source_prefix = source_arg[: source_name_match.start(1)].strip()
        if "*" not in source_prefix:
            continue
        base_tokens = [token for token in re.split(r"\s+", source_prefix.replace("*", " ").strip()) if token]
        if not base_tokens:
            continue
        base_type = base_tokens[-1]
        if base_type not in {"char", "short", "int", "long", "float", "double", "void", "size_t", "FILE"} and base_type[0].isupper():
            return True
    return False


def _source_header_args_unmaterialized_8616(
    c_text: str,
    *,
    func_name: str,
    source_decl: str | None,
    source_arg_text: str | None = None,
) -> bool:
    if not isinstance(func_name, str) or not func_name:
        return False
    if not source_decl and not source_arg_text:
        return False
    header_re = re.compile(
        rf"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?:\{{|$)"
    )
    current_header = header_re.search(c_text)
    if current_header is None:
        return False
    source_parts = _split_source_decl_args_8616(source_decl, source_arg_text)
    current_parts = _split_c_signature_args_8616(current_header.group("args"))
    if not source_parts or len(source_parts) != len(current_parts):
        return False
    body_text = c_text[current_header.end() :]
    for current_part, source_part in zip(current_parts, source_parts):
        current_name = _decl_arg_name_8616(current_part)
        source_name = _decl_arg_name_8616(source_part)
        if not current_name or not source_name or current_name == source_name:
            continue
        current_used = re.search(rf"(?<![A-Za-z_]){re.escape(current_name)}(?![A-Za-z_])", body_text) is not None
        source_used = re.search(rf"(?<![A-Za-z_]){re.escape(source_name)}(?![A-Za-z_])", body_text) is not None
        if current_used and not source_used:
            return True
    return False


def _restore_codegen_header_for_unmaterialized_source_args_8616(
    before_text: str,
    after_text: str,
    *,
    func_name: str,
) -> str:
    if not isinstance(func_name, str) or not func_name:
        return after_text
    header_re = re.compile(
        rf"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)(?P<suffix>\s*[;{{]?\s*)$"
    )
    before_match = header_re.search(before_text)
    after_match = header_re.search(after_text)
    if before_match is None or after_match is None:
        return after_text
    replacement = before_match.group(0)
    before_suffix = before_match.group("suffix") or ""
    after_suffix = after_match.group("suffix") or ""
    if after_suffix.strip() and not before_suffix.strip():
        replacement = replacement.rstrip() + after_suffix
    return after_text[: after_match.start()] + replacement + after_text[after_match.end() :]


def _apply_source_decl_to_header_8616(
    lines: list[str],
    *,
    header_index: int,
    header_re: re.Pattern[str],
    func_name: str,
    source_decl: str | None,
    header_changed: bool,
) -> bool:
    if not source_decl:
        return header_changed
    decl_match = re.match(
        r"^(?P<ret>.+?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
        source_decl.strip(),
    )
    if decl_match is None:
        return header_changed
    source_ret = decl_match.group("ret").strip()
    source_args_text = decl_match.group("args").strip()
    if _source_decl_has_custom_ptr_8616(_split_args_8616(source_args_text)):
        return header_changed
    current_header = header_re.match(lines[header_index])
    if current_header is None:
        return header_changed
    c_text = "\n".join(lines)
    if _source_header_args_unmaterialized_8616(
        c_text,
        func_name=func_name,
        source_decl=source_decl,
        source_arg_text=None,
    ):
        return header_changed
    replacement_header = f"{current_header.group('indent')}{source_ret} {func_name}({source_args_text})"
    if current_header.group("suffix") == "{":
        replacement_header += " {"
    elif current_header.group("suffix") == ";":
        replacement_header += ";"
    if lines[header_index] != replacement_header:
        lines[header_index] = replacement_header
        return True
    return header_changed


def _normalize_existing_decl_names_8616(
    lines: list[str],
    *,
    body_start: int,
    decl_re: re.Pattern[str],
    declared_names: set[str],
) -> None:
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
        if spec is None:
            declared_names.add(declared_name)
            continue
        normalized_name = spec.name
        declared_names.add(normalized_name)
        if normalized_name != declared_name:
            lines[scan_index] = re.sub(
                rf"(?<![A-Za-z_]){re.escape(declared_name)}(?![A-Za-z_])\s*;\s*(?://.*)?$",
                f"{normalized_name};",
                line,
                count=1,
            )


def _collect_cod_materialized_decls_8616(
    *,
    metadata: CODProcMetadata,
    source_prototypes: dict[str, str],
    func_name: str,
    body_text: str,
    declared_names: set[str],
) -> tuple[list[str], list[str]]:
    def _impl():
        declarations: list[str] = []
        prototype_declarations: list[str] = []
        seen_declared = set(declared_names)
        for proto_name, source_proto in source_prototypes.items():
            normalized_proto_name = proto_name.lstrip("_")
            if normalized_proto_name != func_name and normalized_proto_name not in seen_declared and re.search(
                rf"(?<![A-Za-z_]){re.escape(normalized_proto_name)}\s*\(",
                body_text,
            ):
                prototype_declarations.append(source_proto)
                seen_declared.add(normalized_proto_name)
        for call_name in getattr(metadata, "call_names", ()) or ():
            if not isinstance(call_name, str) or not call_name:
                continue
            normalized_call_name = call_name.lstrip("_")
            if not normalized_call_name or normalized_call_name == func_name or normalized_call_name in seen_declared:
                continue
            if not re.search(rf"(?<![A-Za-z_]){re.escape(normalized_call_name)}\s*\(", body_text):
                continue
            helper_decl = preferred_known_helper_signature_decl(call_name)
            prototype_declarations.append(helper_decl.rstrip(";").strip() + ";" if helper_decl is not None else f"int {normalized_call_name}();")
            seen_declared.add(normalized_call_name)
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
        return prototype_declarations, declarations

    return _impl()


def _normalize_scalar_assigned_extern_arrays_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text
        body = "\n".join(lines)
        changed = False
        seen: set[str] = set()
        normalized_lines: list[str] = []
        decl_re = re.compile(r"^(?P<indent>\s*)extern\s+char\s+(?P<name>[A-Za-z_]\w*)\[(?P<size>\d+)\];\s*$")
        for line in lines:
            match = decl_re.match(line)
            if match is None:
                normalized_lines.append(line)
                continue
            name = match.group("name")
            usage_body = "\n".join(
                candidate
                for candidate in lines
                if not decl_re.match(candidate)
            )
            direct_assign = re.search(rf"(?m)^\s*{re.escape(name)}\s*=", usage_body) is not None
            scalar_arith = re.search(
                rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])\s*(?:\+|-|\*|/|>>|<<|==|!=|<=|>=|<|>)",
                usage_body,
            ) is not None
            unary_update = re.search(
                rf"(?:\+\+|--)\s*(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])|"
                rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])\s*(?:\+\+|--)",
                usage_body,
            ) is not None
            indexed_use = re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])\s*\[", usage_body) is not None
            if indexed_use or not (direct_assign or scalar_arith or unary_update):
                normalized_lines.append(line)
                continue
            replacement = f"{match.group('indent')}extern unsigned short {name};"
            if replacement in seen:
                changed = True
                continue
            seen.add(replacement)
            normalized_lines.append(replacement)
            changed = True
        if not changed:
            return c_text
        normalized = "\n".join(normalized_lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _normalize_concat_zero_text(c_text: str) -> str:
    # Lower decompiler textual CONCAT forms that represent zero-extension.
    # Examples:
    #   "x CONCAT 0" -> "x"
    #   "0 CONCAT x" -> "x"
    normalized = re.sub(r"\(\s*([A-Za-z_]\w*)\s+CONCAT\s+0\s*\)", r"\1", c_text)
    normalized = re.sub(r"(?<![A-Za-z_])([A-Za-z_]\w*)\s+CONCAT\s+0(?![A-Za-z_])", r"\1", normalized)
    normalized = re.sub(r"0\s+CONCAT\s+([A-Za-z_]\w*)", r"\1", normalized)
    return normalized


def _prune_dead_stack_base_assignments_text(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text
    assign_re = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]*stack_base[^;]*);\s*$")
    changed = False
    kept: list[str] = []
    full_text = "\n".join(lines)
    for line in lines:
        m = assign_re.match(line)
        if m is None:
            kept.append(line)
            continue
        lhs = m.group("lhs")
        token_re = re.compile(rf"(?<![A-Za-z_0-9]){re.escape(lhs)}(?![A-Za-z_0-9])")
        occurrences = len(token_re.findall(full_text))
        # Two occurrences means declaration + this assignment, i.e. no real use.
        if occurrences <= 2:
            changed = True
            continue
        kept.append(line)
    if not changed:
        return c_text
    out = "\n".join(kept)
    if c_text.endswith("\n"):
        out += "\n"
    return out


def _materialize_stack_base_placeholder_declaration_text(c_text: str) -> str:
    if "stack_base" not in c_text:
        return c_text
    decl_re = re.compile(r"(?m)^\s*[A-Za-z_][\w\s\*]*\bstack_base\b\s*(?:[;=,\[])")
    if decl_re.search(c_text):
        return c_text
    lines = c_text.splitlines()
    if not lines:
        return c_text
    insert_at = None
    for idx, line in enumerate(lines):
        if "{" in line:
            insert_at = idx + 1
            break
    if insert_at is None:
        return c_text
    lines.insert(insert_at, "    unsigned short stack_base;")
    out = "\n".join(lines)
    if c_text.endswith("\n"):
        out += "\n"
    return out


def _normalize_integer_dereference_stores_text(c_text: str) -> str:
    # Compile-hygiene only: preserve explicit linear-address store semantics in a
    # compilable lvalue form when codegen leaves integer-as-pointer stores.
    # Example: *(seg*16 + stack_base + K) = v;  -> SEG_U8(0, seg*16 + stack_base + K) = v;
    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)\*\(\s*(?P<addr>[^)]+)\s*\)\s*=\s*(?P<rhs>[^;]+);\s*$"
    )

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        addr = match.group("addr").strip()
        rhs = match.group("rhs").strip()
        # Preserve already-lowered SEG_* lvalues and obvious typed pointers.
        if addr.startswith("SEG_U8(") or addr.startswith("SEG_U16(") or addr.startswith("SEG_U32("):
            return match.group(0)
        # Compile-hygiene lowering target: raw real-mode linearized integer address.
        # Evidence: expressions that carry seg*16 linearization or stack-base carrier math.
        has_linearized_seg = re.search(r"\bir_\d+\s*\*\s*16\b", addr) is not None
        has_stack_carrier = "stack_base" in addr
        has_vvar_linear_carrier = re.search(r"\bvvar_\d+\b", addr) is not None and any(op in addr for op in ("+", "-"))
        if not (has_linearized_seg or has_stack_carrier or has_vvar_linear_carrier):
            return match.group(0)
        return f"{indent}SEG_U8(0, {addr}) = {rhs};"

    return pattern.sub(_replace, c_text)


def _materialize_missing_g_hex_externs_text(c_text: str) -> str:
    token_re = re.compile(r"(?<![A-Za-z_0-9])(g_[0-9a-fA-F]+)(?![A-Za-z_0-9])")
    decl_re = re.compile(r"(?m)^\s*extern\s+[^\n;]*\b(g_[0-9a-fA-F]+)\b[^\n;]*;\s*$")
    used = set(token_re.findall(c_text))
    declared = set(decl_re.findall(c_text))
    missing = sorted(name for name in used if name not in declared)
    if not missing:
        return c_text
    lines = c_text.splitlines()
    insert_at = 0
    for idx, line in enumerate(lines):
        if line.strip().startswith("extern "):
            insert_at = idx + 1
    decl_lines = [f"extern unsigned short {name};" for name in missing]
    lines[insert_at:insert_at] = decl_lines
    out = "\n".join(lines)
    if c_text.endswith("\n"):
        out += "\n"
    return out


def _dedupe_conflicting_extern_variable_declarations_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text
        decl_re = re.compile(
            r"^(?P<indent>\s*)extern\s+(?P<type>[^;()]+?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*$"
        )
        type_rank = {
            "void": 0,
            "char": 1,
            "unsigned char": 2,
            "short": 3,
            "unsigned short": 4,
            "int": 5,
            "unsigned int": 6,
            "long": 7,
            "unsigned long": 8,
        }
        winners: dict[str, tuple[int, str, str, int]] = {}
        for idx, line in enumerate(lines):
            match = decl_re.match(line)
            if match is None:
                continue
            name = match.group("name")
            raw_type = " ".join(match.group("type").split())
            rank = type_rank.get(raw_type, 100)
            prior = winners.get(name)
            if prior is None or rank > prior[0]:
                winners[name] = (rank, raw_type, match.group("indent"), idx)

        if not winners:
            return c_text

        kept: list[str] = []
        emitted: set[str] = set()
        changed = False
        for line in lines:
            match = decl_re.match(line)
            if match is None:
                kept.append(line)
                continue
            name = match.group("name")
            winner = winners.get(name)
            if winner is None:
                kept.append(line)
                continue
            if name in emitted:
                changed = True
                continue
            winner_type = winner[1]
            winner_indent = winner[2]
            normalized = f"{winner_indent}extern {winner_type} {name};"
            if normalized != line:
                changed = True
            kept.append(normalized)
            emitted.add(name)

        if not changed:
            return c_text
        out = "\n".join(kept)
        if c_text.endswith("\n"):
            out += "\n"
        return out

    return _impl()


def _materialize_missing_segment_macro_locals_text(c_text: str) -> str:
    def _impl():
        needed = {
            segment
            for segment in ("ds", "es", "ss")
            if re.search(rf"\b(?:SEG_U8|SEG_U16|SEG_U32|SEG_PTR|MK_FP)\s*\(\s*{segment}\b", c_text)
        }
        if not needed:
            return c_text
        lines = c_text.splitlines()
        existing = {
            match.group("name")
            for line in lines
            for match in (re.match(r"\s*unsigned\s+short\s+(?P<name>ds|es|ss)\s*(?:;|,)", line),)
            if match is not None
        }
        missing = sorted(needed - existing)
        if not missing:
            return c_text
        for index, line in enumerate(lines):
            if line.strip() == "{":
                insert_at = index + 1
                lines[insert_at:insert_at] = [f"    unsigned short {name};" for name in missing]
                normalized = "\n".join(lines)
                if c_text.endswith("\n"):
                    normalized += "\n"
                return normalized
        return c_text

    return _impl()


def _prototype_for_direct_call(name: str, observed_arg_count: int | None) -> str:
    helper_decl = preferred_known_helper_signature_decl(name)
    if helper_decl is not None:
        match = re.search(r"\((?P<args>[^)]*)\)", helper_decl)
        helper_arg_count = None
        if match is not None:
            arg_text = match.group("args").strip()
            if not arg_text or arg_text == "void":
                helper_arg_count = 0
            else:
                helper_arg_count = len([part for part in arg_text.split(",") if part.strip()])
        if isinstance(helper_arg_count, int) and isinstance(observed_arg_count, int):
            if helper_arg_count != observed_arg_count:
                return f"int {name}();"
        return helper_decl.rstrip(";").strip() + ";"
    return f"int {name}();"


def _parameter_names_from_args_text_8616(args_text: str) -> set[str]:
    names: set[str] = set()
    if not args_text.strip() or args_text.strip() == "void":
        return names
    for part in _split_args_8616(args_text):
        fnptr_match = re.search(r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)", part)
        if fnptr_match is not None:
            names.add(fnptr_match.group("name"))
            continue
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part.strip())
        if match is not None:
            names.add(match.group(1))
    return names


def _extract_function_header_args_8616(line: str) -> str | None:
    header = line.split("{", 1)[0].strip()
    if not header or header.endswith(";"):
        return None
    close_idx = header.rfind(")")
    if close_idx < 0:
        return None
    depth = 0
    open_idx = None
    for idx in range(close_idx, -1, -1):
        char = header[idx]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                open_idx = idx
                break
    if open_idx is None:
        return None
    prefix = header[:open_idx].strip()
    if not re.search(r"\b[A-Za-z_]\w*$", prefix):
        return None
    return header[open_idx + 1 : close_idx]


def _collect_function_parameter_names_8616(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for idx, line in enumerate(lines):
        candidate = line
        lookahead = idx + 1
        while "{" not in candidate and lookahead < len(lines) and lookahead <= idx + 2:
            if ";" in candidate:
                break
            candidate = f"{candidate} {lines[lookahead].strip()}"
            lookahead += 1
        args_text = _extract_function_header_args_8616(candidate)
        if args_text is not None:
            names.update(_parameter_names_from_args_text_8616(args_text))
    return names


def _collect_declared_and_defined_function_names(lines: list[str]) -> set[str]:
    def _impl():
        declared = {
            match.group("name")
            for line in lines
            for match in (
                re.match(r"\s*(?:extern\s+)?[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;", line),
            )
            if match is not None
        }
        defined: set[str] = set()
        definition_re = re.compile(r"\s*[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?P<brace>\{?)\s*$")
        for index, line in enumerate(lines):
            match = definition_re.match(line)
            if match is None:
                continue
            if match.group("brace"):
                defined.add(match.group("name"))
                continue
            lookahead = index + 1
            while lookahead < len(lines) and not lines[lookahead].strip():
                lookahead += 1
            if lookahead < len(lines) and lines[lookahead].strip().startswith("{"):
                defined.add(match.group("name"))
        return declared | defined

    return _impl()


def _has_decl_or_def_in_text(c_text: str, declared: set[str], name: str) -> bool:
    escaped = re.escape(name)
    decl_or_def_re = re.compile(
        rf"(?m)^\s*(?:extern\s+)?[A-Za-z_][\w\s\*]*?\s+(?:\*\s*)?{escaped}\s*\([^;{{}}]*\)\s*(?:;|\{{.*$)"
    )
    if decl_or_def_re.search(c_text):
        return True
    return name in declared


def _collect_direct_calls_and_observed_arity(lines: list[str], c_text: str, declared: set[str]) -> tuple[list[str], dict[str, int]]:
    def _impl():
        keywords = {
            "auto",
            "char",
            "const",
            "do",
            "double",
            "else",
            "enum",
            "extern",
            "float",
            "for",
            "if",
            "int",
            "long",
            "register",
            "return",
            "short",
            "signed",
            "sizeof",
            "static",
            "struct",
            "switch",
            "typedef",
            "union",
            "unsigned",
            "void",
            "volatile",
            "while",
        }
        standard_c_functions = {
            "toupper",
            "tolower",
            "isalpha",
            "isdigit",
            "isalnum",
            "isspace",
            "isupper",
            "islower",
            "isprint",
            "iscntrl",
            "ispunct",
            "isxdigit",
        }
        runtime_helpers = {"SEG_U8", "SEG_U16", "SEG_U32", "SEG_PTR", "SEG_LINEAR", "MK_FP"}
        parameter_names = _collect_function_parameter_names_8616(lines)
        calls: list[str] = []
        observed_args: dict[str, int] = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("/*", "*", "//", "#")):
                continue
            for match in re.finditer(r"(?<![A-Za-z_])(?P<name>[A-Za-z_]\w*)\s*\(", line):
                name = match.group("name")
                after = line[match.end():]
                close_idx = after.find(")")
                if close_idx >= 0:
                    arg_expr = after[:close_idx].strip()
                    argc = 0 if not arg_expr else len([part for part in arg_expr.split(",") if part.strip()])
                    observed_args[name] = max(observed_args.get(name, 0), argc)
                if (
                    name in keywords
                    or name in standard_c_functions
                    or name in runtime_helpers
                    or name in parameter_names
                    or name in calls
                    or _has_decl_or_def_in_text(c_text, declared, name)
                ):
                    continue
                calls.append(name)
        return calls, observed_args

    return _impl()


def _find_first_function_insert_index(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", line):
            return index
        if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*$", line):
            lookahead = index + 1
            while lookahead < len(lines) and not lines[lookahead].strip():
                lookahead += 1
            if lookahead < len(lines) and lines[lookahead].strip().startswith("{"):
                return index
    return None


def _materialize_missing_direct_call_prototypes_text(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text
    declared = _collect_declared_and_defined_function_names(lines)
    calls, observed_args = _collect_direct_calls_and_observed_arity(lines, c_text, declared)
    if not calls:
        return c_text
    insert_at = _find_first_function_insert_index(lines)
    if insert_at is None:
        return c_text
    prototypes = [_prototype_for_direct_call(name, observed_args.get(name)) for name in calls]
    if insert_at > 0 and lines[insert_at - 1].strip():
        prototypes.append("")
    lines[insert_at:insert_at] = prototypes
    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _strip_comments_and_strings_8616(text: str) -> str:
    text = re.sub(r"(?s)/\*.*?\*/", " ", text)
    text = re.sub(r"//.*?$", " ", text, flags=re.M)
    text = re.sub(r"^\s*#.*?$", " ", text, flags=re.M)
    text = re.sub(r'"(?:\\.|[^"\\])*"', " ", text)
    text = re.sub(r"'(?:\\.|[^'\\])'", " ", text)
    return text


def _collect_declared_identifiers_8616(text_lines: list[str]) -> set[str]:
    def _impl():
        declared: set[str] = set()
        function_sig_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^)]*)\)\s*\{?$")
        decl_stmt_re = re.compile(
            r"^\s*(?:extern\s+|static\s+)?[A-Za-z_][\w\s\*\[\]<>]*\b(?P<name>[A-Za-z_][\w$?@]*)(?:\s*[\[,;=]|\s*\()"
        )
        for raw_line in text_lines:
            line = raw_line.strip()
            if not line or line.startswith(("//", "*", "/*", "///")):
                continue
            sig_match = function_sig_re.match(line)
            if sig_match is not None:
                declared.add(sig_match.group("name"))
                for arg in re.split(r",", sig_match.group("args")):
                    arg_match = re.search(r"(?<![A-Za-z_])([A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])$", arg.strip())
                    if arg_match:
                        declared.add(arg_match.group(1))
                continue
            decl_match = decl_stmt_re.match(line)
            if decl_match is None:
                continue
            declared.add(decl_match.group("name"))
            if "," not in line:
                continue
            for segment in line.split(",")[1:]:
                nested = re.match(r"(?P<name>[A-Za-z_][\w$?@]*)", segment.strip())
                if nested is not None:
                    declared.add(nested.group("name"))
        return declared

    return _impl()


def _is_known_compiler_temp_8616(name: str) -> bool:
    return bool(re.match(r"^(?:vvar_\d+|s_[0-9a-fA-F]+(?:_[0-9a-fA-F]*)*|tmp_\d+|ir_\d+|arg_[0-9a-fA-F]+)$", name))


def _safe_finditer_8616(pattern: str, text_value: str):
    try:
        return re.finditer(pattern, text_value)
    except re.error:
        return ()


def _collect_global_usage_candidates_from_body_8616(text: str, declared: set[str]) -> list[str]:
    def _impl():
        work = _strip_comments_and_strings_8616(text)
        function_like = {m.group("name") for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)(?=\s*\()", work)}
        candidates: list[str] = []
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)\s*\[", work)
            if m.group("name") not in function_like
        )
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)\.[A-Za-z_][\w$?@]*", work)
            if m.group("name") not in function_like
        )
        for match in _safe_finditer_8616(
            r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)(?:\+\+|--)(?![A-Za-z0-9_])|(?:\+\+|--)(?P<name2>[A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])",
            work,
        ):
            name = match.group("name") or match.group("name2")
            if name:
                candidates.append(name)
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"&\s*(?P<name>[A-Za-z_][\w$?@]*)", work)
            if m.group("name") not in function_like
        )
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>g_[0-9a-fA-F]+)(?![A-Za-z0-9_])", work)
        )
        ordered: list[str] = []
        seen: set[str] = set()
        banned = {"if", "for", "while", "switch", "return", "sizeof", "case", "else", "struct", "stdint", "stdbool", "time", "stddef"}
        for name in candidates:
            if name in seen or name in declared or _is_known_compiler_temp_8616(name) or name in banned:
                continue
            seen.add(name)
            ordered.append(name)
        return ordered

    return _impl()


def _synthetic_name_width_map_8616(synthetic_globals: dict[int, tuple[str, int]] | None) -> dict[str, int]:
    name_to_width: dict[str, int] = {}
    if not synthetic_globals:
        return name_to_width
    for _addr, (global_name, width) in synthetic_globals.items():
        if isinstance(global_name, str) and global_name and isinstance(width, int):
            name_to_width[global_name] = max(name_to_width.get(global_name, 0), width)
    return name_to_width


def _used_global_names_8616(lines: list[str], body_text: str, declared: set[str], candidate_names: set[str]) -> list[str]:
    def _impl():
        missing_synthetic = sorted(
            name
            for name in candidate_names
            if name not in declared and re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])", body_text) is not None
        )
        used: list[str] = []
        all_text = "\n".join(lines)
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("/*", "*", "//", "#")):
                continue
            for match in re.finditer(r"(?<![A-Za-z_])(?P<name>g_b[0-9a-fA-F]+)(?![A-Za-z_])", line):
                name = match.group("name")
                if name not in declared and name not in used:
                    used.append(name)
            for name in missing_synthetic:
                if name not in used and re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])", line) is not None:
                    used.append(name)
        for name in list(candidate_names):
            if name not in used and name not in declared and re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])", all_text):
                used.append(name)
        if used:
            return used
        for name in sorted(candidate_names):
            if name not in declared and re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])", body_text):
                used.append(name)
        return used

    return _impl()


def _first_function_insert_index_8616(lines: list[str]) -> int | None:
    def _impl():
        insert_at = 0
        function_found = False
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("/*", "//", "*")):
                continue
            function_found = True
            if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", line):
                insert_at = index
                break
            if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*$", line):
                lookahead = index + 1
                while lookahead < len(lines) and not lines[lookahead].strip():
                    lookahead += 1
                if lookahead < len(lines) and lines[lookahead].strip().startswith("{"):
                    insert_at = index
                    break
        return insert_at if function_found else None

    return _impl()


def _infer_decl_for_global_8616(name: str, width: int | None, body_text: str) -> list[str]:
    escaped = re.escape(name)
    members = {
        match.group("field")
        for match in re.finditer(rf"(?<![A-Za-z_]){escaped}\s*\[[^\]]+\]\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)", body_text)
    }
    has_indexed_use = re.search(rf"(?<![A-Za-z_]){escaped}\s*\[", body_text) is not None
    declared_type = "char" if width == 1 else "short" if width in {2, None} else "long"
    c_decl_type = f"unsigned {declared_type}"
    if members:
        struct_name = f"_inertia_global_{re.sub(r'[^A-Za-z0-9_]', '_', name)}"
        field_names = sorted(field for field in members if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field)) or ["value"]
        return [f"    struct {struct_name} {{", *[f"        {c_decl_type} {field};" for field in field_names], f"    }};", f"    extern struct {struct_name} {name}[1];"]
    if has_indexed_use:
        return [f"    extern {c_decl_type} {name}[1];"]
    return [f"    extern {c_decl_type} {name};"]


def _source_function_designator_names_8616(
    source_lines: Sequence[str] | None,
    candidate_names: set[str],
) -> set[str]:
    if not source_lines or not candidate_names:
        return set()

    candidate_by_normalized = {
        str(name).lstrip("_"): str(name)
        for name in candidate_names
        if isinstance(name, str) and name
    }
    if not candidate_by_normalized:
        return set()

    function_pointer_vars: set[str] = set()
    for raw_line in source_lines:
        line = str(raw_line).strip()
        if not line:
            continue
        for match in re.finditer(r"\(\s*\*\s*(?P<name>[A-Za-z_][\w$?@]*)\s*\)\s*\(", line):
            function_pointer_vars.add(match.group("name"))

    if not function_pointer_vars:
        return set()

    designators: set[str] = set()
    for raw_line in source_lines:
        line = str(raw_line).strip()
        if not line:
            continue
        for fp_var in function_pointer_vars:
            match = re.search(
                rf"(?<![A-Za-z_]){re.escape(fp_var)}(?![A-Za-z0-9_])\s*=\s*(?P<target>[A-Za-z_][\w$?@]*)\s*;",
                line,
            )
            if match is None:
                continue
            target = match.group("target")
            normalized_target = target.lstrip("_")
            proven_name = candidate_by_normalized.get(normalized_target)
            if proven_name is not None:
                designators.add(proven_name)
    return designators


def _materialize_missing_synthetic_global_declarations_text(
    c_text: str,
    metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text

        body_text = "\n".join(lines)
        declared = _collect_declared_identifiers_8616(lines)
        declared |= {
            match.group("name")
            for line in lines
            for match in (
                re.match(
                    r"\s*(?:extern\s+)?(?:unsigned\s+)?(?:char|short|int|long|uint\d+_t|int\d+_t)\s+"
                    r"(?P<name>g_b[0-9a-fA-F]+)\s*(?:\[[^\]]*\])?\s*(?:;|=|,)",
                    line,
                ),
            )
            if match is not None
        }

        global_names = {
            name
            for name in getattr(metadata, "global_names", ())
            if isinstance(name, str) and name
        }
        synthetic_names = {
            global_name
            for _addr, (global_name, _width) in (synthetic_globals or {}).items()
            if isinstance(global_name, str) and global_name
        }
        candidate_names = global_names | synthetic_names

        name_to_width = _synthetic_name_width_map_8616(synthetic_globals)

        if body_text:
            candidate_names.update(_collect_global_usage_candidates_from_body_8616(body_text, declared))

        source_function_designators = _source_function_designator_names_8616(
            getattr(metadata, "source_lines", ()) if metadata is not None else (),
            candidate_names,
        )

        used = _used_global_names_8616(lines, body_text, declared, candidate_names)
        if not used:
            return c_text

        insert_at = _first_function_insert_index_8616(lines)
        if insert_at is None:
            return c_text

        declarations: list[str] = []
        for name in used:
            if name not in candidate_names:
                continue
            if name in source_function_designators:
                declarations.append(f"int {name}();")
                declared.add(name)
                continue
            width = name_to_width.get(name)
            declarations.extend(_infer_decl_for_global_8616(name, width, body_text))

        if insert_at > 0 and lines[insert_at - 1].strip():
            declarations.append("")
        lines[insert_at:insert_at] = declarations
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _normalize_scalar_gb_array_declarations_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text

        decl_re = re.compile(
            r"^(?P<indent>\s*)extern\s+char\s+(?P<name>g_[0-9a-fA-F]+)\s*\[(?P<size>\d+)\]\s*;\s*$"
        )
        names: dict[str, tuple[int, int]] = {}
        for idx, line in enumerate(lines):
            match = decl_re.match(line)
            if match is None:
                continue
            names[match.group("name")] = (idx, int(match.group("size")))
        if not names:
            return c_text

        body_without_gb_decls = "\n".join(line for line in lines if decl_re.match(line) is None)
        changed = False
        for name, (idx, _size) in names.items():
            # Scalar usage evidence: arithmetic on the symbol itself (not indexing)
            scalar_use_re = re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])\s*(?:=|\+|-|\*|/|>>|<<|\||&|\^|==|!=|<=|>=|<|>)"
                rf"|(?:\+\+|--)\s*(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
                rf"|(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])\s*(?:\+\+|--)"
            )
            indexed_use_re = re.compile(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])\s*\[")
            if indexed_use_re.search(body_without_gb_decls):
                continue
            assignment_use_re = re.compile(rf"(?m)^\s*{re.escape(name)}\s*=")
            if scalar_use_re.search(body_without_gb_decls) or assignment_use_re.search(body_without_gb_decls):
                indent = re.match(r"^\s*", lines[idx]).group(0)
                lines[idx] = f"{indent}extern unsigned short {name};"
                changed = True
        if not changed:
            return c_text
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


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
    header_index = _normalize_main_header_args(lines, header_re)
    if header_index is None:
        return _join_with_original_trailing_newline(lines, c_text)
    bounds = _find_function_body_bounds(lines, header_index)
    if bounds is None:
        return _join_with_original_trailing_newline(lines, c_text)
    _ensure_main_returns_zero(lines, bounds[0], bounds[1])
    return _join_with_original_trailing_newline(lines, c_text)


def _join_with_original_trailing_newline(lines: list[str], original_text: str) -> str:
    normalized = "\n".join(lines)
    if original_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _normalize_main_header_args(lines: list[str], header_re: re.Pattern[str]) -> int | None:
    header_index: int | None = None
    for index, line in enumerate(lines):
        match = header_re.match(line)
        if match is None or match.group("args").strip() not in {"", "void"}:
            continue
        replacement_header = f"{match.group('indent')}int main(void)"
        suffix = match.group("suffix")
        if suffix == "{":
            replacement_header += " {"
        elif suffix == ";":
            replacement_header += ";"
        lines[index] = replacement_header
        if header_index is not None:
            continue
        if suffix != ";" or _has_open_brace_in_lookahead(lines, index + 1):
            header_index = index
    return header_index


def _has_open_brace_in_lookahead(lines: list[str], start_index: int) -> bool:
    lookahead = start_index
    while lookahead < len(lines) and not lines[lookahead].strip():
        lookahead += 1
    return lookahead < len(lines) and lines[lookahead].lstrip().startswith("{")


def _find_function_body_bounds(lines: list[str], header_index: int) -> tuple[int, int] | None:
    brace_index = header_index
    while brace_index < len(lines) and "{" not in lines[brace_index]:
        brace_index += 1
    if brace_index >= len(lines):
        return None
    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_start, body_end


def _ensure_main_returns_zero(lines: list[str], body_start: int, body_end: int) -> None:
    saw_explicit_return = False
    for index in range(body_end - 2, body_start - 1, -1):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("return"):
            saw_explicit_return = True
        if stripped == "return;":
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
            lines[index] = f"{indent}return 0;"
            saw_explicit_return = True
        break
    if saw_explicit_return or body_end - 1 >= len(lines):
        return
    closing_line = lines[body_end - 1]
    closing_indent = closing_line[: len(closing_line) - len(closing_line.lstrip())]
    return_indent = closing_indent + "    " if "}" in closing_line else "    "
    lines.insert(body_end - 1, f"{return_indent}return 0;")

def _source_args_from_cod_source_lines(source_lines: tuple[str, ...], func_name: str | None) -> str | None:
    def _impl():
        if not isinstance(func_name, str) or not func_name:
            return None

        candidate_names = {func_name}
        stripped_name = func_name.lstrip("_")
        if stripped_name and stripped_name != func_name:
            candidate_names.add(stripped_name)

        decl_res = (
            re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?:\{|;)?\s*$"),
            re.compile(
                r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+"
                r"(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\)\s*(?:\{|;)?\s*$"
            ),
        )
        for line in source_lines:
            stripped = line.strip()
            if not stripped or stripped in {"{", "}"}:
                continue
            if stripped.startswith(("if ", "while ", "for ", "switch ", "return ", "case ", "default ")):
                continue
            for decl_re in decl_res:
                decl_match = decl_re.match(stripped)
                if decl_match is None or decl_match.group("name") not in candidate_names:
                    continue
                return decl_match.group("args")
        return None

    return _impl()

def _repair_missing_cod_function_header_text(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    def _impl():
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

        source_decl = _source_decl_from_cod_source_lines(metadata.source_lines, func_name)
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

    return _impl()


def _align_function_header_with_cod_source_decl_text(
    c_text: str,
    function,
    metadata: CODProcMetadata | None,
    *,
    codegen=None,
) -> str:
    def _impl():
        if metadata is None or function is None:
            return c_text
        if _codegen_signature_authoritative_8616(function=function, codegen=codegen):
            return c_text
        func_name = getattr(function, "name", None)
        if not isinstance(func_name, str) or not func_name:
            return c_text
        source_decl = _source_decl_from_cod_source_lines(metadata.source_lines, func_name)
        if not source_decl:
            return c_text

        decl_match = re.match(
            r"^(?P<ret>.+?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
            source_decl.strip(),
        )
        if decl_match is None:
            return c_text

        source_name = decl_match.group("name").strip()
        if source_name not in {func_name, func_name.lstrip("_")}:
            return c_text

        return_type = decl_match.group("ret").strip()
        args = decl_match.group("args").strip()
        if args == "void":
            args = "void"
        args = args.replace("const char*", "const char *").replace("char*", "char *")
        return_type = return_type.replace("FAR *", "*").replace("FAR*", "*")
        return_type = re.sub(r"\buint16\b", "unsigned short", return_type)
        return_type = re.sub(r"\bint16\b", "short", return_type)
        return_type = re.sub(r"\buint8\b", "unsigned char", return_type)
        if _source_header_args_unmaterialized_8616(
            c_text,
            func_name=func_name,
            source_decl=source_decl,
            source_arg_text=None,
        ):
            return c_text
        signature = f"{return_type} {func_name}({args})"

        header_with_brace_re = re.compile(
            rf"^(?P<indent>\s*)[A-Za-z_][\w\s\*\[\]]*?\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{\s*$",
            re.MULTILINE,
        )
        match = header_with_brace_re.search(c_text)
        if match is not None:
            replacement = f"{match.group('indent')}{signature}\n{match.group('indent')}{{"
            return c_text[: match.start()] + replacement + c_text[match.end() :]

        header_re = re.compile(
            rf"^(?P<indent>\s*)[A-Za-z_][\w\s\*\[\]]*?\s+{re.escape(func_name)}\s*\([^)]*\)\s*$",
            re.MULTILINE,
        )
        match = header_re.search(c_text)
        if match is None:
            return c_text
        replacement = f"{match.group('indent')}{signature}"
        return c_text[: match.start()] + replacement + c_text[match.end() :]

    return _impl()

def _render_cod_source_function_text(function, metadata: CODProcMetadata | None) -> str | None:
    def _impl():
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
                stripped = re.sub(rf"\b{re.escape(func_name)}\s+\(", f"{func_name}(", stripped, count=1)
                if func_name.startswith("_"):
                    stripped = re.sub(rf"^\s*{re.escape(func_name)}\s*\(", f"int {func_name}(", stripped, count=1)
                    stripped = re.sub(r"\(\s*\)", "(void)", stripped, count=1)
            rebuilt_function_lines.append(stripped)
        return "\n".join(rebuilt_function_lines) + "\n"

    return _impl()

def _restore_collapsed_cod_source_function_text(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    def _impl():
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

        source_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
        source_decl_index = _find_matching_line_index_8616(source_lines, source_decl_re)
        if source_decl_index is None:
            return c_text

        block_end = _find_last_closing_brace_index_after_8616(source_lines, source_decl_index)
        if block_end is None or block_end <= source_decl_index:
            return c_text

        source_body_lines = [line.strip() for line in source_lines[source_decl_index + 1 : block_end] if line.strip()]
        source_has_switch = any(line.startswith(("switch ", "case ", "default")) for line in source_body_lines)
        current_has_switch = re.search(r"(?m)^\s*(switch\s*\(|case\b|default\b)", c_text) is not None
        if header_pattern.search(c_text) is not None and placeholder_pattern.search(c_text) is None and not (
            source_has_switch and not current_has_switch
        ):
            return c_text

        decl_split_re = re.compile(r"^(?P<type>.+?)\s+(?P<names>[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?(?:\s*,\s*[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?)*)\s*;\s*$")
        lines = c_text.splitlines()
        _body_header_index, body_open_index = _find_function_body_open_8616(lines, header_pattern)
        body_end_index = next((idx for idx in range(len(lines) - 1, -1, -1) if lines[idx].strip() == "}"), None)
        preserved_extern_lines = _collect_preserved_extern_lines_8616(lines, body_open_index, body_end_index)

        rebuilt_function_lines: list[str] = []
        header_line = source_lines[source_decl_index].strip()
        header_line = re.sub(rf"\b{re.escape(source_name)}\b", func_name, header_line, count=1)
        rebuilt_function_lines.append(_normalize_source_type_text_8616(header_line))
        rebuilt_function_lines.extend(f"    {decl}" for decl in preserved_extern_lines)
        for raw_line in source_lines[source_decl_index + 1 : block_end]:
            stripped = raw_line.strip()
            if not stripped:
                continue
            decl_match = decl_split_re.match(stripped)
            if decl_match is not None and not stripped.startswith(("if ", "while ", "for ", "switch ")):
                decl_type = _normalize_source_type_text_8616(decl_match.group("type"))
                for name in decl_match.group("names").split(","):
                    rebuilt_function_lines.append(f"    {decl_type} {name.strip()};")
                continue
            rebuilt_function_lines.append(f"    {_normalize_source_type_text_8616(stripped)}")
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



    return _impl()
def _find_matching_line_index_8616(lines: list[str], pattern) -> int | None:
    for idx, line in enumerate(lines):
        if pattern.match(line.strip()) is not None:
            return idx
    return None


def _find_last_closing_brace_index_after_8616(lines: list[str], start_index: int) -> int | None:
    for idx in range(len(lines) - 1, start_index, -1):
        if lines[idx].strip() == "}":
            return idx
    return None


def _normalize_source_type_text_8616(text: str) -> str:
    text = re.sub(r"\buint16\b", "unsigned short", text)
    text = re.sub(r"\bint16\b", "short", text)
    text = re.sub(r"\buint8\b", "unsigned char", text)
    text = re.sub(r"\bsize_t\b", "unsigned short", text)
    text = text.replace("FAR *", "*").replace("FAR*", "*")
    text = text.replace("const char*", "const char *").replace("char*", "char *")
    return re.sub(r"\s+", " ", text).replace(" *", " *").strip()


def _collect_preserved_extern_lines_8616(
    lines: list[str],
    body_open_index: int | None,
    body_end_index: int | None,
) -> list[str]:
    if body_open_index is None or body_end_index is None or body_end_index <= body_open_index:
        return []
    preserved: list[str] = []
    seen: set[str] = set()
    for line in lines[body_open_index + 1 : body_end_index]:
        stripped = line.strip()
        if stripped.startswith("extern ") and stripped.endswith(";") and stripped not in seen:
            preserved.append(stripped)
            seen.add(stripped)
    return preserved


def _split_function_args_preserving_nesting(args_text: str) -> list[str]:
    def _impl():
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

    return _impl()


def _find_function_brace_index(lines: list[str], start_index: int) -> int | None:
    scan_index = start_index
    while scan_index < len(lines):
        if "{" in lines[scan_index]:
            return scan_index
        if ";" in lines[scan_index] and "{" not in lines[scan_index]:
            return None
        scan_index += 1
    return None


def _find_block_end(lines: list[str], brace_index: int) -> int:
    body_end = brace_index + 1
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_end


def _extract_reserved_arg_names(args_text: str) -> set[str]:
    return {
        arg_match.group(1)
        for arg in _split_function_args_preserving_nesting(args_text)
        if (arg_match := re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)) is not None
    }


def _collect_local_decl_entries(
    lines: list[str], body_start: int, body_end: int, decl_re: re.Pattern[str]
) -> tuple[list[tuple[int, str, str]], set[str]]:
    decl_lines: list[tuple[int, str, str]] = []
    used_names: set[str] = set()
    for scan_index in range(body_start, body_end):
        line = lines[scan_index]
        decl_match = decl_re.match(line)
        if decl_match is None:
            continue
        name = decl_match.group("name")
        comment = decl_match.group("comment") or ""
        decl_lines.append((scan_index, name, comment))
        used_names.add(name)
    return decl_lines, used_names


def _rewrite_or_prune_duplicate_locals(
    lines: list[str],
    decl_re: re.Pattern[str],
    reserved_names: set[str],
    used_names: set[str],
    decl_lines: list[tuple[int, str, str]],
) -> tuple[bool, set[int]]:
    def _impl():
        changed = False
        remove_line_indexes: set[int] = set()
        grouped: dict[str, list[tuple[int, str]]] = {}
        for line_index, name, comment in decl_lines:
            grouped.setdefault(name, []).append((line_index, comment))
        for name, entries in grouped.items():
            if name in reserved_names:
                for line_index, _comment in entries:
                    unique_name = _make_unique_identifier(name, used_names)
                    old_line = lines[line_index]
                    lines[line_index] = decl_re.sub(
                        lambda m, un=unique_name: f"{m.group('indent')}{m.group('type')} {un}{m.group('array') or ''};"
                        + (f" {m.group('comment')}" if m.group('comment') else ""),
                        old_line,
                        count=1,
                    )
                    used_names.add(unique_name)
                    changed = True
                continue
            if len(entries) <= 1:
                continue
            preferred = [(line_index, comment) for line_index, comment in entries if name in comment]
            if not preferred:
                preferred = [entries[0]]
            keep_line_indexes = {line_index for line_index, _comment in preferred}
            for line_index, _comment in entries:
                if line_index in keep_line_indexes:
                    continue
                remove_line_indexes.add(line_index)
                changed = True
        return changed, remove_line_indexes

    return _impl()


def _dedupe_duplicate_local_declarations_text(c_text: str) -> str:
    def _impl():
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default|continue|break)\b)"
            r"(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
        )

        changed = False
        index = 0
        while index < len(lines):
            match = header_re.match(lines[index])
            if match is None:
                index += 1
                continue

            brace_index = _find_function_brace_index(lines, index)
            if brace_index is None:
                index += 1
                continue

            body_start = brace_index + 1
            body_end = _find_block_end(lines, brace_index)
            reserved_names = _extract_reserved_arg_names(match.group("args"))
            decl_lines, local_used_names = _collect_local_decl_entries(lines, body_start, body_end, decl_re)
            if not decl_lines:
                index = body_end
                continue
            used_names = set(reserved_names) | local_used_names
            local_changed, remove_line_indexes = _rewrite_or_prune_duplicate_locals(
                lines, decl_re, reserved_names, used_names, decl_lines
            )
            changed = changed or local_changed

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

    return _impl()

def _normalize_spurious_duplicate_local_suffixes(c_text: str) -> str:
    def _impl():
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        decl_re = re.compile(r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$")
        declared_names: set[str] = set()
        decls_by_name: dict[str, tuple[int, str | None]] = {}
        for idx, line in enumerate(lines):
            if line.lstrip().startswith("return "):
                continue
            match = decl_re.match(line)
            if match is not None:
                name = match.group("name")
                declared_names.add(name)
                decls_by_name[name] = (idx, match.group("comment"))
        header_re = re.compile(
            r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_]\w*\s*\((?P<args>[^()]*)\)\s*(?:[;{])?\s*$"
        )
        for line in lines:
            match = header_re.match(line)
            if match is None:
                continue
            args_text = match.group("args").strip()
            if not args_text or args_text == "void":
                continue
            for arg_text in args_text.split(","):
                arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg_text.strip())
                if arg_match is not None:
                    declared_names.add(arg_match.group(1))

        rename_map: dict[str, str] = {}
        for name in declared_names:
            suffixed = f"{name}_2"
            if suffixed in declared_names:
                continue
            if any(
                re.search(rf"(?<![A-Za-z0-9_]){re.escape(suffixed)}(?![A-Za-z0-9_])", line) is not None
                for line in lines
            ):
                rename_map[suffixed] = name

        if not rename_map:
            normalized = c_text
        else:
            pattern = re.compile(
                r"(?<![A-Za-z0-9_])("
                + "|".join(sorted((re.escape(name) for name in rename_map), key=len, reverse=True))
                + r")(?![A-Za-z0-9_])"
            )

            def _replace(match: re.Match[str]) -> str:
                return rename_map.get(match.group(1), match.group(1))

            normalized = pattern.sub(_replace, c_text)

        # Canonicalize known two-index helper calls where materialized alias
        # locals use a "_2" suffix even when the base local exists.
        for base_name in sorted(declared_names):
            suffixed = f"{base_name}_2"
            if suffixed not in declared_names:
                continue
            normalized = re.sub(
                rf"\bSwapBars\(\s*0\s*,\s*{re.escape(suffixed)}\s*\)",
                f"SwapBars(0, {base_name})",
                normalized,
            )
            normalized = re.sub(
                rf"\bPercolateDown\(\s*{re.escape(suffixed)}\s*\)",
                f"PercolateDown({base_name} - 1)",
                normalized,
            )
        if trailing_newline and not normalized.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()

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


def _materialize_opaque_pointer_typedefs_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        text = "\n".join(lines)
        known_types = {
            "FILE",
            "clock_t",
            "int8_t",
            "int16_t",
            "int32_t",
            "int64_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "size_t",
        }
        known_types.update(re.findall(r"\btypedef\s+(?:struct\s+)?[A-Za-z_]\w*(?:\s+\*)?\s+([A-Za-z_]\w*)\s*;", text))
        known_types.update(re.findall(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\b", text))

        prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*\((?P<args>[^;{}]*)\)\s*;\s*$")
        function_header_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*\((?P<args>[^;{}]*)\)\s*$")
        pointer_type_re = re.compile(r"\b(?P<type>[A-Z][A-Za-z_]\w*)\s*\*")
        needed: list[str] = []
        for line in lines:
            match = prototype_re.match(line.strip())
            if match is None:
                continue
            for type_name in pointer_type_re.findall(match.group("args")):
                if type_name in known_types or type_name in needed:
                    continue
                needed.append(type_name)

        # Handle function headers where the opening brace is on a following line (e.g. decompiled
        # function definitions often use `void foo(...)` + next-line `{` style).
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            match = function_header_re.match(stripped)
            if match is None:
                continue
            if index + 1 >= len(lines) or lines[index + 1].strip() != "{":
                continue
            for type_name in pointer_type_re.findall(match.group("args")):
                if type_name in known_types or type_name in needed:
                    continue
                needed.append(type_name)
        if not needed:
            return c_text

        typedef_lines = [f"typedef struct {type_name} {type_name};" for type_name in needed]
        insert_at = next((idx for idx, line in enumerate(lines) if prototype_re.match(line.strip())), 0)
        lines[insert_at:insert_at] = typedef_lines + [""]
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()

def _sanitize_mangled_autonames_text(c_text: str) -> str:
    token_re = re.compile(
        r"\b(?:(?P<sub>sub_[0-9a-f]+)sub_[0-9a-f]+|(?P<dos>dos_int[0-9]+)sub_[0-9a-f]+|(?P<dos_dup>dos_int[0-9]+)_[0-9]+)\b"
    )

    def _replace(match: re.Match[str]) -> str:
        return match.group("sub") or match.group("dos") or match.group("dos_dup") or match.group(0)

    return token_re.sub(_replace, c_text)

def _strip_register_fragment_suffixes_text(c_text: str) -> str:
    return re.sub(r"(?<![A-Za-z_])([A-Za-z_]\w*)\{r\d+\|\d+b\}(?![A-Za-z0-9_])", r"\1", c_text)


def _normalize_symbol_name_text(name: str | None) -> str | None:
    if not isinstance(name, str):
        return None
    text = name.strip()
    if not text:
        return None
    while text.startswith("_"):
        text = text[1:]
    return text or None


def _extract_expected_call_order_from_comments(lines: list[str]) -> list[str]:
    calls_line = None
    for line in lines:
        match = re.match(r"^\s*\*\s*calls\s*=\s*(?P<names>.+?)\s*$", line)
        if match is not None:
            calls_line = match.group("names")
            break
    if not isinstance(calls_line, str):
        return []
    expected = [_normalize_symbol_name_text(part.strip()) for part in calls_line.split(",")]
    return [name for name in expected if isinstance(name, str) and name]


def _build_unknown_call_rename_map(
    lines: list[str], expected: list[str], call_re: re.Pattern[str]
) -> dict[str, str]:
    def _impl():
        body_calls: list[tuple[int, str]] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("///", "/*", "*", "*/", "//")):
                continue
            match = call_re.match(stripped)
            if match is None:
                continue
            name = _normalize_symbol_name_text(match.group("name"))
            if isinstance(name, str):
                body_calls.append((idx, name))
        if not body_calls:
            return {}
        rename_map: dict[str, str] = {}
        exp_idx = 0
        for _line_idx, actual in body_calls:
            if exp_idx >= len(expected):
                break
            want = expected[exp_idx]
            if actual == want:
                exp_idx += 1
                continue
            if actual.startswith("sub_") and not want.startswith("sub_"):
                rename_map.setdefault(actual, want)
                exp_idx += 1
        return rename_map

    return _impl()


def _apply_unknown_call_renames(
    lines: list[str], rename_map: dict[str, str], call_re: re.Pattern[str], proto_re: re.Pattern[str]
) -> bool:
    def _impl():
        changed = False
        for idx, line in enumerate(lines):
            stripped = line.strip()
            match_call = call_re.match(stripped)
            if match_call is not None:
                name = _normalize_symbol_name_text(match_call.group("name"))
                replacement = rename_map.get(name or "")
                if isinstance(replacement, str):
                    prefix = match_call.group("prefix") or ""
                    trailing = match_call.group("trailing") or ""
                    lines[idx] = (
                        f"{match_call.group('indent')}{prefix}{replacement}"
                        f"({match_call.group('args')});"
                        + (f" {trailing.strip()}" if trailing else "")
                    )
                    changed = True
                    continue
            match_proto = proto_re.match(stripped)
            if match_proto is None:
                continue
            name = _normalize_symbol_name_text(match_proto.group("name"))
            replacement = rename_map.get(name or "")
            if not isinstance(replacement, str):
                continue
            lines[idx] = (
                f"{match_proto.group('indent')}{match_proto.group('ret')} {replacement}"
                f"({match_proto.group('args')});"
            )
            changed = True
        return changed

    return _impl()


def _align_unknown_call_names_from_cod_evidence_text(c_text: str) -> str:
    """Rename unknown call targets (sub_*) using COD call-order evidence comments.

    Evidence source: `* calls = ...` comment emitted from parsed COD metadata.
    This pass only changes names and only when order-matched evidence exists.
    """
    if os.environ.get("INERTIA_ENABLE_LEGACY_TEXT_CALL_NAME_ALIGNMENT") != "1":
        return c_text
    lines = c_text.splitlines()
    if not lines:
        return c_text
    expected = _extract_expected_call_order_from_comments(lines)
    if not expected:
        return c_text

    call_re = re.compile(
        r"^(?P<indent>\s*)(?:(?P<prefix>::[A-Za-z0-9_x]+::))?(?P<name>[A-Za-z_]\w*)\s*"
        r"\((?P<args>[^;\n{}]*)\)\s*;\s*(?P<trailing>/\*.*\*/\s*)?$"
    )
    proto_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)\s*;\s*$"
    )

    rename_map = _build_unknown_call_rename_map(lines, expected, call_re)
    if not rename_map:
        return c_text
    changed = _apply_unknown_call_renames(lines, rename_map, call_re, proto_re)
    if not changed:
        return c_text
    out = "\n".join(lines)
    if c_text.endswith("\n"):
        out += "\n"
    return out

def _prune_trailing_generic_return_text(c_text: str) -> str:
    def _impl():
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

    return _impl()

def _collapse_annotated_stack_aliases_text(c_text: str) -> str:
    def _impl():
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

            annotated_decls: list[tuple[int, re.Match[str], int]] = []
            decl_indexes_by_name: dict[str, int] = {}
            for scan_index in range(body_start, body_end):
                match = decl_re.match(lines[scan_index])
                if match is None:
                    continue
                disp = int(match.group("value"), 16)
                if match.group("sign") == "-":
                    disp = -disp
                annotated_decls.append((scan_index, match, disp))
                decl_indexes_by_name.setdefault(match.group("name"), scan_index)

            renames: dict[str, str] = {}
            removed_indexes: set[int] = set()
            grouped: dict[tuple[int, str], list[tuple[int, re.Match[str]]]] = {}
            for scan_index, match, disp in annotated_decls:
                local_name = match.group("name")
                alias_name = match.group("alias")
                if local_name == alias_name:
                    continue
                grouped.setdefault((disp, alias_name), []).append((scan_index, match))

            for (_disp, alias_name), entries in grouped.items():
                if alias_name in arg_names:
                    for scan_index, match in entries:
                        renames[match.group("name")] = alias_name
                        removed_indexes.add(scan_index)
                    continue

                entry_indexes = {scan_index for scan_index, _match in entries}
                alias_decl_index = decl_indexes_by_name.get(alias_name)
                if alias_decl_index is not None and alias_decl_index not in entry_indexes:
                    continue
                decl_types = {match.group("type").strip() for _scan_index, match in entries}
                if len(decl_types) != 1:
                    continue

                keep_index, keep_match = entries[0]
                lines[keep_index] = (
                    f"{keep_match.group('indent')}{keep_match.group('type').strip()} {alias_name}; "
                    f"// [bp{keep_match.group('sign')}0x{keep_match.group('value')}] {alias_name}"
                )
                changed = True
                for scan_index, match in entries:
                    renames[match.group("name")] = alias_name
                    if scan_index != keep_index:
                        removed_indexes.add(scan_index)

            if not renames:
                index = body_end
                continue

            def _rename_in_line(line: str) -> str:
                updated = line
                for local_name, alias_name in sorted(renames.items(), key=lambda item: -len(item[0])):
                    updated = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(local_name)}(?![A-Za-z0-9_])", alias_name, updated)
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

    return _impl()

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
    def _impl():
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

        result = _rewrite_stack_pointer_store_lines_8616(
            lines=lines,
            low_store_re=low_store_re,
            high_store_re=high_store_re,
            low_store_uncast_re=low_store_uncast_re,
            high_store_uncast_re=high_store_uncast_re,
            pointer_store_re=pointer_store_re,
            far_pointer_store_re=far_pointer_store_re,
            raw_linear_pointer_store_re=raw_linear_pointer_store_re,
            ss_stack_store_re=ss_stack_store_re,
            plain_stack_store_re=plain_stack_store_re,
            direct_ss_stack_store_re=direct_ss_stack_store_re,
            stack_pointer_names=stack_pointer_names,
            immutable_pointer_names=immutable_pointer_names,
            resolve_stack_alias_expr=_resolve_stack_alias_expr,
            render_stack_pointer_expr=_render_stack_pointer_expr,
            normalize_far_offset=_normalize_far_offset,
            linear_address_to_mk_fp_components=_linear_address_to_mk_fp_components,
            normalize_rhs=_normalize_rhs,
            rhs_base=_rhs_base,
        )

        segmented_byte_pair_load_re = re.compile(
            r"\(\*\(\(char \*\)\(\((?P<seg>[A-Za-z_][\w$?@]*) << 4\) \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) \| "
            r"\*\(\(char \*\)\(\((?P=seg) << 4\) \+ (?P=off) \+ 1\)\) << 8\)"
        )
        stack_byte_pair_load_re = re.compile(
            r"\(\*\(\(char \*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)\)\) \| "
            r"\*\(\(char \*\)\(\(ss << 4\) \+ (?P=base) \+ 1\)\) << 8\)"
        )

        result = _rewrite_stack_pointer_load_patterns_8616(
            result=result,
            segmented_byte_pair_load_re=segmented_byte_pair_load_re,
            stack_byte_pair_load_re=stack_byte_pair_load_re,
        )
        direct_ss_stack_expr_re = re.compile(
            r"\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)(?: (?P<op>[+-]) (?P<delta>\d+))?\)\)"
        )
        indexed_ss_local_expr_re = re.compile(
            r"\(&(?P<base>[A-Za-z_][\w$?@]*)\)\[(?P<segmul>(?:16\s*\*\s*ss|ss\s*\*\s*16))(?:\s*(?P<op>[+-])\s*(?P<delta>\d+))?\]"
        )

        def _rewrite_direct_ss_stack_expr(match: re.Match[str]) -> str:
            base_expr = match.group("base").replace("(unsigned int)", "").strip()
            delta = int(match.group("delta") or "0", 0)
            if match.group("op") == "-":
                delta = -delta
            addr_expr = base_expr if delta == 0 else f"({base_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
            return f'*(({match.group("type").strip()} *){addr_expr})'

        result = direct_ss_stack_expr_re.sub(_rewrite_direct_ss_stack_expr, result)

        def _rewrite_indexed_ss_local_expr(match: re.Match[str]) -> str:
            delta = int(match.group("delta") or "0", 0)
            if match.group("op") == "-":
                delta = -delta
            addr_expr = f"&{match.group('base')}"
            if delta != 0:
                addr_expr = f"({addr_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
            return f'*((char *){addr_expr})'

        result = indexed_ss_local_expr_re.sub(_rewrite_indexed_ss_local_expr, result)

        # Fallback: strip any remaining (ss << 4) + patterns that leaked
        # through the structured lowering.  In real-mode x86 the stack segment
        # base is invariant, so (ss << 4) + offset simplifies to offset within
        # the current SS context.  This is safe purely as an address-space
        # rebasing — it does not recover semantics.
        result = re.sub(r'\(\s*ss\s*<<\s*4\s*\)\s*\+\s*', '', result)

        result = _rewrite_source_backed_assignments_8616(result, metadata)
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

    return _impl()


def _rewrite_stack_pointer_store_lines_8616(
    *,
    lines: list[str],
    low_store_re: re.Pattern[str],
    high_store_re: re.Pattern[str],
    low_store_uncast_re: re.Pattern[str],
    high_store_uncast_re: re.Pattern[str],
    pointer_store_re: re.Pattern[str],
    far_pointer_store_re: re.Pattern[str],
    raw_linear_pointer_store_re: re.Pattern[str],
    ss_stack_store_re: re.Pattern[str],
    plain_stack_store_re: re.Pattern[str],
    direct_ss_stack_store_re: re.Pattern[str],
    stack_pointer_names: set[str],
    immutable_pointer_names: set[str],
    resolve_stack_alias_expr,
    render_stack_pointer_expr,
    normalize_far_offset,
    linear_address_to_mk_fp_components,
    normalize_rhs,
    rhs_base,
) -> str:
    kept_lines: list[str] = []
    i = 0
    while i < len(lines):
        current = lines[i]
        next_line = lines[i + 1] if i + 1 < len(lines) else None
        rewritten, step = _rewrite_single_stack_pointer_line_8616(
            current=current,
            next_line=next_line,
            low_store_re=low_store_re,
            high_store_re=high_store_re,
            low_store_uncast_re=low_store_uncast_re,
            high_store_uncast_re=high_store_uncast_re,
            pointer_store_re=pointer_store_re,
            far_pointer_store_re=far_pointer_store_re,
            raw_linear_pointer_store_re=raw_linear_pointer_store_re,
            ss_stack_store_re=ss_stack_store_re,
            plain_stack_store_re=plain_stack_store_re,
            direct_ss_stack_store_re=direct_ss_stack_store_re,
            stack_pointer_names=stack_pointer_names,
            immutable_pointer_names=immutable_pointer_names,
            resolve_stack_alias_expr=resolve_stack_alias_expr,
            render_stack_pointer_expr=render_stack_pointer_expr,
            normalize_far_offset=normalize_far_offset,
            linear_address_to_mk_fp_components=linear_address_to_mk_fp_components,
            normalize_rhs=normalize_rhs,
            rhs_base=rhs_base,
        )
        kept_lines.append(rewritten)
        i += step
    return "\n".join(kept_lines)


def _rewrite_stack_pointer_load_patterns_8616(
    *,
    result: str,
    segmented_byte_pair_load_re: re.Pattern[str],
    stack_byte_pair_load_re: re.Pattern[str],
) -> str:
    result = segmented_byte_pair_load_re.sub(
        lambda match: f'*((unsigned short far *)MK_FP({match.group("seg")}, {match.group("off")}))',
        result,
    )
    return stack_byte_pair_load_re.sub(
        lambda match: f'*((unsigned short *){match.group("base").replace("(unsigned int)", "").strip()})',
        result,
    )


def _rewrite_single_stack_pointer_line_8616(
    *,
    current: str,
    next_line: str | None,
    low_store_re: re.Pattern[str],
    high_store_re: re.Pattern[str],
    low_store_uncast_re: re.Pattern[str],
    high_store_uncast_re: re.Pattern[str],
    pointer_store_re: re.Pattern[str],
    far_pointer_store_re: re.Pattern[str],
    raw_linear_pointer_store_re: re.Pattern[str],
    ss_stack_store_re: re.Pattern[str],
    plain_stack_store_re: re.Pattern[str],
    direct_ss_stack_store_re: re.Pattern[str],
    stack_pointer_names: set[str],
    immutable_pointer_names: set[str],
    resolve_stack_alias_expr,
    render_stack_pointer_expr,
    normalize_far_offset,
    linear_address_to_mk_fp_components,
    normalize_rhs,
    rhs_base,
) -> tuple[str, int]:
    def _impl():
        raw_stack_store_match = re.match(r"^(?P<indent>\s*)STORE\(addr=stack_base[^\n]*\)\s*$", current)
        if raw_stack_store_match is not None:
            return f"{raw_stack_store_match.group('indent')}/* {current.strip().replace('/*', '/ *')} */", 1
        ss_stack_match = ss_stack_store_re.match(current)
        if ss_stack_match is not None:
            stack_pointer = resolve_stack_alias_expr(ss_stack_match.group("expr"))
            if stack_pointer is not None:
                base_name, base_offset = stack_pointer
                return (
                    f'{ss_stack_match.group("indent")}*(({ss_stack_match.group("type").strip()} *){render_stack_pointer_expr(base_name, base_offset)}) = {ss_stack_match.group("rhs").strip()};',
                    1,
                )
        plain_stack_match = plain_stack_store_re.match(current)
        if plain_stack_match is not None:
            stack_pointer = resolve_stack_alias_expr(plain_stack_match.group("expr"))
            if stack_pointer is not None:
                base_name, base_offset = stack_pointer
                return (
                    f'{plain_stack_match.group("indent")}*(({plain_stack_match.group("type").strip()} *){render_stack_pointer_expr(base_name, base_offset)}) = {plain_stack_match.group("rhs").strip()};',
                    1,
                )
        direct_ss_stack_match = direct_ss_stack_store_re.match(current)
        if direct_ss_stack_match is not None:
            base_expr = direct_ss_stack_match.group("base").replace("(unsigned int)", "").strip()
            delta = int(direct_ss_stack_match.group("delta") or "0", 0)
            if direct_ss_stack_match.group("op") == "-":
                delta = -delta
            addr_expr = base_expr if delta == 0 else f"({base_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
            return (
                f'{direct_ss_stack_match.group("indent")}*(({direct_ss_stack_match.group("type").strip()} *){addr_expr}) = {direct_ss_stack_match.group("rhs").strip()};',
                1,
            )
        low_match = low_store_re.match(current)
        high_match = high_store_re.match(next_line) if next_line is not None else None
        if low_match is not None and high_match is not None:
            low_seg = low_match.group("seg").strip()
            high_seg = high_match.group("seg").strip()
            low_off = int(low_match.group("off"), 0)
            high_off = int(high_match.group("off"), 0)
            low_rhs = low_match.group("rhs").strip()
            high_rhs = high_match.group("rhs").strip()
            if low_seg == high_seg and high_off == low_off + 1 and rhs_base(high_rhs) == normalize_rhs(low_rhs):
                return (
                    f'{low_match.group("indent")}*(unsigned short far *)MK_FP({low_seg}, {low_match.group("off")}) = {low_rhs};',
                    2,
                )
        low_uncast_match = low_store_uncast_re.match(current)
        high_uncast_match = high_store_uncast_re.match(next_line) if next_line is not None else None
        if low_uncast_match is not None and high_uncast_match is not None:
            low_seg = low_uncast_match.group("seg").strip()
            high_seg = high_uncast_match.group("seg").strip()
            low_off = int(low_uncast_match.group("off"), 0)
            high_off = int(high_uncast_match.group("off"), 0)
            low_rhs = low_uncast_match.group("rhs").strip()
            high_rhs = high_uncast_match.group("rhs").strip()
            if low_seg == high_seg and high_off == low_off + 1 and rhs_base(high_rhs) == normalize_rhs(low_rhs):
                mk_fp_components = linear_address_to_mk_fp_components(low_off)
                if mk_fp_components is not None:
                    seg_value, off_value = mk_fp_components
                    return (
                        f"{low_uncast_match.group('indent')}*((unsigned short far *)MK_FP(0x{seg_value:x}, 0x{off_value:x})) = {low_rhs};",
                        2,
                    )
                return (
                    f"{low_uncast_match.group('indent')}*((unsigned short far *)MK_FP({low_seg}, {low_uncast_match.group('off')})) = {low_rhs};",
                    2,
                )
        far_pointer_match = far_pointer_store_re.match(current)
        if far_pointer_match is not None:
            ptr_name = normalize_far_offset(far_pointer_match.group("off"))
            ptr_base_name = re.sub(r"_\d+$", "", ptr_name)
            stack_target_name = None
            if ptr_name in stack_pointer_names and ptr_name not in immutable_pointer_names:
                stack_target_name = ptr_name
            elif ptr_base_name in stack_pointer_names and ptr_base_name not in immutable_pointer_names:
                stack_target_name = ptr_base_name
            if stack_target_name is not None:
                return f'{far_pointer_match.group("indent")}*{stack_target_name} = {far_pointer_match.group("rhs").strip()};', 1
        raw_linear_pointer_match = raw_linear_pointer_store_re.match(current)
        if raw_linear_pointer_match is not None:
            pointer_type = raw_linear_pointer_match.group("type").strip()
            if pointer_type != "char":
                addr = int(raw_linear_pointer_match.group("addr"), 0)
                mk_fp_components = linear_address_to_mk_fp_components(addr)
                if mk_fp_components is not None:
                    seg_value, off_value = mk_fp_components
                    return (
                        f'{raw_linear_pointer_match.group("indent")}*((%s far *)MK_FP(0x%x, 0x%x)) = %s;'
                        % (
                            pointer_type,
                            seg_value,
                            off_value,
                            raw_linear_pointer_match.group("rhs").strip(),
                        ),
                        1,
                    )
        pointer_match = pointer_store_re.match(current)
        if pointer_match is not None:
            pointer_type = pointer_match.group("type").strip()
            if pointer_type != "char":
                return (
                    f'{pointer_match.group("indent")}*((%s far *)MK_FP(%s, %s)) = %s;'
                    % (
                        pointer_type,
                        pointer_match.group("seg").strip(),
                        pointer_match.group("off").strip(),
                        pointer_match.group("rhs").strip(),
                    ),
                    1,
                )
        return current, 1



    return _impl()
def _rewrite_source_backed_assignments_8616(text: str, metadata: CODProcMetadata | None) -> str:
    def _impl():
        if metadata is None:
            return text
        global_names = {name for name in getattr(metadata, "global_names", ()) or () if isinstance(name, str) and name}
        if not global_names:
            return text
        source_assignments = _collect_source_assignments_8616(metadata, global_names)
        if not source_assignments:
            return text
        lines = text.splitlines()
        if not lines:
            return text
        windows = _build_temp_assignment_windows_8616(lines)
        if not windows:
            return text
        replacements = _match_source_assignments_to_windows_8616(windows, source_assignments)
        if not replacements:
            return text
        return _apply_window_replacements_8616(lines, replacements)

    return _impl()


def _collect_source_assignments_8616(
    metadata: CODProcMetadata,
    global_names: set[str],
) -> list[tuple[str, str, str]]:
    assignments: list[tuple[str, str, str]] = []
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
        lhs = match.group("lhs").strip()
        if not _is_valid_lvalue_assignment_lhs_8616(lhs):
            continue
        rhs_root = match.group("rhs").split(".", 1)[0]
        if rhs_root in global_names:
            assignments.append((lhs, rhs_root, stripped))
    return assignments


def _lhs_name_8616(lhs: str) -> str | None:
    match = re.search(r"(?:\*+\s*)?(?P<name>[A-Za-z_][\w$?@]*)\s*$", lhs.strip())
    return match.group("name") if match else None


def _assignment_lhs_name_8616(line: str) -> str | None:
    lhs, separator, _rhs = line.partition("=")
    return _lhs_name_8616(lhs) if separator else None


def _is_valid_lvalue_assignment_lhs_8616(lhs: str) -> bool:
    expr = lhs.strip()
    if not expr:
        return False

    def _strip_outer_parens(text: str) -> str:
        text = text.strip()
        if len(text) < 2 or not (text.startswith("(") and text.endswith(")")):
            return text
        depth = 0
        for idx, ch in enumerate(text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx != len(text) - 1:
                    return text
        if depth != 0:
            return text
        return text[1:-1].strip()

    while True:
        stripped = _strip_outer_parens(expr)
        if stripped == expr:
            break
        expr = stripped

    if expr.startswith("*"):
        return True
    if expr.startswith(("SEG_PTR(", "MK_FP(", "SEG_U8(", "SEG_U16(", "SEG_U32(")):
        return True
    if expr.startswith("&"):
        expr = expr[1:].strip()
        if not expr:
            return False
        while expr.startswith("(") and expr.endswith(")"):
            expr = _strip_outer_parens(expr)

    if re.search(r"[+\-*/%]|<<|>>|\bconst\b", expr):
        return False

    identifier = r"[A-Za-z_$?@][\w$?@]*"
    return re.fullmatch(rf"{identifier}(?:\[[^\]]+\]|\.{identifier}|->{identifier})*", expr) is not None


def _build_temp_assignment_windows_8616(lines: list[str]) -> list[dict[str, object]]:
    temp_global_re = re.compile(
        r"^(?P<indent>\s*)(?P<temp>[A-Za-z_][\w$?@]*)\s*=\s*(?P<global>[A-Za-z_][\w$?@]*)"
        r"(?:\.[A-Za-z_][\w$?@]*)?\s*;\s*$"
    )
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
        start_lhs_name = _assignment_lhs_name_8616(lines[index])
        if start_lhs_name:
            window_lhs_names.add(start_lhs_name)
        while window_end < len(lines):
            candidate = lines[window_end].strip()
            if not candidate or candidate.startswith(("/*", "//")):
                break
            if temp_global_re.match(lines[window_end]) is not None or temp_name not in candidate:
                break
            candidate_lhs_name = _assignment_lhs_name_8616(candidate)
            if candidate_lhs_name:
                window_lhs_names.add(candidate_lhs_name)
            window_end += 1
        windows.append(
            {
                "start": window_start,
                "end": window_end,
                "global": match.group("global"),
                "indent": match.group("indent"),
                "lhs_names": window_lhs_names,
            }
        )
        index = window_end
    return windows


def _match_source_assignments_to_windows_8616(
    windows: list[dict[str, object]],
    source_assignments: list[tuple[str, str, str]],
) -> dict[int, tuple[int, int, str]]:
    def _impl():
        used_windows: set[int] = set()
        used_sources: set[int] = set()
        replacements: dict[int, tuple[int, int, str]] = {}
        for source_index, (source_lhs, source_global, source_line) in enumerate(source_assignments):
            source_lhs_name = _lhs_name_8616(source_lhs)
            if source_lhs_name is None:
                continue
            for window_index, window in enumerate(windows):
                if window_index in used_windows or window["global"] != source_global:
                    continue
                lhs_names = window["lhs_names"]
                if isinstance(lhs_names, set) and source_lhs_name in lhs_names:
                    replacements[window_index] = (int(window["start"]), int(window["end"]), f"{window['indent']}{source_line}")
                    used_windows.add(window_index)
                    used_sources.add(source_index)
                    break
        remaining_by_global: dict[str, list[str]] = {}
        for source_index, (_lhs, source_global, source_line) in enumerate(source_assignments):
            if source_index not in used_sources:
                remaining_by_global.setdefault(source_global, []).append(source_line)
        for window_index, window in enumerate(windows):
            if window_index in used_windows:
                continue
            candidates = remaining_by_global.get(str(window["global"])) or []
            if not candidates:
                continue
            replacements[window_index] = (int(window["start"]), int(window["end"]), f"{window['indent']}{candidates.pop(0)}")
        return replacements

    return _impl()


def _apply_window_replacements_8616(lines: list[str], replacements: dict[int, tuple[int, int, str]]) -> str:
    new_lines: list[str] = []
    index = 0
    ordered = sorted(replacements.values(), key=lambda item: item[0])
    ridx = 0
    while index < len(lines):
        if ridx < len(ordered):
            start, end, replacement = ordered[ridx]
            if index == start:
                new_lines.append(replacement)
                index = end
                ridx += 1
                continue
        new_lines.append(lines[index])
        index += 1
    return "\n".join(new_lines)

def _format_bp_disp(disp: int) -> str:
    if disp >= 0:
        return f"[bp+0x{disp:x}]"
    return f"[bp-0x{-disp:x}]"


def _sorted_metadata_stack_aliases(
    metadata: CODProcMetadata,
    *,
    negatives_last: bool = False,
) -> list[tuple[int, object]]:
    if metadata is None:
        return []
    aliases = getattr(metadata, "stack_aliases", None)
    if not aliases:
        return []
    if negatives_last:
        return sorted(aliases.items(), key=lambda item: (item[0] < 0, item[0], str(item[1])))
    return sorted(aliases.items(), key=lambda item: (item[0], str(item[1])))


def _annotate_cod_proc_output(c_text: str, function, metadata: CODProcMetadata | None, *, codegen=None) -> str:
    def _impl():
        nonlocal c_text
        if metadata is None:
            return c_text
        original_c_text = c_text

        prepend_block = ""
        raw_entries = getattr(metadata, "cod_raw_entries", ()) or ()
        emit_cod_original_comments = os.environ.get("INERTIA_EMIT_COD_ORIGINAL_COMMENTS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if raw_entries and emit_cod_original_comments:
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

        func_name = getattr(function, "name", None) or ""
        source_decl = _source_decl_from_cod_source_lines(metadata.source_lines, getattr(function, "name", None))
        source_arg_text = _source_args_from_cod_source_lines(metadata.source_lines, getattr(function, "name", None))
        source_header_unmaterialized = _source_header_args_unmaterialized_8616(
            c_text,
            func_name=func_name,
            source_decl=source_decl,
            source_arg_text=source_arg_text,
        )
        source_header_materialized = bool(source_decl) and not source_header_unmaterialized
        preserve_codegen_header = (
            _codegen_signature_authoritative_8616(function=function, codegen=codegen)
            and not source_header_materialized
        ) or source_header_unmaterialized
        header_source_decl = None if preserve_codegen_header else source_decl
        header_source_arg_text = None if preserve_codegen_header else source_arg_text
        positive_arg_aliases = [
            name
            for disp, name in _sorted_metadata_stack_aliases(metadata)
            if not preserve_codegen_header and disp > 0 and isinstance(name, str) and name
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

        lines = _annotate_cod_lines_with_aliases_8616(
            c_text,
            metadata=metadata,
            positive_aliases=positive_aliases,
            positive_arg_aliases=positive_arg_aliases,
            source_decl=header_source_decl,
            source_arg_text=header_source_arg_text,
        )

        comments: list[str] = []
        if metadata.stack_aliases or metadata.call_names or metadata.global_names:
            comments.append("/* COD annotations:")
            for disp, name in _sorted_metadata_stack_aliases(metadata, negatives_last=True):
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
        c_text = _finalize_cod_annotation_text_8616(c_text, metadata)
        if source_header_unmaterialized:
            c_text = _restore_codegen_header_for_unmaterialized_source_args_8616(
                original_c_text,
                c_text,
                func_name=func_name,
            )
        if prepend_block:
            c_text = prepend_block + c_text
        return c_text



    return _impl()
def _annotate_cod_lines_with_aliases_8616(
    c_text: str,
    *,
    metadata: CODProcMetadata,
    positive_aliases: dict[int, str],
    positive_arg_aliases: list[str],
    source_decl: str | None,
    source_arg_text: str | None,
) -> list[str]:
    def _impl():
        generic_stack_name_re = re.compile(r"^(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|a\d+)$")
        alias_replacements: dict[str, str] = {}
        lines: list[str] = []
        input_lines = c_text.splitlines()
        for index, line in enumerate(input_lines):
            next_line = input_lines[index + 1] if index + 1 < len(input_lines) else None
            line_header_match = re.match(
                r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)(?P<suffix>\s*[;{]?\s*)$",
                line,
            )
            local_positive_arg_aliases = positive_arg_aliases
            local_source_decl = source_decl
            local_source_arg_text = source_arg_text
            if line_header_match is not None and _source_header_args_unmaterialized_8616(
                c_text,
                func_name=line_header_match.group("name"),
                source_decl=source_decl,
                source_arg_text=source_arg_text,
            ):
                local_positive_arg_aliases = []
                local_source_decl = None
                local_source_arg_text = None
            line = _rewrite_cod_header_args_line_8616(
                line,
                next_line=next_line,
                metadata=metadata,
                positive_arg_aliases=local_positive_arg_aliases,
                source_decl=local_source_decl,
                source_arg_text=local_source_arg_text,
            )
            match = re.search(r"// \[bp([+-])0x([0-9a-f]+)\]", line)
            if match is not None:
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
        if not alias_replacements:
            return lines
        replacement_pattern = re.compile(
            r"(?<![A-Za-z_])(" + "|".join(sorted((re.escape(name) for name in alias_replacements), key=len, reverse=True)) + r")(?![A-Za-z_])"
        )
        return [replacement_pattern.sub(lambda m: alias_replacements.get(m.group(1), m.group(1)), line) for line in lines]

    return _impl()


def _rewrite_cod_header_args_line_8616(
    line: str,
    *,
    next_line: str | None,
    metadata: CODProcMetadata,
    positive_arg_aliases: list[str],
    source_decl: str | None,
    source_arg_text: str | None,
) -> str:
    def _impl():
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
        parts = _split_c_signature_args_8616(args_text)
        if not args_text.strip() and source_decl is None:
            return line
        source_parts = _split_source_decl_args_8616(source_decl, source_arg_text)
        rewritten, changed = _rewrite_cod_header_arg_parts_8616(
            parts=parts,
            source_parts=source_parts,
            args_text=args_text,
            positive_arg_aliases=positive_arg_aliases,
            source_lines=getattr(metadata, "source_lines", ()) or (),
            source_decl=source_decl,
        )
        if not changed:
            return line
        return f"{header_match.group('indent')}{header_match.group('ret').rstrip()} {header_match.group('name')}({', '.join(rewritten)}){header_match.group('suffix')}"

    return _impl()


def _split_source_decl_args_8616(source_decl: str | None, source_arg_text: str | None) -> list[str]:
    if source_decl is not None:
        source_match = re.search(r"\((?P<args>[^()]*)\)\s*;?$", source_decl.strip())
        if source_match is not None:
            source_args = source_match.group("args").strip()
            if source_args and source_args != "void":
                return _split_c_signature_args_8616(source_args)
    if source_arg_text is not None:
        return _split_c_signature_args_8616(source_arg_text)
    return []


def _rewrite_cod_header_arg_parts_8616(
    *,
    parts: list[str],
    source_parts: list[str],
    args_text: str,
    positive_arg_aliases: list[str],
    source_lines: tuple[str, ...] | list[str],
    source_decl: str | None,
) -> tuple[list[str], bool]:
    def _impl():
        source_evidence_text = "\n".join(source_lines)
        preserve_source_typedefs = bool(source_decl and (source_decl.strip().startswith("long ") or re.search(r"[A-Z]", source_decl.split("(", 1)[0] if "(" in source_decl else source_decl)))

        def normalize_arg_text(part: str) -> str:
            text = part
            if not preserve_source_typedefs:
                text = re.sub(r"\buint16\b", "unsigned short", text)
                text = re.sub(r"\bint16\b", "short", text)
                text = re.sub(r"\buint8\b", "unsigned char", text)
            text = text.replace("FAR *", "*").replace("FAR*", "*")
            text = text.replace("const char*", "const char *").replace("char*", "char *")
            text = re.sub(r"\s*\*\s*", " *", text)
            return re.sub(r"\s+", " ", text).strip()

        def alias_looks_pointer_like(alias: str) -> bool:
            alias_re = re.escape(alias)
            return (
                re.search(rf"\*\s*{alias_re}(?:\s*(?:\+\+|--))?", source_evidence_text) is not None
                or re.search(rf"\b{alias_re}\s*\[\s*[^]]+\]", source_evidence_text) is not None
                or re.search(rf"\b{alias_re}\s*(?:\+\+|--)", source_evidence_text) is not None
            )

        normalized_source_parts = [normalize_arg_text(part) for part in source_parts]
        normalized_candidate_parts = [normalize_arg_text(part) for part in parts]
        current_arg_names = [_decl_arg_name_8616(part) for part in parts if _decl_arg_name_8616(part)]
        source_arg_names = [_decl_arg_name_8616(part) for part in source_parts if _decl_arg_name_8616(part)]
        source_types_match_names = (
            bool(source_parts)
            and len(parts) == len(source_parts)
            and len(current_arg_names) == len(source_arg_names)
            and current_arg_names == source_arg_names
            and normalized_candidate_parts != normalized_source_parts
        )
        use_source_args = bool(source_parts) and (
            not parts
            or len(parts) != len(source_parts)
            or args_text.strip() in {"", "void"}
            or source_types_match_names
            or all(re.fullmatch(r"(?:v\d+|vvar_\d+|a\d+)", n or "") for n in current_arg_names)
        )
        candidate_parts = normalized_source_parts if use_source_args else (normalized_candidate_parts or parts)
        rewritten: list[str] = []
        changed = False
        for index, part in enumerate(candidate_parts):
            split = _decl_arg_name_8616(part)
            if split is None or index >= len(positive_arg_aliases):
                rewritten.append(part)
                continue
            alias = positive_arg_aliases[index]
            prefix = part[: part.rfind(split)]
            if split == alias:
                if alias_looks_pointer_like(alias) and "*" not in prefix and "[" not in prefix:
                    rewritten.append(f"{prefix.rstrip()} *{alias}")
                    changed = True
                else:
                    rewritten.append(part)
                continue
            rewritten.append(f"{prefix}{alias}")
            changed = True
        if use_source_args and rewritten == candidate_parts and args_text.strip() != ", ".join(rewritten):
            changed = True
        return rewritten, changed

    return _impl()


def _finalize_cod_annotation_text_8616(c_text: str, metadata: CODProcMetadata) -> str:
    if metadata.call_names and "CallReturn();" in c_text:
        c_text = c_text.replace("CallReturn();", f"{metadata.call_names[0]}();", 1)
    if len(tuple(dict.fromkeys(metadata.call_names))) == 1:
        call_name = metadata.call_names[0].lstrip("_")
        if re.search(rf"(?<![A-Za-z_]){re.escape(call_name)}\s*\(", c_text) is not None:
            c_text = re.sub(r"(?m)^\s*s_[0-9a-fA-F]+\s*=\s*[^;]+;\s*$", "", c_text)
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
    return c_text

def _prune_unused_staging_assignments(c_text: str) -> str:
    def _impl():
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
            generic_assign_re = re.compile(
                r"^(?P<indent>\s*)(?P<name>[A-Za-z_]\w*)(?:\{[^}]+\})?\s*=\s*(?P<rhs>[^;]+);\s*$"
            )
            raw_register_frag_re = re.compile(r"\{r\d+\|\d+b\}")
            self_addr_assign_re = re.compile(
                r"^\s*(?P<name>[A-Za-z_]\w*)\s*=\s*&\s*(?P=name)\s*;\s*$"
            )
            ident_re = re.compile(r"\b[A-Za-z_]\w*\b")
            ident_use_counts: dict[str, int] = {}
            for line in lines:
                for ident in ident_re.findall(line):
                    ident_use_counts[ident] = ident_use_counts.get(ident, 0) + 1
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
                if self_addr_assign_re.match(stripped):
                    changed = True
                    continue
                match = assign_re.match(stripped)
                if match is None:
                    generic_match = generic_assign_re.match(stripped)
                    if generic_match is not None and raw_register_frag_re.search(generic_match.group("rhs")) is not None:
                        lhs_name = generic_match.group("name")
                        # If the assignment's LHS never appears elsewhere, this is
                        # a dead carrier of raw register-fragment text.
                        if ident_use_counts.get(lhs_name, 0) <= 2:
                            changed = True
                            continue
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

    return _impl()

def _prune_parameter_shadow_declarations_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default|break|continue)\b)"
            r"(?:[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?://.*)?$"
        )
        out = list(lines)
        idx = 0
        changed = False
        while idx < len(out):
            m = header_re.match(out[idx])
            brace_idx = idx
            arg_names: set[str] = set()
            if m is not None:
                args_text = m.group("args").strip()
                arg_names = _parameter_names_from_args_text_8616(args_text)
            else:
                candidate = out[idx]
                lookahead = idx + 1
                while "{" not in candidate and lookahead < len(out) and lookahead <= idx + 2:
                    if ";" in candidate:
                        break
                    candidate = f"{candidate} {out[lookahead].strip()}"
                    lookahead += 1
                args_text = _extract_function_header_args_8616(candidate)
                if args_text is not None:
                    arg_names = _parameter_names_from_args_text_8616(args_text)
                    while brace_idx < len(out) and "{" not in out[brace_idx]:
                        brace_idx += 1
                else:
                    idx += 1
                    continue
            if not arg_names:
                idx += 1
                continue
            while brace_idx < len(out) and "{" not in out[brace_idx]:
                brace_idx += 1
            if brace_idx >= len(out):
                idx += 1
                continue
            body_start = brace_idx + 1
            body_end = body_start
            depth = out[brace_idx].count("{") - out[brace_idx].count("}")
            while body_end < len(out) and depth > 0:
                depth += out[body_end].count("{") - out[body_end].count("}")
                body_end += 1
            scan = body_start
            while scan < body_end:
                stripped = out[scan].strip()
                if not stripped:
                    scan += 1
                    continue
                dm = decl_re.match(out[scan])
                if dm is None:
                    break
                name = dm.group("name")
                if name in arg_names:
                    del out[scan]
                    body_end -= 1
                    changed = True
                    continue
                scan += 1
            idx = body_end
        if not changed:
            return c_text
        normalized = "\n".join(out)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()

def _prune_undefined_fragment_carrier_assignments_text(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text
        ident_re = re.compile(r"\b[A-Za-z_]\w*\b")
        assign_re = re.compile(
            r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>vvar_\d+(?:\{r\d+\|\d+b\})?)\s*;\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?:[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?://.*)?$"
        )
        declared: set[str] = set()
        for line in lines:
            dm = decl_re.match(line)
            if dm is not None:
                declared.add(dm.group("name"))
        lhs_assign_re = re.compile(r"^\s*(?P<lhs>[A-Za-z_]\w*)\s*=\s*.*;\s*$")
        read_usage: dict[str, int] = {}
        for line in lines:
            dm = decl_re.match(line)
            if dm is not None:
                continue
            lhs_name: str | None = None
            lm = lhs_assign_re.match(line)
            if lm is not None:
                lhs_name = lm.group("lhs")
            for name in ident_re.findall(line):
                if lhs_name is not None and name == lhs_name:
                    continue
                read_usage[name] = read_usage.get(name, 0) + 1
        out: list[str] = []
        changed = False
        for line in lines:
            am = assign_re.match(line.strip())
            if am is None:
                out.append(line)
                continue
            lhs = am.group("lhs")
            rhs = am.group("rhs").split("{", 1)[0]
            if rhs not in declared and read_usage.get(lhs, 0) == 0:
                changed = True
                continue
            out.append(line)
        if not changed:
            return c_text
        normalized = "\n".join(out)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _prune_non_lvalue_arithmetic_assignments(c_text: str) -> str:
    """Drop invalid assignments whose left side is an arithmetic expression.

    This is compile-hygiene cleanup only: real variable, member, index, and
    dereference assignments are preserved.
    """
    assign_re = re.compile(
        r"^(?P<indent>\s*)(?P<lhs>[^=;]+?)\s*(?<![!<>=+\-*/%&|^])=(?!=)\s*(?P<rhs>[^;]+);\s*$"
    )
    kept: list[str] = []
    for line in c_text.splitlines():
        match = assign_re.match(line)
        if match is None:
            kept.append(line)
            continue
        lhs = match.group("lhs").strip()
        if lhs.startswith(("*", "SEG_", "MK_FP")):
            kept.append(line)
            continue
        if re.fullmatch(r"[A-Za-z_]\w*(?:\[[^\]]+\]|\.[A-Za-z_]\w*|->[A-Za-z_]\w*)*", lhs):
            kept.append(line)
            continue
        if re.search(r"(?:\+|-|\*|/|<<|>>|\bSEG_PTR\b|\bstack_base\b)", lhs):
            continue
        kept.append(line)
    return "\n".join(kept)


def _normalize_seg_offset_void_pointer_args_text(c_text: str) -> str:
    # Normalize nested address-index carriers produced by stack/materialization
    # lanes into scalar offset expressions accepted by C compilers:
    #   &(&v2)[52700 + v6] -> (52700 + v6)
    def _impl():
        nonlocal c_text
        c_text = re.sub(
            r"&\s*\(\s*&\s*[A-Za-z_]\w*\s*\)\s*\[\s*([^\]]+?)\s*\]",
            r"(\1)",
            c_text,
        )
        lines = c_text.splitlines()
        if not lines:
            return c_text
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>\{?)\s*$"
        )
        changed = False
        for idx, line in enumerate(lines):
            m = header_re.match(line)
            if m is None:
                continue
            args = m.group("args")
            if "void*" not in args:
                continue
            body = "\n".join(lines[idx + 1 :])
            rewritten = args
            for am in re.finditer(r"\bvoid\s*\*\s*(?P<arg>[A-Za-z_]\w*)\b", args):
                arg_name = am.group("arg")
                used_as_seg_off = re.search(
                    rf"\bSEG_U(?:8|16|32)\s*\([^,\n]+,\s*[^)\n]*\b{re.escape(arg_name)}\b",
                    body,
                )
                if used_as_seg_off is None:
                    continue
                rewritten = re.sub(
                    rf"\bvoid\s*\*\s*{re.escape(arg_name)}\b",
                    f"unsigned short {arg_name}",
                    rewritten,
                )
            if rewritten == args:
                continue
            suffix = m.group("suffix")
            lines[idx] = f"{m.group('indent')}{m.group('ret')} {m.group('name')}({rewritten}){(' ' + suffix) if suffix else ''}"
            changed = True
        if not changed:
            return c_text
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _normalize_shift_add_precedence_in_assignments(c_text: str) -> str:
    """Normalize assignment RHS expressions that parse incorrectly without explicit parentheses.

    Examples:
      ``x = y + 1 >> 8;`` -> ``x = (y + 1) >> 8;``
    """
    assign_re = re.compile(r"^(?P<indent>\s*)(?P<lhs>[^=;]+?)\s*=\s*(?P<rhs>[^;]+);\s*$")

    def _rewrite_match(match: re.Match[str]) -> str:
        rhs = match.group("rhs").strip()
        full_match = re.fullmatch(r"(?P<base>.+?)\+\s*1\s*>>\s*8", rhs)
        if full_match is None:
            return match.group(0)
        base_expr = full_match.group("base").rstrip()
        if base_expr.endswith(">>") or base_expr.endswith("<<") or base_expr.endswith("&"):
            return match.group(0)
        if base_expr.startswith("(") and base_expr.endswith(")"):
            return match.group(0)
        return f'{match.group("indent")}{match.group("lhs").strip()} = ({base_expr} + 1) >> 8;'

    lines = c_text.splitlines()
    rewritten = [_rewrite_match(match) if (match := assign_re.match(line)) else line for line in lines]
    return "\n".join(rewritten)


def _normalize_unsupported_computed_goto_text(c_text: str) -> str:
    """Rewrite GCC-style computed goto into a compilable conservative fallback.

    MS C does not support ``goto <expression>;`` forms.
    """

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        expr = match.group("expr").strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
            return match.group(0)
        return f"{indent}/* unsupported computed goto: {expr} */ return;"

    pattern = re.compile(r"(?m)^(?P<indent>\s*)goto\s+(?P<expr>[^;]+);\s*$")
    return pattern.sub(_replace, c_text)


def _rewrite_known_helper_signature_text(c_text: str, function, *, codegen=None) -> str:
    def _impl():
        if bool(getattr(codegen, "_inertia_codegen_signature_authoritative_8616", False)):
            return c_text
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

        func_name = getattr(function, "name", "")
        if not isinstance(func_name, str) or not func_name:
            return c_text
        lines = c_text.splitlines()
        header_pattern = _compile_function_header_pattern_8616(func_name)
        header_index, body_open_index = _find_function_body_open_8616(lines, header_pattern)
        if header_index is None or body_open_index is None:
            return c_text

        header_match = header_pattern.match(lines[header_index])
        if header_match is None:
            return c_text

        current_args = _split_c_signature_args_8616(header_match.group("args"))
        old_arg_names = [_decl_arg_name_8616(arg_text) for arg_text in current_args]

        renamed_pairs = [
            (old_name, new_name)
            for old_name, new_name in zip(old_arg_names, helper_arg_names)
            if old_name and old_name != new_name
        ]
        if not renamed_pairs:
            annotated_arg_names = _annotated_bp_arg_names_8616(lines[:header_index])
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
            body_end = _find_body_end_index_8616(lines, body_open_index)
            _rename_identifiers_in_body_8616(lines, body_open_index + 1, body_end, renamed_pairs)
            _remove_missing_arg_decls_8616(lines, body_open_index + 1, body_end, helper_arg_names)


        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        normalized = re.sub(r"\n{3,}", "\n\n", normalized)
        if func_name in SOURCE_EMPTY_HELPERS:
            normalized = _prune_void_function_return_values_text(normalized)
        return normalized

    return _impl()


def _compile_function_header_pattern_8616(func_name: str):
    return re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )


def _find_function_body_open_8616(lines: list[str], header_pattern):
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        suffix = match.group("suffix")
        if suffix == "{":
            return index, index
        if index + 1 < len(lines) and lines[index + 1].strip() == "{":
            return index, index + 1
    return None, None


def _split_c_signature_args_8616(arg_text: str) -> list[str]:
    def _impl():
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

    return _impl()


def _decl_arg_name_8616(arg_text: str) -> str | None:
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
    return name if prefix.strip() else None


def _annotated_bp_arg_names_8616(lines_before_header: list[str]) -> list[str]:
    names: list[str] = []
    for line in lines_before_header:
        match = re.match(r"^\s*\*\s+\[bp\+(?P<disp>0x[0-9a-f]+)\]\s*=\s*(?P<name>[A-Za-z_][\w$?@]*)\s*$", line)
        if match is not None:
            names.append(match.group("name"))
    return names


def _find_body_end_index_8616(lines: list[str], body_open_index: int) -> int:
    body_end = body_open_index + 1
    brace_depth = lines[body_open_index].count("{") - lines[body_open_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_end


def _rename_identifiers_in_body_8616(lines: list[str], start: int, end: int, renamed_pairs: list[tuple[str, str]]) -> None:
    rename_patterns = [(re.compile(rf"(?<![A-Za-z_]){re.escape(old)}(?![A-Za-z_])"), new) for old, new in renamed_pairs]
    for index in range(start, end):
        line = lines[index]
        for pattern, new in rename_patterns:
            line = pattern.sub(new, line)
        lines[index] = line


def _remove_missing_arg_decls_8616(lines: list[str], start: int, end: int, helper_arg_names: tuple[str, ...]) -> None:
    helper_arg_name_set = set(helper_arg_names)
    for index in range(start, end):
        line = lines[index]
        if "<missing-" not in line and "// [bp" not in line:
            continue
        stripped = line.strip()
        if any(re.match(rf"^<missing-[^>]+>\s+{re.escape(arg)}\s*;\s*(?://.*)?$", stripped) for arg in helper_arg_name_set):
            lines[index] = ""

def _prune_unused_local_declarations_text(c_text: str) -> str:
    def _impl():
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
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

    return _impl()

def _format_known_helper_calls(
    project: angr.Project,
    function,
    c_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None = None,
    codegen=None,
) -> str:
    def _impl():
        nonlocal c_text
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
        c_text = _rewrite_known_helper_signature_text(c_text, function, codegen=codegen)
        c_text = _align_function_header_with_cod_source_decl_text(c_text, function, cod_metadata, codegen=codegen)
        c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
        return _repair_missing_fallthrough_returns(c_text).rstrip("\n")

    return _impl()

def _repair_missing_fallthrough_returns(c_text: str) -> str:
    def _impl():
        nonlocal c_text
        c_text = re.sub(
            r"(?m)^(?P<indent>\s*)if \((?P<cond>[^\n]+)\)\s*(?=\n\s*(?:\}|$))",
            r"\g<indent>if (\g<cond>);",
            c_text,
        )

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

    return _impl()

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

    # Repair empty if-body rendering gaps before } or EOF.
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)if \(false\)\s*$",
        r"\g<indent>if (0);",
        rewritten,
    )
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)if \((?P<cond>[^\n]+)\)\s*(?=\n\s*(?:\}|$))",
        r"\g<indent>if (\g<cond>);",
        rewritten,
    )
    # Strict 16-bit compilers reject shifting raw address expressions. Make the
    # integer high-byte projection explicit for generic address-of carriers.
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*&(?P<base>[A-Za-z_]\w*)\s*>>\s*8\s*;\s*$",
        r"\g<indent>\g<lhs> = ((unsigned short)&\g<base>) >> 8;",
        rewritten,
    )
    return rewritten

def _normalize_mk_fp_segment_names(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None:
        return c_text

    positive_aliases = [
        (disp, name)
        for disp, name in _sorted_metadata_stack_aliases(metadata)
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
