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

from angr_platforms.X86_16.analysis_helpers import seed_calling_conventions

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
__all__ = ['_seed_scan_windows', '_entry_window_seed_targets', '_linear_function_seed_targets', '_looks_like_x86_16_function_prologue', '_looks_like_x86_16_entry_byte', '_resolve_x86_16_function_start', '_resolve_x86_16_call_target', '_infer_x86_16_linear_region', '_pick_function', '_pick_function_lean', '_x86_16_recovery_windows', '_x86_16_fast_recovery_windows', '_recover_cfg', '_recover_partial_cfg', '_function_skip_reason', '_function_recovery_score', '_function_covered_ranges', '_addr_in_ranges', '_candidate_recovery_regions', '_richest_bounded_recovery_region', '_recovery_score_good_enough', '_exact_region_recovery_looks_truncated', '_count_region_local_functions', '_function_recovery_truncated', '_needs_pre_entry_body_supplement', '_prioritized_pre_entry_follow_on_targets', '_mark_function_recovery_truncated', '_recover_candidate_function_pair', '_interesting_functions', '_rank_function_cfg_pairs_for_display', '_expanded_exe_discovery_limit', '_supplement_cached_seeded_recovery', '_store_catalog_address_cache', '_load_catalog_address_cache', '_supplement_functions_from_prologue_scan', '_rank_gap_scan_candidate_addrs', '_rank_prologue_scan_candidate_addrs', '_relocation_seed_targets', '_rank_exe_function_seeds', '_recover_fast_seed_functions', '_recover_fast_exe_catalog', '_recover_hidden_sidecar_display_pairs', '_rank_hidden_sidecar_pairs_for_display_throughput', '_recover_cached_function_pairs', '_candidate_recovery_cache_key', '_lookup_candidate_recovery_cache', '_store_candidate_recovery_cache', '_persistent_recovery_attempt_cache_key', '_lookup_persistent_recovery_timeout', '_recover_candidate_with_timeout', '_recover_seeded_exe_functions', '_direct_recovery_inventory_count', '_fallback_entry_function', '_recover_lst_function', '_recover_ranked_binary_function', '_make_placeholder_function', '_is_zero_filled_region', '_rank_labeled_function_entries', '_sidecar_label_ranking_cache_key', '_rank_labeled_function_entries_cached', '_select_sidecar_showcase_entries', '_format_sidecar_function_catalog', '_recover_blob_entry_function', '_recover_direct_addr_function']

def _seed_scan_windows(project: angr.Project) -> list[tuple[int, int]]:
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return []

    image_end = linked_base + max_addr + 1
    windows: list[tuple[int, int]] = []

    metadata = getattr(project, "_inertia_lst_metadata", None)
    if metadata is not None:
        for start, end in sorted(getattr(metadata, "code_ranges", {}).values()):
            if start >= end:
                continue
            if _lst_code_label(metadata, start, project.entry) is None:
                continue
            windows.append((max(linked_base, start), min(image_end, end)))

    for span in getattr(main_object, "mz_segment_spans", ()):
        start = max(linked_base, getattr(span, "start_linear", linked_base))
        end = min(image_end, getattr(span, "end_linear", image_end))
        if start < end:
            windows.append((start, end))

    if not windows:
        return [(linked_base, image_end)]

    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged

def _entry_window_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
    entry_window: int = 0x200,
) -> set[int]:
    start = max(linked_base, project.entry)
    end = min(linked_base + len(code), project.entry + max(1, entry_window))
    if start >= end:
        return set()

    entry_targets: set[int] = set()
    start_offset = start - linked_base
    end_offset = end - linked_base
    for offset in range(start_offset, end_offset):
        opcode = code[offset]
        callsite = linked_base + offset
        if opcode == 0xE8 and offset + 2 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            entry_targets.add(callsite + 3 + rel)
        elif opcode == 0x9A and offset + 4 < len(code):
            off = int.from_bytes(code[offset + 1 : offset + 3], "little")
            seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
            entry_targets.add(linked_base + (seg << 4) + off)
        elif opcode == 0xE9 and offset + 2 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            entry_targets.add(callsite + 3 + rel)
        elif opcode == 0xEB and offset + 1 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
            entry_targets.add(callsite + 2 + rel)
    return entry_targets

def _linear_function_seed_targets(
    project: angr.Project,
    start_addr: int,
    *,
    max_scan: int = 0x200,
    include_jumps: bool = True,
) -> set[int]:
    try:
        code = bytes(project.loader.memory.load(start_addr, max_scan))
    except Exception:
        return set()
    if not code:
        return set()

    targets: set[int] = set()
    offset = 0
    while offset < len(code):
        window = code[offset : offset + 16]
        if not window:
            break
        insn = next(project.arch.capstone.disasm(window, start_addr + offset, 1), None)
        if insn is None or insn.size <= 0:
            break
        opcode = code[offset]
        if opcode == 0xE8 and offset + 2 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            targets.add(insn.address + 3 + rel)
        elif opcode == 0x9A and offset + 4 < len(code):
            off = int.from_bytes(code[offset + 1 : offset + 3], "little")
            seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
            linked_base = getattr(getattr(project.loader, "main_object", None), "linked_base", 0)
            targets.add(linked_base + (seg << 4) + off)
        elif include_jumps and opcode == 0xE9 and offset + 2 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            targets.add(insn.address + 3 + rel)
        elif include_jumps and opcode == 0xEB and offset + 1 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
            targets.add(insn.address + 2 + rel)
        offset += insn.size
        if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
            break
    return targets

def _looks_like_x86_16_function_prologue(code: bytes, offset: int) -> bool:
    window = code[offset : offset + 4]
    return window.startswith(b"\x55\x8B\xEC")

def _looks_like_x86_16_entry_byte(code: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(code):
        return False
    return code[offset] not in {0x00, 0x90, 0xCC}

def _resolve_x86_16_function_start(code: bytes, offset: int, *, max_padding: int = 0x10) -> int | None:
    if offset < 0 or offset >= len(code):
        return None
    if _looks_like_x86_16_function_prologue(code, offset):
        return offset
    padded = offset
    limit = min(len(code), offset + max_padding)
    while padded < limit and code[padded] in {0x00, 0x90, 0xCC}:
        padded += 1
    if padded < len(code) and _looks_like_x86_16_function_prologue(code, padded):
        return padded
    return None

def _resolve_x86_16_call_target(code: bytes, offset: int) -> int | None:
    canonical = _resolve_x86_16_function_start(code, offset)
    if canonical is not None:
        return canonical
    if _looks_like_x86_16_entry_byte(code, offset):
        return offset
    return None

def _infer_x86_16_linear_region(project: angr.Project, start_addr: int, *, window: int) -> tuple[int, int]:
    end_limit = start_addr + max(window, 1)
    current = start_addr
    ah = None
    padding_bytes = {0x00, 0x90, 0xCC}

    while current < end_limit:
        try:
            chunk = bytes(project.loader.memory.load(current, 16))
        except Exception:
            break
        if not chunk:
            break

        insn = next(project.arch.capstone.disasm(chunk, current, 1), None)
        if insn is None or insn.size <= 0:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        if text.startswith("mov ah, "):
            try:
                ah = int(text.split(", ", 1)[1], 0)
            except ValueError:
                ah = None
        elif text.startswith("mov ax, "):
            try:
                ax = int(text.split(", ", 1)[1], 0)
            except ValueError:
                ax = None
            if ax is not None:
                ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic in {"ret", "retf", "iret"}:
            if current >= end_limit:
                break
            try:
                lookahead = bytes(project.loader.memory.load(current, min(16, end_limit - current)))
            except Exception:
                break
            if lookahead and all(byte in padding_bytes for byte in lookahead):
                break
        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break

    return start_addr, max(start_addr + 1, current)

def _pick_function(
    project: angr.Project,
    addr: int | None,
    *,
    regions=None,
    data_references: bool | None = None,
    force_smart_scan: bool | None = None,
):
    target_addr = project.entry if addr is None else addr
    data_refs = True if data_references is None else data_references
    if force_smart_scan is None and project.arch.name == "86_16" and regions is not None:
        smart_scan_modes = (False, True)
    else:
        smart_scan_modes = (force_smart_scan,)

    cfg = None
    for complete_scan in (False, True) if project.arch.name == "86_16" else (False,):
        for smart_scan in smart_scan_modes:
            try:
                cfg = project.analyses.CFGFast(
                    start_at_entry=False,
                    function_starts=[target_addr],
                    regions=regions,
                    normalize=True,
                    data_references=data_refs,
                    force_smart_scan=smart_scan,
                    force_complete_scan=complete_scan,
                )
            except Exception as ex:  # noqa: BLE001
                logging.getLogger(__name__).debug(
                    "CFGFast recovery attempt failed for %s (complete=%s smart=%s): %s",
                    hex(target_addr),
                    complete_scan,
                    smart_scan,
                    ex,
                )
                continue
            if target_addr in cfg.functions:
                break
        if cfg is not None and target_addr in cfg.functions:
            break
    if cfg is None or target_addr not in cfg.functions:
        raise KeyError(f"Function {target_addr:#x} was not recovered by CFGFast.")
    function = cfg.functions[target_addr]

    if project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        extended_cfg = extend_cfg_for_neighbor_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        patch_interrupt_service_call_sites(function, getattr(project.loader.main_object, "binary", None))
    seed_calling_conventions(cfg)

    return cfg, function

def _pick_function_lean(
    project: angr.Project,
    addr: int | None,
    *,
    regions=None,
    data_references: bool = False,
    extend_far_calls: bool = True,
):
    """
    Recover a known entry point with a deliberately cheap CFGFast pass.

    This is used as an early fast path for COD procedures that are dominated by
    helper calls. For those procedures, indirect-jump resolution and cross-
    reference discovery are often unnecessary and can dominate the recovery
    budget before the function is even identified.
    """

    target_addr = project.entry if addr is None else addr
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[target_addr],
        regions=regions,
        normalize=False,
        data_references=data_references,
        force_smart_scan=False,
        force_complete_scan=False,
        resolve_indirect_jumps=False,
        function_prologues=False,
        symbols=False,
        cross_references=False,
    )
    if target_addr not in cfg.functions:
        raise KeyError(f"Function {target_addr:#x} was not recovered by CFGFast.")

    function = cfg.functions[target_addr]
    if extend_far_calls and project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        extended_cfg = extend_cfg_for_neighbor_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        patch_interrupt_service_call_sites(function, getattr(project.loader.main_object, "binary", None))
    seed_calling_conventions(cfg)
    return cfg, function

def _x86_16_recovery_windows(window: int, *, low_memory: bool = False) -> tuple[int, ...]:
    base_window = max(window, 0x80 if low_memory else 0x200)
    return tuple(base_window * factor for factor in (1, 2, 4, 8, 16))

def _x86_16_fast_recovery_windows(window: int, *, low_memory: bool = False) -> tuple[int, ...]:
    candidate_windows = (0x40, 0x80, 0x100) if low_memory else (0x80, 0x100, 0x200)
    windows: list[int] = []
    for candidate in candidate_windows:
        if window <= candidate:
            effective_window = window
        else:
            effective_window = candidate
        if effective_window not in windows:
            windows.append(effective_window)
    if not windows:
        windows.append(window)
    return tuple(windows)

def _recover_cfg(
    project: angr.Project,
    binary_path: Path,
    *,
    base_addr: int,
    window: int,
    low_memory: bool = False,
):
    print(f"[dbg] recover_cfg: entry={hex(project.entry)} base_addr={hex(base_addr)} window={hex(window)} binary={binary_path}")
    sys.stdout.flush()
    if binary_path.suffix.lower() == ".com":
        force_smart_scan = False if project.arch.name == "86_16" else None
        regions = [infer_com_region(binary_path, base_addr=base_addr, window=window, arch=project.arch)]
        cfg = project.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[project.entry],
            regions=regions,
            normalize=True,
            force_complete_scan=False,
            data_references=not low_memory,
            force_smart_scan=force_smart_scan,
        )
    else:
        print("[dbg] calling CFGFast (non-COM path)")
        sys.stdout.flush()
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
            data_references=not low_memory,
        )
        print("[dbg] CFGFast returned")
        sys.stdout.flush()

    if project.arch.name == "86_16" and project.entry in cfg.functions:
        extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
        extended_cfg = extend_cfg_for_neighbor_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
        patch_interrupt_service_call_sites(cfg.functions[project.entry], binary_path)
    seed_calling_conventions(cfg)
    return cfg

def _recover_partial_cfg(
    project: angr.Project,
    *,
    window: int,
    low_memory: bool = False,
):
    """
    Recover a bounded x86-16 catalog around the entry point.

    This is the whole-binary fallback for awkward real-mode executables such as
    packed startup stubs. It keeps CFGFast inside narrow entry windows instead
    of asking angr to recover the entire executable at once.
    """

    candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
    last_error: Exception | None = None
    for candidate_window in candidate_windows:
        project._inertia_decompiler_stage = f"catalog:narrow:{candidate_window:#x}"
        if project.arch.name == "86_16":
            regions = [_infer_x86_16_linear_region(project, project.entry, window=candidate_window)]
        else:
            regions = [(project.entry, project.entry + candidate_window)]
        for data_refs in (False, True) if project.arch.name == "86_16" else (False,):
            try:
                cfg = project.analyses.CFGFast(
                    start_at_entry=False,
                    function_starts=[project.entry],
                    regions=regions,
                    normalize=True,
                    force_complete_scan=False,
                    data_references=data_refs,
                    force_smart_scan=False if project.arch.name == "86_16" else None,
                )
            except Exception as ex:  # noqa: BLE001
                last_error = ex
                continue
            if project.entry not in cfg.functions:
                last_error = KeyError(f"Function {project.entry:#x} was not recovered by CFGFast.")
                continue
            if project.arch.name == "86_16":
                extended_cfg = extend_cfg_for_far_calls(
                    project,
                    cfg.functions[project.entry],
                    entry_window=(regions[0][1] - regions[0][0]) if regions else candidate_window,
                )
                if extended_cfg is not None and project.entry in extended_cfg.functions:
                    cfg = extended_cfg
                extended_cfg = extend_cfg_for_neighbor_calls(
                    project,
                    cfg.functions[project.entry],
                    entry_window=(regions[0][1] - regions[0][0]) if regions else candidate_window,
                )
                if extended_cfg is not None and project.entry in extended_cfg.functions:
                    cfg = extended_cfg
                patch_interrupt_service_call_sites(
                    cfg.functions[project.entry],
                    getattr(project.loader.main_object, "binary", None),
                )
            seed_calling_conventions(cfg)
            return cfg

    if last_error is not None:
        raise last_error
    raise KeyError(f"Function {project.entry:#x} was not recovered by bounded CFGFast.")

def _function_skip_reason(function):
    if getattr(function, "is_simprocedure", False):
        return "SimProcedure (DOS helper)"
    addr = getattr(function, "addr", None)
    if isinstance(addr, int) and addr >= DOS_SERVICE_BASE_ADDR:
        return "DOS service address"
    return None

def _function_recovery_score(function) -> tuple[int, int]:
    blocks = tuple(getattr(function, "blocks", ()) or ())
    if not blocks:
        return (0, 0)
    total_bytes = sum(max(0, getattr(block, "size", 0)) for block in blocks)
    return (len(blocks), total_bytes)

def _function_covered_ranges(function) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for block in tuple(getattr(function, "blocks", ()) or ()):
        addr = getattr(block, "addr", None)
        size = max(0, getattr(block, "size", 0))
        if not isinstance(addr, int) or size <= 0:
            continue
        ranges.append((addr, addr + size))
    if not ranges:
        addr = getattr(function, "addr", None)
        score = _function_recovery_score(function)
        if isinstance(addr, int) and score[1] > 0:
            ranges.append((addr, addr + score[1]))
    if not ranges:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged

def _addr_in_ranges(addr: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= addr < end for start, end in ranges)

def _candidate_recovery_regions(
    metadata: LSTMetadata | None,
    addr: int,
    *,
    image_end: int,
    region_span: int,
    project_entry: int,
) -> list[tuple[int, int]]:
    exact_region = _lst_code_region(metadata, addr)
    if exact_region is not None:
        return [exact_region]
    regions: list[tuple[int, int]] = []
    candidate_windows = _x86_16_fast_recovery_windows(region_span)
    if addr < project_entry:
        candidate_windows = (candidate_windows[-1],)
    for candidate_window in candidate_windows:
        region = (addr, min(addr + candidate_window, image_end))
        if region not in regions:
            regions.append(region)
    return regions

def _richest_bounded_recovery_region(
    addr: int,
    *,
    image_end: int,
    region_span: int,
) -> tuple[int, int]:
    return (addr, min(addr + _x86_16_recovery_windows(region_span)[-1], image_end))

def _recovery_score_good_enough(score: tuple[int, int]) -> bool:
    blocks, total_bytes = score
    return total_bytes >= 0x40 or blocks >= 4

def _exact_region_recovery_looks_truncated(
    function,
    exact_region: tuple[int, int] | None,
) -> bool:
    if exact_region is None:
        return False
    region_size = max(0, exact_region[1] - exact_region[0])
    if region_size < 0x40:
        return False
    _blocks, total_bytes = _function_recovery_score(function)
    return total_bytes < max(0x20, region_size // 3)

def _count_region_local_functions(cfg, exact_region: tuple[int, int] | None) -> int:
    if exact_region is None or cfg is None:
        return 0
    functions = getattr(cfg, "functions", None)
    if functions is None:
        return 0
    start, end = exact_region
    return sum(1 for addr in functions.keys() if isinstance(addr, int) and start <= addr < end)

def _function_recovery_truncated(function) -> bool:
    info = getattr(function, "info", None)
    return isinstance(info, dict) and bool(info.get("x86_16_recovery_truncated"))

def _needs_pre_entry_body_supplement(function, project_entry: int) -> bool:
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int) or addr >= project_entry:
        return False
    return _function_recovery_truncated(function) or _function_recovery_score(function)[1] <= 0x20

def _prioritized_pre_entry_follow_on_targets(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    covered_ranges: list[tuple[int, int]],
    existing_addrs: set[int],
    image_end: int,
) -> list[int]:
    main_object = getattr(project.loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(linked_base, int):
        return []

    prioritized: list[int] = []
    queued = set(existing_addrs)

    def _record(target_addrs) -> None:
        for target_addr in target_addrs:
            if not isinstance(target_addr, int):
                continue
            if target_addr in queued or _addr_in_ranges(target_addr, covered_ranges):
                continue
            if not (linked_base <= target_addr < image_end):
                continue
            prioritized.append(target_addr)
            queued.add(target_addr)

    gap_candidates = _rank_gap_scan_candidate_addrs(
        project,
        function_cfg_pairs,
        covered_ranges,
        queued,
        image_end=image_end,
    )
    _record(gap_candidates)

    pre_entry_functions = [
        function
        for _cfg, function in function_cfg_pairs
        if _needs_pre_entry_body_supplement(function, getattr(project, "entry", 0))
    ]
    for function in pre_entry_functions:
        _record(_linear_function_seed_targets(project, function.addr, include_jumps=False))

    for function in pre_entry_functions:
        neighbor_targets: list[int] = []
        for target in collect_neighbor_call_targets(function):
            target_addr = getattr(target, "target_addr", None)
            if isinstance(target_addr, int):
                neighbor_targets.append(target_addr)
        _record(neighbor_targets)

    return prioritized

def _mark_function_recovery_truncated(function, truncated: bool) -> None:
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_recovery_truncated"] = truncated

def _recover_candidate_function_pair(
    candidate_project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata: LSTMetadata | None,
    project_entry: int,
    region_span: int,
):
    block = candidate_project.factory.block(candidate_addr, size=8, opt_level=0)
    insns = block.capstone.insns
    if len(insns) < 1:
        raise KeyError(f"Function {candidate_addr:#x} does not have a valid first instruction.")
    exact_region = _lst_code_region(metadata, candidate_addr)
    candidate_regions = _candidate_recovery_regions(
        metadata,
        candidate_addr,
        image_end=image_end,
        region_span=region_span,
        project_entry=project_entry,
    )
    best_pair: tuple[object, object] | None = None
    best_score = (-1, -1)
    last_error: Exception | None = None
    for candidate_region in candidate_regions:
        try:
            recovered_pair = _pick_function_lean(
                candidate_project,
                candidate_addr,
                regions=[candidate_region],
                data_references=False,
                extend_far_calls=False,
            )
            score = _function_recovery_score(recovered_pair[1])
            if score > best_score:
                best_pair = recovered_pair
                best_score = score
            if (
                _recovery_score_good_enough(score)
                and not (candidate_addr < project_entry and score[1] <= 0x20 and candidate_region != candidate_regions[-1])
            ):
                break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
    truncated = False
    if best_pair is not None and exact_region is not None and _exact_region_recovery_looks_truncated(best_pair[1], exact_region):
        truncated = True
        bounded_region = _richest_bounded_recovery_region(candidate_addr, image_end=image_end, region_span=region_span)
        richer_best_pair: tuple[object, object] | None = None
        richer_best_score = best_score
        for data_references in (False, True):
            try:
                richer_pair = _pick_function(
                    candidate_project,
                    candidate_addr,
                    regions=[bounded_region],
                    data_references=data_references,
                    force_smart_scan=False,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
            richer_score = _function_recovery_score(richer_pair[1])
            if richer_score > richer_best_score:
                richer_best_pair = richer_pair
                richer_best_score = richer_score
        if richer_best_pair is not None:
            best_pair = richer_best_pair
            best_score = richer_best_score
            truncated = False
    if (
        best_pair is not None
        and candidate_addr < project_entry
        and best_score[1] <= 0x20
        and candidate_regions
    ):
        truncated = True
        try:
            richer_pair = _pick_function(
                candidate_project,
                candidate_addr,
                regions=[_richest_bounded_recovery_region(candidate_addr, image_end=image_end, region_span=region_span)],
                data_references=True,
                force_smart_scan=False,
            )
            richer_score = _function_recovery_score(richer_pair[1])
            if richer_score > best_score:
                best_pair = richer_pair
                best_score = richer_score
        except Exception as exc:  # noqa: BLE001
            last_error = exc
    if best_pair is not None:
        _mark_function_recovery_truncated(best_pair[1], truncated)
        return best_pair
    if last_error is not None:
        raise last_error
    raise KeyError(f"Function {candidate_addr:#x} was not recovered.")

def _interesting_functions(cfg, *, limit: int | None):
    functions = []
    skipped = 0
    for function in sorted(cfg.functions.values(), key=lambda function: function.addr):
        if function.is_plt or function.name.startswith("Unresolvable"):
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            print(f"[dbg] skipping {function.addr:#x} {function.name}: {reason}")
            skipped += 1
            continue
        functions.append(function)
    total = len(functions) + skipped
    if limit is not None and limit > 0:
        functions = functions[:limit]
    return functions, total

def _rank_function_cfg_pairs_for_display(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
) -> list[tuple[object, object]]:
    if not function_cfg_pairs:
        return []
    entry_addr = getattr(project, "entry", None)
    direct_entry_targets = _linear_function_seed_targets(project, entry_addr, max_scan=0x180, include_jumps=False)

    def _display_metrics(function) -> tuple[int, int]:
        complexity_blocks, complexity_bytes = _function_complexity(function)
        recovery_blocks, recovery_bytes = _function_recovery_score(function)
        return (max(complexity_blocks, recovery_blocks), max(complexity_bytes, recovery_bytes))

    def _body_seed_rank(item: tuple[object, object]) -> tuple[int, int, int, int, int]:
        _cfg, function = item
        addr = getattr(function, "addr", None)
        block_count, byte_count = _display_metrics(function)
        tiny_wrapper_like = int(block_count <= 3 and byte_count <= 0x20 and not _function_recovery_truncated(function))
        direct_entry_rank = 0 if isinstance(addr, int) and addr in direct_entry_targets else 1
        truncation_rank = 0 if _function_recovery_truncated(function) else 1
        distance = abs(addr - entry_addr) if isinstance(addr, int) and isinstance(entry_addr, int) else 0
        return (tiny_wrapper_like, truncation_rank, direct_entry_rank, -byte_count, distance)

    body_seed_candidates = [
        item
        for item in function_cfg_pairs
        if isinstance(getattr(item[1], "addr", None), int) and item[1].addr < entry_addr
    ]
    primary_body_seed = min(body_seed_candidates, key=_body_seed_rank)[1].addr if body_seed_candidates else None
    body_targets = (
        _linear_function_seed_targets(project, primary_body_seed, include_jumps=False)
        if isinstance(primary_body_seed, int)
        else set()
    )

    def _meaningful_pre_entry_body(addr: int | None, byte_count: int, truncated: bool) -> bool:
        return isinstance(addr, int) and isinstance(entry_addr, int) and addr < entry_addr and (truncated or byte_count > 0x20)

    def _priority(item: tuple[object, object]) -> tuple[int, int, int, int, int]:
        _cfg, function = item
        addr = getattr(function, "addr", 0)
        block_count, byte_count = _display_metrics(function)
        truncated = _function_recovery_truncated(function)
        tiny_wrapper_like = int(block_count <= 3 and byte_count <= 0x20 and not truncated)
        meaningful_pre_entry_body = _meaningful_pre_entry_body(addr, byte_count, truncated)
        if addr == entry_addr:
            bucket = 0
        elif isinstance(primary_body_seed, int) and addr == primary_body_seed:
            bucket = 1
        elif meaningful_pre_entry_body and addr in body_targets:
            bucket = 2
        elif meaningful_pre_entry_body:
            bucket = 3
        elif addr in body_targets:
            bucket = 4
        elif addr in direct_entry_targets:
            bucket = 5
        elif isinstance(addr, int) and addr < entry_addr:
            bucket = 6
        else:
            bucket = 7
        distance = abs(addr - entry_addr) if isinstance(addr, int) and isinstance(entry_addr, int) else 0
        return (bucket, tiny_wrapper_like, block_count, byte_count, distance)

    return sorted(function_cfg_pairs, key=_priority)

def _expanded_exe_discovery_limit(limit: int | None) -> int | None:
    if limit is None or limit <= 0:
        return None
    return max(limit * 2, limit + 4)

def _supplement_cached_seeded_recovery(
    project: angr.Project,
    cached_recovered: list[tuple[object, object]],
    cached_addrs: list[int],
    *,
    region_span: int,
    per_function_timeout: int,
    limit: int | None,
    cache_key: dict[str, object] | None,
) -> tuple[list[tuple[object, object]], list[int]]:
    cached_seen = {function.addr for _cfg, function in cached_recovered if isinstance(getattr(function, "addr", None), int)}
    cached_covered_ranges: list[tuple[int, int]] = []
    for _cfg, function in cached_recovered:
        cached_covered_ranges.extend(_function_covered_ranges(function))
    cached_pre_entry = [
        function
        for _cfg, function in cached_recovered
        if isinstance(getattr(function, "addr", None), int) and function.addr < project.entry
    ]
    needs_body_supplement = not cached_pre_entry or all(
        _function_recovery_truncated(function) or _function_recovery_score(function)[1] <= 0x20
        for function in cached_pre_entry
    )
    if not needs_body_supplement:
        return cached_recovered, cached_addrs

    main_object = getattr(project.loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
    supplemental_pairs: list[tuple[object, object]] = []
    if image_end is not None:
        prioritized_candidates = _prioritized_pre_entry_follow_on_targets(
            project,
            cached_recovered,
            covered_ranges=cached_covered_ranges,
            existing_addrs=set(cached_addrs) | {project.entry},
            image_end=image_end,
        )
        if prioritized_candidates:
            supplemental_pairs = _supplement_functions_from_prologue_scan(
                project,
                set(cached_addrs),
                candidate_addrs=prioritized_candidates,
                region_span=region_span,
                recover_limit=1 if limit is None else max(1, min(limit, 2)),
                per_function_timeout=per_function_timeout,
            )
    if not supplemental_pairs:
        supplemental_pairs = _supplement_functions_from_prologue_scan(
            project,
            set(cached_addrs),
            region_span=region_span,
            recover_limit=1 if limit is None else max(1, min(limit, 2)),
            per_function_timeout=per_function_timeout,
        )
    if not supplemental_pairs:
        return cached_recovered, cached_addrs

    for function_cfg, function in supplemental_pairs:
        if function.addr in cached_seen:
            continue
        cached_recovered.append((function_cfg, function))
        cached_addrs.append(function.addr)
        cached_seen.add(function.addr)
    cached_recovered = _rank_function_cfg_pairs_for_display(project, cached_recovered)
    cached_addrs = [function.addr for _cfg, function in cached_recovered]
    if cache_key is not None:
        _store_cache_json("recovery", cache_key, {"addrs": cached_addrs})
    return cached_recovered, cached_addrs

def _store_catalog_address_cache(
    project: angr.Project,
    binary_path: Path,
    function_cfg_pairs: list[tuple[object, object]],
) -> None:
    cache_key = _recovery_cache_key(
        binary_path=binary_path,
        kind="display_catalog_addrs",
        extra={
            "entry": getattr(project, "entry", None),
            "arch": getattr(getattr(project, "arch", None), "name", None),
        },
    )
    if cache_key is None:
        return
    addrs = [
        getattr(function, "addr", None)
        for _cfg, function in function_cfg_pairs
        if isinstance(getattr(function, "addr", None), int)
    ]
    _store_cache_json("recovery", cache_key, {"addrs": addrs})

def _load_catalog_address_cache(project: angr.Project, binary_path: Path) -> list[int]:
    cache_key = _recovery_cache_key(
        binary_path=binary_path,
        kind="display_catalog_addrs",
        extra={
            "entry": getattr(project, "entry", None),
            "arch": getattr(getattr(project, "arch", None), "name", None),
        },
    )
    cached = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if not isinstance(cached, dict):
        return []
    addrs = cached.get("addrs")
    if not isinstance(addrs, list) or not all(isinstance(addr, int) for addr in addrs):
        return []
    return addrs

def _supplement_functions_from_prologue_scan(
    project: angr.Project,
    existing_addrs: set[int],
    *,
    candidate_addrs: list[int] | None = None,
    search_span: int = 0x2000,
    region_span: int = 0x120,
    scan_limit: int = 8,
    recover_limit: int = 1,
    per_function_timeout: int = 2,
):
    if project.arch.name != "86_16":
        return []

    ranked_candidates = (
        candidate_addrs
        if candidate_addrs is not None
        else _rank_prologue_scan_candidate_addrs(
            project,
            existing_addrs,
            search_span=search_span,
        )
    )
    if not ranked_candidates:
        return []
    main_object = getattr(project.loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    binary_path = getattr(main_object, "binary", None)
    if not isinstance(linked_base, int):
        return []
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(max_addr, int):
        return []
    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []

    supplemental: list[tuple[object, object]] = []
    scanned = 0
    for addr in ranked_candidates:
        if len(supplemental) >= recover_limit or scanned >= scan_limit:
            break
        scanned += 1

        def _recover_candidate(candidate_addr=addr):
            candidate_project = project
            if binary_path is not None:
                candidate_project = _build_project_cached(
                    str(Path(binary_path)),
                    force_blob=False,
                    base_addr=linked_base,
                    entry_point=project.entry,
                )
            return _pick_function_lean(
                candidate_project,
                candidate_addr,
                regions=[
                    (
                        candidate_addr,
                        min(candidate_addr + region_span, linked_base + len(code)),
                    )
                ],
                data_references=False,
                extend_far_calls=False,
            )

        try:
            function_cfg, function = _run_with_timeout_in_daemon_thread(
                _recover_candidate,
                timeout=per_function_timeout,
                thread_name_prefix="supplement",
            )
        except FuturesTimeoutError:
            continue
        except Exception:
            continue

        if function.addr in existing_addrs:
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            continue
        existing_addrs.add(function.addr)
        supplemental.append((function_cfg, function))

    if supplemental:
        print(
            f"/* supplemental prologue scan recovered {len(supplemental)} additional function(s) near entry. */"
        )
    return supplemental

def _rank_gap_scan_candidate_addrs(
    project: angr.Project,
    recovered_function_pairs: list[tuple[object, object]],
    covered_ranges: list[tuple[int, int]],
    existing_addrs: set[int],
    *,
    image_end: int,
    search_span: int = 0x2000,
) -> list[int]:
    if project.arch.name != "86_16":
        return []
    if getattr(getattr(project, "arch", None), "capstone", None) is None:
        return []

    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []

    max_addr = getattr(main_object, "max_addr", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []

    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []

    merged_ranges: list[tuple[int, int]] = []
    for start, end in sorted(covered_ranges):
        start = max(linked_base, min(start, image_end))
        end = max(linked_base, min(end, image_end))
        if start >= end:
            continue
        if not merged_ranges or start > merged_ranges[-1][1]:
            merged_ranges.append((start, end))
        else:
            merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], end))

    gap_ranges: list[tuple[int, int]] = []
    cursor = linked_base
    for start, end in merged_ranges:
        if cursor < start:
            gap_ranges.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < image_end:
        gap_ranges.append((cursor, image_end))

    ranked_candidates: dict[int, tuple[int, int, int]] = {}

    def _record(addr: int, source_rank: int, gap_start: int, subrank: int) -> None:
        if not (linked_base <= addr < image_end):
            return
        if addr in existing_addrs or _addr_in_ranges(addr, merged_ranges):
            return
        current = ranked_candidates.get(addr)
        candidate = (source_rank, gap_start, subrank)
        if current is None or candidate < current:
            ranked_candidates[addr] = candidate

    for _cfg, function in recovered_function_pairs:
        for block in tuple(getattr(function, "blocks", ()) or ()):
            block_addr = getattr(block, "addr", None)
            block_size = max(0, getattr(block, "size", 0))
            if not isinstance(block_addr, int) or block_size <= 0:
                continue
            try:
                block_targets = _linear_function_seed_targets(
                    project,
                    block_addr,
                    max_scan=min(block_size, search_span),
                    include_jumps=False,
                )
            except Exception:
                continue
            for target_addr in block_targets:
                _record(target_addr, 1, block_addr, target_addr)

    align_bytes = {0x00, 0x90, 0xCC}
    for gap_start, gap_end in gap_ranges:
        scan_end = min(gap_end, gap_start + search_span)
        if scan_end - gap_start < 3:
            continue
        try:
            gap_code = bytes(main_object.memory.load(gap_start - linked_base, scan_end - gap_start))
        except Exception:
            continue

        offset = 0
        while offset <= len(gap_code) - 3:
            if gap_code[offset : offset + 3] == b"\x55\x8b\xec":
                addr = gap_start + offset
                try:
                    block = project.factory.block(addr, size=16, opt_level=0)
                except Exception:
                    pass
                else:
                    insns = block.capstone.insns
                    if (
                        len(insns) >= 2
                        and insns[0].mnemonic == "push"
                        and insns[0].op_str == "bp"
                        and insns[1].mnemonic == "mov"
                        and insns[1].op_str == "bp, sp"
                    ):
                        _record(addr, 0, gap_start, offset)

            window = gap_code[offset : offset + 16]
            insn = next(project.arch.capstone.disasm(window, gap_start + offset, 1), None)
            if insn is None or insn.size <= 0:
                break
            if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
                next_offset = offset + insn.size
                skipped_alignment = False
                while next_offset < len(gap_code) and gap_code[next_offset] in align_bytes:
                    skipped_alignment = True
                    next_offset += 1
                if next_offset < len(gap_code):
                    candidate_addr = gap_start + next_offset
                    if skipped_alignment or gap_code[next_offset : next_offset + 3] == b"\x55\x8b\xec":
                        _record(candidate_addr, 2, gap_start, next_offset)
            offset += insn.size

    return [addr for addr, _meta in sorted(ranked_candidates.items(), key=lambda item: (*item[1], item[0]))]

def _rank_prologue_scan_candidate_addrs(
    project: angr.Project,
    existing_addrs: set[int],
    *,
    search_span: int = 0x2000,
) -> list[int]:
    if project.arch.name != "86_16":
        return []

    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []

    max_addr = getattr(main_object, "max_addr", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []

    try:
        code = main_object.memory.load(0, max_addr + 1)
    except Exception:
        return []

    upper_bound = min(project.entry + search_span, linked_base + len(code))
    ranked_candidates: list[tuple[int, int, int]] = []
    for offset in range(len(code) - 2):
        if code[offset : offset + 3] != b"\x55\x8b\xec":
            continue
        addr = linked_base + offset
        if not (project.entry <= addr < upper_bound) or addr in existing_addrs:
            continue
        try:
            block = project.factory.block(addr, size=16, opt_level=0)
        except Exception:
            continue
        insns = block.capstone.insns
        if (
            len(insns) < 2
            or insns[0].mnemonic != "push"
            or insns[0].op_str != "bp"
            or insns[1].mnemonic != "mov"
            or insns[1].op_str != "bp, sp"
        ):
            continue
        has_dos_interrupt = any(insn.mnemonic == "int" and insn.op_str == "0x21" for insn in insns[:8])
        ranked_candidates.append((0 if has_dos_interrupt else 1, -offset, addr))
    return [addr for _priority, _neg_offset, addr in sorted(ranked_candidates)]

def _relocation_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
) -> tuple[set[int], set[int]]:
    main_object = getattr(project.loader, "main_object", None)
    relocation_entries = getattr(main_object, "mz_relocation_entries", ()) if main_object is not None else ()
    if not relocation_entries:
        return set(), set()

    strong_targets: set[int] = set()
    weak_targets: set[int] = set()
    image_end = linked_base + len(code)

    for reloc_offset, reloc_segment in relocation_entries:
        if not isinstance(reloc_offset, int) or not isinstance(reloc_segment, int):
            continue
        reloc_addr = linked_base + (reloc_segment << 4) + reloc_offset
        seg_index = reloc_addr - linked_base
        if seg_index < 0 or seg_index + 1 >= len(code):
            continue
        seg = int.from_bytes(code[seg_index : seg_index + 2], "little")
        if seg_index >= 2:
            off = int.from_bytes(code[seg_index - 2 : seg_index], "little")
            target = linked_base + (seg << 4) + off
            if linked_base <= target < image_end:
                weak_targets.add(target)
                opcode_index = seg_index - 3
                if opcode_index >= 0 and code[opcode_index] in {0x9A, 0xEA}:
                    strong_targets.add(target)
    weak_targets.difference_update(strong_targets)
    return strong_targets, weak_targets

def _rank_exe_function_seeds(project: angr.Project) -> list[int]:
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []
    binary_path = getattr(main_object, "binary", None)
    max_addr = getattr(main_object, "max_addr", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []
    metadata = getattr(project, "_inertia_lst_metadata", None)
    recovery_labels = {}
    metadata_fingerprint = None
    if metadata is not None:
        recovery_labels = _recovery_code_labels(metadata)
        signature_matched_addrs = _signature_matched_code_addrs(metadata)
        code_ranges = getattr(metadata, "code_ranges", None) or {}
        metadata_fingerprint = {
            "source_format": getattr(metadata, "source_format", None),
            "recovery_code_addrs": sorted(recovery_labels),
            "signature_code_addrs": sorted(signature_matched_addrs),
            "bounded_code_range_count": sum(1 for span in code_ranges.values() if span is not None and span[1] > span[0]),
        }
    else:
        signature_matched_addrs = frozenset()
    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path) if isinstance(binary_path, (str, Path)) else None,
        kind="exe_seed_ranking",
        extra={
            "entry": getattr(project, "entry", None),
            "linked_base": linked_base,
            "max_addr": max_addr,
            "ranking_policy": "strong-non-library-v2",
            "metadata": metadata_fingerprint,
        },
    )
    cached_ranking = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached_ranking, dict):
        cached_addrs = cached_ranking.get("addrs")
        if isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs):
            return cached_addrs

    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []
    seed_windows = _seed_scan_windows(project)
    neighbor_targets: set[int] = set()
    entry_window_targets = _entry_window_seed_targets(project, code, linked_base=linked_base)

    def _window_contains(addr: int) -> bool:
        return any(start <= addr < end for start, end in seed_windows)

    try:
        _entry_cfg, entry_function = _run_with_timeout_in_daemon_thread(
            lambda: _pick_function_lean(
                project,
                project.entry,
                regions=[(project.entry, min(project.entry + 0x200, linked_base + len(code)))],
                data_references=False,
                extend_far_calls=True,
            ),
            timeout=1,
            thread_name_prefix="seed-rank",
        )
        for target in collect_neighbor_call_targets(entry_function):
            neighbor_targets.add(target.target_addr)
    except Exception:
        pass

    ranked: dict[int, tuple[int, int]] = {}
    bounded_metadata_spans: dict[int, int] = {}
    near_call_targets: set[int] = set()
    far_call_targets: set[int] = set()
    prologue_targets: set[int] = set()
    relocation_control_targets: set[int] = set()
    relocation_pointer_targets: set[int] = set()

    def _consider(addr: int, priority: int) -> None:
        if not (linked_base <= addr < linked_base + len(code)):
            return
        if addr in signature_matched_addrs:
            return
        if not _window_contains(addr):
            return
        if addr == project.entry:
            return
        distance = abs(addr - project.entry)
        existing = ranked.get(addr)
        candidate = (priority, distance)
        if existing is None or candidate < existing:
            ranked[addr] = candidate

    metadata_labels = _visible_code_labels(metadata) if metadata is not None else {}
    if not metadata_labels and metadata is not None:
        metadata_labels = recovery_labels
    for addr, _name in metadata_labels.items():
        if (span := _lst_code_region(metadata, addr)) is None:
            continue
        span_len = span[1] - span[0]
        if span_len > 0:
            bounded_metadata_spans[addr] = span_len
        _consider(addr, 0)

    tracer = trace_16bit_seed_candidates(
        project,
        code,
        linked_base=linked_base,
        windows=seed_windows,
    )
    for target in entry_window_targets:
        _consider(target, 0)
    for target in tracer.call_targets:
        canonical = _resolve_x86_16_call_target(code, target - linked_base)
        if canonical is not None:
            _consider(linked_base + canonical, 0 if target in entry_window_targets else 1)
    for target in tracer.jump_targets:
        if target not in tracer.call_targets:
            canonical = _resolve_x86_16_function_start(code, target - linked_base)
            if canonical is not None:
                _consider(linked_base + canonical, 2)

    for offset in range(len(code) - 2):
        opcode = code[offset]
        if opcode == 0xE8:
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            callsite = linked_base + offset
            target = callsite + 3 + rel
            canonical = _resolve_x86_16_call_target(code, target - linked_base)
            if canonical is not None:
                resolved = linked_base + canonical
                near_call_targets.add(resolved)
                _consider(resolved, 0)
        if code[offset : offset + 3] == b"\x55\x8b\xec":
            target = linked_base + offset
            prologue_targets.add(target)
            _consider(target, 1)

    for offset in range(len(code) - 4):
        if code[offset] != 0x9A:
            continue
        off = int.from_bytes(code[offset + 1 : offset + 3], "little")
        seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
        target = linked_base + (seg << 4) + off
        canonical = _resolve_x86_16_call_target(code, target - linked_base)
        if canonical is not None:
            resolved = linked_base + canonical
            far_call_targets.add(resolved)
            _consider(resolved, 0)

    relocation_control_targets, relocation_pointer_targets = _relocation_seed_targets(
        project,
        code,
        linked_base=linked_base,
    )
    for target in relocation_control_targets:
        _consider(target, 1)
    for target in relocation_pointer_targets:
        _consider(target, 4)

    try:
        insns = _linear_disassembly(project, linked_base, linked_base + len(code))
    except Exception:
        insns = []
    terminal_next_targets: set[int] = set()
    for insn in insns:
        mnemonic = insn.mnemonic.lower()
        if not (mnemonic.startswith("ret") or mnemonic == "iret"):
            continue
        target = insn.address + insn.size
        if not (linked_base <= target < linked_base + len(code)):
            continue
        next_offset = target - linked_base
        while next_offset < len(code) and code[next_offset] in {0x00, 0x90, 0xCC}:
            next_offset += 1
        if next_offset >= len(code):
            continue
        if not _looks_like_x86_16_function_prologue(code, next_offset):
            continue
        next_target = linked_base + next_offset
        terminal_next_targets.add(next_target)
        _consider(next_target, 2)

    reranked: list[tuple[tuple[int, int, int], int]] = []
    for addr, (_priority, distance) in ranked.items():
        metadata_span_len = bounded_metadata_spans.get(addr)
        in_near_call = addr in near_call_targets
        in_far_call = addr in far_call_targets
        in_tracer_call = addr in tracer.call_targets
        in_prologue = addr in prologue_targets
        in_terminal_next = addr in terminal_next_targets
        in_neighbor = addr in neighbor_targets
        in_entry_window = addr in entry_window_targets
        in_relocation_control = addr in relocation_control_targets
        in_relocation_pointer = addr in relocation_pointer_targets
        entry_descends_from_stub = in_entry_window and addr < project.entry
        if metadata_span_len is not None:
            final_priority = 0
        elif entry_descends_from_stub and (in_neighbor or in_near_call or in_far_call):
            final_priority = 0
        elif entry_descends_from_stub:
            final_priority = 1
        elif in_entry_window and (in_neighbor or in_near_call or in_far_call):
            final_priority = 1
        elif in_relocation_control and (in_prologue or in_near_call or in_far_call):
            final_priority = 2
        elif in_relocation_control:
            final_priority = 3
        elif in_neighbor and in_prologue:
            final_priority = 2
        elif in_entry_window:
            final_priority = 2
        elif in_neighbor:
            final_priority = 3
        elif in_prologue and (in_near_call or in_far_call):
            final_priority = 2
        elif in_prologue:
            final_priority = 3
        elif in_relocation_pointer and (in_near_call or in_far_call or in_prologue):
            final_priority = 4
        elif in_relocation_pointer:
            final_priority = 5
        elif in_terminal_next and (in_near_call or in_far_call):
            final_priority = 4
        elif in_terminal_next:
            final_priority = 5
        elif in_far_call:
            final_priority = 6
        elif in_near_call and in_tracer_call:
            final_priority = 6
        elif in_near_call:
            # A raw near-call target with no prologue, entry-window, relocation,
            # metadata, or fast-tracer confirmation is often an internal label in
            # compiler/runtime code. Keep direct-call-only labels out of the
            # default "likely function" queue; stronger signals above still admit
            # legitimate naked functions.
            final_priority = 8
        else:
            final_priority = 9
        if final_priority >= 8:
            continue
        size_rank = -metadata_span_len if metadata_span_len is not None else 0
        reranked.append(((final_priority, size_rank, distance), addr))

    ranked_addrs = [addr for _meta, addr in sorted(reranked)]
    if cache_key is not None:
        _store_cache_json("recovery", cache_key, {"addrs": ranked_addrs})
    return ranked_addrs

def _recover_fast_seed_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
):
    if project.arch.name != "86_16":
        return []
    recovered = _recover_seeded_exe_functions(project, timeout=timeout, limit=limit)
    if recovered:
        print("/* quick function-entry scan found likely functions using call/prologue/epilogue patterns without helper metadata. */")
    return recovered

def _recover_fast_exe_catalog(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    low_memory: bool,
    limit: int | None,
) -> list[tuple[object, object]]:
    recovered: list[tuple[object, object]] = []
    seen_addrs: set[int] = set()

    entry_start = time.perf_counter()
    try:
        entry_pair = _run_with_timeout_in_daemon_thread(
            lambda: _fallback_entry_function(
                project,
                timeout=max(1, min(timeout, 6)),
                window=window,
                low_memory=low_memory,
                prefer_fast_recovery=True,
            ),
            timeout=max(1, min(timeout, 6)),
            thread_name_prefix="fast-entry",
        )
    except Exception:
        entry_pair = None
    print(f"[dbg] quick EXE function-list pass: entry-function recovery {time.perf_counter() - entry_start:.2f}s")
    sys.stdout.flush()
    if entry_pair is not None:
        entry_cfg, entry_function = entry_pair
        if _function_skip_reason(entry_function) is None:
            recovered.append((entry_cfg, entry_function))
            seen_addrs.add(entry_function.addr)

    seed_limit = None if limit is None else max(limit * 2, limit + 4)
    seed_start = time.perf_counter()
    seeded = _recover_fast_seed_functions(
        project,
        timeout=max(1, min(timeout, 8)),
        limit=seed_limit,
    )
    print(
        f"[dbg] quick EXE function-list pass: candidate-function recovery {time.perf_counter() - seed_start:.2f}s "
        f"(seed limit {seed_limit if seed_limit is not None else 'all'})"
    )
    sys.stdout.flush()
    for function_cfg, function in seeded:
        if function.addr in seen_addrs:
            continue
        recovered.append((function_cfg, function))
        seen_addrs.add(function.addr)

    if recovered:
        recovered = _rank_function_cfg_pairs_for_display(project, recovered)
        if limit is not None:
            recovered = recovered[:limit]
        print("/* quick EXE function discovery found entry/body functions without needing whole-program control-flow recovery. */")
    return recovered

def _recover_hidden_sidecar_display_pairs(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    timeout: int,
    window: int,
    low_memory: bool,
    limit: int,
) -> list[tuple[object, object]]:
    if limit <= 0 or not ranked_binary_offsets:
        return []

    recovered: list[tuple[object, object]] = []
    seen_addrs: set[int] = set()

    try:
        entry_pair = _run_with_timeout_in_daemon_thread(
            lambda: _fallback_entry_function(
                project,
                timeout=max(1, min(timeout, 4)),
                window=window,
                low_memory=low_memory,
                prefer_fast_recovery=True,
            ),
            timeout=max(2, min(timeout, 5)),
            thread_name_prefix="hidden-sidecar-entry",
        )
    except Exception:
        entry_pair = None
    if entry_pair is not None:
        entry_cfg, entry_function = entry_pair
        if _function_skip_reason(entry_function) is None:
            recovered.append((entry_cfg, entry_function))
            seen_addrs.add(entry_function.addr)

    remaining_slots = max(0, limit - len(recovered))
    if remaining_slots <= 0:
        return recovered[:limit]

    preview_probe_count = min(max(remaining_slots * 2, remaining_slots + 2), max(remaining_slots, 8))
    preview_items = _prepare_ranked_binary_preview_items(
        project,
        ranked_binary_offsets,
        max_count=preview_probe_count,
        timeout=timeout,
        window=window,
        low_memory=low_memory,
    )
    for item in preview_items:
        addr = getattr(item.function, "addr", None)
        if item.function_cfg is None or not isinstance(addr, int) or addr in seen_addrs:
            continue
        recovered.append((item.function_cfg, item.function))
        seen_addrs.add(addr)

    if recovered:
        recovered = _rank_hidden_sidecar_pairs_for_display_throughput(
            project,
            recovered,
            limit=limit,
        )
        print("/* hidden-sidecar EXE: using ranked direct-binary preview for the capped display set before broad CFG recovery. */")
    return recovered

def _rank_hidden_sidecar_pairs_for_display_throughput(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    limit: int,
) -> list[tuple[object, object]]:
    if not function_cfg_pairs:
        return []

    entry_addr = getattr(project, "entry", None)
    indexed_pairs = list(enumerate(function_cfg_pairs))
    entry_pair: tuple[int, tuple[object, object]] | None = None
    non_entry_pairs: list[tuple[int, tuple[object, object]]] = []

    for original_index, pair in indexed_pairs:
        _cfg, function = pair
        addr = getattr(function, "addr", None)
        if isinstance(entry_addr, int) and addr == entry_addr and entry_pair is None:
            entry_pair = (original_index, pair)
            continue
        non_entry_pairs.append((original_index, pair))

    def _throughput_priority(indexed_pair: tuple[int, tuple[object, object]]) -> tuple[int, int, int, int, int]:
        original_index, (_cfg, function) = indexed_pair
        addr = getattr(function, "addr", None)
        block_count, byte_count = _function_complexity(function)
        truncated = _function_recovery_truncated(function)
        far_pre_entry = int(
            isinstance(addr, int)
            and isinstance(entry_addr, int)
            and addr < entry_addr
            and (entry_addr - addr) > 0x200
        )
        pre_entry = int(isinstance(addr, int) and isinstance(entry_addr, int) and addr < entry_addr)
        tiny_wrapper_like = int(block_count <= 1 and byte_count <= 8 and not truncated)
        distance = abs(addr - entry_addr) if isinstance(addr, int) and isinstance(entry_addr, int) else 0
        return (far_pre_entry, pre_entry, tiny_wrapper_like, block_count, byte_count, distance, original_index)

    ordered_non_entry = [pair for _index, pair in sorted(non_entry_pairs, key=_throughput_priority)]
    if entry_pair is None:
        return ordered_non_entry[:limit] if limit > 0 else ordered_non_entry

    if limit <= 1:
        return [entry_pair[1]]

    if limit == 2:
        ordered = list(ordered_non_entry[:1])
        ordered.append(entry_pair[1])
        return ordered[:limit]

    ordered_all = list(ordered_non_entry)
    ordered_all.append(entry_pair[1])
    return ordered_all[:limit]

def _recover_cached_function_pairs(
    project: angr.Project,
    *,
    addrs: list[int],
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
) -> list[tuple[object, object]]:
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []
    binary_path = getattr(main_object, "binary", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return []

    deadline = time.monotonic() + max(1, timeout)
    metadata = getattr(project, "_inertia_lst_metadata", None)
    image_end = linked_base + max_addr + 1
    recovered: list[tuple[object, object]] = []
    seen_addrs: set[int] = set()

    for addr in addrs:
        if limit is not None and len(recovered) >= limit:
            break
        if not isinstance(addr, int) or addr in seen_addrs:
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        candidate_timeout = min(per_function_timeout, max(1, int(remaining)))
        if isinstance(getattr(project, "entry", None), int) and addr < project.entry:
            candidate_timeout = min(max(2, per_function_timeout), max(1, int(remaining)))

        try:
            function_cfg, function = _recover_candidate_with_timeout(
                project,
                candidate_addr=addr,
                image_end=image_end,
                metadata=metadata,
                project_entry=project.entry,
                region_span=region_span,
                timeout=candidate_timeout,
                binary_path=Path(binary_path),
                linked_base=linked_base,
            )
        except (_AnalysisTimeout, KeyError):
            continue
        except Exception:
            continue

        if function.addr in seen_addrs:
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            continue
        seen_addrs.add(function.addr)
        recovered.append((function_cfg, function))

    if recovered:
        print(f"/* restored {len(recovered)} previously recovered function entr{'y' if len(recovered) == 1 else 'ies'} from recovery cache. */")
    return recovered

def _candidate_recovery_cache_key(
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
) -> tuple[int, int, int, int]:
    return (candidate_addr, image_end, project_entry, region_span)

def _lookup_candidate_recovery_cache(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
):
    cache = getattr(project, "_inertia_candidate_recovery_cache", None)
    if not isinstance(cache, dict):
        return None
    return cache.get(
        _candidate_recovery_cache_key(
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
        )
    )

def _store_candidate_recovery_cache(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
    value,
) -> None:
    cache = getattr(project, "_inertia_candidate_recovery_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_candidate_recovery_cache", cache)
    cache[
        _candidate_recovery_cache_key(
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
        )
    ] = value

def _persistent_recovery_attempt_cache_key(
    *,
    binary_path: Path | None,
    addr: int,
    mode: str,
    window: int,
    low_memory: bool,
) -> dict[str, object] | None:
    return _recovery_cache_key(
        binary_path=binary_path,
        kind="function_recovery_attempt",
        extra={
            "addr": addr,
            "mode": mode,
            "window": window,
            "low_memory": bool(low_memory),
            "recovery_policy": "lazy-candidate-timeout-v1",
        },
    )

def _lookup_persistent_recovery_timeout(
    *,
    binary_path: Path | None,
    addr: int,
    mode: str,
    window: int,
    low_memory: bool,
    timeout: int,
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None]:
    cache_key = _persistent_recovery_attempt_cache_key(
        binary_path=binary_path,
        addr=addr,
        mode=mode,
        window=window,
        low_memory=low_memory,
    )
    cached = _load_cache_json("function_recovery_attempt", cache_key) if cache_key is not None else None
    if not isinstance(cached, dict) or cached.get("status") is None:
        return None, "", cache_key
    name = str(cached.get("name") or f"sub_{addr:x}")
    return (
        None,
        (
            f"[dbg] ignoring cached failed recovery for {addr:#x} {name} "
            f"mode={mode}; only successful decompilation results are cached\n"
        ),
        cache_key,
    )

def _recover_candidate_with_timeout(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata,
    project_entry: int,
    region_span: int,
    timeout: int,
    binary_path: Path,
    linked_base: int,
):
    cached_result = _lookup_candidate_recovery_cache(
        project,
        candidate_addr=candidate_addr,
        image_end=image_end,
        project_entry=project_entry,
        region_span=region_span,
    )
    if isinstance(cached_result, tuple):
        cache_status = cached_result[0]
        if cache_status == "ok":
            return cached_result[1]
        if cache_status == "keyerror":
            raise KeyError(cached_result[1])

    def _recover_candidate(candidate_project):
        return _recover_candidate_function_pair(
            candidate_project,
            candidate_addr=candidate_addr,
            image_end=image_end,
            metadata=metadata,
            project_entry=project_entry,
            region_span=region_span,
        )

    def _recover_once():
        try:
            recovered_pair = _recover_candidate(project)
            _store_candidate_recovery_cache(
                project,
                candidate_addr=candidate_addr,
                image_end=image_end,
                project_entry=project_entry,
                region_span=region_span,
                value=("ok", recovered_pair),
            )
            return recovered_pair
        except KeyError as exc:
            _store_candidate_recovery_cache(
                project,
                candidate_addr=candidate_addr,
                image_end=image_end,
                project_entry=project_entry,
                region_span=region_span,
                value=("keyerror", str(exc)),
            )
            raise
        except Exception:
            candidate_project = _build_project_cached(
                str(binary_path),
                force_blob=False,
                base_addr=linked_base,
                entry_point=project_entry,
            )
            recovered_pair = _recover_candidate(candidate_project)
            _store_candidate_recovery_cache(
                project,
                candidate_addr=candidate_addr,
                image_end=image_end,
                project_entry=project_entry,
                region_span=region_span,
                value=("ok", recovered_pair),
            )
            return recovered_pair

    timeout = max(1, int(timeout))
    if (
        os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
    ):
        try:
            return _run_with_timeout_in_fork(
                _recover_once,
                timeout=timeout + 1,
            )
        except Exception:
            pass
    if threading.current_thread() is threading.main_thread():
        with _analysis_timeout(timeout):
            return _recover_once()
    return _run_with_timeout_in_daemon_thread(
        _recover_once,
        timeout=timeout,
        thread_name_prefix="recover-candidate",
    )

def _recover_seeded_exe_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
    return_addrs: bool = False,
):
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return ([], []) if return_addrs else []
    binary_path = getattr(main_object, "binary", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return ([], []) if return_addrs else []

    ranked_seeds = _rank_exe_function_seeds(project)
    if not ranked_seeds:
        return ([], []) if return_addrs else []

    deadline = time.monotonic() + max(1, timeout)
    recovered: list[tuple[object, object]] = []
    recovered_addrs: list[int] = []
    seen_addrs: set[int] = {project.entry}
    queued_addrs: set[int] = set(ranked_seeds)
    pending_seed_addrs: list[int] = list(ranked_seeds)
    pending_gap_addrs: list[int] = []
    pending_neighbor_addrs: list[int] = []
    covered_ranges: list[tuple[int, int]] = []
    metadata = getattr(project, "_inertia_lst_metadata", None)
    image_end = linked_base + max_addr + 1
    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path),
        kind="seeded_function_catalog",
        extra={
            "entry": getattr(project, "entry", None),
            "linked_base": linked_base,
            "max_addr": max_addr,
            "region_span": region_span,
        },
    )
    cached_payload = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached_payload, dict):
        cached_addrs = cached_payload.get("addrs")
        if isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs):
            cached_recovered = _recover_cached_function_pairs(
                project,
                addrs=cached_addrs,
                timeout=timeout,
                limit=limit,
                region_span=region_span,
                per_function_timeout=per_function_timeout,
            )
            if cached_recovered:
                try:
                    cached_recovered, cached_addrs = _run_with_timeout_in_daemon_thread(
                        lambda: _supplement_cached_seeded_recovery(
                            project,
                            cached_recovered,
                            list(cached_addrs),
                            region_span=region_span,
                            per_function_timeout=per_function_timeout,
                            limit=limit,
                            cache_key=cache_key,
                        ),
                        timeout=min(max(2, timeout), 4),
                        thread_name_prefix="cached-supplement",
                    )
                except FuturesTimeoutError:
                    pass
                return (cached_recovered, cached_addrs) if return_addrs else cached_recovered

    prologue_candidates = _rank_prologue_scan_candidate_addrs(project, seen_addrs | queued_addrs)
    if prologue_candidates:
        initial_prologue_targets = [
            addr
            for addr in prologue_candidates[:8]
            if addr not in seen_addrs and addr not in queued_addrs and linked_base <= addr < image_end
        ]
        if initial_prologue_targets:
            pending_seed_addrs[:0] = initial_prologue_targets
            queued_addrs.update(initial_prologue_targets)

    while pending_seed_addrs or pending_gap_addrs or pending_neighbor_addrs:
        if pending_seed_addrs:
            addr = pending_seed_addrs.pop(0)
        elif pending_gap_addrs:
            addr = pending_gap_addrs.pop(0)
        else:
            addr = pending_neighbor_addrs.pop(0)
        if _addr_in_ranges(addr, covered_ranges):
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            function_cfg, function = _recover_candidate_with_timeout(
                project,
                candidate_addr=addr,
                image_end=image_end,
                metadata=metadata,
                project_entry=project.entry,
                region_span=region_span,
                timeout=min(per_function_timeout, max(1, int(remaining))),
                binary_path=Path(binary_path),
                linked_base=linked_base,
            )
        except (_AnalysisTimeout, KeyError):
            continue
        except Exception:
            continue

        if function.addr in seen_addrs:
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            continue
        seen_addrs.add(function.addr)
        recovered_addrs.append(function.addr)
        if limit is None or len(recovered) < limit:
            recovered.append((function_cfg, function))
        covered_ranges.extend(_function_covered_ranges(function))
        function_score = _function_recovery_score(function)
        function_truncated = _function_recovery_truncated(function)

        if limit is not None and not return_addrs and len(recovered) >= limit:
            break

        def _queue_targets(target_addrs: list[int], *, queue: str) -> None:
            queued_targets: list[int] = []
            for target_addr in target_addrs:
                if target_addr in seen_addrs or target_addr in queued_addrs:
                    continue
                if _addr_in_ranges(target_addr, covered_ranges):
                    continue
                if not (linked_base <= target_addr < image_end):
                    continue
                queued_targets.append(target_addr)
            if queued_targets:
                if queue == "gap":
                    pending_gap_addrs.extend(queued_targets)
                else:
                    pending_neighbor_addrs.extend(queued_targets)
                queued_addrs.update(queued_targets)

        linear_targets = list(_linear_function_seed_targets(project, function.addr, include_jumps=False))
        neighbor_targets: list[int] = []
        for target in collect_neighbor_call_targets(function):
            target_addr = getattr(target, "target_addr", None)
            if isinstance(target_addr, int):
                neighbor_targets.append(target_addr)
        if _needs_pre_entry_body_supplement(function, project.entry):
            _queue_targets(
                _prioritized_pre_entry_follow_on_targets(
                    project,
                    [(function_cfg, function)],
                    covered_ranges=covered_ranges,
                    existing_addrs=seen_addrs | queued_addrs,
                    image_end=image_end,
                ),
                queue="gap",
            )
        else:
            _queue_targets(neighbor_targets, queue="neighbor")

    if recovered_addrs:
        if cache_key is not None:
            _store_cache_json(
                "recovery",
                cache_key,
                {"addrs": recovered_addrs},
            )
        print(f"/* quick function-entry scan recovered {len(recovered_addrs)} additional function(s). */")
    return (recovered, recovered_addrs) if return_addrs else recovered

def _direct_recovery_inventory_count(project: angr.Project) -> int | None:
    try:
        ranked_seeds = _rank_exe_function_seeds(project)
    except Exception:
        return None
    return len(ranked_seeds) if ranked_seeds else None

def _fallback_entry_function(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
    prefer_fast_recovery: bool = False,
):
    # If whole-binary recovery already timed out, prefer a much smaller bounded
    # entry-only recovery window instead of retrying the same expensive search.
    # When memory pressure is high, keep the scan even narrower so the fallback
    # uses less memory and avoids the whole-binary CFG path entirely.
    project._inertia_decompiler_stage = "recovery"
    candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
    recovery_timeout = max(1, min(timeout, 5 if prefer_fast_recovery else 10))
    with _analysis_timeout(recovery_timeout):
        if prefer_fast_recovery:
            project._inertia_decompiler_stage = "recovery:fast"
            for fast_window in _x86_16_fast_recovery_windows(window, low_memory=low_memory):
                try:
                    if project.arch.name == "86_16":
                        fast_regions = [
                            _infer_x86_16_linear_region(project, project.entry, window=fast_window)
                        ]
                    else:
                        fast_regions = [(project.entry, project.entry + fast_window)]
                    return _pick_function_lean(
                        project,
                        project.entry,
                        regions=fast_regions,
                        data_references=False,
                        extend_far_calls=False,
                    )
                except (KeyError, _AnalysisTimeout):
                    continue
                except Exception as ex:  # noqa: BLE001
                    logging.getLogger(__name__).debug(
                        "Skipping fast x86-16 recovery for %s after %s",
                        hex(project.entry),
                        ex,
                    )
                    continue

        for candidate_window in candidate_windows:
            try:
                project._inertia_decompiler_stage = f"recovery:narrow:{candidate_window:#x}"
                if project.arch.name == "86_16":
                    regions = [
                        _infer_x86_16_linear_region(project, project.entry, window=candidate_window)
                    ]
                else:
                    regions = [(project.entry, project.entry + candidate_window)]
                try:
                    return _pick_function(
                        project,
                        project.entry,
                        regions=regions,
                        data_references=False,
                        force_smart_scan=False,
                    )
                except KeyError:
                    pass
                return _pick_function(
                    project,
                    project.entry,
                    regions=regions,
                    data_references=True if project.arch.name == "86_16" else None,
                )
            except _AnalysisTimeout:
                raise
            except KeyError:
                continue
        raise _AnalysisTimeout()

def _recover_lst_function(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    offset: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
):
    addr = offset if lst_metadata.absolute_addrs else project.entry + offset
    exact_region = _lst_code_region(lst_metadata, addr)
    if project.arch.name == "86_16" and exact_region is not None:
        slice_plan = plan_x86_16_exact_slice(*exact_region)
        if slice_plan.needs_rebased_slice:
            code = bytes(project.loader.memory.load(slice_plan.original_start, slice_plan.original_end - slice_plan.original_start))
            slice_project = _build_project_from_bytes(
                code,
                base_addr=slice_plan.slice_base,
                entry_point=slice_plan.slice_start,
            )
            slice_project._inertia_original_project = project
            slice_project._inertia_original_linear_delta = exact_region[0] - slice_plan.slice_start
            slice_project._inertia_disable_ail_narrowing = True
            slice_project._inertia_disable_complex_expr_scan = True
            slice_project._inertia_fast_block_peephole = True
            _inherit_tail_validation_runtime_policy(slice_project, project)
            slice_region = (slice_plan.slice_start, slice_plan.slice_end)
            with _analysis_timeout(max(1, timeout)):
                try:
                    cfg, func = _pick_function_lean(
                        slice_project,
                        slice_plan.slice_start,
                        regions=[slice_region],
                        data_references=False,
                        extend_far_calls=False,
                    )
                except KeyError:
                    cfg, func = _pick_function(
                        slice_project,
                        slice_plan.slice_start,
                        regions=[slice_region],
                        data_references=False,
                        force_smart_scan=False,
                    )
            func.name = name
            mark_function_original_addr(func, exact_region[0])
            print(
                f"[dbg] rebased exact-region recovery for {name}: "
                f"{exact_region[0]:#x}-{exact_region[1]:#x} -> {slice_region[0]:#x}-{slice_region[1]:#x}"
            )
            return cfg, func
    with _analysis_timeout(max(1, timeout)):
        if project.arch.name == "86_16":
            fast_windows = _x86_16_fast_recovery_windows(window, low_memory=low_memory)
            candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
            last_error: Exception | None = None
            for candidate_window in fast_windows:
                if exact_region is not None:
                    regions = [exact_region]
                else:
                    regions = [_infer_x86_16_linear_region(project, addr, window=candidate_window)]
                try:
                    cfg, func = _pick_function_lean(
                        project,
                        addr,
                        regions=regions,
                        data_references=False,
                        extend_far_calls=False,
                    )
                    break
                except KeyError as ex:
                    last_error = ex
            else:
                cfg = None
                func = None

            if cfg is not None and func is not None:
                if _exact_region_recovery_looks_truncated(func, exact_region):
                    split_count = _count_region_local_functions(cfg, exact_region)
                    if split_count > 1:
                        print(
                            f"[dbg] exact-region recovery split {name} into {split_count} local functions "
                            f"inside {exact_region[0]:#x}-{exact_region[1]:#x}"
                        )
                    best_cfg = cfg
                    best_func = func
                    best_score = _function_recovery_score(func)
                    for data_refs in (False, True):
                        try:
                            retried_cfg, retried_func = _pick_function(
                                project,
                                addr,
                                regions=[exact_region],
                                data_references=data_refs,
                                force_smart_scan=False,
                            )
                        except KeyError:
                            continue
                        retried_score = _function_recovery_score(retried_func)
                        if retried_score > best_score:
                            best_cfg = retried_cfg
                            best_func = retried_func
                            best_score = retried_score
                    cfg, func = best_cfg, best_func
            else:
                last_error = None
                for candidate_window in candidate_windows:
                    if exact_region is not None:
                        regions = [exact_region]
                    else:
                        regions = [_infer_x86_16_linear_region(project, addr, window=candidate_window)]
                    try:
                        cfg, func = _pick_function(
                            project,
                            addr,
                            regions=regions,
                        )
                        break
                    except KeyError as ex:
                        last_error = ex
                else:
                    if last_error is not None:
                        raise last_error
                    raise KeyError(f"Function {addr:#x} was not recovered by CFGFast.")
        else:
            regions = [(addr, addr + window)]
            cfg, func = _pick_function(project, addr, regions=regions)

    func.name = name
    return cfg, func

def _recover_ranked_binary_function(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
):
    with _analysis_timeout(max(1, timeout)):
        if project.arch.name == "86_16":
            fast_windows = _x86_16_fast_recovery_windows(window, low_memory=low_memory)
            candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
            last_error: Exception | None = None
            for candidate_window in fast_windows:
                try:
                    cfg, func = _pick_function_lean(
                        project,
                        addr,
                        regions=[_infer_x86_16_linear_region(project, addr, window=candidate_window)],
                        data_references=False,
                        extend_far_calls=False,
                    )
                    break
                except KeyError as ex:
                    last_error = ex
            else:
                cfg = None
                func = None

            if cfg is None or func is None:
                last_error = None
                for candidate_window in candidate_windows:
                    try:
                        cfg, func = _pick_function(
                            project,
                            addr,
                            regions=[_infer_x86_16_linear_region(project, addr, window=candidate_window)],
                        )
                        break
                    except KeyError as ex:
                        last_error = ex
                else:
                    if last_error is not None:
                        raise last_error
                    raise KeyError(f"Function {addr:#x} was not recovered by CFGFast.")
        else:
            cfg, func = _pick_function(project, addr, regions=[(addr, addr + window)])

    func.name = name
    return cfg, func

def _make_placeholder_function(project: angr.Project, addr: int, name: str):
    return SimpleNamespace(
        addr=addr,
        name=name,
        project=project,
        is_plt=False,
        is_simprocedure=False,
    )

def _is_zero_filled_region(project: angr.Project, addr: int, *, size: int = 8) -> bool:
    try:
        data = bytes(project.loader.memory.load(addr, size))
    except Exception:
        return False
    return bool(data) and all(byte == 0x00 for byte in data)

def _rank_labeled_function_entries(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> list[tuple[int, str]]:
    entry_addr = getattr(project, "entry", None)
    preferred_app_prefix_buckets = (
        ("init_", 1),
        ("draw_", 2),
        ("clear_", 3),
        ("proc_", 4),
        ("generation", 5),
        ("pause_", 6),
        ("rand_", 7),
        ("timer", 8),
        ("refresh", 9),
    )
    runtime_helper_names = {
        "astart",
        "_astart",
        "start",
        "_start",
        "chkstk",
        "_chkstk",
        "atol",
        "_atol",
        "strlen",
        "_strlen",
        "srand",
        "_srand",
        "exit",
        "_exit",
        "amsg_exit",
        "_amsg_exit",
        "nullcheck",
        "_nullcheck",
        "cintdiv",
        "_cintdiv",
        "dosret0",
        "_dosret0",
        "dosretax",
        "_dosretax",
    }

    def _priority(item: tuple[int, str]) -> tuple[int, int, int]:
        addr, name = item
        lowered = name.lower()
        region = _lst_code_region(metadata, addr)
        size = (region[1] - region[0]) if region is not None else None
        if lowered in {"main", "_main"} or lowered.endswith("main"):
            return (0, abs(addr - entry_addr), addr)
        for prefix, bucket in preferred_app_prefix_buckets:
            if lowered.startswith(prefix):
                return (bucket, abs(addr - entry_addr), addr)
        if addr == entry_addr:
            return (10, 0, addr)
        if lowered in {"start", "_start"} or lowered.endswith("_start"):
            return (11, abs(addr - entry_addr), addr)
        if lowered in runtime_helper_names:
            helper_bucket = 15 if size is not None and size <= 0x20 else 16
            return (helper_bucket, abs(addr - entry_addr), addr)
        if size is not None and size <= 0x20:
            return (12, abs(addr - entry_addr), addr)
        if size is not None and size <= 0x80:
            return (13, abs(addr - entry_addr), addr)
        if "padding" in lowered or lowered.startswith("align_"):
            return (18, abs(addr - entry_addr), addr)
        if _is_zero_filled_region(project, addr):
            return (17, abs(addr - entry_addr), addr)
        return (14, abs(addr - entry_addr), addr)

    return sorted(labeled_entries, key=_priority)

def _sidecar_label_ranking_cache_key(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None,
) -> dict[str, object] | None:
    main_object = getattr(project.loader, "main_object", None)
    binary_path = getattr(main_object, "binary", None)
    if not isinstance(binary_path, (str, Path)):
        return None
    code_ranges = getattr(metadata, "code_ranges", None) or {}
    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path),
        kind="sidecar_label_ranking",
        extra={
            "entry": getattr(project, "entry", None),
            "source_format": getattr(metadata, "source_format", None),
            "entries": [
                (
                    addr,
                    name,
                    tuple(code_ranges.get(addr)) if code_ranges.get(addr) is not None else None,
                )
                for addr, name in labeled_entries
            ],
        },
    )
    return cache_key

def _rank_labeled_function_entries_cached(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> tuple[list[tuple[int, str]], bool]:
    cache_key = _sidecar_label_ranking_cache_key(project, labeled_entries, metadata)
    cached = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached, dict):
        entries = cached.get("entries")
        if isinstance(entries, list) and all(
            isinstance(item, list | tuple)
            and len(item) == 2
            and isinstance(item[0], int)
            and isinstance(item[1], str)
            for item in entries
        ):
            return [(item[0], item[1]) for item in entries], True

    ranked = _rank_labeled_function_entries(project, labeled_entries, metadata)
    if cache_key is not None:
        _store_cache_json("recovery", cache_key, {"entries": ranked})
    return ranked, False

def _select_sidecar_showcase_entries(
    project: angr.Project,
    metadata: LSTMetadata,
    labeled_entries: list[tuple[int, str]],
    *,
    max_count: int,
    ranked_entries: list[tuple[int, str]] | None = None,
) -> list[tuple[int, str]]:
    ranked = ranked_entries if ranked_entries is not None else _rank_labeled_function_entries(project, labeled_entries, metadata)
    if max_count <= 0 or not ranked:
        return []

    by_addr = {addr: name for addr, name in ranked}
    selected: list[tuple[int, str]] = []
    seen: set[int] = set()

    def _add(addr: int | None) -> None:
        if addr is None or addr in seen or addr not in by_addr or len(selected) >= max_count:
            return
        selected.append((addr, by_addr[addr]))
        seen.add(addr)

    entry_addr = getattr(project, "entry", None)
    _add(entry_addr)

    def _tiny_candidate_priority(item: tuple[int, str]) -> tuple[int, int, int]:
        addr, name = item
        lowered = name.lower()
        region = _lst_code_region(metadata, addr)
        size = (region[1] - region[0]) if region is not None else 0xFFFF
        if lowered.startswith("nullsub"):
            bucket = 0
        elif lowered.startswith("sub_"):
            bucket = 1
        elif "exit" in lowered or "amsg" in lowered:
            bucket = 4
        else:
            bucket = 2
        return (bucket, size, abs(addr - getattr(project, "entry", 0)))

    tiny_candidates = [
        (addr, name)
        for addr, name in ranked
        if addr not in seen
        and (span := _lst_code_region(metadata, addr)) is not None
        and (span[1] - span[0]) <= 0x20
        and "padding" not in name.lower()
        and name.lower() not in {"main", "_main", "start", "_start"}
    ]
    tiny_candidates.sort(key=_tiny_candidate_priority)
    if tiny_candidates:
        _add(tiny_candidates[0][0])

    main_candidates = [
        addr
        for addr, name in ranked
        if name.lower() in {"main", "_main"} or name.lower().endswith("main")
    ]
    additional_tiny_candidates = tiny_candidates[1:3]
    for addr, _name in additional_tiny_candidates:
        _add(addr)
    if main_candidates:
        _add(main_candidates[0])

    for addr, _name in ranked:
        _add(addr)
        if len(selected) >= max_count:
            break

    return selected

def _format_sidecar_function_catalog(metadata: LSTMetadata, *, limit: int | None = None) -> str:
    lines: list[str] = []
    entries = sorted(_visible_code_labels(metadata).items())
    if limit is not None and limit > 0:
        entries = entries[:limit]
    for addr, name in entries:
        region = _lst_code_region(metadata, addr)
        if region is not None:
            size = region[1] - region[0]
            lines.append(f"{addr:#x} {name} size={size:#x} range=[{region[0]:#x}, {region[1]:#x})")
        else:
            lines.append(f"{addr:#x} {name}")
    return "\n".join(lines)

def _recover_blob_entry_function(project: angr.Project, entry_addr: int, *, timeout: int):
    project._inertia_decompiler_stage = "recovery:full"
    with _analysis_timeout(timeout):
        cfg = project.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[entry_addr],
            normalize=True,
            force_complete_scan=False,
            data_references=False,
        )
        if entry_addr not in cfg.functions:
            cfg = project.analyses.CFGFast(
                start_at_entry=False,
                function_starts=[entry_addr],
                normalize=True,
                force_complete_scan=False,
                data_references=True,
            )
        if entry_addr not in cfg.functions and project.arch.name == "86_16":
            cfg = project.analyses.CFGFast(
                start_at_entry=False,
                function_starts=[entry_addr],
                normalize=True,
                force_complete_scan=True,
                data_references=True,
            )

    if entry_addr not in cfg.functions:
        raise KeyError(f"Function {entry_addr:#x} was not recovered by CFGFast.")
    return cfg, cfg.functions[entry_addr]

def _recover_direct_addr_function(
    project: angr.Project,
    addr: int,
    *,
    timeout: int,
    window: int,
    function_label: str | None,
    lst_metadata: LSTMetadata | None,
    low_memory_path: bool,
    prefer_fast_recovery: bool,
):
    if (
        lst_metadata is not None
        and project.arch.name == "86_16"
        and _lst_code_region(lst_metadata, addr) is not None
    ):
        sidecar_addr = _lst_code_region(lst_metadata, addr)[0]
        code_name = _lst_code_label(lst_metadata, sidecar_addr, project.entry) or f"sub_{sidecar_addr:x}"
        return _recover_lst_function(
            project,
            lst_metadata,
            sidecar_addr if lst_metadata.absolute_addrs else sidecar_addr - project.entry,
            code_name,
            timeout=timeout,
            window=window,
            low_memory=low_memory_path,
        )
    if function_label is not None and addr == project.entry and project.arch.name == "86_16":
        return _fallback_entry_function(
            project,
            timeout=timeout,
            window=window,
            low_memory=low_memory_path,
            prefer_fast_recovery=bool(function_label is not None and prefer_fast_recovery),
        )
    if function_label is not None and addr == project.entry:
        return _recover_blob_entry_function(project, addr, timeout=timeout)

    with _analysis_timeout(timeout):
        if project.arch.name == "86_16":
            main_object = getattr(project.loader, "main_object", None)
            linked_base = getattr(main_object, "linked_base", None)
            max_addr = getattr(main_object, "max_addr", None)
            if isinstance(linked_base, int) and isinstance(max_addr, int):
                return _recover_candidate_function_pair(
                    project,
                    candidate_addr=addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=lst_metadata,
                    project_entry=project.entry,
                    region_span=max(window, 0x180),
                )
            regions = [_infer_x86_16_linear_region(project, addr, window=window)]
        else:
            regions = [(addr, addr + window)]
        return _pick_function(project, addr, regions=regions)
