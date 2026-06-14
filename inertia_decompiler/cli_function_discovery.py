# AUTO-GENERATED split from cli_runtime_shared.py
from __future__ import annotations

import contextlib
import logging
import os
import sys
import threading
import time
import weakref
from collections.abc import Mapping, Sequence
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.analysis_helpers import (
    collect_neighbor_call_targets,
    extend_cfg_for_far_calls,
    extend_cfg_for_neighbor_calls,
    infer_com_region,
    patch_interrupt_service_call_sites,
    seed_calling_conventions,
)
from angr_platforms.X86_16.exact_region_diagnostics import (
    build_exact_region_diagnostics_8616,
    classify_region_split_8616,
    format_exact_region_diagnostics_8616,
)
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.cache import (
    _load_cache_json,
    _recovery_cache_key,
    _store_cache_json,
)
from inertia_decompiler.cli_output import (
    _timestamped_print,
)
from inertia_decompiler.disassembly_helpers import (
    _linear_disassembly,
)
from inertia_decompiler.project_loading import (
    _build_project_cached,
    _build_project_from_bytes,
)
from inertia_decompiler.sidecar_metadata import (
    _lst_code_label,
    _lst_code_region,
    _recovery_code_labels,
    _signature_matched_code_addrs,
    _visible_code_labels,
)
from inertia_decompiler.tail_validation import (
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
)
from inertia_decompiler.telemetry import trace_function
from inertia_decompiler.x86_16_exact_slice import (
    mark_function_original_addr,
    plan_x86_16_exact_slice,
)

# Pseudo-callee DOS helper addresses (when materialized) live in a synthetic
# high-address range, well above real 16-bit image code.
DOS_SERVICE_BASE_ADDR = 0xF000_0000


from inertia_decompiler.runtime_support import (
    AnalysisTimeout as _AnalysisTimeout,
)
from inertia_decompiler.runtime_support import (
    analysis_timeout as _analysis_timeout,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
)
from inertia_decompiler.work_items import (
    FunctionWorkResult,
)

print = _timestamped_print
__all__ = [
    "_seed_scan_windows",
    "_entry_window_seed_targets",
    "_linear_function_seed_targets",
    "_looks_like_x86_16_function_prologue",
    "_looks_like_x86_16_entry_byte",
    "_resolve_x86_16_function_start",
    "_resolve_x86_16_call_target",
    "_infer_x86_16_linear_region",
    "_pick_function",
    "_pick_function_lean",
    "_x86_16_recovery_windows",
    "_x86_16_fast_recovery_windows",
    "_recover_cfg",
    "_recover_partial_cfg",
    "_function_skip_reason",
    "_function_recovery_score",
    "_function_covered_ranges",
    "_addr_in_ranges",
    "_candidate_recovery_regions",
    "_richest_bounded_recovery_region",
    "_recovery_score_good_enough",
    "_exact_region_recovery_looks_truncated",
    "_count_region_local_functions",
    "_function_recovery_truncated",
    "_needs_pre_entry_body_supplement",
    "_prioritized_pre_entry_follow_on_targets",
    "_mark_function_recovery_truncated",
    "_recover_candidate_function_pair",
    "_interesting_functions",
    "_rank_function_cfg_pairs_for_display",
    "_expanded_exe_discovery_limit",
    "_supplement_cached_seeded_recovery",
    "_store_catalog_address_cache",
    "_load_catalog_address_cache",
    "_supplement_functions_from_prologue_scan",
    "_rank_gap_scan_candidate_addrs",
    "_rank_prologue_scan_candidate_addrs",
    "_relocation_seed_targets",
    "_rank_exe_function_seeds",
    "_recover_fast_seed_functions",
    "_recover_fast_exe_catalog",
    "_recover_hidden_sidecar_display_pairs",
    "_rank_hidden_sidecar_pairs_for_display_throughput",
    "_recover_cached_function_pairs",
    "_candidate_recovery_cache_key",
    "_lookup_candidate_recovery_cache",
    "_store_candidate_recovery_cache",
    "_persistent_recovery_attempt_cache_key",
    "_lookup_persistent_recovery_timeout",
    "_recover_candidate_with_timeout",
    "_recover_seeded_exe_functions",
    "_direct_recovery_inventory_count",
    "_fallback_entry_function",
    "_recover_lst_function",
    "_recover_ranked_binary_function",
    "_make_placeholder_function",
    "_is_zero_filled_region",
    "_rank_labeled_function_entries",
    "_sidecar_label_ranking_cache_key",
    "_rank_labeled_function_entries_cached",
    "_select_sidecar_showcase_entries",
    "_format_sidecar_function_catalog",
    "_recover_blob_entry_function",
    "_recover_direct_addr_function",
]


def _seed_scan_windows(project: angr.Project) -> list[tuple[int, int]]:
    def _impl():
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

    return _impl()


def _entry_window_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
    entry_window: int = 0x200,
) -> set[int]:
    def _impl():
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

    return _impl()


def _linear_function_seed_targets(
    project: angr.Project,
    start_addr: int,
    *,
    max_scan: int = 0x200,
    include_jumps: bool = True,
) -> set[int]:
    def _impl():
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

    return _impl()


def _looks_like_x86_16_function_prologue(code: bytes, offset: int) -> bool:
    window = code[offset : offset + 4]
    return window.startswith(b"\x55\x8b\xec")


def _looks_like_x86_16_entry_byte(code: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(code):
        return False
    return code[offset] not in {0x00, 0x90, 0xCC}


_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT = 0x80


def _resolve_x86_16_function_start(code: bytes, offset: int, *, max_padding: int = 0x20) -> int | None:
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
    def _impl():
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

    return _impl()


def _pick_function(
    project: angr.Project,
    addr: int | None,
    *,
    regions=None,
    data_references: bool | None = None,
    force_smart_scan: bool | None = None,
):
    def _impl():
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

    return _impl()


def _pick_function_lean(
    project: angr.Project,
    addr: int | None,
    *,
    regions=None,
    data_references: bool = False,
    extend_far_calls: bool = True,
):
    def _impl():
        """Recover a known entry point with a deliberately cheap CFGFast pass.

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

    return _impl()


_DEFAULT_PICK_FUNCTION_LEAN = _pick_function_lean


def _normalized_x86_16_recovery_window(window: int | None, *, low_memory: bool = False) -> int:
    floor = 0x80 if low_memory else 0x200
    if not isinstance(window, int):
        return floor
    return max(window, floor)


def _x86_16_recovery_windows(window: int | None, *, low_memory: bool = False) -> tuple[int, ...]:
    base_window = _normalized_x86_16_recovery_window(window, low_memory=low_memory)
    return tuple(base_window * factor for factor in (1, 2, 4, 8, 16))


def _x86_16_fast_recovery_windows(window: int | None, *, low_memory: bool = False) -> tuple[int, ...]:
    effective_window = _normalized_x86_16_recovery_window(window, low_memory=low_memory)
    candidate_windows = (0x40, 0x80, 0x100) if low_memory else (0x80, 0x100, 0x200)
    windows: list[int] = []
    for candidate in candidate_windows:
        if effective_window <= candidate:
            current_window = effective_window
        else:
            current_window = candidate
        if current_window not in windows:
            windows.append(current_window)
    if not windows:
        windows.append(effective_window)
    return tuple(windows)


@trace_function(name="discovery.recover_cfg")
def _recover_cfg(
    project: angr.Project,
    binary_path: Path,
    *,
    base_addr: int,
    window: int,
    low_memory: bool = False,
):
    print(
        f"[dbg] recover_cfg: entry={hex(project.entry)} base_addr={hex(base_addr)} window={hex(window)} binary={binary_path}"
    )
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


@trace_function(name="discovery.recover_partial_cfg")
def _recover_partial_cfg(
    project: angr.Project,
    *,
    window: int,
    low_memory: bool = False,
):
    def _impl():
        """Recover a bounded x86-16 catalog around the entry point.

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

    return _impl()


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


def _block_ranges_for_overlap_8616(blocks, exact_region: tuple[int, int] | None = None) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for block in tuple(blocks or ()):
        addr = getattr(block, "addr", None)
        size = max(0, getattr(block, "size", 0))
        if not isinstance(addr, int) or size <= 0:
            continue
        end = addr + size
        if exact_region is not None:
            region_start, region_end = exact_region
            if end <= region_start or addr >= region_end:
                continue
            addr = max(addr, region_start)
            end = min(end, region_end)
            if addr >= end:
                continue
        ranges.append((addr, end))
    return sorted(ranges)


def _block_overlap_count_8616(blocks, exact_region: tuple[int, int] | None = None) -> int:
    ranges = _block_ranges_for_overlap_8616(blocks, exact_region)
    overlap_count = 0
    last_end: int | None = None
    for start, end in ranges:
        if last_end is not None and start < last_end:
            overlap_count += 1
        last_end = max(last_end or end, end)
    return overlap_count


def _block_unique_covered_bytes_8616(blocks, exact_region: tuple[int, int] | None = None) -> int:
    ranges = _block_ranges_for_overlap_8616(blocks, exact_region)
    if not ranges:
        return 0
    merged: list[list[int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
            continue
        merged[-1][1] = max(merged[-1][1], end)
    return sum(end - start for start, end in merged)


def _function_block_overlap_count_8616(function, exact_region: tuple[int, int] | None = None) -> int:
    return _block_overlap_count_8616(tuple(getattr(function, "blocks", ()) or ()), exact_region)


def _should_replace_exact_region_candidate_8616(
    current,
    candidate,
    exact_region: tuple[int, int] | None,
) -> bool:
    current_score = _function_recovery_score(current)
    candidate_score = _function_recovery_score(candidate)
    if candidate_score <= current_score:
        return False
    if exact_region is not None:
        current_overlap = _function_block_overlap_count_8616(current, exact_region)
        candidate_overlap = _function_block_overlap_count_8616(candidate, exact_region)
        if current_overlap == 0 and candidate_overlap > 0:
            return False
    return True


def _function_covered_ranges(function) -> list[tuple[int, int]]:
    def _impl():
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

    return _impl()


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
        candidate_windows = (region_span,)
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


def _maybe_extend_x86_16_exact_region_terminator(
    project: angr.Project | None,
    exact_region: tuple[int, int] | None,
) -> tuple[int, int] | None:
    def _impl():
        if exact_region is None:
            return None
        start, end = exact_region
        size = max(0, end - start)
        if size <= 0 or size > 0x40:
            return exact_region
        if project is None:
            return exact_region
        main_object = getattr(project.loader, "main_object", None)
        max_addr = getattr(main_object, "max_addr", None)
        if not isinstance(max_addr, int):
            return exact_region
        image_end = max_addr + 1
        if end >= image_end:
            return exact_region
        lookahead = min(0x10, image_end - end)
        try:
            trailer = bytes(project.loader.memory.load(end, lookahead))
        except Exception:
            return exact_region
        if not trailer:
            return exact_region
        op0 = trailer[0]
        if op0 in {0xC3, 0xCB}:  # ret / retf
            return (start, end + 1)
        if op0 in {0xC2, 0xCA}:  # ret imm16 / retf imm16
            return (start, min(image_end, end + 3))
        # Coarse sidecar regions for tiny functions can stop at a branch target
        # right before the epilogue bytes. If a nearby return exists, extend to
        # include it so control-flow/condition recovery can see full tail shape.
        for idx, byte in enumerate(trailer):
            if byte in {0xC3, 0xCB}:  # ret / retf
                return (start, min(image_end, end + idx + 1))
            if byte in {0xC2, 0xCA}:  # ret imm16 / retf imm16
                return (start, min(image_end, end + idx + 3))
        return exact_region

    return _impl()


def _x86_16_exact_region_has_terminator(
    project: angr.Project,
    exact_region: tuple[int, int] | None,
) -> bool:
    if exact_region is None:
        return False
    start, end = exact_region
    size = max(0, end - start)
    if size <= 0:
        return False
    main_object = getattr(project.loader, "main_object", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(max_addr, int):
        return False
    image_end = max_addr + 1
    if start >= image_end:
        return False
    read_size = min(size, image_end - start)
    if read_size <= 0:
        return False
    try:
        raw = bytes(project.loader.memory.load(start, read_size))
    except Exception:
        return False
    if not raw:
        return False
    # Accept plain returns, iret, and direct near/far jumps as explicit block terminators.
    terminators = {0xC2, 0xC3, 0xCA, 0xCB, 0xCF, 0xE9, 0xEA, 0xEB}
    return any(byte in terminators for byte in raw)


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


def _x86_16_block_successors_from_capstone_8616(
    block,
    region_start: int,
    region_end: int,
) -> tuple[set[int], bool]:
    def _impl():
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            return set(), True

        last_insn = insns[-1]
        mnemonic = str(getattr(last_insn, "mnemonic", "")).lower()
        successors: set[int] = set()
        block_end = block.addr + block.size
        in_region_fallthrough = block_end < region_end

        def _append_target(target_addr: int | None) -> None:
            if not isinstance(target_addr, int):
                return
            if region_start <= target_addr < region_end:
                successors.add(target_addr)
            # Keep CFG faithful: branch targets outside region are treated as exits.

        def _jump_target(last_insn) -> int | None:
            capstone_insn = getattr(last_insn, "insn", None)
            operands = getattr(capstone_insn, "operands", None)
            if not operands:
                return None
            for operand in operands:
                if getattr(operand, "type", None) != 2:
                    continue
                imm = getattr(operand, "imm", None)
                if isinstance(imm, int):
                    return imm
            return None

        if mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
            return successors, True

        if mnemonic in {"call", "lcall", "callq"}:
            if in_region_fallthrough:
                successors.add(block_end)
            return successors, False

        if mnemonic == "jmp":
            target = _jump_target(last_insn)
            _append_target(target)
            return successors, target is None

        if mnemonic.startswith("j"):
            target = _jump_target(last_insn)
            _append_target(target)
            if in_region_fallthrough:
                successors.add(block_end)
            return successors, False

        if mnemonic in {"loop", "loope", "loopne", "loopnz", "loopz"}:
            target = _jump_target(last_insn)
            _append_target(target)
            if in_region_fallthrough:
                successors.add(block_end)
            return successors, False

        if in_region_fallthrough:
            successors.add(block_end)
        return successors, False

    return _impl()


def _stitch_x86_16_exact_function_8616(
    project: angr.Project,
    function,
    exact_region: tuple[int, int] | None,
) -> tuple[object, bool]:
    if exact_region is None:
        return function, False
    start, end = exact_region
    if not (isinstance(start, int) and isinstance(end, int) and start < end):
        return function, False

    entry = getattr(function, "addr", None)
    if not isinstance(entry, int) or not (start <= entry < end):
        return function, False

    reachable, edges = _collect_stitched_blocks_and_edges_8616(project, entry, start, end)

    if len(reachable) <= 1:
        return function, False

    if not _should_replace_function_with_stitched_graph_8616(function, reachable, exact_region):
        return function, False

    _reset_function_graph_state_8616(function)
    _rebuild_function_transition_graph_8616(function, reachable, edges)
    _mark_stitched_return_sites_8616(function, reachable)

    function.normalized = False
    return function, True


def _collect_stitched_blocks_and_edges_8616(
    project: angr.Project, entry: int, start: int, end: int
) -> tuple[dict[int, object], set[tuple[int, int]]]:
    reachable: dict[int, object] = {}
    edges: set[tuple[int, int]] = set()
    queue: list[int] = [entry]
    visited: set[int] = set()
    while queue:
        block_addr = queue.pop(0)
        if block_addr in visited or not (start <= block_addr < end):
            continue
        visited.add(block_addr)
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            visited.remove(block_addr)
            continue
        if len(getattr(block, "bytes", b"")) <= 0:
            visited.remove(block_addr)
            continue
        reachable[block_addr] = block
        successors, _ = _x86_16_block_successors_from_capstone_8616(block, region_start=start, region_end=end)
        for succ in successors:
            if start <= succ < end and succ not in visited:
                queue.append(succ)
            edges.add((block_addr, succ))
    reachable = _cap_stitched_blocks_to_leaders_8616(project, reachable)
    edges = _recompute_stitched_edges_8616(reachable, start, end)
    return reachable, edges


def _cap_stitched_blocks_to_leaders_8616(project: angr.Project, reachable: dict[int, object]) -> dict[int, object]:
    if len(reachable) <= 1:
        return reachable
    leaders = sorted(reachable)
    capped: dict[int, object] = {}
    for block_addr in leaders:
        block = reachable[block_addr]
        block_size = int(getattr(block, "size", 0) or 0)
        if block_size <= 0:
            capped[block_addr] = block
            continue
        block_end = block_addr + block_size
        next_leader = next((leader for leader in leaders if block_addr < leader < block_end), None)
        if not isinstance(next_leader, int):
            capped[block_addr] = block
            continue
        capped_size = next_leader - block_addr
        if capped_size <= 0:
            capped[block_addr] = block
            continue
        try:
            capped_block = project.factory.block(block_addr, size=capped_size, opt_level=0)
        except Exception:
            capped[block_addr] = block
            continue
        if int(getattr(capped_block, "size", 0) or 0) > 0:
            capped[block_addr] = capped_block
        else:
            capped[block_addr] = block
    return capped


def _recompute_stitched_edges_8616(
    reachable: dict[int, object],
    start: int,
    end: int,
) -> set[tuple[int, int]]:
    edges: set[tuple[int, int]] = set()
    for block_addr, block in reachable.items():
        successors, _ = _x86_16_block_successors_from_capstone_8616(block, region_start=start, region_end=end)
        for succ in successors:
            edges.add((block_addr, succ))
    return edges


def _should_replace_function_with_stitched_graph_8616(
    function,
    reachable: dict[int, object],
    exact_region: tuple[int, int] | None = None,
) -> bool:
    current_block_count, current_block_bytes = _function_recovery_score(function)
    stitched_bytes = sum(len(getattr(block, "bytes", b"")) for block in reachable.values())
    current_blocks = tuple(getattr(function, "blocks", ()) or ())
    stitched_blocks = tuple(reachable.values())
    current_overlap = _block_overlap_count_8616(current_blocks, exact_region)
    stitched_overlap = _block_overlap_count_8616(stitched_blocks, exact_region)
    if current_overlap > stitched_overlap:
        current_unique = _block_unique_covered_bytes_8616(current_blocks, exact_region)
        stitched_unique = _block_unique_covered_bytes_8616(stitched_blocks, exact_region)
        if stitched_unique >= current_unique:
            return True
    return stitched_bytes > current_block_bytes or len(reachable) > current_block_count


def _reset_function_graph_state_8616(function) -> None:
    try:
        function._addr_to_block_node.clear()
        function._block_sizes.clear()
        function._local_block_addrs.clear()
        function._local_blocks.clear()
        function._call_sites.clear()
        function._ret_sites.clear()
        function._jumpout_sites.clear()
        function._callout_sites.clear()
        function._retout_sites.clear()
        function._endpoints.clear()
        if hasattr(function, "transition_graph"):
            function.transition_graph.clear()
        if hasattr(function, "startpoint"):
            function.startpoint = None
    except Exception:
        pass


def _rebuild_function_transition_graph_8616(
    function, reachable: dict[int, object], edges: set[tuple[int, int]]
) -> None:
    from angr.knowledge_plugins.cfg.cfg_node import BlockNode

    for block_addr in sorted(reachable):
        block = reachable[block_addr]
        node = BlockNode(block_addr, block.size, bytestr=getattr(block, "bytes", None))
        function._register_node(True, node)
    for source_addr, target_addr in edges:
        source_node = function.get_node(source_addr)
        target_node = function.get_node(target_addr)
        if source_node is None or target_node is None:
            continue
        source_capstone = getattr(reachable[source_addr], "capstone", None)
        insns = getattr(source_capstone, "insns", ())
        ins_addr = int(getattr(insns[-1], "address", source_addr)) if insns else source_addr
        try:
            function.transition_graph.add_edge(source_node, target_node, type="transition", ins_addr=ins_addr)
        except Exception:
            continue


def _mark_stitched_return_sites_8616(function, reachable: dict[int, object]) -> None:
    for block_addr in sorted(reachable):
        source_node = function.get_node(block_addr)
        if source_node is None:
            continue
        last_insns = tuple(getattr(getattr(reachable[block_addr], "capstone", None), "insns", ()) or ())
        if not last_insns:
            continue
        last_mnemonic = str(getattr(last_insns[-1], "mnemonic", "")).lower()
        if last_mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
            function._add_return_site(source_node)
        if last_mnemonic.startswith("j") and not tuple(function.transition_graph.edges(source_node)):
            function._add_return_site(source_node)


def _mark_x86_16_stitched_recovery_8616(function) -> None:
    info = getattr(function, "info", None)
    if not isinstance(info, dict):
        with contextlib.suppress(Exception):
            function.info = {}
        info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_stitched_recovery"] = True
    with contextlib.suppress(Exception):
        setattr(function, "_inertia_x86_16_stitched_recovery", True)


def _commit_exact_region_function_to_kb_8616(
    project: angr.Project, cfg, function, exact_region: tuple[int, int] | None
) -> bool:
    """Commit a selected exact-region function into the function managers that later
    analysis consults.

    CFGFast can leave smaller region-local pseudo-functions in the project KB
    even after the recovery layer stitches the full exact-region body. Leaving
    those stale entries visible makes later decompiler stages treat internal
    block leaders as independent functions. The recovery layer owns this handoff:
    it has the exact-region evidence and the selected bounded graph.
    """
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    if exact_region is None:
        return False
    entry_addr = getattr(function, "addr", None)
    if not isinstance(entry_addr, int):
        return False
    start, end = exact_region
    if not (isinstance(start, int) and isinstance(end, int) and start <= entry_addr < end):
        return False

    managers: list[object] = []
    project_functions = getattr(getattr(project, "kb", None), "functions", None)
    cfg_functions = getattr(cfg, "functions", None)
    for manager in (project_functions, cfg_functions):
        if manager is not None and all(id(manager) != id(existing) for existing in managers):
            managers.append(manager)

    changed = False
    for manager in managers:
        keys = tuple(getattr(manager, "keys", lambda: ())() or ())
        for candidate_addr in keys:
            if not isinstance(candidate_addr, int):
                continue
            if start < candidate_addr < end:
                with contextlib.suppress(Exception):
                    del manager[candidate_addr]
                    changed = True

        existing = None
        with contextlib.suppress(Exception):
            existing = manager.function(addr=entry_addr, create=False)
        if existing is not function:
            with contextlib.suppress(Exception):
                del manager[entry_addr]
            function_map = getattr(manager, "_function_map", None)
            if function_map is None:
                continue
            try:
                function_map[entry_addr] = function
                changed = True
            except Exception:
                continue

        with contextlib.suppress(Exception):
            manager.function_addrs_set.add(entry_addr)
        name = getattr(function, "name", None)
        if isinstance(name, str) and name:
            with contextlib.suppress(Exception):
                manager._func_name_to_addrs[name].add(entry_addr)
        with contextlib.suppress(Exception):
            manager._func_block_counts.pop(entry_addr, None)

    if project_functions is not None:
        with contextlib.suppress(Exception):
            function._function_manager = weakref.proxy(project_functions)
    with contextlib.suppress(Exception):
        function._local_transition_graph = None
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_exact_region_committed"] = True
    return changed


def _repair_x86_16_function_graph_8616(project: angr.Project, function) -> None:
    """Best-effort, conservative CFG completion for x86-16 direct recovery paths.

    The recovery layer should own this because missing return sites here are
    usually a graph-completion issue from bounded CFGFast extraction, not an
    IR/lowering defect.
    """
    if getattr(project, "arch", None) is None or getattr(project.arch, "name", None) != "86_16":
        return

    entry_addr = getattr(function, "addr", None)
    if not isinstance(entry_addr, int):
        return

    if bool(getattr(function, "returning", None)):
        return

    existing_ret_sites = tuple(getattr(function, "ret_sites", ()) or ())
    if existing_ret_sites:
        return

    existing_blocks = tuple(getattr(function, "blocks", ()) or ())
    if not existing_blocks:
        return

    block_addrs = sorted(
        (addr for addr in (getattr(block, "addr", None) for block in existing_blocks) if isinstance(addr, int))
    )
    if not block_addrs:
        return

    seed_max_byte = sum(max(0, getattr(block, "size", 0)) for block in existing_blocks)
    scan_limit = max(0x200, min(0x2000, max(0x200, seed_max_byte * 4)))
    start_bound = max(min(block_addrs), entry_addr - 0x100)
    end_bound = max(block_addrs) + scan_limit

    def _is_in_scan_bound(addr: int) -> bool:
        return isinstance(addr, int) and start_bound <= addr < end_bound

    discovered: dict[int, object] = {}
    edges: set[tuple[int, int]] = set()
    queue: list[int] = [entry_addr]
    visited: set[int] = set()
    visited_bytes = 0
    limit_nodes = 512
    seen_targets: set[int] = set()

    while queue and len(visited) < limit_nodes and visited_bytes <= scan_limit:
        block_addr = queue.pop(0)
        if block_addr in visited or not _is_in_scan_bound(block_addr):
            continue
        visited.add(block_addr)
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        block_size = int(getattr(block, "size", 0))
        if block_size <= 0:
            continue
        visited_bytes += block_size
        if visited_bytes > scan_limit:
            break
        discovered[block_addr] = block
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            continue
        last_insn = insns[-1]
        last_mnemonic = str(getattr(last_insn, "mnemonic", "")).lower()
        successors, _is_direct_exit = _x86_16_block_successors_from_capstone_8616(
            block,
            region_start=start_bound,
            region_end=end_bound,
        )
        for succ in successors:
            if _is_in_scan_bound(succ) and succ not in seen_targets:
                queue.append(succ)
                seen_targets.add(succ)
            edges.add((block_addr, succ))
        if last_mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
            pass

    if not discovered:
        return

    from angr.knowledge_plugins.cfg.cfg_node import BlockNode

    def _seed_node_address_cache() -> None:
        try:
            local_blocks = getattr(function, "_local_blocks", None)
            if isinstance(local_blocks, dict):
                for node in local_blocks.values():
                    if isinstance(node, BlockNode):
                        function._update_addr_to_block_cache(node)
        except Exception:
            return

    def _ensure_block_node_8616(block_addr: int) -> object | None:
        if not isinstance(block_addr, int):
            return None

        node = function.get_node(block_addr)
        if node is not None:
            return node

        local_blocks = getattr(function, "_local_blocks", None)
        if isinstance(local_blocks, dict):
            candidate = local_blocks.get(block_addr)
            if isinstance(candidate, BlockNode):
                function._update_addr_to_block_cache(candidate)
                return function.get_node(block_addr) or candidate

        discovered_block = discovered.get(block_addr)
        if discovered_block is None:
            return None

        block_size = int(getattr(discovered_block, "size", 0))
        if block_size <= 0:
            return None

        try:
            new_node = BlockNode(
                block_addr,
                block_size,
                bytestr=getattr(discovered_block, "bytes", None),
            )
            function._register_node(True, new_node)
            function._update_addr_to_block_cache(new_node)
            return new_node
        except Exception:
            return None

    _seed_node_address_cache()

    for block_addr in sorted(discovered):
        if _ensure_block_node_8616(block_addr) is None:
            continue

    for source_addr, target_addr in sorted(edges):
        source_node = _ensure_block_node_8616(source_addr)
        target_node = _ensure_block_node_8616(target_addr)
        if source_node is None:
            continue
        if target_node is None:
            continue
        try:
            source_capstone = getattr(discovered[source_addr], "capstone", None)
            insns = tuple(getattr(source_capstone, "insns", ()) or ())
            ins_addr = int(getattr(insns[-1], "address", source_addr))
        except Exception:
            ins_addr = source_addr
        try:
            function.transition_graph.add_edge(source_node, target_node, type="transition", ins_addr=ins_addr)
        except Exception:
            continue

    discovered_returns = 0
    for block_addr in sorted(discovered):
        source_node = function.get_node(block_addr)
        if source_node is None:
            continue
        block = discovered[block_addr]
        block_insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not block_insns:
            continue
        last_mnemonic = str(getattr(block_insns[-1], "mnemonic", "")).lower()
        if last_mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
            with contextlib.suppress(Exception):
                function._add_return_site(source_node)
                discovered_returns += 1

    if discovered_returns > 0:
        with contextlib.suppress(Exception):
            setattr(function, "_inertia_x86_16_return_repair_applied", True)


def _count_region_local_functions(cfg, exact_region: tuple[int, int] | None) -> int:
    if exact_region is None or cfg is None:
        return 0
    functions = getattr(cfg, "functions", None)
    if functions is None:
        return 0
    start, end = exact_region
    return sum(1 for addr in functions.keys() if isinstance(addr, int) and start <= addr < end)


def _best_region_function_candidate(
    cfg,
    *,
    exact_region: tuple[int, int] | None,
    preferred_addr: int | None,
):
    def _impl():
        if cfg is None or exact_region is None:
            return None
        functions = getattr(cfg, "functions", None)
        if functions is None:
            return None
        start, end = exact_region
        best = None
        best_rank = None
        for candidate in functions.values():
            caddr = getattr(candidate, "addr", None)
            if not isinstance(caddr, int) or not (start <= caddr < end):
                continue
            c_blocks, c_bytes = _function_recovery_score(candidate)
            c_truncated = _function_recovery_truncated(candidate)
            # Prefer non-truncated, semantically richer region-local bodies.
            distance = abs(caddr - preferred_addr) if isinstance(preferred_addr, int) else 0
            rank = (0 if not c_truncated else 1, -c_bytes, -c_blocks, distance)
            if best is None or rank < best_rank:
                best = candidate
                best_rank = rank
        return best

    return _impl()


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


@trace_function(name="discovery.recover_candidate")
def _recover_candidate_function_pair(
    candidate_project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata: LSTMetadata | None,
    project_entry: int,
    region_span: int,
):
    def _impl():
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
                if _recovery_score_good_enough(score) and not (
                    candidate_addr < project_entry and score[1] <= 0x20 and candidate_region != candidate_regions[-1]
                ):
                    break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
        truncated = False
        if (
            best_pair is not None
            and exact_region is not None
            and _exact_region_recovery_looks_truncated(best_pair[1], exact_region)
        ):
            truncated = True
            try:
                stitched_func, stitched = _stitch_x86_16_exact_function_8616(
                    candidate_project,
                    best_pair[1],
                    exact_region,
                )
                if stitched:
                    best_pair = (best_pair[0], stitched_func)
                    truncated = False
                    _mark_x86_16_stitched_recovery_8616(stitched_func)
                    best_score = _function_recovery_score(stitched_func)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "x86-16 candidate-pair stitching failed for %s: %s",
                    hex(candidate_addr),
                    ex,
                )
            bounded_region = _richest_bounded_recovery_region(
                candidate_addr, image_end=image_end, region_span=region_span
            )
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
        if best_pair is not None and candidate_addr < project_entry and best_score[1] <= 0x20 and candidate_regions:
            truncated = True
            try:
                richer_pair = _pick_function(
                    candidate_project,
                    candidate_addr,
                    regions=[
                        _richest_bounded_recovery_region(candidate_addr, image_end=image_end, region_span=region_span)
                    ],
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
            _repair_x86_16_function_graph_8616(candidate_project, best_pair[1])
            _mark_function_recovery_truncated(best_pair[1], truncated)
            return best_pair
        if last_error is not None:
            raise last_error
        raise KeyError(f"Function {candidate_addr:#x} was not recovered.")

    return _impl()


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


def _function_complexity_local(function) -> tuple[int, int]:
    """Best-effort function complexity when cli_decompilation helper is unavailable."""
    blocks = tuple(getattr(function, "blocks", ()) or ())
    if blocks:
        count = len(blocks)
        total = 0
        for block in blocks:
            size = getattr(block, "size", 0)
            if isinstance(size, int) and size > 0:
                total += size
        return count, total
    block_addrs = tuple(getattr(function, "block_addrs_set", ()) or ())
    if block_addrs:
        return len(block_addrs), 0
    return 0, 0


_function_complexity = _function_complexity_local


def _rank_function_cfg_pairs_for_display(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
) -> list[tuple[object, object]]:
    if not function_cfg_pairs:
        return []
    entry_addr = getattr(project, "entry", None)
    direct_entry_targets = _linear_function_seed_targets(project, entry_addr, max_scan=0x180, include_jumps=False)

    def _display_metrics(function) -> tuple[int, int]:
        complexity_blocks, complexity_bytes = _function_complexity_local(function)
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
        return (
            isinstance(addr, int)
            and isinstance(entry_addr, int)
            and addr < entry_addr
            and (truncated or byte_count > 0x20)
        )

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
    def _impl():
        nonlocal cached_recovered, cached_addrs
        cached_seen = {
            function.addr for _cfg, function in cached_recovered if isinstance(getattr(function, "addr", None), int)
        }
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

    return _impl()


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
    def _impl():
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
            print(f"/* supplemental prologue scan recovered {len(supplemental)} additional function(s) near entry. */")
        return supplemental

    return _impl()


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

    merged_ranges = _normalize_and_merge_ranges_8616(covered_ranges, linked_base, image_end)
    gap_ranges = _compute_gap_ranges_8616(merged_ranges, linked_base, image_end)

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

    _record_recovered_block_targets_8616(
        project,
        recovered_function_pairs,
        search_span=search_span,
        record=_record,
    )

    _record_gap_scan_candidates_8616(
        project,
        main_object,
        linked_base=linked_base,
        gap_ranges=gap_ranges,
        search_span=search_span,
        record=_record,
    )

    return [addr for addr, _meta in sorted(ranked_candidates.items(), key=lambda item: (*item[1], item[0]))]


def _normalize_and_merge_ranges_8616(
    covered_ranges: list[tuple[int, int]], linked_base: int, image_end: int
) -> list[tuple[int, int]]:
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
    return merged_ranges


def _compute_gap_ranges_8616(
    merged_ranges: list[tuple[int, int]], linked_base: int, image_end: int
) -> list[tuple[int, int]]:
    gap_ranges: list[tuple[int, int]] = []
    cursor = linked_base
    for start, end in merged_ranges:
        if cursor < start:
            gap_ranges.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < image_end:
        gap_ranges.append((cursor, image_end))
    return gap_ranges


def _record_recovered_block_targets_8616(project, recovered_function_pairs, *, search_span: int, record) -> None:
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
                record(target_addr, 1, block_addr, target_addr)


def _looks_like_86_16_frame_prologue_8616(project, addr: int) -> bool:
    try:
        block = project.factory.block(addr, size=16, opt_level=0)
    except Exception:
        return False
    insns = block.capstone.insns
    return (
        len(insns) >= 2
        and insns[0].mnemonic == "push"
        and insns[0].op_str == "bp"
        and insns[1].mnemonic == "mov"
        and insns[1].op_str == "bp, sp"
    )


def _record_gap_scan_candidates_8616(
    project,
    main_object,
    *,
    linked_base: int,
    gap_ranges: list[tuple[int, int]],
    search_span: int,
    record,
) -> None:
    def _impl():
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
                    if _looks_like_86_16_frame_prologue_8616(project, addr):
                        record(addr, 0, gap_start, offset)
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
                            record(candidate_addr, 2, gap_start, next_offset)
                offset += insn.size

    return _impl()


def _rank_prologue_scan_candidate_addrs(
    project: angr.Project,
    existing_addrs: set[int],
    *,
    search_span: int = 0x2000,
) -> list[int]:
    def _impl():
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
            ranked_candidates.append((0 if has_dos_interrupt else 1, offset, addr))
        return [addr for _priority, _offset, addr in sorted(ranked_candidates)]

    return _impl()


def _relocation_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
) -> tuple[set[int], set[int]]:
    def _impl():
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

    return _impl()


@dataclass(frozen=True, slots=True)
class _SeedTrace16:
    call_targets: frozenset[int]
    jump_targets: frozenset[int]


def trace_16bit_seed_candidates(
    project,
    code: bytes,
    *,
    linked_base: int,
    windows: Sequence[tuple[int, int]],
) -> _SeedTrace16:
    def _impl():
        """Collect lightweight call/jump seed candidates from 16-bit code bytes."""

        def _window_contains(addr: int) -> bool:
            return any(start <= addr < end for start, end in windows)

        call_targets: set[int] = set()
        jump_targets: set[int] = set()
        n = len(code)

        # near call rel16 / near jmp rel16
        for off in range(max(0, n - 2)):
            op = code[off]
            if op == 0xE8:
                rel = int.from_bytes(code[off + 1 : off + 3], "little", signed=True)
                target = linked_base + off + 3 + rel
                canonical = _resolve_x86_16_call_target(code, target - linked_base)
                if canonical is None:
                    continue
                resolved = linked_base + canonical
                if _window_contains(resolved):
                    call_targets.add(resolved)
                    jump_targets.add(resolved)
                continue
            if op == 0xE9:
                rel = int.from_bytes(code[off + 1 : off + 3], "little", signed=True)
                target = linked_base + off + 3 + rel
                canonical = _resolve_x86_16_function_start(code, target - linked_base)
                if canonical is None:
                    continue
                resolved = linked_base + canonical
                if _window_contains(resolved):
                    jump_targets.add(resolved)

        # far call ptr16:16
        for off in range(max(0, n - 4)):
            if code[off] != 0x9A:
                continue
            tgt_off = int.from_bytes(code[off + 1 : off + 3], "little")
            seg = int.from_bytes(code[off + 3 : off + 5], "little")
            target = linked_base + (seg << 4) + tgt_off
            canonical = _resolve_x86_16_call_target(code, target - linked_base)
            if canonical is None:
                continue
            resolved = linked_base + canonical
            if _window_contains(resolved):
                call_targets.add(resolved)
                jump_targets.add(resolved)

        return _SeedTrace16(frozenset(call_targets), frozenset(jump_targets))

    return _impl()


def _seed_ranking_metadata_context(project: angr.Project):
    metadata = getattr(project, "_inertia_lst_metadata", None)
    recovery_labels = {}
    metadata_fingerprint = None
    include_library_functions = bool(getattr(project, "_inertia_include_library_functions", False))
    if metadata is not None:
        recovery_labels = _recovery_code_labels(metadata)
        signature_matched_addrs = _signature_matched_code_addrs(metadata)
        signature_source = getattr(metadata, "source_format", "")
        allow_signature_seed = include_library_functions or (
            "signature_catalog" not in signature_source and "flair_sig" not in signature_source
        )
        code_ranges = getattr(metadata, "code_ranges", None) or {}
        metadata_fingerprint = {
            "source_format": getattr(metadata, "source_format", None),
            "recovery_code_addrs": sorted(recovery_labels),
            "signature_code_addrs": sorted(signature_matched_addrs),
            "bounded_code_range_count": sum(
                1 for span in code_ranges.values() if span is not None and span[1] > span[0]
            ),
        }
    else:
        signature_matched_addrs = frozenset()
        allow_signature_seed = False
    return metadata, recovery_labels, signature_matched_addrs, allow_signature_seed, metadata_fingerprint


def _seed_ranking_cache_key(
    binary_path,
    project,
    linked_base: int,
    max_addr: int,
    metadata_fingerprint,
    include_library_functions: bool,
):
    return _recovery_cache_key(
        binary_path=Path(binary_path) if isinstance(binary_path, (str, Path)) else None,
        kind="exe_seed_ranking",
        extra={
            "entry": getattr(project, "entry", None),
            "linked_base": linked_base,
            "max_addr": max_addr,
            "ranking_policy": "strong-non-library-v2",
            "include_library_functions": bool(include_library_functions),
            "metadata": metadata_fingerprint,
        },
    )


def _load_seed_ranking_cache(cache_key: str | None):
    cached_ranking = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached_ranking, dict):
        cached_addrs = cached_ranking.get("addrs")
        if isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs):
            return cached_addrs
    return None


def _collect_neighbor_targets_for_seed_ranking(project: angr.Project, code: bytes, linked_base: int) -> set[int]:
    neighbor_targets: set[int] = set()
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
    return neighbor_targets


def _scan_opcode_seed_targets_8616(
    code: bytes,
    *,
    linked_base: int,
    consider,
) -> tuple[set[int], set[int], set[int]]:
    near_call_targets: set[int] = set()
    far_call_targets: set[int] = set()
    prologue_targets: set[int] = set()
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
                consider(resolved, 0)
        if code[offset : offset + 3] == b"\x55\x8b\xec":
            target = linked_base + offset
            prologue_targets.add(target)
            consider(target, 1)
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
            consider(resolved, 0)
    return near_call_targets, far_call_targets, prologue_targets


def _collect_terminal_next_targets_8616(project: angr.Project, code: bytes, linked_base: int, consider) -> set[int]:
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
        consider(next_target, 2)
    return terminal_next_targets


def _final_seed_priority_8616(
    *,
    addr: int,
    distance: int,
    project_entry: int,
    bounded_metadata_spans: dict[int, int],
    near_call_targets: set[int],
    far_call_targets: set[int],
    tracer_call_targets: set[int],
    prologue_targets: set[int],
    terminal_next_targets: set[int],
    neighbor_targets: set[int],
    entry_window_targets: set[int],
    relocation_control_targets: set[int],
    relocation_pointer_targets: set[int],
) -> tuple[int, int, int] | None:
    def _impl():
        metadata_span_len = bounded_metadata_spans.get(addr)
        in_near_call = addr in near_call_targets
        in_far_call = addr in far_call_targets
        in_tracer_call = addr in tracer_call_targets
        in_prologue = addr in prologue_targets
        in_terminal_next = addr in terminal_next_targets
        in_neighbor = addr in neighbor_targets
        in_entry_window = addr in entry_window_targets
        in_relocation_control = addr in relocation_control_targets
        in_relocation_pointer = addr in relocation_pointer_targets
        entry_descends_from_stub = in_entry_window and addr < project_entry
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
            final_priority = 8
        else:
            final_priority = 9
        size_rank = -metadata_span_len if metadata_span_len is not None else 0
        return (final_priority, size_rank, distance)

    return _impl()


def _rank_exe_function_seeds(
    project: angr.Project,
    include_library_functions: bool | None = None,
) -> list[int]:
    def _impl():
        main_object = getattr(project.loader, "main_object", None)
        if main_object is None:
            return []
        lib_functions = include_library_functions
        if lib_functions is None:
            lib_functions = bool(getattr(project, "_inertia_include_library_functions", False))
        binary_path = getattr(main_object, "binary", None)
        max_addr = getattr(main_object, "max_addr", None)
        linked_base = getattr(main_object, "linked_base", None)
        if not isinstance(max_addr, int) or not isinstance(linked_base, int):
            return []
        metadata, recovery_labels, signature_matched_addrs, allow_signature_seed, metadata_fingerprint = (
            _seed_ranking_metadata_context(project)
        )
        cache_key = _seed_ranking_cache_key(
            binary_path,
            project,
            linked_base,
            max_addr,
            metadata_fingerprint,
            bool(lib_functions),
        )
        cached_addrs = _load_seed_ranking_cache(cache_key)
        if cached_addrs is not None:
            return cached_addrs

        try:
            code = bytes(main_object.memory.load(0, max_addr + 1))
        except Exception:
            return []
        seed_windows = _seed_scan_windows(project)
        entry_window_targets = _entry_window_seed_targets(project, code, linked_base=linked_base)

        def _window_contains(addr: int) -> bool:
            return any(start <= addr < end for start, end in seed_windows)

        neighbor_targets = _collect_neighbor_targets_for_seed_ranking(project, code, linked_base)

        ranked: dict[int, tuple[int, int]] = {}
        bounded_metadata_spans: dict[int, int] = {}
        relocation_control_targets: set[int] = set()
        relocation_pointer_targets: set[int] = set()

        def _consider(addr: int, priority: int) -> None:
            if not (linked_base <= addr < linked_base + len(code)):
                return
            if addr in signature_matched_addrs and not allow_signature_seed:
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
        if lib_functions and metadata is not None:
            metadata_labels = recovery_labels
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

        near_call_targets, far_call_targets, prologue_targets = _scan_opcode_seed_targets_8616(
            code,
            linked_base=linked_base,
            consider=_consider,
        )

        relocation_control_targets, relocation_pointer_targets = _relocation_seed_targets(
            project,
            code,
            linked_base=linked_base,
        )
        for target in relocation_control_targets:
            _consider(target, 1)
        for target in relocation_pointer_targets:
            _consider(target, 4)

        terminal_next_targets = _collect_terminal_next_targets_8616(project, code, linked_base, _consider)

        reranked: list[tuple[tuple[int, int, int], int]] = []
        tracer_call_targets = set(tracer.call_targets)
        for addr, (_priority, distance) in ranked.items():
            priority = _final_seed_priority_8616(
                addr=addr,
                distance=distance,
                project_entry=project.entry,
                bounded_metadata_spans=bounded_metadata_spans,
                near_call_targets=near_call_targets,
                far_call_targets=far_call_targets,
                tracer_call_targets=tracer_call_targets,
                prologue_targets=prologue_targets,
                terminal_next_targets=terminal_next_targets,
                neighbor_targets=neighbor_targets,
                entry_window_targets=entry_window_targets,
                relocation_control_targets=relocation_control_targets,
                relocation_pointer_targets=relocation_pointer_targets,
            )
            if priority is not None:
                reranked.append((priority, addr))

        ranked_addrs = [addr for _meta, addr in sorted(reranked)]
        if cache_key is not None:
            _store_cache_json("recovery", cache_key, {"addrs": ranked_addrs})
        return ranked_addrs

    return _impl()


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
        print(
            "/* quick function-entry scan found likely functions using call/prologue/epilogue patterns without helper metadata. */"
        )
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
        print(
            "/* quick EXE function discovery found entry/body functions without needing whole-program control-flow recovery. */"
        )
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
    def _impl():
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
            print(
                "/* hidden-sidecar EXE: using ranked direct-binary preview for the capped display set before broad CFG recovery. */"
            )
        return recovered

    return _impl()


def _rank_hidden_sidecar_pairs_for_display_throughput(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    limit: int,
) -> list[tuple[object, object]]:
    def _impl():
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

    return _impl()


def _recover_cached_function_pairs(
    project: angr.Project,
    *,
    addrs: list[int],
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
) -> list[tuple[object, object]]:
    def _impl():
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
            print(
                f"/* restored {len(recovered)} previously recovered function entr{'y' if len(recovered) == 1 else 'ies'} from recovery cache. */"
            )
        return recovered

    return _impl()


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
    if os.name == "posix" and threading.current_thread() is threading.main_thread() and threading.active_count() == 1:
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


def _seeded_recovery_empty_result(return_addrs: bool):
    return ([], []) if return_addrs else []


def _load_seeded_recovery_from_cache(
    *,
    project: angr.Project,
    timeout: int,
    limit: int | None,
    region_span: int,
    per_function_timeout: int,
    return_addrs: bool,
    cache_key: str | None,
):
    if cache_key is None:
        return None
    cached_payload = _load_cache_json("recovery", cache_key)
    if not isinstance(cached_payload, dict):
        return None
    cached_addrs = cached_payload.get("addrs")
    if not (isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs)):
        return None
    cached_recovered = _recover_cached_function_pairs(
        project,
        addrs=cached_addrs,
        timeout=timeout,
        limit=limit,
        region_span=region_span,
        per_function_timeout=per_function_timeout,
    )
    if not cached_recovered:
        return None
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


def _queue_new_seed_targets_8616(
    target_addrs: list[int],
    *,
    seen_addrs: set[int],
    queued_addrs: set[int],
    covered_ranges: list[tuple[int, int]],
    linked_base: int,
    image_end: int,
    queue_name: str,
    pending_gap_addrs: list[int],
    pending_neighbor_addrs: list[int],
) -> None:
    queued_targets: list[int] = []
    for target_addr in target_addrs:
        if target_addr in seen_addrs or target_addr in queued_addrs:
            continue
        if _addr_in_ranges(target_addr, covered_ranges):
            continue
        if not (linked_base <= target_addr < image_end):
            continue
        queued_targets.append(target_addr)
    if not queued_targets:
        return
    if queue_name == "gap":
        pending_gap_addrs.extend(queued_targets)
    else:
        pending_neighbor_addrs.extend(queued_targets)
    queued_addrs.update(queued_targets)


def _recover_seeded_exe_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
    return_addrs: bool = False,
    include_library_functions: bool | None = None,
):
    def _impl():
        main_object = getattr(project.loader, "main_object", None)
        if main_object is None:
            return _seeded_recovery_empty_result(return_addrs)
        binary_path = getattr(main_object, "binary", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
            return _seeded_recovery_empty_result(return_addrs)

        ranked_seeds = _rank_exe_function_seeds(
            project,
            include_library_functions=include_library_functions,
        )
        if not ranked_seeds:
            return _seeded_recovery_empty_result(return_addrs)

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
        cached_result = _load_seeded_recovery_from_cache(
            project=project,
            timeout=timeout,
            limit=limit,
            region_span=region_span,
            per_function_timeout=per_function_timeout,
            return_addrs=return_addrs,
            cache_key=cache_key,
        )
        if cached_result is not None:
            return cached_result

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

            linear_targets = list(_linear_function_seed_targets(project, function.addr, include_jumps=False))
            neighbor_targets: list[int] = []
            for target in collect_neighbor_call_targets(function):
                target_addr = getattr(target, "target_addr", None)
                if isinstance(target_addr, int):
                    neighbor_targets.append(target_addr)
            if _needs_pre_entry_body_supplement(function, project.entry):
                _queue_new_seed_targets_8616(
                    _prioritized_pre_entry_follow_on_targets(
                        project,
                        [(function_cfg, function)],
                        covered_ranges=covered_ranges,
                        existing_addrs=seen_addrs | queued_addrs,
                        image_end=image_end,
                    ),
                    seen_addrs=seen_addrs,
                    queued_addrs=queued_addrs,
                    covered_ranges=covered_ranges,
                    linked_base=linked_base,
                    image_end=image_end,
                    queue_name="gap",
                    pending_gap_addrs=pending_gap_addrs,
                    pending_neighbor_addrs=pending_neighbor_addrs,
                )
            else:
                _queue_new_seed_targets_8616(
                    neighbor_targets,
                    seen_addrs=seen_addrs,
                    queued_addrs=queued_addrs,
                    covered_ranges=covered_ranges,
                    linked_base=linked_base,
                    image_end=image_end,
                    queue_name="neighbor",
                    pending_gap_addrs=pending_gap_addrs,
                    pending_neighbor_addrs=pending_neighbor_addrs,
                )

        if recovered_addrs:
            if cache_key is not None:
                _store_cache_json(
                    "recovery",
                    cache_key,
                    {"addrs": recovered_addrs},
                )
            print(f"/* quick function-entry scan recovered {len(recovered_addrs)} additional function(s). */")
        return (recovered, recovered_addrs) if return_addrs else recovered

    return _impl()


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
    def _impl():
        project._inertia_decompiler_stage = "recovery"
        candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
        recovery_timeout = max(1, timeout if prefer_fast_recovery else min(timeout, 10))

        def _repair_recovered_entry_function(result, regions):
            if project.arch.name != "86_16":
                return result
            if not isinstance(result, tuple) or len(result) != 2:
                return result
            if not regions:
                return result
            cfg, function = result
            region = regions[0]
            try:
                stitched_func, stitched = _stitch_x86_16_exact_function_8616(
                    project,
                    function,
                    region,
                )
            except Exception as ex:  # noqa: BLE001
                logging.getLogger(__name__).debug(
                    "x86-16 fallback entry stitching failed for %s: %s",
                    hex(project.entry),
                    ex,
                )
                stitched_func, stitched = function, False
            if stitched:
                _mark_x86_16_stitched_recovery_8616(stitched_func)
                function = stitched_func
            _repair_x86_16_function_graph_8616(project, function)
            return cfg, function

        with _analysis_timeout(recovery_timeout):
            if prefer_fast_recovery:
                project._inertia_decompiler_stage = "recovery:fast"
                for fast_window in _x86_16_fast_recovery_windows(window, low_memory=low_memory):
                    try:
                        if project.arch.name == "86_16":
                            fast_regions = [_infer_x86_16_linear_region(project, project.entry, window=fast_window)]
                        else:
                            fast_regions = [(project.entry, project.entry + fast_window)]
                        return _repair_recovered_entry_function(
                            _pick_function_lean(
                                project,
                                project.entry,
                                regions=fast_regions,
                                data_references=False,
                                extend_far_calls=False,
                            ),
                            fast_regions,
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
                        regions = [_infer_x86_16_linear_region(project, project.entry, window=candidate_window)]
                    else:
                        regions = [(project.entry, project.entry + candidate_window)]
                    try:
                        return _repair_recovered_entry_function(
                            _pick_function(
                                project,
                                project.entry,
                                regions=regions,
                                data_references=False,
                                force_smart_scan=False,
                            ),
                            regions,
                        )
                    except KeyError:
                        pass
                    return _repair_recovered_entry_function(
                        _pick_function(
                            project,
                            project.entry,
                            regions=regions,
                            data_references=True if project.arch.name == "86_16" else None,
                        ),
                        regions,
                    )
                except _AnalysisTimeout:
                    raise
                except KeyError:
                    continue
            raise _AnalysisTimeout()

    return _impl()


def _derive_lst_exact_region_8616(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    *,
    addr: int,
    name: str,
) -> tuple[int, int] | None:
    def _impl():
        exact_region = _lst_code_region(lst_metadata, addr)
        if exact_region is None and isinstance(name, str) and name:
            target_names = {name, name.lstrip("_")}
            label_candidates: list[tuple[int, tuple[int, int]]] = []
            for label_addr, label_name in (_visible_code_labels(lst_metadata) or {}).items():
                if not isinstance(label_name, str) or label_name not in target_names:
                    continue
                span = _lst_code_region(lst_metadata, label_addr)
                if span is None:
                    continue
                label_candidates.append((abs(int(label_addr) - int(addr)), span))
            if label_candidates:
                label_candidates.sort(key=lambda item: item[0])
                exact_region = label_candidates[0][1]
                print(
                    f"[dbg] recovered exact-region by sidecar name for {name}: "
                    f"{exact_region[0]:#x}-{exact_region[1]:#x}",
                    file=sys.stderr,
                    flush=True,
                )
        if (
            project.arch.name == "86_16"
            and exact_region is not None
            and isinstance(addr, int)
            and exact_region[0] < addr < exact_region[1]
        ):
            try:
                probe = bytes(project.loader.memory.load(addr, min(4, max(0, exact_region[1] - addr))))
            except Exception:
                probe = b""
            if _looks_like_x86_16_function_prologue(probe, 0):
                exact_region = (addr, exact_region[1])
                print(
                    f"[dbg] adjusted exact-region start for {name}: "
                    f"{addr:#x}-{exact_region[1]:#x} (from containing sidecar span)"
                )
        if project.arch.name == "86_16" and exact_region is not None:
            start, end = exact_region
            try:
                probe = bytes(
                    project.loader.memory.load(
                        start,
                        min(_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT, max(0, end - start)),
                    )
                )
            except Exception:
                probe = b""
            resolved_start = _resolve_x86_16_function_start(
                probe,
                0,
                max_padding=_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT,
            )
            if isinstance(resolved_start, int) and resolved_start > 0:
                adjusted_start = start + resolved_start
                if adjusted_start < end:
                    exact_region = (adjusted_start, end)
                    print(
                        f"[dbg] adjusted exact-region start for {name}: "
                        f"{adjusted_start:#x}-{end:#x} (from sidecar padding)"
                    )
        if project.arch.name == "86_16" and exact_region is not None:
            exact_region = _maybe_extend_x86_16_exact_region_terminator(project, exact_region)
            exact_size = max(0, exact_region[1] - exact_region[0])
            if exact_size <= 0x20 and not _x86_16_exact_region_has_terminator(project, exact_region):
                exact_region = None
        return exact_region

    return _impl()


def _try_rebased_exact_region_recovery_8616(
    project: angr.Project,
    *,
    exact_region: tuple[int, int] | None,
    timeout: int,
    name: str,
):
    if project.arch.name != "86_16" or exact_region is None:
        return None
    exact_region_size = max(0, exact_region[1] - exact_region[0])
    loader = getattr(project, "loader", None)
    project_memory = getattr(loader, "memory", None)
    if project_memory is None or not hasattr(project_memory, "load"):
        return None
    slice_plan = plan_x86_16_exact_slice(*exact_region)
    enable_rebased_exact_slice = _env_flag_enabled_8616("INERTIA_ENABLE_REBASED_EXACT_SLICE", "1")
    use_rebased_exact_slice = (
        enable_rebased_exact_slice and slice_plan.needs_rebased_slice and 0x20 <= exact_region_size <= 0x280
    )
    if not use_rebased_exact_slice:
        return None
    code = bytes(
        project.loader.memory.load(slice_plan.original_start, slice_plan.original_end - slice_plan.original_start)
    )
    if code:
        nop_ratio = float(code.count(0x90)) / float(len(code))
        if nop_ratio > 0.30:
            return None
    slice_project = _build_project_from_bytes(
        code,
        base_addr=slice_plan.slice_base,
        entry_point=slice_plan.slice_start,
    )
    slice_project._inertia_original_project = project
    slice_project._inertia_original_linear_delta = exact_region[0] - slice_plan.slice_start
    tiny_rebased_core = exact_region_size <= 0x30
    slice_project._inertia_disable_ail_narrowing = tiny_rebased_core
    slice_project._inertia_disable_complex_expr_scan = tiny_rebased_core
    slice_project._inertia_fast_block_peephole = tiny_rebased_core
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
    try:
        stitched_func, stitched = _stitch_x86_16_exact_function_8616(
            slice_project,
            func,
            slice_region,
        )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "x86-16 rebased exact function stitching failed for %s: %s",
            hex(slice_plan.slice_start),
            ex,
        )
        stitched_func, stitched = func, False
    if stitched:
        func = stitched_func
        _mark_x86_16_stitched_recovery_8616(func)
    func.name = name
    _commit_exact_region_function_to_kb_8616(slice_project, cfg, func, slice_region)
    mark_function_original_addr(func, exact_region[0])
    with contextlib.suppress(Exception):
        source_func = project.kb.functions.function(addr=exact_region[0], create=False)
        source_prototype = getattr(source_func, "prototype", None) if source_func is not None else None
        if source_prototype is not None:
            func.prototype = source_prototype
        source_cc = getattr(source_func, "calling_convention", None) if source_func is not None else None
        if source_cc is not None:
            func.calling_convention = source_cc
        source_info = getattr(source_func, "info", None) if source_func is not None else None
        if isinstance(source_info, dict):
            func_info = getattr(func, "info", None)
            if not isinstance(func_info, dict):
                func_info = {}
                func.info = func_info
            for key, value in source_info.items():
                func_info.setdefault(key, value)
    print(
        f"[dbg] rebased exact-region recovery for {name}: "
        f"{exact_region[0]:#x}-{exact_region[1]:#x} -> {slice_region[0]:#x}-{slice_region[1]:#x}"
    )
    return cfg, func


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
    def _impl():
        addr = offset if getattr(lst_metadata, "absolute_addrs", False) else project.entry + offset
        exact_region = _derive_lst_exact_region_8616(project, lst_metadata, addr=addr, name=name)
        rebased = _try_rebased_exact_region_recovery_8616(
            project,
            exact_region=exact_region,
            timeout=timeout,
            name=name,
        )
        if rebased is not None:
            return rebased
        with _analysis_timeout(max(1, timeout)):
            if project.arch.name == "86_16":
                can_run_default_lean = (
                    hasattr(project, "analyses") or _pick_function_lean is not _DEFAULT_PICK_FUNCTION_LEAN
                )
                fast_windows = (
                    _x86_16_fast_recovery_windows(window, low_memory=low_memory) if can_run_default_lean else ()
                )
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
                    except _AnalysisTimeout:
                        raise
                    except Exception as ex:  # noqa: BLE001
                        # Lean CFGFast is a best-effort acceleration path.
                        # If a lightweight test/project stub cannot support it,
                        # fall back to regular bounded recovery windows.
                        last_error = ex
                else:
                    cfg = None
                    func = None

                if cfg is not None and func is not None:
                    if _exact_region_recovery_looks_truncated(func, exact_region):
                        block_addrs = tuple(
                            int(getattr(block, "addr"))
                            for block in tuple(getattr(func, "blocks", ()) or ())
                            if isinstance(getattr(block, "addr", None), int)
                        )
                        cfg_functions = getattr(getattr(cfg, "kb", None), "functions", None)
                        diagnostics = build_exact_region_diagnostics_8616(
                            name,
                            requested_start=exact_region[0],
                            requested_end=exact_region[1],
                            covered_block_addrs=block_addrs,
                            cfg_functions=cfg_functions,
                            proc_identity=name,
                        )
                        split = classify_region_split_8616(diagnostics)
                        if split.is_split:
                            print(
                                f"[dbg] {format_exact_region_diagnostics_8616(diagnostics)}",
                                file=sys.stderr,
                                flush=True,
                            )
                        best_cfg = cfg
                        best_func = func
                        best_score = _function_recovery_score(func)
                        try:
                            stitched_func, stitched = _stitch_x86_16_exact_function_8616(
                                project,
                                best_func,
                                exact_region,
                            )
                        except Exception as ex:
                            logging.getLogger(__name__).debug(
                                "x86-16 exact function stitching failed for %s: %s",
                                hex(addr),
                                ex,
                            )
                            stitched_func, stitched = best_func, False
                        if stitched:
                            best_func = stitched_func
                            best_score = _function_recovery_score(best_func)
                            _mark_x86_16_stitched_recovery_8616(best_func)
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
                            if _should_replace_exact_region_candidate_8616(best_func, retried_func, exact_region):
                                best_cfg = retried_cfg
                                best_func = retried_func
                                best_score = retried_score
                        # Escalate through richer candidate-pair recovery when the
                        # exact-region target still looks truncated.
                        if _exact_region_recovery_looks_truncated(best_func, exact_region):
                            main_object = getattr(project.loader, "main_object", None)
                            linked_base = getattr(main_object, "linked_base", None)
                            max_addr = getattr(main_object, "max_addr", None)
                            if isinstance(linked_base, int) and isinstance(max_addr, int):
                                try:
                                    cand_cfg, cand_func = _recover_candidate_function_pair(
                                        project,
                                        candidate_addr=addr,
                                        image_end=linked_base + max_addr + 1,
                                        metadata=lst_metadata,
                                        project_entry=project.entry,
                                        region_span=max(window, max(0x180, exact_region[1] - exact_region[0])),
                                    )
                                    cand_score = _function_recovery_score(cand_func)
                                    if _should_replace_exact_region_candidate_8616(best_func, cand_func, exact_region):
                                        best_cfg = cand_cfg
                                        best_func = cand_func
                                        best_score = cand_score
                                except Exception:
                                    pass
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

        if exact_region is not None:
            selected_blocks, selected_bytes = _function_recovery_score(func)
            selected_tiny = selected_blocks <= 2 and selected_bytes <= 0x20 and not _function_recovery_truncated(func)
            if selected_tiny:
                promoted = _best_region_function_candidate(
                    cfg,
                    exact_region=exact_region,
                    preferred_addr=addr,
                )
                if promoted is not None:
                    promoted_blocks, promoted_bytes = _function_recovery_score(promoted)
                    if (promoted_bytes, promoted_blocks) > (selected_bytes, selected_blocks):
                        print(
                            f"[dbg] promoted exact-region candidate for {name}: "
                            f"{func.addr:#x}({selected_blocks}/{selected_bytes}) -> "
                            f"{promoted.addr:#x}({promoted_blocks}/{promoted_bytes})",
                            file=sys.stderr,
                            flush=True,
                        )
                        func = promoted

        func.name = name
        if exact_region is not None:
            _commit_exact_region_function_to_kb_8616(project, cfg, func, exact_region)
        return cfg, func

    return _impl()


def _recover_ranked_binary_function(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
):
    def _impl():
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

    return _impl()


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


def _is_plausible_code_seed(
    project: angr.Project,
    addr: int,
    *,
    metadata: LSTMetadata | None = None,
) -> bool:
    def _impl():
        region = _lst_code_region(metadata, addr)
        probe_size = 16
        if region is not None:
            region_size = max(0, region[1] - region[0])
            if region_size == 0:
                return False
            probe_size = min(probe_size, region_size)
        if probe_size <= 0:
            return False
        try:
            data = bytes(project.loader.memory.load(addr, probe_size))
        except Exception:
            return True
        if not data:
            return False
        if all(byte == 0x00 for byte in data):
            return False
        if all(byte == 0xFF for byte in data):
            return False
        if region is not None:
            region_size = max(0, region[1] - region[0])
            if 0 < region_size <= 8:
                try:
                    block = project.factory.block(addr, size=region_size, opt_level=0)
                    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
                except Exception:
                    insns = ()
                if not insns:
                    return False
                terminators = {"ret", "retn", "retf", "jmp", "ljmp", "call", "lcall", "int", "iret"}
                if not any(getattr(insn, "mnemonic", "").lower() in terminators for insn in insns):
                    return False
        # If sidecar does not provide an exact code region and the seed begins with
        # a null-padded stream, treat it as data-like unless proven otherwise.
        if region is None:
            head = data[:8]
            if len(head) >= 4 and head[:2] == b"\x00\x00" and sum(1 for b in head if b == 0x00) >= 4:
                return False
        return True

    return _impl()


def _filter_noncode_labeled_entries(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> list[tuple[int, str]]:
    filtered: list[tuple[int, str]] = []
    for addr, name in labeled_entries:
        if _is_plausible_code_seed(project, addr, metadata=metadata):
            filtered.append((addr, name))
    return filtered


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
        "anchkstk",
        "_anchkstk",
        "__anchkstk",
        "analloca_probe",
        "_analloca_probe",
        "__analloca_probe",
        "chkstk",
        "_chkstk",
        "__chkstk",
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
        if addr == entry_addr:
            return (0, 0, addr)
        if lowered in {"main", "_main"} or lowered.endswith("main"):
            return (1, abs(addr - entry_addr), addr)
        for prefix, bucket in preferred_app_prefix_buckets:
            if lowered.startswith(prefix):
                return (bucket + 1, abs(addr - entry_addr), addr)
        if lowered in {"start", "_start"} or lowered.endswith("_start"):
            return (11, abs(addr - entry_addr), addr)
        if lowered in runtime_helper_names:
            helper_bucket = 15 if size is not None and size <= 0x20 else 16
            return (helper_bucket, abs(addr - entry_addr), addr)
        if "padding" in lowered or lowered.startswith("align_"):
            return (18, abs(addr - entry_addr), addr)
        if size is not None and size <= 0x20:
            return (12, abs(addr - entry_addr), addr)
        if size is not None and size <= 0x80:
            return (13, abs(addr - entry_addr), addr)
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
    def _impl():
        filtered_entries = _filter_noncode_labeled_entries(project, labeled_entries, metadata)
        cache_key = _sidecar_label_ranking_cache_key(project, filtered_entries, metadata)
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

        ranked = _rank_labeled_function_entries(project, filtered_entries, metadata)
        if cache_key is not None:
            _store_cache_json("recovery", cache_key, {"entries": ranked})
        return ranked, False

    return _impl()


def _select_sidecar_showcase_entries(
    project: angr.Project,
    metadata: LSTMetadata,
    labeled_entries: list[tuple[int, str]],
    *,
    max_count: int,
    ranked_entries: list[tuple[int, str]] | None = None,
) -> list[tuple[int, str]]:
    def _impl():
        ranked = (
            ranked_entries
            if ranked_entries is not None
            else _rank_labeled_function_entries(project, labeled_entries, metadata)
        )
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
            addr for addr, name in ranked if name.lower() in {"main", "_main"} or name.lower().endswith("main")
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

    return _impl()


def _format_sidecar_function_catalog(
    metadata: LSTMetadata,
    *,
    limit: int | None = None,
    code_labels: Mapping[int, str] | None = None,
) -> str:
    lines: list[str] = []
    entries = sorted((code_labels if code_labels is not None else _visible_code_labels(metadata)).items())
    if limit is not None and limit > 0:
        entries = entries[:limit]
    for addr, name in entries:
        region = _lst_code_region(metadata, addr)
        if region is not None:
            size = region[1] - region[0]
            lines.append(f"/* {addr:#x} {name} size={size:#x} range=[{region[0]:#x}, {region[1]:#x}) */")
        else:
            lines.append(f"/* {addr:#x} {name} */")
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


def _env_flag_enabled_8616(name: str, default: str = "") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _try_recover_direct_addr_from_sidecar_region(
    *,
    project: angr.Project,
    addr: int,
    timeout: int,
    window: int,
    low_memory_path: bool,
    lst_metadata: LSTMetadata | None,
    function_label: str | None,
    strict_direct_addr: bool,
):
    def _impl():
        if lst_metadata is None or project.arch.name != "86_16":
            return None
        sidecar_region_for_addr = _lst_code_region(lst_metadata, addr)
        if sidecar_region_for_addr is None:
            return None
        sidecar_addr = sidecar_region_for_addr[0]
        effective_label = function_label or _lst_code_label(lst_metadata, addr, project.entry)
        if effective_label:
            target_names = {effective_label, effective_label.lstrip("_")}
            label_matches: list[int] = []
            for label_addr, label_name in (_visible_code_labels(lst_metadata) or {}).items():
                if isinstance(label_addr, int) and isinstance(label_name, str) and label_name in target_names:
                    label_matches.append(label_addr)
            if label_matches:
                sidecar_addr = min(label_matches, key=lambda la: abs(la - addr))
        recover_addr = addr if strict_direct_addr else sidecar_addr
        code_name = _lst_code_label(lst_metadata, recover_addr, project.entry) or f"sub_{recover_addr:x}"
        try:
            return _recover_lst_function(
                project,
                lst_metadata,
                recover_addr if lst_metadata.absolute_addrs else recover_addr - project.entry,
                code_name,
                timeout=timeout,
                window=window,
                low_memory=low_memory_path,
            )
        except _AnalysisTimeout:
            return None
        except Exception as ex:  # noqa: BLE001
            logging.getLogger(__name__).debug(
                "sidecar region lst recovery failed for %s: %s",
                hex(recover_addr),
                ex,
            )
            return None

    return _impl()


def _try_recover_direct_addr_from_sidecar_label(
    *,
    project: angr.Project,
    addr: int,
    timeout: int,
    window: int,
    low_memory_path: bool,
    lst_metadata: LSTMetadata | None,
    function_label: str | None,
):
    def _impl():
        if lst_metadata is None or project.arch.name != "86_16":
            return None
        effective_label = function_label or _lst_code_label(lst_metadata, addr, project.entry)
        if not isinstance(effective_label, str) or not effective_label:
            return None
        target_names = {effective_label, effective_label.lstrip("_")}
        label_matches = [
            label_addr
            for label_addr, label_name in (_visible_code_labels(lst_metadata) or {}).items()
            if isinstance(label_addr, int) and isinstance(label_name, str) and label_name in target_names
        ]
        if not label_matches:
            return None
        recover_addr = min(label_matches, key=lambda la: abs(la - addr))
        try:
            return _recover_lst_function(
                project,
                lst_metadata,
                recover_addr if lst_metadata.absolute_addrs else recover_addr - project.entry,
                effective_label,
                timeout=timeout,
                window=window,
                low_memory=low_memory_path,
            )
        except _AnalysisTimeout:
            return None
        except Exception as ex:  # noqa: BLE001
            logging.getLogger(__name__).debug(
                "sidecar label lst recovery failed for %s: %s",
                hex(recover_addr),
                ex,
            )
            return None

    return _impl()


@trace_function(name="discovery.recover_direct_addr")
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
    def _impl():
        nonlocal addr
        use_sidecar_start_for_direct_addr = _env_flag_enabled_8616("INERTIA_DIRECT_ADDR_USE_SIDECAR_START")
        if project.arch.name == "86_16" and lst_metadata is not None and use_sidecar_start_for_direct_addr:
            sidecar_region = _lst_code_region(lst_metadata, addr)
            if sidecar_region is not None:
                sidecar_addr = sidecar_region[0]
                if isinstance(sidecar_addr, int) and sidecar_addr >= 0 and sidecar_addr != addr:
                    addr = sidecar_addr

        prefer_lst_direct = _env_flag_enabled_8616("INERTIA_DIRECT_ADDR_PREFER_LST", "1")
        strict_direct_addr = _env_flag_enabled_8616("INERTIA_DIRECT_ADDR_STRICT")
        if prefer_lst_direct:
            recovered = _try_recover_direct_addr_from_sidecar_region(
                project=project,
                addr=addr,
                timeout=timeout,
                window=window,
                low_memory_path=low_memory_path,
                lst_metadata=lst_metadata,
                function_label=function_label,
                strict_direct_addr=strict_direct_addr,
            )
            if recovered is not None:
                return recovered
            recovered = _try_recover_direct_addr_from_sidecar_label(
                project=project,
                addr=addr,
                timeout=timeout,
                window=window,
                low_memory_path=low_memory_path,
                lst_metadata=lst_metadata,
                function_label=function_label,
            )
            if recovered is not None:
                return recovered
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

        candidate_addr = addr
        if project.arch.name == "86_16" and lst_metadata is not None:
            sidecar_region = _lst_code_region(lst_metadata, addr)
            if sidecar_region is not None and isinstance(sidecar_region[0], int):
                candidate_addr = sidecar_region[0]

        with _analysis_timeout(timeout):
            if project.arch.name == "86_16":
                main_object = getattr(project.loader, "main_object", None)
                linked_base = getattr(main_object, "linked_base", None)
                max_addr = getattr(main_object, "max_addr", None)
                if isinstance(linked_base, int) and isinstance(max_addr, int):
                    return _recover_candidate_function_pair(
                        project,
                        candidate_addr=candidate_addr,
                        image_end=linked_base + max_addr + 1,
                        metadata=lst_metadata,
                        project_entry=project.entry,
                        region_span=max(window, 0x180),
                    )
                regions = [_infer_x86_16_linear_region(project, addr, window=window)]
            else:
                regions = [(addr, addr + window)]
            recovered = _pick_function(project, addr, regions=regions)
            _repair_x86_16_function_graph_8616(project, recovered[1])
            return recovered

    return _impl()
