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
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.analysis_helpers import InterruptCall, collect_dos_int21_calls, interrupt_service_name

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

from .cli_c_ast_rewrites import _c_constant_value, _same_c_expression, _unwrap_c_casts

structured_c = structured_codegen.c

print = _timestamped_print
__all__ = ['InterruptWrapperCall', 'InterruptWrapperFieldAccess', '_normalize_interrupt_wrapper_name', '_interrupt_wrapper_call_kind', '_interrupt_wrapper_call_signature', '_interrupt_wrapper_field_path', '_interrupt_wrapper_field_role', '_interrupt_wrapper_field_access_summary', '_interrupt_wrapper_call_text', 'collect_interrupt_wrapper_calls', 'collect_interrupt_wrapper_field_accesses', '_attach_interrupt_wrapper_callees', '_interrupt_wrapper_register_state_value', '_interrupt_wrapper_record_register_write', '_interrupt_wrapper_helper_call_expr', '_interrupt_wrapper_result_helper_expr', '_interrupt_wrapper_result_extract_expr', '_interrupt_wrapper_result_replacement', '_interrupt_wrapper_result_expr_replacement', '_lower_interrupt_wrapper_result_reads', '_attach_dos_pseudo_callees']

def _iter_c_nodes(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, (list, tuple)):
            stack.extend(reversed(current))
            continue
        for attr in ("lhs", "rhs", "operand", "condition", "condition_and_nodes", "else_node", "args", "statements", "expr", "variable"):
            child = getattr(current, attr, None)
            if child is None:
                continue
            if attr == "condition_and_nodes" and isinstance(child, list):
                for cond, body in reversed(child):
                    stack.append(body)
                    stack.append(cond)
            else:
                stack.append(child)

@dataclass(frozen=True)
class InterruptWrapperCall:
    callee_name: str
    canonical_name: str
    kind: str
    arguments: tuple[object, ...]
    vector_arg: object | None = None
    inregs_arg: object | None = None
    outregs_arg: object | None = None
    sregs_arg: object | None = None

@dataclass(frozen=True)
class InterruptWrapperFieldAccess:
    base_name: str
    field_path: tuple[str, ...]
    expr: object

def _normalize_interrupt_wrapper_name(name: str | None) -> str | None:
    if not isinstance(name, str) or not name:
        return None
    return name.lstrip("_")

def _interrupt_wrapper_call_kind(name: str | None, args: tuple[object, ...] | None = None) -> str | None:
    canonical = _normalize_interrupt_wrapper_name(name)
    if canonical not in {"int86", "int86x", "intdos", "intdosx"}:
        if canonical != "CallReturn" or not args:
            return None
        first_arg = _unwrap_c_casts(args[0])
        first_value = _c_constant_value(first_arg)
        if len(args) >= 4:
            return "int86x" if first_value is not None else "intdosx"
        if len(args) >= 3:
            return "int86" if first_value is not None else "intdos"
        return None
    return canonical

def _interrupt_wrapper_call_signature(node: structured_c.CFunctionCall) -> InterruptWrapperCall | None:
    callee_name = None
    callee_func = getattr(node, "callee_func", None)
    if callee_func is not None:
        callee_name = getattr(callee_func, "name", None)
    elif isinstance(getattr(node, "callee_target", None), str):
        callee_name = getattr(node, "callee_target")

    args = tuple(getattr(node, "args", ()) or ())
    kind = _interrupt_wrapper_call_kind(callee_name, args)
    if kind is None:
        return None
    if kind in {"int86", "int86x"}:
        vector_arg = args[0] if len(args) >= 1 else None
        inregs_arg = args[1] if len(args) >= 2 else None
        outregs_arg = args[2] if len(args) >= 3 else None
        sregs_arg = args[3] if kind == "int86x" and len(args) >= 4 else None
    else:
        vector_arg = None
        inregs_arg = args[0] if len(args) >= 1 else None
        outregs_arg = args[1] if len(args) >= 2 else None
        sregs_arg = args[2] if kind == "intdosx" and len(args) >= 3 else None

    return InterruptWrapperCall(
        callee_name=callee_name or kind,
        canonical_name=kind,
        kind=kind,
        arguments=args,
        vector_arg=vector_arg,
        inregs_arg=inregs_arg,
        outregs_arg=outregs_arg,
        sregs_arg=sregs_arg,
    )

def _interrupt_wrapper_field_path(expr) -> InterruptWrapperFieldAccess | None:
    path: list[str] = []
    current = expr
    while isinstance(current, structured_c.CVariableField):
        field = getattr(current, "field", None)
        field_name = getattr(field, "field", None)
        if not isinstance(field_name, str) or not field_name:
            return None
        path.append(field_name)
        current = getattr(current, "variable", None)

    if not isinstance(current, structured_c.CVariable):
        return None

    base_name = getattr(current, "name", None)
    if not isinstance(base_name, str) or not base_name:
        return None
    if not path:
        return None

    path.reverse()
    return InterruptWrapperFieldAccess(base_name=base_name, field_path=tuple(path), expr=expr)

def _interrupt_wrapper_field_role(base_name: str) -> str:
    if base_name == "inregs":
        return "input"
    if base_name == "outregs":
        return "output"
    if base_name == "sregs":
        return "segment"
    return "other"

def _interrupt_wrapper_field_access_summary(
    accesses: list[InterruptWrapperFieldAccess],
) -> dict[str, list[InterruptWrapperFieldAccess]]:
    summary: dict[str, list[InterruptWrapperFieldAccess]] = {
        "input": [],
        "output": [],
        "segment": [],
        "other": [],
    }
    for access in accesses:
        summary.setdefault(_interrupt_wrapper_field_role(access.base_name), []).append(access)
    return summary

def _interrupt_wrapper_call_text(sig: InterruptWrapperCall) -> str:
    args = [str(arg) for arg in sig.arguments if arg is not None]
    return f"{sig.canonical_name}({', '.join(args)})"

def collect_interrupt_wrapper_calls(codegen) -> list[InterruptWrapperCall]:
    if getattr(codegen, "cfunc", None) is None:
        return []

    calls: list[InterruptWrapperCall] = []
    for node in _iter_c_nodes(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        sig = _interrupt_wrapper_call_signature(node)
        if sig is not None:
            calls.append(sig)
    return calls

def collect_interrupt_wrapper_field_accesses(codegen) -> list[InterruptWrapperFieldAccess]:
    if getattr(codegen, "cfunc", None) is None:
        return []

    accesses: list[InterruptWrapperFieldAccess] = []
    for node in _iter_c_nodes(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariableField):
            continue
        access = _interrupt_wrapper_field_path(node)
        if access is not None and access.base_name in {"inregs", "outregs", "sregs"}:
            accesses.append(access)
    return accesses

def _attach_interrupt_wrapper_callees(project: angr.Project, codegen, api_style: str) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    wrapper_calls = collect_interrupt_wrapper_calls(codegen)
    wrapper_field_accesses = collect_interrupt_wrapper_field_accesses(codegen)
    if not wrapper_calls and not wrapper_field_accesses:
        return False

    cache = getattr(project, "_inertia_interrupt_wrappers", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_interrupt_wrappers", cache)

    cache[getattr(codegen.cfunc, "addr", 0)] = {
        "api_style": api_style,
        "calls": wrapper_calls,
        "field_accesses": wrapper_field_accesses,
        "field_access_summary": _interrupt_wrapper_field_access_summary(wrapper_field_accesses),
    }

    changed = False
    for node in _iter_c_nodes(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        sig = _interrupt_wrapper_call_signature(node)
        if sig is None:
            continue
        callee_func = getattr(node, "callee_func", None)
        if callee_func is None:
            continue
        if getattr(callee_func, "name", None) != sig.canonical_name:
            callee_func.name = sig.canonical_name
            changed = True

    return changed

def _interrupt_wrapper_register_state_value(
    state: dict[str, dict[tuple[str, ...], int]],
    base_name: str,
    field_path: tuple[str, ...],
) -> int | None:
    return state.get(base_name, {}).get(field_path)

def _interrupt_wrapper_record_register_write(
    state: dict[str, dict[tuple[str, ...], int]],
    base_name: str,
    field_path: tuple[str, ...],
    value: int | None,
) -> None:
    if value is None:
        return

    regs = state.setdefault(base_name, {})
    regs[field_path] = value & 0xFFFF

    if field_path == ("x", "ax"):
        ax = value & 0xFFFF
        regs[("h", "ah")] = (ax >> 8) & 0xFF
        regs[("h", "al")] = ax & 0xFF
    elif field_path == ("x", "bx"):
        bx = value & 0xFFFF
        regs[("h", "bh")] = (bx >> 8) & 0xFF
        regs[("h", "bl")] = bx & 0xFF
    elif field_path == ("x", "cx"):
        cx = value & 0xFFFF
        regs[("h", "ch")] = (cx >> 8) & 0xFF
        regs[("h", "cl")] = cx & 0xFF
    elif field_path == ("x", "dx"):
        dx = value & 0xFFFF
        regs[("h", "dh")] = (dx >> 8) & 0xFF
        regs[("h", "dl")] = dx & 0xFF
    elif field_path == ("h", "ah"):
        ah = value & 0xFF
        regs[("h", "ah")] = ah
        al = regs.get(("h", "al"))
        if al is not None:
            regs[("x", "ax")] = ((ah & 0xFF) << 8) | (al & 0xFF)
    elif field_path == ("h", "al"):
        al = value & 0xFF
        regs[("h", "al")] = al
        ah = regs.get(("h", "ah"))
        if ah is not None:
            regs[("x", "ax")] = ((ah & 0xFF) << 8) | (al & 0xFF)
    elif field_path == ("h", "bh"):
        regs[("h", "bh")] = value & 0xFF
    elif field_path == ("h", "bl"):
        regs[("h", "bl")] = value & 0xFF
    elif field_path == ("h", "ch"):
        regs[("h", "ch")] = value & 0xFF
    elif field_path == ("h", "cl"):
        regs[("h", "cl")] = value & 0xFF
    elif field_path == ("h", "dh"):
        regs[("h", "dh")] = value & 0xFF
    elif field_path == ("h", "dl"):
        regs[("h", "dl")] = value & 0xFF

def _interrupt_wrapper_helper_call_expr(
    sig: InterruptWrapperCall,
    input_state: dict[str, dict[tuple[str, ...], int]],
    api_style: str,
    codegen,
):
    vector = _c_constant_value(_unwrap_c_casts(sig.vector_arg)) if sig.vector_arg is not None else None
    if vector is None and sig.kind in {"intdos", "intdosx"}:
        vector = 0x21
    if vector is None:
        return None

    service_call = InterruptCall(insn_addr=0, vector=vector & 0xFF)
    if vector == 0x21:
        inregs = "inregs"
        ah = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "ah"))
        al = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "al"))
        ax = _interrupt_wrapper_register_state_value(input_state, inregs, ("x", "ax"))
        if ax is None and ah is not None and al is not None:
            ax = ((ah & 0xFF) << 8) | (al & 0xFF)
        if ax is not None and ah is None:
            ah = (ax >> 8) & 0xFF
        if ax is not None and al is None:
            al = ax & 0xFF

        if ah is None:
            return None

        service_call = InterruptCall(
            insn_addr=0,
            vector=0x21,
            ah=ah,
            al=al,
            ax=ax,
            bx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "bx")),
            cx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "cx")),
            dx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "dx")),
            ds=_interrupt_wrapper_register_state_value(input_state, inregs, ("ds",)),
            es=_interrupt_wrapper_register_state_value(input_state, inregs, ("es",)),
            ss=_interrupt_wrapper_register_state_value(input_state, inregs, ("ss",)),
            cs=_interrupt_wrapper_register_state_value(input_state, inregs, ("cs",)),
        )
    elif vector == 0x10:
        inregs = "inregs"
        ah = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "ah"))
        if ah is None:
            return None
        service_call = InterruptCall(
            insn_addr=0,
            vector=0x10,
            ah=ah,
            al=_interrupt_wrapper_register_state_value(input_state, inregs, ("h", "al")),
            ax=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "ax")),
            bx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "bx")),
            cx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "cx")),
            dx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "dx")),
            ds=_interrupt_wrapper_register_state_value(input_state, inregs, ("ds",)),
            es=_interrupt_wrapper_register_state_value(input_state, inregs, ("es",)),
            ss=_interrupt_wrapper_register_state_value(input_state, inregs, ("ss",)),
            cs=_interrupt_wrapper_register_state_value(input_state, inregs, ("cs",)),
        )

    helper_name = interrupt_service_name(service_call, api_style)
    if helper_name.startswith("int86") or helper_name.startswith("intdos"):
        return None

    helper_args: list[object] = []
    if sig.kind in {"int86", "int86x"} and vector == 0x10:
        selector = _interrupt_wrapper_register_state_value(input_state, "inregs", ("h", "ah"))
        if selector is not None:
            helper_args.append(structured_c.CConstant(selector, SimTypeShort(False), codegen=codegen))
    if sig.kind in {"int86", "int86x"} and vector == 0x16:
        selector = _interrupt_wrapper_register_state_value(input_state, "inregs", ("h", "ah"))
        if selector is not None:
            helper_args.append(structured_c.CConstant(selector, SimTypeShort(False), codegen=codegen))
    if helper_name.endswith("getvect"):
        helper_args.append(structured_c.CConstant(0x21, SimTypeShort(False), codegen=codegen))

    return structured_c.CFunctionCall(helper_name, None, helper_args, codegen=codegen)

def _interrupt_wrapper_result_helper_expr(helper_expr, codegen):
    helper_name = getattr(helper_expr, "callee_target", None)
    if not isinstance(helper_name, str):
        helper_func = getattr(helper_expr, "callee_func", None)
        helper_name = getattr(helper_func, "name", None)
    if not isinstance(helper_name, str) or not helper_name:
        return None

    helper_args = list(getattr(helper_expr, "args", ()) or ())
    return structured_c.CFunctionCall(helper_name, None, helper_args, codegen=codegen)

def _interrupt_wrapper_result_extract_expr(access: InterruptWrapperFieldAccess, helper_expr, codegen):
    helper_call = _interrupt_wrapper_result_helper_expr(helper_expr, codegen)
    if helper_call is None:
        return None

    helper_name = getattr(helper_call, "callee_target", None)
    if not isinstance(helper_name, str):
        helper_func = getattr(helper_call, "callee_func", None)
        helper_name = getattr(helper_func, "name", None)

    if access.base_name == "outregs" and access.field_path == ("x", "ax"):
        return helper_call

    if access.base_name == "outregs" and access.field_path in {("x", "bx"), ("x", "cx"), ("x", "dx")}:
        if "getvect" in str(helper_name) and access.field_path == ("x", "bx"):
            return structured_c.CFunctionCall(
                "FP_OFF",
                None,
                [helper_call],
                codegen=codegen,
            )
        return helper_call

    if access.base_name == "outregs" and access.field_path == ("h", "ah"):
        return structured_c.CBinaryOp(
            "And",
            structured_c.CBinaryOp(
                "Shr",
                helper_call,
                structured_c.CConstant(8, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0xFF, SimTypeShort(), codegen=codegen),
            codegen=codegen,
        )

    if access.base_name == "outregs" and access.field_path == ("h", "al"):
        return structured_c.CBinaryOp(
            "And",
            helper_call,
            structured_c.CConstant(0xFF, SimTypeShort(), codegen=codegen),
            codegen=codegen,
        )

    if "getvect" in str(helper_name):
        if access.base_name == "sregs" and access.field_path == ("es",):
            return structured_c.CFunctionCall(
                "FP_SEG",
                None,
                [helper_call],
                codegen=codegen,
            )

    if access.base_name == "sregs" and access.field_path == ("es",):
        return helper_call

    return None

def _interrupt_wrapper_result_replacement(
    access: InterruptWrapperFieldAccess,
    helper_expr,
    api_style: str,
    codegen,
):
    if helper_expr is None:
        return None
    return _interrupt_wrapper_result_extract_expr(access, helper_expr, codegen)

def _interrupt_wrapper_result_expr_replacement(expr, helper_expr, api_style: str, codegen):
    if helper_expr is None:
        return None

    replacement = None
    if isinstance(expr, structured_c.CVariable) and getattr(expr, "name", None) == "outregs":
        return _interrupt_wrapper_result_helper_expr(helper_expr, codegen)

    access = _interrupt_wrapper_field_path(expr)
    if access is not None:
        replacement = _interrupt_wrapper_result_replacement(access, helper_expr, api_style, codegen)
        if replacement is not None:
            return replacement

    helper_name = getattr(helper_expr, "callee_target", None)
    if not isinstance(helper_name, str):
        helper_func = getattr(helper_expr, "callee_func", None)
        helper_name = getattr(helper_func, "name", None)
    if not isinstance(helper_name, str) or not helper_name:
        return None

    if helper_name in {"get_dos_version", "_dos_get_version", "dos_get_version"}:
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Or", "Add"}:
            return None

        for high_expr, low_expr in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            high_expr = _unwrap_c_casts(high_expr)
            low_expr = _unwrap_c_casts(low_expr)
            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Shl", "Mul"}:
                continue

            scale = _c_constant_value(_unwrap_c_casts(high_expr.rhs))
            if scale != 8:
                continue

            high_access = _interrupt_wrapper_field_path(high_expr.lhs)
            low_access = _interrupt_wrapper_field_path(low_expr)
            if (
                high_access is not None
                and low_access is not None
                and high_access.base_name == low_access.base_name == "outregs"
                and high_access.field_path == ("h", "ah")
                and low_access.field_path == ("h", "al")
            ):
                return structured_c.CFunctionCall(
                    helper_name,
                    getattr(helper_expr, "callee_func", None),
                    list(getattr(helper_expr, "args", ()) or ()),
                    codegen=codegen,
                )

    return None

def _lower_interrupt_wrapper_result_reads(project: angr.Project, codegen, api_style: str) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node, state: dict[str, dict[tuple[str, ...], int]], active_helper) -> None:
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            local_state = {base_name: dict(values) for base_name, values in state.items()}
            current_helper = active_helper
            new_statements = []

            for stmt in node.statements:
                if isinstance(stmt, structured_c.CAssignment):
                    lhs_access = _interrupt_wrapper_field_path(stmt.lhs)
                    if lhs_access is not None and lhs_access.base_name in {"inregs", "outregs", "sregs"}:
                        const_value = _c_constant_value(_unwrap_c_casts(stmt.rhs))
                        _interrupt_wrapper_record_register_write(
                            local_state,
                            lhs_access.base_name,
                            lhs_access.field_path,
                            const_value,
                        )

                    if current_helper is not None:
                        replacement = _interrupt_wrapper_result_expr_replacement(
                            stmt.rhs,
                            current_helper,
                            api_style,
                            codegen,
                        )
                        if replacement is not None and not _same_c_expression(stmt.rhs, replacement):
                            stmt = structured_c.CAssignment(stmt.lhs, replacement, codegen=codegen)
                            changed = True

                elif isinstance(stmt, structured_c.CFunctionCall):
                    sig = _interrupt_wrapper_call_signature(stmt)
                    if sig is not None:
                        helper = _interrupt_wrapper_helper_call_expr(sig, local_state, api_style, codegen)
                        if helper is not None:
                            current_helper = helper
                            if not _same_c_expression(stmt, helper):
                                stmt = helper
                                changed = True
                        else:
                            # Preserve the wrapper call itself as the result source when
                            # service-specific lowering is not possible yet.
                            current_helper = stmt

                elif isinstance(stmt, structured_c.CExpressionStatement):
                    expr = getattr(stmt, "expr", None)
                    if isinstance(expr, structured_c.CFunctionCall):
                        sig = _interrupt_wrapper_call_signature(expr)
                        if sig is not None:
                            helper = _interrupt_wrapper_helper_call_expr(sig, local_state, api_style, codegen)
                            if helper is not None:
                                current_helper = helper
                                if not _same_c_expression(expr, helper):
                                    stmt = structured_c.CExpressionStatement(helper, codegen=codegen)
                                    changed = True
                            else:
                                current_helper = expr

                visit(stmt, local_state, current_helper)
                new_statements.append(stmt)

            if new_statements != list(node.statements):
                node.statements = new_statements
            return

        if isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body, {base_name: dict(values) for base_name, values in state.items()}, active_helper)
            if node.else_node is not None:
                visit(node.else_node, {base_name: dict(values) for base_name, values in state.items()}, active_helper)

    visit(codegen.cfunc.statements, {}, None)
    return changed

def _attach_dos_pseudo_callees(project: angr.Project, function, codegen, api_style: str) -> bool:
    if api_style != "pseudo" or getattr(codegen, "cfunc", None) is None:
        return False

    dos_calls = collect_dos_int21_calls(function)
    if not dos_calls:
        return False

    pseudo_funcs = []
    for call in dos_calls:
        target = function.get_call_target(call.insn_addr)
        if target is None:
            continue
        pseudo_funcs.append(project.kb.functions.function(addr=target))

    if not pseudo_funcs:
        return False

    call_nodes = [
        node
        for node in _iter_c_nodes(codegen.cfunc.statements)
        if isinstance(node, structured_c.CFunctionCall) and node.callee_func is None
    ]

    for node, pseudo_func in zip(call_nodes, pseudo_funcs):
        if pseudo_func is not None:
            node.callee_func = pseudo_func
    return bool(call_nodes)
