from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
import time
from collections import Counter
from copy import copy
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .analysis_helpers import patch_direct_call_sites, preferred_known_helper_signature_decl
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_stack_metadata import (
    _generic_stack_carrier_keys_8616,
    _stack_carrier_key_8616,
    prune_materialized_callsite_segment_metadata_8616,
)
from .callsite_summary import summarize_x86_16_callsite
from .cod_extract import extract_cod_proc_metadata
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_dereference_8616,
    _match_bp_stack_load_8616,
    _match_real_mode_linear_expr_8616,
    _match_real_mode_segmented_store_shape_8616,
    _match_segmented_dereference_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
)
from .lowering.real_mode_linear import _stack_offset_from_expr_8616
from .lowering.stack_lowering_from_facts import (
    _materialize_stack_cvar_at_offset as _materialize_stack_cvar_at_offset_from_facts_8616,
)
from .lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from .pipeline.errors import PipelineHardError
from .stack_probe_fact_trace import (
    ensure_stack_probe_fact_stats_8616,
    record_callsite_summary_fact_8616,
    record_callsite_summary_map_facts_8616,
    record_stack_arg_materialization_8616,
)

__all__ = [
    "_attach_callsite_summaries_8616",
    "_recover_missing_direct_calls_from_evidence_8616",
    "_materialize_stdlib_call_chains_8616",
    "_materialize_callsite_stack_arguments_8616",
    "_materialize_callsite_prototypes_8616",
    "_normalize_call_target_names_8616",
]

_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
_NAMESPACED_TARGET_RE = re.compile(r"^::0x(?P<addr>[0-9a-fA-F]+)::")
log = logging.getLogger(__name__)
_RUNTIME_SEGMENT_HELPERS_8616 = frozenset({"SEG_U8", "SEG_U16", "SEG_U32", "MK_FP", "SEG_PTR"})
_CALL_TOKEN_RE_8616 = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _source_call_floor_enabled_8616() -> bool:
    return os.environ.get("INERTIA_ENABLE_SOURCE_CALL_FLOOR_RECOVERY", "").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _single_function_context_measuring_enabled_8616() -> bool:
    return (
        os.environ.get("INERTIA_MEASURE_SINGLE_FUNCTION_CONTEXT", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )


def _structured_root_8616(cfunc):
    return getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc


def _materialize_stdlib_call_chains_8616(project, codegen) -> bool:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        root = _structured_root_8616(cfunc)
        statements = getattr(root, "statements", None)
        if not isinstance(statements, list):
            return False

        def _call_name(stmt) -> str | None:
            expr = getattr(stmt, "expr", None)
            if not isinstance(expr, CFunctionCall):
                return None
            name = normalize_callee_name_8616(_call_node_name_8616(expr))
            return name if isinstance(name, str) and name else None

        def _is_zero_constant(expr) -> bool:
            value = getattr(expr, "value", None)
            if isinstance(value, int):
                return value == 0
            return type(expr).__name__ == "CConstant" and getattr(expr, "value", None) == 0

        def _is_zero_arg_call(stmt, target_name: str) -> bool:
            expr = getattr(stmt, "expr", None)
            if not isinstance(expr, CFunctionCall):
                return False
            name = _call_name(stmt)
            if name != target_name:
                return False
            args = tuple(getattr(expr, "args", ()) or ())
            return len(args) == 1 and _is_zero_constant(args[0])

        changed = False
        idx = 0
        while idx + 1 < len(statements):
            first = statements[idx]
            second = statements[idx + 1]
            # Recover common C stdlib seeding chain when argument materialization
            # lost producer-consumer linkage between time() and srand().
            if _is_zero_arg_call(first, "srand") and _is_zero_arg_call(second, "time"):
                srand_call = getattr(first, "expr", None)
                time_call = getattr(second, "expr", None)
                if isinstance(srand_call, CFunctionCall) and isinstance(time_call, CFunctionCall):
                    srand_call.args = [time_call]
                    del statements[idx + 1]
                    changed = True
                    continue
            if _is_zero_arg_call(first, "time") and _is_zero_arg_call(second, "srand"):
                srand_call = getattr(second, "expr", None)
                time_call = getattr(first, "expr", None)
                if isinstance(srand_call, CFunctionCall) and isinstance(time_call, CFunctionCall):
                    srand_call.args = [time_call]
                    del statements[idx]
                    changed = True
                    continue
            idx += 1
        return changed

    return _impl()


def _sync_cfunc_root_statements_8616(cfunc, root, root_statements) -> None:
    def _impl():
        cfunc_statements = getattr(cfunc, "statements", None)
        cfunc_body = getattr(cfunc, "body", None)
        body_statements = getattr(cfunc_body, "statements", None)
        if root is not cfunc and isinstance(root_statements, (list, tuple)):
            if hasattr(root, "statements"):
                with contextlib.suppress(Exception):
                    cfunc.body = root
            if isinstance(cfunc_statements, (list, tuple)) and cfunc_statements is not root_statements:
                cfunc.statements = list(root_statements) if isinstance(cfunc_statements, list) else tuple(root_statements)
            if cfunc_body is not None and isinstance(body_statements, (list, tuple)) and body_statements is not root_statements:
                cfunc_body.statements = list(root_statements) if isinstance(body_statements, list) else tuple(root_statements)

    return _impl()


def _missing_calls_from_sequences_8616(
    source_call_names: list[str], expected_names: list[str], present_names: list[str]
) -> tuple[list[str], list[str]]:
    def _impl():
        source_sequence = [
            (normalize_callee_name_8616(name) or name)
            for name in source_call_names
            if isinstance(name, str) and name and name != "aNchkstk"
        ]
        actual_sequence = [
            (normalize_callee_name_8616(name) or name)
            for name in present_names
            if isinstance(name, str) and name and name != "aNchkstk"
        ]
        missing: list[str] = []
        if source_sequence:
            j = 0
            for expected_name in source_sequence:
                while j < len(actual_sequence) and actual_sequence[j] != expected_name:
                    j += 1
                if j < len(actual_sequence) and actual_sequence[j] == expected_name:
                    j += 1
                else:
                    missing.append(expected_name)
        else:
            expected_counts = Counter(
                (normalize_callee_name_8616(name) or name) for name in expected_names if name != "aNchkstk"
            )
            present_counts = Counter(actual_sequence)
            for name, needed in expected_counts.items():
                have = int(present_counts.get(name, 0))
                if have < needed:
                    missing.extend([name] * (needed - have))
        return source_sequence, missing

    return _impl()


def _structured_present_call_names_8616(project, codegen, root, source_call_names: list[str]) -> list[str]:
    def _impl():
        summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
        if isinstance(summary_map, dict):
            _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
        else:
            summary_map = {}

        source_sequence = [
            normalize_callee_name_8616(name) or name
            for name in source_call_names
            if isinstance(name, str) and name and name != "aNchkstk"
        ]
        source_idx = 0
        present_names: list[str] = []
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
                continue
            normalized = normalize_callee_name_8616(_call_node_name_8616(node) or "") or _call_node_name_8616(node)
            summary = summary_map.get(id(node))
            target_addr = getattr(summary, "target_addr", None) if summary is not None else None
            if isinstance(target_addr, int):
                for source_name in source_sequence:
                    if _source_name_matches_target_8616(project, target_addr, source_name):
                        if not isinstance(normalized, str) or _call_name_is_unknown_8616(normalized):
                            normalized = source_name
                        break
            if (
                isinstance(normalized, str)
                and source_idx < len(source_sequence)
                and normalized == source_sequence[source_idx]
            ):
                source_idx += 1
            elif (
                isinstance(normalized, str)
                and _call_name_is_unknown_8616(normalized)
                and summary is not None
                and source_idx < len(source_sequence)
            ):
                expected_arg_count = _expected_arg_count_for_known_callee_8616(source_sequence[source_idx])
                summary_arg_count = int(getattr(summary, "arg_count", 0) or 0)
                current_arg_count = len(tuple(getattr(node, "args", ()) or ()))
                if (
                    isinstance(expected_arg_count, int)
                    and expected_arg_count >= 0
                    and (summary_arg_count == expected_arg_count or current_arg_count == expected_arg_count)
                ):
                    normalized = source_sequence[source_idx]
                    source_idx += 1
            if isinstance(normalized, str) and normalized and normalized != "aNchkstk":
                present_names.append(normalized)
        return present_names

    return _impl()


def _ordered_missing_from_source_8616(source_sequence: list[str], missing: list[str]) -> list[str]:
    missing_counts = Counter(missing)
    if not source_sequence:
        return list(missing)
    ordered_missing: list[str] = []
    for name in source_sequence:
        if missing_counts.get(name, 0) > 0:
            ordered_missing.append(name)
            missing_counts[name] -= 1
    return ordered_missing


def _debug_loop_relocate_precheck_8616(
    *, debug_enabled: bool, context_tag: str, func_addr: int, ordered_missing: list[str], current_statements
) -> None:
    if not debug_enabled:
        return
    stmt_kinds = []
    for stmt in list(current_statements)[:12]:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        stmt_kinds.append(
            (
                type(stmt).__name__,
                bool(hasattr(stmt, "condition") or hasattr(stmt, "cond")),
                type(body).__name__ if body is not None else None,
                len(body_statements) if isinstance(body_statements, (list, tuple)) else None,
            )
        )
    loop_body_details = []
    for stmt in list(current_statements)[:12]:
        if not isinstance(stmt, structured_c.CForLoop):
            continue
        body = getattr(stmt, "body", None)
        body_statements = list(getattr(body, "statements", ()) or ())
        for bstmt in body_statements[:6]:
            expr = getattr(bstmt, "expr", None)
            loop_body_details.append((type(bstmt).__name__, type(expr).__name__, repr(expr)[:120]))
    log.warning(
        "[call-recover] context=%s loop-relocate precheck addr=%#x source_sequence=%r top=%r loop_body=%r",
        context_tag,
        func_addr,
        ordered_missing,
        stmt_kinds,
        loop_body_details,
    )


def _match_expected_call_stmt_indexes_8616(mutable_statements, ordered_missing: list[str]) -> tuple[int | None, list[str], list[int]]:
    def _impl():
        first_return_idx = None
        for idx, stmt in enumerate(mutable_statements):
            if isinstance(stmt, structured_c.CReturn):
                first_return_idx = idx
                break
        scan_slice = (
            list(enumerate(mutable_statements[first_return_idx + 1 :], start=first_return_idx + 1))
            if first_return_idx is not None
            else list(enumerate(mutable_statements))
        )
        call_stmt_indexes: list[int] = []
        call_stmt_names: list[str] = []
        for idx, stmt in scan_slice:
            expr = getattr(stmt, "expr", None)
            if not isinstance(expr, CFunctionCall):
                continue
            normalized = normalize_callee_name_8616(_call_node_name_8616(expr)) or _call_node_name_8616(expr)
            if not isinstance(normalized, str) or not normalized:
                continue
            call_stmt_indexes.append(idx)
            call_stmt_names.append(normalized)
        expected = [name for name in ordered_missing if isinstance(name, str) and name]
        matched_call_stmt_indexes: list[int] = []
        if expected:
            exp_i = 0
            for rel_i, call_name in enumerate(call_stmt_names):
                if exp_i >= len(expected):
                    break
                if call_name == expected[exp_i]:
                    matched_call_stmt_indexes.append(call_stmt_indexes[rel_i])
                    exp_i += 1
        return first_return_idx, call_stmt_names, matched_call_stmt_indexes

    return _impl()


def _relocate_recovered_calls_into_loops_8616(
    *,
    debug_enabled: bool,
    context_tag: str,
    func_addr: int,
    ordered_missing: list[str],
    root,
    root_statements,
    cfunc,
) -> bool:
    def _impl():
        current_statements = getattr(root, "statements", None)
        if not isinstance(current_statements, (list, tuple)):
            current_statements = root_statements
        empty_loop_bodies = _empty_loop_bodies_8616(current_statements)
        _debug_loop_relocate_precheck_8616(
            debug_enabled=debug_enabled,
            context_tag=context_tag,
            func_addr=func_addr,
            ordered_missing=ordered_missing,
            current_statements=current_statements,
        )
        if not empty_loop_bodies:
            return False
        mutable_statements = list(current_statements)
        first_return_idx, call_stmt_names, matched_call_stmt_indexes = _match_expected_call_stmt_indexes_8616(
            mutable_statements, ordered_missing
        )
        expected = [name for name in ordered_missing if isinstance(name, str) and name]
        if debug_enabled:
            log.warning(
                "[call-recover] context=%s loop-relocate candidates addr=%#x first_return_idx=%r calls=%r expected=%r matched=%r",
                context_tag,
                func_addr,
                first_return_idx,
                call_stmt_names,
                expected,
                matched_call_stmt_indexes,
            )
        if not expected or len(matched_call_stmt_indexes) != len(expected):
            return False
        target_bodies = list(empty_loop_bodies)
        move_count = min(len(expected), len(matched_call_stmt_indexes))
        for rel_idx in range(move_count):
            stmt_idx = matched_call_stmt_indexes[rel_idx]
            body_idx = min(rel_idx, len(target_bodies) - 1)
            body = target_bodies[body_idx]
            body_statements = list(getattr(body, "statements", ()) or ())
            body_statements.append(mutable_statements[stmt_idx])
            body.statements = body_statements
        remove_indexes = set(matched_call_stmt_indexes[:move_count])
        mutable_statements = [stmt for idx, stmt in enumerate(mutable_statements) if idx not in remove_indexes]
        if first_return_idx is not None and first_return_idx < len(mutable_statements):
            if isinstance(mutable_statements[first_return_idx], structured_c.CReturn):
                del mutable_statements[first_return_idx]
        if debug_enabled:
            log.warning(
                "[call-recover] context=%s loop-relocate applied addr=%#x moved=%d",
                context_tag,
                func_addr,
                move_count,
            )
        updated_statements = mutable_statements if isinstance(root_statements, list) else tuple(mutable_statements)
        root.statements = updated_statements
        _sync_cfunc_root_statements_8616(cfunc, root, updated_statements)
        return True

    return _impl()


def _recover_missing_direct_calls_from_evidence_8616(project, codegen) -> bool:
    def _impl():
        debug_enabled = bool(os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"))
        context_tag = getattr(codegen, "_inertia_call_recover_context", "postprocess")
        prepared = _prepare_call_recovery_context_8616(project, codegen, debug_enabled=debug_enabled, context_tag=context_tag)
        if prepared is None:
            return False
        cfunc, root, root_statements, func_addr, function = prepared

        expected_names, expected_summary_by_name, source_call_names = _recover_expected_calls_8616(
            project, cfunc, function, func_addr
        )

        if not expected_names:
            if debug_enabled:
                log.warning(
                    "[call-recover] context=%s skip=no-expected-names addr=%#x codegen_id=%#x",
                    context_tag,
                    func_addr,
                    id(codegen),
                )
            return False

        # Presence checks consume structured callsite evidence first. Rendered C is
        # a fallback only, because unknown return calls may be target-proven by the
        # call summary even when their emitted name is still a placeholder.
        present_names = _structured_present_call_names_8616(project, codegen, root, source_call_names)
        if not present_names:
            present_names, rendered_ok = _rendered_call_names_8616(codegen, cfunc)
        else:
            rendered_ok = True
        if not rendered_ok:
            for node in _iter_c_nodes_deep_8616(root):
                if not isinstance(node, CFunctionCall):
                    continue
                for raw in (
                    getattr(node, "callee_target", None),
                    getattr(getattr(node, "callee_func", None), "name", None),
                    getattr(node, "callee", None),
                ):
                    if isinstance(raw, str) and raw:
                        present_names.append(raw)
                        break

        source_sequence, missing = _missing_calls_from_sequences_8616(source_call_names, expected_names, present_names)
        if not missing:
            _sync_cfunc_root_statements_8616(cfunc, root, root_statements)
            if debug_enabled:
                log.warning(
                    "[call-recover] context=%s skip=no-missing addr=%#x codegen_id=%#x", context_tag, func_addr, id(codegen)
                )
            return False

        summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
        mutable_statements = list(root_statements)
        changed = False
        first_empty_loop_body = _first_empty_loop_body_8616(mutable_statements)
        # Preserve source call ordering when recovering missing calls.
        # Build a replay queue by scanning source order and selecting only calls that
        # still need insertion according to `missing` multiset.
        ordered_missing = _ordered_missing_from_source_8616(source_sequence, missing)

        def _summary_looks_loop_carried_arg_8616(summary_obj) -> bool:
            if summary_obj is None:
                return False
            raw_sources = tuple(getattr(summary_obj, "arg_sources", ()) or ())
            for src in raw_sources:
                if not isinstance(src, tuple) or len(src) != 2:
                    continue
                base, disp = src
                if base == "bp" and isinstance(disp, int):
                    return True
            return False

        changed, mutable_statements = _insert_missing_calls_8616(
            project=project,
            codegen=codegen,
            mutable_statements=mutable_statements,
            ordered_missing=ordered_missing,
            source_sequence=source_sequence,
            expected_summary_by_name=expected_summary_by_name,
            summary_map=summary_map,
            first_empty_loop_body=first_empty_loop_body,
        )
        if changed:
            updated_statements = mutable_statements if isinstance(root_statements, list) else tuple(mutable_statements)
            root.statements = updated_statements
            _sync_cfunc_root_statements_8616(cfunc, root, updated_statements)
            if debug_enabled:
                cfunc_calls = []
                cfunc_root_now = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
                for node in _iter_c_nodes_deep_8616(cfunc_root_now):
                    if isinstance(node, CFunctionCall):
                        cfunc_calls.append(_call_node_name_8616(node))
                log.warning(
                    "[call-recover] context=%s function=%#x codegen_id=%#x recovered=%r root=%s root_id=%#x cfunc_root=%s cfunc_root_id=%#x calls=%r",
                    context_tag,
                    getattr(cfunc, "addr", 0) or 0,
                    id(codegen),
                    ordered_missing,
                    type(root).__name__,
                    id(root),
                    type(cfunc_root_now).__name__,
                    id(cfunc_root_now),
                    cfunc_calls,
                )
            codegen._inertia_callsite_summaries = summary_map
            setattr(
                codegen,
                "_inertia_direct_call_floor_recovered_count",
                int(getattr(codegen, "_inertia_direct_call_floor_recovered_count", 0)) + len(missing),
            )
        if source_sequence and _relocate_recovered_calls_into_loops_8616(
            debug_enabled=debug_enabled,
            context_tag=context_tag,
            func_addr=func_addr,
            ordered_missing=ordered_missing,
            root=root,
            root_statements=root_statements,
            cfunc=cfunc,
        ):
            changed = True
        return changed

    return _impl()


def _prepare_call_recovery_context_8616(project, codegen, *, debug_enabled: bool, context_tag: str):
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            if debug_enabled:
                log.warning("[call-recover] context=%s skip=no-cfunc codegen_id=%#x", context_tag, id(codegen))
            return None
        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
        root_statements = getattr(root, "statements", None)
        if not isinstance(root_statements, (list, tuple)):
            if debug_enabled:
                log.warning(
                    "[call-recover] context=%s skip=bad-root-statements codegen_id=%#x root=%s root_statements=%s",
                    context_tag,
                    id(codegen),
                    type(root).__name__,
                    type(root_statements).__name__ if root_statements is not None else "None",
                )
            return None
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            if debug_enabled:
                log.warning("[call-recover] context=%s skip=bad-func-addr codegen_id=%#x", context_tag, id(codegen))
            return None
        function = project.kb.functions.function(addr=func_addr, create=False)
        if function is None:
            if debug_enabled:
                log.warning(
                    "[call-recover] context=%s skip=no-kb-function addr=%r codegen_id=%#x",
                    context_tag,
                    func_addr,
                    id(codegen),
                )
            return None
        return cfunc, root, root_statements, func_addr, function

    return _impl()


def _recover_expected_calls_8616(project, cfunc, function, func_addr: int):
    def _impl():
        expected_names: list[str] = []
        expected_summary_by_name: dict[str, list[object]] = {}
        callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
        for callsite_addr in callsite_addrs:
            target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
            if not isinstance(target, int):
                continue
            callee = _lookup_callee_function_8616(project, target)
            callee_name = getattr(callee, "name", None)
            if not isinstance(callee_name, str) or not callee_name or callee_name in _RUNTIME_SEGMENT_HELPERS_8616:
                continue
            normalized_name = normalize_callee_name_8616(callee_name) or callee_name
            expected_names.append(normalized_name)
            summary = summarize_x86_16_callsite(function, callsite_addr)
            if summary is not None:
                expected_summary_by_name.setdefault(normalized_name, []).append(summary)
        source_call_names: list[str] = []
        if _source_call_floor_enabled_8616():
            source_call_names = list(_cod_source_call_names_8616(project, func_addr))
            if not source_call_names:
                source_call_names = list(_cod_source_call_names_for_symbol_8616(project, getattr(cfunc, "name", None)))
            for source_name in source_call_names:
                if isinstance(source_name, str) and source_name:
                    expected_names.append(source_name)
        return expected_names, expected_summary_by_name, source_call_names

    return _impl()


def _insert_missing_calls_8616(
    *,
    project,
    codegen,
    mutable_statements: list[object],
    ordered_missing: list[str],
    source_sequence: list[str],
    expected_summary_by_name: dict[str, list[object]],
    summary_map: dict[int, object],
    first_empty_loop_body,
) -> tuple[bool, list[object]]:
    def _impl():
        insert_at = len(mutable_statements)
        for idx, stmt in enumerate(mutable_statements):
            if isinstance(stmt, structured_c.CReturn):
                insert_at = idx
                break

        def _summary_looks_loop_carried_arg_8616(summary_obj) -> bool:
            if summary_obj is None:
                return False
            raw_sources = tuple(getattr(summary_obj, "arg_sources", ()) or ())
            for src in raw_sources:
                if not isinstance(src, tuple) or len(src) != 2:
                    continue
                base, disp = src
                if base == "bp" and isinstance(disp, int):
                    return True
            return False

        changed = False
        for idx, name in enumerate(ordered_missing):
            callee_func = project.kb.functions.function(name=name, create=False)
            seeded_args = _known_default_args_for_missing_8616(name, codegen)
            call_args = list(seeded_args) if isinstance(seeded_args, tuple) else []
            call = CFunctionCall(name, callee_func, call_args, codegen=codegen)
            call_stmt = structured_c.CExpressionStatement(call, codegen=codegen)
            inserted_in_loop = False
            summary_candidates = expected_summary_by_name.get(normalize_callee_name_8616(name) or name, [])
            preferred_summary = summary_candidates[0] if summary_candidates else None
            loop_carried_missing = _summary_looks_loop_carried_arg_8616(preferred_summary)
            if ((idx == 0 and source_sequence and source_sequence[0] == name) or loop_carried_missing) and first_empty_loop_body is not None:
                loop_body_statements = list(getattr(first_empty_loop_body, "statements", ()) or ())
                loop_body_statements.append(call_stmt)
                first_empty_loop_body.statements = loop_body_statements
                inserted_in_loop = True
            if not inserted_in_loop:
                mutable_statements.insert(insert_at, call_stmt)
            if summary_candidates:
                summary_map[id(call)] = summary_candidates.pop(0)
            if not inserted_in_loop:
                insert_at += 1
            changed = True
        return changed, mutable_statements

    return _impl()


def _first_empty_loop_body_8616(statements) -> object | None:
    for stmt in statements:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        if isinstance(body_statements, (list, tuple)) and len(body_statements) == 0:
            # Loop-like nodes expose condition fields in structured_codegen nodes.
            if hasattr(stmt, "condition") or hasattr(stmt, "cond"):
                return body
    return None


def _empty_loop_bodies_8616(statements) -> list[object]:
    def _stmt_is_placeholder_8616(stmt) -> bool:
        if stmt is None:
            return True
        nested = getattr(stmt, "statements", None)
        if isinstance(nested, (list, tuple)):
            return all(_stmt_is_placeholder_8616(child) for child in nested)
        expr = getattr(stmt, "expr", None)
        if expr is None:
            return True
        if isinstance(expr, CFunctionCall):
            return False
        if isinstance(expr, CBinaryOp):
            # Keep conservative: loop bodies with binary expression side-effects
            # are not safe anchors.
            return False
        if isinstance(expr, structured_c.CAssignment):
            lhs = getattr(expr, "lhs", None)
            rhs = getattr(expr, "rhs", None)
            return _same_c_expression_8616(lhs, rhs)
        # Unknown loop statement kind: refuse anchoring.
        return False

    bodies: list[object] = []
    for stmt in statements:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        if not isinstance(body_statements, (list, tuple)):
            continue
        if not (hasattr(stmt, "condition") or hasattr(stmt, "cond")):
            continue
        if len(body_statements) == 0:
            bodies.append(body)
            continue
        if all(_stmt_is_placeholder_8616(body_stmt) for body_stmt in body_statements):
            bodies.append(body)
    return bodies


def _rendered_call_names_8616(codegen, cfunc) -> tuple[list[str], bool]:
    def _impl():
        try:
            rendered = codegen.render_text(cfunc)
        except Exception:
            return ([], False)
        if isinstance(rendered, tuple):
            rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
        if not isinstance(rendered, str) or not rendered:
            return ([], False)
        # Presence checks must only inspect executable body text.
        # Embedded original-source evidence comments (/// ...) include call names
        # that can otherwise mask genuinely missing recovered calls.
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered, flags=re.S)
        text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
        text_wo_comments = "\n".join(line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///"))
        body = text_wo_comments.split("{", 1)[-1] if "{" in text_wo_comments else text_wo_comments
        names: list[str] = []
        for name in _CALL_TOKEN_RE_8616.findall(body):
            if name in {"if", "for", "while", "switch", "return", "sizeof"}:
                continue
            names.append(name)
        return (names, True)

    return _impl()


@dataclass(slots=True)
class CallsiteMaterializationStats:
    callsite_count: int = 0
    call_target_fact_count: int = 0
    call_target_materialized_count: int = 0
    call_arg_fact_count: int = 0
    call_arg_materialized_count: int = 0
    bp_slot_arg_value_normalized_count: int = 0
    pointer_arg_materialized_count: int = 0
    push_order_reversed_count: int = 0
    consumed_outgoing_stack_placeholder_count: int = 0
    stale_target_rejected_count: int = 0
    known_prototype_arg_mismatch_count: int = 0
    has_push_arg_evidence_count: int = 0
    no_push_arg_evidence_count: int = 0
    source_proven_stack_probe_count: int = 0
    failure_count: int = 0
    known_prototype_arg_mismatches: list[dict[str, object]] = field(default_factory=list)


class CallArgSemanticKind8616(Enum):
    UNKNOWN = "unknown"
    POINTER = "pointer"
    VALUE = "value"


_KNOWN_HELPER_ARG_KIND_CACHE_8616: dict[str, dict[int, CallArgSemanticKind8616]] = {}


def _ensure_callsite_materialization_stats_8616(codegen) -> CallsiteMaterializationStats:
    stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    field_names = tuple(getattr(CallsiteMaterializationStats, "__dataclass_fields__", {}) or ())
    if not isinstance(stats, CallsiteMaterializationStats) or any(not hasattr(stats, name) for name in field_names):
        previous = stats
        stats = CallsiteMaterializationStats()
        for name in field_names:
            if name == "known_prototype_arg_mismatches":
                value = getattr(previous, name, None)
                if isinstance(value, list):
                    stats.known_prototype_arg_mismatches = list(value)
                continue
            try:
                setattr(stats, name, int(getattr(previous, name, getattr(stats, name, 0)) or 0))
            except Exception:
                continue
        codegen._inertia_callsite_materialization_stats = stats
    return stats


def _sync_callsite_materialization_stats_8616(codegen) -> CallsiteMaterializationStats:
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    raw = ensure_stack_probe_fact_stats_8616(codegen)
    for key in (
        "callsite_count",
        "call_target_fact_count",
        "call_target_materialized_count",
        "call_arg_fact_count",
        "call_arg_materialized_count",
        "bp_slot_arg_value_normalized_count",
        "pointer_arg_materialized_count",
        "push_order_reversed_count",
        "consumed_outgoing_stack_placeholder_count",
        "stale_target_rejected_count",
        "known_prototype_arg_mismatch_count",
        "has_push_arg_evidence_count",
        "no_push_arg_evidence_count",
        "source_proven_stack_probe_count",
        "failure_count",
    ):
        raw[key] = int(getattr(stats, key, 0) or 0)
    return stats


def _is_stack_probe_call_name_8616(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    lowered = normalized.lower()
    return lowered in {
        "anchkstk",
        "chkstk",
        "_chkstk",
        "__chkstk",
        "__aNchkstk".lower(),
    }


def _lookup_callee_function_8616(project, target_addr: int, *, allow_containing: bool = False):
    def _iter_functions(candidate_project):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        if functions is None:
            return ()
        values = getattr(functions, "values", None)
        if callable(values):
            try:
                return tuple(values())
            except Exception:
                return ()
        return ()

    def _lookup_unique_near_target(candidate_project, candidate_addr: int):
        if not (isinstance(candidate_addr, int) and 0 <= candidate_addr <= 0xFFFF):
            return None
        matches = []
        for function in _iter_functions(candidate_project):
            func_addr = getattr(function, "addr", None)
            if isinstance(func_addr, int) and (func_addr & 0xFFFF) == candidate_addr:
                matches.append(function)
        if len(matches) == 1:
            return matches[0]
        return None

    def _lookup_exact_or_containing(candidate_project, candidate_addr: int):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", lambda **_: None)
        function = lookup(addr=candidate_addr, create=False)
        floor_func = getattr(functions, "floor_func", None)
        ceiling_addr = getattr(functions, "ceiling_addr", None)

        def _contains_addr(containing, *, allow_range: bool) -> bool:
            if containing is None:
                return False
            start_addr = getattr(containing, "addr", None)
            if not isinstance(start_addr, int):
                return allow_range is False
            if not isinstance(start_addr, int) or start_addr > candidate_addr:
                return False
            block_addrs = tuple(getattr(containing, "block_addrs_set", ()) or ())
            if candidate_addr in block_addrs:
                return True
            if start_addr == candidate_addr:
                return True
            if allow_range and callable(ceiling_addr):
                try:
                    next_addr = ceiling_addr(start_addr + 1)
                except Exception as ex:
                    log.debug(
                        "ceiling_addr lookup failed target=%#x candidate_start=%#x: %s",
                        candidate_addr,
                        start_addr,
                        ex,
                    )
                    next_addr = None
                if isinstance(next_addr, int):
                    return start_addr <= candidate_addr < next_addr
            return False

        if _contains_addr(function, allow_range=False):
            return function
        if not allow_containing or not callable(floor_func):
            return None
        try:
            containing = floor_func(candidate_addr)
        except Exception as ex:
            log.debug("floor_func lookup failed target=%#x: %s", candidate_addr, ex)
            containing = None
        if containing is None or not _contains_addr(containing, allow_range=True):
            return None
        return containing

    candidate_addrs = [target_addr]
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        candidate_addrs.append(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    ordered_addrs: list[int] = []
    for addr in candidate_addrs:
        if addr not in ordered_addrs:
            ordered_addrs.append(addr)

    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        for candidate_addr in ordered_addrs:
            function = _lookup_exact_or_containing(candidate_project, candidate_addr)
            if function is not None:
                return function
            function = _lookup_unique_near_target(candidate_project, candidate_addr)
            if function is not None:
                return function
    return None


def _candidate_linear_target_addrs_8616(project, target_addr: int) -> tuple[int, ...]:
    candidate_addrs = [target_addr]
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        candidate_addrs.append(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    ordered: list[int] = []
    for addr in candidate_addrs:
        if isinstance(addr, int) and addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _sidecar_label_for_target_8616(project, target_addr: int) -> str | None:
    def _impl():
        candidates: list[str] = []
        lookup_addrs = {target_addr}
        original_project = getattr(project, "_inertia_original_project", None)
        original_delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(original_delta, int):
            lookup_addrs.add(target_addr + original_delta)
            rebased = target_addr - original_delta
            if rebased >= 0:
                lookup_addrs.add(rebased)

        for lookup_addr in sorted(lookup_addrs):
            for labels in (
                getattr(getattr(project, "_inertia_lst_metadata", None), "code_labels", None),
                getattr(getattr(project, "kb", None), "labels", None),
            ):
                if labels is None:
                    continue
                label = getattr(labels, "get", lambda _addr: None)(lookup_addr)
                if isinstance(label, str) and label:
                    candidates.append(label)
                if isinstance(target_addr, int) and 0 <= target_addr <= 0xFFFF:
                    items = getattr(labels, "items", None)
                    if callable(items):
                        near_matches = []
                        try:
                            iterable = tuple(items())
                        except Exception:
                            iterable = ()
                        for label_addr, label_name in iterable:
                            if (
                                isinstance(label_addr, int)
                                and (label_addr & 0xFFFF) == target_addr
                                and isinstance(label_name, str)
                                and label_name
                            ):
                                near_matches.append(label_name)
                        if len(near_matches) == 1:
                            candidates.append(near_matches[0])

        if original_project is not None and isinstance(original_delta, int):
            for lookup_addr in sorted(lookup_addrs):
                for labels in (
                    getattr(getattr(original_project, "_inertia_lst_metadata", None), "code_labels", None),
                    getattr(getattr(original_project, "kb", None), "labels", None),
                ):
                    if labels is None:
                        continue
                    label = getattr(labels, "get", lambda _addr: None)(lookup_addr)
                    if isinstance(label, str) and label:
                        candidates.append(label)
                    if isinstance(target_addr, int) and 0 <= target_addr <= 0xFFFF:
                        items = getattr(labels, "items", None)
                        if callable(items):
                            near_matches = []
                            try:
                                iterable = tuple(items())
                            except Exception:
                                iterable = ()
                            for label_addr, label_name in iterable:
                                if (
                                    isinstance(label_addr, int)
                                    and (label_addr & 0xFFFF) == target_addr
                                    and isinstance(label_name, str)
                                    and label_name
                                ):
                                    near_matches.append(label_name)
                            if len(near_matches) == 1:
                                candidates.append(near_matches[0])

        for label in candidates:
            normalized = normalize_callee_name_8616(label.lstrip("_"))
            if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
                return normalized
        return None

    return _impl()


def _function_matches_target_addr_8616(function, target_addr: int | None) -> bool:
    if function is None or not isinstance(target_addr, int):
        return False
    start_addr = getattr(function, "addr", None)
    if not isinstance(start_addr, int):
        return False
    if _target_addr_matches_near_or_linear_8616(start_addr, target_addr):
        return True
    block_addrs = tuple(getattr(function, "block_addrs_set", ()) or ())
    return any(_target_addr_matches_near_or_linear_8616(block_addr, target_addr) for block_addr in block_addrs)


def _target_addr_matches_near_or_linear_8616(candidate_addr: int, target_addr: int) -> bool:
    if candidate_addr == target_addr:
        return True
    if not (isinstance(candidate_addr, int) and isinstance(target_addr, int)):
        return False
    # x86-16 near calls encode the callee IP. The project function database stores
    # rebased linear addresses, so match the low 16-bit offset when the summary
    # target is a near IP rather than a linear address.
    if 0 <= target_addr <= 0xFFFF:
        return (candidate_addr & 0xFFFF) == target_addr
    return False


def _expected_arg_count_for_known_callee_8616(name: str) -> int | None:
    def _impl():
        normalized = normalize_callee_name_8616(name)
        if not isinstance(normalized, str):
            return None
        table = {
            "aNchkstk": 0,
            "__aNchkstk": 0,
            "clock": 0,
            "memset": 3,
            "_memset": 3,
            "settextcolor": 1,
            "_settextcolor": 1,
            "settextposition": 2,
            "_settextposition": 2,
            "outtext": 1,
            "_outtext": 1,
            "outtextxy": 3,
            "_outtextxy": 3,
            "sprintf": 2,
            "_sprintf": 2,
            "settextrows": 1,
            "clearscreen": 1,
            "displaycursor": 1,
            "setvideomode": 1,
            "PercolateUp": 1,
            "_PercolateUp": 1,
            "PercolateDown": 1,
            "_PercolateDown": 1,
            "SwapBars": 2,
            "_SwapBars": 2,
            "Swaps": 2,
            "_Swaps": 2,
            "DrawBar": 1,
            "_DrawBar": 1,
            "DrawTime": 1,
            "_DrawTime": 1,
        }
        if normalized in table:
            return table[normalized]
        decl = preferred_known_helper_signature_decl(normalized)
        if isinstance(decl, str):
            m = re.search(r"\((?P<args>[^)]*)\)", decl)
            arg_text = m.group("args").strip() if m is not None else ""
            if not arg_text or arg_text == "void":
                return 0
            parts = [part.strip() for part in arg_text.split(",") if part.strip()]
            # Variadic declarations encode minimum required arguments before `...`.
            if parts and parts[-1] == "...":
                parts = parts[:-1]
            return len(parts)
        return None

    return _impl()


def _expected_arg_count_for_call_8616(
    summary_arg_count: int | None,
    *,
    known_arg_count: int | None,
    prototype_arg_count: int | None,
) -> int | None:
    """
    Resolve expected call arity with summary evidence preferred over declarative hints.

    Summary data is authoritative when present and non-zero. A summary value of 0 is
    treated as explicit zero only when no stronger known/prototype arity is available.
    """
    if isinstance(summary_arg_count, int):
        if summary_arg_count > 0:
            return summary_arg_count
        return 0
    if isinstance(known_arg_count, int) and known_arg_count > 0:
        return known_arg_count
    if isinstance(prototype_arg_count, int) and prototype_arg_count > 0:
        return prototype_arg_count
    return None


def _known_default_args_for_missing_8616(name: str, codegen) -> tuple | None:
    """Compiler/runtime helper ABI defaults used when a known helper omits pushes."""
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return None
    defaults = {
        "clearscreen": (0,),
        "displaycursor": (0,),
        "setvideomode": (0xFFFF,),
    }
    if normalized in {"Swaps", "_Swaps"}:
        project = getattr(codegen, "project", None)
        arch = getattr(project, "arch", None)
        reg_info = getattr(arch, "registers", {}).get("ds") if arch is not None else None
        if isinstance(reg_info, tuple) and len(reg_info) >= 1:
            ds_reg = structured_c.CVariable(
                SimRegisterVariable(reg_info[0], 2, name="ds"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            )
            off = structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen)
            ptr1 = structured_c.CFunctionCall("SEG_PTR", None, [copy(ds_reg), off], codegen=codegen)
            ptr2 = structured_c.CFunctionCall("SEG_PTR", None, [copy(ds_reg), copy(off)], codegen=codegen)
            return (ptr1, ptr2)
    values = defaults.get(normalized)
    if values is None:
        return None
    return tuple(structured_c.CConstant(value, SimTypeShort(False), codegen=codegen) for value in values)


def _callee_expects_pointer_arg_8616(name: str, arg_index: int) -> bool:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return _call_arg_semantic_kind_8616(normalized, arg_index) is CallArgSemanticKind8616.POINTER


def _call_arg_semantic_kind_8616(callee: str, arg_index: int) -> CallArgSemanticKind8616:
    def _impl():
        normalized = normalize_callee_name_8616(callee)
        if not isinstance(normalized, str):
            return CallArgSemanticKind8616.UNKNOWN
        cached = _KNOWN_HELPER_ARG_KIND_CACHE_8616.get(normalized)
        if cached is None:
            cached = {}
            decl = preferred_known_helper_signature_decl(normalized)
            if isinstance(decl, str):
                m = re.search(r"\((?P<args>[^)]*)\)", decl)
                arg_text = m.group("args").strip() if m is not None else ""
                if arg_text and arg_text != "void":
                    parts = [part.strip() for part in arg_text.split(",") if part.strip()]
                    for idx, part in enumerate(parts):
                        kind = (
                            CallArgSemanticKind8616.POINTER
                            if ("*" in part or "[" in part)
                            else CallArgSemanticKind8616.VALUE
                        )
                        cached[idx] = kind
            _KNOWN_HELPER_ARG_KIND_CACHE_8616[normalized] = cached
        return cached.get(arg_index, CallArgSemanticKind8616.UNKNOWN)

    return _impl()


def _callee_name_should_yield_to_sidecar_8616(callee_func, sidecar_label: str | None) -> bool:
    if callee_func is None or not isinstance(sidecar_label, str):
        return False
    callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if callee_name is None or callee_name.startswith("sub_"):
        return True
    if callee_name == sidecar_label:
        return False
    block_addrs = tuple(getattr(callee_func, "block_addrs_set", ()) or ())
    return len(block_addrs) == 0


def _cod_metadata_for_function_8616(project: SimpleNamespace, func_addr: int) -> None:
    def _impl():
        original_project = getattr(project, "_inertia_original_project", None)
        original_delta = getattr(project, "_inertia_original_linear_delta", None)
        project_variants = [project]
        if original_project is not None:
            project_variants.append(original_project)

        addr_candidates = [func_addr]
        if isinstance(original_delta, int):
            addr_candidates.append(func_addr + original_delta)
            rebased = func_addr - original_delta
            if rebased >= 0:
                addr_candidates.append(rebased)

        normalized_addr_candidates: list[int] = []
        for candidate in addr_candidates:
            if candidate not in normalized_addr_candidates:
                normalized_addr_candidates.append(candidate)

        for candidate_project in project_variants:
            lst_metadata = getattr(candidate_project, "_inertia_lst_metadata", None)
            cod_path = getattr(lst_metadata, "cod_path", None)
            if not cod_path:
                continue
            binary_path = getattr(getattr(getattr(candidate_project, "loader", None), "main_object", None), "binary", None)
            cache = getattr(candidate_project, "_inertia_sidecar_cod_metadata_cache", None)
            if not isinstance(cache, dict):
                cache = {}
                setattr(candidate_project, "_inertia_sidecar_cod_metadata_cache", cache)

            for candidate_addr in normalized_addr_candidates:
                function = getattr(getattr(candidate_project, "kb", None), "functions", None)
                function = getattr(function, "function", lambda **_: None)(addr=candidate_addr, create=False)
                function_name = getattr(function, "name", None)
                if not isinstance(function_name, str) or not function_name:
                    function_name = _sidecar_label_for_target_8616(project, candidate_addr)
                if not isinstance(function_name, str) or not function_name:
                    continue

                proc_kind = (getattr(lst_metadata, "cod_proc_kinds", {}).get(candidate_addr) or "NEAR").upper()
                name_candidates = [function_name]
                if function_name.startswith("_"):
                    stripped = function_name.lstrip("_")
                    if stripped:
                        name_candidates.append(stripped)
                else:
                    name_candidates.append(f"_{function_name}")

                for candidate in name_candidates:
                    cache_key = (str(cod_path), candidate, proc_kind)
                    if cache_key in cache:
                        return cache[cache_key]
                    try:
                        metadata = extract_cod_proc_metadata(Path(cod_path), candidate, proc_kind)
                    except Exception as ex:
                        log.debug(
                            "COD metadata lookup failed path=%s candidate=%s kind=%s: %s",
                            cod_path,
                            candidate,
                            proc_kind,
                            ex,
                        )
                        continue
                    cache[cache_key] = metadata
                    if binary_path is not None:
                        cache[(str(binary_path), candidate, proc_kind)] = metadata
                    return metadata
        return None

    return _impl()


def _candidate_target_addrs_from_call_8616(node) -> tuple[int, ...]:
    addrs: list[int] = []
    callee_func = getattr(node, "callee_func", None)
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        addrs.append(callee_addr)

    for target in (
        getattr(node, "callee_target", None),
        getattr(callee_func, "name", None),
    ):
        if not isinstance(target, str):
            continue
        normalized = normalize_callee_name_8616(target)
        if not isinstance(normalized, str):
            continue
        match = _SUB_TARGET_RE.match(normalized)
        if match is None:
            match = _NAMESPACED_TARGET_RE.match(target)
        if match is None:
            continue
        try:
            addrs.append(int(match.group("addr"), 16))
        except ValueError:
            continue

    ordered: list[int] = []
    for addr in addrs:
        if addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _rename_call_node_from_sidecar_8616(project, node) -> bool:
    if project is None:
        return False
    renamed = False
    replacement = None
    for target_addr in _candidate_target_addrs_from_call_8616(node):
        replacement = _sidecar_label_for_target_8616(project, target_addr)
        if isinstance(replacement, str):
            break
    if not isinstance(replacement, str):
        return False

    callee_func = getattr(node, "callee_func", None)
    current_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    current_target = normalize_callee_name_8616(getattr(node, "callee_target", None))
    if callee_func is not None and (current_name is None or current_name.startswith("sub_")):
        callee_func.name = replacement
        renamed = True
    if current_target is None or current_target.startswith("sub_"):
        node.callee_target = replacement
        renamed = True
    return renamed


def _call_node_name_8616(node) -> str | None:
    callee_func = getattr(node, "callee_func", None)
    for raw in (
        getattr(callee_func, "name", None),
        getattr(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def _is_runtime_segment_helper_call_8616(node) -> bool:
    tags = getattr(node, "tags", None)
    marker_name = tags.get("inertia_x86_16_runtime_segment_helper") if isinstance(tags, dict) else None
    if isinstance(marker_name, str) and marker_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616:
        return True
    call_name = _call_node_name_8616(node)
    return isinstance(call_name, str) and call_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616


def _call_name_is_unknown_8616(name: str | None) -> bool:
    return name is None or name.startswith("sub_") or name == "CallReturn"


def _callee_names_match_8616(left: str | None, right: str | None) -> bool:
    left_norm = normalize_callee_name_8616(left)
    right_norm = normalize_callee_name_8616(right)
    if not isinstance(left_norm, str) or not isinstance(right_norm, str):
        return False
    if left_norm == right_norm:
        return True
    # MSC/OMF public C symbols commonly carry one leading underscore while the
    # generated C call expression does not. Treat that decoration as equivalent.
    return left_norm.lstrip("_") == right_norm.lstrip("_")


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
        for stmt in _iter_c_nodes_deep_8616(root):
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


def _call_node_matches_summary_8616(project, node, summary) -> bool:
    def _impl():
        if node is None or summary is None:
            return False
        call_name = _call_node_name_8616(node)
        if bool(getattr(summary, "stack_probe_helper", False)) and _is_stack_probe_call_name_8616(call_name):
            return True

        target_addr = getattr(summary, "target_addr", None)
        if isinstance(target_addr, int):
            for candidate_addr in _candidate_target_addrs_from_call_8616(node):
                if _target_addr_matches_near_or_linear_8616(candidate_addr, target_addr):
                    return True
            if isinstance(call_name, str):
                functions = getattr(getattr(project, "kb", None), "functions", None)
                lookup = getattr(functions, "function", None)
                for candidate_addr in _candidate_linear_target_addrs_8616(project, target_addr):
                    try:
                        target_function = lookup(addr=candidate_addr, create=False) if callable(lookup) else None
                    except TypeError:
                        target_function = None
                    if _callee_names_match_8616(getattr(target_function, "name", None), call_name):
                        return True
                lookup_names = [call_name]
                undecorated = call_name.lstrip("_")
                decorated = f"_{undecorated}" if undecorated else None
                if decorated is not None and decorated not in lookup_names:
                    lookup_names.append(decorated)
                try:
                    named_function = None
                    if callable(lookup):
                        for lookup_name in lookup_names:
                            named_function = lookup(name=lookup_name, create=False)
                            if named_function is not None:
                                break
                except TypeError:
                    named_function = None
                named_addr = getattr(named_function, "addr", None)
                if isinstance(named_addr, int) and _target_addr_matches_near_or_linear_8616(named_addr, target_addr):
                    return True
            for candidate_name in (
                _sidecar_label_for_target_8616(project, target_addr),
                normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
            ):
                if _callee_names_match_8616(candidate_name, call_name):
                    return True
        return False

    return _impl()


def _source_name_matches_target_8616(project, target_addr: int | None, expected_source_name: str | None) -> bool:
    if not isinstance(expected_source_name, str) or not expected_source_name:
        return False
    normalized_expected = normalize_callee_name_8616(expected_source_name)
    if not isinstance(normalized_expected, str):
        return False
    if not isinstance(target_addr, int):
        return False
    for candidate_name in (
        _sidecar_label_for_target_8616(project, target_addr),
        normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
    ):
        if _callee_names_match_8616(candidate_name, normalized_expected):
            return True
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    try:
        function = lookup(name=normalized_expected, create=False) if callable(lookup) else None
    except TypeError:
        function = None
    function_addr = getattr(function, "addr", None)
    return (
        isinstance(function_addr, int)
        and isinstance(target_addr, int)
        and _target_addr_matches_near_or_linear_8616(function_addr, target_addr)
    )


def _align_cod_call_names_8616(project, codegen) -> bool:
    # Evidence-based rename from optional COD/debug metadata.
    # Safe by default: if no metadata exists, this pass is a no-op.
    def _impl():
        if os.environ.get("INERTIA_DISABLE_COD_CALL_NAME_ALIGNMENT"):
            return False
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return False
        cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
        cod_call_names = tuple(
            normalize_callee_name_8616(name)
            for name in getattr(cod_metadata, "call_names", ()) or ()
            if isinstance(normalize_callee_name_8616(name), str)
        )
        if not cod_call_names:
            return False

        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
        call_nodes = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
        ]
        if not call_nodes:
            return False

        summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
        if not isinstance(summary_map, dict):
            return False
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)

        changed = False
        cod_idx = 0
        for node in call_nodes:
            current_name = _call_node_name_8616(node)
            if not _call_name_is_unknown_8616(current_name):
                if cod_idx < len(cod_call_names) and cod_call_names[cod_idx] == current_name:
                    cod_idx += 1
                elif cod_idx == 0 and current_name in cod_call_names:
                    # Initial alignment tolerance: allow one-time seek when the first
                    # emitted call appears later in the COD sequence (e.g., stack probe skipped).
                    cod_idx = cod_call_names.index(current_name) + 1
                continue
            if cod_idx >= len(cod_call_names):
                break
            summary = summary_map.get(id(node))
            target_addr = getattr(summary, "target_addr", None) if summary is not None else None
            summary_arg_count = int(getattr(summary, "arg_count", 0) or 0) if summary is not None else 0
            matched_cod_idx = None
            replacement = None
            for candidate_idx in range(cod_idx, len(cod_call_names)):
                candidate = cod_call_names[candidate_idx]
                if not isinstance(candidate, str) or not candidate or candidate.startswith("sub_"):
                    continue
                if _source_name_matches_target_8616(project, target_addr, candidate):
                    matched_cod_idx = candidate_idx
                    replacement = candidate
                    break
            if matched_cod_idx is None and cod_idx < len(cod_call_names) and summary is not None:
                candidate = cod_call_names[cod_idx]
                expected_arity = _expected_arg_count_for_known_callee_8616(candidate)
                current_arity = len(tuple(getattr(node, "args", ()) or ()))
                if (
                    isinstance(candidate, str)
                    and candidate
                    and not candidate.startswith("sub_")
                    and isinstance(expected_arity, int)
                    and expected_arity >= 0
                    and (summary_arg_count == expected_arity or current_arity == expected_arity)
                ):
                    matched_cod_idx = cod_idx
                    replacement = candidate
            if matched_cod_idx is None or replacement is None:
                continue
            cod_idx = matched_cod_idx + 1
            expected_arity = _expected_arg_count_for_known_callee_8616(replacement)
            current_arity = len(tuple(getattr(node, "args", ()) or ()))
            # Guard against order drift: never rename an unknown call to a helper
            # whose known arity disagrees with the current callsite shape.
            callsite_arity = summary_arg_count if summary_arg_count > 0 else current_arity
            if isinstance(expected_arity, int) and callsite_arity != expected_arity:
                continue
            callee_func = getattr(node, "callee_func", None)
            if callee_func is not None and getattr(callee_func, "name", None) != replacement:
                callee_func.name = replacement
                changed = True
            if getattr(node, "callee_target", None) != replacement:
                node.callee_target = replacement
                changed = True
        return changed

    return _impl()


def _normalize_call_target_names_8616(codegen) -> bool:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        project = getattr(codegen, "project", None)
        changed = False
        allow_call_target_rewrites = bool(int(os.environ.get("INERTIA_ENABLE_CALLSITE_TARGET_REWRITES", "0")))
        stats = _ensure_callsite_materialization_stats_8616(codegen)
        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
        summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
        if not isinstance(summary_map, dict):
            summary_map = {}
        else:
            _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
        source_call_names: tuple[str, ...] = ()
        if _source_call_floor_enabled_8616():
            source_call_names = _cod_source_call_names_8616(project, getattr(cfunc, "addr", None))
        source_call_idx = 0
        call_nodes = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
        ]
        for node in call_nodes:
            summary = summary_map.get(id(node))
            expected_source_name = None
            is_stack_probe_helper = bool(getattr(summary, "stack_probe_helper", False)) if summary is not None else False
            if summary is not None and is_stack_probe_helper and _summary_proves_stack_probe_call_8616(summary, node=node):
                expected_source_name = "aNchkstk"
            elif summary is not None and not is_stack_probe_helper and source_call_idx < len(source_call_names):
                expected_source_name = source_call_names[source_call_idx]
                source_call_idx += 1
            target_addr = getattr(summary, "target_addr", None) if summary is not None else None
            summary_arg_count = int(getattr(summary, "arg_count", 0) or 0) if summary is not None else 0
            summary_stack_cleanup = getattr(summary, "stack_cleanup", None) if summary is not None else None

            changed |= _normalize_single_call_target_node_8616(
                project=project,
                node=node,
                expected_source_name=expected_source_name,
                target_addr=target_addr,
                summary_arg_count=summary_arg_count,
                summary_stack_cleanup=summary_stack_cleanup,
                stats=stats,
                allow_call_target_rewrites=allow_call_target_rewrites,
            )

            if _rename_call_node_from_sidecar_8616(project, node):
                changed = True

        if _align_cod_call_names_8616(project, codegen):
            changed = True

        _finalize_callsite_materialization_stats_8616(codegen)
        return changed

    return _impl()


def _normalize_single_call_target_node_8616(
    *,
    project,
    node,
    expected_source_name: str | None,
    target_addr: int | None,
    summary_arg_count: int,
    summary_stack_cleanup: int | None,
    stats: CallsiteMaterializationStats,
    allow_call_target_rewrites: bool,
) -> bool:
    def _impl():
        changed = False
        callee_target = getattr(node, "callee_target", None)
        normalized_target = normalize_callee_name_8616(callee_target)
        if isinstance(normalized_target, str) and normalized_target != callee_target:
            node.callee_target = normalized_target
            changed = True

        callee_func = getattr(node, "callee_func", None)
        callee_name = getattr(callee_func, "name", None)
        normalized_name = normalize_callee_name_8616(callee_name)
        if callee_func is not None and isinstance(normalized_name, str) and normalized_name != callee_name:
            callee_func.name = normalized_name
            changed = True

        if isinstance(expected_source_name, str) and expected_source_name:
            changed |= _prefer_expected_source_name_8616(
                project=project,
                node=node,
                expected_source_name=expected_source_name,
                target_addr=target_addr,
                summary_arg_count=summary_arg_count,
            )

        if _source_proves_stack_probe_call_8616(
            node=node,
            expected_source_name=expected_source_name,
            summary_arg_count=summary_arg_count,
            summary_stack_cleanup=summary_stack_cleanup,
        ):
            if getattr(node, "callee_func", None) is not None:
                node.callee_func = None
                changed = True
            normalized_probe_name = normalize_callee_name_8616(expected_source_name) or "aNchkstk"
            if getattr(node, "callee_target", None) != normalized_probe_name:
                node.callee_target = normalized_probe_name
                changed = True

        if isinstance(target_addr, int):
            changed |= _bind_stale_probe_or_unknown_target_8616(
                project=project,
                node=node,
                target_addr=target_addr,
                stats=stats,
            )

        if allow_call_target_rewrites and isinstance(target_addr, int):
            changed |= _bind_node_target_addr_8616(
                project=project,
                node=node,
                expected_source_name=expected_source_name,
                target_addr=target_addr,
                stats=stats,
            )

        if (
            isinstance(expected_source_name, str)
            and expected_source_name
            and _call_name_is_unknown_8616(_call_node_name_8616(node))
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
        ):
            if getattr(node, "callee_target", None) != expected_source_name:
                node.callee_target = expected_source_name
                changed = True
            callee_func = getattr(node, "callee_func", None)
            if callee_func is not None and getattr(callee_func, "name", None) != expected_source_name:
                callee_func.name = expected_source_name
                changed = True
        return changed

    return _impl()


def _source_proves_stack_probe_call_8616(
    *,
    node,
    expected_source_name: str | None,
    summary_arg_count: int,
    summary_stack_cleanup: int | None,
) -> bool:
    if not _is_stack_probe_call_name_8616(expected_source_name):
        return False
    if not _call_name_is_unknown_8616(_call_node_name_8616(node)):
        return False
    # Microsoft C stack probes are compiler helpers called before normal stack
    # argument setup. COD/source evidence alone is not enough; require the
    # binary callsite summary to show no pushed args and no caller cleanup.
    return summary_arg_count == 0 and summary_stack_cleanup is None


def _source_proven_stack_probe_summary_8616(summary, *, node, expected_source_name: str | None):
    summary_arg_count = int(getattr(summary, "arg_count", 0) or 0)
    summary_stack_cleanup = getattr(summary, "stack_cleanup", None)
    if not _source_proves_stack_probe_call_8616(
        node=node,
        expected_source_name=expected_source_name,
        summary_arg_count=summary_arg_count,
        summary_stack_cleanup=summary_stack_cleanup,
    ):
        return summary
    if (
        bool(getattr(summary, "stack_probe_helper", False))
        and getattr(summary, "helper_return_state", None) == "stack_address"
        and getattr(summary, "helper_return_space", None) == "ss"
        and getattr(summary, "helper_return_width", None) == 2
        and getattr(summary, "helper_return_address_kind", None) == "stack"
    ):
        return summary
    return replace(
        summary,
        stack_probe_helper=True,
        helper_return_state="stack_address",
        helper_return_space="ss",
        helper_return_width=2,
        helper_return_address_kind="stack",
    )


def _summary_proves_stack_probe_call_8616(summary, *, node) -> bool:
    if not bool(getattr(summary, "stack_probe_helper", False)):
        return False
    if not _call_name_is_unknown_8616(_call_node_name_8616(node)):
        return False
    return int(getattr(summary, "arg_count", 0) or 0) == 0 and getattr(summary, "stack_cleanup", None) is None


def _bind_stale_probe_or_unknown_target_8616(*, project, node, target_addr: int, stats) -> bool:
    def _impl():
        call_name = _call_node_name_8616(node)
        if not (_is_stack_probe_call_name_8616(call_name) or _call_name_is_unknown_8616(call_name)):
            return False
        callee_func = getattr(node, "callee_func", None)
        if _function_matches_target_addr_8616(callee_func, target_addr):
            return False

        candidate = _lookup_callee_function_8616(project, target_addr)
        sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
        candidate_name = normalize_callee_name_8616(getattr(candidate, "name", None))
        target_name = (
            sidecar_label
            if isinstance(sidecar_label, str) and sidecar_label
            else candidate_name
            if isinstance(candidate_name, str) and candidate_name
            else None
        )
        if candidate is None and not isinstance(target_name, str):
            return False

        changed = False
        if candidate is not None and getattr(node, "callee_func", None) is not candidate:
            node.callee_func = candidate
            changed = True
        elif candidate is None and getattr(node, "callee_func", None) is not None:
            node.callee_func = None
            changed = True
        if isinstance(target_name, str) and getattr(node, "callee_target", None) != target_name:
            node.callee_target = target_name
            changed = True
        if changed:
            stats.stale_target_rejected_count += 1
        return changed

    return _impl()


def _prefer_expected_source_name_8616(
    *,
    project,
    node,
    expected_source_name: str,
    target_addr: int | None,
    summary_arg_count: int,
) -> bool:
    def _impl():
        expected_arity = _expected_arg_count_for_known_callee_8616(expected_source_name)
        current_call_name = _call_node_name_8616(node)
        current_arity = len(tuple(getattr(node, "args", ()) or ()))
        current_expected_arity = (
            _expected_arg_count_for_known_callee_8616(current_call_name)
            if isinstance(current_call_name, str) and current_call_name
            else None
        )
        callsite_arity = summary_arg_count if summary_arg_count > 0 else current_arity
        source_name_proved = _source_name_matches_target_8616(project, target_addr, expected_source_name)
        if not (
            isinstance(expected_arity, int)
            and expected_arity >= 0
            and callsite_arity == expected_arity
            and isinstance(current_call_name, str)
            and current_call_name
            and current_call_name != expected_source_name
            and source_name_proved
            and (
                current_expected_arity is None
                or current_expected_arity != expected_arity
                or current_expected_arity == callsite_arity
            )
        ):
            return False
        changed = False
        if getattr(node, "callee_func", None) is not None:
            node.callee_func = None
            changed = True
        if getattr(node, "callee_target", None) != expected_source_name:
            node.callee_target = expected_source_name
            changed = True
        return changed

    return _impl()


def _bind_node_target_addr_8616(*, project, node, expected_source_name: str | None, target_addr: int, stats) -> bool:
    def _impl():
        changed = False
        candidate = _lookup_callee_function_8616(project, target_addr)
        if candidate is not None and getattr(node, "callee_func", None) is not candidate:
            candidate_name = normalize_callee_name_8616(getattr(candidate, "name", None))
            source_conflict = (
                isinstance(expected_source_name, str)
                and expected_source_name
                and _source_name_matches_target_8616(project, target_addr, expected_source_name)
                and isinstance(candidate_name, str)
                and candidate_name
                and expected_source_name != candidate_name
            )
            if not source_conflict:
                node.callee_func = candidate
                changed = True

        callee_func = getattr(node, "callee_func", None)
        current_addr = getattr(callee_func, "addr", None)
        matched_function = candidate if candidate is not None else callee_func
        if (
            not _function_matches_target_addr_8616(matched_function, target_addr)
            and isinstance(expected_source_name, str)
            and isinstance(current_addr, int)
        ):
            stats.stale_target_rejected_count += 1
            node.callee_func = None
            if getattr(node, "callee_target", None) != expected_source_name:
                node.callee_target = expected_source_name
                changed = True
            return True
        if (
            isinstance(expected_source_name, str)
            and callee_func is not None
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
        ):
            current_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
            if current_name != expected_source_name:
                callee_func.name = expected_source_name
                changed = True
            if getattr(node, "callee_target", None) != expected_source_name:
                node.callee_target = expected_source_name
                changed = True
        return changed

    return _impl()


def _finalize_callsite_materialization_stats_8616(codegen) -> CallsiteMaterializationStats:
    def _impl():
        previous = _ensure_callsite_materialization_stats_8616(codegen)
        stats = CallsiteMaterializationStats(
            bp_slot_arg_value_normalized_count=int(getattr(previous, "bp_slot_arg_value_normalized_count", 0) or 0),
            has_push_arg_evidence_count=int(getattr(previous, "has_push_arg_evidence_count", 0) or 0),
            no_push_arg_evidence_count=int(getattr(previous, "no_push_arg_evidence_count", 0) or 0),
            pointer_arg_materialized_count=int(getattr(previous, "pointer_arg_materialized_count", 0) or 0),
            push_order_reversed_count=int(getattr(previous, "push_order_reversed_count", 0) or 0),
            consumed_outgoing_stack_placeholder_count=int(
                getattr(previous, "consumed_outgoing_stack_placeholder_count", 0) or 0
            ),
            stale_target_rejected_count=int(getattr(previous, "stale_target_rejected_count", 0) or 0),
        )
        cfunc = getattr(codegen, "cfunc", None)
        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
        summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
        if not isinstance(summary_map, dict):
            summary_map = {}
        else:
            _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
        project = getattr(codegen, "project", None)
        source_call_names = _cod_source_call_names_8616(project, getattr(cfunc, "addr", None))
        source_call_idx = 0
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall):
                continue
            summary = summary_map.get(id(node))
            if summary is None or bool(getattr(summary, "stack_probe_helper", False)):
                continue
            expected_source_name = None
            if source_call_idx < len(source_call_names):
                expected_source_name = source_call_names[source_call_idx]
                source_call_idx += 1
            _accumulate_callsite_materialization_stats_8616(
                stats=stats,
                node=node,
                summary=summary,
                expected_source_name=expected_source_name,
            )

        if stats.call_target_fact_count > stats.call_target_materialized_count:
            stats.failure_count += stats.call_target_fact_count - stats.call_target_materialized_count
        if stats.call_arg_fact_count > stats.call_arg_materialized_count:
            stats.failure_count += stats.call_arg_fact_count - stats.call_arg_materialized_count

        codegen._inertia_callsite_materialization_stats = stats
        _sync_callsite_materialization_stats_8616(codegen)

        if stats.known_prototype_arg_mismatch_count:
            mismatch_details = tuple(getattr(stats, "known_prototype_arg_mismatches", ()) or ())
            log.error("known prototype call argument mismatches: %r", mismatch_details[:8])
            raise PipelineHardError(
                f"known prototype call argument mismatch count={stats.known_prototype_arg_mismatch_count}",
                layer="callsite_materialization",
                function_addr=int(getattr(cfunc, "addr", 0) or 0),
                details={
                    "known_prototype_arg_mismatch_count": int(stats.known_prototype_arg_mismatch_count),
                    "callsite_count": int(stats.callsite_count),
                    "mismatches": mismatch_details[:8],
                },
            )
        # Callsite summary evidence can be partial (especially for tiny helpers /
        # aggressively transformed CFG edges). Keep this as a diagnostic counter
        # instead of hard-aborting the whole function decompilation.
        if stats.call_target_fact_count > stats.call_target_materialized_count:
            log.debug(
                "callsite materialization incomplete: targets fact=%d materialized=%d",
                stats.call_target_fact_count,
                stats.call_target_materialized_count,
            )
        if stats.call_arg_fact_count > stats.call_arg_materialized_count:
            log.debug(
                "callsite materialization incomplete: args fact=%d materialized=%d",
                stats.call_arg_fact_count,
                stats.call_arg_materialized_count,
            )
        return stats

    return _impl()


def _accumulate_callsite_materialization_stats_8616(*, stats, node, summary, expected_source_name: str | None) -> None:
    def _impl():
        stats.callsite_count += 1
        target_addr = getattr(summary, "target_addr", None)
        if isinstance(target_addr, int):
            stats.call_target_fact_count += 1
            if _function_matches_target_addr_8616(getattr(node, "callee_func", None), target_addr):
                stats.call_target_materialized_count += 1
            else:
                for candidate_addr in _candidate_target_addrs_from_call_8616(node):
                    if candidate_addr == target_addr:
                        stats.call_target_materialized_count += 1
                        break
                else:
                    call_name = _call_node_name_8616(node)
                    if isinstance(expected_source_name, str) and call_name == expected_source_name:
                        stats.call_target_materialized_count += 1
        known_arg_count = _expected_arg_count_for_known_callee_8616(_call_node_name_8616(node) or "")
        arg_fact_count = int(getattr(summary, "arg_count", 0) or 0)
        if known_arg_count == 0:
            arg_fact_count = 0
        if arg_fact_count > 0:
            stats.call_arg_fact_count += arg_fact_count
            materialized_args = tuple(getattr(node, "args", ()) or ())
            stats.call_arg_materialized_count += min(arg_fact_count, len(materialized_args))
        expected_arg_count = known_arg_count
        actual_arg_count = len(tuple(getattr(node, "args", ()) or ()))
        if expected_arg_count is not None and actual_arg_count != expected_arg_count:
            stats.known_prototype_arg_mismatch_count += 1
            stats.failure_count += 1
            stats.known_prototype_arg_mismatches.append(
                {
                    "call": _call_node_name_8616(node),
                    "callsite_addr": getattr(summary, "callsite_addr", None),
                    "target_addr": target_addr,
                    "expected_arg_count": expected_arg_count,
                    "actual_arg_count": actual_arg_count,
                    "summary_arg_count": int(getattr(summary, "arg_count", 0) or 0),
                    "stack_probe_helper": bool(getattr(summary, "stack_probe_helper", False)),
                }
            )

    return _impl()


def _cod_source_call_names_8616(project, func_addr: int) -> tuple[str, ...]:
    def _impl():
        cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
        if cod_metadata is None:
            return ()
        # Evidence policy: prefer binary-derived call metadata (call_names) over
        # source-level call_sources for semantic recovery. Source-only wrappers can
        # diverge from emitted binary calls (e.g. GetRandom vs rand) and must not
        # drive call-floor materialization.
        names: list[str] = []
        seen: set[str] = set()
        for raw_name in getattr(cod_metadata, "call_names", ()) or ():
            normalized = normalize_callee_name_8616(raw_name)
            if not (isinstance(normalized, str) and normalized and not normalized.startswith("sub_")):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            names.append(normalized)
        if names:
            return tuple(names)
        for item in getattr(cod_metadata, "call_sources", ()) or ():
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            normalized = normalize_callee_name_8616(item[0])
            if not (isinstance(normalized, str) and normalized and not normalized.startswith("sub_")):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            names.append(normalized)
        return tuple(names)

    return _impl()


def _cod_source_call_names_for_symbol_8616(project, symbol_name: str | None) -> tuple[str, ...]:
    def _impl():
        if not isinstance(symbol_name, str) or not symbol_name:
            return ()
        lst_metadata = getattr(project, "_inertia_lst_metadata", None)
        cod_path = getattr(lst_metadata, "cod_path", None)
        if not cod_path:
            return ()
        proc_kind = "NEAR"
        for candidate in (symbol_name, symbol_name.lstrip("_"), f"_{symbol_name.lstrip('_')}"):
            if not candidate:
                continue
            try:
                metadata = extract_cod_proc_metadata(Path(cod_path), candidate, proc_kind)
            except Exception:
                continue
            names: list[str] = []
            for raw_name in getattr(metadata, "call_names", ()) or ():
                normalized = normalize_callee_name_8616(raw_name)
                if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
                    names.append(normalized)
            if names:
                return tuple(names)
        return ()

    return _impl()


def _cod_source_prototype_arg_count_8616(project, symbol_name: str | None) -> int | None:
    def _impl():
        if not isinstance(symbol_name, str) or not symbol_name:
            return None
        lst_metadata = getattr(project, "_inertia_lst_metadata", None)
        cod_path = getattr(lst_metadata, "cod_path", None)
        if not cod_path:
            return None
        try:
            text = Path(cod_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        wanted = {
            normalize_callee_name_8616(candidate)
            for candidate in (symbol_name, symbol_name.lstrip("_"), f"_{symbol_name.lstrip('_')}")
            if candidate
        }
        wanted = {item for item in wanted if isinstance(item, str) and item}
        if not wanted:
            return None
        signature_re = re.compile(r";\|\*\*\*\s+[^()\n;]+\b(?P<name>_?[A-Za-z]\w*)\s*\((?P<args>[^)]*)\)")
        for match in signature_re.finditer(text):
            normalized_name = normalize_callee_name_8616(match.group("name"))
            if normalized_name not in wanted:
                continue
            args_text = match.group("args").strip()
            if not args_text or args_text == "void":
                return 0
            return len([part for part in args_text.split(",") if part.strip() and part.strip() != "..."])
        return None

    return _impl()


def _summary_type_8616(project, width: int):
    arch = getattr(project, "arch", None)
    if width >= 4:
        ty = SimTypeLong(False)
    else:
        ty = SimTypeShort(False)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _word_type_8616(project):
    return _summary_type_8616(project, 2)


def _safe_type_size_bits_8616(type_, project=None) -> int | None:
    if type_ is None:
        return None
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return bits
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(type_, "with_arch"):
        with contextlib.suppress(Exception):
            bound = type_.with_arch(arch)
            bits = getattr(bound, "size", None)
            if isinstance(bits, int) and bits > 0:
                return bits
    return None


def _near_function_pointer_type_8616(project, arg_count: int | None):
    argc = arg_count if isinstance(arg_count, int) and arg_count >= 0 else 1
    prototype = SimTypeFunction(
        [_word_type_8616(project) for _ in range(argc)],
        _word_type_8616(project),
        variadic=False,
    )
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(prototype, "with_arch"):
        prototype = prototype.with_arch(arch)
    ptr_type = SimTypePointer(prototype)
    return ptr_type.with_arch(arch) if arch is not None and hasattr(ptr_type, "with_arch") else ptr_type


def _summary_return_type_8616(project, summary):
    return_shape = getattr(summary, "return_shape", None)
    if return_shape == "dx_ax" and getattr(summary, "return_used", None) is True:
        return _summary_type_8616(project, 4)
    if (return_shape in {None, "ax"} and getattr(summary, "return_register", None) == "ax"
            and getattr(summary, "return_used", None) is True):
        return _summary_type_8616(project, 2)
    ty = SimTypeBottom(label="void")
    arch = getattr(project, "arch", None)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _prototype_needs_summary_8616(prototype) -> bool:
    if prototype is None:
        return True
    args = tuple(getattr(prototype, "args", ()) or ())
    return_type = getattr(prototype, "returnty", None)
    if args:
        return False
    return type(return_type) is SimTypeBottom


def _apply_summary_prototype_8616(project, callee_func, summary) -> bool:
    def _impl():
        if callee_func is None or not _prototype_needs_summary_8616(getattr(callee_func, "prototype", None)):
            return False
        arg_count = getattr(summary, "arg_count", None)
        if not isinstance(arg_count, int):
            return False
        arg_widths = tuple(getattr(summary, "arg_widths", ()) or ())
        known_arg_count = _expected_arg_count_for_known_callee_8616(getattr(callee_func, "name", None) or "")
        if isinstance(known_arg_count, int) and known_arg_count > arg_count:
            arg_count = known_arg_count
        if len(arg_widths) < arg_count:
            arg_widths = arg_widths + tuple(2 for _ in range(arg_count - len(arg_widths)))
        elif len(arg_widths) > arg_count:
            arg_widths = arg_widths[:arg_count]
        arg_types = [_summary_type_8616(project, width) for width in arg_widths]
        arg_names = _normalize_arg_names_8616(None, len(arg_types))
        prototype = SimTypeFunction(
            arg_types,
            _summary_return_type_8616(project, summary),
            arg_names=arg_names,
            variadic=False,
        )
        arch = getattr(project, "arch", None)
        if arch is not None and hasattr(prototype, "with_arch"):
            prototype = prototype.with_arch(arch)
        callee_func.prototype = prototype
        callee_func.is_prototype_guessed = True
        return True

    return _impl()


def _attach_callsite_summaries_8616(project, codegen) -> bool:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return False
        measure_single_function_context = _single_function_context_measuring_enabled_8616()
        kb_lookup_count = 1
        lookup_start = time.perf_counter() if measure_single_function_context else 0.0
        function = project.kb.functions.function(addr=func_addr, create=False)
        if function is None:
            return False
        patch_direct_call_sites(function)
        names_changed = _align_cod_call_names_8616(project, codegen)

        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
        call_nodes = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
        ]
        callsite_addrs = _all_function_callsite_addrs_8616(project, function)
        if not call_nodes or not callsite_addrs:
            return False

        def _node_callsite_addr(node) -> int | None:
            tags = getattr(node, "tags", None)
            if isinstance(tags, dict):
                for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
                    value = tags.get(key)
                    if isinstance(value, int):
                        return value
            value = getattr(node, "addr", None)
            return value if isinstance(value, int) else None

        changed = bool(names_changed)
        allow_call_target_rewrites = bool(int(os.environ.get("INERTIA_ENABLE_CALLSITE_TARGET_REWRITES", "0")))
        stats = _ensure_callsite_materialization_stats_8616(codegen)
        summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
        source_call_names = _cod_source_call_names_8616(project, func_addr)
        source_call_idx = 0
        debug_callsites = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))
        if debug_callsites:
            try:
                callsite_dbg = []
                for cs_addr in callsite_addrs:
                    tgt = getattr(function, "get_call_target", lambda _addr: None)(cs_addr)
                    if measure_single_function_context and isinstance(tgt, int):
                        kb_lookup_count += 1
                    callee = project.kb.functions.function(addr=tgt, create=False) if isinstance(tgt, int) else None
                    callsite_dbg.append(
                        (
                            hex(cs_addr),
                            hex(tgt) if isinstance(tgt, int) else None,
                            normalize_callee_name_8616(getattr(callee, "name", None)) if callee is not None else None,
                        )
                    )
                log.warning(
                    "[callsite-summary] function=%#x callsites=%r source_calls=%r",
                    int(func_addr),
                    callsite_dbg,
                    tuple(source_call_names),
                )
            except Exception:
                pass
        ordered_pairs = _ordered_callsite_pairs_8616(
            project=project,
            function=function,
            root=root,
            call_nodes=call_nodes,
            callsite_addrs=callsite_addrs,
            node_callsite_addr_resolver=_node_callsite_addr,
        )

        if measure_single_function_context:
            print(
                f"[metric] fn={func_addr:#x} kind=kb-callsite-summary-lookups "
                f"kb_lookups={kb_lookup_count} elapsed_ms={int((time.perf_counter() - lookup_start) * 1000)}",
                file=sys.stderr,
                flush=True,
            )

        for node, callsite_addr in ordered_pairs:
            summary = summarize_x86_16_callsite(function, callsite_addr)
            if summary is None:
                continue
            if debug_callsites:
                log.warning(
                    "[callsite-summary] map node_id=%#x callsite=%#x target=%r name_before=%r",
                    id(node),
                    callsite_addr,
                    getattr(summary, "target_addr", None),
                    _call_node_name_8616(node),
                )
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-attach] function=%#x node=%s callsite=%#x summary_args=%r summary_sources=%r",
                    func_addr,
                    _call_node_name_8616(node),
                    callsite_addr,
                    getattr(summary, "arg_widths", None),
                    getattr(summary, "push_arg_sources", None),
                )
            expected_source_name = None
            if not bool(getattr(summary, "stack_probe_helper", False)) and source_call_idx < len(source_call_names):
                expected_source_name = source_call_names[source_call_idx]
                source_call_idx += 1
            changed |= _apply_callsite_summary_to_node_8616(
                project=project,
                codegen=codegen,
                node=node,
                summary=summary,
                summary_map=summary_map,
                expected_source_name=expected_source_name,
                allow_call_target_rewrites=allow_call_target_rewrites,
                stats=stats,
            )
        if summary_map:
            codegen._inertia_callsite_summaries = summary_map
        return changed

    return _impl()


def _all_function_callsite_addrs_8616(project, function) -> tuple[int, ...]:
    recorded = {
        int(addr)
        for addr in (getattr(function, "get_call_sites", lambda: [])() or ())
        if isinstance(addr, int)
    }
    discovered = set(recorded)
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return tuple(sorted(discovered))
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        if not isinstance(block_addr, int):
            continue
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            mnemonic = str(getattr(insn, "mnemonic", "") or "").strip().lower()
            if not mnemonic.startswith("call"):
                continue
            insn_addr = getattr(insn, "address", None)
            if isinstance(insn_addr, int):
                discovered.add(insn_addr)
    return tuple(sorted(discovered))


def _ordered_callsite_pairs_8616(*, project, function, root, call_nodes, callsite_addrs, node_callsite_addr_resolver):
    def _impl():
        def _node_contains_target(parent, target_id: int) -> bool:
            if id(parent) == target_id:
                return True
            for child in _iter_c_nodes_deep_8616(parent):
                if id(child) == target_id:
                    return True
            return False

        def _assignment_lhs_stack_offset(node) -> int | None:
            lhs = getattr(node, "lhs", None)
            while isinstance(lhs, CTypeCast):
                lhs = lhs.expr
            if isinstance(lhs, structured_c.CVariable):
                variable = getattr(lhs, "variable", None)
                if isinstance(variable, SimStackVariable):
                    offset = getattr(variable, "offset", None)
                    return offset if isinstance(offset, int) else None
            return None

        def _constant_int_value(node) -> int | None:
            while isinstance(node, CTypeCast):
                node = node.expr
            value = getattr(node, "value", None)
            if isinstance(value, int):
                return value & 0xFFFF
            return None

        def _single_existing_imm_arg(node) -> int | None:
            args = tuple(getattr(node, "args", ()) or ())
            if len(args) != 1:
                return None
            return _constant_int_value(args[0])

        def _single_summary_imm_arg(summary) -> int | None:
            sources = getattr(summary, "push_arg_sources", None)
            if not isinstance(sources, tuple) or len(sources) != 1:
                return None
            source = sources[0]
            if not isinstance(source, tuple) or len(source) < 2:
                return None
            if source[0] != "imm" or not isinstance(source[1], int):
                return None
            return int(source[1]) & 0xFFFF

        call_return_store_offsets: dict[int, int] = {}
        for assignment in _iter_c_nodes_deep_8616(root):
            if not isinstance(assignment, structured_c.CAssignment):
                continue
            lhs_offset = _assignment_lhs_stack_offset(assignment)
            if not isinstance(lhs_offset, int):
                continue
            rhs = getattr(assignment, "rhs", None)
            for node in call_nodes:
                if _node_contains_target(rhs, id(node)):
                    call_return_store_offsets[id(node)] = lhs_offset

        def _target_name_for_callsite(callsite_addr: int) -> str | None:
            try:
                target_addr = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
            except Exception:
                target_addr = None
            if not isinstance(target_addr, int):
                summary = summarize_x86_16_callsite(function, callsite_addr)
                target_addr = getattr(summary, "target_addr", None) if summary is not None else None
            if not isinstance(target_addr, int):
                return None
            candidate_func = _lookup_callee_function_8616(project, target_addr)
            candidate_name = normalize_callee_name_8616(getattr(candidate_func, "name", None))
            if isinstance(candidate_name, str) and candidate_name:
                return candidate_name
            return _sidecar_label_for_target_8616(project, target_addr)

        nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
        remaining_nodes: list[CFunctionCall] = []
        for node in call_nodes:
            callsite_addr = node_callsite_addr_resolver(node)
            if isinstance(callsite_addr, int):
                nodes_by_callsite.setdefault(callsite_addr, []).append(node)
            else:
                remaining_nodes.append(node)

        ordered_pairs: list[tuple[CFunctionCall, int]] = []
        used_node_ids: set[int] = set()
        unmatched_callsites: list[int] = []
        for callsite_addr in callsite_addrs:
            matched_nodes = nodes_by_callsite.get(callsite_addr)
            if not matched_nodes:
                unmatched_callsites.append(callsite_addr)
                continue
            summary = summarize_x86_16_callsite(function, callsite_addr)
            chosen_index = None
            if summary is not None:
                for idx, node in enumerate(matched_nodes):
                    if _call_node_matches_summary_8616(project, node, summary):
                        chosen_index = idx
                        break
            if chosen_index is None:
                unmatched_callsites.append(callsite_addr)
                continue
            node = matched_nodes.pop(chosen_index)
            ordered_pairs.append((node, callsite_addr))
            used_node_ids.add(id(node))

        remaining_nodes.extend(node for node in call_nodes if id(node) not in used_node_ids and node not in remaining_nodes)
        still_unmatched_callsites: list[int] = []
        if remaining_nodes and unmatched_callsites:
            available_nodes = list(remaining_nodes)
            if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
                log.warning(
                    "[callsite-summary] ordered unmatched callsites=%r remaining_names=%r",
                    tuple(hex(addr) for addr in unmatched_callsites[:8]),
                    tuple(_call_node_name_8616(node) for node in available_nodes[:16]),
                )
            for callsite_addr in unmatched_callsites:
                summary = summarize_x86_16_callsite(function, callsite_addr)
                matched_index = None
                if summary is not None:
                    for idx, node in enumerate(available_nodes):
                        if _call_node_matches_summary_8616(project, node, summary):
                            matched_index = idx
                            break
                if matched_index is None and summary is not None:
                    destination = getattr(summary, "return_store_destination", None)
                    if (
                        isinstance(destination, tuple)
                        and len(destination) == 2
                        and destination[0] == "bp"
                        and isinstance(destination[1], int)
                    ):
                        target_name = _target_name_for_callsite(callsite_addr)
                        for idx, node in enumerate(available_nodes):
                            if call_return_store_offsets.get(id(node)) != destination[1]:
                                continue
                            if isinstance(target_name, str) and not _callee_names_match_8616(
                                _call_node_name_8616(node), target_name
                            ):
                                continue
                            matched_index = idx
                            break
                if matched_index is None:
                    target_name = _target_name_for_callsite(callsite_addr)
                    if isinstance(target_name, str) and target_name:
                        summary_imm_arg = _single_summary_imm_arg(summary)
                        if summary_imm_arg is not None:
                            for idx, node in enumerate(available_nodes):
                                existing_imm_arg = _single_existing_imm_arg(node)
                                if existing_imm_arg != summary_imm_arg:
                                    continue
                                if _callee_names_match_8616(_call_node_name_8616(node), target_name):
                                    matched_index = idx
                                    break
                        for idx, node in enumerate(available_nodes):
                            if matched_index is not None:
                                break
                            existing_imm_arg = _single_existing_imm_arg(node)
                            if (
                                summary_imm_arg is not None
                                and existing_imm_arg is not None
                                and existing_imm_arg != summary_imm_arg
                            ):
                                continue
                            if _callee_names_match_8616(_call_node_name_8616(node), target_name):
                                matched_index = idx
                                break
                if matched_index is None:
                    still_unmatched_callsites.append(callsite_addr)
                    continue
                node = available_nodes.pop(matched_index)
                ordered_pairs.append((node, callsite_addr))
                used_node_ids.add(id(node))
            remaining_nodes = available_nodes
        if len(remaining_nodes) == len(still_unmatched_callsites) and all(
            _call_node_name_8616(node) is None for node in remaining_nodes
        ):
            for node, callsite_addr in zip(remaining_nodes, still_unmatched_callsites, strict=False):
                ordered_pairs.append((node, callsite_addr))
        return ordered_pairs

    return _impl()


def _apply_callsite_summary_to_node_8616(
    *,
    project,
    codegen,
    node,
    summary,
    summary_map,
    expected_source_name: str | None,
    allow_call_target_rewrites: bool,
    stats: CallsiteMaterializationStats,
) -> bool:
    def _impl():
        changed = False
        active_summary = summary
        upgraded_summary = _source_proven_stack_probe_summary_8616(
            active_summary,
            node=node,
            expected_source_name=expected_source_name,
        )
        if upgraded_summary is not active_summary:
            active_summary = upgraded_summary
            stats.source_proven_stack_probe_count += 1
            normalized_probe_name = normalize_callee_name_8616(expected_source_name) or "aNchkstk"
            if getattr(node, "callee_func", None) is not None:
                node.callee_func = None
                changed = True
            if getattr(node, "callee_target", None) != normalized_probe_name:
                node.callee_target = normalized_probe_name
                changed = True
        if summary_map.get(id(node)) != active_summary:
            summary_map[id(node)] = active_summary
            changed = True
            record_callsite_summary_fact_8616(codegen, active_summary, node_id=id(node), attached=True)
        target_addr = getattr(active_summary, "target_addr", None)
        if not isinstance(target_addr, int):
            return changed
        callee_func = getattr(node, "callee_func", None)
        candidate = _lookup_callee_function_8616(project, target_addr)
        if candidate is not None:
            current_addr = getattr(callee_func, "addr", None)
            candidate_addr = getattr(candidate, "addr", None)
            if (
                allow_call_target_rewrites
                and (
                    callee_func is None
                    or (
                        isinstance(current_addr, int)
                        and isinstance(candidate_addr, int)
                        and current_addr != candidate_addr
                    )
                )
            ):
                node.callee_func = candidate
                changed = True
                callee_func = candidate
        sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
        if callee_func is None and node is not None and isinstance(sidecar_label, str):
            node.callee_func = candidate
            callee_func = candidate
        if callee_func is None and isinstance(sidecar_label, str) and getattr(node, "callee_target", None) != sidecar_label:
            node.callee_target = sidecar_label
            changed = True
        if _callee_name_should_yield_to_sidecar_8616(callee_func, sidecar_label):
            callee_func.name = sidecar_label
            changed = True
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        current_addr = getattr(callee_func, "addr", None)
        matched_function = candidate if candidate is not None else callee_func
        if (
            not _function_matches_target_addr_8616(matched_function, target_addr)
            and isinstance(expected_source_name, str)
            and isinstance(target_addr, int)
            and isinstance(current_addr, int)
        ):
            stats.stale_target_rejected_count += 1
            node.callee_func = None
            callee_func = None
            callee_name = None
            changed = True
        if (
            isinstance(expected_source_name, str)
            and callee_func is not None
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            and callee_name != expected_source_name
        ):
            callee_func.name = expected_source_name
            changed = True
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        if callee_name is not None and getattr(node, "callee_target", None) != callee_name:
            node.callee_target = callee_name
            changed = True
        elif (
            callee_name is None
            and isinstance(expected_source_name, str)
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            and getattr(node, "callee_target", None) != expected_source_name
        ):
            node.callee_target = expected_source_name
            changed = True
        elif _rename_call_node_from_sidecar_8616(project, node):
            changed = True
        return changed

    return _impl()


def _refresh_callsite_summary_node_ids_8616(codegen, summary_map: dict[int, object]) -> bool:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
        if root is None:
            return False

        def _node_callsite_addr(node) -> int | None:
            tags = getattr(node, "tags", None)
            if isinstance(tags, dict):
                for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
                    value = tags.get(key)
                    if isinstance(value, int):
                        return value
            value = getattr(node, "addr", None)
            return value if isinstance(value, int) else None

        call_nodes = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
        ]
        nodes_by_callsite: dict[int, CFunctionCall] = {}
        current_node_ids: set[int] = set()
        for node in call_nodes:
            current_node_ids.add(id(node))
            callsite_addr = _node_callsite_addr(node)
            if isinstance(callsite_addr, int) and callsite_addr not in nodes_by_callsite:
                nodes_by_callsite[callsite_addr] = node

        changed = False
        refreshed = dict(summary_map)
        for node_id, summary in tuple(summary_map.items()):
            if node_id in current_node_ids:
                continue
            callsite_addr = getattr(summary, "callsite_addr", None)
            if not isinstance(callsite_addr, int):
                continue
            node = nodes_by_callsite.get(callsite_addr)
            if node is None:
                continue
            refreshed[id(node)] = summary
            refreshed.pop(node_id, None)
            changed = True

        if changed:
            codegen._inertia_callsite_summaries = refreshed
            summary_map.clear()
            summary_map.update(refreshed)
            return True

        # Fallback remap lane: when callsite tags are unavailable after AST
        # rewrites, rebind summaries only when the current call node still matches
        # the summary target/name evidence. Unknown means refuse; do not zip stale
        # summaries by order because that can manufacture wrong call semantics.
        stale_items: list[tuple[int, object]] = [
            (node_id, summary) for node_id, summary in tuple(summary_map.items()) if node_id not in current_node_ids
        ]
        if not stale_items:
            return False
        if not all(isinstance(getattr(summary, "callsite_addr", None), int) for _, summary in stale_items):
            return False
        project = getattr(codegen, "project", None)
        available_nodes = [node for node in call_nodes if id(node) not in refreshed]
        rebound = dict(refreshed)
        for old_node_id, summary in sorted(stale_items, key=lambda item: int(getattr(item[1], "callsite_addr", 0))):
            matched_idx = None
            for idx, node in enumerate(available_nodes):
                if _call_node_matches_summary_8616(project, node, summary):
                    matched_idx = idx
                    break
            if matched_idx is None:
                continue
            node = available_nodes.pop(matched_idx)
            rebound.pop(old_node_id, None)
            rebound[id(node)] = summary

        if rebound == refreshed:
            return False
        codegen._inertia_callsite_summaries = rebound
        summary_map.clear()
        summary_map.update(rebound)
        return True

    return _impl()


def _materialize_callsite_prototypes_8616(project, codegen) -> bool:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
        if not isinstance(summary_map, dict) or not summary_map:
            return False

        def _ctype_for_width(width: object) -> str:
            if isinstance(width, int) and width >= 4:
                return "unsigned long"
            if isinstance(width, int) and width == 1:
                return "unsigned char"
            return "unsigned short"

        def _prototype_decl_from_summary(name: str, summary) -> str | None:
            if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None:
                return None
            arg_count = getattr(summary, "arg_count", None)
            if not isinstance(arg_count, int) or arg_count < 0:
                return None
            arg_widths = tuple(getattr(summary, "arg_widths", ()) or ())
            if len(arg_widths) != arg_count:
                arg_widths = tuple(2 for _ in range(arg_count))
            args = (
                "void"
                if arg_count == 0
                else ", ".join(f"{_ctype_for_width(width)} a{idx}" for idx, width in enumerate(arg_widths))
            )
            return_type = (
                _ctype_for_width(4)
                if getattr(summary, "return_shape", None) == "dx_ax" and getattr(summary, "return_used", None) is True
                else _ctype_for_width(2)
                if getattr(summary, "return_shape", None) in {None, "ax"}
                and getattr(summary, "return_register", None) == "ax"
                and getattr(summary, "return_used", None) is True
                else "int"
            )
            return f"{return_type} {name}({args});"

        prototype_decls: list[str] = []
        seen_decls: set[str] = set(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
        changed = False
        root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall):
                continue
            summary = summary_map.get(id(node))
            if summary is None:
                continue
            if not isinstance(getattr(summary, "target_addr", None), int):
                continue
            if getattr(summary, "arg_count", None) == 0 and tuple(getattr(node, "args", ()) or ()):
                continue
            call_name = _call_node_name_8616(node)
            if preferred_known_helper_signature_decl(call_name or "") is not None:
                continue
            if _apply_summary_prototype_8616(project, getattr(node, "callee_func", None), summary):
                changed = True
            if bool(getattr(summary, "stack_probe_helper", False)):
                continue
            if getattr(summary, "arg_count", None) == 0:
                continue
            decl = _prototype_decl_from_summary(call_name or "", summary)
            if decl is not None and decl not in seen_decls:
                seen_decls.add(decl)
                prototype_decls.append(decl)
        if prototype_decls:
            existing = tuple(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
            codegen._inertia_callsite_prototype_decls = existing + tuple(prototype_decls)
        return changed

    return _impl()


def _stack_probe_summary_flags_8616(summary_map: dict[int, object], typed_stack_probe_facts: dict[int, object]) -> tuple[bool, bool]:
    def _impl():
        has_recoverable_stack_probe = False
        for summary_obj in tuple(summary_map.values()):
            if not bool(getattr(summary_obj, "stack_probe_helper", False)):
                continue
            if getattr(summary_obj, "helper_return_state", None) != "stack_address":
                continue
            helper_return_space = getattr(summary_obj, "helper_return_space", None)
            helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
            if helper_return_space not in {None, "ss"}:
                continue
            has_recoverable_stack_probe = True
            break
        has_unverified_non_ss_stack_probe = False
        for summary_node_id, summary_obj in tuple(summary_map.items()):
            if not bool(getattr(summary_obj, "stack_probe_helper", False)):
                continue
            if typed_stack_probe_facts.get(summary_node_id) is not None:
                continue
            if getattr(summary_obj, "helper_return_state", None) != "stack_address":
                continue
            helper_return_space = getattr(summary_obj, "helper_return_space", None)
            helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
            if helper_return_space in {None, "ss"}:
                continue
            has_unverified_non_ss_stack_probe = True
            break
        return has_recoverable_stack_probe, has_unverified_non_ss_stack_probe

    return _impl()


def _call_arg_materialization_mode_flags_8616(has_recoverable_stack_probe: bool) -> tuple[bool, bool]:
    conservative_materialization = os.environ.get(
        "INERTIA_CONSERVATIVE_CALLSITE_ARG_MATERIALIZE", "0"
    ).strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    } and not has_recoverable_stack_probe
    prune_consumed_arg_stores = os.environ.get(
        "INERTIA_ENABLE_PRUNE_CONSUMED_CALL_ARG_STORES", "1"
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return conservative_materialization, prune_consumed_arg_stores


def _conservative_call_arg_seed_8616(
    *,
    root,
    summary_map: dict[int, object],
    codegen,
    has_unverified_non_ss_stack_probe: bool,
    call_name_fn,
    expected_arg_count_fn,
    known_default_args_fn,
    direct_expr_from_push_source_fn,
    normalize_materialized_call_args_fn,
    all_arg_exprs_are_non_segment_registers_fn,
    set_materialized_call_args_fn,
    refresh_summary_arg_shape_fn,
    call_args_need_rematerialization_fn,
) -> bool:
    def _impl():
        changed = False
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
                continue
            call_name = call_name_fn(node) or ""
            summary = summary_map.get(id(node))
            push_sources = getattr(summary, "push_arg_sources", ()) if summary is not None else ()
            summary_arg_count = getattr(summary, "arg_count", None) if summary is not None else None
            known_count = expected_arg_count_fn(call_name)
            expected_count = _expected_arg_count_for_call_8616(
                summary_arg_count,
                known_arg_count=known_count,
                prototype_arg_count=None,
            )
            if not (isinstance(expected_count, int) and expected_count > 0):
                continue
            current_args = tuple(getattr(node, "args", ()) or ())
            arity_mismatch = isinstance(known_count, int) and len(current_args) != known_count
            if current_args and not arity_mismatch and not call_args_need_rematerialization_fn(node, push_arg_sources=push_sources):
                continue
            seeded_args = None
            if isinstance(push_sources, tuple) and len(push_sources) == expected_count:
                ordered_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
                direct_args = [
                    direct_expr_from_push_source_fn(source, call_name=call_name, arg_index=idx)
                    for idx, source in enumerate(ordered_sources)
                ]
                if all(arg is not None for arg in direct_args):
                    normalized_args = normalize_materialized_call_args_fn(
                        direct_args,
                        [-1] * len(direct_args),
                        [],
                        call_name=call_name,
                    )
                    if normalized_args is not None and all_arg_exprs_are_non_segment_registers_fn(normalized_args):
                        seeded_args = tuple(normalized_args)
            if seeded_args is None:
                defaults = known_default_args_fn(call_name, codegen)
                if defaults is not None and len(defaults) == expected_count and not has_unverified_non_ss_stack_probe:
                    seeded_args = tuple(defaults)
            if seeded_args is None:
                continue
            set_materialized_call_args_fn(node, seeded_args, call_name=call_name, force_replace=True)
            refresh_summary_arg_shape_fn(node, summary)
            changed = True
        return changed

    return _impl()


def _seed_empty_known_helper_calls_8616(
    *,
    root,
    summary_map: dict[int, object],
    codegen,
    has_unverified_non_ss_stack_probe: bool,
    call_name_fn,
    expected_arg_count_fn,
    known_default_args_fn,
    direct_expr_from_push_source_fn,
    set_materialized_call_args_fn,
    refresh_summary_arg_shape_fn,
) -> bool:
    def _impl():
        changed = False
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
                continue
            call_name = call_name_fn(node) or ""
            known_count = expected_arg_count_fn(call_name)
            summary = summary_map.get(id(node))
            summary_arg_count = getattr(summary, "arg_count", None) if summary is not None else None
            expected_count = _expected_arg_count_for_call_8616(
                summary_arg_count,
                known_arg_count=known_count,
                prototype_arg_count=None,
            )
            if not (isinstance(expected_count, int) and expected_count > 0):
                continue
            if tuple(getattr(node, "args", ()) or ()):
                continue
            push_sources = getattr(summary, "push_arg_sources", ()) if summary is not None else ()
            seeded_args = None
            if isinstance(push_sources, tuple) and len(push_sources) == expected_count:
                ordered_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
                direct_args = [
                    direct_expr_from_push_source_fn(source, call_name=call_name, arg_index=idx)
                    for idx, source in enumerate(ordered_sources)
                ]
                if all(arg is not None for arg in direct_args):
                    seeded_args = tuple(direct_args)
            if seeded_args is None:
                defaults = known_default_args_fn(call_name, codegen)
                if defaults is not None and len(defaults) == expected_count and not has_unverified_non_ss_stack_probe:
                    seeded_args = tuple(defaults)
            if seeded_args is None:
                continue
            set_materialized_call_args_fn(node, seeded_args, call_name=call_name, force_replace=True)
            refresh_summary_arg_shape_fn(node, summary)
            changed = True
        return changed

    return _impl()


def _clear_zero_arg_known_helper_args_8616(
    *,
    root,
    summary_map: dict[int, object],
    call_name_fn,
    expected_arg_count_fn,
    set_materialized_call_args_fn,
    refresh_summary_arg_shape_fn,
) -> bool:
    def _impl():
        changed = False
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
                continue
            call_name = call_name_fn(node) or ""
            known_count = expected_arg_count_fn(call_name)
            if known_count != 0:
                continue
            current_args = tuple(getattr(node, "args", ()) or ())
            if not current_args:
                continue
            summary = summary_map.get(id(node))
            set_materialized_call_args_fn(node, (), call_name=call_name, force_replace=True)
            if summary is not None:
                updated = replace(summary, arg_count=0, arg_widths=())
                summary_map[id(node)] = updated
                changed = True
            changed = True
        return changed

    return _impl()


def _materialize_callsite_stack_arguments_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    if getattr(codegen, "_inertia_pointer_memory_materialized_8616", None):
        # Pointer-memory materialization replaces small leaf bodies from
        # instruction evidence. Running stale callsite recovery afterward can
        # rewrite non-call carrier statements, so call lowering must refuse.
        codegen._inertia_callsite_stack_args_refused_pointer_memory_8616 = (
            int(getattr(codegen, "_inertia_callsite_stack_args_refused_pointer_memory_8616", 0) or 0) + 1
        )
        return False
    func_addr = getattr(cfunc, "addr", None)
    cod_metadata = _cod_metadata_for_function_8616(project, func_addr) if isinstance(func_addr, int) else None
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    # Evidence gate removed: when push-source evidence is absent, we still run
    # conservative materialization using backtracking/defaults.
    # The pass still remains diagnostic and must preserve semantics if no
    # recoverable evidence is available.
    has_push_arg_evidence = False
    for _summary in summary_map.values():
        push_sources = getattr(_summary, "push_arg_sources", None)
        if isinstance(push_sources, tuple) and any(source is not None for source in push_sources):
            has_push_arg_evidence = True
            break
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    if has_push_arg_evidence:
        stats.has_push_arg_evidence_count += 1
    else:
        stats.no_push_arg_evidence_count += 1

    _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    typed_stack_probe_facts = build_typed_stack_probe_return_facts_8616(codegen)
    record_callsite_summary_map_facts_8616(codegen, summary_map)
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    has_recoverable_stack_probe, has_unverified_non_ss_stack_probe = _stack_probe_summary_flags_8616(
        summary_map, typed_stack_probe_facts
    )

    changed = False
    conservative_materialization, prune_consumed_arg_stores = _call_arg_materialization_mode_flags_8616(
        has_recoverable_stack_probe
    )
    if conservative_materialization and has_push_arg_evidence:
        conservative_materialization = False
    materialized_callsite_metadata_ids: dict[int, tuple[int, ...]] = {}
    synthetic_stack_cvars: dict[int, structured_c.CVariable] = {}

    def _arg_width_from_expr(expr) -> int:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        type_ = getattr(node, "type", None)
        bits = _safe_type_size_bits_8616(type_, getattr(codegen, "project", None))
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        byte_width = getattr(arch, "byte_width", None)
        if isinstance(bits, int) and bits > 0 and isinstance(byte_width, int) and byte_width > 0:
            return max(bits // byte_width, 1)
        variable = getattr(node, "variable", None)
        size = getattr(variable, "size", None)
        if isinstance(size, int) and size > 0:
            return size
        return 2

    def _is_segment_register_value_expr(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CBinaryOp) and node.op in {"Shr", "Shl", "And", "Or"}:
            return _is_segment_register_value_expr(node.lhs)
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
            return True
        return False

    def _is_call_arg_count_evidence_tuple(source) -> bool:
        if not isinstance(source, tuple) or len(source) < 2:
            return False
        if source[0] not in {"bp", "imm", "sp", "ss", "ds", "cs", "es", "dx", "ax", "bx", "cx", "dx", "di", "si", "di", "si"}:
            return False
        return isinstance(source[1], int)

    def _fallback_call_arg_count_8616(
        *,
        expected_arg_count: int | None,
        push_arg_sources: tuple,
    ) -> int | None:
        if isinstance(expected_arg_count, int):
            return expected_arg_count
        if isinstance(push_arg_sources, tuple) and push_arg_sources and all(
            _is_call_arg_count_evidence_tuple(source) for source in push_arg_sources
        ):
            return len(push_arg_sources)
        return 1

    def _all_arg_exprs_are_non_segment_registers(args) -> bool:
        return bool(args) and all(not _is_segment_register_value_expr(arg) for arg in args)

    def _is_plain_register_value_expr(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            return False
        return not _is_segment_register_value_expr(node)

    def _plain_register_expr_key(expr):
        if not _is_plain_register_value_expr(expr):
            return None
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        if variable is None:
            return None
        return (
            getattr(variable, "reg", None),
            getattr(variable, "size", None),
        )

    def _outgoing_stack_value_expr_key(expr):
        if not _is_outgoing_stack_value_carrier_expr(expr):
            return None
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        if variable is None:
            return None
        return (
            getattr(variable, "offset", None),
            getattr(variable, "size", None),
            getattr(variable, "base", None),
            getattr(variable, "name", None) or getattr(node, "name", None),
        )

    def _value_expr_key(expr):
        return _plain_register_expr_key(expr) or _outgoing_stack_value_expr_key(expr)

    def _same_value_carrier_identity_expr(expr_a, expr_b) -> bool:
        node_a = expr_a
        while isinstance(node_a, CTypeCast):
            node_a = node_a.expr
        node_b = expr_b
        while isinstance(node_b, CTypeCast):
            node_b = node_b.expr
        if not isinstance(node_a, structured_c.CVariable) or not isinstance(node_b, structured_c.CVariable):
            return False
        key_a = _value_expr_key(node_a)
        key_b = _value_expr_key(node_b)
        if key_a is None or key_b is None or key_a != key_b:
            return False
        var_a = getattr(node_a, "variable", None)
        var_b = getattr(node_b, "variable", None)
        name_a = getattr(var_a, "name", None) or getattr(node_a, "name", None)
        name_b = getattr(var_b, "name", None) or getattr(node_b, "name", None)
        return name_a == name_b

    def _is_outgoing_stack_value_carrier_expr(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return False
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int):
            return False
        if offset < 0 or offset > 2:
            return False
        return True

    def _is_c_ast_node(value) -> bool:
        return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")

    def _clone_c_ast_tree(node):
        if not _is_c_ast_node(node):
            return node
        cloned = copy(node)
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "variable",
            "index",
        ):
            if not hasattr(cloned, attr):
                continue
            value = getattr(cloned, attr, None)
            if _is_c_ast_node(value):
                setattr(cloned, attr, _clone_c_ast_tree(value))
        for attr in ("args", "operands"):
            if not hasattr(cloned, attr):
                continue
            items = getattr(cloned, attr, None)
            if not isinstance(items, (list, tuple)):
                continue
            rebuilt = [_clone_c_ast_tree(item) if _is_c_ast_node(item) else item for item in items]
            setattr(cloned, attr, tuple(rebuilt) if isinstance(items, tuple) else rebuilt)
        return cloned

    def _resolve_recent_value_assignment(expr, statements_prefix: list):
        if not (_is_plain_register_value_expr(expr) or _is_outgoing_stack_value_carrier_expr(expr)):
            return expr, len(statements_prefix)
        expr_value_key = _value_expr_key(expr)
        for stmt_idx in range(len(statements_prefix) - 1, -1, -1):
            stmt = statements_prefix[stmt_idx]
            for assignment in reversed(_iter_assignment_nodes(stmt)):
                lhs, rhs = _assignment_lhs_rhs(assignment)
                if lhs is None or rhs is None:
                    continue
                lhs_value_key = _value_expr_key(lhs)
                if not _same_c_expression_8616(lhs, expr) and not (
                    expr_value_key is not None and lhs_value_key is not None and lhs_value_key == expr_value_key
                ):
                    continue
                if _assignment_lhs_writes_memory(lhs) or _is_segment_register_value_expr(rhs):
                    return None, stmt_idx
                if _same_value_carrier_identity_expr(rhs, expr):
                    return None, stmt_idx
                return rhs, stmt_idx
        return None, None

    def _expr_contains_plain_register_uses(expr) -> bool:
        stack = [expr]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            while isinstance(node, CTypeCast):
                node = node.expr
            if _is_plain_register_value_expr(node) or _is_outgoing_stack_value_carrier_expr(node):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(node, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(node, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _resolve_register_carriers_in_expr(expr, statements_prefix: list, seen_keys: set | None = None):
        if not _expr_contains_plain_register_uses(expr):
            return expr

        if seen_keys is None:
            seen_keys = set()
        rewritten = _clone_c_ast_tree(expr)
        failed = False

        def transform(node):
            nonlocal failed
            if failed or not (_is_plain_register_value_expr(node) or _is_outgoing_stack_value_carrier_expr(node)):
                return node
            key = _value_expr_key(node)
            scoped_key = (key, len(statements_prefix)) if key is not None else None
            if scoped_key is not None and scoped_key in seen_keys:
                failed = True
                return node
            resolved, resolved_stmt_idx = _resolve_recent_value_assignment(node, statements_prefix)
            if resolved is None:
                failed = True
                return node
            next_seen = set(seen_keys)
            current_prefix_len = len(statements_prefix)
            next_prefix = (
                statements_prefix[:resolved_stmt_idx]
                if isinstance(resolved_stmt_idx, int) and resolved_stmt_idx >= 0
                else statements_prefix
            )
            if key is not None:
                # Guard only against revisiting the same register identity at the
                # same search horizon. When the horizon shrinks, we still want to
                # walk earlier same-register carriers (ax_9 -> ax_7 -> iParent).
                next_seen.add((key, current_prefix_len))
            resolved = _resolve_register_carriers_in_expr(resolved, next_prefix, next_seen)
            if resolved is None or _expr_contains_plain_register_uses(resolved):
                failed = True
                return node
            return _clone_c_ast_tree(resolved)

        new_root = transform(rewritten)
        if new_root is not rewritten:
            rewritten = new_root
        if failed:
            return None
        _replace_c_children_8616(rewritten, transform)
        if failed or _expr_contains_plain_register_uses(rewritten):
            return None
        return rewritten

    def _stack_slot_fallback_name(offset: int) -> str:
        stack_aliases = getattr(cod_metadata, "stack_aliases", None)
        if isinstance(stack_aliases, dict):
            alias_name = stack_aliases.get(offset)
            if not isinstance(alias_name, str) and isinstance(offset, int):
                alias_name = stack_aliases.get(offset + 1)
            if isinstance(alias_name, str) and alias_name:
                return alias_name
        if offset >= 0:
            slot_index = max(offset // 2, 1)
            return f"arg_{slot_index}"
        slot_index = max(((-offset) + 1) // 2, 1)
        return f"local_{slot_index}"

    def _stack_name_preference(name: str | None) -> int:
        if not isinstance(name, str) or not name:
            return 0
        if name.startswith(("vvar_", "tmp_", "ir_", "s_", "stack_bp_", "stack_sp_")):
            return 1
        if name.startswith(("local_", "arg_")):
            return 3
        return 4

    def _iter_stack_cvar_candidates():
        yielded: set[int] = set()
        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if isinstance(variable, SimStackVariable) and isinstance(cvar, structured_c.CVariable):
                    yielded.add(id(cvar))
                    yield cvar
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is not None:
            for node in _iter_c_nodes_deep_8616(root):
                if not isinstance(node, structured_c.CVariable):
                    continue
                variable = getattr(node, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                if id(node) in yielded:
                    continue
                yielded.add(id(node))
                yield node

    def _stack_cvar_for_offset(offset: int, *, size_hint: int = 2, allow_best_match: bool = True):
        existing_synthetic = synthetic_stack_cvars.get(offset)
        if existing_synthetic is not None:
            return _clone_c_ast_tree(existing_synthetic)

        def _register_synthetic_stack_cvar(name: str, variable_type):
            cvar = _materialize_stack_cvar_at_offset_from_facts_8616(codegen, offset, max(size_hint, 1))
            variable = getattr(cvar, "variable", None)
            bound_variable_type = variable_type or _word_type_8616(project)
            if not isinstance(cvar, structured_c.CVariable) or not isinstance(variable, SimStackVariable):
                variable = SimStackVariable(
                    offset,
                    max(size_hint, 1),
                    base="bp",
                    name=name,
                    region=getattr(getattr(codegen, "cfunc", None), "addr", None),
                )
                cvar = structured_c.CVariable(
                    variable,
                    variable_type=bound_variable_type,
                    codegen=codegen,
                )
            else:
                if getattr(variable, "name", None) != name:
                    variable.name = name
                if getattr(cvar, "variable_type", None) is None:
                    cvar.variable_type = bound_variable_type
            synthetic_stack_cvars[offset] = cvar
            variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                variables_in_use[variable] = cvar
            unified_locals = getattr(getattr(codegen, "cfunc", None), "unified_local_vars", None)
            if isinstance(unified_locals, dict):
                unified_locals[variable] = {(cvar, getattr(cvar, "variable_type", None))}
            return cvar

        stack_aliases = getattr(cod_metadata, "stack_aliases", None)
        exact_alias_name = None
        if isinstance(stack_aliases, dict):
            maybe_alias = stack_aliases.get(offset)
            if not isinstance(maybe_alias, str) and isinstance(offset, int):
                maybe_alias = stack_aliases.get(offset + 1)
            if isinstance(maybe_alias, str) and maybe_alias:
                exact_alias_name = maybe_alias
        if exact_alias_name is not None:
            for cvar in _iter_stack_cvar_candidates():
                variable = getattr(cvar, "variable", None)
                base_offset = getattr(variable, "offset", None)
                name = getattr(variable, "name", None) or getattr(cvar, "name", None)
                if isinstance(variable, SimStackVariable) and base_offset == offset and name == exact_alias_name:
                    return _clone_c_ast_tree(cvar)
            return _clone_c_ast_tree(_register_synthetic_stack_cvar(exact_alias_name, _word_type_8616(project)))

        exact_match = None
        exact_match_score = None
        for cvar in _iter_stack_cvar_candidates():
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            base_offset = getattr(variable, "offset", None)
            if base_offset != offset or not isinstance(base_offset, int):
                continue
            name = getattr(variable, "name", None) or getattr(cvar, "name", None)
            name_pref = _stack_name_preference(name)
            size_hint_ok = (
                1
                if isinstance(size_hint, int)
                and getattr(variable, "size", None) is not None
                and int(getattr(variable, "size", 0)) >= int(size_hint)
                else 0
            )
            score = (name_pref, size_hint_ok, getattr(variable, "size", 0))
            if exact_match_score is None or score > exact_match_score:
                exact_match = cvar
                exact_match_score = score
        if exact_match is not None:
            exact_name = getattr(getattr(exact_match, "variable", None), "name", None) or getattr(
                exact_match, "name", None
            )
            if _stack_name_preference(exact_name) <= 1:
                return _clone_c_ast_tree(
                    _register_synthetic_stack_cvar(
                        _stack_slot_fallback_name(offset),
                        getattr(exact_match, "variable_type", None) or _word_type_8616(project),
                    )
                )
            return _clone_c_ast_tree(exact_match)

        best = None
        best_score = None
        if allow_best_match:
            for cvar in _iter_stack_cvar_candidates():
                variable = getattr(cvar, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                base_offset = getattr(variable, "offset", None)
                size = getattr(variable, "size", None)
                if not isinstance(base_offset, int) or not isinstance(size, int) or size <= 0:
                    continue
                relation = 0
                if base_offset == offset:
                    relation = 4
                elif base_offset <= offset < base_offset + size:
                    relation = 3
                elif abs(base_offset - offset) == 1:
                    relation = 2
                if relation == 0:
                    continue
                name = getattr(variable, "name", None) or getattr(cvar, "name", None)
                name_pref = _stack_name_preference(name)
                score = (
                    1 if name_pref >= 3 else 0,
                    relation,
                    name_pref,
                    1 if isinstance(size_hint, int) and size >= size_hint else 0,
                    size,
                    -abs(base_offset - offset),
                )
                if best_score is None or score > best_score:
                    best = cvar
                    best_score = score

        if best is not None:
            best_name = getattr(getattr(best, "variable", None), "name", None) or getattr(best, "name", None)
            if _stack_name_preference(best_name) <= 1:
                return _clone_c_ast_tree(
                    _register_synthetic_stack_cvar(
                        _stack_slot_fallback_name(offset),
                        getattr(best, "variable_type", None) or _word_type_8616(project),
                    )
                )
            return _clone_c_ast_tree(best)

        return _clone_c_ast_tree(
            _register_synthetic_stack_cvar(_stack_slot_fallback_name(offset), _word_type_8616(project))
        )

    def _set_stack_slot_type_8616(offset: int, variable_type) -> bool:
        changed_type = False
        cfunc_obj = getattr(codegen, "cfunc", None)
        variables = getattr(cfunc_obj, "variables_in_use", None)
        if isinstance(variables, dict):
            for variable, cvar in variables.items():
                if not isinstance(variable, SimStackVariable):
                    continue
                if getattr(variable, "offset", None) != offset:
                    continue
                if getattr(cvar, "variable_type", None) != variable_type:
                    cvar.variable_type = variable_type
                    changed_type = True
        unified = getattr(cfunc_obj, "unified_local_vars", None)
        if isinstance(unified, dict):
            for variable, entries in list(unified.items()):
                if not isinstance(variable, SimStackVariable) or getattr(variable, "offset", None) != offset:
                    continue
                new_entries = set()
                for cvar, _old_type in entries:
                    if getattr(cvar, "variable_type", None) != variable_type:
                        cvar.variable_type = variable_type
                        changed_type = True
                    new_entries.add((cvar, variable_type))
                unified[variable] = new_entries
        for node in _iter_c_nodes_deep_8616(cfunc_obj):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = getattr(node, "variable", None)
            if not isinstance(variable, SimStackVariable) or getattr(variable, "offset", None) != offset:
                continue
            if getattr(node, "variable_type", None) != variable_type:
                node.variable_type = variable_type
                changed_type = True
        return changed_type

    def _canonical_stack_cvar_for_offset_8616(offset: int):
        best = None
        best_score = None
        for cvar in _iter_stack_cvar_candidates():
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            if getattr(variable, "offset", None) != offset:
                continue
            name = getattr(variable, "name", None) or getattr(cvar, "name", None)
            score = (_stack_name_preference(name), getattr(variable, "size", 0))
            if best_score is None or score > best_score:
                best = cvar
                best_score = score
        return best

    def _type_size_bytes_8616(type_, *, default: int = 2) -> int:
        if isinstance(type_, SimTypePointer) and getattr(getattr(project, "arch", None), "name", None) == "86_16":
            return 2
        bits = _safe_type_size_bits_8616(type_, project)
        if isinstance(bits, int) and bits > 0:
            return max(1, (bits + 7) // 8)
        return default

    def _set_codegen_prototype_from_args_8616(prototype) -> bool:
        changed_proto = False
        cfunc_obj = getattr(codegen, "cfunc", None)
        if cfunc_obj is not None:
            if getattr(cfunc_obj, "functy", None) != prototype:
                cfunc_obj.functy = prototype
                changed_proto = True
            if getattr(cfunc_obj, "prototype", None) != prototype:
                with contextlib.suppress(Exception):
                    cfunc_obj.prototype = prototype
                    changed_proto = True
        func_addr = getattr(cfunc_obj, "addr", None)
        func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
        if func is not None and getattr(func, "prototype", None) != prototype:
            func.prototype = prototype
            func.is_prototype_guessed = False
            changed_proto = True
        return changed_proto

    def _promote_stack_arg_type_8616(offset: int, variable_type) -> bool:
        if not isinstance(offset, int) or offset < 4:
            return False
        cfunc_obj = getattr(codegen, "cfunc", None)
        if cfunc_obj is None:
            return False
        prototype = getattr(cfunc_obj, "functy", None) or getattr(cfunc_obj, "prototype", None)
        if prototype is None:
            func_addr = getattr(cfunc_obj, "addr", None)
            func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
            prototype = getattr(func, "prototype", None) if func is not None else None
        if prototype is None:
            prototype = SimTypeFunction([], _word_type_8616(project), arg_names=(), variadic=False)
            arch = getattr(project, "arch", None)
            if arch is not None and hasattr(prototype, "with_arch"):
                prototype = prototype.with_arch(arch)
        args = list(getattr(prototype, "args", ()) or ())
        arg_names = list(getattr(prototype, "arg_names", None) or ())
        cursor = 4
        target_index = None
        for idx, arg_type in enumerate(args):
            if cursor == offset:
                target_index = idx
                break
            cursor += max(2, _type_size_bytes_8616(arg_type))
        if target_index is None:
            if offset > 0x40:
                return False
            while cursor <= offset:
                new_type = variable_type if cursor == offset else _word_type_8616(project)
                args.append(new_type)
                if len(arg_names) < len(args):
                    arg_names.append(_stack_slot_fallback_name(cursor))
                if cursor == offset:
                    target_index = len(args) - 1
                    break
                cursor += max(2, _type_size_bytes_8616(new_type))
        if target_index is None:
            return False

        changed_arg = False
        if args[target_index] != variable_type:
            args[target_index] = variable_type
            changed_arg = True

        desired_args = []
        variables = getattr(cfunc_obj, "variables_in_use", None)
        unified = getattr(cfunc_obj, "unified_local_vars", None)
        func_addr = getattr(cfunc_obj, "addr", None)
        cursor = 4
        for idx, arg_type in enumerate(args):
            cvar = _canonical_stack_cvar_for_offset_8616(cursor)
            name = arg_names[idx] if idx < len(arg_names) and isinstance(arg_names[idx], str) else None
            if not name:
                name = _stack_slot_fallback_name(cursor)
            width = max(2, _type_size_bytes_8616(arg_type))
            if cvar is None:
                variable = SimStackVariable(
                    cursor,
                    width,
                    base="bp",
                    name=name,
                    region=func_addr,
                )
                cvar = structured_c.CVariable(variable, variable_type=arg_type, codegen=codegen)
                if isinstance(variables, dict):
                    variables[variable] = cvar
                if isinstance(unified, dict):
                    unified[variable] = {(cvar, arg_type)}
                changed_arg = True
            variable = getattr(cvar, "variable", None)
            if isinstance(variable, SimStackVariable):
                if getattr(variable, "name", None) != name:
                    variable.name = name
                    changed_arg = True
                if getattr(variable, "size", None) != width:
                    variable.size = width
                    changed_arg = True
            if getattr(cvar, "variable_type", None) != arg_type:
                cvar.variable_type = arg_type
                changed_arg = True
            desired_args.append(cvar)
            cursor += width

        existing_arg_ids = tuple(id(arg) for arg in getattr(cfunc_obj, "arg_list", ()) or ())
        desired_arg_ids = tuple(id(arg) for arg in desired_args)
        if existing_arg_ids != desired_arg_ids:
            cfunc_obj.arg_list = desired_args
            changed_arg = True
        arg_offsets: set[int] = set()
        cursor = 4
        for arg_type in args:
            arg_offsets.add(cursor)
            cursor += max(2, _type_size_bytes_8616(arg_type))
        desired_ids = {id(arg) for arg in desired_args}
        if isinstance(variables, dict):
            for variable, cvar in tuple(variables.items()):
                if not isinstance(variable, SimStackVariable):
                    continue
                if getattr(variable, "offset", None) not in arg_offsets:
                    continue
                if id(cvar) in desired_ids:
                    continue
                del variables[variable]
                changed_arg = True
        if isinstance(unified, dict):
            for variable, entries in tuple(unified.items()):
                if not isinstance(variable, SimStackVariable):
                    continue
                if getattr(variable, "offset", None) not in arg_offsets:
                    continue
                kept_entries = {
                    (cvar, entry_type)
                    for cvar, entry_type in (entries or ())
                    if id(cvar) in desired_ids
                }
                if kept_entries:
                    if kept_entries != entries:
                        unified[variable] = kept_entries
                        changed_arg = True
                else:
                    del unified[variable]
                    changed_arg = True
        refresh = getattr(cfunc_obj, "refresh", None)
        if callable(refresh):
            with contextlib.suppress(Exception):
                refresh()

        normalized_names = _normalize_arg_names_8616(arg_names, len(args))
        new_prototype = SimTypeFunction(
            args,
            getattr(prototype, "returnty", _word_type_8616(project)),
            arg_names=normalized_names,
            variadic=getattr(prototype, "variadic", False),
        )
        arch = getattr(project, "arch", None)
        if arch is not None and hasattr(new_prototype, "with_arch"):
            new_prototype = new_prototype.with_arch(arch)
        if _set_codegen_prototype_from_args_8616(new_prototype):
            changed_arg = True
        return changed_arg

    def _stack_slot_offset_for_name_8616(name: str | None) -> int | None:
        if not isinstance(name, str) or not name:
            return None
        for cvar in _iter_stack_cvar_candidates():
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            candidate_name = getattr(variable, "name", None) or getattr(cvar, "name", None)
            if candidate_name == name:
                offset = getattr(variable, "offset", None)
                return offset if isinstance(offset, int) else None
        return None

    def _indirect_call_target_stack_offset_8616(call, summary=None) -> int | None:
        if call is None:
            return None
        target_source = getattr(summary, "target_source", None) if summary is not None else None
        if (
            isinstance(target_source, tuple)
            and len(target_source) >= 2
            and target_source[0] == "bp"
            and isinstance(target_source[1], int)
        ):
            return int(target_source[1])
        callee_target = getattr(call, "callee_target", None)
        offset = _plain_bp_stack_load_offset(callee_target)
        if offset is None:
            offset = _plain_stack_slot_address_offset(callee_target)
        return offset

    def _apply_indirect_callsite_type_8616(call, summary, expected_arg_count: int | None) -> bool:
        target_addr = getattr(summary, "target_addr", None) if summary is not None else None
        if call is None or isinstance(target_addr, int):
            return False
        target_offset = _indirect_call_target_stack_offset_8616(call, summary)
        if not isinstance(target_offset, int):
            return False
        fnptr_type = _near_function_pointer_type_8616(project, expected_arg_count)
        changed_type = _set_stack_slot_type_8616(target_offset, fnptr_type)
        changed_type = _promote_stack_arg_type_8616(target_offset, fnptr_type) or changed_type
        push_arg_sources = tuple(getattr(summary, "push_arg_sources", ()) or ()) if summary is not None else ()
        arg_widths = tuple(getattr(summary, "arg_widths", ()) or ()) if summary is not None else ()
        for arg_idx, source in enumerate(push_arg_sources):
            if (
                isinstance(source, tuple)
                and len(source) >= 2
                and source[0] == "bp"
                and isinstance(source[1], int)
                and source[1] >= 4
            ):
                width = arg_widths[arg_idx] if arg_idx < len(arg_widths) and isinstance(arg_widths[arg_idx], int) else 2
                changed_type = _promote_stack_arg_type_8616(int(source[1]), _summary_type_8616(project, int(width))) or changed_type
        target_cvar = _stack_cvar_for_offset(target_offset, size_hint=2, allow_best_match=False)
        if target_cvar is not None:
            if getattr(call, "callee_func", None) is not None:
                call.callee_func = None
                changed_type = True
            if not _same_c_expression_8616(getattr(call, "callee_target", None), target_cvar):
                call.callee_target = _clone_c_ast_tree(target_cvar)
                changed_type = True
        return changed_type

    def _set_assignment_lhs_8616(assignment, new_lhs) -> bool:
        if assignment is None or new_lhs is None:
            return False
        if hasattr(assignment, "lhs"):
            if _same_c_expression_8616(getattr(assignment, "lhs", None), new_lhs):
                return False
            assignment.lhs = _clone_c_ast_tree(new_lhs)
            return True
        if hasattr(assignment, "dst"):
            if _same_c_expression_8616(getattr(assignment, "dst", None), new_lhs):
                return False
            assignment.dst = _clone_c_ast_tree(new_lhs)
            return True
        return False

    def _apply_call_return_store_destination_8616(stmt, call, summary) -> bool:
        destination = getattr(summary, "return_store_destination", None) if summary is not None else None
        if (
            call is None
            or not isinstance(destination, tuple)
            or len(destination) != 2
            or destination[0] != "bp"
            or not isinstance(destination[1], int)
            or getattr(summary, "return_register", None) not in {None, "ax"}
        ):
            return False
        dest_cvar = _stack_cvar_for_offset(destination[1], allow_best_match=False)
        if dest_cvar is None:
            dest_cvar = _stack_cvar_for_offset(destination[1], allow_best_match=True)
        if dest_cvar is None:
            return False
        updated = False
        for assignment in _iter_assignment_nodes(stmt):
            if _call_from_statement(assignment) is not call and not any(
                node is call for node in _iter_c_nodes_deep_8616(assignment)
            ):
                continue
            updated |= _set_assignment_lhs_8616(assignment, dest_cvar)
        return updated

    def _near_function_symbol_expr_8616(target_addr: int, arg_count: int | None = None):
        name = None
        synthetic_globals = getattr(codegen, "_inertia_synthetic_globals", None)
        if not isinstance(synthetic_globals, dict):
            synthetic_globals = getattr(project, "_inertia_synthetic_globals", None)
        if isinstance(synthetic_globals, dict):
            synthetic = synthetic_globals.get(target_addr)
            if (
                isinstance(synthetic, tuple)
                and len(synthetic) >= 1
                and isinstance(synthetic[0], str)
                and synthetic[0]
            ):
                name = normalize_callee_name_8616(synthetic[0].lstrip("_")) or synthetic[0].lstrip("_")
        if not isinstance(name, str) or not name:
            name = _sidecar_label_for_target_8616(project, target_addr)
        if not isinstance(name, str) or not name:
            callee = _lookup_callee_function_8616(project, target_addr)
            name = normalize_callee_name_8616(getattr(callee, "name", None))
        if not isinstance(name, str) or not name:
            return None
        variable = SimMemoryVariable(target_addr, 2, name=name, region=getattr(cfunc, "addr", None))
        return structured_c.CVariable(
            variable,
            variable_type=_near_function_pointer_type_8616(project, arg_count),
            codegen=codegen,
        )

    def _operand_reg_name_from_capstone_8616(insn, operand) -> str | None:
        reg = getattr(operand, "reg", None)
        if not isinstance(reg, int):
            return None
        reg_name = getattr(insn, "reg_name", None)
        if not callable(reg_name):
            return None
        with contextlib.suppress(Exception):
            name = reg_name(reg)
            if isinstance(name, str) and name:
                return name.lower()
        return None

    def _mov_bp_imm_store_8616(insn) -> tuple[int, int] | None:
        if str(getattr(insn, "mnemonic", "") or "").lower() != "mov":
            return None
        operands = tuple(getattr(insn, "operands", ()) or ())
        if len(operands) != 2:
            return None
        dst, src = operands
        if getattr(dst, "type", None) != 3 or getattr(src, "type", None) != 2:
            return None
        mem = getattr(dst, "mem", None)
        base_reg = getattr(mem, "base", None) if mem is not None else None
        base_operand = SimpleNamespace(reg=base_reg) if isinstance(base_reg, int) else None
        base = _operand_reg_name_from_capstone_8616(insn, base_operand) if base_operand is not None else None
        if base != "bp":
            return None
        disp = getattr(mem, "disp", None)
        imm = getattr(src, "imm", None)
        if not isinstance(disp, int) or not isinstance(imm, int):
            return None
        return disp, imm & 0xFFFF

    def _mov_bp_store_offset_8616(insn) -> int | None:
        if str(getattr(insn, "mnemonic", "") or "").lower() != "mov":
            return None
        operands = tuple(getattr(insn, "operands", ()) or ())
        if len(operands) != 2:
            return None
        dst = operands[0]
        if getattr(dst, "type", None) != 3:
            return None
        mem = getattr(dst, "mem", None)
        base_reg = getattr(mem, "base", None) if mem is not None else None
        base_operand = SimpleNamespace(reg=base_reg) if isinstance(base_reg, int) else None
        base = _operand_reg_name_from_capstone_8616(insn, base_operand) if base_operand is not None else None
        if base != "bp":
            return None
        disp = getattr(mem, "disp", None)
        return disp if isinstance(disp, int) else None

    def _function_for_current_cfunc_8616():
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return None
        functions = getattr(getattr(project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", None)
        if not callable(lookup):
            return None
        with contextlib.suppress(Exception):
            return lookup(addr=func_addr, create=False)
        return None

    def _function_pointer_stack_store_evidence_8616() -> dict[int, list[tuple[int, object]]]:
        function = _function_for_current_cfunc_8616()
        block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
        evidence: dict[int, list[tuple[int, object]]] = {}
        seen_stores: set[tuple[int, int, int]] = set()
        for block_addr in block_addrs:
            with contextlib.suppress(Exception):
                block = project.factory.block(block_addr, opt_level=0)
                insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
                for insn in insns:
                    capstone_insn = getattr(insn, "insn", insn)
                    store = _mov_bp_imm_store_8616(capstone_insn)
                    if store is None:
                        continue
                    offset, imm = store
                    insn_addr = getattr(insn, "address", 0) or 0
                    store_key = (int(insn_addr), int(offset), int(imm))
                    if store_key in seen_stores:
                        continue
                    seen_stores.add(store_key)
                    symbol = _near_function_symbol_expr_8616(imm)
                    if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"):
                        log.warning(
                            "[fnptr-store] func=%#x block=%#x insn=%#x offset=%r imm=%#x symbol=%r",
                            getattr(cfunc, "addr", 0) or 0,
                            block_addr,
                            insn_addr,
                            offset,
                            imm,
                            getattr(getattr(symbol, "variable", None), "name", None) if symbol is not None else None,
                        )
                    if symbol is None:
                        continue
                    evidence.setdefault(offset, []).append((insn_addr, symbol))
        ordered: dict[int, list[tuple[int, object]]] = {}
        for offset, items in evidence.items():
            ordered[offset] = [
                (int(getattr(getattr(symbol, "variable", None), "addr", imm) or imm), _clone_c_ast_tree(symbol))
                for _addr, symbol in sorted(items, key=lambda item: item[0])
                for imm in [int(getattr(getattr(symbol, "variable", None), "addr", 0) or 0)]
            ]
        return ordered

    def _bp_stack_store_counts_8616() -> Counter[int]:
        function = _function_for_current_cfunc_8616()
        block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
        counts: Counter[int] = Counter()
        seen_insns: set[int] = set()
        for block_addr in block_addrs:
            with contextlib.suppress(Exception):
                block = project.factory.block(block_addr, opt_level=0)
                insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
                for insn in insns:
                    insn_addr = int(getattr(insn, "address", 0) or 0)
                    if insn_addr in seen_insns:
                        continue
                    capstone_insn = getattr(insn, "insn", insn)
                    offset = _mov_bp_store_offset_8616(capstone_insn)
                    if offset is None:
                        continue
                    seen_insns.add(insn_addr)
                    counts[offset] += 1
        return counts

    def _stack_offset_from_cvar_8616(expr) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return None
        variable = getattr(node, "variable", None)
        offset = getattr(variable, "offset", None)
        return offset if isinstance(variable, SimStackVariable) and isinstance(offset, int) else None

    def _is_immediate_like_expr_8616(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        return isinstance(node, structured_c.CConstant)

    def _constant_int_value_8616(expr) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        value = getattr(node, "value", None) if isinstance(node, structured_c.CConstant) else None
        return int(value) & 0xFFFF if isinstance(value, int) else None

    def _symbol_name_8616(expr) -> str | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        return name if isinstance(name, str) and name else None

    def _assignment_to_stack_offset_8616(stmt, offset: int):
        for assignment in _iter_assignment_nodes(stmt):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if _stack_offset_from_cvar_8616(lhs) == offset:
                return assignment, rhs
        return None, None

    def _replace_stack_code_pointer_assignments_8616(root) -> bool:
        evidence = _function_pointer_stack_store_evidence_8616()
        if not evidence:
            return False
        bp_stack_store_counts = _bp_stack_store_counts_8616()
        changed_local = False
        debug_fnptr = bool(os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"))

        def _debug_expr_name_offset_value_8616(expr) -> tuple[str, str | None, int | None, int | None]:
            node = expr
            while isinstance(node, CTypeCast):
                node = node.expr
            variable = getattr(node, "variable", None)
            name = getattr(variable, "name", None) or getattr(node, "name", None)
            offset = getattr(variable, "offset", None) if isinstance(variable, SimStackVariable) else None
            value = getattr(node, "value", None) if isinstance(node, structured_c.CConstant) else None
            return (
                type(node).__name__ if node is not None else "None",
                name if isinstance(name, str) else None,
                offset if isinstance(offset, int) else None,
                value if isinstance(value, int) else None,
            )

        def _debug_assignment_tuple_8616(assignment) -> tuple[
            tuple[str, str | None, int | None, int | None],
            tuple[str, str | None, int | None, int | None],
        ]:
            lhs, rhs = _assignment_lhs_rhs(assignment)
            return (_debug_expr_name_offset_value_8616(lhs), _debug_expr_name_offset_value_8616(rhs))

        def _debug_assignments_in_stmt_8616(stmt) -> tuple[tuple[int | None, str | None, str], ...]:
            return tuple(_debug_assignment_tuple_8616(assignment) for assignment in _iter_assignment_nodes(stmt))

        def symbol_for_immediate(offset: int, imm: int | None, *, exclude_names: set[str] | None = None):
            symbols = evidence.get(offset)
            if not symbols:
                return None
            excluded = exclude_names or set()
            if isinstance(imm, int):
                for candidate_imm, symbol in symbols:
                    if (candidate_imm & 0xFFFF) == (imm & 0xFFFF):
                        return _clone_c_ast_tree(symbol)
            for _candidate_imm, symbol in symbols:
                name = _symbol_name_8616(symbol)
                if name is not None and name in excluded:
                    continue
                return _clone_c_ast_tree(symbol)
            return None

        def materialize_assignment(stmt) -> bool:
            local_changed = False
            for offset in tuple(evidence):
                assignment, rhs = _assignment_to_stack_offset_8616(stmt, offset)
                if assignment is None or not _is_immediate_like_expr_8616(rhs):
                    continue
                symbol = symbol_for_immediate(offset, _constant_int_value_8616(rhs))
                if symbol is None:
                    continue
                lhs, _old_rhs = _assignment_lhs_rhs(assignment)
                _set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
                if hasattr(assignment, "rhs"):
                    assignment.rhs = symbol
                elif hasattr(assignment, "src"):
                    assignment.src = symbol
                if lhs is not None:
                    _set_assignment_lhs_8616(assignment, lhs)
                local_changed = True
            return local_changed

        def make_assignment(offset: int, symbol):
            lhs = _stack_cvar_for_offset(offset, allow_best_match=False)
            if lhs is None:
                lhs = _stack_cvar_for_offset(offset, allow_best_match=True)
            if lhs is None:
                return None
            _set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
            return structured_c.CAssignment(_clone_c_ast_tree(lhs), _clone_c_ast_tree(symbol), codegen=codegen)

        def _materialize_symbol_store_assignment_8616(assignment, offset: int, symbol) -> bool:
            lhs = _stack_cvar_for_offset(offset, allow_best_match=False)
            if lhs is None:
                lhs = _stack_cvar_for_offset(offset, allow_best_match=True)
            if lhs is None:
                return False
            symbol = _clone_c_ast_tree(symbol)
            _set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
            if hasattr(assignment, "lhs"):
                assignment.lhs = _clone_c_ast_tree(lhs)
            elif hasattr(assignment, "dst"):
                assignment.dst = _clone_c_ast_tree(lhs)
            else:
                return False
            if hasattr(assignment, "rhs"):
                assignment.rhs = symbol
            elif hasattr(assignment, "src"):
                assignment.src = symbol
            else:
                return False
            return True

        def _repair_branch_immediate_function_pointer_stores_8616(stmt: structured_c.CIfElse) -> bool:
            local_changed = False
            branch_nodes = [child for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()) if child is not None]
            else_node = getattr(stmt, "else_node", None)
            if else_node is not None:
                branch_nodes.append(else_node)
            if len(branch_nodes) < 2:
                return False
            branch_assignments = [
                assignment
                for node in branch_nodes
                for assignment in _iter_assignment_nodes(node)
                if _assignment_lhs_rhs(assignment)[0] is not None and _assignment_lhs_rhs(assignment)[1] is not None
            ]
            if len(branch_assignments) < 2:
                return False
            for offset, symbols in evidence.items():
                symbol_by_imm = {int(imm) & 0xFFFF: symbol for imm, symbol in symbols}
                if len(symbol_by_imm) < 2:
                    continue
                matched: list[tuple[object, int, object]] = []
                for assignment in branch_assignments:
                    lhs, rhs = _assignment_lhs_rhs(assignment)
                    imm = _constant_int_value_8616(rhs)
                    if imm is None or (imm & 0xFFFF) not in symbol_by_imm:
                        continue
                    lhs_offset = _stack_offset_from_cvar_8616(lhs)
                    if lhs_offset == offset and _symbol_name_8616(rhs) in {
                        _symbol_name_8616(symbol) for symbol in symbol_by_imm.values()
                    }:
                        continue
                    matched.append((assignment, imm & 0xFFFF, lhs))
                if len({imm for _assignment, imm, _lhs in matched}) != len(matched):
                    continue
                if not matched:
                    continue
                # This is a branch-local storage repair, not a naming guess: every
                # rewritten RHS immediate must match an instruction-level near
                # function-pointer store to the same BP-relative slot.
                for assignment, imm, _lhs in matched:
                    symbol = symbol_by_imm.get(imm)
                    if symbol is None:
                        continue
                    if _materialize_symbol_store_assignment_8616(assignment, offset, symbol):
                        local_changed = True
                        codegen._inertia_fnptr_branch_store_identity_repaired_8616 = (
                            int(getattr(codegen, "_inertia_fnptr_branch_store_identity_repaired_8616", 0) or 0) + 1
                        )
            return local_changed

        def _branch_node_is_empty_8616(node) -> bool:
            return node is not None and not tuple(getattr(node, "statements", ()) or ())

        def _replace_branch_node_with_assignment_8616(node, assignment) -> bool:
            if node is None:
                return False
            statements = getattr(node, "statements", None)
            if not isinstance(statements, (list, tuple)):
                return False
            node.statements = [assignment] if isinstance(statements, list) else (assignment,)
            return True

        def _materialize_empty_branch_function_pointer_stores_8616(stmt: structured_c.CIfElse) -> bool:
            condition_nodes = tuple(getattr(stmt, "condition_and_nodes", ()) or ())
            if len(condition_nodes) != 1:
                return False
            true_node = condition_nodes[0][1]
            else_node = getattr(stmt, "else_node", None)
            if not (_branch_node_is_empty_8616(true_node) and _branch_node_is_empty_8616(else_node)):
                return False
            for offset, symbols in evidence.items():
                ordered_symbols = tuple(symbol for _imm, symbol in symbols)
                if len(ordered_symbols) != 2:
                    continue
                true_assignment = make_assignment(offset, ordered_symbols[0])
                false_assignment = make_assignment(offset, ordered_symbols[1])
                if true_assignment is None or false_assignment is None:
                    continue
                if not _replace_branch_node_with_assignment_8616(true_node, true_assignment):
                    continue
                if not _replace_branch_node_with_assignment_8616(else_node, false_assignment):
                    continue
                codegen._inertia_fnptr_empty_branch_stores_materialized_8616 = (
                    int(getattr(codegen, "_inertia_fnptr_empty_branch_stores_materialized_8616", 0) or 0) + 2
                )
                return True
            return False

        def _ifelse_branch_symbol_names_for_offset_8616(stmt: structured_c.CIfElse, offset: int) -> set[str]:
            names: set[str] = set()
            for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()):
                for assignment in _iter_assignment_nodes(child):
                    lhs, rhs = _assignment_lhs_rhs(assignment)
                    if _stack_offset_from_cvar_8616(lhs) == offset:
                        name = _symbol_name_8616(rhs)
                        if name is not None:
                            names.add(name)
            else_node = getattr(stmt, "else_node", None)
            if else_node is not None:
                for assignment in _iter_assignment_nodes(else_node):
                    lhs, rhs = _assignment_lhs_rhs(assignment)
                    if _stack_offset_from_cvar_8616(lhs) == offset:
                        name = _symbol_name_8616(rhs)
                        if name is not None:
                            names.add(name)
            return names

        def _assignment_is_stale_post_branch_fnptr_overwrite_8616(stmt, offset: int, symbol_names: set[str]) -> bool:
            assignments = tuple(_iter_assignment_nodes(stmt))
            if len(assignments) != 1:
                return False
            assignment = assignments[0]
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if _stack_offset_from_cvar_8616(lhs) != offset:
                return False
            rhs_symbol = _symbol_name_8616(rhs)
            if rhs_symbol in symbol_names:
                return False
            for node in _iter_c_nodes_deep_8616(stmt):
                if isinstance(node, CFunctionCall):
                    return False
            return True

        def _prune_stale_post_branch_fnptr_overwrites_8616(block) -> bool:
            statements = getattr(block, "statements", None)
            if not isinstance(statements, (list, tuple)) or len(statements) < 2:
                return False
            new_statements = list(statements)
            changed_block = False
            idx = 0
            while idx + 1 < len(new_statements):
                stmt = new_statements[idx]
                next_stmt = new_statements[idx + 1]
                if not isinstance(stmt, structured_c.CIfElse):
                    idx += 1
                    continue
                removed = False
                for offset, symbols in evidence.items():
                    symbol_names = {
                        name
                        for _imm, symbol in symbols
                        for name in [_symbol_name_8616(symbol)]
                        if name is not None
                    }
                    if len(symbol_names) < 2:
                        continue
                    branch_names = _ifelse_branch_symbol_names_for_offset_8616(stmt, offset)
                    if branch_names != symbol_names:
                        continue
                    if int(bp_stack_store_counts.get(offset, 0)) != len(symbols):
                        continue
                    if not _assignment_is_stale_post_branch_fnptr_overwrite_8616(next_stmt, offset, symbol_names):
                        continue
                    del new_statements[idx + 1]
                    codegen._inertia_fnptr_stale_post_branch_overwrites_pruned_8616 = (
                        int(getattr(codegen, "_inertia_fnptr_stale_post_branch_overwrites_pruned_8616", 0) or 0) + 1
                    )
                    changed_block = True
                    removed = True
                    break
                if not removed:
                    idx += 1
            if not changed_block:
                return False
            block.statements = new_statements if isinstance(statements, list) else tuple(new_statements)
            return True

        def walk_statement(stmt) -> None:
            nonlocal changed_local
            if stmt is None:
                return
            if isinstance(stmt, structured_c.CIfElse):
                if debug_fnptr:
                    branch_debug = []
                    for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()):
                        branch_debug.append((type(child).__name__ if child is not None else "None", _debug_assignments_in_stmt_8616(child)))
                    else_node = getattr(stmt, "else_node", None)
                    log.warning(
                        "[fnptr-ast] func=%#x ifelse branches=%r else=%r evidence_offsets=%r",
                        getattr(cfunc, "addr", 0) or 0,
                        branch_debug,
                        (
                            type(else_node).__name__ if else_node is not None else "None",
                            _debug_assignments_in_stmt_8616(else_node) if else_node is not None else (),
                        ),
                        tuple(sorted(evidence)),
                    )
                for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()):
                    walk_statement(child)
                else_node = getattr(stmt, "else_node", None)
                if _materialize_empty_branch_function_pointer_stores_8616(stmt):
                    changed_local = True
                if _repair_branch_immediate_function_pointer_stores_8616(stmt):
                    changed_local = True
                for offset, symbols in evidence.items():
                    symbol_by_name = {
                        name: symbol
                        for _addr, symbol in symbols
                        for name in [_symbol_name_8616(symbol)]
                        if name is not None
                    }
                    if len(symbol_by_name) < 2:
                        continue
                    branch_assignments: list[tuple[object, object | None]] = []
                    for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()):
                        for assignment in _iter_assignment_nodes(child):
                            lhs, rhs = _assignment_lhs_rhs(assignment)
                            if _stack_offset_from_cvar_8616(lhs) == offset:
                                branch_assignments.append((assignment, rhs))
                    if else_node is not None:
                        for assignment in _iter_assignment_nodes(else_node):
                            lhs, rhs = _assignment_lhs_rhs(assignment)
                            if _stack_offset_from_cvar_8616(lhs) == offset:
                                branch_assignments.append((assignment, rhs))
                    known_names = {
                        name
                        for _assignment, rhs in branch_assignments
                        for name in [_symbol_name_8616(rhs)]
                        if name in symbol_by_name
                    }
                    unknown_assignments = [
                        assignment
                        for assignment, rhs in branch_assignments
                        if _symbol_name_8616(rhs) not in symbol_by_name
                    ]
                    remaining = [
                        symbol
                        for name, symbol in symbol_by_name.items()
                        if name not in known_names
                    ]
                    if len(unknown_assignments) == 1 and len(remaining) == 1:
                        assignment = unknown_assignments[0]
                        symbol = _clone_c_ast_tree(remaining[0])
                        _set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
                        if hasattr(assignment, "rhs"):
                            assignment.rhs = symbol
                        elif hasattr(assignment, "src"):
                            assignment.src = symbol
                        codegen._inertia_fnptr_branch_symbols_materialized_8616 = (
                            int(getattr(codegen, "_inertia_fnptr_branch_symbols_materialized_8616", 0) or 0) + 1
                        )
                        changed_local = True
                for offset, symbols in evidence.items():
                    has_empty_else = else_node is None or not tuple(getattr(else_node, "statements", ()) or ())
                    if not has_empty_else:
                        continue
                    branch_names: set[str] = set()
                    for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()):
                        for assignment in _iter_assignment_nodes(child):
                            lhs, rhs = _assignment_lhs_rhs(assignment)
                            if _stack_offset_from_cvar_8616(lhs) == offset:
                                name = _symbol_name_8616(rhs)
                                if name is not None:
                                    branch_names.add(name)
                    symbol = symbol_for_immediate(offset, None, exclude_names=branch_names)
                    if symbol is None:
                        continue
                    assignment = make_assignment(offset, symbol)
                    if assignment is None:
                        continue
                    stmt.else_node = structured_c.CStatements([assignment], codegen=codegen)
                    changed_local = True
                if getattr(stmt, "else_node", None) is not None:
                    walk_statement(getattr(stmt, "else_node", None))
                return
            if materialize_assignment(stmt):
                changed_local = True
            for attr in ("statements",):
                children = getattr(stmt, attr, None)
                if isinstance(children, (list, tuple)):
                    for child in children:
                        walk_statement(child)
                    if _prune_stale_post_branch_fnptr_overwrites_8616(stmt):
                        changed_local = True
            for attr in ("body", "else_node"):
                child = getattr(stmt, attr, None)
                if child is not None:
                    walk_statement(child)

        walk_statement(root)
        return changed_local

    def _materialize_final_return_call_8616(statements: list) -> bool:
        if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"):
            log.warning(
                "[return-call-list] %r",
                [
                    (
                        idx,
                        stmt.__class__.__name__,
                        getattr(getattr(stmt, "expr", None), "__class__", type(None)).__name__,
                        getattr(getattr(stmt, "retval", None), "__class__", type(None)).__name__,
                    )
                    for idx, stmt in enumerate(statements[-8:])
                ],
            )
        if len(statements) < 2:
            return False

        def standalone_call_from_statement(stmt):
            if isinstance(stmt, CFunctionCall):
                return stmt
            expr = getattr(stmt, "expr", None)
            if isinstance(expr, CFunctionCall):
                return expr
            nested = getattr(stmt, "statements", None)
            if isinstance(nested, (list, tuple)) and len(nested) == 1:
                return standalone_call_from_statement(nested[0])
            return None

        def final_standalone_call_ref(stmt):
            call = standalone_call_from_statement(stmt)
            if call is not None:
                return call, None, None
            nested = getattr(stmt, "statements", None)
            if not isinstance(nested, list) or not nested:
                return None, None, None
            call = standalone_call_from_statement(nested[-1])
            if call is None:
                return None, None, None
            return call, nested, len(nested) - 1

        def single_nested_statement(stmt):
            nested = getattr(stmt, "statements", None)
            if isinstance(nested, (list, tuple)) and len(nested) == 1:
                return nested[0]
            return stmt

        ret_idx = None
        ret_stmt = None
        for idx in range(len(statements) - 1, -1, -1):
            candidate = single_nested_statement(statements[idx])
            if isinstance(candidate, structured_c.CReturn):
                ret_idx = idx
                ret_stmt = candidate
                break
        if ret_idx is None or ret_idx <= 0:
            return False
        call_idx = ret_idx - 1
        while call_idx >= 0 and not _statement_contains_call(statements[call_idx]):
            class_name = statements[call_idx].__class__.__name__
            if class_name not in {"CStatements"}:
                return False
            call_idx -= 1
        if call_idx < 0:
            return False
        call_stmt = statements[call_idx]
        ret_stmt = single_nested_statement(statements[ret_idx])
        if not isinstance(ret_stmt, structured_c.CReturn):
            return False
        call, nested_call_statements, nested_call_idx = final_standalone_call_ref(call_stmt)
        if call is None:
            return False
        summary = summary_map.get(id(call))
        if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"):
            log.warning(
                "[return-call] call=%r summary_return=%r used=%r ret=%r",
                _call_node_name_8616(call),
                getattr(summary, "return_register", None) if summary is not None else None,
                getattr(summary, "return_used", None) if summary is not None else None,
                getattr(getattr(ret_stmt, "retval", None), "value", None),
            )
        if getattr(summary, "return_register", None) != "ax":
            return False
        if getattr(summary, "return_used", None) is not True:
            return False
        push_arg_sources = getattr(summary, "push_arg_sources", ())
        summary_arg_count = getattr(summary, "arg_count", None)
        if (
            isinstance(summary_arg_count, int)
            and summary_arg_count > 0
            and isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == summary_arg_count
            and len(tuple(getattr(call, "args", ()) or ())) != summary_arg_count
        ):
            ordered_push_sources = (
                list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
            )
            direct_args = []
            direct_bindings = {}
            for idx, source in enumerate(ordered_push_sources):
                arg = _direct_expr_from_push_source_8616(
                    source,
                    call_name=_call_node_name_8616(call),
                    arg_index=idx,
                )
                if arg is None:
                    direct_args = []
                    break
                direct_args.append(arg)
                if (
                    isinstance(source, tuple)
                    and len(source) >= 2
                    and source[0] == "bp"
                    and isinstance(source[1], int)
                ):
                    direct_bindings[int(source[1])] = _clone_c_ast_tree(arg)
            if len(direct_args) == summary_arg_count:
                normalized_args = _normalize_materialized_call_args(
                    direct_args,
                    [-1] * len(direct_args),
                    statements,
                    call_name=_call_node_name_8616(call),
                    stack_bindings=direct_bindings or None,
                )
                if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                    _set_materialized_call_args(
                        call,
                        normalized_args,
                        call_name=_call_node_name_8616(call),
                        force_replace=True,
                    )
                    record_stack_arg_materialization_8616(codegen, len(normalized_args))
                    _refresh_summary_arg_shape(call, summary)
        retval = getattr(ret_stmt, "retval", None)
        if retval is not None and not isinstance(retval, structured_c.CConstant):
            return False
        ret_stmt.retval = _clone_c_ast_tree(call)
        if nested_call_statements is not None and nested_call_idx is not None:
            del nested_call_statements[nested_call_idx]
            if not nested_call_statements:
                del statements[call_idx]
        else:
            del statements[call_idx]
        return True

    def _segment_register_expr(seg_name: str):
        register = getattr(getattr(project, "arch", None), "registers", {}).get(seg_name.lower())
        if not isinstance(register, tuple) or not register:
            return None
        return structured_c.CVariable(
            SimRegisterVariable(register[0], 2, name=seg_name.lower()),
            variable_type=_word_type_8616(project),
            codegen=codegen,
        )

    def _plain_stack_slot_address_offset(node) -> int | None:
        term_root = node
        while isinstance(term_root, CTypeCast):
            term_root = term_root.expr

        def resolve_stack_offset(expr) -> int | None:
            while isinstance(expr, CTypeCast):
                expr = expr.expr
            if isinstance(expr, structured_c.CVariable):
                variable = getattr(expr, "variable", None)
                offset = getattr(variable, "offset", None)
                if isinstance(variable, SimStackVariable) and isinstance(offset, int):
                    return offset
                return None
            if isinstance(expr, structured_c.CIndexedVariable):
                base_expr = getattr(expr, "variable", None)
                index_expr = getattr(expr, "index", None)
                while isinstance(base_expr, CTypeCast):
                    base_expr = base_expr.expr
                if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
                    base_expr = base_expr.operand
                base_offset = resolve_stack_offset(base_expr)
                index_value = getattr(index_expr, "value", None)
                if isinstance(base_offset, int) and isinstance(index_value, int):
                    if index_value % 2 == 0 and abs(index_value) >= 2:
                        return base_offset + index_value // 2
                    return base_offset + index_value
            return None

        def flatten(term, sign: int = 1):
            while isinstance(term, CTypeCast):
                term = term.expr
            if isinstance(term, CBinaryOp) and term.op == "Add":
                return flatten(term.lhs, sign) + flatten(term.rhs, sign)
            if isinstance(term, CBinaryOp) and term.op == "Sub":
                return flatten(term.lhs, sign) + flatten(term.rhs, -sign)
            return [(term, sign)]

        const_total = 0
        stack_offsets: list[int] = []
        for term, sign in flatten(term_root):
            value = getattr(term, "value", None) if isinstance(term, structured_c.CConstant) else None
            if isinstance(value, int):
                const_total += sign * value
                continue
            if isinstance(term, CUnaryOp) and term.op == "Reference":
                inner = term.operand
                offset = resolve_stack_offset(inner)
                if isinstance(offset, int):
                    stack_offsets.append(sign * offset)
                    continue
            offset = resolve_stack_offset(term)
            if isinstance(offset, int):
                stack_offsets.append(sign * offset)
                continue
            return None
        if len(stack_offsets) != 1:
            return None
        return stack_offsets[0] + const_total

    def _plain_bp_stack_load_offset(node) -> int | None:
        node = _clone_c_ast_tree(node)
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CUnaryOp) or node.op != "Dereference":
            return None
        return _plain_stack_slot_address_offset(node.operand)

    def _normalize_bp_slot_value_arg_8616(
        expr, *, stack_bindings=None, pointer_arg: bool = False
    ) -> tuple[object, int]:
        replacements = 0
        debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))

        def transform(node):
            nonlocal replacements
            displacement = _match_bp_stack_load_8616(node, project)
            if displacement is None:
                displacement = _plain_bp_stack_load_offset(node)
            if displacement is None:
                plain_slot_offset = _plain_stack_slot_address_offset(node)
                if isinstance(plain_slot_offset, int) and (
                    not pointer_arg
                    or _node_contains_placeholder_stack_8616(node)
                    or _node_contains_stable_named_stack_value_8616(node)
                ):
                    displacement = plain_slot_offset
            if displacement is None:
                return node
            replacement = None
            if isinstance(stack_bindings, dict):
                replacement = stack_bindings.get(displacement)
            if replacement is None:
                replacement = _stack_cvar_for_offset(displacement)
            if replacement is None:
                return node
            replacements += 1
            if debug_materialization:
                log.warning(
                    "[call-bp-normalize] function=%#x displacement=%r pointer_arg=%s node=%r replacement=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    displacement,
                    pointer_arg,
                    node,
                    replacement,
                )
            return _clone_c_ast_tree(replacement)

        rewritten = _clone_c_ast_tree(expr)
        for _ in range(3):
            changed = False
            new_root = transform(rewritten)
            if new_root is not rewritten:
                rewritten = new_root
                changed = True
            if _replace_c_children_8616(rewritten, transform):
                changed = True
            if not changed:
                break
        return rewritten, replacements

    def _materialize_pointer_arg_8616(expr, *, target_name: str, arg_index: int):
        if not _callee_expects_pointer_arg_8616(target_name, arg_index):
            return expr, False
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall) and getattr(node, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
            return expr, False
        ds_expr = _segment_register_expr("ds")
        if ds_expr is None:
            return None, False
        target = str(
            getattr(getattr(codegen, "project", None), "_inertia_c_target", "portable-flat") or "portable-flat"
        )
        helper = "SEG_PTR" if target == "portable-flat" else "MK_FP"
        return (
            structured_c.CFunctionCall(
                helper,
                None,
                [ds_expr, _clone_c_ast_tree(expr)],
                codegen=codegen,
            ),
            True,
        )

    def _direct_expr_from_push_source_8616(source, *, call_name: str | None, arg_index: int):
        if not isinstance(source, tuple) or len(source) < 2:
            return None
        source_kind, source_value = source[0], source[1]
        if source_kind == "bp" and isinstance(source_value, int):
            return _stack_cvar_for_offset(source_value, allow_best_match=False)
        if source_kind == "imm" and isinstance(source_value, int):
            return structured_c.CConstant(source_value, SimTypeShort(False), codegen=codegen)
        if source_kind == "expr" and len(source) == 3 and isinstance(source_value, tuple):
            expr = _direct_expr_from_push_source_8616(source_value, call_name=call_name, arg_index=arg_index)
            if expr is None:
                return None
            for op_name, op_value in source[2]:
                if not isinstance(op_name, str) or not isinstance(op_value, int):
                    return None
                if op_name not in {"add", "sub", "shl", "shr"}:
                    return None
                c_op = {"add": "Add", "sub": "Sub", "shl": "Shl", "shr": "Shr"}[op_name]
                lhs_expr = expr
                if c_op == "Shr":
                    lhs_node = lhs_expr
                    while isinstance(lhs_node, CTypeCast):
                        lhs_node = lhs_node.expr
                    if isinstance(lhs_node, CUnaryOp) and getattr(lhs_node, "op", None) in {"Reference", "AddressOf"}:
                        # High-byte projection of address-like carrier must be an explicit
                        # integer operation for strict 16-bit C compilers.
                        lhs_expr = CTypeCast(None, SimTypeShort(False), lhs_expr, codegen=codegen)
                expr = CBinaryOp(
                    c_op,
                    lhs_expr,
                    structured_c.CConstant(op_value, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            return expr
        return None

    def _node_contains_stable_named_stack_value_8616(node) -> bool:
        stack = [node]
        while stack:
            current = stack.pop()
            while isinstance(current, CTypeCast):
                current = current.expr
            if _is_stable_named_stack_value_expr_8616(current):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(current, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(current, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _node_contains_placeholder_stack_8616(node) -> bool:
        stack = [node]
        while stack:
            current = stack.pop()
            while isinstance(current, CTypeCast):
                current = current.expr
            if isinstance(current, structured_c.CFakeVariable) and getattr(current, "name", None) == "stack_base":
                return True
            if isinstance(current, structured_c.CVariable):
                variable = getattr(current, "variable", None)
                name = getattr(variable, "name", None) or getattr(current, "name", None)
                if name == "stack_base":
                    return True
                if (
                    isinstance(variable, SimStackVariable)
                    and isinstance(name, str)
                    and name.startswith(("arg_", "s_", "stack_", "vvar_", "tmp_", "ir_"))
                ):
                    return True
            if _is_virtual_dirty_expr_8616(current):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(current, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(current, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _debug_expr_8616(node):
        if isinstance(node, CTypeCast):
            return f"Cast({_debug_expr_8616(node.expr)})"
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            name = getattr(variable, "name", None) or getattr(node, "name", None) or "var"
            offset = getattr(variable, "offset", None)
            if isinstance(variable, SimStackVariable) and isinstance(offset, int):
                return f"{name}@{offset}"
            reg = getattr(variable, "reg", None)
            if isinstance(variable, SimRegisterVariable) and reg is not None:
                return f"{name}#{reg}"
            return name
        if isinstance(node, structured_c.CIndexedVariable):
            return f"Index({_debug_expr_8616(node.variable)},{_debug_expr_8616(node.index)})"
        if isinstance(node, structured_c.CConstant):
            return repr(getattr(node, "value", None))
        if isinstance(node, CUnaryOp):
            return f"{node.op}({_debug_expr_8616(node.operand)})"
        if isinstance(node, CBinaryOp):
            return f"{node.op}({_debug_expr_8616(node.lhs)},{_debug_expr_8616(node.rhs)})"
        if isinstance(node, CFunctionCall):
            name = (
                getattr(node, "callee_target", None)
                or getattr(getattr(node, "callee_func", None), "name", None)
                or "call"
            )
            return f"{name}({','.join(_debug_expr_8616(arg) for arg in (getattr(node, 'args', ()) or ()))})"
        return node.__class__.__name__

    def _call_arg_semantic_key_8616(node):
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CConstant):
            value = getattr(node, "value", None)
            return ("const", int(value)) if isinstance(value, int) else None
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable):
                offset = getattr(variable, "offset", None)
                return ("stack", int(offset)) if isinstance(offset, int) else None
            if isinstance(variable, SimRegisterVariable):
                reg = getattr(variable, "reg", None)
                size = getattr(variable, "size", None)
                return ("reg", int(reg), int(size or 0)) if isinstance(reg, int) else None
            name = getattr(variable, "name", None) or getattr(node, "name", None)
            return ("var", str(name)) if isinstance(name, str) and name else None
        if isinstance(node, CUnaryOp):
            operand_key = _call_arg_semantic_key_8616(node.operand)
            return ("unary", node.op, operand_key) if operand_key is not None else None
        if isinstance(node, CBinaryOp):
            lhs_key = _call_arg_semantic_key_8616(node.lhs)
            rhs_key = _call_arg_semantic_key_8616(node.rhs)
            if lhs_key is None or rhs_key is None:
                return None
            return ("binary", node.op, lhs_key, rhs_key)
        if isinstance(node, CFunctionCall):
            arg_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in getattr(node, "args", ()) or ())
            if any(key is None for key in arg_keys):
                return None
            return ("call", getattr(node, "callee_target", None), arg_keys)
        return None

    def _arg_semantic_quality_8616(arg_name: str | None, arg_index: int, node) -> int:
        kind = _call_arg_semantic_kind_8616(arg_name or "", arg_index)
        raw = node
        while isinstance(raw, CTypeCast):
            raw = raw.expr
        if kind is CallArgSemanticKind8616.POINTER:
            if _node_contains_placeholder_stack_8616(raw) or _expr_contains_plain_register_uses(raw):
                return 0
            if isinstance(raw, CFunctionCall) and getattr(raw, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
                return 8
            if isinstance(raw, CUnaryOp) and raw.op == "Reference":
                return 7
            return 2
        if kind is CallArgSemanticKind8616.VALUE:
            if _node_contains_placeholder_stack_8616(raw):
                return 0
            if _node_contains_stable_named_stack_value_8616(raw):
                return 8
            if isinstance(raw, structured_c.CConstant):
                return 4
            if isinstance(raw, CFunctionCall) and getattr(raw, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
                return 0
            return 3
        if _is_stable_named_stack_value_expr_8616(raw):
            return 6
        if isinstance(raw, structured_c.CConstant):
            return 4
        if isinstance(raw, CFunctionCall):
            return 4
        if _node_contains_placeholder_stack_8616(raw):
            return 0
        return 2

    def _normalize_materialized_call_args(
        rhs_values: list,
        source_indices: list[int],
        statements: list,
        *,
        call_name: str | None = None,
        stack_bindings: dict[int, object] | None = None,
    ):
        if not rhs_values:
            return None
        debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))
        normalized = []

        def _expr_int_constants(node) -> set[int]:
            values: set[int] = set()
            for current in (node, *_iter_c_nodes_deep_8616(node)):
                if isinstance(current, structured_c.CConstant):
                    value = getattr(current, "value", None)
                    if isinstance(value, int):
                        values.add(value)
            return values

        def _recent_dirty_value_rhs(expr, prefix: list):
            expr_node = expr
            while isinstance(expr_node, CTypeCast):
                expr_node = expr_node.expr
            expr_op = getattr(expr_node, "op", None) if isinstance(expr_node, CBinaryOp) else None
            expr_consts = _expr_int_constants(expr_node)
            matches: list[tuple[tuple[int, int], object]] = []
            seen_assignments: set[int] = set()
            for stmt_idx in range(len(prefix) - 1, -1, -1):
                stmt = prefix[stmt_idx]
                for assignment in reversed(_iter_assignment_nodes(stmt)):
                    assignment_id = id(assignment)
                    if assignment_id in seen_assignments:
                        continue
                    seen_assignments.add(assignment_id)
                    lhs, rhs_stmt = _assignment_lhs_rhs(assignment)
                    if lhs is None or rhs_stmt is None or _assignment_lhs_writes_memory(lhs):
                        continue
                    if lhs.__class__.__name__ != "CDirtyExpression":
                        continue
                    if _is_segment_register_value_expr(rhs_stmt) or _expr_contains_plain_register_uses(rhs_stmt):
                        continue
                    rhs_node = rhs_stmt
                    while isinstance(rhs_node, CTypeCast):
                        rhs_node = rhs_node.expr
                    rhs_op = getattr(rhs_node, "op", None) if isinstance(rhs_node, CBinaryOp) else None
                    if expr_op is not None and rhs_op != expr_op:
                        continue
                    rhs_consts = _expr_int_constants(rhs_node)
                    if expr_consts and rhs_consts and expr_consts.isdisjoint(rhs_consts):
                        continue
                    score = (
                        1 if _node_contains_stable_named_stack_value_8616(rhs_node) else 0,
                        0 if _node_contains_placeholder_stack_8616(rhs_node) else 1,
                        stmt_idx,
                    )
                    matches.append((score, rhs_stmt))
            if not matches:
                return None
            matches.sort(key=lambda item: item[0], reverse=True)
            if len(matches) > 1 and matches[0][0] == matches[1][0]:
                return None
            return matches[0][1]

        if len(source_indices) != len(rhs_values):
            source_indices = [-1] * len(rhs_values)
        for rhs, source_idx in zip(rhs_values, source_indices):
            if _is_segment_register_value_expr(rhs):
                return None
            if not _expr_contains_plain_register_uses(rhs):
                normalized.append(_clone_c_ast_tree(rhs))
                continue
            prefix = statements[: source_idx + 1] if isinstance(source_idx, int) and source_idx >= 0 else statements
            resolved = _resolve_register_carriers_in_expr(rhs, prefix)
            if debug_materialization:
                log.warning(
                    "[call-normalize] function=%#x target=%s rhs=%s resolved=%s source_idx=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    _debug_expr_8616(rhs),
                    _debug_expr_8616(resolved) if resolved is not None else None,
                    source_idx,
                )
            if resolved is None:
                dirty_rhs = _recent_dirty_value_rhs(rhs, prefix)
                if dirty_rhs is not None:
                    if debug_materialization:
                        log.warning(
                            "[call-normalize-dirty-fallback] function=%#x target=%s rhs=%s fallback=%s source_idx=%r",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            call_name,
                            _debug_expr_8616(rhs),
                            _debug_expr_8616(dirty_rhs),
                            source_idx,
                            )
                    resolved = dirty_rhs
            if resolved is None:
                # Byte-split push carriers often materialize as `Shr(word_expr, 8)`.
                # For call-arg recovery we want the underlying 16-bit word value;
                # if that can be resolved, use it instead of failing the whole arg list.
                rhs_node = rhs
                while isinstance(rhs_node, CTypeCast):
                    rhs_node = rhs_node.expr
                if isinstance(rhs_node, CBinaryOp) and rhs_node.op == "Shr":
                    shift_const = getattr(rhs_node.rhs, "value", None)
                    if isinstance(shift_const, int) and shift_const == 8:
                        lhs_resolved = _resolve_register_carriers_in_expr(rhs_node.lhs, prefix)
                        if lhs_resolved is None:
                            lhs_resolved = _recent_dirty_value_rhs(rhs_node.lhs, prefix)
                        if lhs_resolved is not None:
                            resolved = lhs_resolved
                elif debug_materialization:
                    window_start = max(0, len(prefix) - 6)
                    for stmt_idx, stmt in enumerate(prefix[window_start:], start=window_start):
                        for assignment in _iter_assignment_nodes(stmt):
                            lhs, rhs_stmt = _assignment_lhs_rhs(assignment)
                            if lhs is None or rhs_stmt is None:
                                continue
                            log.warning(
                                "[call-normalize-prefix] function=%#x target=%s stmt_idx=%d lhs=%s rhs=%s memory_lhs=%s",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                call_name,
                                stmt_idx,
                                _debug_expr_8616(lhs),
                                _debug_expr_8616(rhs_stmt),
                                _assignment_lhs_writes_memory(lhs),
                            )
            raw_expr = _clone_c_ast_tree(rhs)
            raw_node = raw_expr
            while isinstance(raw_node, CTypeCast):
                raw_node = raw_node.expr
            if resolved is None and not (
                isinstance(raw_node, CFunctionCall) and getattr(raw_node, "callee_target", None) in {"SEG_PTR", "MK_FP"}
            ):
                return None
            expr = _clone_c_ast_tree(resolved) if resolved is not None else raw_expr
            if isinstance(expr, CFunctionCall) and getattr(expr, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
                helper_args = list(getattr(expr, "args", ()) or ())
                if len(helper_args) >= 2:
                    helper_offset = helper_args[1]
                    if _expr_contains_plain_register_uses(helper_offset):
                        resolved_offset = _resolve_register_carriers_in_expr(helper_offset, prefix)
                        if debug_materialization:
                            log.warning(
                                "[call-helper-offset-normalize] function=%#x target=%s offset=%s resolved=%s source_idx=%r",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                call_name,
                                _debug_expr_8616(helper_offset),
                                _debug_expr_8616(resolved_offset) if resolved_offset is not None else None,
                                source_idx,
                            )
                        if resolved_offset is None:
                            dirty_offset = _recent_dirty_value_rhs(helper_offset, prefix)
                            if dirty_offset is not None:
                                resolved_offset = dirty_offset
                        if resolved_offset is not None:
                            helper_offset = _clone_c_ast_tree(resolved_offset)
                    rewritten_offset, replacement_count = _normalize_bp_slot_value_arg_8616(
                        helper_offset,
                        stack_bindings=stack_bindings,
                        pointer_arg=True,
                    )
                    if replacement_count:
                        stats.bp_slot_arg_value_normalized_count += replacement_count
                    helper_args[1] = rewritten_offset
                    expr.args = helper_args
            if _is_segment_register_value_expr(expr) or _expr_contains_plain_register_uses(expr):
                return None
            normalized.append(expr)
        for idx, expr in enumerate(tuple(normalized)):
            source_idx = source_indices[idx] if idx < len(source_indices) else -1
            prefix = statements[: source_idx + 1] if isinstance(source_idx, int) and source_idx >= 0 else statements
            pointer_arg = _callee_expects_pointer_arg_8616(call_name or "", idx)
            rewritten, replacement_count = _normalize_bp_slot_value_arg_8616(
                expr,
                stack_bindings=stack_bindings,
                pointer_arg=pointer_arg,
            )
            if replacement_count:
                stats.bp_slot_arg_value_normalized_count += replacement_count
                if _expr_contains_plain_register_uses(rewritten):
                    resolved_rewritten = _resolve_register_carriers_in_expr(rewritten, prefix)
                    if debug_materialization:
                        log.warning(
                            "[call-post-bp-resolve] function=%#x target=%s rewritten=%s resolved=%s source_idx=%r",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            call_name,
                            _debug_expr_8616(rewritten),
                            _debug_expr_8616(resolved_rewritten) if resolved_rewritten is not None else None,
                            source_idx,
                        )
                    if resolved_rewritten is not None:
                        rewritten = _clone_c_ast_tree(resolved_rewritten)
            pointer_expr, pointer_materialized = _materialize_pointer_arg_8616(
                rewritten,
                target_name=call_name or "",
                arg_index=idx,
            )
            if pointer_expr is None:
                return None
            if pointer_materialized:
                stats.pointer_arg_materialized_count += 1
            normalized[idx] = pointer_expr
        return normalized

    def _normalize_existing_call_args_8616(call, statements: list, *, call_name: str | None) -> bool:
        args = tuple(getattr(call, "args", ()) or ())
        if not args:
            return False
        normalized_args = _normalize_materialized_call_args(
            list(args),
            [-1] * len(args),
            statements,
            call_name=call_name,
        )
        if normalized_args is None:
            return False
        if tuple(normalized_args) == args:
            return False
        _set_materialized_call_args(call, normalized_args, call_name=call_name)
        return True

    def _set_materialized_call_args(call, args, *, call_name: str | None, force_replace: bool = False):
        def _protected_call_arg_state():
            protected = getattr(codegen, "_inertia_protected_call_args_8616", None)
            if not isinstance(protected, dict):
                protected = {}
                codegen._inertia_protected_call_args_8616 = protected
            return protected

        args_before = tuple(getattr(call, "args", ()) or ())
        args_after = tuple(args)
        if args_before and not force_replace:
            before_score = sum(_arg_semantic_quality_8616(call_name, idx, arg) for idx, arg in enumerate(args_before))
            after_score = sum(_arg_semantic_quality_8616(call_name, idx, arg) for idx, arg in enumerate(args_after))
            if after_score < before_score:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-materialized-skip] function=%#x target=%s before_score=%d after_score=%d args_before=%s args_after=%s",
                        getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        before_score,
                        after_score,
                        tuple(_debug_expr_8616(arg) for arg in args_before),
                        tuple(_debug_expr_8616(arg) for arg in args_after),
                    )
                return
        if not args_before and len(args_after) > 1:
            stats.push_order_reversed_count += 1
        call.args = list(args_after)
        protected = _protected_call_arg_state()
        for idx, arg in enumerate(args_after):
            key = (id(call), idx)
            score = _arg_semantic_quality_8616(call_name, idx, arg)
            current = protected.get(key)
            if not isinstance(current, tuple) or len(current) != 2 or score >= int(current[1]):
                protected[key] = (_clone_c_ast_tree(arg), score)
        log.debug(
            "callarg-normalized function=%#x target=%s args_before=%s args_after=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
            call_name,
            tuple(_debug_expr_8616(arg) for arg in args_before),
            tuple(_debug_expr_8616(arg) for arg in args_after),
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-materialized] function=%#x target=%s args_before=%s args_after=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                tuple(_debug_expr_8616(arg) for arg in args_before),
                tuple(_debug_expr_8616(arg) for arg in args_after),
            )

    def _prototype_arg_count(call) -> int | None:
        callee_func = getattr(call, "callee_func", None)
        prototype = getattr(callee_func, "prototype", None)
        args = getattr(prototype, "args", None)
        if isinstance(args, (list, tuple)):
            return len(args)
        return None

    def _is_stable_named_stack_value_expr_8616(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return False
        offset = getattr(variable, "offset", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if not isinstance(offset, int) or not isinstance(name, str) or not name:
            return False
        if name.startswith(("arg_", "s_", "stack_", "vvar_", "tmp_", "ir_")):
            return False
        return True

    def _call_args_need_rematerialization_8616(call, push_arg_sources=()) -> bool:
        args = tuple(getattr(call, "args", ()) or ())
        if not args:
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-remat] function=%#x target=%s reason=no-args",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    getattr(call, "callee_target", None),
                )
            return True
        if (
            isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == len(args)
            and all(
                isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int)
                for source in push_arg_sources
            )
        ):
            expected_offsets = [
                int(source[1])
                for source in (reversed(push_arg_sources) if len(push_arg_sources) > 1 else push_arg_sources)
            ]
            actual_offsets: list[int | None] = []
            for arg in args:
                node = arg
                while isinstance(node, CTypeCast):
                    node = node.expr
                actual_offsets.append(_plain_stack_slot_address_offset(node))
            if all(isinstance(offset, int) for offset in actual_offsets):
                normalized_actual = [int(offset) for offset in actual_offsets]
                if normalized_actual != expected_offsets:
                    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                        log.warning(
                            "[call-remat] function=%#x target=%s reason=push-source-mismatch actual=%s expected=%s",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            getattr(call, "callee_target", None),
                            tuple(normalized_actual),
                            tuple(expected_offsets),
                        )
                    return True
        if (
            isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == len(args)
            and any(source is not None for source in push_arg_sources)
        ):
            ordered_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
            expected_args = [
                _direct_expr_from_push_source_8616(
                    source, call_name=getattr(call, "callee_target", None), arg_index=idx
                )
                for idx, source in enumerate(ordered_sources)
            ]
            if all(expected is not None for expected in expected_args):
                expected_keys = tuple(_call_arg_semantic_key_8616(expected) for expected in expected_args)
                actual_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in args)
                if all(key is not None for key in expected_keys) and all(key is not None for key in actual_keys):
                    if actual_keys != expected_keys:
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            log.warning(
                                "[call-remat] function=%#x target=%s reason=derived-push-source-mismatch actual=%s expected=%s",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                getattr(call, "callee_target", None),
                                actual_keys,
                                expected_keys,
                            )
                        return True
        for arg in args:
            node = arg
            while isinstance(node, CTypeCast):
                node = node.expr
            if _node_contains_placeholder_stack_8616(node):
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=stack-placeholder-expression",
                        getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                    )
                return True
            if _is_stable_named_stack_value_expr_8616(node):
                continue
            if _plain_bp_stack_load_offset(node) is not None:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=bp-load",
                        getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                    )
                return True
            if _plain_stack_slot_address_offset(node) is not None:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=stack-slot-address",
                        getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                    )
                return True
            if isinstance(node, structured_c.CVariable):
                variable = getattr(node, "variable", None)
                name = getattr(variable, "name", None) or getattr(node, "name", None)
                if isinstance(variable, SimStackVariable):
                    if isinstance(name, str) and (
                        name.startswith("arg_") or name.startswith("stack_") or name.startswith("s_")
                    ):
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            log.warning(
                                "[call-remat] function=%#x target=%s reason=stack-placeholder name=%s offset=%r",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                getattr(call, "callee_target", None),
                                name,
                                getattr(variable, "offset", None),
                            )
                        return True
                    offset = getattr(variable, "offset", None)
                    if isinstance(offset, int) and offset <= 2:
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            log.warning(
                                "[call-remat] function=%#x target=%s reason=small-stack-offset offset=%r",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                getattr(call, "callee_target", None),
                                offset,
                            )
                        return True
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-remat] function=%#x target=%s reason=keep-existing args=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                getattr(call, "callee_target", None),
                tuple(
                    getattr(getattr(arg, "variable", None), "name", None)
                    or getattr(arg, "name", None)
                    or arg.__class__.__name__
                    for arg in args
                ),
            )
        return False

    def _refresh_summary_arg_shape(call, summary) -> None:
        nonlocal changed
        if summary is None:
            return
        args = tuple(getattr(call, "args", ()) or ())
        arg_widths_live = tuple(_arg_width_from_expr(arg) for arg in args)
        existing_count = getattr(summary, "arg_count", None)
        existing_widths = tuple(getattr(summary, "arg_widths", ()) or ())
        floor_count = existing_count if isinstance(existing_count, int) and existing_count >= 0 else 0
        next_count = max(len(arg_widths_live), floor_count)
        if len(arg_widths_live) < next_count:
            padded = list(arg_widths_live)
            while len(padded) < next_count:
                if len(existing_widths) > len(padded) and isinstance(existing_widths[len(padded)], int):
                    padded.append(int(existing_widths[len(padded)]))
                else:
                    padded.append(2)
            arg_widths = tuple(padded)
        else:
            arg_widths = arg_widths_live
        updated = replace(summary, arg_count=next_count, arg_widths=arg_widths)
        if summary_map.get(id(call)) != updated:
            summary_map[id(call)] = updated
            changed = True

    def _record_prunable_segment_metadata_ids(call, statements: list, consumed_indices: list[int]) -> None:
        if call is None or not consumed_indices:
            return
        tail_ids: list[int] = []
        scan = max(consumed_indices) + 1
        while scan < len(statements):
            stmt = statements[scan]
            if _is_segment_register_metadata_store(stmt):
                tail_ids.append(id(stmt))
                scan += 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                scan += 1
                continue
            break
        if tail_ids:
            materialized_callsite_metadata_ids[id(call)] = tuple(tail_ids)

    def _delete_consumed_indices_8616(statements: list, indices: list[int]) -> None:
        if not isinstance(statements, list) or not indices:
            return
        clean_indices = sorted(
            {
                int(idx)
                for idx in indices
                if isinstance(idx, int) and 0 <= int(idx) < len(statements)
            },
            reverse=True,
        )
        for idx in clean_indices:
            del statements[idx]

    def _call_from_statement(stmt):
        if isinstance(stmt, CFunctionCall):
            return stmt
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return expr
        rhs = getattr(stmt, "rhs", None)
        if isinstance(rhs, CFunctionCall):
            return rhs
        src = getattr(stmt, "src", None)
        if isinstance(src, CFunctionCall):
            return src
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
            return _call_from_statement(nested_statements[0])
        return None

    def _statement_contains_call(stmt) -> bool:
        if isinstance(stmt, CFunctionCall):
            return True
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return True
        for node in _iter_c_nodes_deep_8616(stmt):
            if isinstance(node, CFunctionCall):
                return True
        return False

    def _is_standalone_call_statement_8616(stmt, call) -> bool:
        if call is None:
            return False
        if stmt is call:
            return True
        return getattr(stmt, "expr", None) is call

    def _stack_probe_helper_statement_is_consumable_8616(stmt, call, summary) -> bool:
        if not _is_standalone_call_statement_8616(stmt, call):
            return False
        if tuple(getattr(call, "args", ()) or ()):
            return False
        call_name = _call_node_name_8616(call)
        if summary is not None and bool(getattr(summary, "stack_probe_helper", False)):
            return (
                int(getattr(summary, "arg_count", 0) or 0) == 0
                and getattr(summary, "stack_cleanup", None) is None
            )
        return _is_stack_probe_call_name_8616(call_name)

    def _assignment_lhs_rhs(node):
        lhs = getattr(node, "lhs", None)
        rhs = getattr(node, "rhs", None)
        if lhs is None and hasattr(node, "dst"):
            lhs = getattr(node, "dst", None)
            rhs = getattr(node, "src", None)
        return lhs, rhs

    def _is_assignment_node(node) -> bool:
        class_name = node.__class__.__name__
        if class_name == "CAssignment" or class_name.endswith("Assignment"):
            return True
        return hasattr(node, "dst") and hasattr(node, "src")

    def _iter_assignment_nodes(stmt):
        candidates = []
        if _is_assignment_node(stmt):
            candidates.append(stmt)
        for node in _iter_c_nodes_deep_8616(stmt):
            if _is_assignment_node(node):
                candidates.append(node)
        return candidates

    def _stack_store_rhs_from_statement(stmt):
        nonlocal project
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            for nested in reversed(tuple(nested_statements)):
                rhs = _stack_store_rhs_from_statement(nested)
                if rhs is not None:
                    return rhs
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            return None

        project = getattr(codegen, "project", None)

        def _contains_ss_evidence(term) -> bool:
            if term is None:
                return False
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                node = raw_node
                while isinstance(node, CTypeCast):
                    node = node.expr
                variable = getattr(node, "variable", None)
                register_name = getattr(variable, "name", None)
                if isinstance(register_name, str) and register_name.lower() == "ss":
                    return True
                seg_name, _linear = _match_real_mode_linear_expr_8616(node, project)
                if seg_name == "ss":
                    return True
                segment_selector = getattr(node, "segment_selector", None)
                if isinstance(segment_selector, str) and segment_selector.lower() == "ss":
                    return True
            return False

        def _contains_ss_dereference(term) -> bool:
            if term is None:
                return False
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                node = raw_node
                while isinstance(node, CTypeCast):
                    node = node.expr
                if (
                    isinstance(node, CUnaryOp)
                    and node.op == "Dereference"
                    and _contains_ss_evidence(getattr(node, "operand", None))
                ):
                    return True
            return False

        def _contains_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ == "CDirtyExpression":
                    return True
            return False

        def _contains_unresolved_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ != "CDirtyExpression":
                    continue
                if _is_virtual_dirty_expr_8616(raw_node):
                    continue
                return True
            return False

        def _is_segment_runtime_store_lvalue(term) -> bool:
            node = term
            while isinstance(node, CTypeCast):
                node = node.expr
            if not isinstance(node, CFunctionCall):
                return False
            call_name = _call_node_name_8616(node)
            return isinstance(call_name, str) and call_name.upper() in {"SEG_U8", "SEG_U16", "SEG_U32"}

        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if lhs is None:
                continue
            if _contains_unresolved_dirty_expr(lhs):
                continue
            if _is_segment_runtime_store_lvalue(lhs):
                return rhs
            seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
            if seg_name == "ss":
                return rhs
            if _match_bp_stack_dereference_8616(lhs, project, codegen) is not None:
                return rhs
            seg_name, _linear = _match_segmented_dereference_8616(lhs, project)
            if seg_name == "ss":
                return rhs
            deref = lhs
            while isinstance(deref, CTypeCast):
                deref = deref.expr
            if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
                if _contains_ss_dereference(lhs):
                    return rhs
                continue
            if isinstance(_stack_offset_from_expr_8616(getattr(deref, "operand", None), project, codegen), int):
                return rhs
            if _contains_ss_evidence(getattr(deref, "operand", None)):
                return rhs
        return None

    def _store_matches_typed_stack_probe_fact(lhs, fact: TypedStackProbeReturnFact8616 | None) -> bool:
        if lhs is None or fact is None:
            return False

        def _contains_unsafe_dirty_term(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ == "CDirtyExpression":
                    if _is_virtual_dirty_expr_8616(raw_node):
                        continue
                    return True
            return False

        seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if any(_contains_unsafe_dirty_term(term) for _sign, term in _offset_terms):
            return False
        if seg_name == fact.segment_space:
            return True

        deref = lhs
        while isinstance(deref, CTypeCast):
            deref = deref.expr
        if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
            return False
        stack_offset = _stack_offset_from_expr_8616(getattr(deref, "operand", None), project, codegen)
        return isinstance(stack_offset, int)

    def _typed_stack_store_rhs_from_statement(stmt, fact: TypedStackProbeReturnFact8616 | None):
        if fact is None:
            return None
        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if not _assignment_lhs_writes_memory(lhs):
                continue
            if _is_segment_register_value_expr(rhs):
                continue
            if _store_matches_typed_stack_probe_fact(lhs, fact):
                return rhs
        return None

    def _stack_store_rhss_from_statement(stmt, *, max_collect: int = 4) -> list:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss = _stack_store_rhss_from_statement(nested, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            return rhss[:max_collect]
        rhs = _stack_store_rhs_from_statement(stmt)
        return [rhs] if rhs is not None else []

    def _typed_stack_store_rhss_from_statement(
        stmt,
        fact: TypedStackProbeReturnFact8616 | None,
        *,
        max_collect: int = 4,
    ) -> list:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss = _typed_stack_store_rhss_from_statement(nested, fact, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            return rhss[:max_collect]
        rhs = _typed_stack_store_rhs_from_statement(stmt, fact)
        return [rhs] if rhs is not None else []

    def _typed_stack_store_rhs_sources_from_statement(
        stmt,
        fact: TypedStackProbeReturnFact8616 | None,
        *,
        max_collect: int = 4,
    ) -> tuple[list, list[set[tuple[str, str | int]]]]:
        if fact is None:
            return [], []
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list = []
            sources: list[set[tuple[str, str | int]]] = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss, nested_sources = _typed_stack_store_rhs_sources_from_statement(
                    nested,
                    fact,
                    max_collect=max_collect,
                )
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    sources.extend(reversed(nested_sources))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            sources.reverse()
            if len(rhss) > max_collect:
                rhss = rhss[:max_collect]
                sources = sources[:max_collect]
            return rhss, sources

        rhs = None
        carrier_sources: set[tuple[str, str | int]] = set()
        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, assignment_rhs = _assignment_lhs_rhs(assignment)
            if not _assignment_lhs_writes_memory(lhs):
                continue
            if _is_segment_register_value_expr(assignment_rhs):
                continue
            if _store_matches_typed_stack_probe_fact(lhs, fact):
                rhs = assignment_rhs
                carrier_sources = set(_generic_stack_carrier_keys_8616(lhs))
                if isinstance(assignment_rhs, object):
                    carrier_sources.update(_generic_stack_carrier_keys_8616(assignment_rhs))
                break
        return ([rhs], [carrier_sources]) if rhs is not None else ([], [])

    def _collect_typed_stack_carrier_defs(
        statements: list,
        start_index: int,
        *,
        wanted_indices: list[int],
        wanted_keys: set[tuple[str, str | int]],
    ) -> list[int]:
        if not wanted_indices or not wanted_keys:
            return wanted_indices
        consumed = list(wanted_indices)
        pending_keys = set(wanted_keys)
        idx = start_index
        while idx >= 0 and pending_keys:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                break
            for assignment in reversed(_iter_assignment_nodes(stmt)):
                lhs, rhs = _assignment_lhs_rhs(assignment)
                if lhs is None:
                    continue
                lhs_keys = _generic_stack_carrier_keys_8616(lhs)
                if not lhs_keys & pending_keys:
                    continue
                consumed.append(idx)
                pending_keys -= lhs_keys
                pending_keys.update(_generic_stack_carrier_keys_8616(rhs))
                break
            idx -= 1
        return sorted(consumed)

    def _is_stack_carrier_temp_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None:
            return False
        if _stack_carrier_key_8616(lhs) is None:
            return False
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        # Carrier temps are arithmetic/address shuttles only.
        if isinstance(rhs_node, CUnaryOp) and rhs_node.op in {"Reference", "Dereference"}:
            return True
        if isinstance(rhs_node, CBinaryOp):
            return rhs_node.op in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
        return False

    def _is_non_memory_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = _assignment_lhs_rhs(candidates[-1])
        return isinstance(lhs, structured_c.CVariable)

    def _value_carrier_assignment_rhs_from_statement(stmt):
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return None
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None or _assignment_lhs_writes_memory(lhs):
            return None
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return None
        if _stack_carrier_key_8616(lhs_node) is None:
            return None
        if _is_segment_register_value_expr(rhs):
            return None
        return rhs

    def _outgoing_arg_placeholder_rhs_from_statement(stmt):
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return None
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None:
            return None
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return None
        variable = getattr(lhs_node, "variable", None)
        name = getattr(variable, "name", None) or getattr(lhs_node, "name", None)
        if not isinstance(name, str):
            return None
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if not isinstance(offset, int) or offset >= 0:
                return None
        elif not (
            name.startswith("local_")
            or name.startswith("arg_")
            or name.startswith("s_")
            or name.startswith("stack_bp_")
            or name.startswith("stack_sp_")
        ):
            return None
        # Accept both canonical stack-placeholder names and materialized local/arg
        # names as potential outgoing stack-argument carriers. This is still gated
        # by immediate callsite backtracking and stack-slot offset constraints.
        if not (
            name.startswith("s_")
            or name.startswith("stack_bp_")
            or name.startswith("stack_sp_")
            or name.startswith("local_")
            or name.startswith("arg_")
        ):
            return None
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        if rhs_node.__class__.__name__ == "CDirtyExpression":
            resolved = _resolve_dirty_virtual_expr_8616(rhs_node)
            if resolved is not None:
                rhs = resolved
        if _is_segment_register_value_expr(rhs):
            return None
        return rhs

    def _is_outgoing_segment_return_store_statement(stmt, *, stack_probe_seen: bool = False) -> bool:
        if not stack_probe_seen:
            return False
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None:
            return False
        segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if segment_name != "ss":
            return False
        rhs_segments = set()
        for raw_node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            variable = getattr(node, "variable", None)
            name = getattr(variable, "name", None) or getattr(node, "name", None)
            if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
                rhs_segments.add(name.lower())
            segment_selector = getattr(node, "segment_selector", None)
            if isinstance(segment_selector, str) and segment_selector.lower() in {"cs", "ds", "es", "ss"}:
                rhs_segments.add(segment_selector.lower())
            seg_name, _offset_terms = _match_real_mode_linear_expr_8616(node, project)
            if seg_name in {"cs", "ds", "es", "ss"}:
                rhs_segments.add(seg_name)
        return rhs_segments == {"ss"}

    def _offset_terms_include_stack_base_placeholder(offset_terms) -> bool:
        for _sign, term in tuple(offset_terms or ()):
            if _node_contains_placeholder_stack_8616(term):
                return True
        return False

    def _is_stack_probe_frame_artifact_store_statement(stmt) -> bool:
        if _statement_contains_call(stmt):
            return False
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None:
            return False
        segment_name, offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if segment_name != "ss":
            return False
        return _offset_terms_include_stack_base_placeholder(offset_terms)

    def _top_level_assignment_node_8616(stmt):
        if _is_assignment_node(stmt):
            return stmt
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
            nested = nested_statements[0]
            if _is_assignment_node(nested):
                return nested
        return None

    def _c_variable_identity_key_8616(node):
        current = node
        while isinstance(current, CTypeCast):
            current = current.expr
        if not isinstance(current, structured_c.CVariable):
            return None
        variable = getattr(current, "variable", None)
        name = getattr(variable, "name", None) or getattr(current, "name", None)
        if isinstance(variable, SimStackVariable):
            return ("stack", getattr(variable, "offset", None), getattr(variable, "size", None), name)
        if isinstance(variable, SimRegisterVariable):
            return ("reg", getattr(variable, "reg", None), getattr(variable, "size", None), name)
        if variable is not None:
            return (
                type(variable).__name__,
                getattr(variable, "ident", None),
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                name,
            )
        if isinstance(name, str) and name:
            return ("name", name)
        return None

    def _statement_references_variable_identity_8616(stmt, key) -> bool:
        if key is None:
            return True
        for raw_node in (stmt, *_iter_c_nodes_deep_8616(stmt)):
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if _c_variable_identity_key_8616(node) == key:
                return True
        return False

    def _variable_identity_referenced_later_8616(key, later_statements: tuple) -> bool:
        return any(_statement_references_variable_identity_8616(stmt, key) for stmt in later_statements)

    def _debug_node_shape_8616(node) -> str:
        if node is None:
            return "None"
        parts = [type(node).__name__]
        for attr in ("statements", "lhs", "rhs", "dst", "src", "expr", "operand", "args"):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if isinstance(value, (list, tuple)):
                parts.append(f"{attr}[{len(value)}]")
            elif value is None:
                parts.append(f"{attr}=None")
            else:
                parts.append(f"{attr}={type(value).__name__}")
        return " ".join(parts)

    def _is_stack_probe_frame_artifact_assignment_statement(stmt, *, later_statements: tuple = ()) -> bool:
        if _statement_contains_call(stmt):
            return False
        assignment = _top_level_assignment_node_8616(stmt)
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-assignment reason=no-top-assignment count=%d stmt=%s",
                    len(_iter_assignment_nodes(stmt)),
                    _debug_expr_8616(stmt),
                )
            return False
        lhs, rhs = _assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-assignment reason=lhs-rhs lhs=%s rhs=%s stmt=%s",
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(rhs),
                    _debug_expr_8616(stmt),
                )
            return False
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-assignment reason=lhs-not-variable lhs_type=%s lhs=%s stmt=%s",
                    type(lhs_node).__name__,
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(stmt),
                )
            return False
        variable = getattr(lhs_node, "variable", None)
        name = getattr(variable, "name", None) or getattr(lhs_node, "name", None)
        lhs_is_stack_variable = isinstance(variable, SimStackVariable)
        if not lhs_is_stack_variable and _assignment_lhs_writes_memory(lhs):
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-assignment reason=memory-lhs lhs=%s rhs=%s stmt=%s",
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(rhs),
                    _debug_expr_8616(stmt),
                )
            return False
        lhs_key = _c_variable_identity_key_8616(lhs_node)
        if _variable_identity_referenced_later_8616(lhs_key, later_statements):
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-assignment reason=live-later key=%r lhs=%s stmt=%s",
                    lhs_key,
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(stmt),
                )
            return False
        if isinstance(variable, SimStackVariable):
            return True
        accepted = isinstance(name, str) and (
            name.startswith(("local_", "vvar_", "tmp_", "ir_")) or re.fullmatch(r"v\d+", name) is not None
        )
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS") and not accepted:
            log.warning(
                "[stack-probe-artifacts] refuse-assignment reason=lhs-name name=%r var_type=%s lhs=%s stmt=%s",
                name,
                type(variable).__name__,
                _debug_expr_8616(lhs),
                _debug_expr_8616(stmt),
            )
        return accepted

    def _is_outgoing_stack_arg_segment_placeholder_store_statement(stmt, *, stack_probe_seen: bool) -> bool:
        if not stack_probe_seen or _statement_contains_call(stmt):
            return False
        assignment = _top_level_assignment_node_8616(stmt)
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-placeholder reason=no-top-assignment count=%d shape=%s stmt=%s",
                    len(_iter_assignment_nodes(stmt)),
                    _debug_node_shape_8616(stmt),
                    _debug_expr_8616(stmt),
                )
            return False
        lhs, rhs = _assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-placeholder reason=lhs-rhs lhs=%s rhs=%s stmt=%s",
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(rhs),
                    _debug_expr_8616(stmt),
                )
            return False
        segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if segment_name != "ss":
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-placeholder reason=segment segment=%r lhs=%s rhs=%s stmt=%s",
                    segment_name,
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(rhs),
                    _debug_expr_8616(stmt),
                )
            return False
        return not _statement_contains_call(rhs)

    def _is_outgoing_stack_slot_placeholder_store_statement(stmt, *, stack_probe_seen: bool) -> bool:
        if not stack_probe_seen or _statement_contains_call(stmt):
            return False
        assignment = _top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, rhs = _assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None or _statement_contains_call(rhs):
            return False
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return False
        variable = getattr(lhs_node, "variable", None)
        offset = getattr(variable, "offset", None)
        return isinstance(variable, SimStackVariable) and isinstance(offset, int) and offset < 0

    def _next_statement_is_materialized_direct_push_call_8616(statements: list, idx: int) -> bool:
        if idx + 1 >= len(statements):
            return False
        next_stmt = statements[idx + 1]
        call = _call_from_statement(next_stmt)
        if call is None:
            return False
        summary = summary_map.get(id(call))
        if summary is None or bool(getattr(summary, "stack_probe_helper", False)):
            return False
        push_sources = getattr(summary, "push_arg_sources", None)
        if not isinstance(push_sources, tuple) or not push_sources:
            return False
        if not all(
            isinstance(source, tuple)
            and len(source) >= 2
            and source[0] == "bp"
            and isinstance(source[1], int)
            for source in push_sources
        ):
            return False
        return bool(tuple(getattr(call, "args", ()) or ()))

    def _stack_variable_offset_8616(expr) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return None
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        offset = getattr(variable, "offset", None)
        return offset if isinstance(offset, int) else None

    def _assignment_ins_addr_8616(stmt) -> int | None:
        tags = getattr(stmt, "tags", None)
        if not isinstance(tags, dict):
            return None
        ins_addr = tags.get("ins_addr")
        return ins_addr if isinstance(ins_addr, int) else None

    def _is_consumed_materialized_call_arg_setup_assignment_8616(statements: list, idx: int) -> bool:
        if idx + 1 >= len(statements):
            return False
        assignment = _top_level_assignment_node_8616(statements[idx])
        if assignment is None or _statement_contains_call(assignment):
            return False
        lhs, rhs = _assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None or _statement_contains_call(rhs):
            return False
        lhs_offset = _stack_variable_offset_8616(lhs)
        if lhs_offset is None or lhs_offset <= 0:
            return False
        next_call = _call_from_statement(statements[idx + 1])
        if next_call is None:
            return False
        summary = summary_map.get(id(next_call))
        if summary is None or bool(getattr(summary, "stack_probe_helper", False)):
            return False
        callsite_addr = getattr(summary, "callsite_addr", None)
        setup_ins_addr = _assignment_ins_addr_8616(assignment)
        if not isinstance(callsite_addr, int) or not isinstance(setup_ins_addr, int):
            return False
        # A consumed push/setup instruction for a near 16-bit call is immediately
        # before the call. Wider gaps can be real source-level stores and must stay.
        if not (0 < callsite_addr - setup_ins_addr <= 4):
            return False
        push_sources = getattr(summary, "push_arg_sources", None)
        if not isinstance(push_sources, tuple) or not push_sources:
            return False
        source_offsets = {
            int(source[1])
            for source in push_sources
            if isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int)
        }
        if lhs_offset not in source_offsets:
            return False
        lhs_key = _c_variable_identity_key_8616(lhs)
        if lhs_key is None:
            return False
        args = tuple(getattr(next_call, "args", ()) or ())
        if not any(_c_variable_identity_key_8616(arg) == lhs_key for arg in args):
            return False
        return True

    def _prune_stack_probe_frame_artifacts(
        statements: list,
        *,
        stack_probe_seen: bool,
        allow_setup_assignment_prune: bool,
    ) -> list:
        if not stack_probe_seen:
            return statements
        helper_or_helper_zone_active = bool(stack_probe_seen)
        pruned = []
        removed_artifacts = 0
        for idx, stmt in enumerate(statements):
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS_VERBOSE"):
                assignment = _top_level_assignment_node_8616(stmt)
                lhs = rhs = None
                if assignment is not None:
                    lhs, rhs = _assignment_lhs_rhs(assignment)
                log.warning(
                    "[stack-probe-artifacts] stmt idx=%d helper_zone=%s stack_probe_seen=%s shape=%s lhs=%s rhs=%s tags=%r",
                    idx,
                    helper_or_helper_zone_active,
                    stack_probe_seen,
                    _debug_node_shape_8616(stmt),
                    _debug_expr_8616(lhs),
                    _debug_expr_8616(rhs),
                    getattr(assignment, "tags", None) if assignment is not None else getattr(stmt, "tags", None),
                )
            call = _call_from_statement(stmt)
            summary = summary_map.get(id(call)) if call is not None else None
            if call is not None and isinstance(summary, object):
                if bool(getattr(summary, "stack_probe_helper", False)):
                    helper_or_helper_zone_active = True
                elif bool(getattr(summary, "stack_probe_helper", False)) is False:
                    helper_or_helper_zone_active = False
            if _is_stack_probe_frame_artifact_store_statement(stmt):
                if not helper_or_helper_zone_active and not stack_probe_seen:
                    pruned.append(stmt)
                    continue
                stats.consumed_outgoing_stack_placeholder_count += 1
                continue
            if helper_or_helper_zone_active and _is_outgoing_stack_arg_segment_placeholder_store_statement(
                stmt,
                stack_probe_seen=stack_probe_seen,
            ):
                if _next_statement_is_materialized_direct_push_call_8616(statements, idx):
                    stats.consumed_outgoing_stack_placeholder_count += 1
                    continue
                if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                    next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
                    next_call = _call_from_statement(next_stmt) if next_stmt is not None else None
                    next_summary = summary_map.get(id(next_call)) if next_call is not None else None
                    log.warning(
                        "[stack-probe-artifacts] refuse-placeholder-consume reason=next-call "
                        "idx=%d next_shape=%s next_call=%s summary=%s push_sources=%r args=%r",
                        idx,
                        _debug_node_shape_8616(next_stmt),
                        _debug_expr_8616(next_call),
                        type(next_summary).__name__ if next_summary is not None else None,
                        getattr(next_summary, "push_arg_sources", None) if next_summary is not None else None,
                        tuple(_debug_expr_8616(arg) for arg in (getattr(next_call, "args", ()) or ()))
                        if next_call is not None
                        else (),
                    )
            if (
                helper_or_helper_zone_active
                and _is_outgoing_stack_slot_placeholder_store_statement(stmt, stack_probe_seen=stack_probe_seen)
            ):
                if _next_statement_is_materialized_direct_push_call_8616(statements, idx):
                    stats.consumed_outgoing_stack_placeholder_count += 1
                    continue
                if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                    next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
                    next_call = _call_from_statement(next_stmt) if next_stmt is not None else None
                    next_summary = summary_map.get(id(next_call)) if next_call is not None else None
                    log.warning(
                        "[stack-probe-artifacts] refuse-slot-placeholder-consume reason=next-call "
                        "idx=%d stmt=%s next_shape=%s next_call=%s summary=%s push_sources=%r args=%r",
                        idx,
                        _debug_expr_8616(stmt),
                        _debug_node_shape_8616(next_stmt),
                        _debug_expr_8616(next_call),
                        type(next_summary).__name__ if next_summary is not None else None,
                        getattr(next_summary, "push_arg_sources", None) if next_summary is not None else None,
                        tuple(_debug_expr_8616(arg) for arg in (getattr(next_call, "args", ()) or ()))
                        if next_call is not None
                        else (),
                    )
            if (
                allow_setup_assignment_prune
                and helper_or_helper_zone_active
                and _is_stack_probe_frame_artifact_assignment_statement(
                    stmt,
                    later_statements=tuple(statements[idx + 1 :]),
                )
            ):
                stats.consumed_outgoing_stack_placeholder_count += 1
                removed_artifacts += 1
                continue
            if prune_consumed_arg_stores and _is_consumed_materialized_call_arg_setup_assignment_8616(statements, idx):
                stats.consumed_outgoing_stack_placeholder_count += 1
                removed_artifacts += 1
                codegen._inertia_call_arg_setup_assignments_pruned_8616 = (
                    int(getattr(codegen, "_inertia_call_arg_setup_assignments_pruned_8616", 0) or 0) + 1
                )
                continue
            pruned.append(stmt)
        if removed_artifacts:
            ensure_stack_probe_fact_stats_8616(codegen)["stack_probe_frame_artifacts_pruned"] = (
                int(ensure_stack_probe_fact_stats_8616(codegen).get("stack_probe_frame_artifacts_pruned", 0) or 0)
                + removed_artifacts
            )
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] pruned=%d before=%d after=%d",
                    removed_artifacts,
                    len(statements),
                    len(pruned),
                )
        return pruned

    def _is_virtual_dirty_expr_8616(term) -> bool:
        dirty = getattr(term, "dirty", None)
        if isinstance(dirty, str):
            return dirty.startswith("vvar_") or dirty.startswith("tmp_") or dirty.startswith("ir_")
        if dirty is None:
            return False
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return True
        name = getattr(dirty, "name", None)
        return isinstance(name, str) and (
            name.startswith("vvar_") or name.startswith("tmp_") or name.startswith("ir_")
        )

    def _assignment_lhs_writes_memory(lhs) -> bool:
        if lhs is None:
            return False
        nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
        for raw_node in nodes:
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if isinstance(node, CFunctionCall):
                call_name = _call_node_name_8616(node)
                if isinstance(call_name, str) and call_name.upper() in {"SEG_U8", "SEG_U16", "SEG_U32"}:
                    return True
            if isinstance(node, CUnaryOp) and node.op == "Dereference":
                return True
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                return True
        return False

    def _is_value_only_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = _assignment_lhs_rhs(candidates[-1])
        return not _assignment_lhs_writes_memory(lhs)

    def _is_segment_register_metadata_store(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        return _assignment_lhs_writes_memory(lhs) and _is_segment_register_value_expr(rhs)

    def _collect_backtracked_stack_args(
        statements: list,
        *,
        wanted_count: int | None = None,
        max_count: int = 4,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None = None,
        allow_partial: bool = False,
        call_return_addr: int | None = None,
    ) -> tuple[list, list]:
        def _dedupe_indices(indices: list[int]) -> list[int]:
            return sorted(set(indices))

        def _rhs_matches_call_return_addr(rhs) -> bool:
            if not isinstance(call_return_addr, int):
                return False
            node = rhs
            while isinstance(node, CTypeCast):
                node = node.expr
            if not isinstance(node, structured_c.CConstant):
                return False
            value = getattr(node, "value", None)
            if not isinstance(value, int):
                return False
            return (value & 0xFFFF) == (int(call_return_addr) & 0xFFFF)

        def _filter_call_return_frame_rhss(rhss: list, source_index: int) -> tuple[list, list[int]]:
            if not rhss:
                return [], []
            kept: list = []
            skipped_indices: list[int] = []
            for rhs in rhss:
                if _rhs_matches_call_return_addr(rhs):
                    skipped_indices.append(source_index)
                    continue
                kept.append(rhs)
            return kept, skipped_indices

        def _is_skip_after_typed_collect(stmt) -> bool:
            return (
                _is_stack_carrier_temp_assignment(stmt)
                or _is_non_memory_assignment(stmt)
                or _is_value_only_assignment(stmt)
                or _is_segment_register_metadata_store(stmt)
            )

        def _expand_typed_carrier_defs(stmt_index: int, wanted_indices: list[int], wanted_keys: set[tuple[str, str | int]]) -> list[int]:
            if not wanted_indices or not wanted_keys:
                return wanted_indices
            if stmt_index < 0:
                return wanted_indices
            return _collect_typed_stack_carrier_defs(
                statements,
                start_index=stmt_index,
                wanted_indices=wanted_indices,
                wanted_keys=wanted_keys,
            )

        def _trailing_stack_store_rhss_after_last_call(
            stmt,
            *,
            max_collect: int,
            parent_stmt_index: int,
        ) -> tuple[list, list[int]]:
            nested_statements = getattr(stmt, "statements", None)
            if not isinstance(nested_statements, (list, tuple)):
                return [], []
            sequence = list(nested_statements)
            last_call_idx = None
            for seq_idx, node in enumerate(sequence):
                if _statement_contains_call(node):
                    last_call_idx = seq_idx
            if last_call_idx is None:
                return [], []

            rhss: list = []
            consumed_nested_indices: list[int] = []
            skipped_carriers = 0
            skipped_value_assignments = 0
            value_skip_limit = 160 if isinstance(wanted_count, int) and wanted_count > 0 else 8
            for seq_idx, node in enumerate(sequence[last_call_idx + 1 :], start=last_call_idx + 1):
                if _statement_contains_call(node):
                    break
                nested_rhss = []
                nested_sources: list[set[tuple[str, str | int]]] = []
                if typed_probe_fact is not None:
                    nested_rhss, nested_sources = _typed_stack_store_rhs_sources_from_statement(
                        node,
                        typed_probe_fact,
                        max_collect=max_collect,
                    )
                    if not nested_rhss:
                        if _is_skip_after_typed_collect(node):
                            if _is_segment_register_metadata_store(node) or _is_stack_carrier_temp_assignment(node):
                                skipped_carriers += 1
                            else:
                                skipped_value_assignments += 1
                            if skipped_carriers > 4 or skipped_value_assignments > 8:
                                break
                            continue
                        break
                    rhss.extend(nested_rhss)
                    consumed_nested_indices.append(seq_idx)
                    if nested_sources:
                        keys = set()
                        for entry in nested_sources:
                            keys.update(entry)
                        # Typed nested store materialization currently remains scoped to the
                        # parent call statement; nested statement indices are not directly
                        # removable from the outer sequence.
                        _expand_typed_carrier_defs(
                            seq_idx - 1,
                            wanted_keys=keys,
                            wanted_indices=[parent_stmt_index - 1],
                        )
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_rhss = _stack_store_rhss_from_statement(node, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(nested_rhss)
                    consumed_nested_indices.append(seq_idx)
                    if len(rhss) >= max_collect:
                        break
                    continue
                placeholder_rhs = _outgoing_arg_placeholder_rhs_from_statement(node)
                if placeholder_rhs is not None:
                    rhss.append(placeholder_rhs)
                    if len(rhss) >= max_collect:
                        break
                    continue
                if _is_segment_register_metadata_store(node):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    continue
                if _is_stack_carrier_temp_assignment(node):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    continue
                if _is_non_memory_assignment(node) or _is_value_only_assignment(node):
                    skipped_value_assignments += 1
                    if skipped_value_assignments > value_skip_limit:
                        break
                    continue
                break
            if consumed_nested_indices:
                for del_idx in reversed(_dedupe_indices(consumed_nested_indices)):
                    if 0 <= del_idx < len(sequence):
                        del sequence[del_idx]
                if isinstance(nested_statements, list):
                    stmt.statements = sequence
                else:
                    stmt.statements = tuple(sequence)

            return rhss[:max_collect], []

        rhs_values: list = []
        consumed_indices: list[int] = []
        consumed_return_frame_indices: list[int] = []
        skipped_carriers = 0
        skipped_value_assignments = 0
        value_skip_limit = 160 if isinstance(wanted_count, int) and wanted_count > 0 else 8
        limit = max_count if wanted_count is None else max(wanted_count, 1)
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < limit:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                trailing_rhss = _trailing_stack_store_rhss_after_last_call(
                    stmt,
                    max_collect=max(0, limit - len(rhs_values)),
                    parent_stmt_index=idx,
                )
                if trailing_rhss:
                    trailing_args, trailing_indices = trailing_rhss
                    if len(trailing_args) > 1:
                        stats.push_order_reversed_count += 1
                    rhs_values.extend(trailing_args)
                    consumed_indices.extend(trailing_indices)
                break
            rhss = []
            rhs_sources: list[set[tuple[str, str | int]]] = []
            if typed_probe_fact is not None:
                rhss, rhs_sources = _typed_stack_store_rhs_sources_from_statement(
                    stmt,
                    typed_probe_fact,
                    max_collect=max_count,
                )
                if not rhss:
                    if _is_skip_after_typed_collect(stmt):
                        if _is_segment_register_metadata_store(stmt) or _is_stack_carrier_temp_assignment(stmt):
                            skipped_carriers += 1
                        else:
                            skipped_value_assignments += 1
                        if skipped_carriers > 4 or skipped_value_assignments > 8:
                            break
                        idx -= 1
                        continue
                    break
            if not rhss and typed_probe_fact is None:
                rhss = _stack_store_rhss_from_statement(stmt, max_collect=max_count)
            if rhss:
                rhss, return_frame_indices = _filter_call_return_frame_rhss(rhss, idx)
                if return_frame_indices:
                    consumed_return_frame_indices.extend(return_frame_indices)
                    if not rhss:
                        idx -= 1
                        continue
                if all(_is_segment_register_value_expr(rhs) for rhs in rhss):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    idx -= 1
                    continue
                if len(rhss) > 1:
                    stats.push_order_reversed_count += 1
                rhs_values.extend(rhss)
                expanded_indices = [idx]
                if typed_probe_fact is not None and rhs_sources:
                    keys = set()
                    for entry in rhs_sources:
                        keys.update(entry)
                    expanded_indices = _expand_typed_carrier_defs(
                        idx - 1,
                        wanted_indices=expanded_indices,
                        wanted_keys=keys,
                    )
                consumed_indices.extend(expanded_indices)
                idx -= 1
                continue
            placeholder_rhs = _outgoing_arg_placeholder_rhs_from_statement(stmt)
            if placeholder_rhs is not None:
                stats.consumed_outgoing_stack_placeholder_count += 1
                rhs_values.append(placeholder_rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            if _is_segment_register_metadata_store(stmt):
                skipped_carriers += 1
                if skipped_carriers > 4:
                    break
                idx -= 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                skipped_carriers += 1
                if skipped_carriers > 4:
                    break
                idx -= 1
                continue
            if _is_non_memory_assignment(stmt) or _is_value_only_assignment(stmt):
                skipped_value_assignments += 1
                if skipped_value_assignments > value_skip_limit:
                    break
                idx -= 1
                continue
            break
        if wanted_count is not None and len(rhs_values) != wanted_count:
            if allow_partial and rhs_values:
                return rhs_values, consumed_indices + consumed_return_frame_indices
            return [], []
        if len(rhs_values) > 1:
            stats.push_order_reversed_count += 1
        return rhs_values, consumed_indices + consumed_return_frame_indices

    def _collect_backtracked_value_carrier_args(
        statements: list,
        *,
        wanted_count: int,
    ) -> tuple[list, list]:
        if not isinstance(wanted_count, int) or wanted_count <= 0:
            return [], []
        rhs_values: list = []
        consumed_indices: list[int] = []
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < wanted_count:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                break
            rhs = _value_carrier_assignment_rhs_from_statement(stmt)
            if rhs is not None:
                rhs_values.append(rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            placeholder_rhs = _outgoing_arg_placeholder_rhs_from_statement(stmt)
            if placeholder_rhs is not None:
                stats.consumed_outgoing_stack_placeholder_count += 1
                rhs_values.append(placeholder_rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                idx -= 1
                continue
            break
        if len(rhs_values) != wanted_count:
            return [], []
        return rhs_values, consumed_indices

    def _extract_inline_stack_store_args(stmt, call, arg_count: int) -> tuple | None:
        if not isinstance(arg_count, int) or arg_count <= 0:
            return None
        nested_statements = getattr(stmt, "statements", None)
        if not isinstance(nested_statements, (list, tuple)):
            return None
        if not nested_statements:
            return None

        sequence = list(nested_statements)

        def _contains_call(node) -> bool:
            if node is call:
                return True
            expr = getattr(node, "expr", None)
            if expr is call:
                return True
            for sub in _iter_c_nodes_deep_8616(node):
                if sub is call:
                    return True
            return False

        call_idx = None
        for idx, node in enumerate(sequence):
            if _contains_call(node):
                call_idx = idx
                break
        if call_idx is None:
            return None

        rhs_values = []
        consumed_indices = []
        scan = call_idx - 1
        skipped_carriers = 0
        while scan >= 0 and len(rhs_values) < arg_count:
            rhs = _stack_store_rhs_from_statement(sequence[scan])
            if rhs is None:
                rhs = _outgoing_arg_placeholder_rhs_from_statement(sequence[scan])
                if rhs is not None:
                    stats.consumed_outgoing_stack_placeholder_count += 1
            if rhs is None:
                if _is_stack_carrier_temp_assignment(sequence[scan]):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    scan -= 1
                    continue
                break
            rhs_values.append(rhs)
            consumed_indices.append(scan)
            scan -= 1
        if len(rhs_values) != arg_count:
            return None

        _delete_consumed_indices_8616(sequence, consumed_indices)
        stmt.statements = sequence if isinstance(nested_statements, list) else tuple(sequence)
        if len(rhs_values) > 1:
            stats.push_order_reversed_count += 1
        return tuple(rhs_values)

    def _restore_protected_call_args_8616(block) -> bool:
        protected = getattr(codegen, "_inertia_protected_call_args_8616", None)
        if not isinstance(protected, dict):
            return False
        restored = False
        for node in _iter_c_nodes_deep_8616(block):
            if not isinstance(node, CFunctionCall):
                continue
            call_name = _call_node_name_8616(node) or ""
            current_args = list(getattr(node, "args", ()) or ())
            if not current_args:
                continue
            updated = False
            for idx, current_arg in enumerate(tuple(current_args)):
                key = (id(node), idx)
                protected_entry = protected.get(key)
                if not isinstance(protected_entry, tuple) or len(protected_entry) != 2:
                    continue
                protected_arg, protected_score = protected_entry
                current_score = _arg_semantic_quality_8616(call_name, idx, current_arg)
                if current_score < int(protected_score):
                    summary = summary_map.get(id(node)) if isinstance(summary_map, dict) else None
                    push_sources = getattr(summary, "push_arg_sources", ()) if summary is not None else ()
                    source_idx = idx
                    if isinstance(push_sources, tuple) and len(push_sources) > 1:
                        source_idx = len(push_sources) - 1 - idx
                    if (
                        isinstance(push_sources, tuple)
                        and source_idx >= 0
                        and source_idx < len(push_sources)
                        and isinstance(push_sources[source_idx], tuple)
                        and len(push_sources[source_idx]) >= 2
                        and push_sources[source_idx][0] == "imm"
                        and isinstance(push_sources[source_idx][1], int)
                        and isinstance(current_arg, structured_c.CConstant)
                        and getattr(current_arg, "value", None) == int(push_sources[source_idx][1])
                    ):
                        # Keep source-evidenced immediates (e.g. first arg 0)
                        # instead of restoring higher-scored stack carriers.
                        continue
                    current_args[idx] = _clone_c_ast_tree(protected_arg)
                    updated = True
            if updated:
                node.args = current_args
                restored = True
        return restored

    def _rewrite_block(
        block,
        *,
        inherited_stack_probe_seen: bool = False,
        inherited_stack_probe_address_seen: bool = False,
        inherited_typed_stack_probe_fact: TypedStackProbeReturnFact8616 | None = None,
        allow_setup_assignment_prune: bool = True,
    ) -> tuple[bool, bool, TypedStackProbeReturnFact8616 | None]:
        nonlocal changed
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return inherited_stack_probe_seen, inherited_stack_probe_address_seen, inherited_typed_stack_probe_fact
        if _replace_stack_code_pointer_assignments_8616(block):
            changed = True
            statements = getattr(block, "statements", None)
            if not isinstance(statements, (list, tuple)):
                return inherited_stack_probe_seen, inherited_stack_probe_address_seen, inherited_typed_stack_probe_fact
        statements = list(statements)
        new_statements = []
        i = 0
        typed_stack_probe_fact = inherited_typed_stack_probe_fact
        stack_probe_seen = inherited_stack_probe_seen or any(
            bool(getattr(item, "stack_probe_helper", False)) for item in summary_map.values()
        )
        stack_probe_address_seen = inherited_stack_probe_address_seen or typed_stack_probe_fact is not None

        def _has_recent_stack_arg_store_evidence(
            statement_list: list,
            wanted_count: int,
            typed_probe_fact: TypedStackProbeReturnFact8616 | None,
        ) -> bool:
            if not isinstance(wanted_count, int) or wanted_count <= 0:
                return False
            needed = wanted_count
            skipped_carriers = 0
            skipped_values = 0
            idx = len(statement_list) - 1
            while idx >= 0 and needed > 0:
                candidate = statement_list[idx]
                if _statement_contains_call(candidate):
                    break
                if typed_probe_fact is not None:
                    rhs = _typed_stack_store_rhs_from_statement(candidate, typed_probe_fact)
                else:
                    rhs = _stack_store_rhs_from_statement(candidate)
                if rhs is not None and not _is_segment_register_value_expr(rhs):
                    needed -= 1
                    idx -= 1
                    continue
                if _outgoing_arg_placeholder_rhs_from_statement(candidate) is not None:
                    needed -= 1
                    idx -= 1
                    continue
                if _is_stack_carrier_temp_assignment(candidate) or _is_segment_register_metadata_store(candidate):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    idx -= 1
                    continue
                if _is_non_memory_assignment(candidate) or _is_value_only_assignment(candidate):
                    skipped_values += 1
                    if skipped_values > 8:
                        break
                    idx -= 1
                    continue
                break
            return needed <= 0

        while i < len(statements):
            stmt = statements[i]
            if _is_outgoing_segment_return_store_statement(stmt, stack_probe_seen=stack_probe_seen):
                stats.consumed_outgoing_stack_placeholder_count += 1
                changed = True
                i += 1
                continue
            call = _call_from_statement(stmt)
            if call is not None and _is_runtime_segment_helper_call_8616(call):
                new_statements.append(stmt)
                i += 1
                continue
            summary = summary_map.get(id(call)) if call is not None else None
            arg_count = getattr(summary, "arg_count", None) if summary is not None else None
            summary_arg_count = arg_count if isinstance(arg_count, int) else None
            call_name = _call_node_name_8616(call) if call is not None else None
            prototype_arg_count = _prototype_arg_count(call) if call is not None else None
            cod_prototype_arg_count = (
                _cod_source_prototype_arg_count_8616(project, call_name)
                if call is not None and summary_arg_count is None and prototype_arg_count is None
                else None
            )
            normalized_call_name = normalize_callee_name_8616(call_name) if isinstance(call_name, str) else None
            known_arg_count = _expected_arg_count_for_known_callee_8616(call_name or "") if call is not None else None
            if known_arg_count is None and isinstance(normalized_call_name, str) and normalized_call_name:
                known_arg_count = _expected_arg_count_for_known_callee_8616(normalized_call_name)
            if known_arg_count is None and isinstance(cod_prototype_arg_count, int):
                known_arg_count = cod_prototype_arg_count
            is_stack_probe_helper = bool(getattr(summary, "stack_probe_helper", False))
            push_arg_sources = getattr(summary, "push_arg_sources", ()) if summary is not None else ()
            if call is not None and not is_stack_probe_helper and _is_stack_probe_call_name_8616(call_name):
                is_stack_probe_helper = True
            if is_stack_probe_helper:
                stack_probe_seen = True
                typed_stack_probe_fact = typed_stack_probe_facts.get(id(call)) if call is not None else None
                helper_return_space = getattr(summary, "helper_return_space", None)
                helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
                helper_return_state = getattr(summary, "helper_return_state", None)
                stack_probe_address_seen = bool(typed_stack_probe_fact is not None) or (
                    bool(helper_return_state == "stack_address")
                    and helper_return_space in {None, "ss"}
                )
                if _stack_probe_helper_statement_is_consumable_8616(stmt, call, summary):
                    ensure_stack_probe_fact_stats_8616(codegen)["stack_probe_calls_pruned"] += 1
                    changed = True
                    i += 1
                    continue
                ensure_stack_probe_fact_stats_8616(codegen)["stack_probe_calls_refused"] += 1
            # A typed stack-probe fact is strong evidence for a helper-returned SS
            # address. If no typed fact exists, direct segmented SS stores before the
            # call remain valid evidence and the generic stack-arg backtracker must
            # stay enabled.
            typed_stack_probe_materialization = (
                typed_stack_probe_fact is not None and stack_probe_seen and not is_stack_probe_helper
            )
            expected_arg_count = _expected_arg_count_for_call_8616(
                arg_count if isinstance(arg_count, int) else None,
                known_arg_count=known_arg_count,
                prototype_arg_count=prototype_arg_count,
            )
            if _apply_indirect_callsite_type_8616(call, summary, expected_arg_count):
                changed = True
            has_strong_direct_push_sources = (
                isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and isinstance(push_arg_sources, tuple)
                and len(push_arg_sources) == expected_arg_count
                and all(
                    isinstance(source, tuple)
                    and len(source) >= 2
                    and source[0] == "bp"
                    and isinstance(source[1], int)
                    for source in push_arg_sources
                )
            )
            if (
                isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and isinstance(known_arg_count, int)
                and known_arg_count > expected_arg_count
                and summary_arg_count is not None
                and (
                    summary_arg_count <= 0
                    or (
                        summary_arg_count > 0
                        and stack_probe_seen
                    )
                )
                and not has_strong_direct_push_sources
            ):
                expected_arg_count = known_arg_count
            fallback_arg_count = _fallback_call_arg_count_8616(
                expected_arg_count=expected_arg_count,
                push_arg_sources=push_arg_sources,
            )
            rematerialize_call_args = (
                _call_args_need_rematerialization_8616(call, push_arg_sources=push_arg_sources)
                if call is not None
                else False
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION") and call is not None:
                log.warning(
                    "[call-summary] function=%#x target=%s expected_arg_count=%r push_arg_sources=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    expected_arg_count,
                    push_arg_sources,
                )
            if os.environ.get("INERTIA_DEBUG_PERCOLATEUP_CALLSITE") and call is not None and call_name == "PercolateUp":
                log.warning(
                    "[percolateup-callsite] function=%#x expected_arg_count=%r prototype_arg_count=%r known_arg_count=%r remat=%r push_arg_sources=%r args=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    expected_arg_count,
                    prototype_arg_count,
                    known_arg_count,
                    rematerialize_call_args,
                    push_arg_sources,
                    tuple(_debug_expr_8616(arg) for arg in tuple(getattr(call, "args", ()) or ())),
                )
            # When a stack-probe helper was seen but its segment space is not SS
            # (e.g. "ds"), the probe return address is not a stack address.
            # Reject backward-scan materialization for calls after the probe.
            # Guard only when we have typed stack-probe address evidence in-flight.
            # Plain stack-probe helpers like aNchkstk are not address-producing
            # evidence and must not globally suppress call-argument rematerialization.
            probe_seen_without_ss_address = (
                stack_probe_seen and not stack_probe_address_seen and typed_stack_probe_fact is not None
            )
            if (
                call is not None
                and isinstance(expected_arg_count, int)
                and expected_arg_count >= 0
                and len(tuple(getattr(call, "args", ()) or ())) != expected_arg_count
            ):
                rematerialize_call_args = True
            if typed_stack_probe_materialization:
                rematerialize_call_args = True
            has_exact_direct_push_sources = (
                isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and isinstance(push_arg_sources, tuple)
                and len(push_arg_sources) == expected_arg_count
                and any(source is not None for source in push_arg_sources)
            )
            has_safe_non_stack_fallback = (
                isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and _known_default_args_for_missing_8616(call_name or "", codegen) is not None
            )
            # Do not destructively clear existing call args when inferred arg-count
            # drops to zero. Zero can be an unproven placeholder; preserving current
            # args keeps call semantics stable until stronger evidence rematerializes.
            if (
                call is not None
                and not is_stack_probe_helper
                and expected_arg_count == 0
                and tuple(getattr(call, "args", ()) or ())
                and not probe_seen_without_ss_address
            ):
                rematerialize_call_args = False
            if os.environ.get("INERTIA_DEBUG_PERCOLATEUP_CALLSITE") and call is not None and call_name == "PercolateUp":
                log.warning(
                    "[percolateup-callsite-post-zero] function=%#x expected_arg_count=%r remat=%r args=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    expected_arg_count,
                    rematerialize_call_args,
                    tuple(_debug_expr_8616(arg) for arg in tuple(getattr(call, "args", ()) or ())),
                )
            if (
                call is not None
                and tuple(getattr(call, "args", ()) or ())
                and _normalize_existing_call_args_8616(call, new_statements, call_name=call_name)
            ):
                _refresh_summary_arg_shape(call, summary)
                changed = True
            has_recent_stack_arg_store_evidence = _has_recent_stack_arg_store_evidence(
                new_statements,
                expected_arg_count,
                typed_stack_probe_fact if stack_probe_seen else None,
            )
            if (
                call is not None
                and not is_stack_probe_helper
                and isinstance(expected_arg_count, int)
                and expected_arg_count == 1
                and isinstance(push_arg_sources, tuple)
                and len(push_arg_sources) == 1
                and isinstance(push_arg_sources[0], tuple)
                and len(push_arg_sources[0]) >= 2
                and push_arg_sources[0][0] == "bp"
                and isinstance(push_arg_sources[0][1], int)
            ):
                src_off = int(push_arg_sources[0][1])
                direct_stack_arg = _stack_cvar_for_offset(src_off, allow_best_match=False)
                if direct_stack_arg is None:
                    direct_stack_arg = _stack_cvar_for_offset(src_off, allow_best_match=True)
                if direct_stack_arg is not None:
                    _set_materialized_call_args(
                        call,
                        [_clone_c_ast_tree(direct_stack_arg)],
                        call_name=call_name,
                        force_replace=True,
                    )
                    while new_statements and _is_outgoing_stack_arg_segment_placeholder_store_statement(
                        new_statements[-1],
                        stack_probe_seen=stack_probe_seen,
                    ):
                        new_statements.pop()
                        stats.consumed_outgoing_stack_placeholder_count += 1
                        changed = True
                    record_stack_arg_materialization_8616(codegen, 1)
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                    if _apply_call_return_store_destination_8616(stmt, call, summary):
                        changed = True
                    new_statements.append(stmt)
                    i += 1
                    continue
            if (
                call is not None
                and isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and rematerialize_call_args
                and (not probe_seen_without_ss_address or has_exact_direct_push_sources or has_safe_non_stack_fallback)
            ):
                strict_arg_shape_applied = False
                if (
                    isinstance(push_arg_sources, tuple)
                    and len(push_arg_sources) == expected_arg_count
                    and any(source is not None for source in push_arg_sources)
                ):
                    ordered_push_sources = (
                        list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
                    )
                    direct_args = []
                    direct_bindings = {}
                    strict_push_sources = all(
                        isinstance(source, tuple)
                        and len(source) >= 2
                        and source[0] == "bp"
                        and isinstance(source[1], int)
                        for source in ordered_push_sources
                    )
                    if strict_push_sources:
                        for source in ordered_push_sources:
                            source_value = source[1]
                            cvar = _stack_cvar_for_offset(source_value, allow_best_match=False)
                            if cvar is None:
                                break
                            direct_args.append(_clone_c_ast_tree(cvar))
                            direct_bindings[source_value] = _clone_c_ast_tree(cvar)
                    else:
                        direct_args = [
                            _direct_expr_from_push_source_8616(source, call_name=call_name, arg_index=idx)
                            for idx, source in enumerate(ordered_push_sources)
                        ]
                    if all(arg is not None for arg in direct_args):
                        normalized_args = _normalize_materialized_call_args(
                            direct_args,
                            [-1] * len(direct_args),
                            new_statements,
                            call_name=call_name,
                            stack_bindings=direct_bindings or None,
                        )
                        if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                            _set_materialized_call_args(
                                call,
                                normalized_args,
                                call_name=call_name,
                                force_replace=all(
                                    isinstance(source, tuple)
                                    and len(source) >= 2
                                    and source[0] == "bp"
                                    and isinstance(source[1], int)
                                    for source in push_arg_sources
                                ),
                            )
                            record_stack_arg_materialization_8616(codegen, len(normalized_args))
                            _refresh_summary_arg_shape(call, summary)
                            changed = True
                            strict_arg_shape_applied = True
                if not strict_arg_shape_applied and len(new_statements) >= expected_arg_count:
                    if (
                        not typed_stack_probe_materialization
                        and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                    ):
                        candidate_stmts = new_statements[-expected_arg_count:]
                        candidate_rhs = []
                        for candidate in candidate_stmts:
                            rhs = _stack_store_rhs_from_statement(candidate)
                            if rhs is None:
                                rhs = _outgoing_arg_placeholder_rhs_from_statement(candidate)
                            candidate_rhs.append(rhs)
                        candidate_indices = list(range(len(new_statements) - expected_arg_count, len(new_statements)))
                        if len(candidate_rhs) > 1:
                            candidate_rhs = list(reversed(candidate_rhs))
                            candidate_indices = list(reversed(candidate_indices))
                        normalized_args = (
                            _normalize_materialized_call_args(
                                candidate_rhs,
                                candidate_indices,
                                new_statements,
                                call_name=call_name,
                            )
                            if all(rhs is not None for rhs in candidate_rhs)
                            else None
                        )
                        if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                            _set_materialized_call_args(call, normalized_args, call_name=call_name)
                            record_stack_arg_materialization_8616(codegen, len(normalized_args))
                            _record_prunable_segment_metadata_ids(
                                call,
                                new_statements,
                                candidate_indices,
                            )
                            if prune_consumed_arg_stores:
                                if (
                                    stack_probe_seen
                                    and not stack_probe_address_seen
                                    and typed_stack_probe_fact is None
                                ):
                                    cleanup_indices = candidate_indices.copy()
                                    scan_idx = min(candidate_indices, default=-1) - 1
                                    while scan_idx >= 0:
                                        prev_stmt = new_statements[scan_idx]
                                        if _statement_contains_call(prev_stmt):
                                            break
                                        if (
                                            _is_stack_carrier_temp_assignment(prev_stmt)
                                            or _is_segment_register_metadata_store(prev_stmt)
                                        ):
                                            cleanup_indices.append(scan_idx)
                                            scan_idx -= 1
                                            continue
                                        break
                                    _delete_consumed_indices_8616(new_statements, list(set(cleanup_indices)))
                                else:
                                    _delete_consumed_indices_8616(
                                        new_statements,
                                        list(range(len(new_statements) - expected_arg_count, len(new_statements))),
                                    )
                            _refresh_summary_arg_shape(call, summary)
                            changed = True
                            strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and typed_stack_probe_fact is not None
                    and stack_probe_seen
                    and not is_stack_probe_helper
                ):
                    expanded_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=fallback_arg_count if isinstance(fallback_arg_count, int) and fallback_arg_count > 0 else None,
                        max_count=4,
                        typed_probe_fact=typed_stack_probe_fact,
                        call_return_addr=getattr(summary, "return_addr", None),
                    )
                    normalized_args = _normalize_materialized_call_args(
                        expanded_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if (
                        normalized_args is not None
                        and isinstance(expected_arg_count, int)
                        and len(normalized_args) >= expected_arg_count
                        and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    ):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        if prune_consumed_arg_stores:
                            _delete_consumed_indices_8616(new_statements, consumed_indices)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and typed_stack_probe_fact is not None
                    and stack_probe_seen
                    and not is_stack_probe_helper
                ):
                    typed_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                        max_count=max(expected_arg_count, 1),
                        typed_probe_fact=typed_stack_probe_fact,
                        call_return_addr=getattr(summary, "return_addr", None),
                    )
                    normalized_args = _normalize_materialized_call_args(
                        typed_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        if prune_consumed_arg_stores:
                            _delete_consumed_indices_8616(new_statements, consumed_indices)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied and (
                    not typed_stack_probe_materialization
                    and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                ):
                    backtracked_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                        call_return_addr=getattr(summary, "return_addr", None),
                    )
                    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                        log.warning(
                            "[call-backtrack] function=%#x target=%s wanted=%r rhs=%s consumed=%r statements=%d",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            call_name,
                            expected_arg_count,
                            tuple(_debug_expr_8616(rhs) for rhs in backtracked_rhs),
                            tuple(consumed_indices),
                            len(new_statements),
                        )
                    normalized_args = _normalize_materialized_call_args(
                        backtracked_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        if prune_consumed_arg_stores:
                            _delete_consumed_indices_8616(new_statements, consumed_indices)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied and (
                    not typed_stack_probe_materialization
                    and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                ):
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, expected_arg_count)
                    normalized_args = (
                        _normalize_materialized_call_args(
                            list(inline_rhs),
                            list(range(max(0, i - len(inline_rhs)), i)),
                            new_statements,
                            call_name=call_name,
                        )
                        if inline_rhs is not None
                        else None
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and not typed_stack_probe_materialization
                    and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                    and isinstance(expected_arg_count, int)
                    and expected_arg_count > 0
                ):
                    carrier_rhs, consumed_indices = _collect_backtracked_value_carrier_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        carrier_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        if prune_consumed_arg_stores:
                            _delete_consumed_indices_8616(new_statements, consumed_indices)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and expected_arg_count == 1
                    and typed_stack_probe_fact is not None
                    and stack_probe_seen
                    and not is_stack_probe_helper
                    and len(new_statements) >= 1
                ):
                    candidate_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=1,
                        max_count=1,
                        typed_probe_fact=typed_stack_probe_fact,
                        call_return_addr=getattr(summary, "return_addr", None),
                    )
                    normalized_args = _normalize_materialized_call_args(
                        candidate_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and not _is_segment_register_value_expr(normalized_args[0]):
                        _set_materialized_call_args(call, [normalized_args[0]], call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, 1)
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        if prune_consumed_arg_stores:
                            _delete_consumed_indices_8616(new_statements, consumed_indices)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and call_name is not None
                    and isinstance(expected_arg_count, int)
                    and expected_arg_count > 0
                    and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                ):
                    default_args = _known_default_args_for_missing_8616(call_name, codegen)
                    if default_args is not None and len(default_args) == expected_arg_count:
                        _set_materialized_call_args(call, list(default_args), call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(default_args))
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
            elif (
                call is not None
                and not is_stack_probe_helper
                and (not isinstance(arg_count, int) or arg_count <= 0)
                and rematerialize_call_args
                and len(new_statements) >= 1
            ):
                fallback_args = None
                if isinstance(expected_arg_count, int) and expected_arg_count > 0:
                    if (
                        isinstance(push_arg_sources, tuple)
                        and len(push_arg_sources) == expected_arg_count
                        and not has_recent_stack_arg_store_evidence
                    ):
                        ordered_push_sources = (
                            list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
                        )
                        direct_args = [
                            _direct_expr_from_push_source_8616(source, call_name=call_name, arg_index=idx)
                            for idx, source in enumerate(ordered_push_sources)
                        ]
                        if all(arg is not None for arg in direct_args):
                            fallback_args = tuple(direct_args)
                    if fallback_args is None:
                        fallback_args = _known_default_args_for_missing_8616(call_name or "", codegen)
                if (
                    fallback_args is not None
                    and isinstance(expected_arg_count, int)
                    and len(fallback_args) == expected_arg_count
                ):
                    _set_materialized_call_args(call, list(fallback_args), call_name=call_name)
                    record_stack_arg_materialization_8616(codegen, len(fallback_args))
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                    if _apply_call_return_store_destination_8616(stmt, call, summary):
                        changed = True
                    new_statements.append(stmt)
                    i += 1
                    continue
                want_arg_count = 0
                if isinstance(fallback_arg_count, int) and fallback_arg_count > 0:
                    want_arg_count = max(fallback_arg_count, 1)
                allow_unbounded_collect = (
                    isinstance(fallback_arg_count, int)
                    and fallback_arg_count > 1
                ) or (
                    isinstance(known_arg_count, int) and known_arg_count > 1
                ) or (
                    isinstance(prototype_arg_count, int) and prototype_arg_count > 1
                )
                candidate_rhs, consumed_indices = _collect_backtracked_stack_args(
                    new_statements,
                    wanted_count=None if allow_unbounded_collect else want_arg_count,
                    max_count=max(want_arg_count, 4),
                    typed_probe_fact=typed_stack_probe_fact if stack_probe_seen else None,
                    allow_partial=not (isinstance(arg_count, int) and arg_count > 0),
                    call_return_addr=getattr(summary, "return_addr", None),
                )
                normalized_args = _normalize_materialized_call_args(
                    candidate_rhs,
                    consumed_indices,
                    new_statements,
                    call_name=call_name,
                )
                if (
                    normalized_args is not None
                    and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    and (
                        (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
                        or (
                            not typed_stack_probe_materialization
                            and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                        )
                    )
                ):
                    _set_materialized_call_args(call, normalized_args, call_name=call_name)
                    record_stack_arg_materialization_8616(codegen, len(normalized_args))
                    _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                    if prune_consumed_arg_stores:
                        _delete_consumed_indices_8616(new_statements, consumed_indices)
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                else:
                    if want_arg_count <= 0:
                        i += 1
                        new_statements.append(stmt)
                        continue
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, 1)
                    normalized_args = (
                        _normalize_materialized_call_args(
                            list(inline_rhs),
                            [max(i - 1, 0)],
                            new_statements,
                            call_name=call_name,
                        )
                        if inline_rhs
                        else None
                    )
                    if (
                        normalized_args is not None
                    and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    and (
                        (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
                        or (
                            not typed_stack_probe_materialization
                            and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
                        )
                    )
                    ):
                        _set_materialized_call_args(call, [normalized_args[0]], call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, 1)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
            if _apply_call_return_store_destination_8616(stmt, call, summary):
                changed = True
            new_statements.append(stmt)
            i += 1
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
            log.warning(
                "[stack-probe-artifacts] final-prune stack_probe_seen=%s statements=%d",
                stack_probe_seen,
                len(new_statements),
            )
        pruned_statements = _prune_stack_probe_frame_artifacts(
            new_statements,
            stack_probe_seen=stack_probe_seen,
            allow_setup_assignment_prune=allow_setup_assignment_prune,
        )
        if pruned_statements != new_statements:
            new_statements = pruned_statements
            changed = True
        if _materialize_final_return_call_8616(new_statements):
            changed = True

        if new_statements != statements:
            block.statements = new_statements

        for stmt in getattr(block, "statements", ()) or ():
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                (
                    child_stack_probe_seen,
                    child_stack_probe_address_seen,
                    child_typed_stack_probe_fact,
                ) = _rewrite_block(
                    stmt,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                )
                stack_probe_seen = stack_probe_seen or child_stack_probe_seen
                stack_probe_address_seen = stack_probe_address_seen or child_stack_probe_address_seen
                if child_typed_stack_probe_fact is not None:
                    typed_stack_probe_fact = child_typed_stack_probe_fact
            nested = getattr(stmt, "body", None)
            if isinstance(getattr(nested, "statements", None), (list, tuple)):
                _rewrite_block(
                    nested,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                    allow_setup_assignment_prune=False,
                )
            else_node = getattr(stmt, "else_node", None)
            if isinstance(getattr(else_node, "statements", None), (list, tuple)):
                _rewrite_block(
                    else_node,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                    allow_setup_assignment_prune=False,
                )
            for pair in getattr(stmt, "condition_and_nodes", ()) or ():
                if isinstance(pair, tuple) and len(pair) == 2:
                    branch = pair[1]
                    if isinstance(getattr(branch, "statements", None), (list, tuple)):
                        _rewrite_block(
                            branch,
                            inherited_stack_probe_seen=stack_probe_seen,
                            inherited_stack_probe_address_seen=stack_probe_address_seen,
                            inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                            allow_setup_assignment_prune=False,
                        )
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    root = _structured_root_8616(cfunc)
    if isinstance(getattr(root, "statements", None), (list, tuple)):
        if not conservative_materialization:
            _rewrite_block(root)
        elif has_push_arg_evidence:
            changed |= _conservative_call_arg_seed_8616(
                root=root,
                summary_map=summary_map,
                codegen=codegen,
                has_unverified_non_ss_stack_probe=has_unverified_non_ss_stack_probe,
                call_name_fn=_call_node_name_8616,
                expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
                known_default_args_fn=_known_default_args_for_missing_8616,
                direct_expr_from_push_source_fn=_direct_expr_from_push_source_8616,
                normalize_materialized_call_args_fn=_normalize_materialized_call_args,
                all_arg_exprs_are_non_segment_registers_fn=_all_arg_exprs_are_non_segment_registers,
                set_materialized_call_args_fn=_set_materialized_call_args,
                refresh_summary_arg_shape_fn=_refresh_summary_arg_shape,
                call_args_need_rematerialization_fn=_call_args_need_rematerialization_8616,
            )
            changed |= _seed_empty_known_helper_calls_8616(
                root=root,
                summary_map=summary_map,
                codegen=codegen,
                has_unverified_non_ss_stack_probe=has_unverified_non_ss_stack_probe,
                call_name_fn=_call_node_name_8616,
                expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
                known_default_args_fn=_known_default_args_for_missing_8616,
                direct_expr_from_push_source_fn=_direct_expr_from_push_source_8616,
                set_materialized_call_args_fn=_set_materialized_call_args,
                refresh_summary_arg_shape_fn=_refresh_summary_arg_shape,
            )
        changed |= _clear_zero_arg_known_helper_args_8616(
            root=root,
            summary_map=summary_map,
            call_name_fn=_call_node_name_8616,
            expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
            set_materialized_call_args_fn=_set_materialized_call_args,
            refresh_summary_arg_shape_fn=_refresh_summary_arg_shape,
        )
        if _restore_protected_call_args_8616(root):
            changed = True
    codegen._inertia_materialized_callsite_metadata_ids = materialized_callsite_metadata_ids
    if prune_materialized_callsite_segment_metadata_8616(project, codegen):
        changed = True
    return changed
