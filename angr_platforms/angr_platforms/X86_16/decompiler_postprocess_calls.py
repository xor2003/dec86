from __future__ import annotations

from copy import copy
from dataclasses import replace
import re
from pathlib import Path

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from .analysis_helpers import patch_direct_call_sites
from .cod_extract import extract_cod_proc_metadata
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import summarize_x86_16_callsite
from .callsite_stack_metadata import prune_materialized_callsite_segment_metadata_8616
from .lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_dereference_8616,
    _match_real_mode_linear_expr_8616,
    _match_real_mode_segmented_store_shape_8616,
    _replace_c_children_8616,
    _segment_reg_name_8616,
    _match_segmented_dereference_8616,
    _same_c_expression_8616,
)
from .stack_probe_fact_trace import (
    record_callsite_summary_fact_8616,
    record_callsite_summary_map_facts_8616,
    record_stack_arg_materialization_8616,
)

__all__ = [
    "_attach_callsite_summaries_8616",
    "_materialize_callsite_stack_arguments_8616",
    "_materialize_callsite_prototypes_8616",
    "_normalize_call_target_names_8616",
]

_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
_NAMESPACED_TARGET_RE = re.compile(r"^::0x(?P<addr>[0-9a-fA-F]+)::")


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


def _lookup_callee_function_8616(project, target_addr: int):
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
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", lambda **_: None)
        for candidate_addr in ordered_addrs:
            function = lookup(addr=candidate_addr, create=False)
            if function is not None:
                return function
    return None


def _sidecar_label_for_target_8616(project, target_addr: int) -> str | None:
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

    for label in candidates:
        normalized = normalize_callee_name_8616(label.lstrip("_"))
        if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
            return normalized
    return None


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


def _cod_metadata_for_function_8616(project, func_addr: int):
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
                except Exception:
                    continue
                cache[cache_key] = metadata
                if binary_path is not None:
                    cache[(str(binary_path), candidate, proc_kind)] = metadata
                return metadata
    return None


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


def _call_name_is_unknown_8616(name: str | None) -> bool:
    return name is None or name.startswith("sub_") or name == "CallReturn"


def _call_node_matches_summary_8616(project, node, summary) -> bool:
    if node is None or summary is None:
        return False
    call_name = _call_node_name_8616(node)
    if bool(getattr(summary, "stack_probe_helper", False)) and _is_stack_probe_call_name_8616(call_name):
        return True

    target_addr = getattr(summary, "target_addr", None)
    if isinstance(target_addr, int):
        for candidate_addr in _candidate_target_addrs_from_call_8616(node):
            if candidate_addr == target_addr:
                return True
        for candidate_name in (
            _sidecar_label_for_target_8616(project, target_addr),
            normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
        ):
            if isinstance(candidate_name, str) and candidate_name == call_name:
                return True
    return False


def _source_name_matches_target_8616(project, target_addr: int | None, expected_source_name: str | None) -> bool:
    if not isinstance(expected_source_name, str) or not expected_source_name:
        return False
    normalized_expected = normalize_callee_name_8616(expected_source_name)
    if not isinstance(normalized_expected, str):
        return False
    if not isinstance(target_addr, int):
        return True
    for candidate_name in (
        _sidecar_label_for_target_8616(project, target_addr),
        normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
    ):
        if isinstance(candidate_name, str) and candidate_name == normalized_expected:
            return True
    functions = getattr(getattr(project, "kb", None), "functions", None)
    function = getattr(functions, "function", lambda **_: None)(name=normalized_expected, create=False)
    return getattr(function, "addr", None) == target_addr


def _align_cod_call_names_8616(project, codegen) -> bool:
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
    call_nodes = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall)]
    if not call_nodes:
        return False

    changed = False
    cod_idx = 0
    for node in call_nodes:
        current_name = _call_node_name_8616(node)
        if not _call_name_is_unknown_8616(current_name):
            while cod_idx < len(cod_call_names) and cod_call_names[cod_idx] != current_name:
                cod_idx += 1
            if cod_idx < len(cod_call_names) and cod_call_names[cod_idx] == current_name:
                cod_idx += 1
                continue
            continue
        if cod_idx >= len(cod_call_names):
            break
        replacement = cod_call_names[cod_idx]
        cod_idx += 1
        if not isinstance(replacement, str) or not replacement or replacement.startswith("sub_"):
            continue
        callee_func = getattr(node, "callee_func", None)
        if callee_func is not None and getattr(callee_func, "name", None) != replacement:
            callee_func.name = replacement
            changed = True
        if getattr(node, "callee_target", None) != replacement:
            node.callee_target = replacement
            changed = True
    return changed


def _normalize_call_target_names_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    project = getattr(codegen, "project", None)
    changed = False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue

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

        if _rename_call_node_from_sidecar_8616(project, node):
            changed = True

    if _align_cod_call_names_8616(project, codegen):
        changed = True

    return changed


def _cod_source_call_names_8616(project, func_addr: int) -> tuple[str, ...]:
    cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
    if cod_metadata is None:
        return ()
    names: list[str] = []
    for item in getattr(cod_metadata, "call_sources", ()) or ():
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        normalized = normalize_callee_name_8616(item[0])
        if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
            names.append(normalized)
    return tuple(names)


def _summary_type_8616(project, width: int):
    arch = getattr(project, "arch", None)
    if width >= 4:
        ty = SimTypeLong(False)
    else:
        ty = SimTypeShort(False)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _summary_return_type_8616(project, summary):
    if getattr(summary, "return_register", None) == "ax" and getattr(summary, "return_used", None) is True:
        return _summary_type_8616(project, 2)
    ty = SimTypeBottom()
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
    if callee_func is None or not _prototype_needs_summary_8616(getattr(callee_func, "prototype", None)):
        return False
    arg_count = getattr(summary, "arg_count", None)
    if not isinstance(arg_count, int):
        return False
    arg_widths = tuple(getattr(summary, "arg_widths", ()) or ())
    if arg_count != len(arg_widths):
        return False
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


def _attach_callsite_summaries_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    patch_direct_call_sites(function)

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    call_nodes = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall)]
    callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
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

    changed = False
    summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
    source_call_names = _cod_source_call_names_8616(project, func_addr)
    source_call_idx = 0
    nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
    remaining_nodes: list[CFunctionCall] = []
    for node in call_nodes:
        callsite_addr = _node_callsite_addr(node)
        if isinstance(callsite_addr, int):
            nodes_by_callsite.setdefault(callsite_addr, []).append(node)
        else:
            remaining_nodes.append(node)

    ordered_pairs: list[tuple[CFunctionCall, int]] = []
    used_node_ids: set[int] = set()
    unmatched_callsites: list[int] = []
    for callsite_addr in callsite_addrs:
        matched_nodes = nodes_by_callsite.get(callsite_addr)
        if matched_nodes:
            node = matched_nodes.pop(0)
            ordered_pairs.append((node, callsite_addr))
            used_node_ids.add(id(node))
        else:
            unmatched_callsites.append(callsite_addr)

    remaining_nodes.extend(node for node in call_nodes if id(node) not in used_node_ids and node not in remaining_nodes)
    still_unmatched_callsites: list[int] = []
    if remaining_nodes and unmatched_callsites:
        available_nodes = list(remaining_nodes)
        for callsite_addr in unmatched_callsites:
            summary = summarize_x86_16_callsite(function, callsite_addr)
            matched_index = None
            if summary is not None:
                for idx, node in enumerate(available_nodes):
                    if _call_node_matches_summary_8616(project, node, summary):
                        matched_index = idx
                        break
            if matched_index is None:
                still_unmatched_callsites.append(callsite_addr)
                continue
            node = available_nodes.pop(matched_index)
            ordered_pairs.append((node, callsite_addr))
            used_node_ids.add(id(node))
        remaining_nodes = available_nodes
    if len(remaining_nodes) == 1 and len(still_unmatched_callsites) == 1:
        ordered_pairs.append((remaining_nodes[0], still_unmatched_callsites[0]))

    for node, callsite_addr in ordered_pairs:
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is None:
            continue
        expected_source_name = None
        if not bool(getattr(summary, "stack_probe_helper", False)) and source_call_idx < len(source_call_names):
            expected_source_name = source_call_names[source_call_idx]
            source_call_idx += 1
        if summary_map.get(id(node)) != summary:
            summary_map[id(node)] = summary
            record_callsite_summary_fact_8616(codegen, summary, node_id=id(node), attached=True)
            changed = True
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            continue
        callee_func = getattr(node, "callee_func", None)
        candidate = _lookup_callee_function_8616(project, target_addr)
        if candidate is not None:
            current_addr = getattr(callee_func, "addr", None)
            candidate_addr = getattr(candidate, "addr", None)
            if callee_func is None or (isinstance(current_addr, int) and isinstance(candidate_addr, int) and current_addr != candidate_addr):
                node.callee_func = candidate
                changed = True
                callee_func = candidate
        sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
        if callee_func is None and isinstance(sidecar_label, str) and getattr(node, "callee_target", None) != sidecar_label:
            node.callee_target = sidecar_label
            changed = True
        if _callee_name_should_yield_to_sidecar_8616(callee_func, sidecar_label):
            callee_func.name = sidecar_label
            changed = True
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        if (
            isinstance(expected_source_name, str)
            and callee_func is not None
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            and (
                callee_name is None
                or callee_name.startswith("sub_")
                or (len(tuple(getattr(callee_func, "block_addrs_set", ()) or ())) == 0 and callee_name != expected_source_name)
            )
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
    if summary_map:
        codegen._inertia_callsite_summaries = summary_map
    return changed


def _refresh_callsite_summary_node_ids_8616(codegen, summary_map: dict[int, object]) -> bool:
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

    call_nodes = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall)]
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
    return changed


def _materialize_callsite_prototypes_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict) or not summary_map:
        return False
    changed = False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summary_map.get(id(node))
        if summary is None:
            continue
        if getattr(summary, "arg_count", None) == 0 and tuple(getattr(node, "args", ()) or ()):
            continue
        if _apply_summary_prototype_8616(project, getattr(node, "callee_func", None), summary):
            changed = True
    return changed


def _materialize_callsite_stack_arguments_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    typed_stack_probe_facts = build_typed_stack_probe_return_facts_8616(codegen)
    record_callsite_summary_map_facts_8616(codegen, summary_map)

    changed = False
    materialized_callsite_metadata_ids: dict[int, tuple[int, ...]] = {}
    def _arg_width_from_expr(expr) -> int:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
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
        project = getattr(codegen, "project", None)
        if project is None:
            return False
        seg_name = _segment_reg_name_8616(node, project)
        return seg_name in {"cs", "ds", "es", "ss"}

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
            getattr(variable, "name", None) or getattr(node, "name", None),
        )

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
        if not _is_plain_register_value_expr(expr):
            return expr
        for stmt in reversed(tuple(statements_prefix)):
            for assignment in reversed(_iter_assignment_nodes(stmt)):
                lhs, rhs = _assignment_lhs_rhs(assignment)
                if lhs is None or rhs is None:
                    continue
                if not _same_c_expression_8616(lhs, expr):
                    continue
                if _assignment_lhs_writes_memory(lhs) or _is_segment_register_value_expr(rhs):
                    return None
                if _same_c_expression_8616(rhs, expr):
                    return None
                return rhs
        return None

    def _expr_contains_plain_register_uses(expr) -> bool:
        stack = [expr]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            while isinstance(node, CTypeCast):
                node = node.expr
            if _is_plain_register_value_expr(node):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse"):
                child = getattr(node, attr, None)
                if child is not None:
                    stack.append(child)
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
            if failed or not _is_plain_register_value_expr(node):
                return node
            key = _plain_register_expr_key(node)
            if key is not None and key in seen_keys:
                failed = True
                return node
            resolved = _resolve_recent_value_assignment(node, statements_prefix)
            if resolved is None:
                failed = True
                return node
            next_seen = set(seen_keys)
            if key is not None:
                next_seen.add(key)
            resolved = _resolve_register_carriers_in_expr(resolved, statements_prefix, next_seen)
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

    def _normalize_materialized_call_args(rhs_values: list, source_indices: list[int], statements: list):
        if not rhs_values:
            return None
        if all(
            not _is_segment_register_value_expr(rhs) and not _expr_contains_plain_register_uses(rhs)
            for rhs in rhs_values
        ):
            return list(rhs_values)
        normalized = []
        if len(source_indices) != len(rhs_values):
            source_indices = [-1] * len(rhs_values)
        for rhs, source_idx in zip(rhs_values, source_indices):
            if _is_segment_register_value_expr(rhs):
                return None
            if not _expr_contains_plain_register_uses(rhs):
                normalized.append(rhs)
                continue
            prefix = statements[:source_idx] if isinstance(source_idx, int) and source_idx >= 0 else statements
            resolved = _resolve_register_carriers_in_expr(rhs, prefix)
            if resolved is None:
                return None
            expr = _clone_c_ast_tree(resolved)
            if _is_segment_register_value_expr(expr) or _expr_contains_plain_register_uses(expr):
                return None
            normalized.append(expr)
        return normalized

    def _prototype_arg_count(call) -> int | None:
        callee_func = getattr(call, "callee_func", None)
        prototype = getattr(callee_func, "prototype", None)
        args = getattr(prototype, "args", None)
        if isinstance(args, (list, tuple)):
            return len(args)
        return None

    def _refresh_summary_arg_shape(call, summary) -> None:
        nonlocal changed
        if summary is None:
            return
        args = tuple(getattr(call, "args", ()) or ())
        if not args:
            return
        arg_widths = tuple(_arg_width_from_expr(arg) for arg in args)
        updated = replace(summary, arg_count=len(arg_widths), arg_widths=arg_widths)
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

    def _call_from_statement(stmt):
        if isinstance(stmt, CFunctionCall):
            return stmt
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return expr
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
                if isinstance(node, CUnaryOp) and node.op == "Dereference" and _contains_ss_evidence(
                    getattr(node, "operand", None)
                ):
                    return True
            return False

        def _contains_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ == "CDirtyExpression":
                    return True
            return False

        def _is_virtual_dirty_expr(term) -> bool:
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

        def _contains_unresolved_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ != "CDirtyExpression":
                    continue
                if _is_virtual_dirty_expr(raw_node):
                    continue
                return True
            return False

        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if lhs is None:
                continue
            if _contains_unresolved_dirty_expr(lhs):
                continue
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
            if _contains_ss_evidence(getattr(deref, "operand", None)):
                return rhs
        return None

    def _store_matches_typed_stack_probe_fact(lhs, fact: TypedStackProbeReturnFact8616 | None) -> bool:
        if lhs is None or fact is None:
            return False
        seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if seg_name != fact.segment_space:
            return False

        def _contains_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ == "CDirtyExpression":
                    return True
            return False

        return not any(_contains_dirty_expr(term) for _sign, term in _offset_terms)

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

    def _is_stack_carrier_temp_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None:
            return False
        variable = getattr(lhs, "variable", None)
        name = getattr(variable, "name", None) or getattr(lhs, "name", None)
        if not isinstance(name, str) or not (
            name.startswith("vvar_") or name.startswith("ir_") or name.startswith("tmp_")
        ):
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

    def _assignment_lhs_writes_memory(lhs) -> bool:
        if lhs is None:
            return False
        nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
        for raw_node in nodes:
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
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
    ) -> tuple[list, list]:
        rhs_values: list = []
        consumed_indices: list[int] = []
        skipped_carriers = 0
        skipped_value_assignments = 0
        limit = max_count if wanted_count is None else max(wanted_count, 1)
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < limit:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                break
            rhss = (
                _typed_stack_store_rhss_from_statement(stmt, typed_probe_fact, max_collect=max_count)
                if typed_probe_fact is not None
                else _stack_store_rhss_from_statement(stmt, max_collect=max_count)
            )
            if rhss:
                if all(_is_segment_register_value_expr(rhs) for rhs in rhss):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    idx -= 1
                    continue
                rhs_values.extend(reversed(rhss))
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
                if skipped_value_assignments > 8:
                    break
                idx -= 1
                continue
            break
        if wanted_count is not None and len(rhs_values) != wanted_count:
            return [], []
        rhs_values.reverse()
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

        for idx in sorted(consumed_indices, reverse=True):
            del sequence[idx]
        stmt.statements = sequence if isinstance(nested_statements, list) else tuple(sequence)
        rhs_values.reverse()
        return tuple(rhs_values)

    def _rewrite_block(
        block,
        *,
        inherited_stack_probe_seen: bool = False,
        inherited_stack_probe_address_seen: bool = False,
        inherited_typed_stack_probe_fact: TypedStackProbeReturnFact8616 | None = None,
    ) -> tuple[bool, bool, TypedStackProbeReturnFact8616 | None]:
        nonlocal changed
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
        while i < len(statements):
            stmt = statements[i]
            call = _call_from_statement(stmt)
            summary = summary_map.get(id(call)) if call is not None else None
            arg_count = getattr(summary, "arg_count", None) if summary is not None else None
            call_name = _call_node_name_8616(call) if call is not None else None
            prototype_arg_count = _prototype_arg_count(call) if call is not None else None
            is_stack_probe_helper = bool(getattr(summary, "stack_probe_helper", False))
            if call is not None and not is_stack_probe_helper and _is_stack_probe_call_name_8616(call_name):
                is_stack_probe_helper = True
            if is_stack_probe_helper:
                stack_probe_seen = True
                typed_stack_probe_fact = typed_stack_probe_facts.get(id(call)) if call is not None else None
                if typed_stack_probe_fact is not None:
                    stack_probe_address_seen = True
                elif summary is None:
                    # Legacy path: keep previous behavior when callsite summary was not attached.
                    stack_probe_address_seen = True
            # A typed stack-probe fact is strong evidence for a helper-returned SS
            # address. If no typed fact exists, direct segmented SS stores before the
            # call remain valid evidence and the generic stack-arg backtracker must
            # stay enabled.
            typed_stack_probe_materialization = (
                typed_stack_probe_fact is not None and stack_probe_seen and not is_stack_probe_helper
            )
            expected_arg_count = arg_count
            if isinstance(prototype_arg_count, int) and prototype_arg_count > 0:
                if not isinstance(expected_arg_count, int) or expected_arg_count <= 0:
                    expected_arg_count = prototype_arg_count
                elif typed_stack_probe_materialization and prototype_arg_count > expected_arg_count:
                    expected_arg_count = prototype_arg_count
            if (
                call is not None
                and isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and not getattr(call, "args", None)
            ):
                strict_arg_shape_applied = False
                if len(new_statements) >= expected_arg_count:
                    candidate_stmts = new_statements[-expected_arg_count:]
                    candidate_rhs = [_stack_store_rhs_from_statement(candidate) for candidate in candidate_stmts]
                    candidate_indices = list(range(len(new_statements) - expected_arg_count, len(new_statements)))
                    normalized_args = (
                        _normalize_materialized_call_args(candidate_rhs, candidate_indices, new_statements)
                        if all(rhs is not None for rhs in candidate_rhs)
                        else None
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        call.args = list(normalized_args)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(
                            call,
                            new_statements,
                            candidate_indices,
                        )
                        del new_statements[-expected_arg_count:]
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
                        wanted_count=None,
                        max_count=4,
                        typed_probe_fact=typed_stack_probe_fact,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        expanded_rhs,
                        list(reversed(consumed_indices)),
                        new_statements,
                    )
                    if (
                        normalized_args is not None
                        and len(normalized_args) > expected_arg_count
                        and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    ):
                        call.args = list(normalized_args)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
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
                    )
                    normalized_args = _normalize_materialized_call_args(
                        typed_rhs,
                        list(reversed(consumed_indices)),
                        new_statements,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        call.args = list(normalized_args)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied and not typed_stack_probe_materialization:
                    backtracked_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        backtracked_rhs,
                        list(reversed(consumed_indices)),
                        new_statements,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        call.args = list(normalized_args)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied and not typed_stack_probe_materialization:
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, expected_arg_count)
                    normalized_args = (
                        _normalize_materialized_call_args(
                            list(inline_rhs),
                            list(range(max(0, i - len(inline_rhs)), i)),
                            new_statements,
                        )
                        if inline_rhs is not None
                        else None
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        call.args = list(normalized_args)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
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
                    )
                    normalized_args = _normalize_materialized_call_args(
                        candidate_rhs,
                        list(reversed(consumed_indices)),
                        new_statements,
                    )
                    if normalized_args is not None and not _is_segment_register_value_expr(normalized_args[0]):
                        call.args = [normalized_args[0]]
                        record_stack_arg_materialization_8616(codegen, 1)
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
            elif (
                call is not None
                and not is_stack_probe_helper
                and (not isinstance(arg_count, int) or arg_count <= 0)
                and not getattr(call, "args", None)
                and len(new_statements) >= 1
            ):
                candidate_rhs, consumed_indices = _collect_backtracked_stack_args(
                    new_statements,
                    wanted_count=None,
                    max_count=4,
                    typed_probe_fact=typed_stack_probe_fact if stack_probe_seen else None,
                )
                normalized_args = _normalize_materialized_call_args(
                    candidate_rhs,
                    list(reversed(consumed_indices)),
                    new_statements,
                )
                if (
                    normalized_args is not None
                    and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    and (
                        (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
                        or (not typed_stack_probe_materialization)
                        or (typed_stack_probe_fact is None and stack_probe_seen and stack_probe_address_seen and not is_stack_probe_helper)
                        or (not stack_probe_seen and summary is None)
                    )
                ):
                    call.args = list(normalized_args)
                    record_stack_arg_materialization_8616(codegen, len(normalized_args))
                    _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                    for consume_idx in sorted(consumed_indices, reverse=True):
                        del new_statements[consume_idx]
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                else:
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, 1)
                    normalized_args = (
                        _normalize_materialized_call_args(
                            list(inline_rhs),
                            [max(i - 1, 0)],
                            new_statements,
                        )
                        if inline_rhs
                        else None
                    )
                    if (
                        normalized_args is not None
                        and _all_arg_exprs_are_non_segment_registers(normalized_args)
                        and (
                            (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
                            or (not typed_stack_probe_materialization)
                            or (typed_stack_probe_fact is None and stack_probe_seen and stack_probe_address_seen and not is_stack_probe_helper)
                            or (not stack_probe_seen and summary is None)
                        )
                    ):
                        call.args = [normalized_args[0]]
                        record_stack_arg_materialization_8616(codegen, 1)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
            new_statements.append(stmt)
            i += 1
        if new_statements != statements:
            block.statements = new_statements

        for stmt in getattr(block, "statements", ()) or ():
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact = _rewrite_block(
                    stmt,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                )
            nested = getattr(stmt, "body", None)
            if isinstance(getattr(nested, "statements", None), (list, tuple)):
                _rewrite_block(
                    nested,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                )
            else_node = getattr(stmt, "else_node", None)
            if isinstance(getattr(else_node, "statements", None), (list, tuple)):
                _rewrite_block(
                    else_node,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
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
                        )
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    if isinstance(getattr(root, "statements", None), (list, tuple)):
        _rewrite_block(root)
    codegen._inertia_materialized_callsite_metadata_ids = materialized_callsite_metadata_ids
    if prune_materialized_callsite_segment_metadata_8616(project, codegen):
        changed = True
    return changed
