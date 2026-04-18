from __future__ import annotations

import re
from pathlib import Path

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort

from .cod_extract import extract_cod_proc_metadata
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import summarize_x86_16_callsite
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = [
    "_attach_callsite_summaries_8616",
    "_materialize_callsite_prototypes_8616",
    "_normalize_call_target_names_8616",
]

_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
_NAMESPACED_TARGET_RE = re.compile(r"^::0x(?P<addr>[0-9a-fA-F]+)::")


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
            getattr(getattr(project, "kb", None), "labels", None),
            getattr(getattr(project, "_inertia_lst_metadata", None), "code_labels", None),
        ):
            if labels is None:
                continue
            label = getattr(labels, "get", lambda _addr: None)(lookup_addr)
            if isinstance(label, str) and label:
                candidates.append(label)

    if original_project is not None and isinstance(original_delta, int):
        for lookup_addr in sorted(lookup_addrs):
            for labels in (
                getattr(getattr(original_project, "kb", None), "labels", None),
                getattr(getattr(original_project, "_inertia_lst_metadata", None), "code_labels", None),
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

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    call_nodes = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall)]
    callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
    if not call_nodes or not callsite_addrs:
        return False

    changed = False
    summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
    for node, callsite_addr in zip(call_nodes, callsite_addrs):
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is None:
            continue
        if summary_map.get(id(node)) != summary:
            summary_map[id(node)] = summary
            changed = True
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            continue
        callee_func = getattr(node, "callee_func", None)
        if callee_func is None:
            candidate = project.kb.functions.function(addr=target_addr, create=False)
            if candidate is not None:
                node.callee_func = candidate
                changed = True
                callee_func = candidate
        sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
        if callee_func is not None and isinstance(sidecar_label, str):
            callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
            if callee_name is None or callee_name.startswith("sub_"):
                callee_func.name = sidecar_label
                changed = True
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        if callee_name is not None and getattr(node, "callee_target", None) != callee_name:
            node.callee_target = callee_name
            changed = True
        elif _rename_call_node_from_sidecar_8616(project, node):
            changed = True
    if summary_map:
        codegen._inertia_callsite_summaries = summary_map
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
        if _apply_summary_prototype_8616(project, getattr(node, "callee_func", None), summary):
            changed = True
    return changed
