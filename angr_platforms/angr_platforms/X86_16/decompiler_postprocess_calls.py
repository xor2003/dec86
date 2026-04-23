from __future__ import annotations

from dataclasses import replace
import re
from pathlib import Path

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort

from .analysis_helpers import patch_direct_call_sites
from .cod_extract import extract_cod_proc_metadata
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import summarize_x86_16_callsite
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_dereference_8616,
    _match_real_mode_linear_expr_8616,
    _match_segmented_dereference_8616,
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
    ordered_pairs.extend(zip(remaining_nodes, unmatched_callsites))

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
            and getattr(node, "callee_target", None) != expected_source_name
        ):
            node.callee_target = expected_source_name
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
        if getattr(summary, "arg_count", None) == 0 and tuple(getattr(node, "args", ()) or ()):
            continue
        if _apply_summary_prototype_8616(project, getattr(node, "callee_func", None), summary):
            changed = True
    return changed


def _materialize_callsite_stack_arguments_8616(project, codegen) -> bool:
    del project
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}

    changed = False
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

    def _call_from_statement(stmt):
        if isinstance(stmt, CFunctionCall):
            return stmt
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return expr
        for node in _iter_c_nodes_deep_8616(stmt):
            if isinstance(node, CFunctionCall):
                return node
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

        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if lhs is None:
                continue
            if _match_bp_stack_dereference_8616(lhs, project, codegen) is not None:
                return rhs
            seg_name, _linear = _match_segmented_dereference_8616(lhs, project)
            if seg_name == "ss":
                return rhs
            deref = lhs
            while isinstance(deref, CTypeCast):
                deref = deref.expr
            if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
                continue
            if _contains_ss_evidence(getattr(deref, "operand", None)):
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

    def _collect_backtracked_stack_args(
        statements: list,
        *,
        wanted_count: int | None = None,
        max_count: int = 4,
    ) -> tuple[list, list]:
        rhs_values: list = []
        consumed_indices: list[int] = []
        skipped_carriers = 0
        limit = max_count if wanted_count is None else max(wanted_count, 1)
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < limit:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                break
            rhss = _stack_store_rhss_from_statement(stmt, max_collect=max_count)
            if rhss:
                rhs_values.extend(reversed(rhss))
                consumed_indices.append(idx)
                idx -= 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                skipped_carriers += 1
                if skipped_carriers > 4:
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

    def _rewrite_block(block) -> None:
        nonlocal changed
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return
        statements = list(statements)
        new_statements = []
        i = 0
        stack_probe_seen = any(bool(getattr(item, "stack_probe_helper", False)) for item in summary_map.values())
        stack_probe_address_seen = any(
            bool(getattr(item, "stack_probe_helper", False))
            and getattr(item, "helper_return_state", None) == "stack_address"
            and getattr(item, "helper_return_space", None) in {None, "ss"}
            for item in summary_map.values()
        )
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
                if getattr(summary, "helper_return_state", None) == "stack_address" and (
                    getattr(summary, "helper_return_space", None) in {None, "ss"}
                ):
                    stack_probe_address_seen = True
                elif summary is None:
                    # Legacy path: keep previous behavior when callsite summary was not attached.
                    stack_probe_address_seen = True
            expected_arg_count = arg_count
            if isinstance(prototype_arg_count, int) and prototype_arg_count > 0:
                if not isinstance(expected_arg_count, int) or expected_arg_count <= 0:
                    expected_arg_count = prototype_arg_count
                elif stack_probe_seen and prototype_arg_count > expected_arg_count:
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
                    if all(rhs is not None for rhs in candidate_rhs):
                        call.args = list(candidate_rhs)
                        del new_statements[-expected_arg_count:]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied:
                    backtracked_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                    )
                    if backtracked_rhs:
                        call.args = list(backtracked_rhs)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied:
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, expected_arg_count)
                    if inline_rhs:
                        call.args = list(inline_rhs)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and expected_arg_count == 1
                    and stack_probe_address_seen
                    and stack_probe_seen
                    and not is_stack_probe_helper
                    and len(new_statements) >= 1
                ):
                    candidate_rhs = _stack_store_rhs_from_statement(new_statements[-1])
                    if candidate_rhs is not None:
                        call.args = [candidate_rhs]
                        del new_statements[-1:]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
            elif (
                call is not None
                and not is_stack_probe_helper
                and (not isinstance(arg_count, int) or arg_count <= 0)
                and not getattr(call, "args", None)
                and len(new_statements) >= 1
            ):
                candidate_rhs, consumed_indices = _collect_backtracked_stack_args(new_statements, wanted_count=None, max_count=4)
                if candidate_rhs and (stack_probe_address_seen or stack_probe_seen or summary is None):
                    call.args = list(candidate_rhs)
                    for consume_idx in sorted(consumed_indices, reverse=True):
                        del new_statements[consume_idx]
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                else:
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, 1)
                    if inline_rhs and (stack_probe_address_seen or stack_probe_seen or summary is None):
                        call.args = [inline_rhs[0]]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
            new_statements.append(stmt)
            i += 1
        if new_statements != statements:
            block.statements = new_statements

        for stmt in getattr(block, "statements", ()) or ():
            nested = getattr(stmt, "body", None)
            if isinstance(getattr(nested, "statements", None), (list, tuple)):
                _rewrite_block(nested)
            else_node = getattr(stmt, "else_node", None)
            if isinstance(getattr(else_node, "statements", None), (list, tuple)):
                _rewrite_block(else_node)
            for pair in getattr(stmt, "condition_and_nodes", ()) or ():
                if isinstance(pair, tuple) and len(pair) == 2:
                    branch = pair[1]
                    if isinstance(getattr(branch, "statements", None), (list, tuple)):
                        _rewrite_block(branch)

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    if isinstance(getattr(root, "statements", None), (list, tuple)):
        _rewrite_block(root)
    return changed
