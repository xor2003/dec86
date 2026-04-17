from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort

from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import summarize_x86_16_callsite
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = [
    "_attach_callsite_summaries_8616",
    "_materialize_callsite_prototypes_8616",
    "_normalize_call_target_names_8616",
]


def _normalize_call_target_names_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

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
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        if callee_name is not None and getattr(node, "callee_target", None) != callee_name:
            node.callee_target = callee_name
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
