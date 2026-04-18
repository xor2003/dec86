from __future__ import annotations

import re

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CStatements,
    CConstant,
    CFunctionCall,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .callee_name_normalization import normalize_callee_name_8616
from .decompiler_postprocess_calls import _cod_metadata_for_function_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_dereference_8616,
    _match_segmented_dereference_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)

__all__ = [
    "TAIL_VALIDATION_FINGERPRINT_VERSION",
    "_bool_projection_fingerprint",
    "_c_constant_int_value",
    "_expr_fingerprint",
    "_extract_same_zero_compare_expr_8616",
    "_extract_zero_flag_source_expr_8616",
    "_function_for_call_context_8616",
    "build_x86_16_contextual_call_fingerprints",
    "_lookup_function_for_call_context_8616",
    "_location_fingerprint",
    "_normalize_zero_flag_comparison_8616",
    "_register_name",
    "_wrap_not_fingerprint",
]


TAIL_VALIDATION_FINGERPRINT_VERSION = 5
_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")


def _segment_linear_lowering_allowed(node, segment_reg: str) -> bool:
    codegen = getattr(node, "codegen", None)
    lowering = getattr(codegen, "_inertia_segmented_memory_lowering", None)
    if not isinstance(lowering, dict):
        return False
    entry = lowering.get(segment_reg.upper())
    return isinstance(entry, dict) and bool(entry.get("allow_linear_lowering", False))

def _register_name(project, reg_offset: int) -> str:
    name = project.arch.register_names.get(reg_offset)
    return name if isinstance(name, str) else f"reg@{reg_offset}"


def _c_constant_int_value(node) -> int | None:
    if isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int):
        return node.value
    return None


def _wrap_not_fingerprint(fingerprint: str) -> str:
    if fingerprint.startswith("Not(") and fingerprint.endswith(")"):
        return fingerprint[4:-1]
    return f"Not({fingerprint})"


def _stack_word_pair_fingerprint(node, project) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    deref_low = _extract_deref_node(left)
    deref_high = _extract_deref_scaled_node(right, scale=256)
    if deref_low is None or deref_high is None:
        deref_low = _extract_deref_node(right)
        deref_high = _extract_deref_scaled_node(left, scale=256)
    if deref_low is None or deref_high is None:
        return None
    low_offset = _match_bp_stack_dereference_8616(deref_low, project)
    high_offset = _match_bp_stack_dereference_8616(deref_high, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return f"stack:{low_offset:+#x}"


def _extract_deref_node(node):
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        return node
    return None


def _extract_deref_scaled_node(node, *, scale: int):
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or node.op != "Mul":
        return None
    if _c_constant_int_value(node.lhs) == scale:
        return _extract_deref_node(node.rhs)
    if _c_constant_int_value(node.rhs) == scale:
        return _extract_deref_node(node.lhs)
    return None


def _bool_projection_fingerprint(node, project) -> str | None:
    while isinstance(node, CTypeCast):
        node = node.expr

    if isinstance(node, CUnaryOp) and node.op == "Not":
        operand = getattr(node, "operand", None)
        inner = _bool_projection_fingerprint(operand, project)
        if inner is not None:
            return _wrap_not_fingerprint(inner)
        if isinstance(operand, CUnaryOp) and operand.op == "Not":
            return _expr_fingerprint(operand.operand, project)
        return None

    if not isinstance(node, CITE):
        return None

    iftrue = _c_constant_int_value(getattr(node, "iftrue", None))
    iffalse = _c_constant_int_value(getattr(node, "iffalse", None))
    if (iftrue, iffalse) == (1, 0):
        inner = _bool_projection_fingerprint(node.cond, project)
        return inner if inner is not None else _expr_fingerprint(node.cond, project)
    if (iftrue, iffalse) == (0, 1):
        inner = _bool_projection_fingerprint(node.cond, project)
        if inner is None:
            inner = _expr_fingerprint(node.cond, project)
        return _wrap_not_fingerprint(inner)
    return None


def _extract_same_zero_compare_expr_8616(node):
    if not isinstance(node, CBinaryOp) or node.op != "CmpEQ":
        return None
    if _c_constant_int_value(node.rhs) == 0:
        return node.lhs
    if _c_constant_int_value(node.lhs) == 0:
        return node.rhs
    return None


def _extract_zero_flag_source_expr_8616(node):
    if isinstance(node, CBinaryOp):
        if node.op == "Mul":
            for maybe_logic, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_int_value(maybe_scale) != 64:
                    continue
                source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                if source_expr is not None:
                    return source_expr
                if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                    continue
                lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                    return lhs_expr

        for child in (node.lhs, node.rhs):
            if _structured_codegen_node_8616(child):
                extracted = _extract_zero_flag_source_expr_8616(child)
                if extracted is not None:
                    return extracted

    elif isinstance(node, CUnaryOp):
        child = getattr(node, "operand", None)
        if _structured_codegen_node_8616(child):
            return _extract_zero_flag_source_expr_8616(child)

    elif isinstance(node, CTypeCast):
        child = getattr(node, "expr", None)
        if _structured_codegen_node_8616(child):
            return _extract_zero_flag_source_expr_8616(child)

    return None


def _normalize_zero_flag_comparison_8616(node):
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _c_constant_int_value(node.rhs) == 0:
        source = node.lhs
    elif _c_constant_int_value(node.lhs) == 0:
        source = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr_8616(source)
    if source_expr is None:
        return node
    if node.op == "CmpEQ":
        return source_expr
    return CUnaryOp("Not", source_expr, codegen=getattr(node, "codegen", None))


def _expr_fingerprint(node, project) -> str:
    if node is None:
        return "none"
    stack_pair = _stack_word_pair_fingerprint(node, project)
    if stack_pair is not None:
        return stack_pair
    bool_projection = _bool_projection_fingerprint(node, project)
    if bool_projection is not None:
        return bool_projection
    node = _normalize_zero_flag_comparison_8616(node)
    if isinstance(node, CConstant):
        return f"const:{node.value!r}"
    if isinstance(node, CVariable):
        return _location_fingerprint(node, project)
    if isinstance(node, CTypeCast):
        return f"cast:{_expr_fingerprint(node.expr, project)}"
    if isinstance(node, CUnaryOp):
        return f"{node.op}({_expr_fingerprint(node.operand, project)})"
    if isinstance(node, CBinaryOp):
        lhs = _expr_fingerprint(node.lhs, project)
        rhs = _expr_fingerprint(node.rhs, project)
        return f"{node.op}({lhs},{rhs})"
    if isinstance(node, CFunctionCall):
        callee = _call_target_name(node, project)
        args = ",".join(_expr_fingerprint(arg, project) for arg in getattr(node, "args", ()) or ())
        return f"call:{callee}({args})"
    return type(node).__name__


def _call_target_name(node: CFunctionCall, project) -> str:
    callee_func = getattr(node, "callee_func", None)
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        return f"addr:{callee_addr:#x}"
    callee = getattr(node, "callee_target", None)
    normalized_callee = normalize_callee_name_8616(callee)
    if isinstance(normalized_callee, str):
        match = _SUB_TARGET_RE.match(normalized_callee)
        if match is not None:
            try:
                return f"addr:{int(match.group('addr'), 16):#x}"
            except ValueError:
                pass
        functions = getattr(getattr(project, "kb", None), "functions", None)
        function = getattr(functions, "function", lambda **_: None)(name=normalized_callee, create=False)
        resolved_addr = getattr(function, "addr", None)
        if isinstance(resolved_addr, int):
            return f"addr:{resolved_addr:#x}"
    if isinstance(normalized_callee, str):
        return normalized_callee
    name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if isinstance(name, str):
        function = getattr(getattr(project, "kb", None), "functions", None)
        function = getattr(function, "function", lambda **_: None)(name=name, create=False)
        resolved_addr = getattr(function, "addr", None)
        if isinstance(resolved_addr, int):
            return f"addr:{resolved_addr:#x}"
    if isinstance(name, str):
        return name
    return "<indirect>"


def _call_symbol_name_8616(node: CFunctionCall) -> str | None:
    callee_func = getattr(node, "callee_func", None)
    for raw in (
        getattr(callee_func, "name", None),
        getattr(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def build_x86_16_contextual_call_fingerprints(root, project) -> dict[int, str]:
    if root is None:
        return {}
    call_nodes = list(_iter_observable_call_nodes_8616(root))
    if not call_nodes:
        return {}
    fingerprints: dict[int, str] = {}
    function = _function_for_call_context_8616(root, project)
    if function is not None:
        callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
        if not callsite_addrs:
            callsite_addrs = _collect_direct_capstone_callsite_addrs_8616(function)
        for node, callsite_addr in zip(call_nodes, callsite_addrs):
            fingerprints[id(node)] = f"callsite:{callsite_addr:#x}"
    if len(fingerprints) < len(call_nodes):
        for node_id, fingerprint in _build_cod_call_name_fingerprints_8616(root, project, call_nodes).items():
            fingerprints.setdefault(node_id, fingerprint)
    if len(fingerprints) < len(call_nodes):
        for node in call_nodes:
            node_addr = _call_node_addr_8616(node)
            if isinstance(node_addr, int):
                fingerprints.setdefault(id(node), f"callsite:{node_addr:#x}")
    return fingerprints


def _function_for_call_context_8616(root, project):
    codegen = getattr(root, "codegen", None)
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is not None and (
        callable(getattr(cfunc, "get_call_sites", None)) or getattr(cfunc, "block_addrs_set", None)
    ):
        return cfunc
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return None
    return _lookup_function_for_call_context_8616(project, func_addr)


def _collect_direct_capstone_callsite_addrs_8616(function) -> tuple[int, ...]:
    project = getattr(function, "project", None)
    factory = getattr(project, "factory", None)
    if project is None or factory is None:
        return ()
    callsites: list[int] = []
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
            if str(getattr(insn, "mnemonic", "") or "").strip().lower() != "call":
                continue
            address = getattr(insn, "address", None)
            if isinstance(address, int):
                callsites.append(address)
    return tuple(callsites)


def _call_node_addr_8616(node) -> int | None:
    for attr in ("ins_addr", "addr"):
        value = getattr(node, attr, None)
        if isinstance(value, int):
            return value
    return None


def _build_cod_call_name_fingerprints_8616(root, project, call_nodes) -> dict[int, str]:
    codegen = getattr(root, "codegen", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return {}
    cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
    cod_call_names = tuple(
        normalized
        for raw in (getattr(cod_metadata, "call_names", ()) or ())
        for normalized in (normalize_callee_name_8616(raw),)
        if isinstance(normalized, str) and normalized
    )
    if not cod_call_names:
        return {}
    fingerprints: dict[int, str] = {}
    cod_idx = 0
    for node in call_nodes:
        current_name = _call_symbol_name_8616(node)
        if current_name not in {None, "<indirect>"} and not current_name.startswith("sub_"):
            while cod_idx < len(cod_call_names) and cod_call_names[cod_idx] != current_name:
                cod_idx += 1
            if cod_idx < len(cod_call_names) and cod_call_names[cod_idx] == current_name:
                fingerprints[id(node)] = f"codcall:{current_name}"
                cod_idx += 1
            continue
        if cod_idx >= len(cod_call_names):
            break
        replacement = cod_call_names[cod_idx]
        cod_idx += 1
        if replacement.startswith("sub_"):
            continue
        fingerprints[id(node)] = f"codcall:{replacement}"
    return fingerprints


def _lookup_function_for_call_context_8616(project, func_addr: int):
    addr_candidates = [func_addr]
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        addr_candidates.append(func_addr + original_delta)
        rebased = func_addr - original_delta
        if rebased >= 0:
            addr_candidates.append(rebased)
    deduped_addrs: list[int] = []
    for addr in addr_candidates:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", lambda **_: None)
        for candidate_addr in deduped_addrs:
            function = lookup(addr=candidate_addr, create=False)
            if function is not None:
                return function
    return None


def _iter_observable_call_nodes_8616(node):
    if node is None:
        return
    if isinstance(node, CStatements):
        for stmt in getattr(node, "statements", ()) or ():
            yield from _iter_observable_call_nodes_8616(stmt)
        return
    if isinstance(node, CFunctionCall):
        yield node
        return
    if isinstance(node, CAssignment):
        rhs = getattr(node, "rhs", None)
        if isinstance(rhs, CFunctionCall):
            yield rhs
        return
    for attr in ("retval", "condition", "cond", "expr"):
        child = getattr(node, attr, None)
        if isinstance(child, CFunctionCall):
            yield child
        elif child is not None:
            yield from _iter_observable_call_nodes_8616(child)
    if hasattr(node, "condition_and_nodes"):
        for cond, body in getattr(node, "condition_and_nodes", ()) or ():
            if isinstance(cond, CFunctionCall):
                yield cond
            elif cond is not None:
                yield from _iter_observable_call_nodes_8616(cond)
            yield from _iter_observable_call_nodes_8616(body)
    else_node = getattr(node, "else_node", None)
    if else_node is not None:
        yield from _iter_observable_call_nodes_8616(else_node)
    for attr in ("body", "initializer", "iterator"):
        child = getattr(node, attr, None)
        if child is not None:
            yield from _iter_observable_call_nodes_8616(child)


def _location_fingerprint(node, project) -> str:
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
            return f"reg:{_register_name(project, variable.reg)}"
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            return f"stack:{offset:+#x}" if isinstance(offset, int) else "stack:unknown"
        if isinstance(variable, SimMemoryVariable):
            addr = getattr(variable, "addr", None)
            if isinstance(addr, int) and addr < 0:
                return f"stack:{addr:+#x}"
            return f"global:{addr:#x}" if isinstance(addr, int) else "global:unknown"

    if isinstance(node, CTypeCast):
        return _location_fingerprint(node.expr, project)

    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        stack_disp = _match_bp_stack_dereference_8616(node, project)
        if isinstance(stack_disp, int):
            return f"stack:{stack_disp:+#x}"
        seg_name, linear = _match_segmented_dereference_8616(node, project)
        if seg_name is not None:
            if isinstance(linear, int) and _segment_linear_lowering_allowed(node, seg_name):
                return f"global:{linear:#x}"
            return f"deref:{seg_name}:{linear:#x}" if isinstance(linear, int) else f"deref:{seg_name}:unknown"
        return f"deref:{_expr_fingerprint(node.operand, project)}"

    return _expr_fingerprint(node, project)
