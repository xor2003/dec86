from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from ..decompiler_postprocess_utils import _replace_c_children_8616, _same_c_expression_8616
from .real_mode_linear import (
    RealModeLinearStackAccess8616,
    _canonical_stack_offset_8616,
    _decompose_linear_global_terms_8616,
    _has_stack_alias_fact_for_displacement_8616,
    _known_bp_stack_offsets_8616,
    _segment_base_name_8616,
    _single_assignment_rhs_8616,
    _single_assignment_rhs_for_virtual_name_8616,
    _stack_offset_from_expr_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)


@dataclass(frozen=True, slots=True)
class SegmentedMemoryExpr:
    space: str
    segment_expr: object
    offset_expr: object
    width_bits: int
    access: str


def _strip_casts_8616(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _extract_segment_scale_8616(node, project, codegen=None) -> tuple[str | None, object | None]:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None, None
    expected_scale = 16 if node.op == "Mul" else 4 if node.op == "Shl" else None
    if expected_scale is None:
        return None, None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_value_8616(maybe_scale) != expected_scale:
            continue
        seg_name = _segment_base_name_8616(maybe_seg, project, codegen=codegen)
        if seg_name is not None:
            return seg_name, maybe_seg
    return None, None


def _linear_carrier_name_8616(node) -> str | None:
    node = _strip_casts_8616(node)
    dirty = getattr(node, "dirty", None)
    if dirty is not None:
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
        name = getattr(dirty, "name", None)
        if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
            return name
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    name = getattr(node, "name", None) or getattr(variable, "name", None)
    if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
        return name
    return None


def _single_assignment_carrier_rhs_8616(node, codegen, seen: set[str]) -> object | None:
    if codegen is None:
        return None
    name = _linear_carrier_name_8616(node)
    if name is None or name in seen:
        return None
    seen.add(name)
    node = _strip_casts_8616(node)
    rhs = _single_assignment_rhs_8616(codegen, node) if isinstance(node, structured_c.CVariable) else None
    if rhs is None:
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, name)
    if rhs is not None:
        codegen._inertia_runtime_segment_carrier_resolved_count_8616 = int(
            getattr(codegen, "_inertia_runtime_segment_carrier_resolved_count_8616", 0) or 0
        ) + 1
    return rhs


def _find_segment_expr_8616(
    node,
    *,
    project,
    codegen,
    segment_name: str,
    seen: set[str] | None = None,
) -> object | None:
    if seen is None:
        seen = set()
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp):
        scaled_name, scaled_expr = _extract_segment_scale_8616(node, project, codegen=codegen)
        if scaled_name is not None and scaled_name.upper() == segment_name.upper():
            return scaled_expr
        for child in (getattr(node, "lhs", None), getattr(node, "rhs", None)):
            found = _find_segment_expr_8616(
                child,
                project=project,
                codegen=codegen,
                segment_name=segment_name,
                seen=seen,
            )
            if found is not None:
                return found
    rhs = _single_assignment_carrier_rhs_8616(node, codegen, seen)
    if rhs is not None:
        return _find_segment_expr_8616(
            rhs,
            project=project,
            codegen=codegen,
            segment_name=segment_name,
            seen=seen,
        )
    return None


def _flatten_signed_terms_8616(node, sign: int = 1) -> tuple[tuple[int, object], ...]:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, sign)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, -sign)
    return ((sign, node),)


def _build_offset_expr_8616(terms: tuple[tuple[int, object], ...], codegen):
    if not terms:
        return structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)

    expr = None
    for sign, term in terms:
        term = _strip_casts_8616(term)
        if expr is None:
            if sign == 1:
                expr = term
            else:
                expr = structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            continue
        expr = structured_c.CBinaryOp("Add" if sign == 1 else "Sub", expr, term, codegen=codegen)
    return expr


def _match_segmented_memory_expr_8616(node, *, project, access: str) -> SegmentedMemoryExpr | None:
    def _impl():
        nonlocal node
        if access == "read" or access == "write":
            node = _strip_casts_8616(node)
            if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
                return None
            base_expr = node.operand
            width_bits = getattr(getattr(node, "type", None), "size", None) or 16
            codegen = getattr(node, "codegen", None)
        else:
            base_expr = node
            width_bits = 0
            codegen = getattr(node, "codegen", None)

        decomposed = _decompose_linear_global_terms_8616(base_expr, project, codegen=codegen)
        if decomposed is not None:
            segment_name, displacement, residual_terms = decomposed
            if segment_name is not None:
                segment_name = segment_name.upper()
                segment_expr = _find_segment_expr_8616(
                    base_expr,
                    project=project,
                    codegen=codegen,
                    segment_name=segment_name,
                )
                if (
                    segment_name in {"DS", "ES", "SS"}
                    and segment_expr is not None
                    and not (segment_name == "SS" and _expr_mentions_stack_variable_8616(base_expr))
                ):
                    offset_terms = list(residual_terms)
                    if displacement:
                        sign = 1 if displacement >= 0 else -1
                        offset_terms.insert(
                            0,
                            (
                                sign,
                                structured_c.CConstant(
                                    abs(displacement),
                                    SimTypeShort(False),
                                    codegen=codegen,
                                ),
                            ),
                        )
                    return SegmentedMemoryExpr(
                        space=segment_name,
                        segment_expr=segment_expr,
                        offset_expr=_build_offset_expr_8616(tuple(offset_terms), codegen),
                        width_bits=int(width_bits),
                        access=access,
                    )

        segment_name = None
        segment_expr = None
        offset_terms: list[tuple[int, object]] = []
        for sign, term in _flatten_signed_terms_8616(base_expr):
            local_name, local_expr = _extract_segment_scale_8616(term, project, codegen=codegen)
            if local_name is not None:
                if sign != 1 or segment_name is not None:
                    return None
                segment_name = local_name.upper()
                segment_expr = local_expr
                continue
            offset_terms.append((sign, term))

        if segment_name not in {"DS", "ES", "SS"} or segment_expr is None:
            return None
        return SegmentedMemoryExpr(
            space=segment_name,
            segment_expr=segment_expr,
            offset_expr=_build_offset_expr_8616(tuple(offset_terms), codegen),
            width_bits=int(width_bits),
            access=access,
        )

    return _impl()


def _seg_macro_for_width_bits_8616(width_bits: int) -> str | None:
    if width_bits <= 8:
        return "SEG_U8"
    if width_bits <= 16:
        return "SEG_U16"
    if width_bits <= 32:
        return "SEG_U32"
    return None


def _expr_mentions_stack_variable_8616(node) -> bool:
    pending = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        variable = getattr(current, "variable", None)
        if isinstance(variable, SimStackVariable):
            return True
        for attr in ("lhs", "rhs", "operand", "expr", "index", "variable"):
            child = getattr(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = getattr(current, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in children if child is not None)
    return False


def _is_proven_ss_stack_access_8616(matched: SegmentedMemoryExpr, *, codegen, project) -> bool:
    if matched.space != "SS":
        return False
    if _expr_mentions_stack_variable_8616(matched.offset_expr):
        return True
    displacement = _stack_offset_from_expr_8616(matched.offset_expr, project, codegen)
    displacement = _canonical_stack_offset_8616(displacement)
    if not isinstance(displacement, int):
        return False
    width = max(int(matched.width_bits or 16) // 8, 1)
    return (
        _has_stack_alias_fact_for_displacement_8616(codegen, displacement, width)
        or displacement in _known_bp_stack_offsets_8616(codegen)
    )


def lower_runtime_segment_access_8616(expr, *, target: str):
    project = getattr(getattr(expr, "codegen", None), "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="read")
    if matched is None:
        return None
    codegen = getattr(expr, "codegen", None)
    if matched.space == "SS" and _is_proven_ss_stack_access_8616(matched, codegen=codegen, project=project):
        return None
    macro = _seg_macro_for_width_bits_8616(matched.width_bits)
    if macro is None:
        return None
    return structured_c.CFunctionCall(
        macro,
        None,
        [matched.segment_expr, matched.offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": macro},
    )


def lower_runtime_segment_address_8616(expr, *, target: str):
    project = getattr(getattr(expr, "codegen", None), "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="address")
    if matched is None:
        return None
    if matched.space not in {"DS", "ES"}:
        return None
    codegen = getattr(expr, "codegen", None)
    return structured_c.CFunctionCall(
        "MK_FP",
        None,
        [matched.segment_expr, matched.offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "MK_FP"},
    )


def _runtime_segment_helper_name_8616(node) -> str | None:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    for candidate in (
        getattr(node, "callee_target", None),
        getattr(getattr(node, "callee_func", None), "name", None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate.strip()
    return None


def _runtime_segment_helper_width_8616(name: str | None) -> int | None:
    normalized = name.upper() if isinstance(name, str) else ""
    if normalized == "SEG_U8":
        return 1
    if normalized == "SEG_U16":
        return 2
    if normalized == "SEG_U32":
        return 4
    return None


def _runtime_segment_helper_args_8616(node) -> tuple[object, object] | None:
    args = getattr(node, "args", None)
    if not isinstance(args, (list, tuple)) or len(args) != 2:
        return None
    return args[0], args[1]


def _runtime_segment_address_helper_name_8616(node) -> str | None:
    name = _runtime_segment_helper_name_8616(node)
    if isinstance(name, str) and name.upper() in {"MK_FP", "SEG_PTR"}:
        return name.upper()
    return None


def _same_runtime_segment_address_helper_8616(lhs, rhs) -> bool:
    lhs_name = _runtime_segment_address_helper_name_8616(lhs)
    rhs_name = _runtime_segment_address_helper_name_8616(rhs)
    if lhs_name is None or rhs_name is None:
        return False
    lhs_args = _runtime_segment_helper_args_8616(lhs)
    rhs_args = _runtime_segment_helper_args_8616(rhs)
    if lhs_args is None or rhs_args is None:
        return False
    return _same_c_expression_8616(lhs_args[0], rhs_args[0]) and _same_c_expression_8616(lhs_args[1], rhs_args[1])


def _prune_runtime_segment_address_self_assignments_8616(codegen) -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False

    changed = False
    candidates = 0
    pruned = 0
    refused = 0
    seen: set[int] = set()

    def is_prunable(stmt) -> bool:
        nonlocal candidates, pruned, refused
        stmt = _strip_casts_8616(stmt)
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _strip_casts_8616(getattr(stmt, "lhs", None))
        rhs = _strip_casts_8616(getattr(stmt, "rhs", None))
        if _runtime_segment_address_helper_name_8616(lhs) is None:
            return False
        candidates += 1
        if _same_runtime_segment_address_helper_8616(lhs, rhs):
            pruned += 1
            return True
        refused += 1
        return False

    def visit(node) -> None:
        nonlocal changed
        node = _strip_casts_8616(node)
        if node is None:
            return
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)

        if isinstance(node, structured_c.CStatements):
            statements = list(getattr(node, "statements", ()) or ())
            rebuilt = []
            for stmt in statements:
                if is_prunable(stmt):
                    changed = True
                    continue
                visit(stmt)
                rebuilt.append(stmt)
            if len(rebuilt) != len(statements):
                node.statements = rebuilt
            return

        for attr in (
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "initializer",
            "iterator",
            "condition",
            "cond",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "statements",
            "retval",
        ):
            child = getattr(node, attr, None)
            if child is not None:
                visit(child)
        for attr in ("args", "operands", "condition_and_nodes"):
            children = getattr(node, attr, None)
            if isinstance(children, (list, tuple)):
                for child in children:
                    if isinstance(child, tuple):
                        for item in child:
                            visit(item)
                    else:
                        visit(child)

    visit(root)
    if changed and hasattr(codegen.cfunc, "body"):
        codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_runtime_segment_address_self_assign_candidates_8616 = int(
        getattr(codegen, "_inertia_runtime_segment_address_self_assign_candidates_8616", 0) or 0
    ) + candidates
    codegen._inertia_runtime_segment_address_self_assign_pruned_8616 = int(
        getattr(codegen, "_inertia_runtime_segment_address_self_assign_pruned_8616", 0) or 0
    ) + pruned
    codegen._inertia_runtime_segment_address_self_assign_refused_8616 = int(
        getattr(codegen, "_inertia_runtime_segment_address_self_assign_refused_8616", 0) or 0
    ) + refused
    return changed


def lower_runtime_ss_segment_helper_to_stack_8616(node, *, codegen, project):
    """Convert proven SS SEG_U* helper accesses back to stack variables."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    helper_name = _runtime_segment_helper_name_8616(node)
    width = _runtime_segment_helper_width_8616(helper_name)
    if width is None:
        return None
    args = _runtime_segment_helper_args_8616(node)
    if args is None:
        return None
    segment_expr, offset_expr = args
    segment_name = _segment_base_name_8616(segment_expr, project, codegen=codegen)
    if segment_name != "ss":
        return None
    displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    displacement = _canonical_stack_offset_8616(displacement)
    if not isinstance(displacement, int):
        return None
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    if (
        not _has_stack_alias_fact_for_displacement_8616(codegen, displacement, width)
        and displacement not in known_offsets
    ):
        return None
    access = RealModeLinearStackAccess8616(displacement=displacement, width=width)
    return stack_cvar_for_stable_ss_linear_access_8616(codegen, access)


def lower_runtime_ss_segment_helpers_to_stack_8616(codegen, *, project=None) -> bool:
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    candidate_count = 0
    materialized_count = 0
    refused_count = 0
    changed = False

    def transform(node):
        nonlocal candidate_count, changed, materialized_count, refused_count
        if not isinstance(_strip_casts_8616(node), structured_c.CFunctionCall):
            return node
        if _runtime_segment_helper_width_8616(_runtime_segment_helper_name_8616(node)) is None:
            return node
        candidate_count += 1
        cvar = lower_runtime_ss_segment_helper_to_stack_8616(node, codegen=codegen, project=project)
        if cvar is None:
            refused_count += 1
            return node
        changed = True
        materialized_count += 1
        return cvar

    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        if hasattr(codegen.cfunc, "body"):
            codegen.cfunc.body = new_root
        changed = True
    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True
    codegen._inertia_runtime_ss_helper_candidate_count_8616 = (
        int(getattr(codegen, "_inertia_runtime_ss_helper_candidate_count_8616", 0) or 0) + candidate_count
    )
    codegen._inertia_runtime_ss_helper_materialized_count_8616 = (
        int(getattr(codegen, "_inertia_runtime_ss_helper_materialized_count_8616", 0) or 0) + materialized_count
    )
    codegen._inertia_runtime_ss_helper_refused_count_8616 = (
        int(getattr(codegen, "_inertia_runtime_ss_helper_refused_count_8616", 0) or 0) + refused_count
    )
    return changed


def apply_runtime_segment_lowering_8616(codegen, *, target: str = "portable-flat") -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    project = getattr(codegen, "project", None)
    if root is None or project is None:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        lowered_access = lower_runtime_segment_access_8616(node, target=target)
        if lowered_access is not None:
            changed = True
            return lowered_access
        lowered_addr = lower_runtime_segment_address_8616(node, target=target)
        if lowered_addr is not None:
            changed = True
            return lowered_addr
        return node

    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        if hasattr(codegen.cfunc, "body"):
            codegen.cfunc.body = new_root
        changed = True
    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True
    if _prune_runtime_segment_address_self_assignments_8616(codegen):
        changed = True
    if lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project):
        changed = True
    return changed


__all__ = [
    "SegmentedMemoryExpr",
    "apply_runtime_segment_lowering_8616",
    "lower_runtime_segment_access_8616",
    "lower_runtime_segment_address_8616",
    "lower_runtime_ss_segment_helper_to_stack_8616",
    "lower_runtime_ss_segment_helpers_to_stack_8616",
]
