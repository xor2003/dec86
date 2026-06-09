from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..decompiler_postprocess_utils import _replace_c_children_8616
from .real_mode_linear import (
    RealModeLinearStackAccess8616,
    _canonical_stack_offset_8616,
    _has_stack_alias_fact_for_displacement_8616,
    _known_bp_stack_offsets_8616,
    _segment_base_name_8616,
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


def _extract_segment_scale_8616(node, project) -> tuple[str | None, object | None]:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None, None
    expected_scale = 16 if node.op == "Mul" else 4 if node.op == "Shl" else None
    if expected_scale is None:
        return None, None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_value_8616(maybe_scale) != expected_scale:
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        if not isinstance(maybe_seg, structured_c.CVariable):
            continue
        variable = getattr(maybe_seg, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            continue
        seg_name = getattr(project.arch, "register_names", {}).get(variable.reg)
        if seg_name is not None:
            return seg_name, maybe_seg
    return None, None


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

        segment_name = None
        segment_expr = None
        offset_terms: list[tuple[int, object]] = []
        for sign, term in _flatten_signed_terms_8616(base_expr):
            local_name, local_expr = _extract_segment_scale_8616(term, project)
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


def lower_runtime_segment_access_8616(expr, *, target: str):
    project = getattr(getattr(expr, "codegen", None), "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="read")
    if matched is None:
        return None
    if matched.space == "SS":
        return None
    macro = _seg_macro_for_width_bits_8616(matched.width_bits)
    if macro is None:
        return None
    codegen = getattr(expr, "codegen", None)
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
