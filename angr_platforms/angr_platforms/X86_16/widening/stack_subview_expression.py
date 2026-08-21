"""Build structured-C expressions for Widening-proven stack subviews.

Layer: Widening.
Responsibility: materialize one accepted scalar stack-object view with exact
width, offset, mask, and shift operations after storage identity is proven.
Consumes only ``StackObjectViewProof8616``; it does not discover ownership.
Consumes alias-proven storage identity through the typed Widening proof.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

This module is a structured-C materialization boundary. Never infer a view from
rendered C, assembly text, variable names, or expression shape here. Unsupported
scalar widths and side-effecting write values must remain unchanged.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort

from ..c_ast_utils import _clone_c_ast_tree_8616
from .stack_subview_proof import StackObjectViewProof8616


def _unsigned_scalar_type_8616(size: int) -> SimType | None:
    """Return the exact supported unsigned scalar type for a byte width."""
    scalar_types: dict[int, SimType] = {
        1: SimTypeChar(signed=False),
        2: SimTypeShort(signed=False),
        4: SimTypeLong(signed=False),
    }
    return scalar_types.get(size)


def _matching_view_type_8616(proof: StackObjectViewProof8616) -> SimType | None:
    """Keep an existing scalar view type only when its width is exact."""
    view_type = proof.view.variable_type
    expected_types: dict[int, type[SimType]] = {
        1: SimTypeChar,
        2: SimTypeShort,
        4: SimTypeLong,
    }
    expected = expected_types.get(proof.view_size)
    return view_type if expected is not None and isinstance(view_type, expected) else None


def scalar_subview_proof_8616(
    proof: StackObjectViewProof8616 | None,
) -> StackObjectViewProof8616 | None:
    """Accept one strict scalar subrange of a supported scalar owner."""
    if proof is None or proof.owner_size not in {2, 4} or proof.view_size not in {1, 2}:
        return None
    if proof.view_size >= proof.owner_size or proof.relative_offset < 0:
        return None
    if proof.relative_offset + proof.view_size > proof.owner_size:
        return None
    return proof


def side_effect_free_subview_rhs_8616(node: object) -> bool:
    """Accept recursively pure values whose evaluation may share an owner read."""
    if isinstance(node, (structured_c.CConstant, structured_c.CVariable)):
        return True
    if isinstance(node, structured_c.CTypeCast):
        return side_effect_free_subview_rhs_8616(node.expr)
    if isinstance(node, structured_c.CBinaryOp):
        return side_effect_free_subview_rhs_8616(node.lhs) and side_effect_free_subview_rhs_8616(
            node.rhs
        )
    return False


def _expression_type_or_width_8616(expr: structured_c.CExpression, size: int) -> SimType:
    """Return a concrete boundary type for an optionally untyped expression."""
    expr_type = expr.type
    fallback = _unsigned_scalar_type_8616(size)
    if fallback is None:
        raise ValueError(f"unsupported scalar stack width {size}")
    return expr_type if isinstance(expr_type, SimType) else fallback


def make_scalar_subview_read_expr_8616(
    codegen: object,
    proof: StackObjectViewProof8616,
) -> structured_c.CExpression:
    """Project one proven scalar rvalue from its unsigned containing owner."""
    owner_type = _unsigned_scalar_type_8616(proof.owner_size)
    if owner_type is None:
        raise ValueError(f"unsupported scalar stack owner width {proof.owner_size}")
    owner = cast(structured_c.CExpression, _clone_c_ast_tree_8616(proof.owner))
    value: structured_c.CExpression = structured_c.CTypeCast(
        _expression_type_or_width_8616(owner, proof.owner_size),
        owner_type,
        owner,
        codegen=codegen,
    )
    shift_bits = proof.relative_offset * 8
    if shift_bits:
        value = structured_c.CBinaryOp(
            "Shr",
            value,
            structured_c.CConstant(shift_bits, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    view_mask = (1 << (proof.view_size * 8)) - 1
    value = structured_c.CBinaryOp(
        "And",
        value,
        structured_c.CConstant(view_mask, owner_type, codegen=codegen),
        codegen=codegen,
    )
    view_type = _matching_view_type_8616(proof)
    if view_type is not None:
        return structured_c.CTypeCast(owner_type, view_type, value, codegen=codegen)
    return value


def make_scalar_subview_write_assignment_8616(
    codegen: object,
    assignment: structured_c.CAssignment,
    proof: StackObjectViewProof8616,
) -> structured_c.CAssignment:
    """Project one pure scalar-view write as a containing-owner update."""
    owner_type = _unsigned_scalar_type_8616(proof.owner_size)
    if owner_type is None:
        raise ValueError(f"unsupported scalar stack owner width {proof.owner_size}")
    owner_read = cast(structured_c.CExpression, _clone_c_ast_tree_8616(proof.owner))
    owner_value = structured_c.CTypeCast(
        _expression_type_or_width_8616(owner_read, proof.owner_size),
        owner_type,
        owner_read,
        codegen=codegen,
    )
    shift_bits = proof.relative_offset * 8
    view_mask = (1 << (proof.view_size * 8)) - 1
    owner_mask = (1 << (proof.owner_size * 8)) - 1
    preserved_mask = owner_mask ^ (view_mask << shift_bits)
    preserved = structured_c.CBinaryOp(
        "And",
        owner_value,
        structured_c.CConstant(preserved_mask, owner_type, codegen=codegen),
        codegen=codegen,
    )
    rhs = cast(structured_c.CExpression, _clone_c_ast_tree_8616(assignment.rhs))
    inserted: structured_c.CExpression = structured_c.CBinaryOp(
        "And",
        structured_c.CTypeCast(
            _expression_type_or_width_8616(rhs, proof.view_size),
            owner_type,
            rhs,
            codegen=codegen,
        ),
        structured_c.CConstant(view_mask, owner_type, codegen=codegen),
        codegen=codegen,
    )
    if shift_bits:
        inserted = structured_c.CBinaryOp(
            "Shl",
            inserted,
            structured_c.CConstant(shift_bits, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    replacement = cast(structured_c.CAssignment, _clone_c_ast_tree_8616(assignment))
    replacement.lhs = cast(structured_c.CExpression, _clone_c_ast_tree_8616(proof.owner))
    replacement.rhs = structured_c.CBinaryOp("Or", preserved, inserted, codegen=codegen)
    return replacement


__all__ = [
    "make_scalar_subview_read_expr_8616",
    "make_scalar_subview_write_assignment_8616",
    "scalar_subview_proof_8616",
    "side_effect_free_subview_rhs_8616",
]
