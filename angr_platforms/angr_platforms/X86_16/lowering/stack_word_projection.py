"""Recognize Alias-owned word values rebuilt from byte stack projections.

Layer: Types/Lowering.
Responsibility: map a side-effect-free low/high byte recomposition to the
canonical word CVariable recorded by stack coordinate Lowering. Storage
ownership comes only from that Alias-derived registry; this module does not
infer stack identity from names, rendered C, assembly text, or addresses.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from .stack_variable_coordinates import stack_variable_coordinate_registry_8616


def _strip_casts_8616(node: object) -> object:
    """Remove syntax-only casts around one byte projection."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node: object) -> int | None:
    """Return the integer carried by one exact C constant."""
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _masked_cvariable_8616(node: object) -> structured_c.CVariable | None:
    """Return a direct or low-byte-masked CVariable."""
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CVariable):
        return node
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
        return None
    for constant, operand in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        candidate = _strip_casts_8616(operand)
        if _constant_value_8616(constant) == 0xFF and isinstance(candidate, structured_c.CVariable):
            return candidate
    return None


def _high_byte_cvariable_8616(node: object) -> structured_c.CVariable | None:
    """Return the byte multiplied by 256 or shifted left by eight."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    operand: object | None = None
    if node.op == "Shl" and _constant_value_8616(node.rhs) == 8:
        operand = node.lhs
    elif node.op == "Mul":
        if _constant_value_8616(node.lhs) == 0x100:
            operand = node.rhs
        elif _constant_value_8616(node.rhs) == 0x100:
            operand = node.lhs
    return _masked_cvariable_8616(operand) if operand is not None else None


def stack_word_projection_owner_8616(
    codegen: object,
    node: object,
) -> structured_c.CVariable | None:
    """Return the exact Alias-owned word represented by two byte projections."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    pairs = (
        (_masked_cvariable_8616(node.lhs), _high_byte_cvariable_8616(node.rhs)),
        (_masked_cvariable_8616(node.rhs), _high_byte_cvariable_8616(node.lhs)),
    )
    registry = stack_variable_coordinate_registry_8616(codegen)
    for low, high in pairs:
        if low is None or high is None:
            continue
        low_variable = low.variable
        high_variable = high.variable
        if not isinstance(low_variable, SimStackVariable) or not isinstance(high_variable, SimStackVariable):
            continue
        if not isinstance(low_variable.offset, int) or not isinstance(high_variable.offset, int):
            continue
        projection = registry.containing_entry_sp_range(low_variable.offset, 1)
        if (
            projection is not None
            and projection.size == 2
            and low_variable.offset == projection.entry_sp_offset
            and high_variable.offset == projection.entry_sp_offset + 1
            and high_variable.size == 1
            and isinstance(projection.cvar, structured_c.CVariable)
        ):
            return projection.cvar
    return None


__all__ = ["stack_word_projection_owner_8616"]
