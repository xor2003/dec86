"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c

type ReplaceCChildren = Callable[[object, Callable[[object], object]], bool]


class _CFunctionLike(Protocol):
    """C function shape needed by the MK_FP cleanup helper."""

    statements: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by the MK_FP cleanup helper."""

    cfunc: _CFunctionLike | None


def _simplify_nested_mk_fp_calls(
    codegen: _CodegenLike,
    *,
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], int | None],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    changed = False

    def _is_zero_offset_mk_fp(expr: object) -> bool:
        expr = unwrap_c_casts(expr)
        # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
        if not isinstance(expr, structured_c.CFunctionCall) or getattr(expr, "callee_target", None) != "MK_FP":
            return False
        # dynamic codegen boundary: structured C call arguments are provided by angr.
        args = list(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return False
        return c_constant_value(unwrap_c_casts(args[1])) == 0

    def transform(node: object) -> object:
        nonlocal changed
        # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
        if not isinstance(node, structured_c.CFunctionCall) or getattr(node, "callee_target", None) != "MK_FP":
            return node
        # dynamic codegen boundary: structured C call arguments are provided by angr.
        args = list(getattr(node, "args", ()) or ())
        if len(args) != 2:
            return node

        seg_expr = unwrap_c_casts(args[0])
        off_expr = unwrap_c_casts(args[1])
        # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
        if isinstance(seg_expr, structured_c.CFunctionCall) and getattr(seg_expr, "callee_target", None) == "MK_FP":
            # dynamic codegen boundary: structured C call arguments are provided by angr.
            inner_args = list(getattr(seg_expr, "args", ()) or ())
            if len(inner_args) == 2 and _is_zero_offset_mk_fp(off_expr):
                changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [unwrap_c_casts(inner_args[0]), unwrap_c_casts(inner_args[1])],
                    codegen=codegen,
                )
        if _is_zero_offset_mk_fp(off_expr):
            # dynamic codegen boundary: structured C call arguments are provided by angr.
            inner_args = list(getattr(off_expr, "args", ()) or ())
            if len(inner_args) == 2:
                changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [seg_expr, unwrap_c_casts(inner_args[0])],
                    codegen=codegen,
                )

        return node

    root = cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed
