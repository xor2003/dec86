"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from archinfo.arch import Arch


class _ProjectLike(Protocol):
    """Project surface needed by segmented pointer elision."""

    arch: Arch


class _CFunctionLike(Protocol):
    """Structured C function surface needed by segmented pointer elision."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by segmented pointer elision."""

    cfunc: _CFunctionLike | None


class _SegmentedDereferenceLike(Protocol):
    """Classified segmented dereference fields consumed by this CLI helper."""

    addr_expr: object | None
    cvar: object | None
    extra_offset: int
    seg_name: str


def _elide_redundant_segment_pointer_dereferences(
    project: _ProjectLike,
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    classify_segmented_dereference: Callable[[object, _ProjectLike], _SegmentedDereferenceLike | None],
    flatten_c_add_terms: Callable[[object], Sequence[object]],
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], int | None],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    match_segment_register_based_dereference: Callable[
        [object, _ProjectLike], tuple[_SegmentedDereferenceLike, object] | None
    ],
    strip_segment_scale_from_addr_expr: Callable[[object, _ProjectLike], object | None],
    same_c_storage: Callable[[object, object], bool],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    changed = False
    eligible_bases: dict[int, tuple[structured_c.CVariable, set[int]]] = {}

    def collect_candidate_bases() -> None:
        for node in iter_c_nodes_deep(cfunc.statements):
            classified = classify_segmented_dereference(node, project)
            if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
                continue

            addr_expr = classified.addr_expr
            base_terms = []
            for term in flatten_c_add_terms(addr_expr):
                inner = unwrap_c_casts(term)
                if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                    segment_scale = False
                    for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                        if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                            continue
                        if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                            segment_scale = True
                            break
                    if segment_scale:
                        continue

                if c_constant_value(inner) is not None:
                    continue

                if isinstance(inner, structured_c.CVariable) and isinstance(
                    # Dynamic codegen boundary: angr CVariable nodes expose optional SimVariable payloads.
                    getattr(inner, "variable", None), SimRegisterVariable
                ):
                    base_terms.append(inner)
                    continue

                base_terms = []
                break

            if len(base_terms) != 1:
                continue
            # Dynamic codegen boundary: CVariable payloads come from angr structured codegen.
            base_var = getattr(base_terms[0], "variable", None)
            if not isinstance(base_var, SimRegisterVariable):
                continue
            entry = eligible_bases.get(id(base_var))
            if entry is None:
                eligible_bases[id(base_var)] = (base_terms[0], {classified.extra_offset})
            else:
                entry[1].add(classified.extra_offset)

    def _addr_expr_is_safe_projection(addr_expr: object) -> bool:
        allowed_ops = {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Div"}

        def _check(node: object) -> bool:
            node = unwrap_c_casts(node)
            if c_constant_value(node) is not None:
                return True
            if isinstance(node, structured_c.CVariable) and isinstance(
                # Dynamic codegen boundary: angr CVariable nodes expose optional SimVariable payloads.
                getattr(node, "variable", None), SimRegisterVariable
            ):
                return True
            if isinstance(node, structured_c.CUnaryOp) and node.op in {"Neg", "BitNot"}:
                return _check(node.operand)
            if isinstance(node, structured_c.CBinaryOp) and node.op in allowed_ops:
                return _check(node.lhs) and _check(node.rhs)
            return False

        return _check(addr_expr)

    def make_deref(base_expr: object, bits: int) -> structured_c.CUnaryOp:
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, cast(structured_c.CExpression, base_expr), codegen=codegen),
            codegen=codegen,
        )

    def transform(node: object) -> object:
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        match = match_segment_register_based_dereference(node, project)
        if match is None:
            classified = classify_segmented_dereference(node, project)
            if classified is None or classified.seg_name not in {"ds", "es"} or classified.addr_expr is None:
                return node
            base_expr = strip_segment_scale_from_addr_expr(classified.addr_expr, project)
            if base_expr is None or not _addr_expr_is_safe_projection(base_expr):
                return node
            if classified.cvar is None or not isinstance(base_expr, structured_c.CVariable):
                return node
            if not same_c_storage(base_expr, classified.cvar):
                return node
        else:
            classified, base_expr = match
            # Dynamic codegen boundary: match results may be CVariable-like codegen nodes.
            base_var = getattr(getattr(base_expr, "variable", None), "reg", None)
            if base_var is None:
                return node
            # Dynamic codegen boundary: CVariable payload identity is supplied by angr codegen.
            eligible = eligible_bases.get(id(getattr(base_expr, "variable", None)))
            if eligible is None or eligible[1] != {0}:
                return node
        # Dynamic codegen boundary: CUnaryOp type metadata is optional in angr structured C.
        type_ = getattr(node, "type", None)
        # Dynamic codegen boundary: angr SimType instances expose size only on concrete types.
        bits = getattr(type_, "size", None)
        if bits != 8:
            return node
        return make_deref(base_expr, bits)

    collect_candidate_bases()
    root = cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True
    return changed
