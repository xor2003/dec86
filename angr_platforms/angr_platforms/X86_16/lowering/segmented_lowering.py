"""Classify and lower typed segmented-address C AST carriers.

Layer: Types/Lowering.
Responsibility: typed segmented-address classification and SS/DS/ES lowering helpers.
Consumes alias, widening, and typed facts to classify SS/DS/ES address forms
before materialization.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Protocol, TypeAlias, runtime_checkable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

_CacheMap8616: TypeAlias = MutableMapping[str, MutableMapping[int, object]]
_ProjectRewriteCache8616: TypeAlias = Callable[[object], _CacheMap8616]
_UnaryObjectCallback8616: TypeAlias = Callable[[object], object]
_ConstantValueCallback8616: TypeAlias = Callable[[object], int | None]
_NormalizeOffsetCallback8616: TypeAlias = Callable[[object], int]
_StackMatchCallback8616: TypeAlias = Callable[[object], tuple[object, object] | None]
_StackIdentityCallback8616: TypeAlias = Callable[[SimStackVariable], object | None]


class _ArchRegisterNames8616(Protocol):
    """Minimal project.arch contract needed for segmented lowering."""

    register_names: Mapping[int, str]


class _ProjectArch8616(Protocol):
    """Minimal project contract needed for segmented lowering."""

    arch: _ArchRegisterNames8616


@runtime_checkable
class _JoinableStackIdentity8616(Protocol):
    """Owned stack-slot identity contract that can merge compatible slots."""

    def can_join(self, other: object) -> bool:
        """Return whether this identity can join with another identity."""
        ...

    def join(self, other: object) -> object | None:
        """Return the joined identity when compatible."""
        ...


def _dynamic_c_attr_8616(obj: object | None, name: str, default: object | None = None) -> object | None:
    """Dynamic third-party angr/codegen boundary: read optional C AST attributes."""
    if obj is None:
        return default
    try:
        # Dynamic third-party angr/codegen boundary: C AST nodes expose optional attributes by shape.
        return getattr(obj, name, default)
    except Exception:  # noqa: BLE001
        return default


@dataclass(frozen=True)
class _SegmentedAccess:
    kind: str
    seg_name: str | None
    assoc_kind: str = "unknown"
    assoc_state: _SegmentAssociationState | None = None
    linear: int | None = None
    cvar: structured_c.CVariable | None = None
    stack_var: SimStackVariable | None = None
    extra_offset: int = 0
    addr_expr: object | None = None

    def allows_object_rewrite(self) -> bool:
        """Return whether this classified access may be rewritten as an object access."""
        if self.assoc_state is not None:
            return not self.assoc_state.is_over_associated()
        return self.assoc_kind != "over"


@dataclass(frozen=True)
class _SegmentAssociationState:
    seg_name: str | None
    base_terms: int = 0
    other_terms: int = 0
    const_offset: int = 0
    stack_slots: tuple[object, ...] = ()

    @property
    def assoc_kind(self) -> str:
        """Return the segment association classification for this address expression."""
        if self.seg_name is None:
            return "unknown"
        if len(self.stack_slots) > 1:
            return "over"
        if self.base_terms == 0:
            return "const" if self.other_terms == 0 else "over"
        if self.other_terms > 0:
            return "over"
        return "single"

    def is_over_associated(self) -> bool:
        """Return whether the expression mixes segment identity with unrelated terms."""
        return self.assoc_kind == "over"


def _merge_stack_slot_identity_8616(stack_slots: list[object], identity: object | None) -> None:
    if identity is None:
        return
    if not stack_slots:
        stack_slots.append(identity)
        return
    if stack_slots[0] == identity:
        return
    existing = stack_slots[0]
    if isinstance(existing, _JoinableStackIdentity8616) and existing.can_join(identity):
        joined_identity = existing.join(identity)
        if joined_identity is not None:
            stack_slots[0] = joined_identity
        return
    stack_slots.append(identity)


def _segment_reg_name(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
) -> str | None:
    cache = project_rewrite_cache(project).setdefault("segment_reg_name", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, str) else None

    reg_offset = _register_offset_for_node_8616(node)
    result = project.arch.register_names.get(reg_offset) if isinstance(reg_offset, int) else None
    cache[key] = result
    return result


def _register_offset_for_node_8616(node: object) -> int | None:
    if isinstance(node, structured_c.CVariable):
        variable = _dynamic_c_attr_8616(node, "variable")
        if isinstance(variable, SimRegisterVariable):
            reg = _dynamic_c_attr_8616(variable, "reg")
            return int(reg) if isinstance(reg, int) else None
    if type(node).__name__ == "CDirtyExpression":
        dirty = _dynamic_c_attr_8616(node, "dirty")
        for attr in ("reg_offset", "reg"):
            reg = _dynamic_c_attr_8616(dirty, attr)
            if isinstance(reg, int):
                return int(reg)
    return None


def _register_size_for_node_8616(node: object) -> int | None:
    if isinstance(node, structured_c.CVariable):
        variable = _dynamic_c_attr_8616(node, "variable")
        size = _dynamic_c_attr_8616(variable, "size")
        return int(size) if isinstance(size, int) else None
    if type(node).__name__ == "CDirtyExpression":
        dirty = _dynamic_c_attr_8616(node, "dirty")
        size = _dynamic_c_attr_8616(dirty, "size")
        if isinstance(size, int):
            return int(size)
        bits = _dynamic_c_attr_8616(dirty, "bits")
        if isinstance(bits, int) and bits > 0:
            return max(1, int(bits) // 8)
    return None


def _classify_segmented_addr_expr(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    flatten_c_add_terms: Callable[[object], Iterable[object]],
    unwrap_c_casts: _UnaryObjectCallback8616,
    c_constant_value: _ConstantValueCallback8616,
    match_stack_cvar_and_offset: _StackMatchCallback8616,
    normalize_16bit_signed_offset: _NormalizeOffsetCallback8616,
    stack_slot_identity_for_variable: _StackIdentityCallback8616,
) -> _SegmentedAccess | None:
    def _impl() -> _SegmentedAccess | None:
        cache = project_rewrite_cache(project).setdefault("segmented_addr_expr", {})
        key = id(node)
        if key in cache:
            cached = cache[key]
            return cached if isinstance(cached, _SegmentedAccess) else None

        seg_name = None
        cvar = None
        stack_var = None
        const_offset = 0
        other_terms: list[object] = []
        base_terms = 0
        stack_slots: list[object] = []
        resolved_term_cache: dict[int, object] = {}

        def _synthetic_sp_anchor(term: object) -> tuple[structured_c.CVariable, int] | None:
            reg_offset = _register_offset_for_node_8616(term)
            reg_name = project.arch.register_names.get(reg_offset) if isinstance(reg_offset, int) else None
            if reg_name not in {"bp", "sp"}:
                return None
            codegen = _dynamic_c_attr_8616(term, "codegen")
            cfunc = _dynamic_c_attr_8616(codegen, "cfunc")
            region = _dynamic_c_attr_8616(cfunc, "addr")
            synthetic = SimStackVariable(
                0,
                _register_size_for_node_8616(term) or 2,
                base=reg_name,
                name=f"{reg_name}_0",
                region=region if isinstance(region, int) else None,
            )
            return structured_c.CVariable(
                synthetic, variable_type=_dynamic_c_attr_8616(term, "variable_type"), codegen=codegen
            ), 0

        def _synthetic_sp_match(term: object) -> tuple[structured_c.CVariable, int] | None:
            synthetic = _synthetic_sp_anchor(term)
            if synthetic is not None:
                return synthetic
            if not isinstance(term, structured_c.CBinaryOp) or term.op not in {"Add", "Sub"}:
                return None
            lhs = _synthetic_sp_anchor(unwrap_c_casts(term.lhs))
            rhs = _synthetic_sp_anchor(unwrap_c_casts(term.rhs))
            lhs_const = c_constant_value(unwrap_c_casts(term.lhs))
            rhs_const = c_constant_value(unwrap_c_casts(term.rhs))
            if lhs is not None and rhs_const is not None:
                base, offset = lhs
                return base, offset + (rhs_const if term.op == "Add" else -rhs_const)
            if rhs is not None and lhs_const is not None and term.op == "Add":
                base, offset = rhs
                return base, offset + lhs_const
            return None

        def _segment_scale_name(term: object) -> str | None:
            if not isinstance(term, structured_c.CBinaryOp):
                return None
            if term.op == "Mul":
                for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                    if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                        continue
                    local_seg = _segment_reg_name(
                        unwrap_c_casts(maybe_seg),
                        project,
                        project_rewrite_cache=project_rewrite_cache,
                    )
                    if local_seg is not None:
                        return local_seg
                return None
            if term.op == "Shl":
                for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                    if c_constant_value(unwrap_c_casts(maybe_scale)) != 4:
                        continue
                    local_seg = _segment_reg_name(
                        unwrap_c_casts(maybe_seg),
                        project,
                        project_rewrite_cache=project_rewrite_cache,
                    )
                    if local_seg is not None:
                        return local_seg
            return None

        def _constant_term_value(term: object) -> int | None:
            term = unwrap_c_casts(term)
            constant = c_constant_value(term)
            if constant is not None:
                return constant
            if not isinstance(term, structured_c.CBinaryOp) or term.op not in {"Add", "Sub"}:
                return None
            lhs = _constant_term_value(term.lhs)
            rhs = _constant_term_value(term.rhs)
            if lhs is None or rhs is None:
                return None
            return lhs + rhs if term.op == "Add" else lhs - rhs

        def _iter_statement_nodes(root: object) -> Iterator[structured_c.CConstruct]:
            stack = [root]
            seen: set[int] = set()
            while stack:
                current = stack.pop()
                if not isinstance(current, structured_c.CConstruct):
                    continue
                current_id = id(current)
                if current_id in seen:
                    continue
                seen.add(current_id)
                yield current

                nested_statements = _dynamic_c_attr_8616(current, "statements")
                if isinstance(nested_statements, (list, tuple)):
                    for item in reversed(tuple(nested_statements)):
                        stack.append(item)
                body = _dynamic_c_attr_8616(current, "body")
                if body is not None:
                    stack.append(body)
                else_node = _dynamic_c_attr_8616(current, "else_node")
                if else_node is not None:
                    stack.append(else_node)
                condition_and_nodes = _dynamic_c_attr_8616(current, "condition_and_nodes")
                if isinstance(condition_and_nodes, (list, tuple)):
                    for pair in reversed(tuple(condition_and_nodes)):
                        if isinstance(pair, tuple):
                            for item in reversed(pair):
                                stack.append(item)

        def _single_assignment_rhs_for_cvar(term: object) -> object | None:
            if not isinstance(term, structured_c.CVariable):
                return None
            term_var = _dynamic_c_attr_8616(term, "variable")
            term_name = _dynamic_c_attr_8616(term, "name") or _dynamic_c_attr_8616(term_var, "name")
            term_reg = _dynamic_c_attr_8616(term_var, "reg")
            term_size = _dynamic_c_attr_8616(term_var, "size")
            codegen = _dynamic_c_attr_8616(term, "codegen")
            cfunc = _dynamic_c_attr_8616(codegen, "cfunc")
            root = _dynamic_c_attr_8616(cfunc, "statements")
            if root is None:
                return None

            def _same_lhs(lhs: object) -> bool:
                if not isinstance(lhs, structured_c.CVariable):
                    return False
                lhs_var = _dynamic_c_attr_8616(lhs, "variable")
                if lhs_var is term_var:
                    return True
                lhs_name = _dynamic_c_attr_8616(lhs, "name") or _dynamic_c_attr_8616(lhs_var, "name")
                if isinstance(term_name, str) and term_name and lhs_name == term_name:
                    return True
                lhs_reg = _dynamic_c_attr_8616(lhs_var, "reg")
                lhs_size = _dynamic_c_attr_8616(lhs_var, "size")
                return (
                    isinstance(term_reg, int)
                    and isinstance(term_size, int)
                    and isinstance(lhs_reg, int)
                    and isinstance(lhs_size, int)
                    and lhs_reg == term_reg
                    and lhs_size == term_size
                )

            matches: list[object] = []
            for stmt in _iter_statement_nodes(root):
                if not isinstance(stmt, structured_c.CAssignment):
                    continue
                if not _same_lhs(_dynamic_c_attr_8616(stmt, "lhs")):
                    continue
                matches.append(_dynamic_c_attr_8616(stmt, "rhs"))
                if len(matches) > 1:
                    return None
            return matches[0] if len(matches) == 1 else None

        def _resolve_term_aliases(term: object) -> object:
            current = unwrap_c_casts(term)
            seen_ids: set[int] = set()
            while isinstance(current, structured_c.CVariable):
                key = id(current)
                if key in resolved_term_cache:
                    return resolved_term_cache[key]
                if key in seen_ids:
                    break
                seen_ids.add(key)
                rhs = _single_assignment_rhs_for_cvar(current)
                if rhs is None:
                    break
                rhs_unwrapped = unwrap_c_casts(rhs)
                if rhs_unwrapped is current:
                    break
                resolved_term_cache[key] = rhs_unwrapped
                current = rhs_unwrapped
            return current

        def _consume_stack_match(
            matched_cvar: object,
            stack_offset: object,
            term: object,
        ) -> tuple[bool, object | None, SimStackVariable | None, int, int]:
            nonlocal cvar, stack_var
            stack_offset = normalize_16bit_signed_offset(stack_offset)
            if not isinstance(matched_cvar, structured_c.CVariable):
                return False, cvar, stack_var, 0, 0
            matched_var = _dynamic_c_attr_8616(matched_cvar, "variable")
            current_var = _dynamic_c_attr_8616(cvar, "variable") if cvar is not None else None
            if cvar is None:
                cvar = matched_cvar
                if isinstance(matched_var, SimStackVariable):
                    stack_var = matched_var
                    _merge_stack_slot_identity_8616(stack_slots, stack_slot_identity_for_variable(matched_var))
                return True, cvar, stack_var, stack_offset, 1
            if current_var is matched_var:
                if isinstance(matched_var, SimStackVariable):
                    _merge_stack_slot_identity_8616(stack_slots, stack_slot_identity_for_variable(matched_var))
                return True, cvar, stack_var, stack_offset, 1
            other_terms.append(term)
            return False, cvar, stack_var, 0, 0

        for term in flatten_c_add_terms(node):
            inner = _resolve_term_aliases(term)
            local_seg = _segment_scale_name(inner)
            if local_seg is not None:
                seg_name = local_seg
                continue
            constant = _constant_term_value(inner)
            if constant is not None:
                const_offset += constant
                continue
            matched_stack = match_stack_cvar_and_offset(inner) or _synthetic_sp_match(inner)
            if matched_stack is not None:
                consumed, _cvar, _stack_var, offset_delta, base_delta = _consume_stack_match(
                    matched_stack[0], matched_stack[1], term
                )
                const_offset += offset_delta
                base_terms += base_delta
                if consumed:
                    continue
            other_terms.append(term)

        if seg_name is None:
            cache[key] = None
            return None

        assoc_state = _SegmentAssociationState(
            seg_name=seg_name,
            base_terms=base_terms,
            other_terms=len(other_terms),
            const_offset=const_offset,
            stack_slots=tuple(stack_slots),
        )
        assoc_kind = assoc_state.assoc_kind

        if seg_name == "ss" and cvar is not None and not other_terms:
            normalized_offset = normalize_16bit_signed_offset(const_offset)
            result = _SegmentedAccess(
                "stack",
                seg_name,
                assoc_kind=assoc_kind,
                assoc_state=assoc_state,
                cvar=cvar,
                stack_var=stack_var,
                extra_offset=normalized_offset,
                addr_expr=node,
            )
            cache[key] = result
            return result

        if cvar is None and not other_terms:
            if seg_name == "es":
                kind = "extra"
                linear = const_offset
            else:
                kind = "segment_const"
                linear = const_offset
            result = _SegmentedAccess(
                kind,
                seg_name,
                assoc_kind=assoc_kind,
                assoc_state=assoc_state,
                linear=linear,
                extra_offset=const_offset,
                addr_expr=node,
            )
            cache[key] = result
            return result

        result = _SegmentedAccess(
            "unknown",
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            linear=const_offset if cvar is None else None,
            cvar=cvar,
            stack_var=stack_var,
            extra_offset=const_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    return _impl()


def _classify_segmented_dereference(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    classify_segmented_addr_expr: Callable[[object, _ProjectArch8616], _SegmentedAccess | None],
) -> _SegmentedAccess | None:
    cache = project_rewrite_cache(project).setdefault("segmented_dereference_class", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, _SegmentedAccess) else None

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        cache[key] = None
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    result = classify_segmented_addr_expr(operand, project)
    cache[key] = result
    return result


def _match_real_mode_linear_expr(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    classify_segmented_addr_expr: Callable[[object, _ProjectArch8616], _SegmentedAccess | None],
) -> tuple[str | None, int | None]:
    cache = project_rewrite_cache(project).setdefault("real_mode_linear_expr", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, tuple) and len(cached) == 2 else (None, None)

    classified = classify_segmented_addr_expr(node, project)
    if classified is None or classified.kind not in {"extra", "segment_const"}:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segmented_dereference(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    classify_segmented_dereference: Callable[[object, _ProjectArch8616], _SegmentedAccess | None],
) -> tuple[str | None, int | None]:
    cache = project_rewrite_cache(project).setdefault("segmented_dereference", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, tuple) and len(cached) == 2 else (None, None)

    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.linear is None:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result
