from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles, infer_induction_variable
from inertia_decompiler.cli_induction_rewrite import rewrite_for_loop_conditions_from_access_traits


def _collect_access_traits(
    project,
    codegen,
    *,
    iter_c_nodes_deep,
    unwrap_c_casts,
    c_constant_value,
    classify_segmented_dereference,
    stack_slot_identity_for_variable,
    access_trait_variable_key,
    AccessTraitStrideEvidence,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    traits: dict[str, dict[tuple[object, ...], object]] = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    cache = getattr(project, "_inertia_access_traits", None)
    if isinstance(cache, dict):
        existing = cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(existing, dict):
            for bucket, bucket_data in existing.items():
                if bucket not in traits or not isinstance(bucket_data, dict):
                    continue
                traits[bucket].update(bucket_data)

    def record(bucket: str, key: tuple[object, ...]) -> None:
        store = traits[bucket]
        store[key] = store.get(key, 0) + 1

    def record_stride_evidence(
        *,
        kind: str,
        seg_name: str,
        base_key: tuple[object, ...] | None,
        index_key: tuple[object, ...] | None,
        stride: int,
        offset: int,
        access_size: int,
    ) -> None:
        if index_key is None:
            return
        evidence_key = (kind, seg_name, base_key, index_key, stride, offset, access_size)
        bucket_name = "induction_evidence" if kind == "induction_like" else "stride_evidence"
        existing = traits[bucket_name].get(evidence_key)
        existing_count = getattr(existing, "count", existing if isinstance(existing, int) else None)
        count = 1 if existing_count is None else int(existing_count) + 1
        traits[bucket_name][evidence_key] = AccessTraitStrideEvidence(
            segment=seg_name,
            base_key=base_key,
            index_key=index_key,
            stride=stride,
            offset=offset,
            width=access_size,
            count=count,
            kind=kind,
        )

    def stable_base_key(variable) -> tuple[object, ...] | None:
        if isinstance(variable, SimRegisterVariable):
            return ("reg", getattr(variable, "reg", None))
        if isinstance(variable, SimStackVariable):
            identity = stack_slot_identity_for_variable(variable)
            if identity is None:
                return None
            return ("stack", identity.base, getattr(variable, "offset", None), getattr(variable, "region", None))
        if isinstance(variable, SimMemoryVariable):
            return ("mem", getattr(variable, "addr", None))
        return None

    def expr_index_key(expr) -> tuple[object, ...] | None:
        expr = unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            return access_trait_variable_key(getattr(expr, "variable", None))
        if isinstance(expr, structured_c.CUnaryOp) and expr.op == "Dereference":
            operand = unwrap_c_casts(getattr(expr, "operand", None))
            if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Reference":
                expr = unwrap_c_casts(getattr(operand, "operand", None))
            else:
                return None
        if isinstance(expr, structured_c.CIndexedVariable):
            base_expr = unwrap_c_casts(getattr(expr, "variable", None))
            if isinstance(base_expr, structured_c.CUnaryOp) and base_expr.op == "Reference":
                base_expr = unwrap_c_casts(getattr(base_expr, "operand", None))
            index = c_constant_value(unwrap_c_casts(getattr(expr, "index", None)))
            if not isinstance(index, int) or not isinstance(base_expr, structured_c.CVariable):
                return None
            base_var = getattr(base_expr, "variable", None)
            if not isinstance(base_var, SimStackVariable):
                return None
            identity = stack_slot_identity_for_variable(base_var)
            if identity is None:
                return None
            base_offset = getattr(base_var, "offset", None)
            if not isinstance(base_offset, int):
                return None
            return ("stack", identity.base, base_offset + index, getattr(base_var, "region", None))
        return None

    def summarize_address(addr_expr):
        from_terms: list[object] = []
        offset = 0
        stride_terms: list[tuple[tuple[object, ...], int]] = []

        for term in _flatten_c_add_terms(addr_expr):
            inner = unwrap_c_casts(term)
            const_value = c_constant_value(inner)
            if const_value is not None:
                offset += const_value
                continue

            if isinstance(inner, structured_c.CBinaryOp) and inner.op in {"Mul", "Shl"}:
                for maybe_index, maybe_stride in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                    stride_value = c_constant_value(unwrap_c_casts(maybe_stride))
                    if inner.op == "Shl" and isinstance(stride_value, int):
                        stride = 1 << stride_value
                    else:
                        stride = stride_value
                    if stride is None:
                        continue
                    index = unwrap_c_casts(maybe_index)
                    index_key = expr_index_key(index)
                    if index_key is not None:
                        stride_terms.append((index_key, stride))
                        break
                else:
                    from_terms.append(inner)
                continue

            index_key = expr_index_key(inner)
            if index_key is not None:
                stride_terms.append((index_key, 1))
                continue

            if isinstance(inner, structured_c.CVariable):
                from_terms.append(inner)
                continue

            from_terms.append(inner)

        return from_terms, offset, stride_terms

    def _flatten_c_add_terms(expr):
        if expr is None:
            return []
        expr = unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Add":
            return [* _flatten_c_add_terms(expr.lhs), * _flatten_c_add_terms(expr.rhs)]
        return [expr]

    for node in iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue

        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        access_size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)

        direct_index_key = expr_index_key(node)
        if direct_index_key is not None and access_size >= 2:
            record_stride_evidence(
                kind="induction_like",
                seg_name="expr",
                base_key=None,
                index_key=direct_index_key,
                stride=1,
                offset=0,
                access_size=access_size,
            )

        plain_base_terms, plain_offset, plain_stride_terms = summarize_address(getattr(node, "operand", None))
        if len(plain_base_terms) == 1 and isinstance(plain_base_terms[0], structured_c.CVariable):
            plain_base_var = getattr(plain_base_terms[0], "variable", None)
            if isinstance(plain_base_var, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                plain_base_key = stable_base_key(plain_base_var)
                if plain_base_key is None:
                    continue
                if plain_offset != 0:
                    record("member_evidence", (plain_base_key, plain_offset, access_size))
                for index_key, stride in plain_stride_terms:
                    if index_key is None or stride not in {2, 4, 8}:
                        continue
                    record("array_evidence", (plain_base_key, index_key, stride, plain_offset, access_size))

        classified = classify_segmented_dereference(node, project)
        if classified is None:
            continue

        base_terms, offset, stride_terms = summarize_address(classified.addr_expr)
        base_key = None
        if len(base_terms) == 1 and isinstance(base_terms[0], structured_c.CVariable):
            base_var = getattr(base_terms[0], "variable", None)
            base_key = access_trait_variable_key(base_var)
            if base_key is not None:
                record("base_const", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offsets", (classified.seg_name, base_key, offset))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
        for index_key, stride in stride_terms:
            if index_key is None or base_key is None:
                continue
            record("base_stride", (classified.seg_name, index_key, stride, offset, access_size))
            record("base_stride_widths", (classified.seg_name, index_key, stride, offset, access_size))
            if index_key[0] in {"reg", "stack"}:
                record_stride_evidence(
                    kind="induction_like",
                    seg_name=classified.seg_name,
                    base_key=base_key,
                    index_key=index_key,
                    stride=stride,
                    offset=offset,
                    access_size=access_size,
                )
            if stride in {2, 4, 8}:
                evidence_bucket = "array_evidence" if offset == 0 else "member_evidence"
                record(
                    evidence_bucket,
                    (classified.seg_name, index_key, stride, offset, access_size),
                )
                record_stride_evidence(
                    kind="array_like" if offset == 0 else "member_like",
                    seg_name=classified.seg_name,
                    base_key=base_key,
                    index_key=index_key,
                    stride=stride,
                    offset=offset,
                    access_size=access_size,
                )

    for key, count in list(traits["repeated_offsets"].items()):
        if count < 2:
            del traits["repeated_offsets"][key]

    for key, count in list(traits["base_stride"].items()):
        if count < 2:
            del traits["base_stride"][key]

    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_access_traits", cache)
    cache[getattr(codegen.cfunc, "addr", 0)] = traits
    return rewrite_for_loop_conditions_from_access_traits(
        project,
        codegen,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        infer_induction_variable=infer_induction_variable,
        iter_c_nodes_deep=iter_c_nodes_deep,
    )
