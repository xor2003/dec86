from __future__ import annotations

import logging
import os

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .decompiler_postprocess_flags import _bool_cite_values_8616
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .lowering.stack_lowering_from_facts import (
    _canonical_stack_offset_8616,
    _stack_object_name,
)
from .semantics.alias_query import _storage_domain_for_expr
from .widening_alias import join_adjacent_register_slices
from .widening_model import prove_adjacent_storage_slices

_log = logging.getLogger(__name__)

PROJECTION_CLEANUP_RULES = (
    (
        "concat_fold",
        "Fold concatenations of constant halves into one constant and preserve the narrower shift width otherwise.",
    ),
    (
        "or_zero_elimination",
        "Eliminate redundant zero terms in Or expressions after the low-level expression facts are stable.",
    ),
    (
        "and_zero_collapse",
        "Collapse And expressions with a zero operand into typed zero constants.",
    ),
    (
        "double_not_collapse",
        "Remove redundant boolean negation pairs after boolean cite recovery.",
    ),
    (
        "zero_compare_projection",
        "Convert zero comparisons into the underlying projection or flag source when the evidence is explicit.",
    ),
    (
        "word_or_update_materialization",
        "Materialize proven in-place word OR updates on stable locals instead of leaking byte-carrier projections.",
    ),
    (
        "sub_self_zero",
        "Collapse self-subtractions into typed zero constants once the low-level operands are proven identical.",
    ),
)


__all__ = [
    "_simplify_structured_expressions_8616",
    "_simplify_boolean_cites_8616",
    "_eliminate_single_use_temporaries_8616",
    "_maybe_eliminate_single_use_temporaries_8616",
    "describe_x86_16_projection_cleanup_rules",
]


def describe_x86_16_projection_cleanup_rules() -> tuple[tuple[str, str], ...]:
    return PROJECTION_CLEANUP_RULES


def _virtual_expr_keys_8616(node) -> tuple[tuple[str, object], ...]:
    keys: list[tuple[str, object]] = []
    dirty = getattr(node, "dirty", None)
    if isinstance(node, CDirtyExpression) and dirty is not None:
        if isinstance(dirty, str) and dirty:
            keys.append(("dirty-name", dirty))
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            keys.append(("dirty-varid", varid))
        tmp_idx = getattr(dirty, "tmp_idx", None)
        if isinstance(tmp_idx, int):
            keys.append(("dirty-tmp", tmp_idx))
        name = getattr(dirty, "name", None)
        if isinstance(name, str) and name:
            keys.append(("dirty-name", name))
        reg_offset = None
        for attr in ("reg_offset", "reg", "variable_offset"):
            value = getattr(dirty, attr, None)
            if isinstance(value, int):
                reg_offset = value
                break
        bits = getattr(dirty, "bits", None)
        if not isinstance(bits, int):
            size = getattr(dirty, "size", None)
            if isinstance(size, int):
                bits = size * 8
        if isinstance(reg_offset, int):
            keys.append(("dirty-reg", (reg_offset, bits if isinstance(bits, int) else None)))
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        name = getattr(node, "name", None) or getattr(variable, "name", None)
        if isinstance(name, str) and name.startswith(("tmp_", "vvar_", "ir_")):
            keys.append(("virtual-name", name))
    return tuple(dict.fromkeys(keys))


def _virtual_expr_key_8616(node) -> tuple[str, object] | None:
    keys = _virtual_expr_keys_8616(node)
    if keys:
        return keys[0]
    return None


def _debug_c_repr_8616(node) -> str:
    try:
        return "".join(str(text) for text, _obj in node.c_repr_chunks(asexpr=True))
    except Exception:
        return repr(node)


def _pure_virtual_inline_rhs_8616(expr) -> bool:
    if isinstance(expr, (CConstant, CVariable, CDirtyExpression)):
        return True
    if isinstance(expr, CTypeCast):
        return _pure_virtual_inline_rhs_8616(expr.expr)
    if isinstance(expr, CUnaryOp):
        if expr.op in {"Dereference", "Reference"}:
            return False
        return _pure_virtual_inline_rhs_8616(expr.operand)
    if isinstance(expr, CBinaryOp):
        return _pure_virtual_inline_rhs_8616(expr.lhs) and _pure_virtual_inline_rhs_8616(expr.rhs)
    if isinstance(expr, CITE):
        return (
            _pure_virtual_inline_rhs_8616(expr.cond)
            and _pure_virtual_inline_rhs_8616(expr.iftrue)
            and _pure_virtual_inline_rhs_8616(expr.iffalse)
        )
    return False


def _expr_contains_virtual_key_8616(node, target_key: tuple[str, object]) -> bool:
    if node is None:
        return False
    if _virtual_expr_key_8616(node) == target_key:
        return True
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child) and _expr_contains_virtual_key_8616(child, target_key):
            return True
    for attr in ("statements", "operands", "args"):
        seq = getattr(node, attr, None)
        if not seq:
            continue
        for item in seq:
            if _structured_codegen_node_8616(item) and _expr_contains_virtual_key_8616(item, target_key):
                return True
            if isinstance(item, tuple):
                for subitem in item:
                    if _structured_codegen_node_8616(subitem) and _expr_contains_virtual_key_8616(subitem, target_key):
                        return True
    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for cond, body in pairs:
            if _structured_codegen_node_8616(cond) and _expr_contains_virtual_key_8616(cond, target_key):
                return True
            if _structured_codegen_node_8616(body) and _expr_contains_virtual_key_8616(body, target_key):
                return True
    return False


def _inline_single_assignment_virtual_expressions_8616(codegen) -> bool:
    """Inline pure SSA-like virtual definitions by structural AST evidence.

    This consumes CDirtyExpression/CVariable virtual definitions that are unique
    in the function. It does not inspect rendered C text and refuses any RHS
    with memory/call/address side effects.
    """

    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False

    def _walk(node):
        if node is None:
            return
        yield node
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                yield from _walk(child)
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    yield from _walk(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            yield from _walk(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    yield from _walk(cond)
                if _structured_codegen_node_8616(body):
                    yield from _walk(body)

    definitions: dict[tuple[str, object], object | None] = {}
    candidate_count = 0
    refused_count = 0
    for node in _walk(root):
        if not isinstance(node, CAssignment):
            continue
        keys = _virtual_expr_keys_8616(getattr(node, "lhs", None))
        if not keys:
            continue
        candidate_count += 1
        rhs = getattr(node, "rhs", None)
        if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
            _log.warning("[virtual-inline] def keys=%r lhs=%s rhs=%s", keys, _debug_c_repr_8616(node.lhs), _debug_c_repr_8616(rhs))
        if not _pure_virtual_inline_rhs_8616(rhs) or any(_expr_contains_virtual_key_8616(rhs, key) for key in keys):
            for key in keys:
                definitions[key] = None
            refused_count += 1
            continue
        if any(key in definitions for key in keys):
            for key in keys:
                definitions[key] = None
            refused_count += 1
            continue
        for key in keys:
            definitions[key] = rhs

    replacements = {key: rhs for key, rhs in definitions.items() if rhs is not None}
    if not replacements:
        if candidate_count:
            codegen._inertia_virtual_inline_candidates = int(
                getattr(codegen, "_inertia_virtual_inline_candidates", 0) or 0
            ) + candidate_count
            codegen._inertia_virtual_inline_refused = int(
                getattr(codegen, "_inertia_virtual_inline_refused", 0) or 0
            ) + refused_count
        return False

    changed = False

    def _transform(node, *, assignment_lhs: bool = False):
        nonlocal changed
        if node is None:
            return node
        if not assignment_lhs:
            keys = _virtual_expr_keys_8616(node)
            key = next((candidate_key for candidate_key in keys if candidate_key in replacements), None)
            replacement = replacements.get(key)
            if replacement is not None:
                if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
                    _log.warning(
                        "[virtual-inline] replace key=%r expr=%s replacement=%s",
                        key,
                        _debug_c_repr_8616(node),
                        _debug_c_repr_8616(replacement),
                    )
                changed = True
                return replacement
            if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE") and keys:
                _log.warning("[virtual-inline] no replacement keys=%r expr=%s", keys, _debug_c_repr_8616(node))
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            new_child = _transform(
                child,
                assignment_lhs=attr == "lhs" and isinstance(node, CAssignment),
            )
            if new_child is not child:
                setattr(node, attr, new_child)
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            new_seq = []
            seq_changed = False
            for item in seq:
                if _structured_codegen_node_8616(item):
                    new_item = _transform(item)
                    new_seq.append(new_item)
                    seq_changed |= new_item is not item
                else:
                    new_seq.append(item)
            if seq_changed:
                setattr(node, attr, new_seq)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            new_pairs = []
            pair_changed = False
            for cond, body in pairs:
                new_cond = _transform(cond) if _structured_codegen_node_8616(cond) else cond
                new_body = _transform(body) if _structured_codegen_node_8616(body) else body
                pair_changed |= new_cond is not cond or new_body is not body
                new_pairs.append((new_cond, new_body))
            if pair_changed:
                setattr(node, "condition_and_nodes", new_pairs)
        return node

    _transform(root)

    def _count_virtual_key_uses_8616(node, target_key: tuple[str, object], *, assignment_lhs: bool = False) -> int:
        if node is None:
            return 0
        total = 0
        if not assignment_lhs and target_key in _virtual_expr_keys_8616(node):
            total += 1
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                total += _count_virtual_key_uses_8616(
                    child,
                    target_key,
                    assignment_lhs=attr == "lhs" and isinstance(node, CAssignment),
                )
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    total += _count_virtual_key_uses_8616(item, target_key)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            total += _count_virtual_key_uses_8616(subitem, target_key)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    total += _count_virtual_key_uses_8616(cond, target_key)
                if _structured_codegen_node_8616(body):
                    total += _count_virtual_key_uses_8616(body, target_key)
        return total

    def _prune_consumed_virtual_definitions_8616(node) -> int:
        pruned = 0
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            kept = []
            for statement in statements:
                keys = _virtual_expr_keys_8616(getattr(statement, "lhs", None)) if isinstance(statement, CAssignment) else ()
                if (
                    keys
                    and any(key in replacements for key in keys)
                    and _pure_virtual_inline_rhs_8616(getattr(statement, "rhs", None))
                    and all(_count_virtual_key_uses_8616(root, key) == 0 for key in keys)
                ):
                    pruned += 1
                    continue
                kept.append(statement)
            if len(kept) != len(statements):
                node.statements = kept
        for child in _walk(node):
            if child is node:
                continue
            child_statements = getattr(child, "statements", None)
            if isinstance(child_statements, list):
                kept = []
                for statement in child_statements:
                    keys = _virtual_expr_keys_8616(getattr(statement, "lhs", None)) if isinstance(statement, CAssignment) else ()
                    if (
                        keys
                        and any(key in replacements for key in keys)
                        and _pure_virtual_inline_rhs_8616(getattr(statement, "rhs", None))
                        and all(_count_virtual_key_uses_8616(root, key) == 0 for key in keys)
                    ):
                        pruned += 1
                        continue
                    kept.append(statement)
                if len(kept) != len(child_statements):
                    child.statements = kept
        return pruned

    if changed:
        pruned_defs = _prune_consumed_virtual_definitions_8616(root)
        if pruned_defs:
            codegen._inertia_virtual_inline_pruned_defs = int(
                getattr(codegen, "_inertia_virtual_inline_pruned_defs", 0) or 0
            ) + pruned_defs
        codegen._inertia_virtual_inline_candidates = int(
            getattr(codegen, "_inertia_virtual_inline_candidates", 0) or 0
        ) + candidate_count
        codegen._inertia_virtual_inline_materialized = int(
            getattr(codegen, "_inertia_virtual_inline_materialized", 0) or 0
        ) + len(replacements)
        codegen._inertia_virtual_inline_refused = int(
            getattr(codegen, "_inertia_virtual_inline_refused", 0) or 0
        ) + refused_count
    return changed


def _simplify_boolean_cites_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        if not isinstance(node, CITE):
            return node
        values = _bool_cite_values_8616(node)
        if values == (1, 0):
            return node.cond
        if values == (0, 1):
            return CUnaryOp("Not", node.cond, codegen=codegen, tags=getattr(node, "tags", None))
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(
                statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=codegen
            )
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _simplify_structured_expressions_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _invert_cmp_op_8616(op: str) -> str | None:
        return {
            "CmpGT": "CmpLE",
            "CmpGE": "CmpLT",
            "CmpLT": "CmpGE",
            "CmpLE": "CmpGT",
            "CmpEQ": "CmpNE",
            "CmpNE": "CmpEQ",
        }.get(op)

    def _is_c_constant_int_8616(expr, value: int) -> bool:
        return isinstance(expr, CConstant) and isinstance(expr.value, int) and expr.value == value

    def _c_constant_int_value_8616(expr) -> int | None:
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return int(expr.value)
        return None

    def _is_power_of_two_minus_one_8616(value: int) -> bool:
        """Check if value is of form 2^n - 1 (all bits set up to position n-1)."""
        if value <= 0:
            return False
        return (value & (value + 1)) == 0

    def _bit_position_of_power_of_two_8616(value: int) -> int | None:
        """Return n if value == 2^n, else None."""
        if value <= 0 or (value & (value - 1)) != 0:
            return None
        return (value - 1).bit_length()

    def _leading_set_bits_8616(value: int) -> int:
        """Return position of highest set bit (1-indexed, so 0xFF -> 8)."""
        if value == 0:
            return 0
        return value.bit_length()

    def _extract_same_zero_compare_expr_8616(expr):
        if not isinstance(expr, CBinaryOp) or expr.op != "CmpEQ":
            return None
        if _is_c_constant_int_8616(expr.rhs, 0):
            return expr.lhs
        if _is_c_constant_int_8616(expr.lhs, 0):
            return expr.rhs
        return None

    def _extract_zero_flag_source_expr_8616(expr):
        if isinstance(expr, CBinaryOp):
            if expr.op == "Mul":
                for maybe_logic, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                    if not _is_c_constant_int_8616(maybe_scale, 64):
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

            for child in (expr.lhs, expr.rhs):
                if _structured_codegen_node_8616(child):
                    extracted = _extract_zero_flag_source_expr_8616(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(expr, CUnaryOp):
            child = getattr(expr, "operand", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        elif isinstance(expr, CTypeCast):
            child = getattr(expr, "expr", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        return None

    def _shifted_high_byte_source_8616(expr):
        while isinstance(expr, CTypeCast):
            expr = getattr(expr, "expr", None)
        if not isinstance(expr, CBinaryOp):
            return None
        if expr.op == "Shl" and _is_c_constant_int_8616(expr.rhs, 8):
            return expr.lhs
        if expr.op == "Mul" and _is_c_constant_int_8616(expr.rhs, 0x100):
            return expr.lhs
        if expr.op == "Mul" and _is_c_constant_int_8616(expr.lhs, 0x100):
            return expr.rhs
        return None

    def _or_terms_8616(expr) -> list[object]:
        if isinstance(expr, CBinaryOp) and expr.op == "Or":
            return [*_or_terms_8616(expr.lhs), *_or_terms_8616(expr.rhs)]
        return [expr]

    def _match_word_or_carrier_expr_8616(expr, target) -> int | None:
        terms = _or_terms_8616(expr)
        constant_terms: list[int] = []
        saw_target = False
        saw_shifted_target = False
        for term in terms:
            const_value = _c_constant_int_value_8616(term)
            if const_value is not None:
                constant_terms.append(const_value)
                continue
            if _same_c_expression_8616(term, target):
                saw_target = True
                continue
            shifted = _shifted_high_byte_source_8616(term)
            if shifted is not None and _same_c_expression_8616(shifted, target):
                saw_shifted_target = True
                continue
            return None
        if not saw_target or not saw_shifted_target or len(constant_terms) != 1:
            return None
        value = constant_terms[0]
        if value < 0 or value > 0xFF:
            return None
        return value

    def _match_word_or_carrier_expr_pair_8616(expr, low_target, high_target) -> int | None:
        terms = _or_terms_8616(expr)
        constant_terms: list[int] = []
        saw_low = False
        saw_shifted_high = False
        for term in terms:
            const_value = _c_constant_int_value_8616(term)
            if const_value is not None:
                constant_terms.append(const_value)
                continue
            if _same_c_expression_8616(term, low_target):
                saw_low = True
                continue
            shifted = _shifted_high_byte_source_8616(term)
            if shifted is not None and _same_c_expression_8616(shifted, high_target):
                saw_shifted_high = True
                continue
            return None
        if not saw_low or not saw_shifted_high or len(constant_terms) != 1:
            return None
        value = constant_terms[0]
        if value < 0 or value > 0xFF:
            return None
        return value

    def _match_word_or_carrier_shift_8616(expr, target) -> int | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shr":
            return None
        if not _is_c_constant_int_8616(expr.rhs, 8):
            return None
        return _match_word_or_carrier_expr_8616(expr.lhs, target)

    def _match_word_or_carrier_pair_shift_8616(expr, low_target, high_target) -> int | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shr":
            return None
        if not _is_c_constant_int_8616(expr.rhs, 8):
            return None
        return _match_word_or_carrier_expr_pair_8616(expr.lhs, low_target, high_target)

    def _stack_word_contains_high_byte_8616(word_expr, high_expr) -> bool:
        word_domain = _storage_domain_for_expr(word_expr)
        high_domain = _storage_domain_for_expr(high_expr)
        if getattr(word_domain, "space", None) != "stack" or getattr(high_domain, "space", None) != "stack":
            return False
        word_slot = getattr(word_domain, "stack_slot", None)
        high_slot = getattr(high_domain, "stack_slot", None)
        if word_slot is None or high_slot is None:
            return False
        if getattr(word_slot, "base", None) != getattr(high_slot, "base", None):
            return False
        if getattr(word_slot, "region", None) != getattr(high_slot, "region", None):
            return False
        word_offset = _canonical_stack_offset_8616(getattr(word_slot, "offset", None))
        high_offset = _canonical_stack_offset_8616(getattr(high_slot, "offset", None))
        if not isinstance(word_offset, int) or not isinstance(high_offset, int):
            return False
        return int(getattr(word_domain, "width", 0) or 0) == 2 and high_offset == word_offset + 1

    def _materialize_joined_word_expr_8616(low_expr, high_expr):
        low_domain = _storage_domain_for_expr(low_expr)
        high_domain = _storage_domain_for_expr(high_expr)
        alias_state = getattr(codegen, "_inertia_alias_state", None)
        if alias_state is None:
            alias_state = getattr(getattr(codegen, "cfunc", None), "_inertia_alias_state", None)
        proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        if isinstance(low_expr, CVariable) and isinstance(high_expr, CVariable):
            widened_register = join_adjacent_register_slices(
                low_expr,
                high_expr,
                codegen,
                alias_state=alias_state,
                proof=proof,
            )
            if widened_register is not None:
                return widened_register
            if isinstance(getattr(low_expr, "variable", None), SimRegisterVariable) or isinstance(
                getattr(high_expr, "variable", None), SimRegisterVariable
            ):
                return None
        joined = proof.merged_domain if proof.ok else None
        if joined is None and alias_state is None:
            joined = low_domain.join(high_domain)
        if joined is None or joined.width != 2:
            return None
        if not isinstance(low_expr, CVariable) or not isinstance(high_expr, CVariable):
            return None

        region = getattr(getattr(codegen, "cfunc", None), "addr", None)
        vartype = (
            getattr(low_expr, "variable_type", None) or getattr(high_expr, "variable_type", None) or SimTypeShort(False)
        )

        if joined.space == "stack" and joined.stack_slot is not None:
            stack_slot = joined.stack_slot
            offset = _canonical_stack_offset_8616(stack_slot.offset)
            if not isinstance(offset, int):
                return None
            variable = SimStackVariable(
                offset,
                2,
                base=stack_slot.base,
                name=_stack_object_name(offset, codegen=codegen),
                region=stack_slot.region if stack_slot.region is not None else region,
            )
            return CVariable(variable, variable_type=vartype, codegen=codegen)

        if joined.space == "memory":
            # Keep structuring-stage guard operands in register form.
            # Folding to a global memory word here can perturb whole-tail
            # validation fingerprints (reg -> memory read) even when the
            # expression is algebraically equivalent.
            stage = str(getattr(getattr(codegen, "project", None), "_inertia_decompiler_stage", "") or "")
            if stage in {"core", "structuring"}:
                return None
            low_var = getattr(low_expr, "variable", None)
            high_var = getattr(high_expr, "variable", None)
            low_addr = getattr(low_var, "addr", None)
            high_addr = getattr(high_var, "addr", None)
            if isinstance(low_addr, int) and isinstance(high_addr, int):
                addr = min(low_addr, high_addr)
                variable = SimMemoryVariable(addr, 2, name=f"g_{addr:x}", region=region)
                return CVariable(variable, variable_type=vartype, codegen=codegen)

        if joined.space == "register":
            low_var = getattr(low_expr, "variable", None)
            high_var = getattr(high_expr, "variable", None)
            low_reg = getattr(low_var, "reg", None)
            high_reg = getattr(high_var, "reg", None)
            if isinstance(low_reg, int) and isinstance(high_reg, int):
                reg = min(low_reg, high_reg)
                variable = SimRegisterVariable(
                    reg, 2, name=getattr(low_var, "name", None) or getattr(high_var, "name", None)
                )
                return CVariable(variable, variable_type=vartype, codegen=codegen)

        return None

    def _simplify_zero_flag_comparison_8616(expr):
        if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
            return expr

        if _is_c_constant_int_8616(expr.rhs, 0):
            source = expr.lhs
        elif _is_c_constant_int_8616(expr.lhs, 0):
            source = expr.rhs
        else:
            return expr

        source_expr = _extract_zero_flag_source_expr_8616(source)
        if source_expr is None:
            return expr
        if expr.op == "CmpEQ":
            return source_expr
        return CUnaryOp("Not", source_expr, codegen=codegen)

    def transform(node):
        if isinstance(node, CBinaryOp) and node.op == "Concat":
            lhs_val = _c_constant_value_8616(node.lhs)
            rhs_val = _c_constant_value_8616(node.rhs)
            rhs_bits = getattr(getattr(node.rhs, "type", None), "size", None)
            lhs_bits = getattr(getattr(node.lhs, "type", None), "size", None)
            if rhs_bits is None:
                rhs_bits = lhs_bits if lhs_bits is not None else 16

            if lhs_val is not None and rhs_val is not None:
                return CConstant((lhs_val << rhs_bits) | rhs_val, getattr(node, "type", None), codegen=codegen)

            shift = CConstant(
                rhs_bits, getattr(node.rhs, "type", None) or getattr(node.lhs, "type", None), codegen=codegen
            )
            return CBinaryOp(
                "Or",
                CBinaryOp("Shl", node.lhs, shift, codegen=codegen, tags=getattr(node, "tags", None)),
                node.rhs,
                codegen=codegen,
                tags=getattr(node, "tags", None),
            )

        if isinstance(node, CBinaryOp) and node.op == "Mul":
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = (
                    getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                )
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CBinaryOp) and node.op == "Or":
            folded = None
            shifted_rhs = _shifted_high_byte_source_8616(node.rhs)
            if shifted_rhs is not None:
                folded = _materialize_joined_word_expr_8616(node.lhs, shifted_rhs)
            if folded is None:
                shifted_lhs = _shifted_high_byte_source_8616(node.lhs)
                if shifted_lhs is not None:
                    folded = _materialize_joined_word_expr_8616(node.rhs, shifted_lhs)
            if folded is not None:
                return folded
            if _is_c_constant_int_8616(node.lhs, 0):
                return node.rhs
            if _is_c_constant_int_8616(node.rhs, 0):
                return node.lhs

        if isinstance(node, CBinaryOp) and node.op == "And":
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = (
                    getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                )
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CUnaryOp) and node.op == "Not":
            operand = getattr(node, "operand", None)
            if isinstance(operand, CUnaryOp) and operand.op == "Not":
                return operand.operand
            if isinstance(operand, CBinaryOp):
                inverted = _invert_cmp_op_8616(operand.op)
                if inverted is not None:
                    return CBinaryOp(
                        inverted,
                        operand.lhs,
                        operand.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None) or getattr(operand, "tags", None),
                    )

        simplified = _simplify_zero_flag_comparison_8616(node)
        if simplified is not node:
            return simplified

        if (
            isinstance(node, CBinaryOp)
            and node.op in {"LogicalAnd", "LogicalOr", "And", "Or"}
            and _same_c_expression_8616(node.lhs, node.rhs)
        ):
            return node.lhs
        if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE"}:
            if isinstance(node.rhs, CConstant) and node.rhs.value == 0:
                if isinstance(node.lhs, CBinaryOp) and node.lhs.op == "Sub" and isinstance(node.lhs.rhs, CConstant):
                    return CBinaryOp(
                        node.op,
                        node.lhs.lhs,
                        node.lhs.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
            if isinstance(node.lhs, CConstant) and node.lhs.value == 0:
                if isinstance(node.rhs, CBinaryOp) and node.rhs.op == "Sub" and isinstance(node.rhs.rhs, CConstant):
                    return CBinaryOp(
                        node.op,
                        node.rhs.lhs,
                        node.rhs.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
        if isinstance(node, CBinaryOp) and node.op == "Sub" and _same_c_expression_8616(node.lhs, node.rhs):
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
            if type_ is not None:
                return CConstant(0, type_, codegen=codegen)
        return node

    def _materialize_word_or_update_statements_8616(root_node) -> bool:
        changed_local = False

        def _unwrap_expr_8616(expr):
            while isinstance(expr, CTypeCast):
                expr = getattr(expr, "expr", None)
            return expr

        def _virtual_assignment_key_8616(stmt) -> tuple[str, object] | None:
            if not isinstance(stmt, CAssignment):
                return None
            return _virtual_expr_key_8616(getattr(stmt, "lhs", None))

        def _virtual_assignment_keys_8616(stmt) -> tuple[tuple[str, object], ...]:
            if not isinstance(stmt, CAssignment):
                return ()
            return _virtual_expr_keys_8616(getattr(stmt, "lhs", None))

        def _copy_alias_map_8616(statements: list[object]) -> dict[tuple[str, object], object]:
            aliases: dict[tuple[str, object], object] = {}
            for candidate in statements:
                if not isinstance(candidate, CAssignment):
                    continue
                keys = _virtual_assignment_keys_8616(candidate)
                if not keys:
                    continue
                rhs = getattr(candidate, "rhs", None)
                if not _pure_virtual_inline_rhs_8616(rhs):
                    for key in keys:
                        aliases.pop(key, None)
                    continue
                for key in keys:
                    aliases[key] = rhs
            return aliases

        def _debug_aliases_8616(aliases: dict[tuple[str, object], object]) -> list[str]:
            if not os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                return []
            return [f"{key}={_debug_c_repr_8616(value)}" for key, value in sorted(aliases.items(), key=str)]

        def _resolve_copy_alias_expr_8616(expr, aliases: dict[tuple[str, object], object], used: set[tuple[str, object]]):
            expr = _unwrap_expr_8616(expr)
            keys = _virtual_expr_keys_8616(expr)
            if not keys:
                return expr
            key = next((candidate_key for candidate_key in keys if candidate_key in aliases), None)
            if key is None:
                return expr
            replacement = aliases.get(key)
            if replacement is None:
                return expr
            used.add(key)
            replacement_key = _virtual_expr_key_8616(replacement)
            if replacement_key == key:
                return expr
            return _resolve_copy_alias_expr_8616(replacement, aliases, used)

        def _match_joined_stack_word_base_8616(
            expr,
            word_target,
            high_target,
            aliases: dict[tuple[str, object], object],
            used: set[tuple[str, object]],
        ):
            expr = _unwrap_expr_8616(expr)
            if not isinstance(expr, CBinaryOp) or expr.op != "Or":
                return None
            for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                low_expr = _resolve_copy_alias_expr_8616(maybe_low, aliases, used)
                shifted = _shifted_high_byte_source_8616(maybe_high)
                if shifted is None:
                    continue
                high_expr = _resolve_copy_alias_expr_8616(shifted, aliases, used)
                if _same_c_expression_8616(low_expr, word_target) and _same_c_expression_8616(high_expr, high_target):
                    return word_target
            return None

        def _same_after_copy_alias_8616(
            left,
            right,
            aliases: dict[tuple[str, object], object],
            used: set[tuple[str, object]],
        ) -> bool:
            left_resolved = _resolve_copy_alias_expr_8616(left, aliases, used)
            right_resolved = _resolve_copy_alias_expr_8616(right, aliases, used)
            return _same_c_expression_8616(left_resolved, right_resolved)

        def _contains_unresolved_virtual_expr_8616(expr) -> bool:
            if expr is None:
                return False
            if _virtual_expr_key_8616(expr) is not None:
                return True
            for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
                child = getattr(expr, attr, None)
                if _structured_codegen_node_8616(child) and _contains_unresolved_virtual_expr_8616(child):
                    return True
            for attr in ("operands", "args"):
                seq = getattr(expr, attr, None)
                if not seq:
                    continue
                for item in seq:
                    if _structured_codegen_node_8616(item) and _contains_unresolved_virtual_expr_8616(item):
                        return True
                    if isinstance(item, tuple):
                        for subitem in item:
                            if _structured_codegen_node_8616(subitem) and _contains_unresolved_virtual_expr_8616(subitem):
                                return True
            return False

        def _match_stack_word_arithmetic_update_8616(
            low_rhs,
            high_rhs,
            word_target,
            high_target,
            aliases: dict[tuple[str, object], object],
        ) -> tuple[str, object, set[tuple[str, object]]] | None:
            def _refuse(reason: str) -> None:
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] arithmetic-pair refused reason=%s low_op=%r high_op=%r high_lhs_op=%r word_domain=%r high_domain=%r aliases=%r",
                        reason,
                        getattr(low_rhs, "op", None),
                        getattr(high_rhs, "op", None),
                        getattr(getattr(high_rhs, "lhs", None), "op", None),
                        _storage_domain_for_expr(word_target),
                        _storage_domain_for_expr(high_target),
                        _debug_aliases_8616(aliases),
                    )

            used: set[tuple[str, object]] = set()
            low_rhs = _unwrap_expr_8616(low_rhs)
            high_rhs = _unwrap_expr_8616(high_rhs)
            if not isinstance(high_rhs, CBinaryOp) or high_rhs.op != "Shr":
                _refuse("high-not-shr")
                return None
            if not _is_c_constant_int_8616(_unwrap_expr_8616(high_rhs.rhs), 8):
                _refuse("shift-not-8")
                return None
            update_expr = low_rhs
            high_update_expr = _unwrap_expr_8616(high_rhs.lhs)
            if not isinstance(update_expr, CBinaryOp) or update_expr.op not in {"Add", "Sub"}:
                _refuse("update-not-add-sub")
                return None
            if (
                not isinstance(high_update_expr, CBinaryOp)
                or high_update_expr.op not in {"Add", "Sub"}
                or high_update_expr.op != update_expr.op
            ):
                _refuse("high-update-not-same-op")
                return None

            def _arithmetic_candidates_8616(expr) -> list[tuple[object, object]]:
                if not isinstance(expr, CBinaryOp):
                    return []
                if expr.op == "Add":
                    return [(expr.lhs, expr.rhs), (expr.rhs, expr.lhs)]
                if expr.op == "Sub":
                    return [(expr.lhs, expr.rhs)]
                return []

            for maybe_base, maybe_delta in _arithmetic_candidates_8616(update_expr):
                low_used = set(used)
                if _match_joined_stack_word_base_8616(
                    maybe_base,
                    word_target,
                    high_target,
                    aliases,
                    low_used,
                ) is None:
                    continue
                delta = _resolve_copy_alias_expr_8616(maybe_delta, aliases, low_used)
                matched_high = False
                matched_used: set[tuple[str, object]] = set(low_used)
                for high_base, high_delta in _arithmetic_candidates_8616(high_update_expr):
                    high_used = set(low_used)
                    if _match_joined_stack_word_base_8616(
                        high_base,
                        word_target,
                        high_target,
                        aliases,
                        high_used,
                    ) is None:
                        continue
                    resolved_high_delta = _resolve_copy_alias_expr_8616(high_delta, aliases, high_used)
                    if not _same_c_expression_8616(delta, resolved_high_delta):
                        continue
                    matched_high = True
                    matched_used = high_used
                    break
                if not matched_high:
                    continue
                if _expr_contains_virtual_key_8616(delta, _virtual_expr_key_8616(word_target) or ("", "")):
                    _refuse("delta-contains-target")
                    continue
                if _contains_unresolved_virtual_expr_8616(delta):
                    _refuse("delta-unresolved-virtual")
                    continue
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] arithmetic-pair matched op=%s word=%r high=%r delta=%r used=%r",
                        update_expr.op,
                        word_target,
                        high_target,
                        delta,
                        sorted(str(key) for key in matched_used),
                    )
                return update_expr.op, delta, matched_used
            _refuse("base-not-joined-word")
            return None

        def _match_duplicate_word_arithmetic_shift_8616(
            rhs,
            word_target,
            aliases: dict[tuple[str, object], object],
        ) -> tuple[str, object, set[tuple[str, object]]] | None:
            def _refuse(reason: str) -> None:
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] duplicate-shift refused reason=%s target_domain=%r rhs_op=%r rhs_lhs_op=%r rhs=%r target=%r aliases=%r",
                        reason,
                        _storage_domain_for_expr(word_target),
                        getattr(rhs, "op", None),
                        getattr(getattr(rhs, "lhs", None), "op", None),
                        rhs,
                        word_target,
                        _debug_aliases_8616(aliases),
                    )

            target_domain = _storage_domain_for_expr(word_target)
            if getattr(target_domain, "space", None) != "stack" or getattr(target_domain, "width", None) != 2:
                _refuse("target-not-stack-word")
                return None
            used: set[tuple[str, object]] = set()
            rhs = _unwrap_expr_8616(rhs)
            if not isinstance(rhs, CBinaryOp) or rhs.op != "Shr":
                _refuse("rhs-not-shr")
                return None
            if not _is_c_constant_int_8616(_unwrap_expr_8616(rhs.rhs), 8):
                _refuse("shift-not-8")
                return None
            update_expr = _unwrap_expr_8616(rhs.lhs)
            if not isinstance(update_expr, CBinaryOp) or update_expr.op not in {"Add", "Sub"}:
                _refuse("update-not-add-sub")
                return None
            candidates: list[tuple[object, object]] = []
            if update_expr.op == "Add":
                candidates.extend(((update_expr.lhs, update_expr.rhs), (update_expr.rhs, update_expr.lhs)))
            else:
                candidates.append((update_expr.lhs, update_expr.rhs))
            for maybe_base, maybe_delta in candidates:
                candidate_used = set(used)
                base = _unwrap_expr_8616(maybe_base)
                if not isinstance(base, CBinaryOp) or base.op != "Or":
                    continue
                matched_base = False
                for maybe_low, maybe_high in ((base.lhs, base.rhs), (base.rhs, base.lhs)):
                    low_expr = _resolve_copy_alias_expr_8616(maybe_low, aliases, candidate_used)
                    shifted = _shifted_high_byte_source_8616(maybe_high)
                    if shifted is None:
                        continue
                    high_expr = _resolve_copy_alias_expr_8616(shifted, aliases, candidate_used)
                    if _same_c_expression_8616(low_expr, word_target) and _same_c_expression_8616(high_expr, word_target):
                        matched_base = True
                        break
                if not matched_base:
                    continue
                delta = _resolve_copy_alias_expr_8616(maybe_delta, aliases, candidate_used)
                if _contains_unresolved_virtual_expr_8616(delta):
                    _refuse("delta-unresolved-virtual")
                    continue
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] duplicate-shift matched op=%s target=%r delta=%r used=%r",
                        update_expr.op,
                        word_target,
                        delta,
                        sorted(str(key) for key in candidate_used),
                    )
                return update_expr.op, delta, candidate_used
            _refuse("base-not-duplicate-word")
            return None

        def _delete_tail_virtual_aliases_8616(statements: list[object], used_keys: set[tuple[str, object]]) -> None:
            if not used_keys:
                return
            kept: list[object] = []
            for statement in statements:
                keys = _virtual_assignment_keys_8616(statement)
                if keys and any(key in used_keys for key in keys):
                    continue
                kept.append(statement)
            statements[:] = kept

        def visit(node) -> None:
            nonlocal changed_local
            if isinstance(node, list):
                replacement = _rewrite_statement_list_8616(node)
                if replacement is not node:
                    node[:] = replacement
                return
            if isinstance(node, CStatements):
                new_statements = _rewrite_statement_list_8616(list(node.statements))
                if new_statements != node.statements:
                    node.statements = new_statements
                return
            pairs = getattr(node, "condition_and_nodes", None)
            if pairs:
                for _cond, body in pairs:
                    if _structured_codegen_node_8616(body):
                        visit(body)
            for attr in ("body", "else_node", "condition", "init", "iteration"):
                child = getattr(node, attr, None)
                if _structured_codegen_node_8616(child):
                    visit(child)

        def _rewrite_statement_list_8616(statements: list[object]) -> list[object]:
            nonlocal changed_local
            new_statements = []
            i = 0
            while i < len(statements):
                stmt = statements[i]
                next_stmt = statements[i + 1] if i + 1 < len(statements) else None
                copy_aliases = _copy_alias_map_8616(new_statements)
                immediate = None
                shifted_immediate = None
                replacement_lhs = None
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    if isinstance(stmt, CAssignment) or isinstance(next_stmt, CAssignment):
                        same_lhs = (
                            isinstance(stmt, CAssignment)
                            and isinstance(next_stmt, CAssignment)
                            and _same_c_expression_8616(stmt.lhs, next_stmt.lhs)
                        )
                        _log.warning(
                            "[word-or-update] seq i=%d stmt=%s next=%s same_lhs=%s lhs=%s rhs=%s next_lhs=%s next_rhs=%s",
                            i,
                            type(stmt).__name__,
                            type(next_stmt).__name__ if next_stmt is not None else None,
                            same_lhs,
                            type(getattr(stmt, "lhs", None)).__name__,
                            type(getattr(stmt, "rhs", None)).__name__,
                            type(getattr(next_stmt, "lhs", None)).__name__ if next_stmt is not None else None,
                            type(getattr(next_stmt, "rhs", None)).__name__ if next_stmt is not None else None,
                        )
                if isinstance(stmt, CAssignment) and isinstance(next_stmt, CAssignment):
                    if (
                        isinstance(stmt.lhs, CVariable)
                        and isinstance(next_stmt.lhs, CVariable)
                        and _same_c_expression_8616(stmt.lhs, next_stmt.lhs)
                    ):
                        replacement_lhs = stmt.lhs
                        immediate = _match_word_or_carrier_expr_8616(stmt.rhs, stmt.lhs)
                        shifted_immediate = _match_word_or_carrier_shift_8616(next_stmt.rhs, stmt.lhs)
                    elif isinstance(stmt.lhs, CVariable) and isinstance(next_stmt.lhs, CVariable):
                        joined_lhs = _materialize_joined_word_expr_8616(stmt.lhs, next_stmt.lhs)
                        if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                            _log.warning(
                                "[word-or-update] join lhs=%r next_lhs=%r joined=%s low_domain=%r high_domain=%r",
                                stmt.lhs,
                                next_stmt.lhs,
                                type(joined_lhs).__name__ if joined_lhs is not None else None,
                                _storage_domain_for_expr(stmt.lhs),
                                _storage_domain_for_expr(next_stmt.lhs),
                            )
                        if isinstance(joined_lhs, CVariable):
                            replacement_lhs = joined_lhs
                            immediate = _match_word_or_carrier_expr_pair_8616(stmt.rhs, stmt.lhs, next_stmt.lhs)
                            shifted_immediate = _match_word_or_carrier_pair_shift_8616(
                                next_stmt.rhs, stmt.lhs, next_stmt.lhs
                            )
                        elif _stack_word_contains_high_byte_8616(stmt.lhs, next_stmt.lhs):
                            replacement_lhs = stmt.lhs
                            immediate = _match_word_or_carrier_expr_pair_8616(stmt.rhs, stmt.lhs, next_stmt.lhs)
                            shifted_immediate = _match_word_or_carrier_pair_shift_8616(
                                next_stmt.rhs, stmt.lhs, next_stmt.lhs
                            )
                        try:
                            codegen._inertia_word_or_update_candidates = int(
                                getattr(codegen, "_inertia_word_or_update_candidates", 0) or 0
                            ) + 1
                        except Exception:
                            pass
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    try:
                        codegen._inertia_word_arithmetic_shift_candidates = int(
                            getattr(codegen, "_inertia_word_arithmetic_shift_candidates", 0) or 0
                        ) + 1
                    except Exception:
                        pass
                    duplicate_shift = _match_duplicate_word_arithmetic_shift_8616(
                        stmt.rhs,
                        stmt.lhs,
                        copy_aliases,
                    )
                    if duplicate_shift is not None:
                        op, delta, used_keys = duplicate_shift
                        _delete_tail_virtual_aliases_8616(new_statements, used_keys)
                        replacement_rhs = CBinaryOp(
                            op,
                            stmt.lhs,
                            delta,
                            codegen=codegen,
                        )
                        new_statements.append(CAssignment(stmt.lhs, replacement_rhs, codegen=codegen))
                        try:
                            codegen._inertia_word_arithmetic_shift_materialized_count = int(
                                getattr(codegen, "_inertia_word_arithmetic_shift_materialized_count", 0) or 0
                            ) + 1
                        except Exception:
                            pass
                        changed_local = True
                        i += 1
                        continue
                if (
                    replacement_lhs is not None
                    and isinstance(next_stmt, CAssignment)
                    and isinstance(next_stmt.lhs, CVariable)
                    and _stack_word_contains_high_byte_8616(replacement_lhs, next_stmt.lhs)
                ):
                    try:
                        codegen._inertia_word_arithmetic_update_candidates = int(
                            getattr(codegen, "_inertia_word_arithmetic_update_candidates", 0) or 0
                        ) + 1
                    except Exception:
                        pass
                    arithmetic_update = _match_stack_word_arithmetic_update_8616(
                        stmt.rhs,
                        next_stmt.rhs,
                        replacement_lhs,
                        next_stmt.lhs,
                        copy_aliases,
                    )
                    if arithmetic_update is not None:
                        op, delta, used_keys = arithmetic_update
                        _delete_tail_virtual_aliases_8616(new_statements, used_keys)
                        replacement_rhs = CBinaryOp(
                            op,
                            replacement_lhs,
                            delta,
                            codegen=codegen,
                        )
                        new_statements.append(CAssignment(replacement_lhs, replacement_rhs, codegen=codegen))
                        try:
                            codegen._inertia_word_arithmetic_update_materialized_count = int(
                                getattr(codegen, "_inertia_word_arithmetic_update_materialized_count", 0) or 0
                            ) + 1
                        except Exception:
                            pass
                        changed_local = True
                        i += 2
                        continue
                if replacement_lhs is not None and immediate is not None and shifted_immediate == immediate:
                    replacement_rhs = CBinaryOp(
                        "Or",
                        replacement_lhs,
                        CConstant(immediate, getattr(stmt.rhs, "type", None), codegen=codegen),
                        codegen=codegen,
                    )
                    new_statements.append(CAssignment(replacement_lhs, replacement_rhs, codegen=codegen))
                    try:
                        codegen._inertia_word_or_update_materialized_count = int(
                            getattr(codegen, "_inertia_word_or_update_materialized_count", 0) or 0
                        ) + 1
                    except Exception:
                        pass
                    changed_local = True
                    i += 2
                    continue
                if replacement_lhs is not None and isinstance(next_stmt, CAssignment):
                    if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                        term_debug = []
                        for term in _or_terms_8616(getattr(stmt, "rhs", None)):
                            term_debug.append(
                                (
                                    type(term).__name__,
                                    _c_constant_int_value_8616(term),
                                    _same_c_expression_8616(term, getattr(stmt, "lhs", None)),
                                    _same_c_expression_8616(term, getattr(next_stmt, "lhs", None)),
                                    type(_shifted_high_byte_source_8616(term)).__name__
                                    if _shifted_high_byte_source_8616(term) is not None
                                    else None,
                                )
                            )
                        _log.warning(
                            "[word-or-update] refused lhs=%r rhs=%r next_lhs=%r next_rhs=%r immediate=%r shifted=%r terms=%r",
                            stmt.lhs,
                            stmt.rhs,
                            next_stmt.lhs,
                            next_stmt.rhs,
                            immediate,
                            shifted_immediate,
                            term_debug,
                        )
                    try:
                        codegen._inertia_word_or_update_refused = int(
                            getattr(codegen, "_inertia_word_or_update_refused", 0) or 0
                        ) + 1
                    except Exception:
                        pass
                visit(stmt)
                new_statements.append(stmt)
                i += 1
            return new_statements

        visit(root_node)
        return changed_local

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(
                statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=codegen
            )
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    for _ in range(3):
        if not _replace_c_children_8616(root, transform):
            break
        changed = True
    for _ in range(4):
        if not _inline_single_assignment_virtual_expressions_8616(codegen):
            break
        changed = True
    if _materialize_word_or_update_statements_8616(root):
        changed = True
    return changed


def _eliminate_single_use_temporaries_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _safe_inline_expr(expr) -> bool:
        if isinstance(expr, (CConstant, CVariable)):
            return True
        if isinstance(expr, CTypeCast):
            return _safe_inline_expr(expr.expr)
        if isinstance(expr, CUnaryOp):
            if expr.op == "Dereference":
                return False
            return _safe_inline_expr(expr.operand)
        if isinstance(expr, CBinaryOp):
            return _safe_inline_expr(expr.lhs) and _safe_inline_expr(expr.rhs)
        if isinstance(expr, CITE):
            return _safe_inline_expr(expr.cond) and _safe_inline_expr(expr.iftrue) and _safe_inline_expr(expr.iffalse)
        return False

    def _count_var_uses(node, target, *, assignment_lhs: bool = False) -> int:
        if node is None:
            return 0
        if isinstance(node, CVariable):
            return 0 if assignment_lhs else int(_same_c_expression_8616(node, target))

        total = 0
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                total += _count_var_uses(
                    child,
                    target,
                    assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
                )
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    total += _count_var_uses(item, target)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            total += _count_var_uses(subitem, target)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    total += _count_var_uses(cond, target)
                if _structured_codegen_node_8616(body):
                    total += _count_var_uses(body, target)
        return total

    def _replace_var_use(node, target, replacement, *, assignment_lhs: bool = False):
        if isinstance(node, CVariable):
            if not assignment_lhs and _same_c_expression_8616(node, target):
                return replacement, True
            return node, False

        changed_local = False
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            new_child, child_changed = _replace_var_use(
                child,
                target,
                replacement,
                assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
            )
            if child_changed:
                setattr(node, attr, new_child)
                changed_local = True
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            new_seq = []
            seq_changed = False
            for item in seq:
                if _structured_codegen_node_8616(item):
                    new_item, item_changed = _replace_var_use(item, target, replacement)
                    new_seq.append(new_item)
                    seq_changed |= item_changed
                else:
                    new_seq.append(item)
            if seq_changed:
                setattr(node, attr, new_seq)
                changed_local = True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            new_pairs = []
            pair_changed = False
            for cond, body in pairs:
                new_cond, cond_changed = (
                    _replace_var_use(cond, target, replacement)
                    if _structured_codegen_node_8616(cond)
                    else (cond, False)
                )
                new_body, body_changed = (
                    _replace_var_use(body, target, replacement)
                    if _structured_codegen_node_8616(body)
                    else (body, False)
                )
                new_pairs.append((new_cond, new_body))
                pair_changed |= cond_changed or body_changed
            if pair_changed:
                setattr(node, "condition_and_nodes", new_pairs)
                changed_local = True
        return node, changed_local

    changed = False

    def visit(node):
        nonlocal changed
        if not isinstance(node, CStatements):
            return

        new_statements = []
        statements = list(node.statements)
        idx = 0
        while idx < len(statements):
            stmt = statements[idx]
            next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
            removed = False

            if (
                isinstance(stmt, CAssignment)
                and isinstance(stmt.lhs, CVariable)
                and _safe_inline_expr(stmt.rhs)
                and next_stmt is not None
            ):
                immediate_uses = _count_var_uses(next_stmt, stmt.lhs)
                later_uses = sum(_count_var_uses(rest, stmt.lhs) for rest in statements[idx + 2 :])
                if immediate_uses == 1 and later_uses == 0:
                    _, replaced = _replace_var_use(next_stmt, stmt.lhs, stmt.rhs)
                    if replaced:
                        changed = True
                        removed = True

            if not removed:
                new_statements.append(stmt)
                visit(stmt)
            idx += 1

        if len(new_statements) != len(node.statements):
            node.statements = new_statements

    root = codegen.cfunc.statements
    visit(root)
    return changed


def _maybe_eliminate_single_use_temporaries_8616(project, codegen) -> bool:
    if not getattr(project, "_inertia_postprocess_single_use_temporaries_enabled", False):
        return False
    return _eliminate_single_use_temporaries_8616(codegen)
