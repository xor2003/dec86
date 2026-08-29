"""Trace exact modular affine scalar expressions through function SSA.

Layer: IR.
Responsibility: normalize constants, MOVs, ADD/SUB, constant shifts, direct
stack loads, and closed byte-composed logical word loads into one typed affine
expression with exact definition provenance. Unsupported operations, missing
definitions, cross-block flow, and ambiguous sources refuse atomically.
This module does not choose pointer segments, infer aliases or types, mutate
code generation, or consume callsite summaries.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .indexed_address_contracts import (
    IndexedAddressDefinitionSite8616,
    IndexedAddressFailureKind8616,
)
from .logical_memory_value_trace import trace_logical_word_load_8616
from .scalar_affine_contracts import (
    ScalarAffineExpression8616,
    ScalarAffineFailure8616,
    ScalarAffineTerm8616,
    ScalarAffineTrace8616,
    ScalarAffineTraceStats8616,
)
from .scalar_definitions import (
    ScalarDefinition8616,
    ScalarDefinitionIndex8616,
    ScalarDefinitionKey8616,
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
    scalar_definition_key_8616,
)
from .ssa_function import SSAFunctionArtifact


@dataclass(frozen=True, slots=True)
class _AffineNode8616:
    """Internal normalized expression before the root contract is attached."""

    constant: int
    terms: tuple[ScalarAffineTerm8616, ...]
    path: tuple[IndexedAddressDefinitionSite8616, ...]


@dataclass(frozen=True, slots=True)
class _NodeTrace8616:
    """Internal successful node or one typed refusal."""

    node: _AffineNode8616 | None
    failure: ScalarAffineFailure8616 | None


def _refusal_8616(failure: ScalarAffineFailure8616) -> ScalarAffineTrace8616:
    """Build one atomic trace refusal with closed failure accounting."""
    return ScalarAffineTrace8616(
        None,
        failure,
        ScalarAffineTraceStats8616(1, 1, 1, 0, 1),
    )


def _site_8616(
    definition: ScalarDefinition8616,
) -> IndexedAddressDefinitionSite8616 | None:
    """Project one scalar definition to an exact path site."""
    instruction = definition.instruction
    if instruction.addr is None:
        return None
    return IndexedAddressDefinitionSite8616(
        definition.block_addr,
        definition.instr_index,
        instruction.addr,
        instruction.op,
    )


def _definition_8616(
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
) -> tuple[ScalarDefinition8616 | None, ScalarAffineFailure8616 | None]:
    """Return one exact same-block reaching definition or a typed refusal."""
    candidates = reaching_scalar_definitions_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not candidates:
        return None, ScalarAffineFailure8616.DEFINITION_MISSING
    if len(candidates) != 1:
        return None, ScalarAffineFailure8616.DEFINITION_CONFLICT
    return candidates[0], None


def _logical_failure_8616(
    failure: IndexedAddressFailureKind8616 | None,
) -> ScalarAffineFailure8616:
    """Map logical-load tracing failures to the scalar affine contract."""
    if failure is IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING:
        return ScalarAffineFailure8616.DEFINITION_MISSING
    if failure is IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT:
        return ScalarAffineFailure8616.DEFINITION_CONFLICT
    if failure is IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED:
        return ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED
    return ScalarAffineFailure8616.SOURCE_UNPROVEN


def _stack_source_8616(instruction: IRInstr, width: int) -> IRAddress | None:
    """Return one exact direct BP-relative scalar LOAD source."""
    address = instruction.args[0] if instruction.args else None
    if (
        instruction.op != "LOAD"
        or instruction.size != width
        or not isinstance(address, IRAddress)
        or address.space is not MemSpace.SS
        or address.base != ("bp",)
        or address.size != width
        or address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
    ):
        return None
    return address


def _scale_node_8616(
    node: _AffineNode8616,
    factor: int,
    mask: int,
) -> _AffineNode8616:
    """Apply one modular constant scale without losing term provenance."""
    terms = tuple(
        ScalarAffineTerm8616(term.value, term.source, coefficient)
        for term in node.terms
        if (coefficient := term.coefficient * factor & mask) != 0
    )
    return _AffineNode8616(node.constant * factor & mask, terms, node.path)


def _combine_nodes_8616(
    left: _AffineNode8616,
    right: _AffineNode8616,
    *,
    sign: int,
    mask: int,
) -> _AffineNode8616:
    """Combine two affine nodes under modular addition or subtraction."""
    scaled_right = _scale_node_8616(right, sign, mask)
    return _AffineNode8616(
        (left.constant + scaled_right.constant) & mask,
        (*left.terms, *scaled_right.terms),
        (*left.path, *scaled_right.path),
    )


def _trace_value_8616(
    artifact: SSAFunctionArtifact,
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
    width: int,
    mask: int,
    seen: frozenset[ScalarDefinitionKey8616] = frozenset(),
) -> _NodeTrace8616:
    """Recursively normalize one exact scalar value inside one SSA block."""
    if value.size != width:
        return _NodeTrace8616(None, ScalarAffineFailure8616.WIDTH_CONFLICT)
    if isinstance(value.const, int):
        return _NodeTrace8616(_AffineNode8616(value.const & mask, (), ()), None)
    key = scalar_definition_key_8616(value)
    if key in seen:
        return _NodeTrace8616(None, ScalarAffineFailure8616.DEFINITION_CONFLICT)
    definition, failure = _definition_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if failure is not None or definition is None:
        return _NodeTrace8616(None, failure or ScalarAffineFailure8616.DEFINITION_MISSING)
    site = _site_8616(definition)
    if site is None:
        return _NodeTrace8616(None, ScalarAffineFailure8616.SOURCE_UNPROVEN)
    instruction = definition.instruction
    source = _stack_source_8616(instruction, width)
    if source is not None and instruction.dst is not None:
        term = ScalarAffineTerm8616(instruction.dst, source, 1)
        return _NodeTrace8616(_AffineNode8616(0, (term,), (site,)), None)
    if instruction.op == "Iop_Or16" and width == 2:
        logical = trace_logical_word_load_8616(
            instruction,
            definitions,
            artifact.logical_memory,
            function_addr=artifact.function_addr,
            block_addr=block_addr,
            before_index=definition.instr_index,
        )
        if not logical.complete or logical.source is None or instruction.dst is None:
            return _NodeTrace8616(None, _logical_failure_8616(logical.failure))
        term = ScalarAffineTerm8616(instruction.dst, logical.source, 1)
        return _NodeTrace8616(
            _AffineNode8616(0, (term,), (site, *logical.definition_path)),
            None,
        )
    next_seen = seen | {key}
    if instruction.op == "MOV" and len(instruction.args) == 1:
        argument = instruction.args[0]
        if not isinstance(argument, IRValue):
            return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
        traced = _trace_value_8616(
            artifact,
            definitions,
            argument,
            block_addr=block_addr,
            before_index=definition.instr_index,
            width=width,
            mask=mask,
            seen=next_seen,
        )
        if traced.node is None:
            return traced
        return _NodeTrace8616(
            _AffineNode8616(
                traced.node.constant,
                traced.node.terms,
                (site, *traced.node.path),
            ),
            None,
        )
    expected_suffix = str(width * 8)
    if instruction.op in {f"Iop_Add{expected_suffix}", f"Iop_Sub{expected_suffix}"}:
        if len(instruction.args) != 2:
            return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
        left, right = instruction.args
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
        left_trace = _trace_value_8616(
            artifact,
            definitions,
            left,
            block_addr=block_addr,
            before_index=definition.instr_index,
            width=width,
            mask=mask,
            seen=next_seen,
        )
        if left_trace.node is None:
            return left_trace
        right_trace = _trace_value_8616(
            artifact,
            definitions,
            right,
            block_addr=block_addr,
            before_index=definition.instr_index,
            width=width,
            mask=mask,
            seen=next_seen,
        )
        if right_trace.node is None:
            return right_trace
        combined = _combine_nodes_8616(
            left_trace.node,
            right_trace.node,
            sign=1 if instruction.op.startswith("Iop_Add") else -1,
            mask=mask,
        )
        return _NodeTrace8616(
            _AffineNode8616(combined.constant, combined.terms, (site, *combined.path)),
            None,
        )
    if instruction.op == f"Iop_Shl{expected_suffix}" and len(instruction.args) == 2:
        argument, amount = instruction.args
        if (
            not isinstance(argument, IRValue)
            or not isinstance(amount, IRValue)
            or not isinstance(amount.const, int)
            or not 0 <= amount.const < width * 8
        ):
            return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
        traced = _trace_value_8616(
            artifact,
            definitions,
            argument,
            block_addr=block_addr,
            before_index=definition.instr_index,
            width=width,
            mask=mask,
            seen=next_seen,
        )
        if traced.node is None:
            return traced
        scaled = _scale_node_8616(traced.node, 1 << amount.const, mask)
        return _NodeTrace8616(
            _AffineNode8616(scaled.constant, scaled.terms, (site, *scaled.path)),
            None,
        )
    return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)


def trace_scalar_affine_expression_8616(
    artifact: SSAFunctionArtifact,
    root: IRValue,
    *,
    block_addr: int,
    before_index: int,
) -> ScalarAffineTrace8616:
    """Trace one scalar root to exact modular constants and stack terms."""
    width = root.size
    if width not in {1, 2, 4} or before_index < 0:
        return _refusal_8616(ScalarAffineFailure8616.ROOT_UNPROVEN)
    mask = (1 << (width * 8)) - 1
    traced = _trace_value_8616(
        artifact,
        build_scalar_definition_index_8616(artifact),
        root,
        block_addr=block_addr,
        before_index=before_index,
        width=width,
        mask=mask,
    )
    if traced.node is None or traced.failure is not None:
        return _refusal_8616(traced.failure or ScalarAffineFailure8616.SOURCE_UNPROVEN)
    expression = ScalarAffineExpression8616(
        root,
        width,
        traced.node.constant,
        traced.node.terms,
        traced.node.path,
    )
    if not expression.complete:
        return _refusal_8616(ScalarAffineFailure8616.SOURCE_UNPROVEN)
    return ScalarAffineTrace8616(
        expression,
        None,
        ScalarAffineTraceStats8616(1, 1, 1, 1, 0),
    )


__all__ = ["trace_scalar_affine_expression_8616"]
