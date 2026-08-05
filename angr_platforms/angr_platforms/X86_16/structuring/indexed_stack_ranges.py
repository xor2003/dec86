"""Prove bounded dynamic reads from initialized stack-array prefixes.

Layer: Structuring.
Responsibility: derive typed read proofs from structured loop, assignment, and
lowering evidence without changing the structured C AST.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Forbidden: rendered-C/assembly matching, function-specific exceptions, alias or
type recovery, AST mutation, and validation verdict policy.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimType, SimTypeArray, SimTypeFixedSizeArray
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import (
    StructuredCallKind8616,
    structured_call_kind_8616,
)
from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from ..semantics.call_contracts import RuntimeCallReturnContract8616
from ..widening.segmented_load_identity import segmented_load_identity_8616

__all__ = [
    "IndexedStackReadProof8616",
    "IndexedStackReadProofKind8616",
    "IndexedStackReadProofReport8616",
    "collect_indexed_stack_read_proofs_8616",
]


class _ScalarStorageKind8616(Enum):
    """Scalar storage spaces used by range-expression identities."""

    STACK = "stack"
    MEMORY = "memory"
    REGISTER = "register"
    CONSTANT = "constant"


class _AddressedCallee8616(Protocol):
    """Third-party callee surface carrying an exact binary address."""

    addr: int


@dataclass(frozen=True, slots=True)
class _ScalarStorage8616:
    """Stable scalar identity used by structured range proofs."""

    kind: _ScalarStorageKind8616
    offset: int
    width: int
    region: int | None = None
    ident: str = ""
    space: MemSpace | None = None


@dataclass(frozen=True, order=True, slots=True)
class _StackArrayStorage8616:
    """One bounded BP-relative stack array."""

    offset: int
    width: int
    element_width: int
    element_count: int


class IndexedStackReadProofKind8616(Enum):
    """Kinds of accepted structured stack-array read proofs."""

    INITIALIZED_PREFIX_BOUNDED_INDEX = "initialized_prefix_bounded_index"


@dataclass(frozen=True, slots=True)
class IndexedStackReadProof8616:
    """Proof that one exact dynamic stack-array read selects initialized data."""

    read_node_id: int
    array_offset: int
    array_width: int
    element_width: int
    index_storage_offset: int
    kind: IndexedStackReadProofKind8616

    def matches(self, node: object, *, array_offset: int, array_width: int) -> bool:
        """Return whether this proof belongs to the supplied exact read."""
        return (
            id(node) == self.read_node_id
            and self.array_offset == array_offset
            and self.array_width == array_width
        )


@dataclass(frozen=True, slots=True)
class IndexedStackReadProofReport8616:
    """Closed evidence loop for bounded dynamic stack-array reads."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    proofs: tuple[IndexedStackReadProof8616, ...]

    def by_read_node_id(self) -> dict[int, IndexedStackReadProof8616]:
        """Return exact proofs indexed by in-memory structured read identity."""
        return {proof.read_node_id: proof for proof in self.proofs}


@dataclass(slots=True)
class _MutableProofReport8616:
    """Mutable counters while one structured tree is analyzed."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    proofs: list[IndexedStackReadProof8616] = field(default_factory=list)

    def freeze(self) -> IndexedStackReadProofReport8616:
        """Return an immutable proof report."""
        materialized = len(self.proofs)
        return IndexedStackReadProofReport8616(
            raw_fact_count=self.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count,
            classified_fact_count=self.classified_fact_count,
            materialized_count=materialized,
            failure_count=self.raw_fact_count - materialized,
            proofs=tuple(self.proofs),
        )


@dataclass(slots=True)
class _RangeProofState8616:
    """Path-local prefix, predecessor, and upper-bound facts."""

    prefixes: dict[_StackArrayStorage8616, _ScalarStorage8616]
    predecessors: dict[_ScalarStorage8616, _ScalarStorage8616]
    ranges: dict[_ScalarStorage8616, _ScalarStorage8616]
    constants: dict[_ScalarStorage8616, int]

    def copy(self) -> _RangeProofState8616:
        """Return an independent path state."""
        return _RangeProofState8616(
            prefixes=dict(self.prefixes),
            predecessors=dict(self.predecessors),
            ranges=dict(self.ranges),
            constants=dict(self.constants),
        )


@dataclass(frozen=True, slots=True)
class _AscendingLoop8616:
    """Canonical zero-based unit-stride loop bound."""

    induction: _ScalarStorage8616
    bound: _ScalarStorage8616


@dataclass(frozen=True, slots=True)
class _RemainderCallEvidence8616:
    """Matched signed-remainder call contract and optional output bound."""

    range_bound: _ScalarStorage8616 | None
    call_node_id: int
    call_contract: RuntimeCallReturnContract8616


def _strip_casts_8616(node: object) -> object:
    """Remove structured type casts without changing expression meaning."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


def _type_width_bytes_8616(type_: object) -> int | None:
    """Return a byte width from an angr type when it is fully bound."""
    if not isinstance(type_, SimType):
        return None
    try:
        bit_size = type_.size
    except (AttributeError, ValueError):
        return None
    if not isinstance(bit_size, int) or bit_size <= 0 or bit_size % 8:
        return None
    return bit_size // 8


def _scalar_storage_8616(node: object) -> _ScalarStorage8616 | None:
    """Return stable storage identity for one scalar C variable."""
    node = _strip_casts_8616(node)
    segmented_identity = segmented_load_identity_8616(node)
    if segmented_identity is not None:
        return _ScalarStorage8616(
            kind=_ScalarStorageKind8616.MEMORY,
            offset=segmented_identity.offset,
            width=segmented_identity.width,
            region=None,
            space=segmented_identity.space,
        )
    if isinstance(node, CConstant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return _ScalarStorage8616(
            kind=_ScalarStorageKind8616.CONSTANT,
            offset=node.value,
            width=0,
        )
    if not isinstance(node, CVariable):
        return None
    variables = (node.unified_variable, node.variable)
    variable = next(
        (
            candidate
            for candidate in variables
            if isinstance(candidate, (SimStackVariable, SimMemoryVariable, SimRegisterVariable))
        ),
        None,
    )
    if isinstance(variable, SimStackVariable):
        width = _type_width_bytes_8616(node.type)
        if width is None:
            width = variable.size if isinstance(variable.size, int) else None
        if not isinstance(variable.offset, int) or not isinstance(width, int) or width <= 0:
            return None
        return _ScalarStorage8616(
            kind=_ScalarStorageKind8616.STACK,
            offset=variable.offset,
            width=width,
            region=None,
            space=MemSpace.SS,
        )
    if isinstance(variable, SimMemoryVariable):
        if not isinstance(variable.addr, int) or not isinstance(variable.size, int) or variable.size <= 0:
            return None
        return _ScalarStorage8616(
            kind=_ScalarStorageKind8616.MEMORY,
            offset=variable.addr,
            width=variable.size,
            region=None,
            space=MemSpace.DS,
        )
    if isinstance(variable, SimRegisterVariable):
        if not isinstance(variable.reg, int) or not isinstance(variable.size, int) or variable.size <= 0:
            return None
        ident = ""
        if isinstance(variable.ident, (int, str)):
            ident = f"{type(variable.ident).__name__}:{variable.ident}"
        return _ScalarStorage8616(
            kind=_ScalarStorageKind8616.REGISTER,
            offset=variable.reg,
            width=variable.size,
            region=variable.region if isinstance(variable.region, int) else None,
            ident=ident,
        )
    return None


def _scalar_memory_address_8616(
    storage: _ScalarStorage8616,
) -> IRAddress | None:
    """Return an exact segmented address for one proven memory identity."""
    if (
        storage.kind is not _ScalarStorageKind8616.MEMORY
        or storage.space not in {MemSpace.DS, MemSpace.ES}
        or storage.width <= 0
    ):
        return None
    return IRAddress(
        space=storage.space,
        offset=storage.offset,
        size=storage.width,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _structured_call_target_addr_8616(call: CFunctionCall) -> int | None:
    """Return a structured call's exact third-party callee address."""
    callee = call.callee_func
    if callee is None:
        return None
    try:
        addr = cast(_AddressedCallee8616, callee).addr
    except AttributeError:
        return None
    return addr if isinstance(addr, int) else None


def _stack_array_storage_8616(node: object) -> _StackArrayStorage8616 | None:
    """Return bounded stack-array identity for one C expression."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CVariable) or not isinstance(
        node.type,
        (SimTypeArray, SimTypeFixedSizeArray),
    ):
        return None
    variable = node.unified_variable
    if not isinstance(variable, SimStackVariable):
        variable = node.variable
    if (
        not isinstance(variable, SimStackVariable)
        or not isinstance(variable.offset, int)
        or not isinstance(variable.size, int)
        or variable.size <= 0
        or not isinstance(node.type.length, int)
        or node.type.length <= 0
    ):
        return None
    element_width = _type_width_bytes_8616(node.type.elem_type)
    if element_width is None:
        if variable.size % node.type.length:
            return None
        element_width = variable.size // node.type.length
    object_width = element_width * node.type.length
    if variable.size not in {element_width, object_width}:
        return None
    return _StackArrayStorage8616(
        offset=variable.offset,
        width=object_width,
        element_width=element_width,
        element_count=node.type.length,
    )


def _assignment_to_scalar_8616(node: object) -> tuple[_ScalarStorage8616, object] | None:
    """Return scalar assignment destination and RHS."""
    if not isinstance(node, CAssignment):
        return None
    lhs = _scalar_storage_8616(node.lhs)
    if lhs is None or lhs.kind is _ScalarStorageKind8616.CONSTANT:
        return None
    return lhs, node.rhs


def _constant_value_8616(node: object) -> int | None:
    """Return one structured integer constant."""
    node = _strip_casts_8616(node)
    if isinstance(node, CConstant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _binary_storage_constant_8616(
    node: object,
    op: str,
    constant: int,
) -> _ScalarStorage8616 | None:
    """Match ``storage op constant`` and return the storage identity."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CBinaryOp) or node.op != op:
        return None
    if _constant_value_8616(node.rhs) != constant:
        return None
    return _scalar_storage_8616(node.lhs)


def _ascending_loop_8616(loop: CForLoop) -> _AscendingLoop8616 | None:
    """Match a zero-based, unit-stride, strict-upper-bound for-loop."""
    initializer = _assignment_to_scalar_8616(loop.initializer)
    if initializer is None or _constant_value_8616(initializer[1]) != 0:
        return None
    induction = initializer[0]
    descriptor = _ascending_condition_8616(loop.condition)
    if descriptor is None or descriptor.induction != induction:
        return None
    iterator = _assignment_to_scalar_8616(loop.iterator)
    if (
        iterator is None
        or iterator[0] != induction
        or _binary_storage_constant_8616(iterator[1], "Add", 1) != induction
    ):
        return None
    return descriptor


def _ascending_condition_8616(condition: object) -> _AscendingLoop8616 | None:
    """Return the induction and bound from an exact ``index < bound`` predicate."""
    condition = _strip_casts_8616(condition)
    if not isinstance(condition, CBinaryOp):
        return None
    if condition.op == "CmpLT":
        induction = _scalar_storage_8616(condition.lhs)
        bound = _scalar_storage_8616(condition.rhs)
    elif condition.op == "CmpGT":
        induction = _scalar_storage_8616(condition.rhs)
        bound = _scalar_storage_8616(condition.lhs)
    else:
        return None
    if (
        induction is None
        or
        bound is None
        or bound == induction
    ):
        return None
    return _AscendingLoop8616(induction=induction, bound=bound)


def _break_only_8616(node: object) -> bool:
    """Return whether one structured branch contains exactly one break."""
    if isinstance(node, CBreak):
        return True
    if not isinstance(node, CStatements) or len(node.statements) != 1:
        return False
    return _break_only_8616(node.statements[0])


def _break_guard_descriptor_8616(node: object) -> _AscendingLoop8616 | None:
    """Return the continued-loop predicate encoded by one exact break guard."""
    if (
        not isinstance(node, CIfElse)
        or node.else_node is not None
        or len(node.condition_and_nodes) != 1
    ):
        return None
    condition, branch = node.condition_and_nodes[0]
    if not _break_only_8616(branch):
        return None
    condition = _strip_casts_8616(condition)
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        operand = _strip_casts_8616(condition.operand)
        if isinstance(operand, CUnaryOp) and operand.op == "Not":
            return _ascending_condition_8616(operand.operand)
        if (
            isinstance(operand, CITE)
            and _constant_value_8616(operand.iftrue) == 0
            and _constant_value_8616(operand.iffalse) == 1
        ):
            return _ascending_condition_8616(operand.cond)
        return _ascending_condition_8616(operand)
    if not isinstance(condition, CBinaryOp):
        return None
    if condition.op == "CmpGE":
        induction = _scalar_storage_8616(condition.lhs)
        bound = _scalar_storage_8616(condition.rhs)
    elif condition.op == "CmpLE":
        induction = _scalar_storage_8616(condition.rhs)
        bound = _scalar_storage_8616(condition.lhs)
    else:
        return None
    if induction is None or bound is None or induction == bound:
        return None
    return _AscendingLoop8616(induction=induction, bound=bound)


def _unconditional_while_8616(loop: CWhileLoop) -> bool:
    """Return whether one structured while loop has an unconditional header."""
    if loop.condition is None:
        return True
    condition = _strip_casts_8616(loop.condition)
    return isinstance(condition, CConstant) and condition.value in {True, 1}


def _canonical_while_8616(
    loop: CWhileLoop,
    state: _RangeProofState8616,
) -> tuple[_AscendingLoop8616, int] | None:
    """Match a zero-based unit-stride while loop with one leading break guard."""
    debug = os.environ.get("INERTIA_DEBUG_INDEXED_STACK_RANGES") == "1"

    def _debug(reason: str, **values: object) -> None:
        """Emit opt-in canonical-while refusal details."""
        if debug:
            logging.getLogger(__name__).warning(
                "indexed-stack-range event=while-shape-%s values=%r",
                reason,
                values,
            )

    def _shape(node: object, depth: int = 0) -> object:
        """Return a bounded typed expression shape for opt-in diagnostics."""
        if depth >= 5:
            return type(node).__name__
        node = _strip_casts_8616(node)
        if isinstance(node, CVariable):
            return ("variable", node.name, _scalar_storage_8616(node))
        if isinstance(node, CConstant):
            return ("constant", node.value)
        if isinstance(node, CUnaryOp):
            return ("unary", node.op, _shape(node.operand, depth + 1))
        if isinstance(node, CBinaryOp):
            return (
                "binary",
                node.op,
                _shape(node.lhs, depth + 1),
                _shape(node.rhs, depth + 1),
            )
        if isinstance(node, CITE):
            return (
                "ite",
                _shape(node.cond, depth + 1),
                _shape(node.iftrue, depth + 1),
                _shape(node.iffalse, depth + 1),
            )
        if isinstance(node, CFunctionCall):
            return (
                "call",
                node.callee_func,
                node.callee_target,
                tuple(_shape(argument, depth + 1) for argument in node.args),
            )
        return type(node).__name__

    if not _unconditional_while_8616(loop):
        _debug("conditional", condition=type(loop.condition).__name__)
        return None
    statements = _transparent_body_statements_8616(loop.body)
    candidates: list[tuple[_AscendingLoop8616, int]] = []
    for guard_index, statement in enumerate(statements):
        descriptor = _break_guard_descriptor_8616(statement)
        if isinstance(statement, CIfElse):
            _debug(
                "guard",
                guard_index=guard_index,
                descriptor=descriptor,
                condition_types=tuple(
                    (
                        type(condition).__name__,
                        condition.op if isinstance(condition, (CBinaryOp, CUnaryOp)) else None,
                        _shape(condition),
                        type(branch).__name__,
                        _break_only_8616(branch),
                    )
                    for condition, branch in statement.condition_and_nodes
                ),
                has_else=statement.else_node is not None,
            )
        if (
            descriptor is None
            or state.constants.get(descriptor.induction) != 0
        ):
            continue
        writes_before_guard = tuple(
            assignment
            for prior in statements[:guard_index]
            for assignment in _direct_scalar_assignments_8616(prior)
            for target_rhs in (_assignment_to_scalar_8616(assignment),)
            if target_rhs is not None
            and target_rhs[0] in {descriptor.induction, descriptor.bound}
        )
        if writes_before_guard:
            _debug(
                "writes-before-guard",
                descriptor=descriptor,
                writes=writes_before_guard,
            )
            continue
        induction_writes = tuple(
            assignment
            for following in statements[guard_index + 1 :]
            for assignment in _direct_scalar_assignments_8616(following)
            for target_rhs in (_assignment_to_scalar_8616(assignment),)
            if target_rhs is not None and target_rhs[0] == descriptor.induction
        )
        if (
            len(induction_writes) != 1
            or _binary_storage_constant_8616(
                induction_writes[0].rhs,
                "Add",
                1,
            )
            != descriptor.induction
        ):
            _debug(
                "induction-writes",
                descriptor=descriptor,
                write_count=len(induction_writes),
                writes=tuple(
                    (
                        type(assignment.rhs).__name__,
                        assignment.rhs.op if isinstance(assignment.rhs, CBinaryOp) else None,
                    )
                    for assignment in induction_writes
                ),
            )
            continue
        candidates.append((descriptor, guard_index))
    if len(candidates) != 1:
        _debug(
            "candidate-count",
            count=len(candidates),
            statement_types=tuple(type(statement).__name__ for statement in statements),
            constants=state.constants,
        )
        return None
    return candidates[0]


def _transparent_body_statements_8616(body: object) -> tuple[object, ...]:
    """Flatten only sequencing containers from one structured loop body.

    Branches, loops, switches, and conditional breaks remain opaque leaves so
    callers cannot mistake conditionally executed assignments for direct
    straight-line effects.
    """
    if not isinstance(body, CStatements):
        return ()
    flattened: list[object] = []
    for statement in body.statements:
        if isinstance(statement, CStatements):
            flattened.extend(_transparent_body_statements_8616(statement))
        else:
            flattened.append(statement)
    return tuple(flattened)


def _prefix_array_8616(
    loop: CForLoop,
    descriptor: _AscendingLoop8616,
) -> _StackArrayStorage8616 | None:
    """Return an array assigned at every iteration before any control split."""
    for statement in _transparent_body_statements_8616(loop.body):
        if not isinstance(statement, CAssignment):
            return None
        if any(
            isinstance(candidate, CFunctionCall)
            for candidate in _iter_c_nodes_deep_8616(statement.rhs)
        ):
            return None
        scalar_assignment = _assignment_to_scalar_8616(statement)
        if scalar_assignment is not None and scalar_assignment[0] in {
            descriptor.induction,
            descriptor.bound,
        }:
            return None
        lhs = statement.lhs
        if not isinstance(lhs, CIndexedVariable):
            continue
        array = _stack_array_storage_8616(lhs.variable)
        if array is not None and _scalar_storage_8616(lhs.index) == descriptor.induction:
            return array
    return None


def _while_prefix_array_8616(
    loop: CWhileLoop,
    descriptor: _AscendingLoop8616,
    guard_index: int,
) -> _StackArrayStorage8616 | None:
    """Return an array written on every guarded continuing while iteration."""
    statements = _transparent_body_statements_8616(loop.body)
    for statement in statements[guard_index + 1 :]:
        if not isinstance(statement, CAssignment):
            return None
        if any(
            isinstance(candidate, CFunctionCall)
            for candidate in _iter_c_nodes_deep_8616(statement.rhs)
        ):
            return None
        scalar_assignment = _assignment_to_scalar_8616(statement)
        if scalar_assignment is not None and scalar_assignment[0] in {
            descriptor.induction,
            descriptor.bound,
        }:
            return None
        lhs = statement.lhs
        if not isinstance(lhs, CIndexedVariable):
            continue
        array = _stack_array_storage_8616(lhs.variable)
        if array is not None and _scalar_storage_8616(lhs.index) == descriptor.induction:
            return array
    return None


def _direct_scalar_assignments_8616(node: object) -> tuple[CAssignment, ...]:
    """Return all scalar assignments in one structured subtree."""
    return tuple(
        candidate
        for candidate in _iter_c_nodes_deep_8616(node)
        if isinstance(candidate, CAssignment)
        and _assignment_to_scalar_8616(candidate) is not None
    )


def _direct_decrement_carriers_8616(
    body: object,
    state: _RangeProofState8616,
    descriptor: _AscendingLoop8616,
) -> frozenset[_ScalarStorage8616]:
    """Return predecessor carriers decremented once on each continuing iteration."""
    straight_line_assignment_ids = {
        id(statement)
        for statement in _transparent_body_statements_8616(body)
        if isinstance(statement, CAssignment)
    }
    if not straight_line_assignment_ids:
        return frozenset()
    all_assignments = _direct_scalar_assignments_8616(body)
    carriers: set[_ScalarStorage8616] = set()
    for candidate, bound in state.predecessors.items():
        if bound != descriptor.bound:
            continue
        writes = tuple(
            statement
            for statement in all_assignments
            for assignment in (_assignment_to_scalar_8616(statement),)
            if assignment is not None and assignment[0] == candidate
        )
        if (
            len(writes) != 1
            or id(writes[0]) not in straight_line_assignment_ids
        ):
            continue
        assignment = _assignment_to_scalar_8616(writes[0])
        decremented = (
            assignment is not None
            and (
                _binary_storage_constant_8616(
                    assignment[1],
                    "Sub",
                    1,
                )
                == candidate
                or _binary_storage_constant_8616(
                    assignment[1],
                    "Add",
                    -1,
                )
                == candidate
            )
        )
        if decremented:
            carriers.add(candidate)
    return frozenset(carriers)


def _common_prefixes_8616(
    states: tuple[_RangeProofState8616, ...],
) -> dict[_StackArrayStorage8616, _ScalarStorage8616]:
    """Return prefix facts shared by every supplied path state."""
    first = states[0].prefixes
    return {
        key: value
        for key, value in first.items()
        if all(state.prefixes.get(key) == value for state in states[1:])
    }


def _common_predecessors_8616(
    states: tuple[_RangeProofState8616, ...],
) -> dict[_ScalarStorage8616, _ScalarStorage8616]:
    """Return predecessor facts shared by every supplied path state."""
    first = states[0].predecessors
    return {
        key: value
        for key, value in first.items()
        if all(state.predecessors.get(key) == value for state in states[1:])
    }


def _common_ranges_8616(
    states: tuple[_RangeProofState8616, ...],
) -> dict[_ScalarStorage8616, _ScalarStorage8616]:
    """Return range facts shared by every supplied path state."""
    first = states[0].ranges
    return {
        key: value
        for key, value in first.items()
        if all(state.ranges.get(key) == value for state in states[1:])
    }


def _common_constants_8616(
    states: tuple[_RangeProofState8616, ...],
) -> dict[_ScalarStorage8616, int]:
    """Return exact scalar constants shared by every supplied path state."""
    first = states[0].constants
    return {
        key: value
        for key, value in first.items()
        if all(state.constants.get(key) == value for state in states[1:])
    }


def _intersect_states_8616(
    states: tuple[_RangeProofState8616, ...],
    fallback: _RangeProofState8616,
) -> _RangeProofState8616:
    """Retain exact facts available on every structured path."""
    if not states:
        return fallback.copy()
    return _RangeProofState8616(
        prefixes=_common_prefixes_8616(states),
        predecessors=_common_predecessors_8616(states),
        ranges=_common_ranges_8616(states),
        constants=_common_constants_8616(states),
    )


def collect_indexed_stack_read_proofs_8616(
    root: object,
    *,
    direct_stack_move_facts: tuple[DirectStackMoveFact8616, ...] = (),
) -> IndexedStackReadProofReport8616:
    """Prove exact dynamic reads selected from initialized stack-array prefixes.

    The proof recognizes zero-based unit-stride prefix initialization, carries
    synchronized ``bound - 1`` countdown variables through a second loop, and
    consumes lowering-proven nonnegative signed-remainder facts. Every
    unmatched dynamic stack-array read remains unproved.
    """
    report = _MutableProofReport8616()
    facts = tuple(
        fact
        for fact in direct_stack_move_facts
        if isinstance(fact, DirectStackMoveFact8616)
    )
    callsite_contracts: dict[int, RuntimeCallReturnContract8616] = {}
    target_contracts: dict[int, RuntimeCallReturnContract8616] = {}
    ambiguous_callsites: set[int] = set()
    ambiguous_targets: set[int] = set()
    for fact in facts:
        contract = fact.source_call_return_contract
        if contract is None:
            continue
        for key, inventory, ambiguous in (
            (
                fact.source_call_ins_addr,
                callsite_contracts,
                ambiguous_callsites,
            ),
            (
                fact.source_call_target,
                target_contracts,
                ambiguous_targets,
            ),
        ):
            if not isinstance(key, int) or key in ambiguous:
                continue
            existing = inventory.get(key)
            if existing is not None and existing != contract:
                inventory.pop(key, None)
                ambiguous.add(key)
            else:
                inventory[key] = contract
    debug = os.environ.get("INERTIA_DEBUG_INDEXED_STACK_RANGES") == "1"

    def _debug(event: str, **values: object) -> None:
        """Emit opt-in typed proof diagnostics."""
        if debug:
            logging.getLogger(__name__).warning(
                "indexed-stack-range event=%s values=%r",
                event,
                values,
            )

    def _invalidate_scalar(
        state: _RangeProofState8616,
        scalar: _ScalarStorage8616,
    ) -> None:
        """Drop facts that depend on a newly written scalar."""
        state.prefixes = {
            array: bound
            for array, bound in state.prefixes.items()
            if bound != scalar
        }
        state.predecessors = {
            candidate: bound
            for candidate, bound in state.predecessors.items()
            if candidate != scalar and bound != scalar
        }
        state.ranges = {
            candidate: bound
            for candidate, bound in state.ranges.items()
            if candidate != scalar and bound != scalar
        }
        state.constants.pop(scalar, None)

    def _invalidate_unknown_call(
        expr: object,
        state: _RangeProofState8616,
        call_contracts: Mapping[int, RuntimeCallReturnContract8616] | None = None,
    ) -> None:
        """Drop bound proofs unless one call contract preserves their address."""
        contracts = call_contracts or {}
        calls = tuple(
            node
            for node in _iter_c_nodes_deep_8616(expr)
            if isinstance(node, CFunctionCall)
        )
        for call in calls:
            if segmented_load_identity_8616(call) is not None:
                continue
            if (
                structured_call_kind_8616(call)
                is StructuredCallKind8616.CODEGEN_INSERT_INTRINSIC
            ):
                continue
            callsite_addr = (
                call.tags.get("ins_addr")
                if isinstance(call.tags, dict)
                else None
            )
            callee_addr = _structured_call_target_addr_8616(call)
            contract = contracts.get(id(call))
            if contract is None and isinstance(callsite_addr, int):
                contract = callsite_contracts.get(callsite_addr)
            if contract is None and isinstance(callee_addr, int):
                contract = target_contracts.get(callee_addr)
            _debug(
                "call-effect",
                call_node_id=id(call),
                contract=contract,
                callsite_addr=callsite_addr,
                callee_addr=callee_addr,
            )
            global_bounds = {
                bound
                for bound in (
                    tuple(state.prefixes.values())
                    + tuple(state.predecessors.values())
                    + tuple(state.ranges.values())
                )
                if bound.kind in {
                    _ScalarStorageKind8616.MEMORY,
                    _ScalarStorageKind8616.REGISTER,
                }
            }
            for bound in global_bounds:
                address = _scalar_memory_address_8616(bound)
                if (
                    contract is not None
                    and address is not None
                    and contract.preserves_address(address)
                ):
                    continue
                _invalidate_scalar(state, bound)

    def _prove_reads(expr: object, state: _RangeProofState8616) -> None:
        """Record proofs for dynamic indexed stack-array reads in one value."""
        if expr is None:
            return
        for node in _iter_c_nodes_deep_8616(expr):
            if not isinstance(node, CIndexedVariable):
                continue
            if _constant_value_8616(node.index) is not None:
                continue
            array = _stack_array_storage_8616(node.variable)
            if array is None:
                continue
            report.raw_fact_count += 1
            index = _scalar_storage_8616(node.index)
            if index is None:
                continue
            report.normalized_fact_count += 1
            prefix_bound = state.prefixes.get(array)
            range_bound = state.ranges.get(index)
            _debug(
                "read",
                array=array,
                index=index,
                prefix_bound=prefix_bound,
                range_bound=range_bound,
            )
            if prefix_bound is None or range_bound is None:
                continue
            report.classified_fact_count += 1
            if prefix_bound != range_bound:
                continue
            report.proofs.append(
                IndexedStackReadProof8616(
                    read_node_id=id(node),
                    array_offset=array.offset,
                    array_width=array.width,
                    element_width=array.element_width,
                    index_storage_offset=index.offset,
                    kind=IndexedStackReadProofKind8616.INITIALIZED_PREFIX_BOUNDED_INDEX,
                )
            )

    def _remainder_range_fact(
        assignment: CAssignment,
        lhs: _ScalarStorage8616,
        state: _RangeProofState8616,
    ) -> _RemainderCallEvidence8616 | None:
        """Bind one structured modulo assignment to lowering and range evidence."""
        rhs = _strip_casts_8616(assignment.rhs)
        if not isinstance(rhs, CBinaryOp) or rhs.op != "Mod":
            return None
        statement_ins_addr = (
            assignment.tags.get("ins_addr")
            if isinstance(assignment.tags, dict)
            else None
        )
        candidates = tuple(
            fact
            for fact in facts
            if fact.source_kind
            is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
            and fact.dst_offset == lhs.offset
            and fact.width == lhs.width
            and fact.source_immediate == 1
            and fact.source_call_return_contract is not None
            and fact.source_call_return_contract.value_range.is_nonnegative
            and (
                not isinstance(statement_ins_addr, int)
                or statement_ins_addr
                in {
                    fact.ins_addr,
                    fact.source_call_ins_addr,
                }
            )
        )
        if len(candidates) != 1:
            _debug(
                "remainder-candidates",
                lhs=lhs,
                statement_ins_addr=statement_ins_addr,
                candidates=candidates,
            )
            return None
        fact = candidates[0]
        divisor = _binary_storage_constant_8616(rhs.rhs, "Add", 1)
        if (
            divisor is None
            or divisor.kind is not _ScalarStorageKind8616.STACK
            or divisor.offset != fact.source_offset
            or not isinstance(fact.source_call_ins_addr, int)
        ):
            _debug(
                "remainder-divisor",
                lhs=lhs,
                divisor=divisor,
                fact=fact,
                ranges=state.ranges,
            )
            return None
        call = _strip_casts_8616(rhs.lhs)
        if not isinstance(call, CFunctionCall):
            _debug(
                "remainder-numerator",
                lhs=lhs,
                statement_ins_addr=statement_ins_addr,
                numerator_type=type(call).__name__,
                divisor=divisor,
            )
            return None
        callsite_addr = (
            call.tags.get("ins_addr")
            if isinstance(call.tags, dict)
            else None
        )
        callee_addr = _structured_call_target_addr_8616(call)
        _debug(
            "remainder-call-identity",
            call_node_id=id(call),
            callsite_addr=callsite_addr,
            callee_addr=callee_addr,
            expected_callsite_addr=fact.source_call_ins_addr,
            expected_callee_addr=fact.source_call_target,
        )
        if (
            callsite_addr != fact.source_call_ins_addr
            and callee_addr != fact.source_call_target
        ):
            return None
        contract = fact.source_call_return_contract
        if contract is None:
            return None
        return _RemainderCallEvidence8616(
            range_bound=state.ranges.get(divisor),
            call_node_id=id(call),
            call_contract=contract,
        )

    def _walk(
        node: object,
        incoming: _RangeProofState8616,
    ) -> _RangeProofState8616:
        """Walk structured control flow without mutating the AST."""
        state = incoming.copy()
        if node is None:
            return state
        if isinstance(node, CStatements):
            for statement in node.statements:
                state = _walk(statement, state)
            return state
        if isinstance(node, CAssignment):
            _prove_reads(node.rhs, state)
            assignment = _assignment_to_scalar_8616(node)
            call_contracts: dict[int, RuntimeCallReturnContract8616] = {}
            derived_range = None
            if assignment is not None:
                derived = _remainder_range_fact(node, assignment[0], state)
                if derived is not None:
                    derived_range = derived.range_bound
                    call_contracts[derived.call_node_id] = derived.call_contract
            _invalidate_unknown_call(
                node.rhs,
                state,
                call_contracts,
            )
            if assignment is None:
                return state
            lhs, rhs = assignment
            assigned_constant = _constant_value_8616(rhs)
            _invalidate_scalar(state, lhs)
            predecessor = _binary_storage_constant_8616(rhs, "Sub", 1)
            if predecessor is not None:
                state.predecessors[lhs] = predecessor
            copied_storage = _scalar_storage_8616(rhs)
            copied_range = (
                state.ranges.get(copied_storage)
                if copied_storage is not None
                else None
            )
            if derived_range is not None:
                state.ranges[lhs] = derived_range
            elif copied_range is not None:
                state.ranges[lhs] = copied_range
            if assigned_constant is not None:
                state.constants[lhs] = assigned_constant
            return state
        if isinstance(node, CExpressionStatement):
            _prove_reads(node.expr, state)
            _invalidate_unknown_call(node.expr, state)
            return state
        if isinstance(node, CIfElse):
            branches = tuple(
                _walk(branch, state)
                for _condition, branch in node.condition_and_nodes
            )
            if node.else_node is None:
                branches += (state.copy(),)
            else:
                branches += (_walk(node.else_node, state),)
            return _intersect_states_8616(branches, state)
        if isinstance(node, CForLoop):
            initialized = _walk(node.initializer, state)
            descriptor = _ascending_loop_8616(node)
            _debug(
                "loop",
                descriptor=descriptor,
                prefixes=initialized.prefixes,
                predecessors=initialized.predecessors,
                body_statements=tuple(
                    (
                        type(statement).__name__,
                        type(statement.lhs).__name__
                        if isinstance(statement, CAssignment)
                        else None,
                        _stack_array_storage_8616(statement.lhs.variable)
                        if isinstance(statement, CAssignment)
                        and isinstance(statement.lhs, CIndexedVariable)
                        else None,
                        _scalar_storage_8616(statement.lhs.index)
                        if isinstance(statement, CAssignment)
                        and isinstance(statement.lhs, CIndexedVariable)
                        else None,
                        (
                            _assignment_to_scalar_8616(statement),
                            type(statement.rhs).__name__,
                            statement.rhs.op
                            if isinstance(statement.rhs, CBinaryOp)
                            else None,
                        )
                        if isinstance(statement, CAssignment)
                        else None,
                    )
                    for statement in node.body.statements
                )
                if isinstance(node.body, CStatements)
                else (),
            )
            if descriptor is None:
                _walk(node.body, initialized)
                return initialized
            body_state = initialized.copy()
            body_state.ranges[descriptor.induction] = descriptor.bound
            carriers = _direct_decrement_carriers_8616(
                node.body,
                initialized,
                descriptor,
            )
            _debug("loop-carriers", descriptor=descriptor, carriers=carriers)
            for carrier in carriers:
                body_state.ranges[carrier] = descriptor.bound
            iterated = _walk(node.iterator, _walk(node.body, body_state))
            outgoing = _intersect_states_8616(
                (initialized, iterated),
                initialized,
            )
            written_scalars = {
                assignment[0]
                for candidate in _direct_scalar_assignments_8616(node)
                for assignment in (_assignment_to_scalar_8616(candidate),)
                if assignment is not None
            }
            for scalar in written_scalars:
                _invalidate_scalar(outgoing, scalar)
            prefix_array = _prefix_array_8616(node, descriptor)
            _debug(
                "loop-prefix",
                descriptor=descriptor,
                prefix_array=prefix_array,
            )
            if prefix_array is not None:
                outgoing.prefixes[prefix_array] = descriptor.bound
            return outgoing
        if isinstance(node, CWhileLoop):
            while_descriptor = _canonical_while_8616(node, state)
            _debug(
                "while-loop",
                descriptor=while_descriptor,
                prefixes=state.prefixes,
                predecessors=state.predecessors,
                constants=state.constants,
            )
            if while_descriptor is None:
                _walk(node.body, state)
                return state
            descriptor, guard_index = while_descriptor
            body_state = state.copy()
            body_state.ranges[descriptor.induction] = descriptor.bound
            carriers = _direct_decrement_carriers_8616(
                node.body,
                state,
                descriptor,
            )
            _debug("while-loop-carriers", descriptor=descriptor, carriers=carriers)
            for carrier in carriers:
                body_state.ranges[carrier] = descriptor.bound
            iterated = _walk(node.body, body_state)
            outgoing = _intersect_states_8616(
                (state, iterated),
                state,
            )
            written_scalars = {
                assignment[0]
                for candidate in _direct_scalar_assignments_8616(node)
                for assignment in (_assignment_to_scalar_8616(candidate),)
                if assignment is not None
            }
            for scalar in written_scalars:
                _invalidate_scalar(outgoing, scalar)
            prefix_array = _while_prefix_array_8616(
                node,
                descriptor,
                guard_index,
            )
            _debug(
                "while-loop-prefix",
                descriptor=descriptor,
                prefix_array=prefix_array,
            )
            if prefix_array is not None:
                outgoing.prefixes[prefix_array] = descriptor.bound
            return outgoing
        if isinstance(node, CSwitchCase):
            _prove_reads(node.switch, state)
            branches = tuple(
                _walk(body, state)
                for body in node.cases.values()
            ) if isinstance(node.cases, dict) else ()
            if node.default is None:
                branches += (state.copy(),)
            else:
                branches += (_walk(node.default, state),)
            return _intersect_states_8616(branches, state)
        _prove_reads(node, state)
        _invalidate_unknown_call(node, state)
        return state

    _walk(
        root,
        _RangeProofState8616(
            prefixes={},
            predecessors={},
            ranges={},
            constants={},
        ),
    )
    return report.freeze()
