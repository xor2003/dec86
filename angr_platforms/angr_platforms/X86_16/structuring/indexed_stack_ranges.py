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
from dataclasses import dataclass, field
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CVariable,
)
from angr.sim_type import SimType, SimTypeArray, SimTypeFixedSizeArray
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)

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


@dataclass(frozen=True, order=True, slots=True)
class _ScalarStorage8616:
    """Stable scalar identity used by structured range proofs."""

    kind: _ScalarStorageKind8616
    offset: int
    width: int
    region: int | None = None
    ident: str = ""


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

    def copy(self) -> _RangeProofState8616:
        """Return an independent path state."""
        return _RangeProofState8616(
            prefixes=dict(self.prefixes),
            predecessors=dict(self.predecessors),
            ranges=dict(self.ranges),
        )


@dataclass(frozen=True, slots=True)
class _AscendingLoop8616:
    """Canonical zero-based unit-stride loop bound."""

    induction: _ScalarStorage8616
    bound: _ScalarStorage8616


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
            region=variable.region if isinstance(variable.region, int) else None,
        )
    if isinstance(variable, SimMemoryVariable):
        if not isinstance(variable.addr, int) or not isinstance(variable.size, int) or variable.size <= 0:
            return None
        return _ScalarStorage8616(
            kind=_ScalarStorageKind8616.MEMORY,
            offset=variable.addr,
            width=variable.size,
            region=variable.region if isinstance(variable.region, int) else None,
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
        or variable.size % node.type.length
    ):
        return None
    element_width = variable.size // node.type.length
    return _StackArrayStorage8616(
        offset=variable.offset,
        width=variable.size,
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
    condition = _strip_casts_8616(loop.condition)
    if not isinstance(condition, CBinaryOp):
        return None
    if condition.op == "CmpLT" and _scalar_storage_8616(condition.lhs) == induction:
        bound = _scalar_storage_8616(condition.rhs)
    elif condition.op == "CmpGT" and _scalar_storage_8616(condition.rhs) == induction:
        bound = _scalar_storage_8616(condition.lhs)
    else:
        return None
    iterator = _assignment_to_scalar_8616(loop.iterator)
    if (
        bound is None
        or bound == induction
        or iterator is None
        or iterator[0] != induction
        or _binary_storage_constant_8616(iterator[1], "Add", 1) != induction
    ):
        return None
    return _AscendingLoop8616(induction=induction, bound=bound)


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

    def _invalidate_unknown_call(
        expr: object,
        state: _RangeProofState8616,
        preserving_call_addrs: frozenset[int] = frozenset(),
    ) -> None:
        """Drop global-bound proofs across calls without preservation evidence."""
        calls = tuple(
            node
            for node in _iter_c_nodes_deep_8616(expr)
            if isinstance(node, CFunctionCall)
        )
        for call in calls:
            ins_addr = call.tags.get("ins_addr") if isinstance(call.tags, dict) else None
            if isinstance(ins_addr, int) and ins_addr in preserving_call_addrs:
                continue
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
    ) -> tuple[_ScalarStorage8616, frozenset[int]] | None:
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
            and fact.source_call_return_contract.preserves_caller_storage
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
            or state.ranges.get(divisor) is None
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
        calls = tuple(
            node
            for node in _iter_c_nodes_deep_8616(rhs.lhs)
            if isinstance(node, CFunctionCall)
        )
        if calls:
            call_addrs = {
                call.tags.get("ins_addr")
                for call in calls
                if isinstance(call.tags, dict)
                and isinstance(call.tags.get("ins_addr"), int)
            }
            if call_addrs and call_addrs != {fact.source_call_ins_addr}:
                return None
        return state.ranges[divisor], frozenset({fact.source_call_ins_addr})

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
            preserving_call_addrs = frozenset()
            derived_range = None
            if assignment is not None:
                derived = _remainder_range_fact(node, assignment[0], state)
                if derived is not None:
                    derived_range, preserving_call_addrs = derived
            _invalidate_unknown_call(
                node.rhs,
                state,
                preserving_call_addrs,
            )
            if assignment is None:
                return state
            lhs, rhs = assignment
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
        _RangeProofState8616(prefixes={}, predecessors={}, ranges={}),
    )
    return report.freeze()
