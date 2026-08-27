"""Place proven wide call-result assignments in the dynamic angr C AST.

Layer: Types/Lowering.
Responsibility: join one immutable wide call-output fact to an exact structured
call and its instruction-tagged carrier statements, then mutate only those
owned nodes. Consumes alias, widening, and typed facts without rediscovery.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable, SimVariable

from ..analysis.stack_frame_ir import (
    FrameAccessArtifact,
    FrameCoordinateStatus8616,
)
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..semantics.carry_borrow_contracts import CarryBorrowKind8616
from ..widening.carry_borrow_storage import WideCarryBorrowStorage8616
from .stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616
from .wide_call_output_assignment_ast import (
    WideCallOutputCallSite8616,
    c_node_instruction_addrs_8616,
    direct_statement_group_parents_8616,
    exact_wide_call_output_call_sites_8616,
)
from .wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentFailure8616,
    WideCallOutputAssignmentResolution8616,
    WideCallOutputAssignmentVerdict8616,
    refused_wide_call_output_assignment_8616,
)

_EVIDENCE_TAG_8616 = "inertia_x86_16_wide_call_output_assignment"


class _CFunctionBoundary8616(Protocol):
    """Dynamic angr C-function surface consumed by placement."""

    statements: object
    variables_in_use: dict[SimVariable, CVariable]
    arg_list: tuple[CVariable, ...]


class _CodegenFrameBoundary8616(Protocol):
    """Dynamic angr codegen surface carrying typed frame evidence."""

    _inertia_vex_ir_frame: FrameAccessArtifact


@dataclass(frozen=True, slots=True)
class _CarrierStatementRef8616:
    """One exact mutable statement slot owned by a carrier fact."""

    group: CStatements
    index: int
    statement: object


@dataclass(frozen=True, slots=True)
class _CarrierScan8616:
    """Carrier references and addresses from one conservative AST scan."""

    refs: tuple[_CarrierStatementRef8616, ...] = ()
    observed: frozenset[int] = frozenset()
    failure: WideCallOutputAssignmentFailure8616 | None = None


def _exact_stack_cvar_8616(
    codegen: object,
    cfunc: _CFunctionBoundary8616,
    bp_offset: int,
    size: int,
) -> CVariable | None:
    """Return one C variable through its exact machine-BP projection."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_bp_range(bp_offset, size)
    if projection is not None:
        return projection.cvar if isinstance(projection.cvar, CVariable) else None
    if registry.projections:
        return None
    candidates: dict[int, CVariable] = {}
    for variable, cvar in cfunc.variables_in_use.items():
        if (
            isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and variable.offset == bp_offset
            and variable.size == size
        ):
            candidates[id(variable)] = cvar
    try:
        arguments = cfunc.arg_list
    except AttributeError:
        arguments = ()
    for cvar in arguments:
        variable = cvar.variable
        if (
            isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and variable.offset == bp_offset
            and variable.size == size
        ):
            candidates[id(variable)] = cvar
    return next(iter(candidates.values())) if len(candidates) == 1 else None


def _entry_sp_offset_for_bp_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> int | None:
    """Project one machine-BP range into angr's entry-SP coordinate."""
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(
        bp_offset,
        size,
    )
    if projection is not None:
        entry_sp_offset = projection.entry_sp_offset
        return entry_sp_offset if isinstance(entry_sp_offset, int) else None
    boundary = cast(_CodegenFrameBoundary8616, codegen)
    try:
        frame = boundary._inertia_vex_ir_frame
    except AttributeError:
        return None
    coordinate = frame.bp_coordinate if isinstance(frame, FrameAccessArtifact) else None
    if (
        coordinate is None
        or coordinate.status is not FrameCoordinateStatus8616.PROVEN
        or not isinstance(coordinate.bp_entry_sp_delta, int)
    ):
        return None
    return bp_offset + coordinate.bp_entry_sp_delta


def _already_materialized_8616(
    root: object,
    fact: WideCallOutputAssignmentFact8616,
) -> bool:
    """Return whether exactly one canonical assignment already owns this fact."""
    matches = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        tags = node.tags
        if isinstance(tags, dict) and tags.get(_EVIDENCE_TAG_8616) == fact:
            matches += 1
    return matches == 1


def _has_call_8616(statement: object) -> bool:
    """Return whether a candidate carrier statement contains any semantic call."""
    return any(
        isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(statement)
    )


def _scan_same_group_8616(
    call_site: WideCallOutputCallSite8616,
    required: frozenset[int],
) -> _CarrierScan8616:
    """Collect a contiguous carrier suffix from the call's immediate group."""
    refs: list[_CarrierStatementRef8616] = []
    observed: set[int] = set()
    for index, statement in enumerate(call_site.statements.statements):
        if index == call_site.index:
            continue
        addresses = c_node_instruction_addrs_8616(statement)
        touched = addresses & required
        if not touched:
            continue
        if not addresses <= required or _has_call_8616(statement):
            return _CarrierScan8616(
                failure=WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
            )
        if index < call_site.index or not isinstance(
            statement, (CAssignment, CExpressionStatement)
        ):
            return _CarrierScan8616(
                failure=WideCallOutputAssignmentFailure8616.CARRIER_ORDER_MISMATCH
            )
        refs.append(_CarrierStatementRef8616(call_site.statements, index, statement))
        observed.update(touched)
    if refs:
        last_index = max(ref.index for ref in refs)
        owned_indices = {ref.index for ref in refs}
        if any(
            index not in owned_indices
            for index in range(call_site.index + 1, last_index + 1)
        ):
            return _CarrierScan8616(
                failure=WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
            )
    return _CarrierScan8616(tuple(refs), frozenset(observed))


def _scan_nested_group_8616(
    group: CStatements,
    required: frozenset[int],
) -> _CarrierScan8616:
    """Collect a nested carrier-only group without crossing control flow."""
    refs: list[_CarrierStatementRef8616] = []
    observed: set[int] = set()
    pending = [group]
    while pending:
        current = pending.pop()
        for index, statement in enumerate(current.statements):
            if isinstance(statement, CStatements):
                pending.append(statement)
                continue
            if not isinstance(statement, (CAssignment, CExpressionStatement)):
                return _CarrierScan8616(
                    failure=WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
                )
            addresses = c_node_instruction_addrs_8616(statement)
            touched = addresses & required
            if not touched or not addresses <= required or _has_call_8616(statement):
                return _CarrierScan8616(
                    failure=WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
                )
            refs.append(_CarrierStatementRef8616(current, index, statement))
            observed.update(touched)
    return _CarrierScan8616(tuple(refs), frozenset(observed))


def _carrier_placement_8616(
    root: object,
    call_site: WideCallOutputCallSite8616,
    required: frozenset[int],
) -> _CarrierScan8616:
    """Resolve one same-group or exact adjacent nested carrier placement."""
    immediate = _scan_same_group_8616(call_site, required)
    if immediate.failure is not None or required <= immediate.observed:
        return immediate
    parents = direct_statement_group_parents_8616(root, call_site.statements)
    if len(parents) > 1:
        return _CarrierScan8616(
            failure=WideCallOutputAssignmentFailure8616.CARRIER_PLACEMENT_AMBIGUOUS
        )
    if not parents:
        return _CarrierScan8616(
            refs=immediate.refs,
            observed=immediate.observed,
            failure=WideCallOutputAssignmentFailure8616.CARRIER_COVERAGE_MISSING,
        )
    parent, child_index = parents[0]
    sibling_index = child_index + 1
    if sibling_index >= len(parent.statements):
        return _CarrierScan8616(
            refs=immediate.refs,
            observed=immediate.observed,
            failure=WideCallOutputAssignmentFailure8616.CARRIER_COVERAGE_MISSING,
        )
    sibling = parent.statements[sibling_index]
    if not isinstance(sibling, CStatements):
        return _CarrierScan8616(
            failure=WideCallOutputAssignmentFailure8616.CARRIER_COVERAGE_MISSING
        )
    nested = _scan_nested_group_8616(sibling, required)
    if nested.failure is not None:
        return nested
    observed = immediate.observed | nested.observed
    if not required <= observed:
        return _CarrierScan8616(
            refs=(*immediate.refs, *nested.refs),
            observed=observed,
            failure=WideCallOutputAssignmentFailure8616.CARRIER_COVERAGE_MISSING,
        )
    return _CarrierScan8616(
        refs=(*immediate.refs, *nested.refs),
        observed=observed,
    )


def _delete_carrier_refs_8616(refs: tuple[_CarrierStatementRef8616, ...]) -> None:
    """Delete exact carrier slots in descending per-group index order."""
    by_group: dict[int, tuple[CStatements, list[int]]] = {}
    for ref in refs:
        entry = by_group.setdefault(id(ref.group), (ref.group, []))
        entry[1].append(ref.index)
    for group, indices in by_group.values():
        for index in sorted(indices, reverse=True):
            del group.statements[index]


def materialize_wide_call_output_assignment_8616(
    codegen: object,
    cfunc: object,
    source: WideCarryBorrowStorage8616,
    fact: WideCallOutputAssignmentFact8616,
) -> WideCallOutputAssignmentResolution8616:
    """Materialize one exact assignment and retire only its owned carriers."""
    boundary = cast(_CFunctionBoundary8616, cfunc)
    root = boundary.statements
    if _already_materialized_8616(root, fact):
        return WideCallOutputAssignmentResolution8616(
            source,
            WideCallOutputAssignmentVerdict8616.MATERIALIZED,
            fact=fact,
            placement_classified=True,
            already_materialized=True,
        )
    destination = _exact_stack_cvar_8616(
        codegen,
        boundary,
        fact.destination_offset,
        4,
    )
    if destination is None:
        return refused_wide_call_output_assignment_8616(
            source,
            WideCallOutputAssignmentFailure8616.DESTINATION_CVARIABLE_MISSING,
            fact=fact,
        )
    call_sites = exact_wide_call_output_call_sites_8616(root, fact)
    if len(call_sites) != 1:
        failure = (
            WideCallOutputAssignmentFailure8616.CALLSITE_MISSING
            if not call_sites
            else WideCallOutputAssignmentFailure8616.CALLSITE_AMBIGUOUS
        )
        return refused_wide_call_output_assignment_8616(source, failure, fact=fact)
    call_site = call_sites[0]
    source_cvar = _exact_stack_cvar_8616(codegen, boundary, fact.source_offset, 4)
    if source_cvar is None:
        entry_sp_offset = _entry_sp_offset_for_bp_8616(
            codegen,
            fact.source_offset,
            4,
        )
        if entry_sp_offset is not None:
            materialize_stack_cvar_at_offset_from_facts_8616(
                codegen,
                entry_sp_offset,
                4,
                machine_bp_offset=fact.source_offset,
            )
        source_cvar = _exact_stack_cvar_8616(codegen, boundary, fact.source_offset, 4)
    if source_cvar is None:
        return refused_wide_call_output_assignment_8616(
            source,
            WideCallOutputAssignmentFailure8616.SOURCE_CVARIABLE_MISSING,
            fact=fact,
        )
    required = frozenset(fact.carrier_ins_addrs) - {fact.call_output.callsite_addr}
    placement = _carrier_placement_8616(root, call_site, required)
    if placement.failure is not None:
        return refused_wide_call_output_assignment_8616(
            source,
            placement.failure,
            fact=fact,
            placement_classified=True,
        )
    tags: dict[str, object] = {
        "ins_addr": fact.call_output.callsite_addr,
        _EVIDENCE_TAG_8616: fact,
    }
    operation = "Add" if fact.kind is CarryBorrowKind8616.ADD_WITH_CARRY else "Sub"
    rhs = CBinaryOp(operation, call_site.call, source_cvar, codegen=codegen, tags=tags)
    assignment = CAssignment(destination, rhs, codegen=codegen, tags=tags)
    call_site.statements.statements[call_site.index] = assignment
    _delete_carrier_refs_8616(placement.refs)
    return WideCallOutputAssignmentResolution8616(
        source,
        WideCallOutputAssignmentVerdict8616.MATERIALIZED,
        fact=fact,
        placement_classified=True,
        changed=True,
    )


__all__ = ["materialize_wide_call_output_assignment_8616"]
