"""Lower typed unobserved call-result carriers to standalone calls.

Layer: Types/Lowering.
Responsibility: consume exact callsite return-use evidence and remove only the
register assignment that stores a proven-clobbered call result while retaining
the call and all of its observable effects.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This owner does not infer liveness from rendered C, helper names, source/COD
metadata, or variable names. Unknown or used return classifications are kept.
Stack-probe helpers remain owned by ``fixed_stack_probe_frames`` because their
call itself may become redundant after fixed-frame recovery.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CUnaryOp,
)
from angr.sim_type import SimTypeBottom

from ..analysis_helpers import (
    InterruptServiceResultKind8616,
    collect_interrupt_service_calls,
    interrupt_service_addr,
    interrupt_service_result_kind_at_addr_8616,
)
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..caller_return_use_contracts import CallsiteReturnUseKind8616
from ..callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616
from ..pipeline.errors import PipelineHardError
from ..semantics.software_interrupt_inputs import SoftwareInterruptInputArtifact8616
from .callsite_prototype_declarations import (
    CallsiteCResultContract8616,
    CallsiteCResultKind8616,
)
from .physical_registers import physical_register_view_8616

__all__ = (
    "UnobservedCallResultLoweringStats8616",
    "lower_unobserved_call_result_assignments_8616",
)


class _UnobservedResultCFunction8616(Protocol):
    """Minimal third-party generated C function surface."""

    statements: object


class _UnobservedResultCodegen8616(Protocol):
    """Dynamic angr codegen fields consumed by this lowering owner."""

    cfunc: _UnobservedResultCFunction8616
    project: object
    _inertia_callsite_summaries: object
    _inertia_callsite_c_result_contracts_8616: object
    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616
    _inertia_unobserved_call_result_lowering_stats_8616: UnobservedCallResultLoweringStats8616


@dataclass(frozen=True, slots=True)
class UnobservedCallResultLoweringStats8616:
    """Closed evidence census for unobserved call-result lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def changed(self) -> bool:
        """Return whether at least one dead result assignment was lowered."""
        return self.materialized_count > 0

    @property
    def closed(self) -> bool:
        """Return whether every classified result was materialized or failed."""
        return bool(
            0 <= self.classified_fact_count <= self.normalized_fact_count <= self.raw_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
        )


def _typed_summary_map_8616(codegen: _UnobservedResultCodegen8616) -> dict[int, CallsiteSummary8616]:
    """Narrow dynamic codegen metadata to owned typed callsite summaries."""
    raw = codegen._inertia_callsite_summaries
    if not isinstance(raw, dict):
        return {}
    return {
        node_id: summary
        for node_id, summary in raw.items()
        if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
    }


def _typed_c_result_contract_map_8616(
    codegen: _UnobservedResultCodegen8616,
) -> dict[int, CallsiteCResultContract8616]:
    """Narrow final declaration contracts to their owned typed mapping."""
    try:
        raw = codegen._inertia_callsite_c_result_contracts_8616
    except AttributeError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        callsite_addr: contract
        for callsite_addr, contract in raw.items()
        if isinstance(callsite_addr, int) and isinstance(contract, CallsiteCResultContract8616)
    }


def _c_result_contract_for_call_8616(
    codegen: _UnobservedResultCodegen8616,
    call: CFunctionCall,
    contracts: dict[int, CallsiteCResultContract8616],
) -> CallsiteCResultContract8616 | None:
    """Resolve a final C result contract by stable active or original callsite identity."""
    callsite_addr = structured_callsite_addr_8616(call)
    if callsite_addr is None:
        return None
    contract = contracts.get(callsite_addr)
    if contract is not None:
        return contract
    try:
        original_delta = cast(Any, codegen.project)._inertia_original_linear_delta
    except AttributeError:
        return None
    if not isinstance(original_delta, int):
        return None
    return contracts.get(callsite_addr + original_delta)


def _is_proven_unobserved_ax_result_8616(
    assignment: CAssignment,
    summary: CallsiteSummary8616,
) -> bool:
    """Classify an exact AX-family result assignment from typed binary facts."""
    if summary.stack_probe_helper:
        return False
    if summary.return_used is not False or summary.return_use_kind not in {
        None,
        CallsiteReturnUseKind8616.CLOBBERED,
    }:
        return False
    if summary.return_register not in {None, "ax", "eax"}:
        return False
    view = physical_register_view_8616(assignment.lhs)
    return view is not None and view.reg_offset == 0 and view.width in {2, 4}


def _projected_call_result_8616(node: object) -> CFunctionCall | None:
    """Return the sole call in an exact generated wide-result projection."""
    if isinstance(node, CFunctionCall):
        return node
    if isinstance(node, CUnaryOp) and node.op in {"Dereference", "Reference"}:
        return _projected_call_result_8616(node.operand)
    if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
        if isinstance(node.rhs, CConstant) and node.rhs.value == 1:
            return _projected_call_result_8616(node.lhs)
        if node.op == "Add" and isinstance(node.lhs, CConstant) and node.lhs.value == 1:
            return _projected_call_result_8616(node.rhs)
    return None


def _is_proven_unobserved_projected_result_8616(summary: CallsiteSummary8616) -> bool:
    """Classify a generated call projection from closed caller-use evidence."""
    return bool(
        not summary.stack_probe_helper
        and summary.return_used is False
        and summary.return_use_kind in {None, CallsiteReturnUseKind8616.CLOBBERED}
        and summary.return_register in {None, "ax", "eax"}
    )


def _is_typed_void_call_8616(call: CFunctionCall) -> bool:
    """Return whether the structured call carries an explicit void contract."""
    try:
        return_type = call.prototype_returnty
    except (AttributeError, TypeError):
        return False
    return isinstance(return_type, SimTypeBottom) and return_type.label == "void"


def _has_proven_void_interrupt_result_8616(
    codegen: _UnobservedResultCodegen8616,
    call: CFunctionCall,
) -> bool:
    """Return whether Semantics proves this exact interrupt has no register result."""
    callsite_addr = structured_callsite_addr_8616(call)
    if callsite_addr is None:
        return False
    try:
        artifact = codegen._inertia_software_interrupt_input_artifact_8616
    except AttributeError:
        return False
    if not isinstance(artifact, SoftwareInterruptInputArtifact8616):
        return False
    matches = tuple(fact for fact in artifact.facts if fact.callsite_addr == callsite_addr)
    return len(matches) == 1 and matches[0].result_register is None


def _has_typed_void_interrupt_target_8616(
    codegen: _UnobservedResultCodegen8616,
    call: CFunctionCall,
) -> bool:
    """Return whether exact synthetic interrupt identity has a typed void result."""
    callee = call.callee_func
    try:
        target_addr = cast(Any, callee).addr
    except AttributeError:
        target_addr = None
    if isinstance(target_addr, int):
        direct_kind = interrupt_service_result_kind_at_addr_8616(target_addr)
        if direct_kind is not None:
            return direct_kind is InterruptServiceResultKind8616.VOID
    callsite_addr = structured_callsite_addr_8616(call)
    try:
        function_addr = cast(Any, codegen.cfunc).addr
        functions = cast(Any, codegen.project).kb.functions
        function = functions.function(addr=function_addr, create=False)
        target_addr = function.get_call_target(callsite_addr)
    except (AttributeError, KeyError, TypeError):
        return False
    if isinstance(target_addr, int):
        cfg_kind = interrupt_service_result_kind_at_addr_8616(target_addr)
        if cfg_kind is not None:
            return cfg_kind is InterruptServiceResultKind8616.VOID
    matches = tuple(
        recovered
        for recovered in collect_interrupt_service_calls(function)
        if recovered.insn_addr == callsite_addr
    )
    return len(matches) == 1 and (
        interrupt_service_result_kind_at_addr_8616(interrupt_service_addr(matches[0]))
        is InterruptServiceResultKind8616.VOID
    )


def lower_unobserved_call_result_assignments_8616(codegen: object) -> bool:
    """Replace only typed-clobbered AX call assignments with standalone calls."""
    boundary = cast(_UnobservedResultCodegen8616, codegen)
    try:
        root = boundary.cfunc.statements
        summaries = _typed_summary_map_8616(boundary)
        c_result_contracts = _typed_c_result_contract_map_8616(boundary)
    except AttributeError:
        return False

    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    seen_assignments: set[int] = set()
    for container in tuple(
        node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements)
    ):
        statements = list(container.statements or ())
        changed = False
        for index, statement in enumerate(statements):
            if not isinstance(statement, CAssignment):
                continue
            direct_call = statement.rhs if isinstance(statement.rhs, CFunctionCall) else None
            projected_call = (
                None
                if direct_call is not None
                else _projected_call_result_8616(statement.rhs)
            )
            call = direct_call or projected_call
            if call is None:
                continue
            assignment_id = id(statement)
            if assignment_id in seen_assignments:
                continue
            seen_assignments.add(assignment_id)
            raw_fact_count += 1
            summary = summaries.get(id(call))
            c_result_contract = _c_result_contract_for_call_8616(
                boundary,
                call,
                c_result_contracts,
            )
            typed_void_projection = projected_call is not None and (
                _is_typed_void_call_8616(call)
                or _has_proven_void_interrupt_result_8616(boundary, call)
                or _has_typed_void_interrupt_target_8616(boundary, call)
                or (
                    c_result_contract is not None
                    and c_result_contract.kind is CallsiteCResultKind8616.VOID
                )
            )
            if summary is None and not typed_void_projection:
                continue
            normalized_fact_count += 1
            direct_is_proven = summary is not None and direct_call is not None and _is_proven_unobserved_ax_result_8616(
                statement,
                summary,
            )
            projected_is_proven = (
                projected_call is not None
                and (
                    typed_void_projection
                    or (
                        summary is not None
                        and _is_proven_unobserved_projected_result_8616(summary)
                    )
                )
            )
            if not direct_is_proven and not projected_is_proven:
                continue
            classified_fact_count += 1
            statements[index] = CExpressionStatement(call, codegen=statement.codegen)
            materialized_count += 1
            changed = True
        if changed:
            cast(Any, container).statements = statements

    stats = UnobservedCallResultLoweringStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=classified_fact_count - materialized_count,
    )
    if not stats.closed:
        raise PipelineHardError("unobserved call-result lowering evidence accounting is not closed")
    boundary._inertia_unobserved_call_result_lowering_stats_8616 = stats
    return stats.changed
