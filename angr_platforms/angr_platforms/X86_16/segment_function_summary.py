"""Join function-local segment facts with typed control-transfer evidence.

Layer: function summaries.
Responsibility: own interprocedural segment requirements and effects after IR has
established local facts. Never infer aliases, types, C repairs, or memory models.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, cast

from .analysis_helpers import CallTargetKind8616, CallTargetSeed, collect_neighbor_call_targets
from .ir.segment_contract import SegmentFactVerdict, SegmentFunctionContract

__all__ = [
    "SegmentCalleeEffectFact8616", "SegmentControlTransferDistance8616",
    "SegmentControlTransferFact8616", "SegmentControlTransferKind8616",
    "SegmentFunctionSummary8616", "apply_x86_16_segment_function_summary",
    "build_x86_16_segment_control_transfers", "join_x86_16_segment_function_summaries",
]

_CALL_KINDS = frozenset({
    CallTargetKind8616.CFG_RESOLVED_CALL, CallTargetKind8616.DIRECT_NEAR_CALL,
    CallTargetKind8616.DIRECT_FAR_CALL, CallTargetKind8616.STORED_NEAR_CALL,
})
class _FunctionSurface8616(Protocol):
    """Dynamic angr function fields used at the frontend-summary boundary."""

    addr: int

    def get_call_sites(self) -> Iterable[int]:
        """Return machine addresses for calls represented in the CFG."""
        ...


class _FunctionManagerSurface8616(Protocol):
    """Dynamic angr function-manager lookup used by the summary attachment."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Return the function at an exact address when present."""
        ...


class _CodegenBoundary8616(Protocol):
    """Owned segment contracts carried across the dynamic angr codegen boundary."""

    _inertia_segment_function_contract: SegmentFunctionContract
    _inertia_segment_function_summary_8616: SegmentFunctionSummary8616


class _ProjectBoundary8616(Protocol):
    """Project registry for incrementally recovered segment summaries."""

    _inertia_segment_local_contracts_8616: dict[int, SegmentFunctionContract]
    _inertia_segment_transfer_facts_8616: dict[int, tuple[SegmentControlTransferFact8616, ...]]
    _inertia_segment_function_summaries_8616: dict[int, SegmentFunctionSummary8616]


class SegmentControlTransferKind8616(str, Enum):
    """Architectural operation performed by one inter-function transfer."""

    CALL = "call"
    TAIL_JUMP = "tail_jump"


class SegmentControlTransferDistance8616(str, Enum):
    """Proven near/far distance, or an explicit refusal when unknown."""

    NEAR = "near"
    FAR = "far"
    UNKNOWN = "unknown"


_DISTANCE_BY_KIND = {
    CallTargetKind8616.DIRECT_NEAR_CALL: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.STORED_NEAR_CALL: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.STORED_NEAR_TAIL_JUMP: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.DIRECT_FAR_CALL: SegmentControlTransferDistance8616.FAR,
    CallTargetKind8616.DIRECT_FAR_TAIL_JUMP: SegmentControlTransferDistance8616.FAR,
}


@dataclass(frozen=True, slots=True)
class SegmentControlTransferFact8616:
    """Typed target and architectural distance for one control transfer."""

    instruction_addr: int
    kind: SegmentControlTransferKind8616
    distance: SegmentControlTransferDistance8616
    target_addr: int | None
    return_addr: int | None
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "instruction_addr": self.instruction_addr,
            "kind": self.kind.value,
            "distance": self.distance.value,
            "target_addr": self.target_addr,
            "return_addr": self.return_addr,
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentCalleeEffectFact8616:
    """Known clobber floor and completeness verdict for one callee edge."""

    instruction_addr: int
    target_addr: int | None
    clobbered_registers: tuple[str, ...]
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "instruction_addr": self.instruction_addr,
            "target_addr": self.target_addr,
            "clobbered_registers": list(self.clobbered_registers),
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentFunctionSummary8616:
    """Function-local contract plus transitive, conservative callee effects."""

    function_addr: int
    local_contract: SegmentFunctionContract
    control_transfers: tuple[SegmentControlTransferFact8616, ...] = ()
    callee_effects: tuple[SegmentCalleeEffectFact8616, ...] = ()
    effective_clobbered_registers: tuple[str, ...] = ()
    unresolved_effect_sites: tuple[int, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "local_contract": self.local_contract.to_dict(),
            "control_transfers": [fact.to_dict() for fact in self.control_transfers],
            "callee_effects": [fact.to_dict() for fact in self.callee_effects],
            "effective_clobbered_registers": list(self.effective_clobbered_registers),
            "unresolved_effect_sites": list(self.unresolved_effect_sites),
            "summary": dict(self.summary),
        }


def _callsite_addrs(function: object) -> tuple[int, ...]:
    """Read exact CFG callsites at the dynamic angr function boundary."""
    try:
        raw = cast(_FunctionSurface8616, function).get_call_sites()
    except (AttributeError, TypeError):
        return ()
    return tuple(sorted({addr for addr in raw if isinstance(addr, int)}))


def _transfer_from_seed(seed: CallTargetSeed) -> SegmentControlTransferFact8616:
    """Normalize one typed frontend seed into a segment-summary transfer."""
    kind = (
        SegmentControlTransferKind8616.CALL
        if seed.kind in _CALL_KINDS
        else SegmentControlTransferKind8616.TAIL_JUMP
    )
    distance = _DISTANCE_BY_KIND.get(seed.kind, SegmentControlTransferDistance8616.UNKNOWN)
    verdict = (
        SegmentFactVerdict.PROVEN
        if distance is not SegmentControlTransferDistance8616.UNKNOWN
        else SegmentFactVerdict.UNKNOWN_REFUSE
    )
    return SegmentControlTransferFact8616(
        instruction_addr=seed.callsite_addr,
        kind=kind,
        distance=distance,
        target_addr=seed.target_addr,
        return_addr=seed.return_addr,
        verdict=verdict,
    )


def build_x86_16_segment_control_transfers(function: object) -> tuple[SegmentControlTransferFact8616, ...]:
    """Collect resolved near/far transfers and retain unresolved CFG calls."""
    seeds = tuple(collect_neighbor_call_targets(function))
    callsites = _callsite_addrs(function)
    seed_callsites = {seed.callsite_addr for seed in seeds if seed.kind in _CALL_KINDS}
    unresolved = tuple(
        SegmentControlTransferFact8616(
            instruction_addr=addr,
            kind=SegmentControlTransferKind8616.CALL,
            distance=SegmentControlTransferDistance8616.UNKNOWN,
            target_addr=None,
            return_addr=None,
            verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
        )
        for addr in callsites
        if addr not in seed_callsites
    )
    return tuple(sorted((*(_transfer_from_seed(seed) for seed in seeds), *unresolved), key=lambda fact: fact.instruction_addr))


def _unknown_effect_functions(
    contracts: Mapping[int, SegmentFunctionContract],
    transfers: Mapping[int, tuple[SegmentControlTransferFact8616, ...]],
) -> set[int]:
    """Find functions whose transitive callee effects are incomplete."""
    unknown = {
        function_addr
        for function_addr, facts in transfers.items()
        if any(fact.target_addr not in contracts for fact in facts)
    }
    changed = True
    while changed:
        changed = False
        for function_addr, facts in transfers.items():
            if function_addr in unknown:
                continue
            if any(fact.target_addr in unknown for fact in facts):
                unknown.add(function_addr)
                changed = True
    return unknown


def _effective_clobbers(
    contracts: Mapping[int, SegmentFunctionContract],
    transfers: Mapping[int, tuple[SegmentControlTransferFact8616, ...]],
) -> dict[int, set[str]]:
    """Reach a deterministic fixed point for known transitive clobbers."""
    effective = {addr: set(contract.clobbered_registers) for addr, contract in contracts.items()}
    changed = True
    while changed:
        changed = False
        for function_addr, facts in transfers.items():
            current = effective.setdefault(function_addr, set())
            before = len(current)
            for fact in facts:
                if fact.target_addr in effective:
                    current.update(effective[fact.target_addr])
            changed = changed or len(current) != before
    return effective


def join_x86_16_segment_function_summaries(
    contracts: Mapping[int, SegmentFunctionContract],
    transfers: Mapping[int, tuple[SegmentControlTransferFact8616, ...]],
) -> dict[int, SegmentFunctionSummary8616]:
    """Join local contracts and callee effects without guessing missing callees."""
    effective = _effective_clobbers(contracts, transfers)
    unknown = _unknown_effect_functions(contracts, transfers)
    summaries: dict[int, SegmentFunctionSummary8616] = {}
    for function_addr in sorted(contracts):
        local = contracts[function_addr]
        function_transfers = transfers.get(function_addr, ())
        effects = tuple(
            SegmentCalleeEffectFact8616(
                instruction_addr=fact.instruction_addr,
                target_addr=fact.target_addr,
                clobbered_registers=tuple(sorted(effective.get(cast(int, fact.target_addr), set()))),
                verdict=(
                    SegmentFactVerdict.PROVEN
                    if fact.target_addr in contracts and fact.target_addr not in unknown
                    else SegmentFactVerdict.UNKNOWN_REFUSE
                ),
            )
            for fact in function_transfers
        )
        local_raw = local.summary.get("raw_fact_count", 0)
        local_classified = local.summary.get("classified_fact_count", 0)
        local_materialized = local.summary.get("materialized_count", 0)
        local_failures = local.summary.get("failure_count", 0)
        transfer_classified = sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in function_transfers)
        effect_classified = sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in effects)
        summaries[function_addr] = SegmentFunctionSummary8616(
            function_addr=function_addr,
            local_contract=local,
            control_transfers=function_transfers,
            callee_effects=effects,
            effective_clobbered_registers=tuple(sorted(effective.get(function_addr, set()))),
            unresolved_effect_sites=tuple(
                fact.instruction_addr for fact in effects if fact.verdict is SegmentFactVerdict.UNKNOWN_REFUSE
            ),
            summary={
                "raw_fact_count": local_raw + len(function_transfers) + len(effects),
                "normalized_fact_count": local_raw + len(function_transfers) + len(effects),
                "classified_fact_count": local_classified + transfer_classified + effect_classified,
                "materialized_count": local_materialized + transfer_classified + effect_classified,
                "failure_count": local_failures
                + len(function_transfers)
                - transfer_classified
                + len(effects)
                - effect_classified,
                "control_transfer_count": len(function_transfers),
                "callee_effect_count": len(effects),
            },
        )
    return summaries


def _function_for_contract(project: object, function_addr: int) -> object | None:
    """Resolve the active angr function for one exact local IR contract."""
    boundary = cast(Any, project)
    try:
        active = boundary._inertia_active_structuring_function_8616
        if cast(_FunctionSurface8616, active).addr == function_addr:
            return cast(object, active)
    except (AttributeError, TypeError):
        pass
    try:
        manager = cast(_FunctionManagerSurface8616, boundary.kb.functions)
        return manager.function(addr=function_addr, create=False)
    except (AttributeError, TypeError):
        return None


def apply_x86_16_segment_function_summary(project: object, codegen: object) -> bool:
    """Attach and register the current typed interprocedural segment summary."""
    codegen_boundary = cast(_CodegenBoundary8616, codegen)
    project_boundary = cast(_ProjectBoundary8616, project)
    try:
        local = codegen_boundary._inertia_segment_function_contract
    except AttributeError:
        return False
    if not isinstance(local, SegmentFunctionContract):
        return False
    function = _function_for_contract(project, local.function_addr)
    if function is None:
        return False
    transfer_facts = build_x86_16_segment_control_transfers(function)
    try:
        contracts = dict(project_boundary._inertia_segment_local_contracts_8616)
        transfers = dict(project_boundary._inertia_segment_transfer_facts_8616)
    except AttributeError:
        contracts = {}
        transfers = {}
    contracts[local.function_addr] = local
    transfers[local.function_addr] = transfer_facts
    summaries = join_x86_16_segment_function_summaries(contracts, transfers)
    project_boundary._inertia_segment_local_contracts_8616 = contracts
    project_boundary._inertia_segment_transfer_facts_8616 = transfers
    project_boundary._inertia_segment_function_summaries_8616 = summaries
    summary = summaries[local.function_addr]
    codegen_boundary._inertia_segment_function_summary_8616 = summary
    return False
