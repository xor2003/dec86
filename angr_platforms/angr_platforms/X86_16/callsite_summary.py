"""Layer: Recovery metadata.

Responsibility: summarize recovered callsite targets, pushes, and return-shape facts.
Forbidden: deriving call semantics from source/COD text or repairing emitted calls.
"""

from __future__ import annotations

import builtins
import contextlib
import logging
import os
from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
from types import SimpleNamespace
from typing import Any, Iterable, Protocol, TypeAlias, cast

from angr.sim_type import SimTypeBottom, SimTypeFunction
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsitePushTrace8616,
    CallsiteRegisterJoinTrace8616,
    merge_callsite_predecessor_stack_traces_8616,
    merge_callsite_register_join_traces_8616,
)
from .analysis_helpers import collect_neighbor_call_targets, resolve_direct_call_target_from_block
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_target_inventory import CallsiteTargetInventory8616
from .compiler_helpers import (
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_registered_stack_probe_target_8616,
    is_x86_16_stack_probe_name_8616,
)
from .helper_abi import (
    known_helper_is_variadic_8616 as _catalog_helper_is_variadic_8616,
)
from .helper_abi import (
    known_helper_logical_argument_widths_8616,
)
from .pipeline.errors import PipelineHardError

__all__ = [
    "CallerReturnUseEvidence8616",
    "CallerReturnUseVerdict8616",
    "CallsiteArgumentClass8616",
    "CallsiteMachineFrameKind8616",
    "CallsiteStackCleanupEvidence8616",
    "CallsiteSummary8616",
    "CallsiteTargetInventory8616",
    "StructuredCallKind8616",
    "bind_structured_callsite_identity_8616",
    "build_callsite_summary_inventory_8616",
    "callsite_summary_inventory_8616",
    "callsite_machine_frame_kind_8616",
    "caller_return_use_evidence_by_addr_8616",
    "collect_caller_return_use_evidence_8616",
    "logical_argument_widths_from_callsite_8616",
    "known_helper_abi_widths_8616",
    "known_helper_is_variadic_8616",
    "callsite_target_name_for_project_8616",
    "record_caller_return_use_evidence_8616",
    "structured_call_kind_8616",
    "structured_callsite_addr_8616",
    "summarize_x86_16_callsite",
]

log: logging.Logger = logging.getLogger(__name__)
_DynamicCallsiteValue8616: TypeAlias = Any
_CallsiteTuple8616: TypeAlias = tuple[object, ...]

def known_helper_abi_widths_8616(symbol_name: str | None) -> tuple[int, ...] | None:
    """Return explicit logical ABI widths for a known runtime helper."""
    normalized = normalize_callee_name_8616(symbol_name)
    return known_helper_logical_argument_widths_8616(normalized)


def known_helper_is_variadic_8616(symbol_name: str | None) -> bool:
    """Return whether a known runtime helper has an open-ended argument list."""
    normalized = normalize_callee_name_8616(symbol_name)
    return _catalog_helper_is_variadic_8616(normalized)


def _dynamic_callsite_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic third-party angr/Capstone callsite boundary."""
    return builtins.getattr(obj, name, default)


def _dynamic_callsite_setattr_8616(obj: object, name: str, value: object) -> None:
    """Write an attribute across the dynamic third-party angr/Capstone callsite boundary."""
    builtins.setattr(obj, name, value)


class _CapstoneInstructionSurface8616(Protocol):
    """Typed fields used from a third-party Capstone instruction."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    operands: tuple[object, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return the backend register name for an operand register id."""
        ...

    def regs_access(self) -> tuple[list[int], list[int]]:
        """Return the registers read and written by this instruction."""
        ...


class _AngrInstructionWrapperSurface8616(Protocol):
    """Typed angr instruction wrapper carrying a Capstone instruction."""

    insn: _CapstoneInstructionSurface8616


class _AngrFunctionPrototypeSurface8616(Protocol):
    """Typed angr function fields used to rank recovered ABI prototypes."""

    prototype: object | None
    is_prototype_guessed: bool


class _CapstoneOperandSurface8616(Protocol):
    """Typed fields used from a third-party Capstone operand."""

    type: int
    reg: int
    imm: int
    size: int
    mem: object


class _DirectedGraphSurface8616(Protocol):
    """Typed fields used from a third-party function CFG."""

    nodes: Iterable[object]

    def predecessors(self, node: object) -> Iterable[object]:
        """Return direct predecessor nodes for one CFG node."""
        ...


class CallsiteReturnShape8616(Enum):
    """AX-family return register width observed after a callsite."""

    AX = "ax"
    DX_AX = "dx_ax"


class StructuredCallKind8616(Enum):
    """Typed classification for machine calls versus codegen intrinsics."""

    MACHINE_CALL = "machine_call"
    CODEGEN_INSERT_INTRINSIC = "codegen_insert_intrinsic"


class CallsiteMachineFrameKind8616(StrEnum):
    """Typed machine return-frame category for a recovered callsite."""

    NEAR = "near"
    FAR = "far"

    @property
    def return_frame_width(self) -> int:
        """Return the number of bytes pushed by the machine call itself."""
        return 2 if self is CallsiteMachineFrameKind8616.NEAR else 4


def structured_call_kind_8616(call: object) -> StructuredCallKind8616:
    """Classify a structured call without treating codegen intrinsics as calls."""
    callee_target = _dynamic_callsite_getattr_8616(call, "callee_target", None)
    callee_func = _dynamic_callsite_getattr_8616(call, "callee_func", None)
    callee_name = _dynamic_callsite_getattr_8616(callee_func, "name", None)
    for candidate in (callee_target, callee_name):
        if isinstance(candidate, str) and candidate.rsplit(".", 1)[-1].lstrip("_") == "INSERT":
            return StructuredCallKind8616.CODEGEN_INSERT_INTRINSIC
    return StructuredCallKind8616.MACHINE_CALL


class CallsiteReturnUseKind8616(StrEnum):
    """How the caller consumes a returned AX-family value."""

    VALUE = "value"
    CONDITION = "condition"
    CLOBBERED = "clobbered"
    FUNCTION_RETURN = "function_return"


class CallerReturnUseVerdict8616(StrEnum):
    """Whether binary callsites consume a function's AX-family return value."""

    USED = "used"
    UNUSED = "unused"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CallerReturnUseEvidence8616:
    """Closed evidence loop for binary caller return-use classification."""

    target_addr: int
    verdict: CallerReturnUseVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    used_callsite_count: int
    unused_callsite_count: int
    callsite_addrs: tuple[int, ...]
    excluded_callsite_count: int = 0


class _CallerReturnUseEvidenceOwner8616(Protocol):
    """Typed Inertia evidence field carried by a third-party project object."""

    _inertia_caller_return_use_evidence_by_addr_8616: dict[int, CallerReturnUseEvidence8616]


def caller_return_use_evidence_by_addr_8616(
    owner: object | None,
) -> dict[int, CallerReturnUseEvidence8616]:
    """Read the owned caller-use evidence contract from a project carrier."""
    if owner is None:
        return {}
    carrier = cast(_CallerReturnUseEvidenceOwner8616, owner)
    try:
        evidence_by_addr = carrier._inertia_caller_return_use_evidence_by_addr_8616
    except AttributeError:
        return {}
    if not isinstance(evidence_by_addr, dict):
        raise TypeError("caller return-use evidence carrier must be a dict")
    return evidence_by_addr


def record_caller_return_use_evidence_8616(
    owner: object,
    function_addr: int,
    evidence: CallerReturnUseEvidence8616,
) -> None:
    """Record typed caller-use evidence on a project carrier."""
    evidence_by_addr = dict(caller_return_use_evidence_by_addr_8616(owner))
    evidence_by_addr[function_addr] = evidence
    cast(_CallerReturnUseEvidenceOwner8616, owner)._inertia_caller_return_use_evidence_by_addr_8616 = evidence_by_addr


class CallsitePushSourceKind8616(Enum):
    """Structured source categories for values pushed as call arguments."""

    BP_VALUE = "bp"
    BP_ADDRESS = "bp_addr"
    BP_INDEX_ADDRESS = "bp_index_addr"
    GLOBAL_VALUE = "global"
    GLOBAL_INDEX_VALUE = "global_index"
    SEGMENTED_INDIRECT_VALUE = "seg_indirect"
    IMMEDIATE = "imm"
    EXPR = "expr"
    RETURN_REGISTER = "ret_reg"
    SEGMENT = "seg"


class CallsitePushExprOp8616(Enum):
    """Operations used to describe reconstructed push-argument expressions."""

    ADD = "add"
    ADC = "adc"
    SUB = "sub"
    SBB = "sbb"
    ADD_SOURCE = "add_source"
    ADC_SOURCE = "adc_source"
    SUB_SOURCE = "sub_source"
    SBB_SOURCE = "sbb_source"
    AND = "and"
    OR = "or"
    XOR = "xor"
    SHL = "shl"
    SHR = "shr"
    MUL = "mul"
    SIGN_EXT_HI = "sign_ext_hi"


class CallsiteArgumentClass8616(StrEnum):
    """Binary-seeded logical C argument classes."""

    VALUE = "value"
    POINTER = "pointer"


@dataclass(frozen=True, slots=True)
class CallsiteStackCleanupEvidence8616:
    """Exact caller-side stack cleanup instruction recovered after one call."""

    amount: int
    instruction_addr: int


@dataclass(frozen=True, slots=True)
class CallsiteSummary8616:
    """Structured 16-bit x86 callsite facts consumed by lowering/postprocess."""

    callsite_addr: int
    target_addr: int | None
    return_addr: int | None
    kind: str | None
    arg_count: int | None
    arg_widths: tuple[int, ...]
    stack_cleanup: int | None
    return_register: str | None
    return_used: bool | None
    stack_probe_helper: bool = False
    stack_probe_allocation_size: int | None = None
    helper_return_state: str = "none"
    helper_return_space: str | None = None
    helper_return_width: int | None = None
    helper_return_address_kind: str = "none"
    return_shape: str | None = None
    push_arg_sources: tuple[_CallsiteTuple8616 | None, ...] = field(default=(), compare=False)
    push_arg_instruction_addrs: tuple[int, ...] = field(default=(), compare=False)
    return_store_destination: tuple[str, int] | None = None
    return_store_width: int | None = None
    target_source: _CallsiteTuple8616 | None = None
    return_use_kind: CallsiteReturnUseKind8616 | None = None
    logical_arg_widths: tuple[int, ...] = field(default=(), compare=False)
    logical_arg_classes: tuple[CallsiteArgumentClass8616, ...] = field(default=(), compare=False)
    stack_cleanup_instruction_addr: int | None = None
    predecessor_stack_merge: CallsitePredecessorStackMerge8616 | None = field(default=None, compare=False)

    def brief(self) -> str:
        """Return a compact diagnostic rendering of the callsite summary."""
        return (
            f"callsite={self.callsite_addr:#x} "
            f"target={None if self.target_addr is None else hex(self.target_addr)} "
            f"args={self.arg_count} "
            f"return_shape={self.return_shape} "
            f"probe_allocation={self.stack_probe_allocation_size} "
            f"helper_return={self.helper_return_state} "
            f"helper_space={self.helper_return_space} "
            f"helper_width={self.helper_return_width} "
            f"helper_addr_kind={self.helper_return_address_kind}"
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation of the summary contract."""
        return asdict(self)


def callsite_machine_frame_kind_8616(
    summary: CallsiteSummary8616,
) -> CallsiteMachineFrameKind8616 | None:
    """Normalize legacy call-kind spellings at the summary boundary."""
    if summary.kind is None:
        return None
    return {
        "near": CallsiteMachineFrameKind8616.NEAR,
        "direct_near": CallsiteMachineFrameKind8616.NEAR,
        "far": CallsiteMachineFrameKind8616.FAR,
        "direct_far": CallsiteMachineFrameKind8616.FAR,
    }.get(summary.kind)


class _StructuredCallsiteTagCarrier8616(Protocol):
    """Third-party structured-call tag field carrying exact recovery metadata."""

    tags: dict[str, object]


def structured_callsite_addr_8616(
    call: _StructuredCallsiteTagCarrier8616,
) -> int | None:
    """Return the exact machine callsite identity attached to a structured call."""
    tags = call.tags
    if not isinstance(tags, dict):
        return None
    callsite_addr = tags.get("ins_addr")
    return callsite_addr if isinstance(callsite_addr, int) else None


def bind_structured_callsite_identity_8616(
    call: _StructuredCallsiteTagCarrier8616,
    summary: CallsiteSummary8616,
) -> None:
    """Persist a typed machine-call identity across AST cloning/regeneration.

    A conflicting instruction tag is evidence corruption and must stop the
    pipeline rather than silently rebinding a structured call.
    """
    tags = call.tags
    if not isinstance(tags, dict):
        raise PipelineHardError("structured call has no writable tag mapping")
    existing_callsite_addr = tags.get("ins_addr")
    if isinstance(existing_callsite_addr, int) and existing_callsite_addr != summary.callsite_addr:
        raise PipelineHardError(
            "structured callsite identity conflicts with typed summary: "
            f"tag={existing_callsite_addr:#x} summary={summary.callsite_addr:#x}"
        )
    call.tags = {**tags, "ins_addr": summary.callsite_addr}


def rebind_cloned_structured_callsite_identity_8616(
    call: _StructuredCallsiteTagCarrier8616,
    inherited_summary: CallsiteSummary8616,
    replacement_summary: CallsiteSummary8616,
) -> None:
    """Retag a proven clone while preserving ordinary identity conflicts.

    AST cloning intentionally copies the source call's instruction tag. Only
    the Structuring split for two exact calls to the same callee may replace
    that inherited identity. The clone must still carry the source summary's
    exact tag and both summaries must identify the same callee.
    """
    if inherited_summary.target_addr != replacement_summary.target_addr:
        raise PipelineHardError(
            "cloned structured callsite cannot change typed callee identity: "
            f"source={inherited_summary.target_addr!r} "
            f"replacement={replacement_summary.target_addr!r}"
        )
    tags = call.tags
    if not isinstance(tags, dict):
        raise PipelineHardError("cloned structured call has no writable tag mapping")
    inherited_callsite_addr = tags.get("ins_addr")
    if inherited_callsite_addr != inherited_summary.callsite_addr:
        raise PipelineHardError(
            "cloned structured callsite does not carry its proven source identity: "
            f"tag={inherited_callsite_addr!r} "
            f"source={inherited_summary.callsite_addr:#x}"
        )
    call.tags = {**tags, "ins_addr": replacement_summary.callsite_addr}


class _CallsiteSummaryInventoryOwner8616(Protocol):
    """Typed Inertia callsite inventory carried by an angr codegen object."""

    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]


def callsite_summary_inventory_8616(owner: object | None) -> dict[int, CallsiteSummary8616]:
    """Return the authoritative owned callsite inventory or fail its contract."""
    if owner is None:
        return {}
    carrier = cast(_CallsiteSummaryInventoryOwner8616, owner)
    try:
        inventory = carrier._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return {}
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory carrier must be a dict")
    for callsite_addr, summary in inventory.items():
        if not isinstance(callsite_addr, int):
            raise TypeError("callsite summary inventory keys must be integers")
        if not isinstance(summary, CallsiteSummary8616):
            raise TypeError("callsite summary inventory values must be CallsiteSummary8616")
        if summary.callsite_addr != callsite_addr:
            raise ValueError("callsite summary inventory key must match summary.callsite_addr")
    return inventory


def build_callsite_summary_inventory_8616(
    function: object,
    callsite_addrs: Iterable[int],
) -> dict[int, CallsiteSummary8616]:
    """Build the authoritative typed summary inventory for exact callsites."""
    typed_function = cast(SimpleNamespace, function)
    target_inventory = CallsiteTargetInventory8616.collect(function)
    inventory: dict[int, CallsiteSummary8616] = {}
    for callsite_addr in sorted(set(callsite_addrs)):
        if not isinstance(callsite_addr, int):
            raise TypeError("callsite summary inventory addresses must be integers")
        summary = summarize_x86_16_callsite(
            typed_function,
            callsite_addr,
            target_inventory=target_inventory,
        )
        if summary is not None:
            inventory[callsite_addr] = summary
    return inventory


def logical_argument_widths_from_callsite_8616(
    summary: CallsiteSummary8616 | None,
    *,
    expected_arg_count: int | None,
) -> tuple[int, ...] | None:
    """Return logical argument widths when each argument has one proven push.

    Callsite widths and sources are stored in execution push order. The result
    is returned in source argument order. Multi-push values such as real-mode
    far pointers intentionally refuse this projection; their logical width must
    come from explicit ABI evidence.
    """
    if summary is None or not isinstance(expected_arg_count, int) or expected_arg_count <= 0:
        return None
    widths = summary.arg_widths
    sources = summary.push_arg_sources
    if len(widths) != expected_arg_count or len(sources) != expected_arg_count:
        return None
    if any(not isinstance(width, int) or width <= 0 for width in widths):
        return None
    if any(source is None for source in sources):
        return None
    return tuple(reversed(widths))


def _logical_arg_interface_for_target_8616(
    function: object,
    target_addr: int | None,
) -> tuple[tuple[int, ...], tuple[CallsiteArgumentClass8616, ...]]:
    """Return prototype-backed widths without guessing pointer/value classes.

    An angr scalar prototype may be synthesized from physical stack width
    alone. Conversely, a pointer prototype can be introduced by later
    materialization. Neither origin, by itself, is independent binary proof of
    the logical argument class. Class evidence is therefore populated only by
    owning reconciliation paths such as exact far-pointer grouping.
    """
    if not isinstance(target_addr, int):
        return (), ()
    try:
        project = cast(Any, function).project
    except AttributeError:
        return (), ()
    candidate_addrs: list[int] = [target_addr]
    try:
        original_delta = project._inertia_original_linear_delta
    except AttributeError:
        original_delta = None
    if isinstance(original_delta, int):
        candidate_addrs.extend((target_addr + original_delta, target_addr - original_delta))
    candidate_projects = [project]
    try:
        original_project = project._inertia_original_project
    except AttributeError:
        original_project = None
    if original_project is not None:
        candidate_projects.append(original_project)
    candidates: list[tuple[bool, int, tuple[int, ...]]] = []
    candidate_order = 0
    for candidate_project in candidate_projects:
        for candidate_addr in dict.fromkeys(addr for addr in candidate_addrs if addr >= 0):
            candidate_order += 1
            try:
                callee = candidate_project.kb.functions.function(addr=candidate_addr, create=False)
            except (AttributeError, KeyError):
                continue
            if callee is None:
                continue
            typed_callee = cast(_AngrFunctionPrototypeSurface8616, callee)
            try:
                prototype = typed_callee.prototype
            except AttributeError:
                continue
            if not isinstance(prototype, SimTypeFunction):
                continue
            widths: list[int] = []
            for arg_type in tuple(prototype.args or ()):
                if isinstance(arg_type, SimTypeBottom):
                    widths = []
                    break
                try:
                    size_bits = arg_type.size
                except AttributeError:
                    widths = []
                    break
                if not isinstance(size_bits, int):
                    widths = []
                    break
                width = max(2, (size_bits + 7) // 8)
                widths.append(width)
            if widths:
                try:
                    is_guessed = bool(typed_callee.is_prototype_guessed)
                except AttributeError:
                    is_guessed = True
                candidates.append((is_guessed, candidate_order, tuple(widths)))
    if candidates:
        _is_guessed, _order, selected_widths = min(
            candidates,
            key=lambda candidate: (candidate[0], candidate[1]),
        )
        return selected_widths, ()
    return (), ()


def _logical_arg_widths_for_target_8616(function: object, target_addr: int | None) -> tuple[int, ...]:
    """Return logical ABI widths from a binary-seeded target prototype."""
    widths, _classes = _logical_arg_interface_for_target_8616(function, target_addr)
    return widths


def _is_stack_probe_target_name_8616(name: str | None) -> bool:
    return bool(is_x86_16_stack_probe_name_8616(name))


def _evidence_name_8616(evidence: object) -> str | None:
    """Read a typed helper-evidence name from the dynamic compiler-helper boundary."""
    name = _dynamic_callsite_getattr_8616(evidence, "name", None)
    return name if isinstance(name, str) else None


def _lookup_target_name_8616(function: object, target_addr: int | None) -> str | None:
    def _impl() -> str | None:
        if not isinstance(target_addr, int):
            return None
        project = _dynamic_callsite_getattr_8616(function, "project", None)
        original_delta = _dynamic_callsite_getattr_8616(project, "_inertia_original_linear_delta", None)
        lookup_addrs = [target_addr]
        if isinstance(original_delta, int):
            lookup_addrs.append(target_addr + original_delta)
            rebased = target_addr - original_delta
            if rebased >= 0:
                lookup_addrs.append(rebased)
        deduped_addrs: list[int] = []
        for addr in lookup_addrs:
            if addr not in deduped_addrs:
                deduped_addrs.append(addr)

        for candidate_project in (project, _dynamic_callsite_getattr_8616(project, "_inertia_original_project", None)):
            kb_functions = _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(candidate_project, "kb", None), "functions", None)
            lookup = _dynamic_callsite_getattr_8616(kb_functions, "function", None)
            for candidate_addr in deduped_addrs:
                evidence = identify_x86_16_compiler_helper_at_8616(candidate_project, candidate_addr)
                generic_name: str | None = None
                if callable(lookup):
                    try:
                        callee = lookup(addr=candidate_addr, create=False)
                    except Exception as ex:
                        log.debug(
                            "callsite target lookup failed project=%r addr=%#x: %s",
                            candidate_project,
                            candidate_addr,
                            ex,
                        )
                        callee = None
                    name = _dynamic_callsite_getattr_8616(callee, "name", None)
                    if isinstance(name, str) and name:
                        normalized = normalize_callee_name_8616(name)
                        if evidence is not None and (
                            not isinstance(normalized, str)
                            or normalized.startswith("sub_")
                            or normalized.startswith("loc_")
                        ):
                            return _evidence_name_8616(evidence)
                        if _is_stack_probe_target_name_8616(name):
                            return name
                        generic_name = name
                for labels in (
                    _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(candidate_project, "kb", None), "labels", None),
                    _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
                ):
                    if labels is None:
                        continue
                    try:
                        label = labels.get(candidate_addr)
                    except Exception as ex:
                        log.debug(
                            "callsite label lookup failed project=%r addr=%#x: %s",
                            candidate_project,
                            candidate_addr,
                            ex,
                        )
                        label = None
                    if isinstance(label, str) and label:
                        if evidence is not None:
                            normalized = normalize_callee_name_8616(label)
                            if (
                                not isinstance(normalized, str)
                                or normalized.startswith("sub_")
                                or normalized.startswith("loc_")
                            ):
                                return _evidence_name_8616(evidence)
                        return label
                if evidence is not None:
                    return _evidence_name_8616(evidence)
                if generic_name is not None:
                    return generic_name
        return None

    return _impl()


def callsite_target_name_for_project_8616(project: object, target_addr: int | None) -> str | None:
    """Resolve a call target name from the project metadata and address evidence."""
    return _lookup_target_name_8616(SimpleNamespace(project=project), target_addr)


def _mnemonic(insn: object) -> str:
    """Return a normalized mnemonic from the typed Capstone boundary."""

    try:
        mnemonic = cast(_CapstoneInstructionSurface8616, insn).mnemonic
    except AttributeError:
        return ""
    return str(mnemonic or "").strip().lower()


def _capstone_insn(insn: object) -> _CapstoneInstructionSurface8616:
    """Return a typed Capstone instruction from an optional angr wrapper."""

    try:
        return cast(_AngrInstructionWrapperSurface8616, insn).insn
    except AttributeError:
        return cast(_CapstoneInstructionSurface8616, insn)


def _operand_reg_name(insn: object, operand: object) -> str | None:
    surface = cast(_CapstoneOperandSurface8616, operand)
    try:
        operand_type = surface.type
    except AttributeError:
        operand_type = None
    if operand_type is not None and operand_type != X86_OP_REG:
        return None
    if operand_type is None:
        try:
            memory = surface.mem
        except AttributeError:
            memory = None
        if memory is not None:
            return None
    try:
        reg = surface.reg
    except AttributeError:
        return None
    if not isinstance(reg, int):
        return None
    capstone_insn = _capstone_insn(insn)
    try:
        value = capstone_insn.reg_name(reg)
    except (AttributeError, Exception) as ex:
        log.debug("capstone reg_name lookup failed reg=%r: %s", reg, ex)
        value = None
    if isinstance(value, str) and value:
        return value.lower()
    return None


def _operand_imm_value(operand: object) -> int | None:
    surface = cast(_CapstoneOperandSurface8616, operand)
    try:
        operand_type = surface.type
    except AttributeError:
        operand_type = None
    if isinstance(operand_type, int) and operand_type != X86_OP_IMM:
        return None
    try:
        imm = surface.imm
    except AttributeError:
        return None
    return imm if isinstance(imm, int) else None


def _operand_mem_value_8616(operand: object) -> _DynamicCallsiteValue8616:
    """Return memory metadata from the typed Capstone operand boundary."""

    surface = cast(_CapstoneOperandSurface8616, operand)
    try:
        operand_type = surface.type
    except AttributeError:
        return None
    if operand_type != X86_OP_MEM:
        return None
    try:
        return surface.mem
    except AttributeError:
        return None


def _operand_is_reg(insn: object, operand: object, names: set[str]) -> bool:
    reg_name = _operand_reg_name(insn, operand)
    return reg_name in names if reg_name is not None else False


def _instruction_operands(insn: object) -> tuple[object, ...]:
    """Return operands from the typed Capstone instruction boundary."""

    try:
        return tuple(_capstone_insn(insn).operands or ())
    except AttributeError:
        return ()


def _fixed_stack_probe_allocation_before_call_8616(
    insns: tuple[object, ...],
    call_index: int,
) -> int | None:
    """Return a bounded immediate AX allocation immediately preceding a probe."""
    for index in range(call_index - 1, max(-1, call_index - 5), -1):
        insn = insns[index]
        operands = _instruction_operands(insn)
        if _mnemonic(insn) == "mov" and len(operands) == 2:
            if not _operand_is_reg(insn, operands[0], {"ax"}):
                continue
            value = _operand_imm_value(operands[1])
            return value if isinstance(value, int) and 0 <= value <= 0x7FFF else None
        if _mnemonic(insn).startswith(("j", "ret", "call")):
            return None
    return None


def _instruction_address_8616(insn: object) -> int | None:
    """Return the typed Capstone instruction address when available."""

    try:
        address = cast(_CapstoneInstructionSurface8616, insn).address
    except AttributeError:
        return None
    return address if isinstance(address, int) else None


def _instruction_size_8616(insn: object) -> int | None:
    """Return the typed Capstone instruction size when available."""

    try:
        size = cast(_CapstoneInstructionSurface8616, insn).size
    except AttributeError:
        return None
    return size if isinstance(size, int) else None


def _instruction_op_str_8616(insn: object) -> str:
    """Return the typed Capstone instruction operand rendering."""

    try:
        op_str = cast(_CapstoneInstructionSurface8616, insn).op_str
    except AttributeError:
        return ""
    return str(op_str or "")


def _find_call_index(insns: tuple[object, ...], callsite_addr: int) -> int | None:
    for idx, insn in enumerate(insns):
        insn_addr = _instruction_address_8616(insn)
        if insn_addr == callsite_addr and _mnemonic(insn).startswith("call"):
            return idx
        insn_size = _instruction_size_8616(insn)
        if (
            isinstance(insn_addr, int)
            and isinstance(insn_size, int)
            and insn_size > 0
            and insn_addr < callsite_addr < insn_addr + insn_size
            and _mnemonic(insn).startswith("call")
        ):
            return idx
    return None


def _block_insns_for_callsite(function: object, callsite_addr: int) -> tuple[object, ...]:
    def _impl() -> tuple[object, ...]:
        project = _dynamic_callsite_getattr_8616(function, "project", None)
        if project is None:
            return ()

        debug = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))

        def _debug_insns(label: str, insns: tuple[object, ...]) -> None:
            if not debug:
                return
            rendered = ", ".join(
                f"{_instruction_address_8616(insn):#x}:{_mnemonic(insn)} {_instruction_op_str_8616(insn)}"
                for insn in insns[:12]
            )
            log.warning("[callsite-window] callsite=%#x %s count=%d %s", callsite_addr, label, len(insns), rendered)

        def _decode_linear_window(start_addr: int) -> tuple[object, ...]:
            if not isinstance(start_addr, int) or start_addr > callsite_addr:
                return ()
            size = max(callsite_addr - start_addr + 16, 16)
            try:
                block = project.factory.block(
                    start_addr,
                    size=size,
                    num_inst=max(callsite_addr - start_addr + 8, 8),
                    strict_block_end=False,
                    opt_level=0,
                )
            except Exception as ex:
                log.debug(
                    "callsite linear-window decode failed start=%#x callsite=%#x: %s", start_addr, callsite_addr, ex
                )
                block = None
            insns = tuple(_dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", ()) or ()) if block is not None else ()
            _debug_insns(f"factory-window start={start_addr:#x}", insns)
            if _find_call_index(insns, callsite_addr) is not None:
                return insns
            capstone_engine = _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(project, "arch", None), "capstone", None)
            memory = _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(project, "loader", None), "memory", None)
            if capstone_engine is None or memory is None:
                return insns
            try:
                data = bytes(memory.load(start_addr, size))
                capstone_insns = tuple(capstone_engine.disasm(data, start_addr))
                _debug_insns(f"capstone-window start={start_addr:#x}", capstone_insns)
                return capstone_insns
            except Exception as ex:
                log.debug(
                    "callsite capstone-window decode failed start=%#x callsite=%#x: %s", start_addr, callsite_addr, ex
                )
                return insns

        candidate_addrs = [callsite_addr]
        func_addr = _dynamic_callsite_getattr_8616(function, "addr", None)
        if isinstance(func_addr, int) and func_addr <= callsite_addr:
            candidate_addrs.append(func_addr)
        for block_addr in tuple(sorted(_dynamic_callsite_getattr_8616(function, "block_addrs_set", ()) or ())):
            if block_addr == callsite_addr:
                continue
            if block_addr > callsite_addr:
                break
            candidate_addrs.append(block_addr)

        for block_addr in reversed(candidate_addrs):
            try:
                block = project.factory.block(block_addr, opt_level=0)
            except Exception as ex:
                log.debug("callsite block decode failed block=%#x: %s", block_addr, ex)
                continue
            insns = tuple(_dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", ()) or ())
            _debug_insns(f"factory-block start={block_addr:#x}", insns)
            call_idx = _find_call_index(insns, callsite_addr)
            if call_idx is not None and call_idx > 0:
                return insns
            if call_idx is not None:
                for start_addr in reversed(candidate_addrs):
                    window_insns = _decode_linear_window(start_addr)
                    window_idx = _find_call_index(window_insns, callsite_addr)
                    if window_idx is not None and window_idx > 0:
                        return window_insns
                return insns
        return ()

    return _impl()


def _next_linear_block_insns(function: object, callsite_addr: int) -> tuple[object, ...]:
    project = _dynamic_callsite_getattr_8616(function, "project", None)
    if project is None:
        return ()
    candidate_addrs = sorted(addr for addr in (_dynamic_callsite_getattr_8616(function, "block_addrs_set", ()) or ()) if addr > callsite_addr)
    for block_addr in candidate_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:
            log.debug("callsite next block decode failed block=%#x: %s", block_addr, ex)
            continue
        insns = tuple(_dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", ()) or ())
        if insns:
            return insns
    return ()


def _call_return_addr_from_insn_8616(insn: object) -> int | None:
    """Return the linear fall-through address after a call instruction.

    Dynamic boundary: third-party Capstone instruction wrappers expose address and size.
    """

    insn_addr = _instruction_address_8616(insn)
    insn_size = _instruction_size_8616(insn)
    if isinstance(insn_addr, int) and isinstance(insn_size, int) and insn_size > 0:
        return insn_addr + insn_size
    return None


def _decode_linear_insns_at_8616(function: object, addr: int, *, limit: int) -> tuple[object, ...]:
    """Decode a bounded instruction window starting at a linear address.

    Dynamic boundary: angr project/block objects expose Capstone instruction wrappers.
    """

    project = _dynamic_callsite_getattr_8616(function, "project", None)
    if project is None or not isinstance(addr, int) or limit <= 0:
        return ()
    try:
        block = project.factory.block(
            addr,
            size=max(limit * 8, 16),
            num_inst=limit,
            strict_block_end=False,
            opt_level=0,
        )
    except TypeError:
        try:
            block = project.factory.block(addr, opt_level=0)
        except Exception as ex:
            log.debug("callsite follow decode failed addr=%#x: %s", addr, ex)
            return ()
    except Exception as ex:
        log.debug("callsite follow decode failed addr=%#x: %s", addr, ex)
        return ()
    insns = tuple(_dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", ()) or ())
    if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
        rendered = ", ".join(
            f"{_instruction_address_8616(insn):#x}:{_mnemonic(insn)} {_instruction_op_str_8616(insn)}"
            for insn in insns[:limit]
        )
        log.warning("[callsite-follow] addr=%#x count=%d %s", addr, len(insns), rendered)
    return insns[:limit]


def _follow_insns_after_call_8616(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    callsite_addr: int,
    *,
    limit: int,
) -> list[object]:
    """Collect the bounded instruction window that immediately follows a call.

    Dynamic boundary: third-party Capstone instruction wrappers expose addresses.
    """

    follow_insns = list(insns[idx + 1 : idx + 1 + limit])
    if len(follow_insns) >= limit:
        return follow_insns
    call_insn = insns[idx] if 0 <= idx < len(insns) else None
    return_addr = _call_return_addr_from_insn_8616(call_insn)
    decoded: tuple[object, ...] = ()
    if isinstance(return_addr, int):
        decoded = _decode_linear_insns_at_8616(function, return_addr, limit=limit - len(follow_insns))
        existing_addrs = {_instruction_address_8616(insn) for insn in follow_insns}
        follow_insns.extend(insn for insn in decoded if _instruction_address_8616(insn) not in existing_addrs)
    if len(follow_insns) < limit:
        existing_addrs = {_instruction_address_8616(insn) for insn in follow_insns}
        follow_insns.extend(
            insn
            for insn in _next_linear_block_insns(function, callsite_addr)
            if _instruction_address_8616(insn) not in existing_addrs
        )
    return follow_insns[:limit]


def _push_arg_width(insn: object) -> int:
    operands = _instruction_operands(insn)
    if operands:
        try:
            size = cast(_CapstoneOperandSurface8616, operands[0]).size
        except AttributeError:
            size = None
        if isinstance(size, int) and size > 0:
            return size
    return 2


def _direct_call_target_for_insn_8616(function: object, insn: object) -> int | None:
    project = _dynamic_callsite_getattr_8616(function, "project", None)
    callsite_addr = _instruction_address_8616(insn)
    if project is None or not isinstance(callsite_addr, int):
        return None
    try:
        target = resolve_direct_call_target_from_block(project, callsite_addr)
        return target if isinstance(target, int) else None
    except Exception:
        return None


def _callee_stack_cleanup_bytes_8616(function: object, insn: object) -> int | None:
    project = _dynamic_callsite_getattr_8616(function, "project", None)
    target = _direct_call_target_for_insn_8616(function, insn)
    if project is None or not isinstance(target, int):
        return None
    original_delta = _dynamic_callsite_getattr_8616(project, "_inertia_original_linear_delta", None)
    candidate_addrs = [target]
    if isinstance(original_delta, int):
        candidate_addrs.append(target + original_delta)
        if target >= original_delta:
            candidate_addrs.append(target - original_delta)
    deduped_addrs: list[int] = []
    for addr in candidate_addrs:
        if isinstance(addr, int) and addr >= 0 and addr not in deduped_addrs:
            deduped_addrs.append(addr)
    for candidate_project in (project, _dynamic_callsite_getattr_8616(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for candidate_addr in deduped_addrs:
            try:
                block = candidate_project.factory.block(candidate_addr, size=256, strict_block_end=False, opt_level=0)
                callee_insns = tuple(_dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", ()) or ())
            except Exception as ex:
                log.debug("callee cleanup decode failed target=%#x: %s", candidate_addr, ex)
                continue
            for callee_insn in callee_insns:
                if not _mnemonic(callee_insn).startswith("ret"):
                    continue
                operands = _instruction_operands(callee_insn)
                if not operands:
                    return 0
                cleanup = _operand_imm_value(operands[0])
                if isinstance(cleanup, int) and 0 <= cleanup <= 128 and cleanup % 2 == 0:
                    return cleanup
                return None
    return None


def _is_segment_register_push_8616(insn: object) -> bool:
    if not _mnemonic(insn).startswith("push"):
        return False
    operands = _instruction_operands(insn)
    return len(operands) == 1 and _operand_reg_name(insn, operands[0]) in {"cs", "ds", "es", "ss"}


def _transparent_between_push_args_8616(insn: object) -> bool:
    mnemonic = _mnemonic(insn)
    if mnemonic in {"cbw", "cwd", "cwde", "cdq", "nop"}:
        return True
    if mnemonic in {"mul", "imul"}:
        operands = _instruction_operands(insn)
        if len(operands) == 1:
            return True
        if len(operands) in {2, 3}:
            dest_name = _operand_reg_name(insn, operands[0])
            return dest_name not in {"sp", "bp", "ss", "ds", "es", "cs"} if dest_name is not None else False
        return False
    if mnemonic in {"mov", "lea"}:
        operands = _instruction_operands(insn)
        if len(operands) != 2:
            return False
        return _operand_reg_name(insn, operands[0]) not in {"sp", "bp", "ss", "ds", "es", "cs"}

    if mnemonic not in {"adc", "add", "sbb", "sub", "shl", "shr", "and", "or", "xor", "inc", "dec"}:
        return False
    operands = _instruction_operands(insn)
    if mnemonic in {"inc", "dec"}:
        if len(operands) != 1:
            return False
        dest_name = _operand_reg_name(insn, operands[0])
        return dest_name not in {"sp", "bp", "ss", "ds", "es", "cs"} if dest_name is not None else False

    if len(operands) != 2:
        return False
    dest_name = _operand_reg_name(insn, operands[0])
    if dest_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return False
    return dest_name is not None


def _rewind_callee_clean_nested_call_args_8616(function: object, insns: tuple[object, ...], call_idx: int) -> int | None:
    cleanup = _callee_stack_cleanup_bytes_8616(function, insns[call_idx])
    if not isinstance(cleanup, int) or cleanup <= 0:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-window] nested-call rewind refused callsite=%#x cleanup=%r",
                _instruction_address_8616(insns[call_idx]) or -1,
                cleanup,
            )
        return None
    scan = call_idx - 1
    skipped_transparents = 0
    total = 0
    while scan >= 0:
        insn = insns[scan]
        if _mnemonic(insn).startswith("push") and not _is_segment_register_push_8616(insn):
            total += _push_arg_width(insn)
            scan -= 1
            skipped_transparents = 0
            if total == cleanup:
                if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
                    log.warning(
                        "[callsite-window] nested-call rewind accepted callsite=%#x cleanup=%d rewound_to=%d",
                        _instruction_address_8616(insns[call_idx]) or -1,
                        cleanup,
                        scan,
                    )
                return scan
            if total > cleanup:
                if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
                    log.warning(
                        "[callsite-window] nested-call rewind refused callsite=%#x reason=overshoot cleanup=%d total=%d",
                        _instruction_address_8616(insns[call_idx]) or -1,
                        cleanup,
                        total,
                    )
                return None
            continue
        if skipped_transparents < 12 and _transparent_between_push_args_8616(insn):
            skipped_transparents += 1
            scan -= 1
            continue
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-window] nested-call rewind refused callsite=%#x reason=barrier cleanup=%d total=%d",
                _instruction_address_8616(insns[call_idx]) or -1,
                cleanup,
                total,
            )
        return None
    return None


def _linear_window_insns_for_callsite_8616(function: object, callsite_addr: int) -> tuple[object, ...]:
    project = _dynamic_callsite_getattr_8616(function, "project", None)
    if project is None:
        return ()
    start = _dynamic_callsite_getattr_8616(function, "addr", None)
    block_addrs = tuple(sorted(_dynamic_callsite_getattr_8616(function, "block_addrs_set", ()) or ()))
    if not isinstance(start, int) or start > callsite_addr:
        starts = [addr for addr in block_addrs if isinstance(addr, int) and addr <= callsite_addr]
        start = starts[0] if starts else None
    if not isinstance(start, int) or start > callsite_addr:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-window] callsite=%#x cleanup-linear refused start=%r blocks=%r",
                callsite_addr,
                start,
                tuple(hex(addr) for addr in block_addrs[:12]),
            )
        return ()
    size = max(callsite_addr - start + 16, 16)
    try:
        block = project.factory.block(
            start,
            size=size,
            num_inst=max(callsite_addr - start + 8, 8),
            strict_block_end=False,
            opt_level=0,
        )
    except Exception as ex:
        log.debug("callsite cleanup linear-window decode failed start=%#x callsite=%#x: %s", start, callsite_addr, ex)
        return ()
    insns = tuple(_dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", ()) or ())
    call_idx = _find_call_index(insns, callsite_addr)
    if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
        log.warning(
            "[callsite-window] callsite=%#x cleanup-linear start=%#x count=%d call_idx=%r",
            callsite_addr,
            start,
            len(insns),
            call_idx,
        )
    if call_idx is None:
        return ()
    return insns


def _function_cfg_instruction_inventory_8616(function: object) -> tuple[object, ...]:
    """Return the address-ordered Capstone instructions owned by one function CFG."""
    blocks: tuple[object, ...] = ()
    try:
        blocks = tuple(cast(Iterable[object], _dynamic_callsite_getattr_8616(function, "blocks", ())))
    except Exception as ex:
        log.debug("callee-save function block enumeration failed: %s", ex)

    project = _dynamic_callsite_getattr_8616(function, "project", None)
    if not blocks and project is not None:
        decoded_blocks: list[object] = []
        for block_addr in sorted(
            addr
            for addr in (_dynamic_callsite_getattr_8616(function, "block_addrs_set", ()) or ())
            if isinstance(addr, int)
        ):
            try:
                decoded_blocks.append(project.factory.block(block_addr, opt_level=0))
            except Exception as ex:
                log.debug("callee-save block decode failed block=%#x: %s", block_addr, ex)
        blocks = tuple(decoded_blocks)

    by_addr: dict[int, object] = {}
    for block in blocks:
        capstone = _dynamic_callsite_getattr_8616(block, "capstone", None)
        for insn in tuple(_dynamic_callsite_getattr_8616(capstone, "insns", ()) or ()):
            address = _instruction_address_8616(insn)
            if isinstance(address, int):
                by_addr.setdefault(address, insn)
    return tuple(by_addr[address] for address in sorted(by_addr))


def _callee_saved_frame_push_addresses_8616(function: object) -> frozenset[int]:
    """Return exact prologue PUSH addresses restored by every decoded epilogue."""
    insns = _function_cfg_instruction_inventory_8616(function)
    if not insns:
        return frozenset()

    callee_saved = {"bx", "si", "di"}
    restored_by_return: list[set[str]] = []
    for ret_index, insn in enumerate(insns):
        if not _mnemonic(insn).startswith("ret"):
            continue
        restored: set[str] = set()
        scan = ret_index - 1
        while scan >= 0:
            candidate = insns[scan]
            mnemonic = _mnemonic(candidate)
            operands = _instruction_operands(candidate)
            if mnemonic == "pop" and len(operands) == 1:
                reg_name = _operand_reg_name(candidate, operands[0])
                if reg_name == "bp":
                    scan -= 1
                    continue
                if reg_name in callee_saved:
                    restored.add(reg_name)
                    scan -= 1
                    continue
            if mnemonic == "leave":
                scan -= 1
                continue
            if mnemonic == "mov" and len(operands) == 2:
                if (
                    _operand_reg_name(candidate, operands[0]) == "sp"
                    and _operand_reg_name(candidate, operands[1]) == "bp"
                ):
                    scan -= 1
                    continue
            if mnemonic == "nop":
                scan -= 1
                continue
            break
        restored_by_return.append(restored)

    if not restored_by_return or any(not restored for restored in restored_by_return):
        return frozenset()
    restored_on_all_paths = set.intersection(*restored_by_return)
    if not restored_on_all_paths:
        return frozenset()

    push_by_register: dict[str, int] = {}
    for insn in insns:
        if _mnemonic(insn) != "push":
            continue
        operands = _instruction_operands(insn)
        if len(operands) != 1:
            continue
        reg_name = _operand_reg_name(insn, operands[0])
        address = _instruction_address_8616(insn)
        if reg_name in restored_on_all_paths and isinstance(address, int):
            push_by_register.setdefault(reg_name, address)
    return frozenset(push_by_register.values())


def _filter_callee_saved_frame_pushes_8616(
    function: object,
    widths: tuple[int, ...],
    sources: tuple[_CallsiteTuple8616 | None, ...],
    instruction_addrs: tuple[int, ...],
) -> tuple[tuple[int, ...], tuple[_CallsiteTuple8616 | None, ...], tuple[int, ...]]:
    """Remove only push/pop-proven frame saves from physical call arguments."""
    if not widths or len(widths) != len(sources) or len(widths) != len(instruction_addrs):
        return widths, sources, instruction_addrs
    frame_push_addrs = _callee_saved_frame_push_addresses_8616(function)
    if not frame_push_addrs:
        return widths, sources, instruction_addrs
    kept = tuple(index for index, address in enumerate(instruction_addrs) if address not in frame_push_addrs)
    return (
        tuple(widths[index] for index in kept),
        tuple(sources[index] for index in kept),
        tuple(instruction_addrs[index] for index in kept),
    )


def _collect_push_args_before_call(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    cleanup: int | None = None,
) -> tuple[int, ...]:
    def _impl() -> tuple[int, ...]:
        widths: list[int] = []
        scan = idx - 1
        skipped_transparents = 0
        skipped_call_segment = False
        target_total = cleanup if isinstance(cleanup, int) and cleanup > 0 else None
        while scan >= 0:
            insn = insns[scan]
            if _mnemonic(insn).startswith("push"):
                if not widths and _is_segment_register_push_8616(insn):
                    skipped_call_segment = True
                    scan -= 1
                    continue
                widths.append(_push_arg_width(insn))
                scan -= 1
                if target_total is not None and sum(widths) >= target_total:
                    break
                continue
            if not widths and skipped_call_segment and _transparent_between_push_args_8616(insn):
                scan -= 1
                continue
            if widths and skipped_transparents < 8 and _transparent_between_push_args_8616(insn):
                skipped_transparents += 1
                scan -= 1
                continue
            if (
                widths
                and target_total is not None
                and sum(widths) < target_total
                and _mnemonic(insn).startswith("call")
            ):
                rewound = _rewind_callee_clean_nested_call_args_8616(function, insns, scan)
                if rewound is not None and rewound < scan:
                    scan = rewound
                    skipped_transparents = 0
                    continue
            break
        widths.reverse()
        return tuple(widths)

    return _impl()


def _push_arg_source(insn: object) -> _CallsiteTuple8616 | None:
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    operand = operands[0]
    reg_name = _operand_reg_name(insn, operand)
    if reg_name in {"cs", "ds", "es", "ss"}:
        return (CallsitePushSourceKind8616.SEGMENT.value, reg_name)
    mem = _operand_mem_value_8616(operand)
    if mem is not None:
        base = _dynamic_callsite_getattr_8616(mem, "base", None)
        disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
        if isinstance(base, int) and isinstance(disp, int):
            base_name = _operand_reg_name(insn, type("_PushMemOperand", (), {"reg": base})())
            index = int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0)
            if base_name == "bp" and int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0) == 0:
                return (CallsitePushSourceKind8616.BP_VALUE.value, int(disp))
            if not base_name and index == 0:
                width = _dynamic_callsite_getattr_8616(operand, "size", None)
                return (
                    CallsitePushSourceKind8616.GLOBAL_VALUE.value,
                    int(disp),
                    int(width) if isinstance(width, int) and width > 0 else 2,
                )
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return (CallsitePushSourceKind8616.IMMEDIATE.value, imm)
    return None


def _call_target_source_8616(insn: object) -> _CallsiteTuple8616 | None:
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    operand = operands[0]
    mem = _operand_mem_value_8616(operand)
    if mem is not None:
        base = _dynamic_callsite_getattr_8616(mem, "base", None)
        disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
        if isinstance(base, int) and isinstance(disp, int):
            base_name = _operand_reg_name(insn, type("_CallMemOperand", (), {"reg": base})())
            if base_name == "bp" and int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0) == 0:
                return ("bp", int(disp))
    reg_name = _operand_reg_name(insn, operand)
    if isinstance(reg_name, str) and reg_name:
        return ("reg", reg_name)
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return ("imm", imm)
    return None


def _source_from_bp_mem_operand_8616(insn: object, operand: object, *, address: bool) -> _CallsiteTuple8616 | None:
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = _dynamic_callsite_getattr_8616(mem, "base", None)
    disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
    if isinstance(base, int) and isinstance(disp, int):
        base_name = _operand_reg_name(insn, type("_SourceMemOperand", (), {"reg": base})())
        index = int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0)
        if base_name == "bp" and index == 0:
            kind = CallsitePushSourceKind8616.BP_ADDRESS if address else CallsitePushSourceKind8616.BP_VALUE
            return (kind.value, int(disp))
        if base_name == "bp" and address and index != 0:
            index_name = _operand_reg_name(insn, type("_SourceMemOperand", (), {"reg": index})())
            scale = int(_dynamic_callsite_getattr_8616(mem, "scale", 1) or 1)
            if isinstance(index_name, str) and index_name not in {"sp", "bp", "ss", "ds", "es", "cs"}:
                return (CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value, int(disp), index_name, scale)
    return None


def _source_from_mov_operand(insn: object, operand: object) -> _CallsiteTuple8616 | None:
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return (CallsitePushSourceKind8616.IMMEDIATE.value, imm)
    bp_source = _source_from_bp_mem_operand_8616(insn, operand, address=False)
    if bp_source is not None:
        return bp_source
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = _dynamic_callsite_getattr_8616(mem, "base", None)
    disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
    index = int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0)
    if isinstance(base, int) and isinstance(disp, int):
        base_name = _operand_reg_name(insn, type("_SourceGlobalMemOperand", (), {"reg": base})())
        if not base_name and index == 0:
            width = _dynamic_callsite_getattr_8616(operand, "size", None)
            return (
                CallsitePushSourceKind8616.GLOBAL_VALUE.value,
                int(disp),
                int(width) if isinstance(width, int) and width > 0 else 2,
            )
    return None


def _ax_immediate_before_one_operand_mul_8616(insns: tuple[object, ...], mul_idx: int) -> int | None:
    scan = mul_idx - 1
    skipped = 0
    while scan >= 0 and skipped < 4:
        insn = insns[scan]
        mnemonic = _mnemonic(insn)
        operands = _instruction_operands(insn)
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) == "ax":
            value = _operand_imm_value(operands[1])
            return int(value) if isinstance(value, int) else None
        if mnemonic in {"cwd", "nop"}:
            skipped += 1
            scan -= 1
            continue
        return None
    return None


def _source_from_lea_operand_8616(insn: object, operand: object) -> _CallsiteTuple8616 | None:
    return _source_from_bp_mem_operand_8616(insn, operand, address=True)


def _indexed_global_source_from_mov_operand_8616(insns: tuple[object, ...], mov_idx: int, insn: object, operand: object) -> _CallsiteTuple8616 | None:
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = _dynamic_callsite_getattr_8616(mem, "base", None)
    disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
    index = int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0)
    if not (isinstance(base, int) and isinstance(disp, int) and index == 0):
        return None
    base_name = _operand_reg_name(insn, type("_IndexedGlobalMemOperand", (), {"reg": base})())
    if not isinstance(base_name, str) or not base_name or base_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return None

    scan = mov_idx - 1
    skipped = 0
    ops: list[tuple[str, object]] = []
    while scan >= 0 and skipped < 8:
        prev = insns[scan]
        mnemonic = _mnemonic(prev)
        operands = _instruction_operands(prev)
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(prev, operands[0]) == base_name:
            base_source = _source_from_mov_operand(prev, operands[1])
            if base_source is None:
                return None
            width = _dynamic_callsite_getattr_8616(operand, "size", None)
            return (
                CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value,
                int(disp),
                int(width) if isinstance(width, int) and width > 0 else 2,
                base_source,
                tuple(reversed(ops)),
            )
        if (
            mnemonic in {"add", "sub", "shl", "shr"}
            and len(operands) == 2
            and _operand_reg_name(prev, operands[0]) == base_name
        ):
            value = _operand_imm_value(operands[1])
            if not isinstance(value, int):
                return None
            op = {
                "add": CallsitePushExprOp8616.ADD,
                "sub": CallsitePushExprOp8616.SUB,
                "shl": CallsitePushExprOp8616.SHL,
                "shr": CallsitePushExprOp8616.SHR,
            }[mnemonic]
            ops.append((op.value, value))
            scan -= 1
            skipped += 1
            continue
        if _mnemonic(prev).startswith("push") and _is_segment_register_push_8616(prev):
            scan -= 1
            skipped += 1
            continue
        if _mnemonic(prev).startswith(("call", "push", "pop", "ret", "jmp")):
            return None
        if not _transparent_between_push_args_8616(prev):
            return None
        skipped += 1
        scan -= 1
    return None


def _segmented_indirect_source_from_operand_8616(
    insns: tuple[object, ...],
    operand_idx: int,
    insn: object,
    operand: object,
) -> _CallsiteTuple8616 | None:
    """Describe a memory value loaded through a proven register address.

    The returned source preserves segmented-memory identity instead of
    misclassifying argument- or local-derived addresses as globals.
    """
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = _dynamic_callsite_getattr_8616(mem, "base", None)
    index = int(_dynamic_callsite_getattr_8616(mem, "index", 0) or 0)
    disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
    if not (isinstance(base, int) and index == 0 and isinstance(disp, int)):
        return None
    base_name = _operand_reg_name(insn, type("_SegmentedIndirectMemOperand", (), {"reg": base})())
    if not isinstance(base_name, str) or base_name in {"", "sp", "bp", "ss", "ds", "es", "cs"}:
        return None
    address_context_idx = operand_idx
    while address_context_idx > 0 and _mnemonic(insns[address_context_idx - 1]).startswith("push"):
        address_context_idx -= 1
    address_source = _register_source_from_context_8616(insns, address_context_idx, base_name)
    if address_source is None:
        return None
    if disp:
        address_source = (
            CallsitePushSourceKind8616.EXPR.value,
            address_source,
            ((CallsitePushExprOp8616.ADD.value, int(disp)),),
        )
    segment_id = int(_dynamic_callsite_getattr_8616(mem, "segment", 0) or 0)
    segment_name = (
        _operand_reg_name(insn, type("_SegmentedIndirectSegmentOperand", (), {"reg": segment_id})())
        if segment_id
        else "ds"
    )
    if segment_name not in {"cs", "ds", "es", "ss"}:
        return None
    width = _dynamic_callsite_getattr_8616(operand, "size", None)
    if not isinstance(width, int) or width not in {1, 2, 4}:
        return None
    return (
        CallsitePushSourceKind8616.SEGMENTED_INDIRECT_VALUE.value,
        segment_name,
        width,
        address_source,
    )


def _register_source_from_context_8616(insns: tuple[object, ...], idx: int, reg_name: str, *, depth: int = 0) -> _CallsiteTuple8616 | None:
    if depth > 4 or reg_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return None
    scan = idx - 1
    skipped = 0
    ops: list[tuple[str, object]] = []
    source_regs = {reg_name}
    while scan >= 0 and skipped < 8:
        insn = insns[scan]
        operands = _instruction_operands(insn)
        mnemonic = _mnemonic(insn)
        if reg_name == "dx" and mnemonic in {"cwd", "cdq"}:
            ax_source = _register_source_from_context_8616(insns, scan, "ax", depth=depth + 1)
            if ax_source is None:
                return None
            high_source = (
                CallsitePushSourceKind8616.EXPR.value,
                ax_source,
                ((CallsitePushExprOp8616.SIGN_EXT_HI.value, 16),),
            )
            if not ops:
                return high_source
            return (CallsitePushSourceKind8616.EXPR.value, high_source, tuple(reversed(ops)))
        if reg_name == "ax" and mnemonic in {"cbw", "cwde"}:
            source_regs.add("al")
            scan -= 1
            skipped += 1
            continue
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) in source_regs:
            rhs_reg = _operand_reg_name(insn, operands[1])
            if isinstance(rhs_reg, str) and rhs_reg and rhs_reg not in source_regs:
                base_source = _register_source_from_context_8616(insns, scan, rhs_reg, depth=depth + 1)
            else:
                base_source = _source_from_mov_operand(insn, operands[1])
                if base_source is None:
                    base_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
            if base_source is None:
                return None
            if (
                "al" in source_regs
                and len(base_source) == 2
                and base_source[0] == CallsitePushSourceKind8616.BP_VALUE.value
            ):
                base_source = (*base_source, 1)
            if not ops:
                return base_source
            return (CallsitePushSourceKind8616.EXPR.value, base_source, tuple(reversed(ops)))
        zero_source = _zeroing_register_source_8616(insn, source_regs)
        if zero_source is not None:
            if not ops:
                return zero_source
            return (CallsitePushSourceKind8616.EXPR.value, zero_source, tuple(reversed(ops)))
        if len(operands) == 2 and _operand_reg_name(insn, operands[0]) == reg_name:
            if mnemonic in {"adc", "add", "sbb", "sub"}:
                value = _operand_imm_value(operands[1])
                if isinstance(value, int):
                    op = {
                        "adc": CallsitePushExprOp8616.ADC,
                        "add": CallsitePushExprOp8616.ADD,
                        "sbb": CallsitePushExprOp8616.SBB,
                        "sub": CallsitePushExprOp8616.SUB,
                    }[mnemonic]
                    ops.append((op.value, value))
                    scan -= 1
                    skipped += 1
                    continue
                rhs_reg = _operand_reg_name(insn, operands[1])
                if isinstance(rhs_reg, str) and rhs_reg and rhs_reg not in source_regs:
                    rhs_source = _register_source_from_context_8616(insns, scan, rhs_reg, depth=depth + 1)
                else:
                    rhs_source = _source_from_mov_operand(insn, operands[1])
                    if rhs_source is None:
                        rhs_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
                if rhs_source is None:
                    return None
                op = {
                    "adc": CallsitePushExprOp8616.ADC_SOURCE,
                    "add": CallsitePushExprOp8616.ADD_SOURCE,
                    "sbb": CallsitePushExprOp8616.SBB_SOURCE,
                    "sub": CallsitePushExprOp8616.SUB_SOURCE,
                }[mnemonic]
                ops.append((op.value, rhs_source))
                scan -= 1
                skipped += 1
                continue
            if mnemonic in {"shl", "shr"}:
                value = _operand_imm_value(operands[1])
                if not isinstance(value, int):
                    return None
                op = CallsitePushExprOp8616.SHL if mnemonic == "shl" else CallsitePushExprOp8616.SHR
                ops.append((op.value, value))
                scan -= 1
                skipped += 1
                continue
            if mnemonic in {"and", "or", "xor"}:
                value = _operand_imm_value(operands[1])
                if not isinstance(value, int):
                    return None
                op = {
                    "and": CallsitePushExprOp8616.AND,
                    "or": CallsitePushExprOp8616.OR,
                    "xor": CallsitePushExprOp8616.XOR,
                }[mnemonic]
                ops.append((op.value, value))
                scan -= 1
                skipped += 1
                continue
        if mnemonic.startswith("push"):
            scan -= 1
            skipped += 1
            continue
        if mnemonic.startswith(("call", "pop", "ret", "jmp")):
            return None
        if _instruction_writes_return_reg(insn, _register_family_for_carrier_8616(reg_name)):
            return None
        if ops and not _transparent_between_push_args_8616(insn):
            return None
        skipped += 1
        scan -= 1
    return None


def _zeroing_register_source_8616(insn: object, source_regs: set[str]) -> _CallsiteTuple8616 | None:
    operands = _instruction_operands(insn)
    if len(operands) != 2:
        return None
    mnemonic = _mnemonic(insn)
    lhs = _operand_reg_name(insn, operands[0])
    if mnemonic == "mov" and lhs in source_regs and _operand_imm_value(operands[1]) == 0:
        return (CallsitePushSourceKind8616.IMMEDIATE.value, 0)
    if mnemonic not in {"sub", "xor"}:
        return None
    rhs = _operand_reg_name(insn, operands[1])
    if lhs is None or lhs != rhs or lhs not in source_regs:
        return None
    return (CallsitePushSourceKind8616.IMMEDIATE.value, 0)


def _register_family_for_carrier_8616(reg_name: str) -> set[str]:
    """Return the complete 16-bit register family for one return carrier."""
    families = (
        {"ax", "al", "ah"},
        {"bx", "bl", "bh"},
        {"cx", "cl", "ch"},
        {"dx", "dl", "dh"},
    )
    return next((family for family in families if reg_name in family), {reg_name})


def _instruction_preserves_return_carrier_8616(insn: object, reg_name: str) -> bool:
    """Prove that one instruction does not overwrite a return-value carrier."""
    mnemonic = _mnemonic(insn)
    if mnemonic.startswith(("call", "ret", "int")) or mnemonic in {
        "iret",
        "iretw",
        "jmp",
        "jmpw",
        "ljmp",
        "loop",
        "loope",
        "loopne",
        "loopnz",
        "loopz",
    }:
        return False
    family = _register_family_for_carrier_8616(reg_name)
    capstone_insn = _capstone_insn(insn)
    try:
        _read_ids, written_ids = capstone_insn.regs_access()
        written_names = {capstone_insn.reg_name(reg_id).lower() for reg_id in written_ids}
    except Exception:
        # Dynamic Capstone boundary: reduced test doubles may not expose regs_access().
        written_names = set()
    if written_names:
        return family.isdisjoint(written_names)
    if mnemonic in {"aaa", "aad", "aam", "aas", "cbw", "cwd", "div", "idiv", "mul", "xlat", "xlatb"}:
        return False
    return not _instruction_writes_return_reg(insn, family)


def _transparent_return_arg_carrier_insn_8616(insn: object) -> bool:
    """Recognize ABI cleanup that preserves an immediately forwarded return pair."""
    mnemonic = _mnemonic(insn)
    operands = _instruction_operands(insn)
    if mnemonic == "nop":
        return True
    if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
        return _operand_imm_value(operands[1]) is not None
    return False


def _cfg_node_addr_8616(node: object) -> int | None:
    """Return a basic-block address across the third-party CFG boundary."""
    if isinstance(node, int) and not isinstance(node, bool):
        return node
    address = _dynamic_callsite_getattr_8616(node, "addr", None)
    return address if isinstance(address, int) and not isinstance(address, bool) else None


def _cfg_node_for_instruction_8616(graph: _DirectedGraphSurface8616, instruction_addr: int) -> object | None:
    """Find the latest CFG block start that contains an instruction address."""
    candidates = [
        (node_addr, node)
        for node in graph.nodes
        if (node_addr := _cfg_node_addr_8616(node)) is not None and node_addr <= instruction_addr
    ]
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def _unique_cfg_predecessor_chain_8616(function: object, source_addr: int, sink_addr: int) -> bool:
    """Prove that every path into the sink block passes through the source block."""
    graph_value = _dynamic_callsite_getattr_8616(function, "graph", None)
    if graph_value is None:
        return False
    graph = cast(_DirectedGraphSurface8616, graph_value)
    source = _cfg_node_for_instruction_8616(graph, source_addr)
    sink = _cfg_node_for_instruction_8616(graph, sink_addr)
    if source is None or sink is None:
        return False
    if source == sink:
        return source_addr < sink_addr
    visited = {sink}
    current = sink
    while current != source:
        try:
            predecessors = tuple(graph.predecessors(current))
        except Exception:
            # Dynamic NetworkX/angr boundary: an unavailable predecessor view is unknown evidence.
            return False
        if len(predecessors) != 1 or predecessors[0] in visited:
            return False
        current = predecessors[0]
        visited.add(current)
    return True


def _return_carrier_path_is_proven_8616(
    function: object,
    insns: tuple[object, ...],
    call_idx: int,
    push_idx: int,
    pushed_reg: str,
) -> bool:
    """Prove a no-clobber, unique-CFG path from a call return to a push."""
    call_addr = _instruction_address_8616(insns[call_idx])
    push_addr = _instruction_address_8616(insns[push_idx])
    if not isinstance(call_addr, int) or not isinstance(push_addr, int):
        return False
    saw_control_transfer = False
    for insn in insns[call_idx + 1 : push_idx]:
        mnemonic = _mnemonic(insn)
        if mnemonic.startswith("push"):
            operands = _instruction_operands(insn)
            sibling = _operand_reg_name(insn, operands[0]) if len(operands) == 1 else None
            if sibling in {"ax", "dx"}:
                continue
        if mnemonic.startswith("j"):
            operands = _instruction_operands(insn)
            target = _operand_imm_value(operands[0]) if len(operands) == 1 else None
            insn_addr = _instruction_address_8616(insn)
            if mnemonic in {"jmp", "jmpw", "ljmp"} or not isinstance(target, int):
                return False
            if not isinstance(insn_addr, int) or target < insn_addr:
                return False
            saw_control_transfer = True
            continue
        if not _instruction_preserves_return_carrier_8616(insn, pushed_reg):
            return False
    if not saw_control_transfer:
        return True
    return _unique_cfg_predecessor_chain_8616(function, call_addr, push_addr)


def _stable_stack_return_store_source_8616(
    function: object,
    insns: tuple[object, ...],
    call_idx: int,
    push_idx: int,
    callsite_addr: int,
) -> tuple[str, int] | None:
    """Resolve unchanged AX provenance through its exact BP-local return store."""
    return_store = _return_store_after_call(function, insns, call_idx, callsite_addr)
    if return_store is None or return_store[0] != "bp" or return_store[2] != 2:
        return None
    destination = return_store[1]
    matching_writes = 0
    for insn in insns[call_idx + 1 : push_idx]:
        operands = _instruction_operands(insn)
        if not operands or _mnemonic(insn) in {"cmp", "test", "lea", "push", "pushw", "pushd"}:
            continue
        base, displacement = _operand_mem_base_disp(insn, operands[0])
        if base == "bp" and displacement == destination:
            matching_writes += 1
    if matching_writes != 1:
        return None
    return (CallsitePushSourceKind8616.BP_VALUE.value, destination)


def _return_register_push_source_from_context_8616(function: object, insns: tuple[object, ...], idx: int, pushed_reg: str) -> _CallsiteTuple8616 | None:
    if pushed_reg not in {"ax", "dx"}:
        return None
    call_idx = idx - 1
    while call_idx >= 0:
        insn = insns[call_idx]
        if _mnemonic(insn).startswith("call"):
            break
        if _instruction_preserves_return_carrier_8616(insn, pushed_reg):
            call_idx -= 1
            continue
        if not _mnemonic(insn).startswith("push"):
            return None
        operands = _instruction_operands(insn)
        if len(operands) != 1:
            return None
        sibling_reg = _operand_reg_name(insn, operands[0])
        if sibling_reg not in {"ax", "dx"}:
            return None
        call_idx -= 1
    if call_idx < 0 or not _mnemonic(insns[call_idx]).startswith("call"):
        return None
    if not _return_carrier_path_is_proven_8616(function, insns, call_idx, idx, pushed_reg):
        return None

    observed_regs: set[str] = set()
    scan = call_idx + 1
    while scan < len(insns):
        insn = insns[scan]
        if not _mnemonic(insn).startswith("push"):
            break
        operands = _instruction_operands(insn)
        if len(operands) != 1:
            break
        reg_name = _operand_reg_name(insn, operands[0])
        if reg_name not in {"ax", "dx"}:
            break
        observed_regs.add(reg_name)
        if scan >= idx and {"ax", "dx"} <= observed_regs:
            break
        scan += 1

    callsite_addr = _instruction_address_8616(insns[call_idx])
    if not isinstance(callsite_addr, int):
        return None
    return_shape = _return_shape_after_call(function, insns, call_idx, callsite_addr)
    if pushed_reg == "ax" and return_shape in {CallsiteReturnShape8616.AX, CallsiteReturnShape8616.DX_AX}:
        stack_source = _stable_stack_return_store_source_8616(function, insns, call_idx, idx, callsite_addr)
        if stack_source is not None:
            return stack_source
        return (CallsitePushSourceKind8616.RETURN_REGISTER.value, callsite_addr, pushed_reg)
    if pushed_reg == "dx" and return_shape is CallsiteReturnShape8616.DX_AX:
        return (CallsitePushSourceKind8616.RETURN_REGISTER.value, callsite_addr, pushed_reg)
    if {"ax", "dx"} <= observed_regs and pushed_reg in observed_regs:
        return (CallsitePushSourceKind8616.RETURN_REGISTER.value, callsite_addr, pushed_reg)
    return None


def _zero_extended_byte_push_source_8616(
    insns: tuple[object, ...], idx: int, pushed_reg: str
) -> tuple[object, ...] | None:
    """Recover a word PUSH composed from a byte source and a proven-zero high byte."""
    byte_parts = {
        "ax": ("al", "ah"),
        "bx": ("bl", "bh"),
        "cx": ("cl", "ch"),
        "dx": ("dl", "dh"),
    }.get(pushed_reg)
    if byte_parts is None:
        return None
    low_reg, high_reg = byte_parts
    low_source: tuple[object, ...] | None = None
    high_zeroed = False
    scan = idx - 1
    skipped = 0
    while scan >= 0 and skipped < 8:
        insn = insns[scan]
        operands = _instruction_operands(insn)
        mnemonic = _mnemonic(insn)
        if mnemonic.startswith("push"):
            scan -= 1
            skipped += 1
            continue
        destination = _operand_reg_name(insn, operands[0]) if operands else None
        if destination == high_reg:
            if _zeroing_register_source_8616(insn, {high_reg}) is None:
                return None
            high_zeroed = True
        elif destination == low_reg:
            if mnemonic != "mov" or len(operands) != 2:
                return None
            rhs_reg = _operand_reg_name(insn, operands[1])
            low_source = (
                _register_source_from_context_8616(insns, scan, rhs_reg, depth=1)
                if isinstance(rhs_reg, str) and rhs_reg
                else _source_from_mov_operand(insn, operands[1])
            )
            if low_source is None:
                low_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
            if low_source is None:
                return None
            if len(low_source) == 2 and low_source[0] == CallsitePushSourceKind8616.BP_VALUE.value:
                low_source = (*low_source, 1)
        elif destination == pushed_reg:
            return None
        if low_source is not None and high_zeroed:
            return (
                CallsitePushSourceKind8616.EXPR.value,
                low_source,
                ((CallsitePushExprOp8616.AND.value, 0xFF),),
            )
        if mnemonic.startswith(("call", "pop", "ret", "jmp")):
            return None
        scan -= 1
        skipped += 1
    return None


def _push_arg_source_from_context(
    function: object, insns: tuple[object, ...], idx: int
) -> _CallsiteTuple8616 | None:
    def _impl() -> _CallsiteTuple8616 | None:
        source = _push_arg_source(insns[idx])
        if source is not None:
            return source
        operands = _instruction_operands(insns[idx])
        if len(operands) != 1:
            return None
        indexed_global_source = _indexed_global_source_from_mov_operand_8616(insns, idx, insns[idx], operands[0])
        if indexed_global_source is not None:
            return indexed_global_source
        segmented_indirect_source = _segmented_indirect_source_from_operand_8616(
            insns, idx, insns[idx], operands[0]
        )
        if segmented_indirect_source is not None:
            return segmented_indirect_source
        pushed_reg = _operand_reg_name(insns[idx], operands[0])
        if pushed_reg is None or pushed_reg in {"sp", "bp", "ss", "ds", "es", "cs"}:
            return None
        return_source = _return_register_push_source_from_context_8616(function, insns, idx, pushed_reg)
        if return_source is not None:
            return return_source
        byte_source = _zero_extended_byte_push_source_8616(insns, idx, pushed_reg)
        if byte_source is not None:
            return byte_source
        scan = idx - 1
        skipped = 0
        ops: list[tuple[str, object]] = []
        source_regs = {pushed_reg}
        while scan >= 0 and skipped < 6:
            insn = insns[scan]
            operands = _instruction_operands(insn)
            mnemonic = _mnemonic(insn)
            if pushed_reg == "dx" and mnemonic in {"cwd", "cdq"}:
                ax_source = _register_source_from_context_8616(insns, scan, "ax", depth=1)
                if ax_source is None:
                    return None
                high_source = (
                    CallsitePushSourceKind8616.EXPR.value,
                    ax_source,
                    ((CallsitePushExprOp8616.SIGN_EXT_HI.value, 16),),
                )
                if not ops:
                    return high_source
                return (CallsitePushSourceKind8616.EXPR.value, high_source, tuple(reversed(ops)))
            if pushed_reg == "ax" and mnemonic in {"cbw", "cwde"}:
                source_regs.add("al")
                scan -= 1
                skipped += 1
                continue
            if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) in source_regs:
                base_source = _source_from_mov_operand(insn, operands[1])
                if base_source is None:
                    base_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
                if base_source is None:
                    return None
                if (
                    "al" in source_regs
                    and len(base_source) == 2
                    and base_source[0]
                    == CallsitePushSourceKind8616.BP_VALUE.value
                ):
                    base_source = (*base_source, 1)
                if not ops:
                    return base_source
                return (CallsitePushSourceKind8616.EXPR.value, base_source, tuple(reversed(ops)))
            if mnemonic == "lea" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) == pushed_reg:
                base_source = _source_from_lea_operand_8616(insn, operands[1])
                if base_source is None:
                    return None
                if (
                    isinstance(base_source, tuple)
                    and len(base_source) >= 4
                    and base_source[0] == CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value
                    and isinstance(base_source[2], str)
                ):
                    index_source = _register_source_from_context_8616(insns, scan, base_source[2])
                    if index_source is not None:
                        base_source = (*base_source, index_source)
                if not ops:
                    return base_source
                return (CallsitePushSourceKind8616.EXPR.value, base_source, tuple(reversed(ops)))
            zero_source = _zeroing_register_source_8616(insn, source_regs)
            if zero_source is not None:
                if not ops:
                    return zero_source
                return (CallsitePushSourceKind8616.EXPR.value, zero_source, tuple(reversed(ops)))
            if len(operands) == 2 and _operand_reg_name(insn, operands[0]) == pushed_reg:
                if mnemonic in {"adc", "add", "sbb", "sub"}:
                    value = _operand_imm_value(operands[1])
                    if isinstance(value, int):
                        op = {
                            "adc": CallsitePushExprOp8616.ADC,
                            "add": CallsitePushExprOp8616.ADD,
                            "sbb": CallsitePushExprOp8616.SBB,
                            "sub": CallsitePushExprOp8616.SUB,
                        }[mnemonic]
                        ops.append((op.value, value))
                        scan -= 1
                        skipped += 1
                        continue
                    rhs_reg = _operand_reg_name(insn, operands[1])
                    if isinstance(rhs_reg, str) and rhs_reg and rhs_reg not in source_regs:
                        rhs_source = _register_source_from_context_8616(insns, scan, rhs_reg, depth=1)
                    else:
                        rhs_source = _source_from_mov_operand(insn, operands[1])
                        if rhs_source is None:
                            rhs_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
                    if rhs_source is None:
                        return None
                    op = {
                        "adc": CallsitePushExprOp8616.ADC_SOURCE,
                        "add": CallsitePushExprOp8616.ADD_SOURCE,
                        "sbb": CallsitePushExprOp8616.SBB_SOURCE,
                        "sub": CallsitePushExprOp8616.SUB_SOURCE,
                    }[mnemonic]
                    ops.append((op.value, rhs_source))
                    scan -= 1
                    skipped += 1
                    continue
                if mnemonic in {"shl", "shr"}:
                    value = _operand_imm_value(operands[1])
                    if not isinstance(value, int):
                        return None
                    op = CallsitePushExprOp8616.SHL if mnemonic == "shl" else CallsitePushExprOp8616.SHR
                    ops.append((op.value, value))
                    scan -= 1
                    skipped += 1
                    continue
                if mnemonic in {"and", "or", "xor"}:
                    value = _operand_imm_value(operands[1])
                    if not isinstance(value, int):
                        return None
                    op = {
                        "and": CallsitePushExprOp8616.AND,
                        "or": CallsitePushExprOp8616.OR,
                        "xor": CallsitePushExprOp8616.XOR,
                    }[mnemonic]
                    ops.append((op.value, value))
                    scan -= 1
                    skipped += 1
                    continue
                return None
            if mnemonic in {"inc", "dec"} and len(operands) == 1 and _operand_reg_name(insn, operands[0]) == pushed_reg:
                ops.append(
                    (
                        CallsitePushExprOp8616.ADD.value if mnemonic == "inc" else CallsitePushExprOp8616.SUB.value,
                        1,
                    )
                )
                scan -= 1
                skipped += 1
                continue
            if mnemonic in {"mul", "imul"}:
                if len(operands) == 1 and pushed_reg == "ax":
                    source = _source_from_mov_operand(insn, operands[0])
                    factor = _ax_immediate_before_one_operand_mul_8616(insns, scan)
                    if source is not None and isinstance(factor, int):
                        return (
                            CallsitePushSourceKind8616.EXPR.value,
                            source,
                            ((CallsitePushExprOp8616.MUL.value, factor), *tuple(reversed(ops))),
                        )
                    return None
                if pushed_reg in {"ax", "dx"}:
                    return None
                if len(operands) in {2, 3} and _operand_reg_name(insn, operands[0]) == pushed_reg:
                    return None
            if _mnemonic(insn).startswith("push"):
                operands = _instruction_operands(insn)
                sibling_reg = _operand_reg_name(insn, operands[0]) if len(operands) == 1 else None
                if _is_segment_register_push_8616(insn) or (
                    isinstance(sibling_reg, str)
                    and (
                        sibling_reg == pushed_reg
                        or (pushed_reg in {"ax", "dx"} and sibling_reg in {"ax", "dx"})
                    )
                ):
                    scan -= 1
                    skipped += 1
                    continue
                return None
            if _mnemonic(insn).startswith(("call", "pop", "ret", "jmp")):
                return None
            if not _transparent_between_push_args_8616(insn):
                return None
            skipped += 1
            scan -= 1
        return None

    return _impl()


def _collect_push_arg_sources_before_call(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    cleanup: int | None = None,
) -> tuple[_CallsiteTuple8616 | None, ...]:
    def _impl() -> tuple[_CallsiteTuple8616 | None, ...]:
        sources: list[_CallsiteTuple8616 | None] = []
        scan = idx - 1
        skipped_transparents = 0
        skipped_call_segment = False
        total = 0
        target_total = cleanup if isinstance(cleanup, int) and cleanup > 0 else None
        while scan >= 0:
            insn = insns[scan]
            if _mnemonic(insn).startswith("push"):
                if not sources and _is_segment_register_push_8616(insn):
                    skipped_call_segment = True
                    scan -= 1
                    continue
                sources.append(_push_arg_source_from_context(function, insns, scan))
                total += _push_arg_width(insn)
                scan -= 1
                if target_total is not None and total >= target_total:
                    break
                continue
            if not sources and skipped_call_segment and _transparent_between_push_args_8616(insn):
                scan -= 1
                continue
            if sources and skipped_transparents < 8 and _transparent_between_push_args_8616(insn):
                skipped_transparents += 1
                scan -= 1
                continue
            if sources and target_total is not None and total < target_total and _mnemonic(insn).startswith("call"):
                rewound = _rewind_callee_clean_nested_call_args_8616(function, insns, scan)
                if rewound is not None and rewound < scan:
                    scan = rewound
                    skipped_transparents = 0
                    continue
            break
        sources.reverse()
        return tuple(sources)

    return _impl()


def _collect_push_arg_instruction_addrs_before_call(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    cleanup: int | None = None,
) -> tuple[int, ...]:
    """Collect exact physical push addresses in execution order."""
    addresses: list[int] = []
    scan = idx - 1
    skipped_transparents = 0
    skipped_call_segment = False
    total = 0
    target_total = cleanup if isinstance(cleanup, int) and cleanup > 0 else None
    while scan >= 0:
        insn = insns[scan]
        if _mnemonic(insn).startswith("push"):
            if not addresses and _is_segment_register_push_8616(insn):
                skipped_call_segment = True
                scan -= 1
                continue
            address = _instruction_address_8616(insn)
            if not isinstance(address, int):
                return ()
            addresses.append(address)
            total += _push_arg_width(insn)
            scan -= 1
            if target_total is not None and total >= target_total:
                break
            continue
        if not addresses and skipped_call_segment and _transparent_between_push_args_8616(insn):
            scan -= 1
            continue
        if addresses and skipped_transparents < 8 and _transparent_between_push_args_8616(insn):
            skipped_transparents += 1
            scan -= 1
            continue
        if addresses and target_total is not None and total < target_total and _mnemonic(insn).startswith("call"):
            rewound = _rewind_callee_clean_nested_call_args_8616(function, insns, scan)
            if rewound is not None and rewound < scan:
                scan = rewound
                skipped_transparents = 0
                continue
        break
    addresses.reverse()
    return tuple(addresses)


def _push_scan_reaches_block_entry_8616(
    insns: tuple[object, ...],
    call_idx: int,
    push_instruction_addrs: tuple[int, ...],
) -> bool:
    """Return whether backward argument scanning reaches this block's entry."""
    if not push_instruction_addrs:
        return False
    first_push_addr = push_instruction_addrs[0]
    first_push_idx = next(
        (idx for idx, insn in enumerate(insns[:call_idx]) if _instruction_address_8616(insn) == first_push_addr),
        None,
    )
    return isinstance(first_push_idx, int) and all(
        _transparent_between_push_args_8616(insn) for insn in insns[:first_push_idx]
    )


def _unresolved_entry_push_register_8616(
    insns: tuple[object, ...],
    sources: tuple[_CallsiteTuple8616 | None, ...],
    instruction_addrs: tuple[int, ...],
) -> tuple[str, int] | None:
    """Return a block-entry register PUSH whose source needs CFG joining."""
    if not sources or not instruction_addrs or sources[0] is not None:
        return None
    push_addr = instruction_addrs[0]
    push = next(
        (insn for insn in insns if _instruction_address_8616(insn) == push_addr),
        None,
    )
    if push is None:
        return None
    operands = _instruction_operands(push)
    register = _operand_reg_name(push, operands[0]) if len(operands) == 1 else None
    if register in {None, "sp", "bp", "ss", "ds", "es", "cs"}:
        return None
    return cast(str, register), push_addr


def _predecessor_stack_merge_8616(
    function: object,
    callsite_addr: int,
    *,
    join_register: str | None = None,
    join_push_addr: int | None = None,
) -> CallsitePredecessorStackMerge8616 | None:
    """Collect and merge physical pushes from every direct predecessor block."""
    graph_value = _dynamic_callsite_getattr_8616(function, "graph", None)
    project = _dynamic_callsite_getattr_8616(function, "project", None)
    if graph_value is None or project is None:
        return None
    graph = cast(_DirectedGraphSurface8616, graph_value)
    sink = _cfg_node_for_instruction_8616(graph, callsite_addr)
    if sink is None:
        return None
    sink_addr = _cfg_node_addr_8616(sink)
    if not isinstance(sink_addr, int):
        return None
    try:
        predecessors = tuple(graph.predecessors(sink))
    except Exception:
        return None
    debug = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))
    if debug:
        log.warning(
            "[callsite-predecessor-stack] callsite=%#x sink=%r predecessors=%r",
            callsite_addr,
            _cfg_node_addr_8616(sink),
            tuple(_cfg_node_addr_8616(node) for node in predecessors),
        )
    if not predecessors:
        return None
    traces: list[CallsitePushTrace8616] = []
    register_traces: list[CallsiteRegisterJoinTrace8616] = []
    for predecessor in predecessors:
        predecessor_addr = _cfg_node_addr_8616(predecessor)
        if not isinstance(predecessor_addr, int):
            return None
        try:
            block = project.factory.block(predecessor_addr, opt_level=0)
        except Exception:
            return None
        predecessor_insns = tuple(
            _dynamic_callsite_getattr_8616(
                _dynamic_callsite_getattr_8616(block, "capstone", None),
                "insns",
                (),
            )
            or ()
        )
        predecessor_insns = tuple(
            insn
            for insn in predecessor_insns
            if (address := _instruction_address_8616(insn)) is not None
            and (predecessor_addr >= sink_addr or address < sink_addr)
        )
        if debug:
            log.warning(
                "[callsite-predecessor-stack] block=%#x insns=%r",
                predecessor_addr,
                tuple(
                    (_instruction_address_8616(insn), _mnemonic(insn), _instruction_op_str_8616(insn))
                    for insn in predecessor_insns
                ),
            )
        while predecessor_insns and _mnemonic(predecessor_insns[-1]).startswith("j"):
            predecessor_insns = predecessor_insns[:-1]
        if join_register is not None:
            register_traces.append(
                CallsiteRegisterJoinTrace8616(
                    predecessor_addr=predecessor_addr,
                    register=join_register,
                    source=_register_source_from_context_8616(
                        predecessor_insns,
                        len(predecessor_insns),
                        join_register,
                    ),
                )
            )
        argument_scan_end = len(predecessor_insns)
        while argument_scan_end > 0 and _transparent_between_push_args_8616(
            predecessor_insns[argument_scan_end - 1]
        ):
            argument_scan_end -= 1
        widths = _collect_push_args_before_call(function, predecessor_insns, argument_scan_end)
        sources = _collect_push_arg_sources_before_call(function, predecessor_insns, argument_scan_end)
        addresses = _collect_push_arg_instruction_addrs_before_call(
            function,
            predecessor_insns,
            argument_scan_end,
        )
        traces.append(CallsitePushTrace8616(widths, sources, addresses))
    register_join = (
        merge_callsite_register_join_traces_8616(
            tuple(register_traces),
            push_instruction_addr=join_push_addr,
        )
        if register_traces and isinstance(join_push_addr, int)
        else None
    )
    merged = merge_callsite_predecessor_stack_traces_8616(
        tuple(traces),
        register_join=register_join,
    )
    if debug:
        log.warning(
            "[callsite-predecessor-stack] callsite=%#x traces=%r merged=%r",
            callsite_addr,
            tuple(traces),
            merged,
        )
    return merged


def _trim_push_args_to_stack_cleanup(arg_widths: tuple[int, ...], cleanup: int | None) -> tuple[int, ...]:
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths:
        return arg_widths
    total = 0
    kept: list[int] = []
    for width in reversed(arg_widths):
        if total + width > cleanup:
            break
        kept.append(width)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return arg_widths


def _trim_push_arg_sources_to_stack_cleanup(
    arg_widths: tuple[int, ...],
    arg_sources: tuple[_CallsiteTuple8616 | None, ...],
    cleanup: int | None,
) -> tuple[_CallsiteTuple8616 | None, ...]:
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths or not arg_sources:
        return arg_sources
    if len(arg_widths) != len(arg_sources):
        return arg_sources
    total = 0
    kept: list[_CallsiteTuple8616 | None] = []
    for width, source in reversed(tuple(zip(arg_widths, arg_sources))):
        if total + width > cleanup:
            break
        kept.append(source)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return arg_sources


def _trim_push_arg_instruction_addrs_to_stack_cleanup(
    arg_widths: tuple[int, ...],
    instruction_addrs: tuple[int, ...],
    cleanup: int | None,
) -> tuple[int, ...]:
    """Trim physical push addresses with the same ABI cleanup proof as sources."""
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths or not instruction_addrs:
        return instruction_addrs
    if len(arg_widths) != len(instruction_addrs):
        return instruction_addrs
    total = 0
    kept: list[int] = []
    for width, address in reversed(tuple(zip(arg_widths, instruction_addrs, strict=True))):
        if total + width > cleanup:
            break
        kept.append(address)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return instruction_addrs


def _push_arg_source_known_count_8616(arg_sources: tuple[_CallsiteTuple8616 | None, ...]) -> int:
    return sum(1 for source in arg_sources if source is not None)


def _push_arg_sources_have_unknown_8616(arg_sources: tuple[_CallsiteTuple8616 | None, ...]) -> bool:
    return any(source is None for source in arg_sources)


def _stack_cleanup_after_call(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    callsite_addr: int,
) -> CallsiteStackCleanupEvidence8616 | None:
    """Recover an exact positive caller-side ``ADD SP, imm`` cleanup."""
    follow_insns = _follow_insns_after_call_8616(function, insns, idx, callsite_addr, limit=1)
    if not follow_insns:
        return None
    insn = follow_insns[0]
    if _mnemonic(insn) != "add":
        return None
    operands = _instruction_operands(insn)
    if len(operands) != 2:
        return None
    if not _operand_is_reg(insn, operands[0], {"sp", "esp"}):
        return None
    amount = _operand_imm_value(operands[1])
    instruction_addr = _instruction_address_8616(insn)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return None
    if not isinstance(instruction_addr, int) or isinstance(instruction_addr, bool):
        return None
    return CallsiteStackCleanupEvidence8616(
        amount=amount,
        instruction_addr=instruction_addr,
    )


def _instruction_reads_return_reg(insn: object, reg_names: set[str]) -> bool:
    operands = _instruction_operands(insn)
    if not operands:
        return False
    for operand in operands:
        if _operand_is_reg(insn, operand, reg_names):
            return True
    return False


def _instruction_writes_return_reg(insn: object, reg_names: set[str]) -> bool:
    operands = _instruction_operands(insn)
    if not operands:
        return False
    mnemonic = _mnemonic(insn)
    if mnemonic in {"cmp", "test", "push", "pushw", "pushd"}:
        return False
    return _operand_is_reg(insn, operands[0], reg_names)


def _wide_return_condition_use_8616(follow_insns: tuple[object, ...] | list[object], index: int) -> bool:
    """Recognize a guarded DX-high then AX-low comparison of one wide return value."""

    if index < 0 or index >= len(follow_insns):
        return False
    high_compare = follow_insns[index]
    if _mnemonic(high_compare) not in {"cmp", "test"}:
        return False
    if not _instruction_reads_return_reg(high_compare, {"dx", "dh", "dl"}):
        return False

    saw_conditional_branch = False
    for candidate in follow_insns[index + 1 : index + 9]:
        mnemonic = _mnemonic(candidate)
        if mnemonic.startswith("call") or mnemonic in {"ret", "retf", "retw", "iret"}:
            return False
        if _instruction_writes_return_reg(candidate, {"ax", "al", "ah", "dx", "dh", "dl"}):
            return False
        if mnemonic in {"cmp", "test"}:
            if _instruction_reads_return_reg(candidate, {"ax", "al", "ah"}):
                return saw_conditional_branch
            if _instruction_reads_return_reg(candidate, {"dx", "dh", "dl"}):
                return False
            continue
        if mnemonic.startswith("j"):
            if mnemonic not in {"jmp", "jmpw", "ljmp"}:
                saw_conditional_branch = True
            continue
        if mnemonic == "nop":
            continue
        return False
    return False


def _transparent_return_epilogue_insn_8616(insn: object) -> bool:
    mnemonic = _mnemonic(insn)
    operands = _instruction_operands(insn)
    if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
        return True
    if mnemonic == "mov" and len(operands) == 2:
        return _operand_is_reg(insn, operands[0], {"sp", "esp"}) and _operand_is_reg(insn, operands[1], {"bp", "ebp"})
    if mnemonic == "pop" and len(operands) == 1:
        return True
    if mnemonic.startswith("j"):
        return True
    return False


def _direct_jump_target_8616(insn: object) -> int | None:
    mnemonic = _mnemonic(insn)
    if mnemonic not in {"jmp", "jmpw", "ljmp"}:
        return None
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    return _operand_imm_value(operands[0])


def _extend_follow_insns_through_direct_jumps_8616(
    function: object, follow_insns: list[object], *, limit: int = 16
) -> list[object]:
    """Append bounded direct-jump target instructions for return-use scans.

    Dynamic boundary: angr project/block objects expose Capstone instruction wrappers.
    """

    project = _dynamic_callsite_getattr_8616(function, "project", None)
    if project is None:
        return follow_insns
    expanded = list(follow_insns)
    decoded_targets: set[int] = set()
    idx = 0
    while idx < len(expanded) and idx < limit:
        target = _direct_jump_target_8616(expanded[idx])
        idx += 1
        if not isinstance(target, int) or target in decoded_targets:
            continue
        decoded_targets.add(target)
        try:
            block = project.factory.block(target, opt_level=0)
        except Exception as ex:
            log.debug("return-use jump target decode failed target=%#x: %s", target, ex)
            continue
        raw_target_insns = _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(block, "capstone", None), "insns", None)
        target_insns = tuple(raw_target_insns) if isinstance(raw_target_insns, tuple | list) else ()
        if not target_insns:
            continue
        existing_addrs = {_instruction_address_8616(insn) for insn in expanded}
        insert = [insn for insn in target_insns if _instruction_address_8616(insn) not in existing_addrs]
        if not insert:
            continue
        expanded[idx:idx] = insert[:limit]
        if len(expanded) > limit * 2:
            del expanded[limit * 2 :]
    return expanded[:limit]


def _operand_mem_base_disp(insn: object, operand: object) -> tuple[str | None, int | None]:
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None, None
    base = _dynamic_callsite_getattr_8616(mem, "base", None)
    disp = _dynamic_callsite_getattr_8616(mem, "disp", None)
    if not isinstance(base, int):
        return None, disp if isinstance(disp, int) else None
    capstone_insn = _capstone_insn(insn)
    try:
        name = capstone_insn.reg_name(base)
    except (AttributeError, Exception) as ex:
        log.debug("capstone mem base lookup failed reg=%r: %s", base, ex)
        name = None
    return (name.lower() if isinstance(name, str) and name else None), disp if isinstance(disp, int) else None


def _return_store_after_call(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    callsite_addr: int,
) -> tuple[str, int, int] | None:
    """Recover a direct stack/global store of AX/AL/AH immediately after a call."""

    follow_insns = _follow_insns_after_call_8616(function, insns, idx, callsite_addr, limit=3)
    for insn_idx, insn in enumerate(follow_insns[:3]):
        mnemonic = _mnemonic(insn)
        operands = _instruction_operands(insn)
        if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
            continue
        if mnemonic.startswith("call"):
            break
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if _operand_is_reg(insn, operands[1], {"al", "ah"}):
            width = 1
        elif _operand_is_reg(insn, operands[1], {"ax"}):
            width = 2
        else:
            continue
        base, disp = _operand_mem_base_disp(insn, operands[0])
        if base == "bp" and isinstance(disp, int):
            return "bp", disp, width
        if base is None and isinstance(disp, int):
            if width == 2 and _global_dx_high_store_follows_8616(tuple(follow_insns), insn_idx, disp):
                return "global", disp, 4
            return "global", disp, width
    return None


def _global_dx_high_store_follows_8616(follow_insns: tuple[object, ...], low_idx: int, low_disp: int) -> bool:
    """Return whether a direct global AX store is paired with a following DX high-word store."""

    for insn in follow_insns[low_idx + 1 : low_idx + 3]:
        mnemonic = _mnemonic(insn)
        operands = _instruction_operands(insn)
        if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
            continue
        if mnemonic.startswith("call"):
            return False
        if mnemonic != "mov" or len(operands) != 2:
            return False
        if not _operand_is_reg(insn, operands[1], {"dx"}):
            return False
        base, disp = _operand_mem_base_disp(insn, operands[0])
        return base is None and isinstance(disp, int) and ((low_disp + 2) & 0xFFFF) == (disp & 0xFFFF)
    return False


def _return_value_feeds_divide_8616(insns: tuple[object, ...]) -> bool:
    """Recognize a bounded AX-to-CWD-to-DIV value-use chain."""
    for index, insn in enumerate(insns[:8]):
        mnemonic = _mnemonic(insn)
        if mnemonic in {"cwd", "cdq"}:
            return any(_mnemonic(candidate) in {"div", "idiv"} for candidate in insns[index + 1 : index + 3])
        if _instruction_writes_return_reg(insn, {"ax", "al", "ah"}):
            return False
        if mnemonic.startswith(("call", "j", "loop")) or mnemonic in {
            "int",
            "into",
            "iret",
            "ret",
            "retf",
            "retw",
        }:
            return False
    return False


def _return_use_after_call(
    function: object,
    insns: tuple[object, ...],
    idx: int,
    callsite_addr: int,
) -> tuple[str | None, bool | None, CallsiteReturnUseKind8616 | None]:
    """Classify the first bounded AX-family use after a call."""

    prototype = _dynamic_callsite_getattr_8616(function, "prototype", None)
    return_type = _dynamic_callsite_getattr_8616(prototype, "returnty", None)
    caller_returns_explicit_void = (
        isinstance(return_type, SimTypeBottom) and return_type.label == "void"
    )
    follow_insns = _follow_insns_after_call_8616(function, insns, idx, callsite_addr, limit=8)
    if any(_wide_return_condition_use_8616(follow_insns, follow_index) for follow_index in range(len(follow_insns))):
        return "ax", True, CallsiteReturnUseKind8616.CONDITION
    follow_insns = _extend_follow_insns_through_direct_jumps_8616(function, follow_insns, limit=16)
    bounded_follow_insns = follow_insns[:16]
    if _return_shape_after_call(function, insns, idx, callsite_addr) is CallsiteReturnShape8616.DX_AX:
        return "ax", True, CallsiteReturnUseKind8616.VALUE
    if _return_value_feeds_divide_8616(tuple(bounded_follow_insns)):
        return "ax", True, CallsiteReturnUseKind8616.VALUE
    for follow_index, insn in enumerate(bounded_follow_insns):
        operands = _instruction_operands(insn)
        mnemonic = _mnemonic(insn)
        if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
            continue
        if _wide_return_condition_use_8616(bounded_follow_insns, follow_index):
            return "ax", True, CallsiteReturnUseKind8616.CONDITION
        reads_return = _instruction_reads_return_reg(insn, {"ax", "al", "ah"})
        writes_return = _instruction_writes_return_reg(insn, {"ax", "al", "ah"})
        if reads_return and writes_return and mnemonic in {
            "adc", "add", "and", "dec", "inc", "neg", "not", "or", "rcl", "rcr", "rol", "ror", "sar", "sbb", "shl", "shr", "sub", "xor"
        }:
            next_mnemonic = _mnemonic(bounded_follow_insns[follow_index + 1]) if follow_index + 1 < len(bounded_follow_insns) else ""
            use_kind = CallsiteReturnUseKind8616.CONDITION if next_mnemonic.startswith("j") and next_mnemonic != "jmp" else CallsiteReturnUseKind8616.VALUE
            return "ax", True, use_kind
        if mnemonic not in {"cmp", "test"} and writes_return:
            return "ax", False, CallsiteReturnUseKind8616.CLOBBERED
        if reads_return:
            return (
                "ax",
                True,
                CallsiteReturnUseKind8616.CONDITION if mnemonic in {"cmp", "test"} else CallsiteReturnUseKind8616.VALUE,
            )
        if mnemonic in {"ret", "retf", "retw", "iret"}:
            if caller_returns_explicit_void:
                return None, False, None
            return "ax", True, CallsiteReturnUseKind8616.FUNCTION_RETURN
        if _transparent_return_epilogue_insn_8616(insn):
            continue
        break
    return None, False, None


def _linear_call_target_8616(insn: object) -> int | None:
    """Return the direct immediate target of one decoded call instruction."""
    if not _mnemonic(insn).startswith("call"):
        return None
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    return _operand_imm_value(operands[0])


def _linear_return_use_after_call_8616(
    insns: tuple[object, ...], call_idx: int
) -> tuple[bool | None, CallsiteReturnUseKind8616 | None]:
    """Classify AX use along a bounded decoded path after a direct call."""
    if call_idx < 0 or call_idx >= len(insns):
        return None, None
    addr_to_index = {
        int(addr): index
        for index, insn in enumerate(insns)
        if isinstance((addr := _instruction_address_8616(insn)), int)
    }
    pending = [call_idx + 1]
    visited: set[int] = set()
    examined = 0
    if _return_value_feeds_divide_8616(insns[call_idx + 1 : call_idx + 9]):
        return True, CallsiteReturnUseKind8616.VALUE
    while pending and examined < 24:
        index = pending.pop()
        if index in visited or index < 0 or index >= len(insns):
            continue
        visited.add(index)
        insn = insns[index]
        examined += 1
        operands = _instruction_operands(insn)
        mnemonic = _mnemonic(insn)
        if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
            pending.append(index + 1)
            continue
        if _wide_return_condition_use_8616(insns, index):
            return True, CallsiteReturnUseKind8616.CONDITION
        if mnemonic not in {"cmp", "test"} and _instruction_writes_return_reg(insn, {"ax", "al", "ah"}):
            return False, CallsiteReturnUseKind8616.CLOBBERED
        if _instruction_reads_return_reg(insn, {"ax", "al", "ah"}):
            kind = CallsiteReturnUseKind8616.CONDITION if mnemonic in {"cmp", "test"} else CallsiteReturnUseKind8616.VALUE
            return True, kind
        if mnemonic in {"ret", "retf", "retw", "iret"}:
            return True, CallsiteReturnUseKind8616.FUNCTION_RETURN
        if mnemonic in {"jmp", "jmpw", "ljmp"}:
            target = _direct_jump_target_8616(insn)
            target_index = addr_to_index.get(target) if isinstance(target, int) else None
            if target_index is None:
                return None, None
            pending.append(target_index)
            continue
        if _transparent_return_epilogue_insn_8616(insn):
            pending.append(index + 1)
            continue
        return False, None
    return None, None


def collect_caller_return_use_evidence_8616(
    project: object,
    target_addr: int,
    function_ranges: tuple[tuple[int, int], ...],
    *,
    target_aliases: tuple[int, ...] = (),
) -> CallerReturnUseEvidence8616:
    """Collect binary caller-use facts from independently proven function ranges.

    Proven target aliases identify recursive calls whose caller-range entry
    differs from the direct-call target because the target has an entry prelude.
    """
    arch = _dynamic_callsite_getattr_8616(project, "arch", None)
    disassembler = _dynamic_callsite_getattr_8616(arch, "capstone", None)
    memory = _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(project, "loader", None), "memory", None)
    if disassembler is None or memory is None:
        return CallerReturnUseEvidence8616(
            target_addr,
            CallerReturnUseVerdict8616.UNKNOWN,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            (),
        )
    with contextlib.suppress(Exception):
        disassembler.detail = True
    decoded_ranges: dict[tuple[int, int], tuple[object, ...]] = {}
    for start, end in sorted(set(function_ranges)):
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            continue
        try:
            data = bytes(memory.load(start, end - start))
            insns = tuple(disassembler.disasm(data, start))
        except Exception as ex:
            log.debug("caller return-use decode failed range=%#x-%#x: %s", start, end, ex)
            continue
        decoded_ranges[(start, end)] = insns

    callsite_cache: dict[int, dict[int, tuple[bool | None, CallsiteReturnUseKind8616 | None, int]]] = {}

    def _callsites_for_target(
        candidate_target: int,
    ) -> dict[int, tuple[bool | None, CallsiteReturnUseKind8616 | None, int]]:
        """Return decoded direct-call use facts keyed by callsite address."""
        normalized_target = candidate_target & 0xFFFF
        cached = callsite_cache.get(normalized_target)
        if cached is not None:
            return cached
        facts: dict[int, tuple[bool | None, CallsiteReturnUseKind8616 | None, int]] = {}
        for (caller_start, _caller_end), insns in decoded_ranges.items():
            for index, insn in enumerate(insns):
                call_target = _linear_call_target_8616(insn)
                if not isinstance(call_target, int) or (call_target & 0xFFFF) != normalized_target:
                    continue
                callsite_addr = _instruction_address_8616(insn)
                if not isinstance(callsite_addr, int):
                    continue
                return_used, kind = _linear_return_use_after_call_8616(insns, index)
                facts[callsite_addr] = (return_used, kind, caller_start)
        callsite_cache[normalized_target] = facts
        return facts

    transitive_cache: dict[int, bool | None] = {}

    def _return_observed_transitively(candidate_target: int, active_targets: frozenset[int]) -> bool | None:
        """Resolve terminal return pass-throughs only through independent callers."""
        normalized_target = candidate_target & 0xFFFF
        cached = transitive_cache.get(normalized_target)
        if cached is not None or normalized_target in transitive_cache:
            return cached
        if normalized_target in active_targets:
            return None
        facts = _callsites_for_target(candidate_target)
        if not facts:
            transitive_cache[normalized_target] = None
            return None
        resolutions: list[bool | None] = []
        next_active = active_targets | {normalized_target}
        for return_used, kind, caller_start in facts.values():
            if kind is CallsiteReturnUseKind8616.FUNCTION_RETURN:
                # A recursive tail pass-through cannot observe its own return.
                # Ignore that cycle when independent callers provide evidence;
                # a recursion-only function still resolves to unknown below.
                if (caller_start & 0xFFFF) in next_active:
                    continue
                resolutions.append(_return_observed_transitively(caller_start, next_active))
            else:
                resolutions.append(return_used)
        if any(resolution is True for resolution in resolutions):
            result: bool | None = True
        elif resolutions and all(resolution is False for resolution in resolutions):
            result = False
        else:
            result = None
        transitive_cache[normalized_target] = result
        return result

    direct_facts = _callsites_for_target(target_addr)
    normalized_target_aliases = frozenset(addr & 0xFFFF for addr in target_aliases)
    callsites: dict[int, bool | None] = {}
    for callsite_addr, (return_used, kind, caller_start) in direct_facts.items():
        if normalized_target_aliases and (caller_start & 0xFFFF) in normalized_target_aliases:
            continue
        if kind is CallsiteReturnUseKind8616.FUNCTION_RETURN:
            return_used = _return_observed_transitively(
                caller_start,
                frozenset({target_addr & 0xFFFF}),
            )
        callsites[callsite_addr] = return_used
    excluded_count = len(direct_facts) - len(callsites)
    used_count = sum(result is True for result in callsites.values())
    unused_count = sum(result is False for result in callsites.values())
    classified_count = used_count + unused_count
    failure_count = len(callsites) - classified_count
    if used_count:
        verdict = CallerReturnUseVerdict8616.USED
    elif callsites and classified_count == len(callsites):
        verdict = CallerReturnUseVerdict8616.UNUSED
    else:
        verdict = CallerReturnUseVerdict8616.UNKNOWN
    return CallerReturnUseEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        raw_fact_count=len(direct_facts),
        normalized_fact_count=len(direct_facts),
        classified_fact_count=classified_count,
        materialized_count=classified_count,
        failure_count=failure_count,
        used_callsite_count=used_count,
        unused_callsite_count=unused_count,
        callsite_addrs=tuple(sorted(direct_facts)),
        excluded_callsite_count=excluded_count,
    )


def _return_shape_after_call(
    function: object, insns: tuple[object, ...], idx: int, callsite_addr: int
) -> CallsiteReturnShape8616 | None:
    follow_insns = _follow_insns_after_call_8616(function, insns, idx, callsite_addr, limit=8)
    if any(_wide_return_condition_use_8616(follow_insns, follow_index) for follow_index in range(len(follow_insns))):
        return CallsiteReturnShape8616.DX_AX
    follow_insns = _extend_follow_insns_through_direct_jumps_8616(function, follow_insns, limit=16)

    store_dx_offsets: set[int] = set()
    store_ax_offsets: set[int] = set()
    forwarded_return_regs: set[str] = set()
    forwarding_window_open = True
    saw_ax = False

    def _has_adjacent_word_pair_8616(ax_offsets: set[int], dx_offsets: set[int]) -> bool:
        for offset in dx_offsets:
            if (offset + 2 in ax_offsets) or (offset - 2 in ax_offsets):
                return True
        for offset in ax_offsets:
            if (offset + 2 in dx_offsets) or (offset - 2 in dx_offsets):
                return True
        return False

    bounded_follow_insns = follow_insns[:16]
    for follow_index, insn in enumerate(bounded_follow_insns):
        if _mnemonic(insn) in {"ret", "retf", "retw", "iret"}:
            break
        if _wide_return_condition_use_8616(bounded_follow_insns, follow_index):
            return CallsiteReturnShape8616.DX_AX

        if forwarding_window_open and _mnemonic(insn) == "push":
            operands = _instruction_operands(insn)
            pushed_reg = _operand_reg_name(insn, operands[0]) if len(operands) == 1 else None
            if pushed_reg in {"ax", "dx"}:
                forwarded_return_regs.add(pushed_reg)
                if {"ax", "dx"} <= forwarded_return_regs:
                    return CallsiteReturnShape8616.DX_AX
            else:
                forwarding_window_open = False
        elif forwarding_window_open and not _transparent_return_arg_carrier_insn_8616(insn):
            forwarding_window_open = False
        if _mnemonic(insn).startswith("call"):
            break

        if _mnemonic(insn) == "mov" and len(_instruction_operands(insn)) == 2:
            operands = _instruction_operands(insn)
            base, disp = _operand_mem_base_disp(insn, operands[0])
            if base in {"bp", None} and isinstance(disp, int):
                if _operand_is_reg(insn, operands[1], {"dx", "dh", "dl"}):
                    store_dx_offsets.add(disp)
                if _operand_is_reg(insn, operands[1], {"ax", "al", "ah"}):
                    store_ax_offsets.add(disp)
                    saw_ax = True
            if _has_adjacent_word_pair_8616(store_ax_offsets, store_dx_offsets):
                return CallsiteReturnShape8616.DX_AX

        if _instruction_reads_return_reg(insn, {"ax", "al", "ah"}):
            saw_ax = True
        if _instruction_writes_return_reg(insn, {"ax", "al", "ah"}):
            saw_ax = True

        if _transparent_return_epilogue_insn_8616(insn):
            continue

    if any(off + 2 in store_ax_offsets for off in store_dx_offsets):
        return CallsiteReturnShape8616.DX_AX
    if any(off - 2 in store_ax_offsets for off in store_dx_offsets):
        return CallsiteReturnShape8616.DX_AX
    if saw_ax:
        return CallsiteReturnShape8616.AX
    return None


def summarize_x86_16_callsite(
    function: SimpleNamespace,
    callsite_addr: int,
    *,
    target_inventory: CallsiteTargetInventory8616 | None = None,
) -> CallsiteSummary8616 | None:
    """Summarize argument, cleanup, and return-use facts for one callsite."""

    def _impl() -> CallsiteSummary8616 | None:
        project = _dynamic_callsite_getattr_8616(function, "project", None)
        if project is None or _dynamic_callsite_getattr_8616(_dynamic_callsite_getattr_8616(project, "arch", None), "name", None) != "86_16":
            return None

        seed = (
            target_inventory.seed_for_callsite(callsite_addr)
            if target_inventory is not None
            else next(
                (
                    candidate
                    for candidate in collect_neighbor_call_targets(function)
                    if candidate.callsite_addr == callsite_addr
                ),
                None,
            )
        )
        target_addr: int | None = None
        return_addr: int | None = None
        kind: str | None = None
        if seed is not None:
            target_addr = seed.target_addr
            return_addr = seed.return_addr
            kind = seed.kind

        insns = _block_insns_for_callsite(function, callsite_addr)
        target_name = _lookup_target_name_8616(function, target_addr)
        stack_probe_helper = is_x86_16_registered_stack_probe_target_8616(
            _dynamic_callsite_getattr_8616(project, "arch", None),
            target_addr,
        ) or _is_stack_probe_target_name_8616(target_name)
        if not insns:
            helper_return_state = "stack_address" if stack_probe_helper else "none"
            helper_return_space = "ss" if stack_probe_helper else None
            helper_return_width = 2 if stack_probe_helper else None
            helper_return_address_kind = "stack" if stack_probe_helper else "none"
            return CallsiteSummary8616(
                callsite_addr,
                target_addr,
                return_addr,
                kind,
                None,
                (),
                None,
                None,
                None,
                stack_probe_helper,
                helper_return_state=helper_return_state,
                helper_return_space=helper_return_space,
                helper_return_width=helper_return_width,
                helper_return_address_kind=helper_return_address_kind,
            )
        call_idx = _find_call_index(insns, callsite_addr)
        if call_idx is None:
            helper_return_state = "stack_address" if stack_probe_helper else "none"
            helper_return_space = "ss" if stack_probe_helper else None
            helper_return_width = 2 if stack_probe_helper else None
            helper_return_address_kind = "stack" if stack_probe_helper else "none"
            return CallsiteSummary8616(
                callsite_addr,
                target_addr,
                return_addr,
                kind,
                None,
                (),
                None,
                None,
                None,
                stack_probe_helper,
                helper_return_state=helper_return_state,
                helper_return_space=helper_return_space,
                helper_return_width=helper_return_width,
                helper_return_address_kind=helper_return_address_kind,
            )

        stack_probe_allocation_size = (
            _fixed_stack_probe_allocation_before_call_8616(insns, call_idx)
            if stack_probe_helper
            else None
        )

        if return_addr is None:
            call_insn = insns[call_idx]
            insn_addr = _instruction_address_8616(call_insn)
            insn_size = _instruction_size_8616(call_insn)
            if isinstance(insn_addr, int) and isinstance(insn_size, int) and insn_size > 0:
                return_addr = (insn_addr + insn_size) & 0xFFFF

        cleanup_evidence = _stack_cleanup_after_call(
            function,
            insns,
            call_idx,
            callsite_addr,
        )
        cleanup_instruction_addr = (
            cleanup_evidence.instruction_addr
            if cleanup_evidence is not None
            else None
        )
        cleanup = cleanup_evidence.amount if cleanup_evidence is not None else None
        if cleanup is None:
            cleanup = _callee_stack_cleanup_bytes_8616(function, insns[call_idx])
        target_source = _call_target_source_8616(insns[call_idx])
        raw_arg_widths = _collect_push_args_before_call(function, insns, call_idx, cleanup)
        raw_arg_sources = _collect_push_arg_sources_before_call(function, insns, call_idx, cleanup)
        raw_push_instruction_addrs = _collect_push_arg_instruction_addrs_before_call(
            function,
            insns,
            call_idx,
            cleanup,
        )
        predecessor_stack_merge = None
        if _push_scan_reaches_block_entry_8616(insns, call_idx, raw_push_instruction_addrs):
            unresolved_entry_push = _unresolved_entry_push_register_8616(
                insns,
                raw_arg_sources,
                raw_push_instruction_addrs,
            )
            predecessor_stack_merge = _predecessor_stack_merge_8616(
                function,
                callsite_addr,
                join_register=unresolved_entry_push[0] if unresolved_entry_push is not None else None,
                join_push_addr=unresolved_entry_push[1] if unresolved_entry_push is not None else None,
            )
            if predecessor_stack_merge is not None:
                raw_arg_widths = predecessor_stack_merge.widths + raw_arg_widths
                raw_arg_sources = predecessor_stack_merge.sources + raw_arg_sources
                raw_push_instruction_addrs = (
                    predecessor_stack_merge.representative_instruction_addrs
                    + raw_push_instruction_addrs
                )
        raw_arg_widths, raw_arg_sources, raw_push_instruction_addrs = _filter_callee_saved_frame_pushes_8616(
            function,
            raw_arg_widths,
            raw_arg_sources,
            raw_push_instruction_addrs,
        )
        if (
            isinstance(cleanup, int)
            and cleanup > 0
            and (sum(raw_arg_widths) < cleanup or _push_arg_sources_have_unknown_8616(raw_arg_sources))
        ):
            window_insns = _linear_window_insns_for_callsite_8616(function, callsite_addr)
            window_idx = _find_call_index(window_insns, callsite_addr) if window_insns else None
            if window_idx is not None:
                window_widths = _collect_push_args_before_call(function, window_insns, window_idx, cleanup)
                window_sources = _collect_push_arg_sources_before_call(function, window_insns, window_idx, cleanup)
                window_push_instruction_addrs = _collect_push_arg_instruction_addrs_before_call(
                    function,
                    window_insns,
                    window_idx,
                    cleanup,
                )
                window_has_better_widths = sum(window_widths) > sum(raw_arg_widths)
                window_has_same_widths_better_sources = (
                    sum(window_widths) == sum(raw_arg_widths)
                    and len(window_widths) == len(raw_arg_widths)
                    and _push_arg_source_known_count_8616(window_sources)
                    > _push_arg_source_known_count_8616(raw_arg_sources)
                )
                if window_has_better_widths or window_has_same_widths_better_sources:
                    raw_arg_widths = window_widths
                    raw_arg_sources = window_sources
                    raw_push_instruction_addrs = window_push_instruction_addrs
        arg_widths = _trim_push_args_to_stack_cleanup(raw_arg_widths, cleanup)
        push_arg_sources = _trim_push_arg_sources_to_stack_cleanup(raw_arg_widths, raw_arg_sources, cleanup)
        push_arg_instruction_addrs = _trim_push_arg_instruction_addrs_to_stack_cleanup(
            raw_arg_widths,
            raw_push_instruction_addrs,
            cleanup,
        )
        arg_count = len(arg_widths)
        helper_abi_widths = known_helper_abi_widths_8616(target_name)
        logical_arg_classes: tuple[CallsiteArgumentClass8616, ...] = ()
        if helper_abi_widths is not None:
            logical_arg_widths = helper_abi_widths
            logical_arg_classes = ()
        else:
            logical_arg_widths, logical_arg_classes = _logical_arg_interface_for_target_8616(
                function,
                target_addr,
            )
        if sum(logical_arg_widths) != sum(arg_widths):
            logical_arg_widths = ()
            logical_arg_classes = ()
        follow_insns = list(insns[call_idx + 1 : call_idx + 3])
        if len(follow_insns) < 2:
            follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 2 - len(follow_insns)])
        has_followup_insns = bool(follow_insns)
        return_register, return_used, return_use_kind = _return_use_after_call(function, insns, call_idx, callsite_addr)
        return_shape = _return_shape_after_call(function, insns, call_idx, callsite_addr)
        return_store = _return_store_after_call(function, insns, call_idx, callsite_addr)
        return_store_destination = return_store[:2] if return_store is not None else None
        return_store_width = return_store[2] if return_store is not None else None
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-summary] callsite=%#x call_idx=%s cleanup=%r target_source=%r raw_widths=%r raw_sources=%r widths=%r logical_widths=%r logical_classes=%r sources=%r push_addrs=%r return_register=%r return_used=%r return_shape=%r return_store=%r return_use_kind=%r",
                callsite_addr,
                call_idx,
                cleanup,
                target_source,
                raw_arg_widths,
                raw_arg_sources,
                arg_widths,
                logical_arg_widths,
                logical_arg_classes,
                push_arg_sources,
                push_arg_instruction_addrs,
                return_register,
                return_used,
                return_shape.value if isinstance(return_shape, CallsiteReturnShape8616) else None,
                return_store,
                return_use_kind,
            )
        helper_return_state = "none"
        helper_return_space = None
        helper_return_width = None
        helper_return_address_kind = "none"
        if stack_probe_helper:
            if return_register not in {None, "ax"}:
                helper_return_state = "unknown"
                helper_return_address_kind = "unknown"
            elif return_used is True or not has_followup_insns:
                helper_return_state = "stack_address"
                helper_return_space = "ss"
                helper_return_width = 2
                helper_return_address_kind = "stack"
        return CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=target_addr,
            return_addr=return_addr,
            kind=kind,
            arg_count=arg_count,
            arg_widths=arg_widths,
            stack_cleanup=cleanup,
            return_register=return_register,
            return_used=return_used,
            stack_probe_helper=stack_probe_helper,
            stack_probe_allocation_size=stack_probe_allocation_size,
            helper_return_state=helper_return_state,
            helper_return_space=helper_return_space,
            helper_return_width=helper_return_width,
            helper_return_address_kind=helper_return_address_kind,
            return_shape=return_shape.value if isinstance(return_shape, CallsiteReturnShape8616) else None,
            push_arg_sources=push_arg_sources,
            push_arg_instruction_addrs=push_arg_instruction_addrs,
            return_store_destination=return_store_destination,
            return_store_width=return_store_width,
            target_source=target_source,
            return_use_kind=return_use_kind,
            logical_arg_widths=logical_arg_widths,
            logical_arg_classes=logical_arg_classes,
            stack_cleanup_instruction_addr=cleanup_instruction_addr,
            predecessor_stack_merge=predecessor_stack_merge,
        )

    return _impl()
