"""Validate that typed required callsites survive structured C materialization.

Layer: Tail validation.
Responsibility: compare typed callsite summary identity with final C call nodes
and report missing required calls as absolute semantic failures.
Forbidden: semantic recovery, source/COD/assembly/rendered-C inspection, AST
mutation, or treating validation findings as repair instructions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, Sequence, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.sim_type import (
    SimType,
    SimTypeArray,
    SimTypeBottom,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypePointer,
)
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from .c_ast_utils import _iter_c_nodes_deep_8616
from .call_target_identity import normalize_x86_16_call_target_addr_8616
from .callsite_summary import (
    CallerReturnUseEvidence8616,
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
    caller_return_use_evidence_by_addr_8616,
    callsite_target_name_for_project_8616,
)
from .helper_abi import (
    known_helper_is_variadic_8616,
    known_helper_logical_argument_widths_8616,
)
from .lowering.call_argument_shape import accounted_target_prototype_shape_evidence_8616
from .lowering.near_pointer_argument import NearPointerArgumentFact8616
from .lowering.return_type_evidence import (
    FunctionReturnClass8616,
    proven_function_return_class_8616,
)
from .lowering.stack_prototype_materialization import FunctionParameterWidthFact8616
from .validation_call_argument_sources import (
    CallArgumentSourceDependencyFact8616,
    CallArgumentSourceIssue8616,
    CallArgumentSourceIssueKind8616,
    call_argument_source_dependency_facts_8616,
    call_argument_source_stack_dependencies_8616,
)

__all__ = [
    "CallArgumentClassIssue8616",
    "CallArgumentClassIssueKind8616",
    "CallArgumentClassValidationReport8616",
    "CallArgumentSourceIssue8616",
    "CallArgumentSourceIssueKind8616",
    "CallInterfaceIssue8616",
    "CallInterfaceIssueKind8616",
    "CallInterfaceValidationReport8616",
    "FunctionReturnClassIssue8616",
    "FunctionReturnClassIssueKind8616",
    "FunctionReturnClassValidationReport8616",
    "FunctionParameterIssue8616",
    "FunctionParameterIssueKind8616",
    "FunctionParameterValidationReport8616",
    "RequiredCallsiteValidationReport8616",
    "validate_call_argument_classes_8616",
    "validate_call_interfaces_8616",
    "validate_function_return_class_8616",
    "validate_function_parameters_8616",
    "validate_required_callsites_8616",
]


class _CodegenCallsiteSurface8616(Protocol):
    """Dynamic angr codegen metadata consumed by callsite validation."""

    _inertia_callsite_summaries: object


class _CodegenProjectSurface8616(Protocol):
    """Dynamic angr codegen project used to normalize exact-slice addresses."""

    project: object


class _AddressedCalleeSurface8616(Protocol):
    """Minimal third-party callee identity used for exact target matching."""

    addr: object


class _PrototypedCalleeSurface8616(Protocol):
    """Third-party callee prototype used to validate logical argument widths."""

    prototype: object


class _TypedCExpressionSurface8616(Protocol):
    """Third-party structured-C expression type surface."""

    type: object


class _CodegenFunctionSurface8616(Protocol):
    """Third-party codegen field containing the emitted C function."""

    cfunc: object


class _CFunctionReturnSurface8616(Protocol):
    """Third-party C function fields that control the emitted declaration."""

    addr: object
    functy: object


class _CodegenFunctionParameterEvidenceSurface8616(Protocol):
    """Owned Lowering facts retained on the third-party codegen object."""

    _inertia_function_parameter_width_facts_8616: object
    _inertia_near_pointer_argument_facts_8616: object


class _CFunctionParameterSurface8616(Protocol):
    """Third-party C function fields that emit parameter declarations."""

    addr: object
    arg_list: object
    functy: object


class _CVariableStorageSurface8616(Protocol):
    """Third-party C variable storage identity used to match BP parameters."""

    variable: object


class _ProjectArchSurface8616(Protocol):
    """Third-party project architecture used for ABI pointer width."""

    arch: Arch


class _ArchBytesSurface8616(Protocol):
    """Third-party architecture ABI byte width."""

    bytes: int


class _SizedTypeSurface8616(Protocol):
    """Third-party SimType bit width."""

    size: int


class CallInterfaceIssueKind8616(StrEnum):
    """Typed final-call interface failures."""

    ARGUMENT_COUNT_MISMATCH = "argument-count-mismatch"
    ARGUMENT_SURFACE_UNAVAILABLE = "argument-surface-unavailable"


class CallArgumentClassIssueKind8616(StrEnum):
    """Typed final-call argument-class failures."""

    CLASS_MISMATCH = "class-mismatch"
    TYPE_SURFACE_UNAVAILABLE = "type-surface-unavailable"


class FunctionReturnClassIssueKind8616(StrEnum):
    """Typed final-function return-class failures."""

    CLASS_MISMATCH = "class-mismatch"
    TYPE_SURFACE_UNAVAILABLE = "type-surface-unavailable"


class FunctionParameterIssueKind8616(StrEnum):
    """Typed final-function parameter interface failures."""

    WIDTH_EVIDENCE_CONFLICT = "width-evidence-conflict"
    WIDTH_MISMATCH = "width-mismatch"
    CLASS_MISMATCH = "class-mismatch"
    TYPE_SURFACE_UNAVAILABLE = "type-surface-unavailable"


@dataclass(frozen=True, slots=True)
class FunctionParameterIssue8616:
    """One contradiction between Lowering parameter facts and final C types."""

    kind: FunctionParameterIssueKind8616
    function_addr: int
    stack_offset: int
    expected_width_bytes: int | None = None
    actual_width_bytes: int | None = None
    expected_class: CallsiteArgumentClass8616 | None = None
    actual_class: CallsiteArgumentClass8616 | None = None

    def token(self) -> str:
        """Return a deterministic failure token for tail-validation reports."""
        prefix = (
            f"function-parameter:{self.kind}:function={self.function_addr:#x}:"
            f"bp={self.stack_offset:+#x}"
        )
        if self.kind is FunctionParameterIssueKind8616.WIDTH_EVIDENCE_CONFLICT:
            return prefix
        if self.expected_width_bytes is not None:
            actual_width = (
                "unknown"
                if self.actual_width_bytes is None
                else str(self.actual_width_bytes)
            )
            return (
                f"{prefix}:expected-width={self.expected_width_bytes}:"
                f"actual-width={actual_width}"
            )
        expected_class = (
            "unknown" if self.expected_class is None else str(self.expected_class)
        )
        actual_class = (
            "unknown" if self.actual_class is None else str(self.actual_class)
        )
        return (
            f"{prefix}:expected-class={expected_class}:"
            f"actual-class={actual_class}"
        )


@dataclass(frozen=True, slots=True)
class FunctionParameterValidationReport8616:
    """Closed evidence-loop counters for final parameter widths and classes."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[FunctionParameterIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every classified parameter fact reached final C."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for canonical tail snapshots."""
        return tuple(issue.token() for issue in self.issues)


@dataclass(frozen=True, order=True, slots=True)
class FunctionReturnClassIssue8616:
    """One mismatch between binary return evidence and the emitted declaration."""

    kind: FunctionReturnClassIssueKind8616
    function_addr: int
    expected_class: FunctionReturnClass8616
    actual_class: FunctionReturnClass8616 | None

    def token(self) -> str:
        """Return a deterministic failure token for tail-validation reports."""
        actual = "unknown" if self.actual_class is None else str(self.actual_class)
        return (
            f"function-return-class:{self.kind}:function={self.function_addr:#x}:"
            f"expected={self.expected_class}:actual={actual}"
        )


@dataclass(frozen=True, slots=True)
class FunctionReturnClassValidationReport8616:
    """Closed evidence-loop counters for the final function return class."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[FunctionReturnClassIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether each proven class matches the emitted declaration."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for canonical tail snapshots."""
        return tuple(issue.token() for issue in self.issues)


@dataclass(frozen=True, order=True, slots=True)
class CallArgumentClassIssue8616:
    """One pointer/value mismatch at a binary-proven logical argument."""

    kind: CallArgumentClassIssueKind8616
    callsite_addr: int
    target_addr: int
    argument_index: int
    expected_class: CallsiteArgumentClass8616
    actual_class: CallsiteArgumentClass8616 | None

    def token(self) -> str:
        """Return a deterministic failure token for tail-validation reports."""
        actual = "unknown" if self.actual_class is None else str(self.actual_class)
        return (
            f"call-argument-class:{self.kind}:callsite={self.callsite_addr:#x}:"
            f"target={self.target_addr:#x}:arg={self.argument_index}:"
            f"expected={self.expected_class}:actual={actual}"
        )


@dataclass(frozen=True, slots=True)
class CallArgumentClassValidationReport8616:
    """Closed evidence counters for final argument classes and dependencies."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[CallArgumentClassIssue8616 | CallArgumentSourceIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every classified argument has its proven class."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for canonical tail snapshots."""
        return tuple(issue.token() for issue in self.issues)


@dataclass(frozen=True, order=True, slots=True)
class CallInterfaceIssue8616:
    """One mismatch between binary callsite evidence and a final C call."""

    kind: CallInterfaceIssueKind8616
    callsite_addr: int
    target_addr: int
    expected_argument_count: int
    actual_argument_count: int | None

    def token(self) -> str:
        """Return a deterministic failure token for tail-validation reports."""
        actual = "unknown" if self.actual_argument_count is None else str(self.actual_argument_count)
        return (
            f"call-interface:{self.kind}:callsite={self.callsite_addr:#x}:"
            f"target={self.target_addr:#x}:expected-argc={self.expected_argument_count}:"
            f"actual-argc={actual}"
        )


@dataclass(frozen=True, slots=True)
class CallInterfaceValidationReport8616:
    """Closed evidence-loop counters for final direct-call interfaces."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[CallInterfaceIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every classified final call has the proven arity."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for canonical tail snapshots."""
        return tuple(issue.token() for issue in self.issues)


@dataclass(frozen=True, slots=True)
class RequiredCallsiteValidationReport8616:
    """Closed evidence-loop counters and failures for required calls."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    missing_calls: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Return whether every classified required call was materialized."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count


@dataclass(frozen=True, slots=True)
class _RequiredCallMatch8616:
    """One canonical required summary and its surviving final call, if any."""

    summary_key: int
    summary: CallsiteSummary8616
    call: CFunctionCall | None


def _final_function_return_surface_8616(
    codegen: object,
) -> tuple[int | None, object]:
    """Read the address and function type that angr emits in the C header."""
    try:
        cfunc = cast(_CodegenFunctionSurface8616, codegen).cfunc
        function_surface = cast(_CFunctionReturnSurface8616, cfunc)
        function_addr = function_surface.addr
        function_type = function_surface.functy
    except AttributeError:
        return None, None
    return (function_addr if isinstance(function_addr, int) else None), function_type


def _materialized_return_class_8616(
    function_type: object,
) -> FunctionReturnClass8616 | None:
    """Classify the return type used by the final structured-C declaration."""
    if not isinstance(function_type, SimTypeFunction):
        return None
    return_type = function_type.returnty
    if isinstance(return_type, SimTypeBottom):
        return (
            FunctionReturnClass8616.VOID
            if return_type.label == "void"
            else None
        )
    if isinstance(return_type, SimType):
        return FunctionReturnClass8616.VALUE
    return None


def _parameter_evidence_8616(
    codegen: object,
) -> tuple[
    tuple[FunctionParameterWidthFact8616, ...],
    tuple[NearPointerArgumentFact8616, ...],
    int,
]:
    """Read typed Lowering parameter facts from the codegen boundary."""
    evidence_surface = cast(_CodegenFunctionParameterEvidenceSurface8616, codegen)
    try:
        raw_width_facts = evidence_surface._inertia_function_parameter_width_facts_8616
    except AttributeError:
        raw_width_facts = ()
    try:
        raw_pointer_facts = evidence_surface._inertia_near_pointer_argument_facts_8616
    except AttributeError:
        raw_pointer_facts = ()
    width_values = (
        tuple(raw_width_facts)
        if isinstance(raw_width_facts, Sequence)
        and not isinstance(raw_width_facts, (str, bytes))
        else ()
    )
    pointer_values = (
        tuple(raw_pointer_facts)
        if isinstance(raw_pointer_facts, Sequence)
        and not isinstance(raw_pointer_facts, (str, bytes))
        else ()
    )
    return (
        tuple(
            fact
            for fact in width_values
            if isinstance(fact, FunctionParameterWidthFact8616)
        ),
        tuple(
            fact
            for fact in pointer_values
            if isinstance(fact, NearPointerArgumentFact8616)
        ),
        len(width_values) + len(pointer_values),
    )


def _final_function_parameters_8616(
    codegen: object,
) -> tuple[int | None, dict[int, SimType] | None]:
    """Map final emitted parameter types by exact positive BP offset."""
    try:
        cfunc = cast(_CodegenFunctionSurface8616, codegen).cfunc
        surface = cast(_CFunctionParameterSurface8616, cfunc)
        function_addr = surface.addr
        function_type = surface.functy
        raw_arg_list = surface.arg_list
    except AttributeError:
        return None, None
    normalized_addr = function_addr if isinstance(function_addr, int) else None
    if (
        not isinstance(function_type, SimTypeFunction)
        or not isinstance(raw_arg_list, Sequence)
        or isinstance(raw_arg_list, (str, bytes))
    ):
        return normalized_addr, None
    arg_types = tuple(function_type.args or ())
    arg_list = tuple(raw_arg_list)
    if len(arg_types) != len(arg_list):
        return normalized_addr, None
    by_offset: dict[int, SimType] = {}
    for cvar, arg_type in zip(arg_list, arg_types):
        try:
            variable = cast(_CVariableStorageSurface8616, cvar).variable
        except AttributeError:
            return normalized_addr, None
        if (
            not isinstance(variable, SimStackVariable)
            or not isinstance(variable.offset, int)
            or variable.offset < 4
            or not isinstance(arg_type, SimType)
            or variable.offset in by_offset
        ):
            return normalized_addr, None
        by_offset[variable.offset] = arg_type
    return normalized_addr, by_offset


def _parameter_type_width_bytes_8616(
    project: object,
    parameter_type: SimType,
) -> int | None:
    """Return the ABI width of one emitted C parameter type."""
    if isinstance(
        parameter_type,
        (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray),
    ):
        try:
            width_bytes = cast(
                _ArchBytesSurface8616,
                cast(_ProjectArchSurface8616, project).arch,
            ).bytes
        except AttributeError:
            return None
        return width_bytes if isinstance(width_bytes, int) and width_bytes > 0 else None
    else:
        try:
            bits = cast(_SizedTypeSurface8616, parameter_type).size
        except (AttributeError, ValueError):
            return None
    if not isinstance(bits, int) or bits <= 0:
        return None
    return max(1, (bits + 7) // 8)


def _parameter_type_class_8616(
    parameter_type: SimType,
) -> CallsiteArgumentClass8616 | None:
    """Classify one emitted parameter without inferring from its width."""
    if isinstance(
        parameter_type,
        (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray),
    ):
        return CallsiteArgumentClass8616.POINTER
    if isinstance(parameter_type, SimTypeBottom):
        return None
    return CallsiteArgumentClass8616.VALUE


def validate_function_parameters_8616(
    project: object,
    codegen: object,
) -> FunctionParameterValidationReport8616:
    """Refuse final parameter widths/classes that contradict Lowering facts."""
    width_facts, pointer_facts, raw_fact_count = _parameter_evidence_8616(codegen)
    width_pairs = tuple(
        sorted(
            {
                (fact.stack_offset, fact.width_bytes)
                for fact in width_facts
                if fact.stack_offset >= 4 and fact.width_bytes > 0
            }
        )
    )
    pointer_offsets = tuple(
        sorted({fact.stack_offset for fact in pointer_facts if fact.stack_offset >= 4})
    )
    normalized_fact_count = len(width_pairs) + len(pointer_offsets)
    widths_by_offset: dict[int, set[int]] = {}
    for stack_offset, width_bytes in width_pairs:
        widths_by_offset.setdefault(stack_offset, set()).add(width_bytes)
    function_addr, parameter_types = _final_function_parameters_8616(codegen)
    if function_addr is None:
        return FunctionParameterValidationReport8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=normalized_fact_count,
        )
    issues: list[FunctionParameterIssue8616] = []
    classified_count = 0
    materialized_count = 0
    for stack_offset, widths in sorted(widths_by_offset.items()):
        if len(widths) != 1:
            issues.append(
                FunctionParameterIssue8616(
                    kind=FunctionParameterIssueKind8616.WIDTH_EVIDENCE_CONFLICT,
                    function_addr=function_addr,
                    stack_offset=stack_offset,
                )
            )
            continue
        expected_width = next(iter(widths))
        classified_count += 1
        parameter_type = (
            parameter_types.get(stack_offset)
            if parameter_types is not None
            else None
        )
        actual_width = (
            _parameter_type_width_bytes_8616(project, parameter_type)
            if parameter_type is not None
            else None
        )
        if actual_width is None:
            issues.append(
                FunctionParameterIssue8616(
                    kind=FunctionParameterIssueKind8616.TYPE_SURFACE_UNAVAILABLE,
                    function_addr=function_addr,
                    stack_offset=stack_offset,
                    expected_width_bytes=expected_width,
                )
            )
        elif actual_width != expected_width:
            issues.append(
                FunctionParameterIssue8616(
                    kind=FunctionParameterIssueKind8616.WIDTH_MISMATCH,
                    function_addr=function_addr,
                    stack_offset=stack_offset,
                    expected_width_bytes=expected_width,
                    actual_width_bytes=actual_width,
                )
            )
        else:
            materialized_count += 1
    for stack_offset in pointer_offsets:
        classified_count += 1
        parameter_type = (
            parameter_types.get(stack_offset)
            if parameter_types is not None
            else None
        )
        actual_class = (
            _parameter_type_class_8616(parameter_type)
            if parameter_type is not None
            else None
        )
        if actual_class is None:
            issues.append(
                FunctionParameterIssue8616(
                    kind=FunctionParameterIssueKind8616.TYPE_SURFACE_UNAVAILABLE,
                    function_addr=function_addr,
                    stack_offset=stack_offset,
                    expected_class=CallsiteArgumentClass8616.POINTER,
                )
            )
        elif actual_class is not CallsiteArgumentClass8616.POINTER:
            issues.append(
                FunctionParameterIssue8616(
                    kind=FunctionParameterIssueKind8616.CLASS_MISMATCH,
                    function_addr=function_addr,
                    stack_offset=stack_offset,
                    expected_class=CallsiteArgumentClass8616.POINTER,
                    actual_class=actual_class,
                )
            )
        else:
            materialized_count += 1
    return FunctionParameterValidationReport8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=len(issues),
        issues=tuple(issues),
    )


def validate_function_return_class_8616(
    project: object,
    codegen: object,
) -> FunctionReturnClassValidationReport8616:
    """Refuse an emitted return class that contradicts closed binary evidence."""
    function_addr, function_type = _final_function_return_surface_8616(codegen)
    if function_addr is None:
        return FunctionReturnClassValidationReport8616()
    evidence = caller_return_use_evidence_by_addr_8616(project).get(function_addr)
    if not isinstance(evidence, CallerReturnUseEvidence8616):
        return FunctionReturnClassValidationReport8616()
    expected_class = proven_function_return_class_8616(project, function_addr)
    if expected_class is None:
        return FunctionReturnClassValidationReport8616(
            raw_fact_count=1,
            normalized_fact_count=1,
        )
    actual_class = _materialized_return_class_8616(function_type)
    if actual_class is expected_class:
        return FunctionReturnClassValidationReport8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        )
    issue = FunctionReturnClassIssue8616(
        kind=(
            FunctionReturnClassIssueKind8616.TYPE_SURFACE_UNAVAILABLE
            if actual_class is None
            else FunctionReturnClassIssueKind8616.CLASS_MISMATCH
        ),
        function_addr=function_addr,
        expected_class=expected_class,
        actual_class=actual_class,
    )
    return FunctionReturnClassValidationReport8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
        issues=(issue,),
    )


def _callsite_addr_8616(node: CFunctionCall) -> int | None:
    """Return an exact instruction address from structured node tags."""
    tags = node.tags
    if not isinstance(tags, Mapping):
        return None
    for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
        value = tags.get(key)
        if isinstance(value, int):
            return value
    return None


def _callee_addr_8616(node: CFunctionCall) -> int | None:
    """Return the exact callee function address when angr retains it."""
    callee = node.callee_func
    if callee is None:
        return None
    try:
        addr = cast(_AddressedCalleeSurface8616, callee).addr
    except AttributeError:
        return None
    return addr if isinstance(addr, int) else None


def _required_summary_token_8616(summary: CallsiteSummary8616) -> str:
    """Render deterministic identity for one missing typed callsite."""
    target = f"{summary.target_addr:#x}" if isinstance(summary.target_addr, int) else "unknown"
    return (
        f"missing-required-call:callsite={summary.callsite_addr:#x}:"
        f"target={target}:argc={summary.arg_count}"
    )


def _canonical_required_summary_items_8616(
    required: tuple[tuple[int, CallsiteSummary8616], ...],
    calls: tuple[CFunctionCall, ...],
) -> tuple[tuple[int, CallsiteSummary8616], ...]:
    """Collapse identical clone metadata while preferring surviving node identity."""
    call_node_ids = {id(call) for call in calls}
    canonical: list[tuple[int, CallsiteSummary8616]] = []
    ordered = sorted(
        required,
        key=lambda item: (
            item[1].callsite_addr,
            item[1].target_addr or -1,
            item[0] not in call_node_ids,
            item[0],
        ),
    )
    for summary_key, summary in ordered:
        duplicate_index = next(
            (
                index
                for index, (_existing_key, existing_summary) in enumerate(canonical)
                if existing_summary == summary
            ),
            None,
        )
        if duplicate_index is None:
            canonical.append((summary_key, summary))
            continue
        existing_key, _existing_summary = canonical[duplicate_index]
        if summary_key in call_node_ids and existing_key not in call_node_ids:
            canonical[duplicate_index] = (summary_key, summary)
    return tuple(canonical)


def _call_matches_summary_identity_8616(
    node: CFunctionCall,
    summary_key: int,
    summary: CallsiteSummary8616,
    project: object,
) -> bool:
    """Accept an object-ID match only with corroborating callsite evidence."""
    if id(node) != summary_key:
        return False
    node_callsite = _callsite_addr_8616(node)
    if node_callsite is not None:
        summary_callsite = summary.callsite_addr
        return isinstance(summary_callsite, int) and node_callsite == summary_callsite
    node_target = _callee_addr_8616(node)
    if node_target is None:
        return False
    summary_target = summary.target_addr
    normalized_node_target: int | None = normalize_x86_16_call_target_addr_8616(
        project,
        node_target,
    )
    normalized_summary_target: int | None = normalize_x86_16_call_target_addr_8616(
        project,
        summary_target if isinstance(summary_target, int) else None,
    )
    return normalized_node_target == normalized_summary_target


def _call_matches_resolved_target_name_8616(
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    project: object,
) -> bool:
    """Match a detached call node only through resolved target name and arity."""
    target_addr = summary.target_addr
    if not isinstance(target_addr, int):
        return False
    target_name: str | None = None
    projects = [project]
    # Dynamic angr project metadata boundary: the original project is optional.
    original_project = getattr(project, "_inertia_original_project", None)
    if original_project is not None and original_project is not project:
        projects.append(original_project)
    for candidate_project in projects:
        try:
            normalized_target = normalize_x86_16_call_target_addr_8616(
                candidate_project,
                target_addr,
            )
            if not isinstance(normalized_target, int):
                continue
            function = cast(Any, candidate_project).kb.functions.function(
                addr=normalized_target,
                create=False,
            )
            candidate_name = cast(Any, function).name
        except (AttributeError, TypeError):
            continue
        if isinstance(candidate_name, str):
            target_name = candidate_name
            break
    if target_name is None:
        target_name = callsite_target_name_for_project_8616(project, target_addr)
    if target_name is None:
        return False
    node_surface = cast(Any, node)
    node_name = node_surface.callee_target
    if not isinstance(node_name, str):
        callee = node_surface.callee_func
        # Dynamic angr C-AST boundary: detached callees expose optional names.
        node_name = getattr(callee, "name", None)
    args = node_surface.args
    return (
        isinstance(target_name, str)
        and isinstance(node_name, str)
        and node_name == target_name
        and isinstance(args, Sequence)
        and not isinstance(args, (str, bytes))
        and len(args) == summary.arg_count
    )


def _required_call_matches_8616(
    codegen: object,
    root: object,
) -> tuple[int, tuple[_RequiredCallMatch8616, ...]]:
    """Match canonical non-probe callsite summaries to surviving C calls."""
    try:
        raw_summaries = cast(_CodegenCallsiteSurface8616, codegen)._inertia_callsite_summaries
    except AttributeError:
        raw_summaries = None
    if not isinstance(raw_summaries, Mapping):
        return 0, ()
    typed_items = tuple(
        (key, summary)
        for key, summary in raw_summaries.items()
        if isinstance(key, int) and isinstance(summary, CallsiteSummary8616)
    )
    required_candidates = tuple(
        (key, summary)
        for key, summary in typed_items
        if not summary.stack_probe_helper and isinstance(summary.target_addr, int)
    )
    calls = tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall))
    try:
        project = cast(_CodegenProjectSurface8616, codegen).project
    except AttributeError:
        project = None
    required = _canonical_required_summary_items_8616(required_candidates, calls)
    available = list(calls)
    matches: list[_RequiredCallMatch8616] = []
    for summary_key, summary in sorted(
        required,
        key=lambda item: (item[1].callsite_addr, item[1].target_addr or -1, item[0]),
    ):
        match_index = next(
            (
                index
                for index, node in enumerate(available)
                if _call_matches_summary_identity_8616(
                    node,
                    summary_key,
                    summary,
                    project,
                )
            ),
            None,
        )
        if match_index is None:
            match_index = next(
                (
                    index
                    for index, node in enumerate(available)
                    if _callsite_addr_8616(node) == summary.callsite_addr
                ),
                None,
            )
        if match_index is None:
            normalized_summary_target = normalize_x86_16_call_target_addr_8616(
                project,
                summary.target_addr,
            )
            match_index = next(
                (
                    index
                    for index, node in enumerate(available)
                    if normalize_x86_16_call_target_addr_8616(
                        project,
                        _callee_addr_8616(node),
                    )
                    == normalized_summary_target
                ),
                None,
            )
        if match_index is None:
            named_matches = [
                index
                for index, node in enumerate(available)
                if _call_matches_resolved_target_name_8616(node, summary, project)
            ]
            if len(named_matches) == 1:
                match_index = named_matches[0]
            if len(named_matches) > 1:
                same_target_callsites = {
                    other_summary.callsite_addr
                    for _other_key, other_summary in required
                    if other_summary.target_addr == summary.target_addr
                }
                untagged_matches = [
                    index
                    for index in named_matches
                    if _callsite_addr_8616(available[index]) is None
                ]
                tagged_matches = {
                    _callsite_addr_8616(available[index])
                    for index in named_matches
                    if _callsite_addr_8616(available[index]) is not None
                }
                if (
                    len(untagged_matches) == 1
                    and summary.callsite_addr not in tagged_matches
                    and tagged_matches <= same_target_callsites
                ):
                    match_index = untagged_matches[0]
        if match_index is None:
            established_names = {
                cast(Any, match.call).callee_target
                for match in matches
                if match.call is not None
                and match.summary.target_addr == summary.target_addr
                and isinstance(cast(Any, match.call).callee_target, str)
            }
            named_matches = [
                index
                for index, node in enumerate(available)
                if cast(Any, node).callee_target in established_names
                and len(tuple(cast(Any, node).args or ())) == summary.arg_count
            ]
            if len(named_matches) == 1:
                match_index = named_matches[0]
        if match_index is None:
            matches.append(_RequiredCallMatch8616(summary_key, summary, None))
            continue
        matches.append(_RequiredCallMatch8616(summary_key, summary, available.pop(match_index)))
    return len(typed_items), tuple(matches)


def validate_required_callsites_8616(
    codegen: object,
    root: object,
) -> RequiredCallsiteValidationReport8616:
    """Match non-probe typed callsite summaries to final structured calls."""
    raw_fact_count, matches = _required_call_matches_8616(codegen, root)
    missing = tuple(
        _required_summary_token_8616(match.summary)
        for match in matches
        if match.call is None
    )
    materialized_count = sum(match.call is not None for match in matches)
    failure_count = len(missing)
    return RequiredCallsiteValidationReport8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=len(matches),
        classified_fact_count=len(matches),
        materialized_count=materialized_count,
        failure_count=failure_count,
        missing_calls=missing,
    )


def _expected_argument_count_8616(summary: CallsiteSummary8616) -> int | None:
    """Return a binary-proven logical argument count for final C validation."""
    logical_widths = summary.logical_arg_widths
    if logical_widths:
        return len(logical_widths)
    # ``arg_count`` and ``arg_widths`` describe physical PUSH operations. One
    # dword or far-pointer C argument may consume two such pushes, so they are
    # not proof of final logical arity.
    return None


def _expected_call_argument_count_8616(
    summary: CallsiteSummary8616,
    call: CFunctionCall,
    project: object | None = None,
) -> int | None:
    """Return typed logical arity before falling back to physical push evidence."""
    callee = call.callee_func
    if callee is None and project is not None and isinstance(summary.target_addr, int):
        try:
            functions = cast(Any, cast(Any, project).kb).functions
            callee = functions.function(addr=summary.target_addr, create=False)
        except (AttributeError, TypeError):
            callee = None
    name = call.callee_target
    if not isinstance(name, str) and callee is not None:
        # Dynamic angr C-AST boundary: callee function names are optional.
        name = getattr(callee, "name", None)
    helper_name = name if isinstance(name, str) else None
    helper_widths = known_helper_logical_argument_widths_8616(helper_name)
    metadata_name: str | None = None
    if helper_widths is None and project is not None and isinstance(summary.target_addr, int):
        metadata_name = callsite_target_name_for_project_8616(project, summary.target_addr)
        helper_widths = known_helper_logical_argument_widths_8616(metadata_name)
    if helper_widths is not None:
        return len(helper_widths)
    if known_helper_is_variadic_8616(helper_name) or known_helper_is_variadic_8616(
        metadata_name
    ):
        return _expected_argument_count_8616(summary)
    logical_argument_count = _expected_argument_count_8616(summary)
    if logical_argument_count is not None:
        return logical_argument_count
    if callee is not None:
        try:
            prototype = cast(Any, callee).prototype
            if isinstance(prototype, SimTypeFunction) and isinstance(prototype.args, Sequence):
                return len(prototype.args)
        except AttributeError:
            pass
    return None


def _materialized_argument_count_8616(call: CFunctionCall) -> int | None:
    """Return the final C argument count at the third-party AST boundary."""
    args = call.args
    if args is None:
        return 0
    if isinstance(args, Sequence) and not isinstance(args, (str, bytes)):
        return len(args)
    return None


def _type_width_bytes_8616(type_surface: object, project: object) -> int | None:
    """Read one structured-C or prototype type width at the angr boundary."""
    if not isinstance(type_surface, SimType):
        return None
    try:
        size_bits = type_surface.size
    except ValueError:
        try:
            arch = cast(_ProjectArchSurface8616, project).arch
            size_bits = type_surface.with_arch(arch).size
        except (AttributeError, ValueError):
            return None
    if not isinstance(size_bits, int) or isinstance(size_bits, bool) or size_bits <= 0:
        return None
    return max(1, (size_bits + 7) // 8)


def _materialized_argument_widths_8616(
    call: CFunctionCall,
    project: object,
) -> tuple[int, ...] | None:
    """Return exact byte widths for every final structured-C argument."""
    arguments = _materialized_arguments_8616(call)
    if arguments is None:
        return None
    widths: list[int] = []
    for argument in arguments:
        try:
            argument_type = cast(_TypedCExpressionSurface8616, argument).type
        except AttributeError:
            return None
        width = _type_width_bytes_8616(argument_type, project)
        if width is None:
            return None
        widths.append(width)
    return tuple(widths)


def _target_prototype_argument_widths_8616(
    call: CFunctionCall,
    project: object,
    target_addr: int | None = None,
) -> tuple[int, ...] | None:
    """Return exact byte widths from the materialized call target prototype."""
    callee = call.callee_func
    if callee is None:
        if isinstance(target_addr, int):
            try:
                functions = cast(Any, cast(Any, project).kb).functions
                callee = functions.function(addr=target_addr, create=False)
            except (AttributeError, TypeError):
                callee = None
    if callee is None:
        return None
    try:
        prototype = cast(_PrototypedCalleeSurface8616, callee).prototype
        prototype_args = cast(SimTypeFunction, prototype).args
    except AttributeError:
        return None
    if not isinstance(prototype_args, Sequence) or isinstance(prototype_args, (str, bytes)):
        return None
    widths: list[int] = []
    for argument_type in prototype_args:
        width = _type_width_bytes_8616(argument_type, project)
        if width is None:
            return None
        widths.append(width)
    return tuple(widths)


def _materialized_arguments_8616(call: CFunctionCall) -> tuple[object, ...] | None:
    """Return final arguments from the third-party structured-C call surface."""
    args = call.args
    if args is None:
        return ()
    if isinstance(args, Sequence) and not isinstance(args, (str, bytes)):
        return tuple(args)
    return None


def _contains_wide_nested_call_8616(call: CFunctionCall, project: object) -> bool:
    """Return whether a final argument contains a typed multiword call result."""
    for argument in _materialized_arguments_8616(call) or ():
        for node in _iter_c_nodes_deep_8616(argument):
            if not isinstance(node, CFunctionCall) or node is call:
                continue
            width = _type_width_bytes_8616(node.type, project)
            if width is not None and width > 2:
                return True
    return False


def _materialized_argument_class_8616(
    argument: object,
) -> CallsiteArgumentClass8616 | None:
    """Classify one final expression from its structured-C type."""
    try:
        argument_type = cast(_TypedCExpressionSurface8616, argument).type
    except AttributeError:
        return None
    if isinstance(argument_type, (SimTypePointer, SimTypeArray)):
        return CallsiteArgumentClass8616.POINTER
    if argument_type is None or isinstance(argument_type, SimTypeBottom):
        return None
    return CallsiteArgumentClass8616.VALUE


def validate_call_argument_classes_8616(
    codegen: object,
    root: object,
) -> CallArgumentClassValidationReport8616:
    """Refuse final arguments that contradict binary classes or dependencies."""
    _raw_summary_count, matches = _required_call_matches_8616(codegen, root)
    proven_matches = tuple(
        match
        for match in matches
        if match.call is not None and match.summary.logical_arg_classes
    )
    raw_class_fact_count = sum(len(match.summary.logical_arg_classes) for match in matches)
    normalized_class_fact_count = sum(len(match.summary.logical_arg_classes) for match in proven_matches)
    classified: list[
        tuple[_RequiredCallMatch8616, int, CallsiteArgumentClass8616, object]
    ] = []
    for match in proven_matches:
        assert match.call is not None
        arguments = _materialized_arguments_8616(match.call)
        expected_classes = match.summary.logical_arg_classes
        if arguments is None or len(arguments) != len(expected_classes):
            continue
        classified.extend(
            (match, index, expected_class, arguments[index])
            for index, expected_class in enumerate(expected_classes)
        )
    source_facts: list[
        tuple[_RequiredCallMatch8616, CallArgumentSourceDependencyFact8616]
    ] = []
    raw_source_fact_count = 0
    normalized_source_fact_count = 0
    for match in matches:
        dependencies = call_argument_source_stack_dependencies_8616(match.summary)
        if dependencies is None:
            continue
        raw_source_fact_count += sum(bool(offsets) for offsets in dependencies)
        if match.call is None:
            continue
        arguments = _materialized_arguments_8616(match.call)
        if arguments is None or len(arguments) != len(dependencies):
            continue
        facts = call_argument_source_dependency_facts_8616(match.summary, arguments)
        normalized_source_fact_count += len(facts)
        source_facts.extend((match, fact) for fact in facts)
    issues: list[CallArgumentClassIssue8616 | CallArgumentSourceIssue8616] = []
    materialized_count = 0
    for match, index, expected_class, argument in classified:
        target_addr = match.summary.target_addr
        if not isinstance(target_addr, int):
            continue
        actual_class = _materialized_argument_class_8616(argument)
        if actual_class is None:
            issues.append(
                CallArgumentClassIssue8616(
                    kind=CallArgumentClassIssueKind8616.TYPE_SURFACE_UNAVAILABLE,
                    callsite_addr=match.summary.callsite_addr,
                    target_addr=target_addr,
                    argument_index=index,
                    expected_class=expected_class,
                    actual_class=None,
                )
            )
            continue
        if actual_class is not expected_class:
            issues.append(
                CallArgumentClassIssue8616(
                    kind=CallArgumentClassIssueKind8616.CLASS_MISMATCH,
                    callsite_addr=match.summary.callsite_addr,
                    target_addr=target_addr,
                    argument_index=index,
                    expected_class=expected_class,
                    actual_class=actual_class,
                )
            )
            continue
        materialized_count += 1
    for match, source_fact in source_facts:
        target_addr = match.summary.target_addr
        if not isinstance(target_addr, int):
            continue
        if source_fact.materialized:
            materialized_count += 1
            continue
        issues.append(
            CallArgumentSourceIssue8616(
                kind=CallArgumentSourceIssueKind8616.STACK_DEPENDENCY_MISMATCH,
                callsite_addr=match.summary.callsite_addr,
                target_addr=target_addr,
                argument_index=source_fact.argument_index,
                expected_stack_offsets=source_fact.expected_stack_offsets,
                actual_stack_offsets=source_fact.actual_stack_offsets,
            )
        )
    return CallArgumentClassValidationReport8616(
        raw_fact_count=raw_class_fact_count + raw_source_fact_count,
        normalized_fact_count=normalized_class_fact_count + normalized_source_fact_count,
        classified_fact_count=len(classified) + len(source_facts),
        materialized_count=materialized_count,
        failure_count=len(issues),
        issues=tuple(issues),
    )


def validate_call_interfaces_8616(
    codegen: object,
    root: object,
) -> CallInterfaceValidationReport8616:
    """Refuse final direct calls whose arity contradicts typed binary facts."""
    raw_fact_count, matches = _required_call_matches_8616(codegen, root)
    matched = tuple(match for match in matches if match.call is not None)
    try:
        project = cast(_CodegenProjectSurface8616, codegen).project
    except AttributeError:
        project = None
    classified: list[tuple[_RequiredCallMatch8616, int]] = []
    for match in matched:
        expected_count = (
            _expected_call_argument_count_8616(match.summary, match.call, project)
            if match.call is not None
            else _expected_argument_count_8616(match.summary)
        )
        if expected_count is not None:
            classified.append((match, expected_count))
    issues: list[CallInterfaceIssue8616] = []
    materialized_count = 0
    for match, expected_count in classified:
        assert match.call is not None
        actual_count = _materialized_argument_count_8616(match.call)
        target_addr = match.summary.target_addr
        if not isinstance(target_addr, int):
            continue
        if actual_count is None:
            issues.append(
                CallInterfaceIssue8616(
                    kind=CallInterfaceIssueKind8616.ARGUMENT_SURFACE_UNAVAILABLE,
                    callsite_addr=match.summary.callsite_addr,
                    target_addr=target_addr,
                    expected_argument_count=expected_count,
                    actual_argument_count=None,
                )
            )
            continue
        if actual_count != expected_count:
            live_widths = _materialized_argument_widths_8616(match.call, project)
            prototype_widths = _target_prototype_argument_widths_8616(
                match.call,
                project,
                target_addr,
            )
            physical_widths = tuple(
                width for width in match.summary.arg_widths if isinstance(width, int) and width > 0
            )
            if (
                live_widths is not None
                and len(live_widths) == actual_count
                and len(physical_widths) == expected_count
                and len(live_widths) < len(physical_widths)
                and sum(live_widths) == sum(physical_widths)
                and (
                    prototype_widths is None
                    or live_widths == prototype_widths
                    or (
                        prototype_widths is None
                        and _contains_wide_nested_call_8616(match.call, project)
                        and expected_count - actual_count == 1
                    )
                )
            ):
                materialized_count += 1
                continue
            if (
                expected_count - actual_count == 1
                and _contains_wide_nested_call_8616(match.call, project)
            ):
                materialized_count += 1
                continue
            grouped_evidence = (
                accounted_target_prototype_shape_evidence_8616(
                    match.summary,
                    live_widths,
                    prototype_widths,
                )
                if live_widths is not None
                else None
            )
            if grouped_evidence is not None and len(grouped_evidence.widths) == actual_count:
                materialized_count += 1
                continue
            issues.append(
                CallInterfaceIssue8616(
                    kind=CallInterfaceIssueKind8616.ARGUMENT_COUNT_MISMATCH,
                    callsite_addr=match.summary.callsite_addr,
                    target_addr=target_addr,
                    expected_argument_count=expected_count,
                    actual_argument_count=actual_count,
                )
            )
            continue
        materialized_count += 1
    return CallInterfaceValidationReport8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=len(matched),
        classified_fact_count=len(classified),
        materialized_count=materialized_count,
        failure_count=len(issues),
        issues=tuple(issues),
    )
