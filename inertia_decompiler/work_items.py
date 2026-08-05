"""Define queued decompilation work items and per-item reporting state.

Layer: CLI/fallback/reporting.
Responsibility: carry decompiler work-item status and reporting snapshots without owning semantic recovery.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr_platforms.X86_16.segment_program_layout_contract import SegmentProgramFunctionEvidence8616

from inertia_decompiler.tail_validation import (
    emit_tail_validation_console_summary,
    tail_validation_display_status,
    tail_validation_runtime_enabled,
    tail_validation_snapshot_for_fallback,
)


class WorkItemStatus(StrEnum):
    """Typed status for a single decompiler work item."""

    OK = "ok"
    ERROR = "error"
    VALIDATION_FAILED = "validation_failed"
    UNKNOWN = "unknown"
    UNCOLLECTED = "uncollected"
    TIMEOUT = "timeout"
    EMPTY = "empty"


class TailValidationDisplayOutcome(StrEnum):
    """Typed display status normalized from tail-validation snapshots."""

    PASSED = "passed"
    FAILED = "failed"
    CHANGED = "changed"
    STABLE = "stable"
    UNKNOWN = "unknown"
    UNCOLLECTED = "uncollected"


def _normalize_tail_validation_status(raw_status: str | None) -> TailValidationDisplayOutcome:
    if raw_status == "" or raw_status is None:
        return TailValidationDisplayOutcome.UNCOLLECTED
    try:
        return TailValidationDisplayOutcome(raw_status)
    except ValueError:
        return TailValidationDisplayOutcome.UNCOLLECTED


def _tail_validation_to_item_status(
    raw_status: str | None,
) -> WorkItemStatus:
    status = _normalize_tail_validation_status(raw_status)
    if status in (
        TailValidationDisplayOutcome.FAILED,
        TailValidationDisplayOutcome.CHANGED,
    ):
        return WorkItemStatus.VALIDATION_FAILED
    if status in (
        TailValidationDisplayOutcome.PASSED,
        TailValidationDisplayOutcome.STABLE,
    ):
        return WorkItemStatus.OK
    if status in (TailValidationDisplayOutcome.UNKNOWN, TailValidationDisplayOutcome.UNCOLLECTED):
        return WorkItemStatus(status.value)
    return WorkItemStatus.UNCOLLECTED


def _work_item_status_display(result: "WorkItemStatus | str") -> WorkItemStatus:
    if isinstance(result, WorkItemStatus):
        return result
    try:
        return WorkItemStatus(result)
    except (TypeError, ValueError):
        return WorkItemStatus.UNCOLLECTED


def _diagnostic_print(line: str) -> None:
    if "PYTEST_CURRENT_TEST" in os.environ:
        print(line)
        return
    print(f"{time.strftime('[%H:%M:%S]')} {line}", file=sys.stderr)


def _visible_source_format(source_format: str | None) -> str:
    raw = source_format or ""
    parts = [part for part in raw.split("+") if part]
    return "+".join(parts) or "sidecars"


@dataclass(frozen=True)
class FunctionDecompileTask:
    """Inputs needed to decompile one discovered function."""

    index: int
    cfg: object
    function: object


@dataclass(frozen=True)
class FunctionDecompileResult:
    """Raw result produced by one function decompilation attempt."""

    index: int
    status: str
    payload: str
    debug_output: str
    elapsed: float


@dataclass(frozen=True)
class FunctionWorkItem:
    """Queue entry used by CLI recovery, decompilation, and fallback reporting.

    ``recovery_addr`` preserves the requested binary/catalog boundary when an
    angr function canonicalizes its active address past padding or a prefix.
    """

    index: int
    function_cfg: object
    function: object
    recovery_addr: int | None = None


@dataclass(frozen=True)
class FunctionWorkResult:
    """Reported result for a function work item."""

    index: int
    status: str
    payload: str
    debug_output: str
    function: object
    function_cfg: object
    partial_payload: str | None = None
    tail_validation: dict[str, object] | None = None
    skip_heavy_fallbacks: bool = False
    elapsed: float | None = None
    from_cache: bool = False
    failure_stage: str | None = None
    block_count: int | None = None
    byte_count: int | None = None
    same_family_retry_stops: int = 0
    fallback_family_labels: tuple[str, ...] = ()
    validated_payload_hash: str | None = None
    gcc_checked_payload_hash: str | None = None
    segment_program_function_evidence: SegmentProgramFunctionEvidence8616 | None = None


def emit_tail_validation_for_function_run_or_uncollected(
    project: object,
    function_cfg: object,
    function: object,
    *,
    allow_project_fallback: bool = True,
    binary_path: Path | None = None,
) -> None:
    """Emit a tail-validation line or an explicit uncollected result for one function."""
    if not tail_validation_runtime_enabled(project):
        return
    snapshot = tail_validation_snapshot_for_fallback(
        project,
        function,
        allow_project_fallback=allow_project_fallback,
    )
    result_status = (
        WorkItemStatus.UNCOLLECTED
        if not snapshot
        else _tail_validation_to_item_status(tail_validation_display_status(snapshot))
    )
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=1,
        status=result_status.value,
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=snapshot,
    )
    emit_tail_validation_console_summary([item], {1: result}, binary_path=binary_path)


def emit_tail_validation_snapshot_or_uncollected(
    function_cfg: object,
    function: object,
    snapshot: Mapping[str, object] | None,
    *,
    binary_path: Path | None = None,
) -> None:
    """Emit an existing tail-validation snapshot or an uncollected placeholder."""
    # Dynamic angr boundary: Function objects expose project through angr-managed attributes.
    project = getattr(function, "project", None)
    if project is not None and not tail_validation_runtime_enabled(project):
        return
    normalized_snapshot = dict(snapshot) if isinstance(snapshot, Mapping) else {}
    result_status = (
        WorkItemStatus.UNCOLLECTED
        if not normalized_snapshot
        else _tail_validation_to_item_status(tail_validation_display_status(normalized_snapshot))
    )
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=1,
        status=result_status.value,
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=normalized_snapshot,
    )
    emit_tail_validation_console_summary([item], {1: result}, binary_path=binary_path)


def function_attempt_display_status(result: FunctionWorkResult) -> str:
    """Return the compact display status for one work result."""
    result_status = _work_item_status_display(result.status)
    if result_status == WorkItemStatus.OK:
        return "decompiled"
    if result_status == WorkItemStatus.TIMEOUT:
        return "timed_out"
    if result_status == WorkItemStatus.EMPTY:
        return "empty"
    if result.partial_payload:
        return "fallback"
    return result_status.value


def print_function_attempt_status(
    function: object,
    *,
    attempt: str,
    validation_snapshot: Mapping[str, object] | None,
) -> None:
    """Print one diagnostic line for a function attempt."""
    # Dynamic angr boundary: Function exposes project/addr/name through angr-managed attributes.
    project = getattr(function, "project", None)
    validation_status = (
        TailValidationDisplayOutcome.UNCOLLECTED.value
        if project is not None and not tail_validation_runtime_enabled(project)
        else tail_validation_display_status(validation_snapshot)
    )
    # Dynamic angr boundary: Function exposes addr/name through angr-managed attributes.
    function_addr = getattr(function, "addr", 0)
    # Dynamic angr boundary: Function exposes addr/name through angr-managed attributes.
    function_name = getattr(function, "name", "sub")
    _diagnostic_print(
        f"/* info: function {function_addr:#x} {function_name} "
        f"attempt={attempt} validation={validation_status} */"
    )


def recovery_evidence_line(binary_path: Path, metadata: object) -> str:
    """Return the CLI evidence banner for sidecar/debug metadata availability."""
    if metadata is None:
        return "/* info: recovery evidence: pure binary recovery mode (no helper metadata/debug info found) */"
    # Dynamic sidecar compatibility boundary: callers may pass legacy metadata carriers.
    source_format = _visible_source_format(getattr(metadata, "source_format", None))
    source_parts = tuple(part for part in source_format.split("+") if part)
    debug_markers = ("codeview", "turbo_debug", "tdinfo", "debug")
    has_debug_info = any(any(marker in part for marker in debug_markers) for part in source_parts)
    if has_debug_info:
        return f"/* info: recovery evidence: sidecar/debug-assisted recovery ({source_format}) */"
    return f"/* info: recovery evidence: sidecar-assisted recovery ({source_format}) */"
