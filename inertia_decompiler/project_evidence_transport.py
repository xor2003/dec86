"""Transport typed evidence across CLI-created project boundaries.

Layer: CLI/fallback/reporting.
Responsibility: copy already-derived typed evidence into retry and slice projects
without reclassifying, rebasing, or inferring decompiler semantics.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr_platforms.X86_16.callsite_summary import (
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.compiler_helpers import transfer_x86_16_compiler_helper_evidence_8616

__all__ = [
    "ProjectEvidenceTransferResult8616",
    "transfer_caller_return_use_evidence_8616",
    "transfer_project_evidence_8616",
]


@dataclass(frozen=True, slots=True)
class ProjectEvidenceTransferResult8616:
    """Counts of typed evidence copied across one CLI project boundary."""

    caller_return_use_count: int
    compiler_helper_target_count: int


def transfer_caller_return_use_evidence_8616(
    source_project: object,
    destination_project: object,
) -> int:
    """Copy typed caller-use facts across one CLI project boundary."""
    evidence_by_addr = caller_return_use_evidence_by_addr_8616(source_project)
    if source_project is destination_project:
        return len(evidence_by_addr)
    for function_addr, evidence in evidence_by_addr.items():
        record_caller_return_use_evidence_8616(destination_project, function_addr, evidence)
    return len(evidence_by_addr)


def transfer_project_evidence_8616(
    source_project: object,
    destination_project: object,
) -> ProjectEvidenceTransferResult8616:
    """Copy all typed evidence required by fresh and sliced CLI projects."""
    return ProjectEvidenceTransferResult8616(
        caller_return_use_count=transfer_caller_return_use_evidence_8616(
            source_project,
            destination_project,
        ),
        compiler_helper_target_count=transfer_x86_16_compiler_helper_evidence_8616(
            source_project,
            destination_project,
        ),
    )
