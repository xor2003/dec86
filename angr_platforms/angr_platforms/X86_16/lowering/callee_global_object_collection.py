"""Collect aggregate-pointee callee evidence from binary project state.

Layer: Types/Lowering.
Responsibility: join binary pointer-argument and all-caller callsite censuses
with Widening-owned global object layouts for one callee address.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os

from ..widening.global_object_layout import GlobalObjectLayoutEvidence8616
from .callee_argument_count_evidence import collect_callee_argument_count_evidence_8616
from .callee_global_object_evidence import (
    CalleeGlobalObjectInterfaceEvidence8616,
    recover_callee_global_object_interface_evidence_8616,
)
from .callee_pointer_evidence import callee_pointer_argument_indices_at_address_8616

_LOGGER = logging.getLogger(__name__)


def collect_callee_global_object_interface_evidence_8616(
    project: object,
    target_addr: int,
    layout_evidence: GlobalObjectLayoutEvidence8616,
) -> CalleeGlobalObjectInterfaceEvidence8616:
    """Collect one complete aggregate-pointee interface census."""
    pointer_indices = callee_pointer_argument_indices_at_address_8616(
        project,
        target_addr,
    )
    if not pointer_indices:
        return recover_callee_global_object_interface_evidence_8616(
            target_addr,
            (),
            layout_evidence,
            (),
        )
    count_evidence = collect_callee_argument_count_evidence_8616(
        project,
        target_addr,
    )
    evidence = recover_callee_global_object_interface_evidence_8616(
        target_addr,
        count_evidence.callsite_summaries,
        layout_evidence,
        pointer_indices,
    )
    if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
        _LOGGER.warning(
            "callee global object collection target=%#x pointers=%s verdict=%s "
            "summaries=%s evidence=%s",
            target_addr,
            pointer_indices,
            count_evidence.verdict,
            tuple(
                (summary.callsite_addr, summary.push_arg_sources)
                for summary in count_evidence.callsite_summaries
            ),
            evidence,
        )
    return evidence


__all__ = ["collect_callee_global_object_interface_evidence_8616"]
