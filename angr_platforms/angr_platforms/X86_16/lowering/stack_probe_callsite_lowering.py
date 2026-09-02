"""Order exact CALL-frame consumption before fixed stack-probe removal.

Layer: Types/Lowering.
Responsibility: coordinate existing typed consumers so a fixed stack-probe call
cannot disappear before its source-invisible machine return frame is consumed.
This module does not infer CALL effects, classify helper names, or inspect
source, COD, assembly text, or rendered C.
"""

from __future__ import annotations

from ..callsite_summary import callsite_summary_inventory_8616
from .fixed_stack_probe_frames import lower_fixed_stack_probe_frames_8616
from .real_mode_linear import prune_call_return_frame_stack_assignments_8616

__all__ = ["lower_fixed_stack_probe_callsite_artifacts_8616"]


def lower_fixed_stack_probe_callsite_artifacts_8616(
    project: object,
    codegen: object,
    *,
    function: object | None = None,
) -> bool:
    """Consume exact probe CALL-frame projections before removing probe calls."""
    inventory = callsite_summary_inventory_8616(codegen)
    return_addresses = {
        summary.callsite_addr: summary.return_addr
        for summary in inventory.values()
        if summary.stack_probe_helper and isinstance(summary.return_addr, int)
    }
    frame_changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        return_addresses,
        function=function,
    )
    probe_changed = lower_fixed_stack_probe_frames_8616(codegen).changed
    return frame_changed or probe_changed
