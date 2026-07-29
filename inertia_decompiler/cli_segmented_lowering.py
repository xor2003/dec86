"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

# Layer: CLI compatibility shim
# Responsibility: import lowering-owned segment/object lowering helpers.
# Forbidden: owning segment/object lowering semantics here.
from angr_platforms.X86_16.lowering.object_lowering import (
    _match_segment_register_based_dereference,
    _match_ss_stack_reference,
    _strip_segment_scale_from_addr_expr,
)

__all__ = [
    "_match_segment_register_based_dereference",
    "_strip_segment_scale_from_addr_expr",
    "_match_ss_stack_reference",
]
