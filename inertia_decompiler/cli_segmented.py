"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

# Layer: CLI compatibility shim
# Responsibility: import lowering-owned segmented helpers for legacy CLI callsites.
# Forbidden: owning segmented/object lowering semantics here.
from angr_platforms.X86_16.lowering.segmented_lowering import (
    _classify_segmented_addr_expr,
    _classify_segmented_dereference,
    _match_real_mode_linear_expr,
    _match_segmented_dereference,
    _segment_reg_name,
)

__all__ = [
    "_classify_segmented_addr_expr",
    "_classify_segmented_dereference",
    "_match_real_mode_linear_expr",
    "_match_segmented_dereference",
    "_segment_reg_name",
]
