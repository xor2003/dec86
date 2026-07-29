"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

# Layer: CLI compatibility shim
# Responsibility: Re-export widening/store-width helpers for legacy CLI callsites.
# Forbidden: Owning semantic widening logic in this module.
from angr_platforms.X86_16.widening.store_width import (
    _extract_dereference_addr_expr,
    _global_load_addr,
    _global_memory_addr,
    _high_byte_store_addr,
    _make_word_dereference_from_addr_expr,
    _match_byte_load_addr_expr,
    _match_byte_store_addr_expr,
    _match_scaled_high_byte,
    _match_shifted_high_byte_addr_expr,
    _match_word_dereference_addr_expr,
    _match_word_pair_low_addr_expr,
)

__all__ = [
    "_global_memory_addr",
    "_global_load_addr",
    "_match_scaled_high_byte",
    "_extract_dereference_addr_expr",
    "_match_byte_load_addr_expr",
    "_match_byte_store_addr_expr",
    "_match_shifted_high_byte_addr_expr",
    "_match_word_pair_low_addr_expr",
    "_make_word_dereference_from_addr_expr",
    "_match_word_dereference_addr_expr",
    "_high_byte_store_addr",
]
