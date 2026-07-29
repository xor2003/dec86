"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

# CLI cleanup shim: stack word coalesce semantics moved to widening layer.
from angr_platforms.X86_16.widening.widening_rules import _coalesce_direct_ss_local_word_statements

__all__ = ["_coalesce_direct_ss_local_word_statements"]
