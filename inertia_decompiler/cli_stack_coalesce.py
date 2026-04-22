from __future__ import annotations

# CLI cleanup shim: stack word coalesce semantics moved to widening layer.
from angr_platforms.X86_16.widening.widening_rules import _coalesce_direct_ss_local_word_statements

__all__ = ["_coalesce_direct_ss_local_word_statements"]
