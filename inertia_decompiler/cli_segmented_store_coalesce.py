from __future__ import annotations

# CLI cleanup shim: segmented store coalesce semantics moved to widening layer.
from angr_platforms.X86_16.widening.widening_rules import (
    _coalesce_segmented_word_store_statements,
    run_typed_widening_pass_8616,
)

__all__ = ["_coalesce_segmented_word_store_statements", "run_typed_widening_pass_8616"]
