"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

# Layer: CLI compatibility shim
# Responsibility: import lowering-owned access-object hint helpers.
# Forbidden: owning object-hint semantics here.
from angr_platforms.X86_16.lowering.object_lowering import (
    AccessTraitObjectHint,
    BaseKey,
    _build_stable_access_object_hints,
    _has_stable_access_object_hints,
    _stable_access_object_hint_for_key,
)

__all__ = [
    "AccessTraitObjectHint",
    "BaseKey",
    "_build_stable_access_object_hints",
    "_has_stable_access_object_hints",
    "_stable_access_object_hint_for_key",
]
