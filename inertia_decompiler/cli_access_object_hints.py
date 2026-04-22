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
    "BaseKey",
    "AccessTraitObjectHint",
    "_build_stable_access_object_hints",
    "_stable_access_object_hint_for_key",
    "_has_stable_access_object_hints",
]
