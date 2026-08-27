"""Layer: Frontend/runtime.

Responsibility: install runtime compatibility patches needed before x86-16 decompilation.
Forbidden: recovering alias, type, or validation semantics through compatibility hooks.
"""

from __future__ import annotations

from typing import Any, cast

from angr.knowledge_plugins.functions.function import Function, PrototypeSource

from .patch_dirty import apply_patch as _apply_dirty_patch
from .stack_compat import apply_x86_16_stack_compatibility as _apply_stack_compatibility
from .typehoon_compat import apply_x86_16_typehoon_compatibility as _apply_typehoon_compatibility

__all__ = ["apply_x86_16_compatibility"]


def _apply_function_prototype_source_compatibility() -> None:
    """Restore the writable guessed-prototype view over angr's source enum."""
    guessed_property = Function.is_prototype_guessed
    if guessed_property.fset is not None:
        return

    def _set_is_prototype_guessed(function: Function, guessed: bool) -> None:
        """Translate the legacy boolean assignment into typed prototype provenance."""
        if guessed:
            function.prototype_source = PrototypeSource.GUESSED
        elif function.prototype_source in {
            PrototypeSource.NONE,
            PrototypeSource.GUESSED,
            PrototypeSource.CCA_LOW,
        }:
            function.prototype_source = PrototypeSource.USER

    function_type = cast(Any, Function)
    function_type.is_prototype_guessed = property(
        guessed_property.fget,
        _set_is_prototype_guessed,
        guessed_property.fdel,
        guessed_property.__doc__,
    )


def apply_x86_16_compatibility() -> None:
    """Install all frontend/runtime compatibility patches for x86-16 support."""
    _apply_function_prototype_source_compatibility()
    _apply_stack_compatibility()
    _apply_typehoon_compatibility()
    _apply_dirty_patch()
