from __future__ import annotations

# Layer: CLI compatibility shim
# Responsibility: Re-export typed stack-lowering helpers for legacy CLI callsites.
# Forbidden: Owning stack-slot identity or stack alias semantics in this module.
from angr_platforms.X86_16.lowering.stack_lowering import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
)

__all__ = [
    "_resolve_stack_cvar_at_offset",
    "_materialize_stack_cvar_at_offset",
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_resolve_stack_cvar_from_addr_expr",
]
