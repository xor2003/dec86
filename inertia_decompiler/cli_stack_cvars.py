from __future__ import annotations

# Layer: CLI compatibility shim
# Responsibility: Re-export typed stack-lowering helpers for legacy CLI callsites.
# Forbidden:
# - do not implement stack-slot identity here
# - do not add alias or pointer-carrier recovery here
# - do not patch final-C symptoms here
# If emitted C still shows raw SS/BP carrier math or unresolved stack locals,
# fix the real owner in angr_platforms.X86_16.lowering.* or cli_stack_byte_offsets.py.
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
