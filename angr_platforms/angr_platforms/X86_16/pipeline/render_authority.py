"""Typed contract for selecting the authoritative generated-C render source.

Layer: Pipeline governance.
Responsibility: Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here. This module only identifies which already-installed codegen surface
owns final rendering.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["CodegenRenderAuthority8616"]


class CodegenRenderAuthority8616(Enum):
    """Authoritative source for rendering a third-party angr codegen object."""

    CFUNCTION_AST = "cfunction_ast"
    PROVEN_FULL_FUNCTION_OVERRIDE = "proven_full_function_override"
