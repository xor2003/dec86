"""Verify materialized return chains on the structured C AST.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
This guard compares Structuring-owned return-chain metadata with constant
returns still present in the authoritative angr C AST.

Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This module validates typed AST state only. It must not inspect, parse, or
repair rendered C text; rendering and final emission consume this result.
Dynamic boundary: the guard reads initialized extension fields and structured
C nodes carried by third-party angr codegen objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CReturn

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from ..pipeline.render_authority import install_codegen_render_integrity_guard_8616
from .return_chains import const_return_value_8616

__all__ = [
    "MaterializedReturnChainIntegrity8616",
    "MaterializedReturnChainIntegrityVerdict8616",
    "assess_materialized_return_chain_integrity_8616",
    "install_materialized_return_chain_integrity_guard_8616",
    "require_materialized_return_chain_integrity_8616",
]


class MaterializedReturnChainIntegrityVerdict8616(StrEnum):
    """Typed status for the Structuring-owned return-chain AST contract."""

    NOT_APPLICABLE = "not_applicable"
    PASSED = "passed"
    INCOMPLETE_CODEGEN_BOUNDARY = "incomplete_codegen_boundary"
    MISSING_EXPECTED_VALUES = "missing_expected_values"
    MISSING_AST_ROOT = "missing_ast_root"
    MISSING_RETURN_VALUES = "missing_return_values"


@dataclass(frozen=True, slots=True)
class MaterializedReturnChainIntegrity8616:
    """Comparison between proven return-chain metadata and the live C AST."""

    verdict: MaterializedReturnChainIntegrityVerdict8616
    expected_values: tuple[int, ...] = ()
    observed_values: tuple[int, ...] = ()
    missing_values: tuple[int, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return whether no active materialized return chain was lost."""
        return self.verdict in {
            MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE,
            MaterializedReturnChainIntegrityVerdict8616.PASSED,
        }

    @property
    def active(self) -> bool:
        """Return whether Structuring claims a materialized return chain."""
        return self.verdict is not MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE

    def diagnostic(self) -> str:
        """Return a stable diagnostic suitable for pipeline hard errors."""
        return (
            f"return-chain AST integrity={self.verdict.value} "
            f"expected={self.expected_values!r} observed={self.observed_values!r} "
            f"missing={self.missing_values!r}"
        )


class _ReturnChainCFunctionBoundary8616(Protocol):
    """Minimum third-party angr C function surface used by this guard."""

    statements: object


class _ReturnChainCodegenBoundary8616(Protocol):
    """Initialized return-chain metadata carried by an angr codegen object."""

    cfunc: _ReturnChainCFunctionBoundary8616
    _inertia_return_chain_flattened_8616: bool
    _inertia_return_chain_suffix_materialized_8616: bool
    _inertia_return_chain_materialized_values_8616: tuple[int, ...]
    _inertia_return_chain_final_value_8616: int


@dataclass(frozen=True, slots=True)
class _MaterializedReturnChainRenderGuard8616:
    """Pipeline callback that reassesses the live Structuring AST at render time."""

    def verify(self, codegen: object, *, context: str) -> None:
        """Consume the Structuring contract through the Pipeline guard protocol."""
        require_materialized_return_chain_integrity_8616(codegen, context=context)


def _missing_values_8616(expected: tuple[int, ...], observed: tuple[int, ...]) -> tuple[int, ...]:
    """Return distinct proven values absent from the live return surface."""
    observed_values = frozenset(observed)
    return tuple(dict.fromkeys(value for value in expected if value not in observed_values))


def assess_materialized_return_chain_integrity_8616(
    codegen: object,
) -> MaterializedReturnChainIntegrity8616:
    """Assess exact constant-return preservation without consulting rendered C."""
    marker_missing = object()
    flattened_marker = getattr(codegen, "_inertia_return_chain_flattened_8616", marker_missing)
    suffix_marker = getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", marker_missing)
    if flattened_marker is marker_missing and suffix_marker is marker_missing:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE
        )
    if flattened_marker is marker_missing or suffix_marker is marker_missing:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    try:
        typed_codegen = cast(_ReturnChainCodegenBoundary8616, codegen)
        flattened = typed_codegen._inertia_return_chain_flattened_8616
        suffix_materialized = typed_codegen._inertia_return_chain_suffix_materialized_8616
    except AttributeError:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    if not (flattened or suffix_materialized):
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE
        )
    try:
        materialized_values = tuple(int(value) for value in typed_codegen._inertia_return_chain_materialized_values_8616)
        final_value = int(typed_codegen._inertia_return_chain_final_value_8616)
    except (AttributeError, TypeError, ValueError):
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    if not materialized_values:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.MISSING_EXPECTED_VALUES
        )
    expected_values = (*materialized_values, final_value)
    try:
        root = typed_codegen.cfunc.statements
    except AttributeError:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.MISSING_AST_ROOT,
            expected_values=expected_values,
        )
    if root is None:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.MISSING_AST_ROOT,
            expected_values=expected_values,
        )
    observed_values = tuple(
        value
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CReturn)
        if (value := const_return_value_8616(node.retval)) is not None
    )
    missing_values = _missing_values_8616(expected_values, observed_values)
    verdict = (
        MaterializedReturnChainIntegrityVerdict8616.MISSING_RETURN_VALUES
        if missing_values
        else MaterializedReturnChainIntegrityVerdict8616.PASSED
    )
    return MaterializedReturnChainIntegrity8616(
        verdict,
        expected_values=expected_values,
        observed_values=observed_values,
        missing_values=missing_values,
    )


def require_materialized_return_chain_integrity_8616(
    codegen: object,
    *,
    context: str,
) -> MaterializedReturnChainIntegrity8616:
    """Hard-fail when an active return-chain AST no longer matches its proof."""
    integrity = assess_materialized_return_chain_integrity_8616(codegen)
    if integrity.accepted:
        return integrity
    cfunc = getattr(codegen, "cfunc", None)
    function_addr = getattr(cfunc, "addr", None)
    raise PipelineHardError(
        "authoritative C AST lost CFG-proven return-chain values",
        layer="structuring",
        function_addr=function_addr if isinstance(function_addr, int) else None,
        details={
            "verdict": integrity.verdict.value,
            "expected_values": integrity.expected_values,
            "observed_values": integrity.observed_values,
            "missing_values": integrity.missing_values,
            "context": context,
        },
    )


def install_materialized_return_chain_integrity_guard_8616(codegen: object) -> None:
    """Install the live return-chain verifier through Pipeline governance."""
    install_codegen_render_integrity_guard_8616(codegen, _MaterializedReturnChainRenderGuard8616())
