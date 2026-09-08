"""Layer: Recovery/reporting.

Responsibility: record whether architectural modules are production-wired,
compatibility wrappers, or test-only prototypes.
Forbidden: admitting a pass into the pipeline or changing recovery behavior by import.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LayerModuleAdmission(Enum):
    """Admission state for a layer module in the production architecture."""

    PRODUCTION_WIRED = "production_wired"
    COMPATIBILITY_WRAPPER = "compatibility_wrapper"
    TEST_ONLY_PROTOTYPE = "test_only_prototype"


@dataclass(frozen=True, slots=True)
class LayerModuleRecord:
    """Document whether a module is production, compatibility, or prototype code."""

    module: str
    admission: LayerModuleAdmission
    owner_layer: str
    note: str


LAYER_MODULE_RECORDS: tuple[LayerModuleRecord, ...] = (
    LayerModuleRecord(
        "angr_platforms.X86_16.validation.canonicalize",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "validation",
        "Validation-only expression canonicalizer consumed by production control-flow checks.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.alias.state",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "alias",
        "Canonical alias state imported by CLI AST rewrites for existing alias evidence handoff.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.alias.domains",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "alias",
        "Register-domain helpers consumed by production alias/segmented lowering bridges.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.structuring.loop_recovery",
        LayerModuleAdmission.TEST_ONLY_PROTOTYPE,
        "structuring",
        "Natural-loop metadata prototype; must be explicitly admitted before affecting output.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.structuring.simple_loop_recovery",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "structuring",
        "Focused counted-loop evidence helper imported by CLI/core decompilation paths.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.structuring.control_flow",
        LayerModuleAdmission.COMPATIBILITY_WRAPPER,
        "structuring",
        "Wrapper exposing existing structuring-stage symbols without owning implementation logic.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.semantics.evidence_cache",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "semantics",
        "Canonical semantic-access cache used by lifter and normalized alias-fact collection.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.postprocess.simplify",
        LayerModuleAdmission.COMPATIBILITY_WRAPPER,
        "postprocess",
        "Wrapper exposing existing cleanup-only simplification pass module.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.quality",
        LayerModuleAdmission.COMPATIBILITY_WRAPPER,
        "diagnostics",
        "Historical quality exports; implementation lives in inertia_decompiler.acceptance_scorecard.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.postprocess.cleanup",
        LayerModuleAdmission.COMPATIBILITY_WRAPPER,
        "postprocess",
        "Reserved cleanup compatibility module; no hidden logic or mirrored dynamic exports.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.lowering.segmented_lowering",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "lowering",
        "Typed segmented-address classifier consumed by production CLI segmented helpers.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.ir.ir_canonicalize_8616",
        LayerModuleAdmission.TEST_ONLY_PROTOTYPE,
        "IR",
        "Local expression canonicalizer prototype; not admitted to production IR mutation yet.",
    ),
    LayerModuleRecord(
        "angr_platforms.X86_16.exact_region_diagnostics",
        LayerModuleAdmission.PRODUCTION_WIRED,
        "diagnostics",
        "Exact-region diagnostics wired into function-discovery reporting.",
    ),
)


def layer_module_records_by_module() -> dict[str, LayerModuleRecord]:
    """Return layer module admission records keyed by module name."""
    return {record.module: record for record in LAYER_MODULE_RECORDS}


__all__ = [
    "LAYER_MODULE_RECORDS",
    "LayerModuleAdmission",
    "LayerModuleRecord",
    "layer_module_records_by_module",
]
