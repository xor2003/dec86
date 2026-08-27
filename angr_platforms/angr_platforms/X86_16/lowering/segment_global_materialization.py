"""Coordinate proven segmented-global materializers after C-AST regeneration.

Layer: Types/Lowering.
Responsibility: replay typed segment/global materialization in one deterministic
order for Structuring, validation priming, and CLI regeneration callers.
Consumes alias, widening, and typed facts; it does not produce semantic evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic boundary: project and codegen are third-party angr plugin objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from ..widening.segmented_load_widening import apply_segmented_load_widening_8616
from .dos_interrupt_aggregate_globals import materialize_dos_interrupt_aggregate_globals_8616
from .segmented_global_loads import (
    materialize_compare_register_global_carriers_8616,
    materialize_direct_global_symbol_stores_8616,
    materialize_indexed_segmented_global_loads_8616,
    materialize_named_segmented_global_loads_8616,
)
from .segmented_memory_lowering import apply_runtime_segment_lowering_8616

type ProjectBoundary8616 = Any
type CodegenBoundary8616 = Any

__all__ = [
    "SegmentGlobalMaterializationResult8616",
    "cod_metadata_for_codegen_8616",
    "run_segment_global_materialization_8616",
]


@dataclass(frozen=True, slots=True)
class SegmentGlobalMaterializationResult8616:
    """Result of one complete segmented-global materialization replay."""

    runtime_segment_changed: bool
    segmented_load_widening_changed: bool
    named_global_changed: bool
    compare_register_global_changed: bool
    direct_global_store_changed: bool
    indexed_global_changed: bool
    dos_interrupt_aggregate_changed: bool

    @property
    def changed(self) -> bool:
        """Return True when any owning materializer changed the C AST."""
        return (
            self.runtime_segment_changed
            or self.segmented_load_widening_changed
            or self.named_global_changed
            or self.compare_register_global_changed
            or self.direct_global_store_changed
            or self.indexed_global_changed
            or self.dos_interrupt_aggregate_changed
        )


def cod_metadata_for_codegen_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
) -> object | None:
    """Return optional sidecar metadata for the active dynamic angr codegen."""
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return None
    projects = (project, getattr(project, "_inertia_original_project", None))
    delta = getattr(project, "_inertia_original_linear_delta", None)
    candidate_addrs = [func_addr]
    if isinstance(delta, int):
        candidate_addrs.extend((func_addr + delta, func_addr - delta))
    for candidate_project in projects:
        metadata_by_addr = getattr(candidate_project, "_inertia_cod_metadata_by_func_addr_8616", None)
        if not isinstance(metadata_by_addr, dict):
            continue
        for candidate_addr in candidate_addrs:
            metadata = metadata_by_addr.get(candidate_addr)
            if metadata is not None:
                return cast(object, metadata)
        unique_metadata = {id(metadata): metadata for metadata in metadata_by_addr.values()}
        if len(unique_metadata) == 1:
            return cast(object, next(iter(unique_metadata.values())))
    return None


def run_segment_global_materialization_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
    *,
    cod_metadata: object | None = None,
    include_runtime_segment: bool = False,
) -> SegmentGlobalMaterializationResult8616:
    """Run proven segment/global materializers in Types/Lowering-owned order."""
    named_global_changed = bool(
        materialize_named_segmented_global_loads_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    )
    compare_register_global_changed = bool(
        materialize_compare_register_global_carriers_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    )
    indexed_global_changed = bool(
        materialize_indexed_segmented_global_loads_8616(project, codegen, cod_metadata=cod_metadata)
    )
    direct_global_store_changed = bool(
        materialize_direct_global_symbol_stores_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    )
    dos_interrupt_aggregate_changed = bool(
        materialize_dos_interrupt_aggregate_globals_8616(codegen)
    )
    segmented_load_widening_changed = bool(apply_segmented_load_widening_8616(codegen))
    target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat")
    runtime_segment_changed = (
        bool(apply_runtime_segment_lowering_8616(codegen, target=target)) if include_runtime_segment else False
    )
    result = SegmentGlobalMaterializationResult8616(
        runtime_segment_changed=runtime_segment_changed,
        segmented_load_widening_changed=segmented_load_widening_changed,
        named_global_changed=named_global_changed,
        compare_register_global_changed=compare_register_global_changed,
        direct_global_store_changed=direct_global_store_changed,
        indexed_global_changed=indexed_global_changed,
        dos_interrupt_aggregate_changed=dos_interrupt_aggregate_changed,
    )
    if result.changed:
        codegen._inertia_segment_global_materialization_8616 = {
            "runtime_segment_changed": result.runtime_segment_changed,
            "segmented_load_widening_changed": result.segmented_load_widening_changed,
            "named_global_changed": result.named_global_changed,
            "compare_register_global_changed": result.compare_register_global_changed,
            "direct_global_store_changed": result.direct_global_store_changed,
            "indexed_global_changed": result.indexed_global_changed,
            "dos_interrupt_aggregate_changed": result.dos_interrupt_aggregate_changed,
            "changed": result.changed,
            "owner": "lowering.segment_global_materialization",
        }
    return result
