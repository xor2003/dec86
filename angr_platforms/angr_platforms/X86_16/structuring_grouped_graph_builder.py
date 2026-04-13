from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ir.core import IRCondition
from .structuring_graph_builder import RegionGraphBuildResult, build_region_graph
from .structuring_grouped_units import (
    CrossEntryGroupedUnitArtifact,
    build_x86_16_cross_entry_grouped_units,
)


@dataclass(frozen=True, slots=True)
class GroupedRegionGraphBuildResult:
    graph_result: RegionGraphBuildResult
    grouped_units: CrossEntryGroupedUnitArtifact | None


def _typed_ir_support_by_region_id(codegen: Any) -> dict[int, dict[str, bool]]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}

    support: dict[int, dict[str, bool]] = {}
    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        region_id = getattr(block, "addr", None)
        if not isinstance(region_id, int):
            continue
        support[region_id] = {
            "has_condition": any(
                any(isinstance(arg, IRCondition) for arg in tuple(getattr(instr, "args", ()) or ()))
                for instr in tuple(getattr(block, "instrs", ()) or ())
            ),
            "has_phi": False,
        }
    for phi in tuple(getattr(function_ssa, "phi_nodes", ()) or ()):
        region_id = getattr(phi, "block_addr", None)
        if not isinstance(region_id, int):
            continue
        support.setdefault(region_id, {"has_condition": False, "has_phi": False})["has_phi"] = True
    return support


def build_grouped_region_graph(codegen: Any) -> GroupedRegionGraphBuildResult:
    graph_result = build_region_graph(codegen)
    grouped_units = build_x86_16_cross_entry_grouped_units(codegen)
    graph = graph_result.graph
    if graph is None or grouped_units is None or not grouped_units.units:
        return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)

    role_by_region_id: dict[int, tuple[str, int]] = {}
    for unit_index, unit in enumerate(grouped_units.units):
        for region_id in unit.primary_entry_region_ids:
            role_by_region_id[region_id] = ("primary_entry", unit_index)
        for region_id in unit.entry_fragment_region_ids:
            role_by_region_id[region_id] = ("entry_fragment", unit_index)
        for region_id in unit.shared_region_ids:
            role_by_region_id[region_id] = ("grouped_entry_candidate", unit_index)

    typed_ir_support = _typed_ir_support_by_region_id(codegen)
    for region in graph.nodes:
        region_id = getattr(region, "region_id", None)
        if not isinstance(region_id, int):
            continue
        role = role_by_region_id.get(region_id)
        if role is None:
            continue
        grouping_kind, unit_index = role
        region.metadata["cross_entry_grouping_kind"] = grouping_kind
        region.metadata["cross_entry_unit_index"] = unit_index
        ir_support = typed_ir_support.get(region_id)
        if ir_support is not None:
            region.metadata["typed_ir_has_condition"] = ir_support["has_condition"]
            region.metadata["typed_ir_has_phi"] = ir_support["has_phi"]
            region.metadata["typed_ir_allow_abnormal_loop_normalization"] = bool(
                ir_support["has_condition"] or ir_support["has_phi"]
            )

    return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)


def describe_x86_16_grouped_region_graph_surface() -> dict[str, object]:
    return {
        "producer": "build_grouped_region_graph",
        "graph_surface": "Region.metadata[cross_entry_*]",
        "unit_surface": "CrossEntryGroupedUnitArtifact",
        "purpose": "Materialize cross-entry grouping directly onto the region graph before structuring.",
    }


__all__ = [
    "GroupedRegionGraphBuildResult",
    "build_grouped_region_graph",
    "describe_x86_16_grouped_region_graph_surface",
]
