from __future__ import annotations

from .structuring_analysis import RegionBasedStructuringPass
from .structuring_grouped_graph_builder import build_grouped_region_graph


class GroupedRegionBasedStructuringPass(RegionBasedStructuringPass):
    def _build_region_graph(self, codegen) -> tuple:
        result = build_grouped_region_graph(codegen)
        return result.graph_result.graph, result.graph_result.entry


def apply_grouped_region_based_structuring(codegen) -> bool:
    pass_instance = GroupedRegionBasedStructuringPass()
    return pass_instance(codegen)


def describe_x86_16_grouped_structuring_pass_surface() -> dict[str, object]:
    return {
        "pass_class": "GroupedRegionBasedStructuringPass",
        "graph_builder": "build_grouped_region_graph",
        "purpose": "Feed grouped region graphs into the real region-based structuring driver.",
    }


__all__ = [
    "GroupedRegionBasedStructuringPass",
    "apply_grouped_region_based_structuring",
    "describe_x86_16_grouped_structuring_pass_surface",
]
