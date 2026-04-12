import networkx as nx

from angr_platforms.X86_16.structuring_grouped_pass import (
    GroupedRegionBasedStructuringPass,
    describe_x86_16_grouped_structuring_pass_surface,
)


class _Node:
    def __init__(self, addr):
        self.addr = addr


class _Clinic:
    def __init__(self, graph):
        self.graph = graph


class _CFunc:
    def __init__(self, addr):
        self.addr = addr
        self.name = "func"


class _Codegen:
    def __init__(self, addr, clinic):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = None


def test_grouped_structuring_pass_builds_grouped_region_graph_for_driver():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    pass_instance = GroupedRegionBasedStructuringPass()
    built_graph, entry = pass_instance._build_region_graph(_Codegen(0x1000, _Clinic(graph)))

    assert built_graph is not None
    assert entry is not None
    by_id = {region.region_id: region for region in built_graph.nodes}
    assert by_id[0x1000].metadata["cross_entry_grouping_kind"] == "primary_entry"
    assert by_id[0x1001].metadata["cross_entry_grouping_kind"] == "entry_fragment"
    assert by_id[0x1002].metadata["cross_entry_grouping_kind"] == "grouped_entry_candidate"


def test_grouped_structuring_pass_surface_is_deterministic():
    assert describe_x86_16_grouped_structuring_pass_surface() == {
        "pass_class": "GroupedRegionBasedStructuringPass",
        "graph_builder": "build_grouped_region_graph",
        "purpose": "Feed grouped region graphs into the real region-based structuring driver.",
    }
