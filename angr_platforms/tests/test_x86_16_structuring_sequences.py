from angr_platforms.X86_16.structuring_sequences import sequence_merge_is_safe
from angr_platforms.X86_16.structuring_region import Region, RegionGraph, RegionType, compute_dominators


def test_sequence_merge_is_unsafe_for_back_edge_successor():
    entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
    header = Region(block_addr=0x1001, region_type=RegionType.Linear)
    body = Region(block_addr=0x1002, region_type=RegionType.Linear)
    exit_region = Region(block_addr=0x1003, region_type=RegionType.Linear)

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, header, body, exit_region):
        graph.add_node(region)

    graph.add_edge(entry, header)
    graph.add_edge(header, body)
    graph.add_edge(body, header)
    graph.add_edge(header, exit_region)

    dominators = compute_dominators(graph)

    assert sequence_merge_is_safe(graph, dominators, header, body) is False


def test_sequence_merge_is_safe_for_plain_linear_chain():
    entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
    a = Region(block_addr=0x2001, region_type=RegionType.Linear)
    b = Region(block_addr=0x2002, region_type=RegionType.Linear)

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, a, b):
        graph.add_node(region)

    graph.add_edge(entry, a)
    graph.add_edge(a, b)

    dominators = compute_dominators(graph)

    assert sequence_merge_is_safe(graph, dominators, a, b) is True
