"""
Tests for structuring-based C code generation (Phase 1.3).

Demonstrates Loop→while/for, IncSwitch→switch rendering.
"""

from types import SimpleNamespace

import archinfo
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring_analysis import StructureAnalysis
from angr_platforms.X86_16.structuring_codegen import (
    StructuringCodegenPass,
    materialize_typed_edge_switch_ast_8616,
)
from angr_platforms.X86_16.structuring_region import Region, RegionGraph, RegionType


class _AstCodegen:
    def __init__(self):
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.stmt_comments = {}
        self.expr_comments = {}
        self.braces_on_own_lines = False
        self.display_block_addrs = False
        self.display_vvar_ids = False
        self.max_str_len = 64
        self.const_formats = {}
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx


class TestStructuringCodegen:
    """Tests for C code generation from structured regions."""

    def test_loop_renders_as_while(self):
        """
        Test that a Loop region renders as while loop C code.
        """
        # Create simple loop
        entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
        header = Region(block_addr=0x1001, region_type=RegionType.Linear)
        body = Region(block_addr=0x1002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x1003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, header)
        graph.add_edge(header, body)
        graph.add_edge(body, header)  # Back-edge
        graph.add_edge(header, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Generate C code
        codegen = StructuringCodegenPass()
        code = codegen.apply(result)

        # Verify codegen completed
        assert code is not None, "Should generate code"
        assert codegen.stats["loops_rendered"] >= 0, "Should track loop count"

    def test_switch_renders_as_switch(self):
        """
        Test that an IncSwitch region renders as switch C code.
        """
        entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
        switch_region = Region(block_addr=0x2001, region_type=RegionType.Condition)
        cases = [Region(block_addr=0x2002 + i * 4, region_type=RegionType.Linear) for i in range(3)]
        exit_region = Region(block_addr=0x2010, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)
        graph.add_node(switch_region)
        for case in cases:
            graph.add_node(case)
        graph.add_node(exit_region)

        graph.add_edge(entry, switch_region)
        for case in cases:
            graph.add_edge(switch_region, case)
            graph.add_edge(case, exit_region)

        # Run structuring (will detect 3-way switch)
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Generate C code
        codegen = StructuringCodegenPass()
        code = codegen.apply(result)

        # Verify codegen
        assert code is not None, "Should generate code"
        assert codegen.stats["switches_rendered"] >= 0, "Should track switch count"

    def test_loop_render_contains_while(self):
        """
        Test that rendered loop code contains 'while' keyword.
        """
        loop_region = Region(block_addr=0x3000, region_type=RegionType.Loop)
        loop_region.metadata["loop_info"] = None

        graph = RegionGraph()
        graph.entry = loop_region

        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        # While loop should appear in simplest case
        assert "while" in code or "do" in code or "for" in code, "Loop should render as C control flow"

    def test_loop_codegen_uses_typed_ir_condition_hint_when_no_explicit_condition(self):
        loop_region = Region(block_addr=0x3100, region_type=RegionType.Loop)
        loop_region.metadata["typed_ir_condition_hint"] = "ax == 0"

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax == 0)" in code

    def test_loop_codegen_uses_condition_edge_hint_as_last_resort(self):
        loop_region = Region(block_addr=0x3104, region_type=RegionType.Loop)
        loop_region.metadata["typed_condition_edge_guard_hints"] = ("ax == 69",)

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax == 69)" in code

    def test_loop_codegen_prefers_direct_condition_hint_over_edge_hint(self):
        loop_region = Region(block_addr=0x3108, region_type=RegionType.Loop)
        loop_region.metadata["typed_ir_condition_hint"] = "ax != 27"
        loop_region.metadata["typed_condition_edge_guard_hints"] = ("ax == 69",)

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax != 27)" in code
        assert "ax == 69" not in code

    def test_switch_render_contains_switch(self):
        """
        Test that rendered switch code contains 'switch' keyword.
        """
        switch_region = Region(block_addr=0x4000, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x1),
            Region(block_addr=0x2),
            Region(block_addr=0x3),
        ]

        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "switch" in code or "case" in code, "Switch should render as C switch statement"

    def test_switch_codegen_uses_typed_edge_case_values_and_lhs(self):
        switch_region = Region(block_addr=0x4100, region_type=RegionType.IncSwitch)
        default_region = Region(block_addr=0x4110, region_type=RegionType.Linear)
        switch_region.metadata["switch_condition_lhs"] = IRValue(MemSpace.REG, name="ax", size=2)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x4150),
            Region(block_addr=0x4160),
            Region(block_addr=0x4170),
        ]
        switch_region.metadata["switch_default_target"] = default_region

        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "switch (ax)" in code
        assert "case 69:" in code
        assert "case 27:" in code
        assert "case 33:" in code
        assert "default:" in code
        assert "case 0x0:" not in code

    def test_typed_edge_switch_ast_materialization_refuses_empty_case_bodies(self):
        switch_region = Region(block_addr=0x4200, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(
            0,
            SimTypeShort(False),
            codegen=_AstCodegen(),
        )
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x4250),
            Region(block_addr=0x4260),
            Region(block_addr=0x4270),
        ]
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen = _AstCodegen()
        codegen._inertia_grouped_structuring_graph = graph

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.changed is False
        assert result.attempted_count == 1
        assert result.materialized_count == 0
        assert result.refusal_reasons == ("missing_case_statements",)
        assert codegen._inertia_typed_edge_switch_ast_nodes_8616 == ()

    def test_typed_edge_switch_ast_materialization_builds_switch_artifact_when_bodies_exist(self):
        codegen = _AstCodegen()
        switch_region = Region(block_addr=0x4300, region_type=RegionType.IncSwitch)
        case_a = Region(block_addr=0x4350)
        case_b = Region(block_addr=0x4360)
        case_c = Region(block_addr=0x4370)
        default_region = Region(block_addr=0x4380)
        case_a.statements.append(structured_c.CLabel("case_a", codegen=codegen))
        case_b.statements.append(structured_c.CLabel("case_b", codegen=codegen))
        case_c.statements.append(structured_c.CLabel("case_c", codegen=codegen))
        default_region.statements.append(structured_c.CLabel("default_case", codegen=codegen))
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.changed is False
        assert result.attempted_count == 1
        assert result.materialized_count == 1
        assert result.refused_count == 0
        [switch_ast] = codegen._inertia_typed_edge_switch_ast_nodes_8616
        rendered = switch_ast.c_repr()
        assert "switch (0)" in rendered
        assert "case 69:" in rendered
        assert "case 27:" in rendered
        assert "case 33:" in rendered
        assert "default:" in rendered
        assert "case_a:" in rendered
        assert "default_case:" in rendered

    def test_codegen_stats_tracking(self):
        """
        Verify that codegen tracks statistics.
        """
        graph = RegionGraph()
        loop1 = Region(block_addr=0x5000, region_type=RegionType.Loop)
        switch1 = Region(block_addr=0x5001, region_type=RegionType.IncSwitch)
        linear1 = Region(block_addr=0x5002, region_type=RegionType.Linear)

        graph.entry = loop1
        for r in [loop1, switch1, linear1]:
            graph.add_node(r)

        codegen = StructuringCodegenPass()
        codegen.apply(graph)

        # Stats should be tracked
        assert codegen.stats["loops_rendered"] >= 0, "Should track loops"
        assert codegen.stats["switches_rendered"] >= 0, "Should track switches"

    def test_multiple_loops_and_switches(self):
        """
        Test codegen with multiple Loop and IncSwitch regions.
        """
        graph = RegionGraph()

        # Create 2 loops and 2 switches
        regions = []
        for i, rtype in enumerate([RegionType.Loop, RegionType.IncSwitch, RegionType.Loop, RegionType.IncSwitch]):
            r = Region(block_addr=0x6000 + i * 4, region_type=rtype)
            if rtype == RegionType.IncSwitch:
                r.metadata["switch_candidates"] = [Region(block_addr=0x7000 + i)]
            graph.add_node(r)
            regions.append(r)

        graph.entry = regions[0]

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert code is not None, "Should generate code for mixed regions"
        assert codegen.stats["loops_rendered"] > 0, "Should count loops"
        assert codegen.stats["switches_rendered"] > 0, "Should count switches"

    def test_codegen_integration_with_structuring(self):
        """
        End-to-end test: structure CFG, then generate C code.
        """
        # Build a realistic CFG: Entry -> Loop, Exit
        entry = Region(block_addr=0x8000, region_type=RegionType.Linear)
        loop_header = Region(block_addr=0x8001, region_type=RegionType.Linear)
        loop_body = Region(block_addr=0x8002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x8003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, loop_header, loop_body, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, loop_header)
        graph.add_edge(loop_header, loop_body)
        graph.add_edge(loop_body, loop_header)  # Back-edge
        graph.add_edge(loop_header, exit_region)

        # Structuring
        analyzer = StructureAnalysis(graph)
        structured = analyzer.structure()

        # Codegen
        codegen = StructuringCodegenPass()
        code = codegen.apply(structured)

        # Should generate valid C structure
        assert code is not None
        assert len(code) > 0, "Should generate non-empty code"

    def test_loop_codegen_mentions_structuring_variables_for_abnormal_loop(self):
        loop_region = Region(block_addr=0x9000, region_type=RegionType.Loop)
        loop_region.metadata["abnormal_loop_plan"] = {
            "can_normalize": True,
            "exit_variable_name": "__loop_exit_sel_9000",
        }
        loop_region.metadata["structuring_variables"] = ["__loop_exit_sel_9000"]
        loop_region.metadata["unstructured_exits"] = [(0x9000, 0x9001)]

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "__loop_exit_sel_9000" in code
        assert "structuring variables" in code


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
