"""Structuring-based code generation for control flow.

This module demonstrates how structured regions (Loop, IncSwitch) are converted
to C control flow constructs. Integration with full decompiler codegen happens
in Phase 1.4+.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .structuring.condition_rendering import render_condition_operand_8616
from .structuring_region import Region, RegionGraph, RegionType

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class LoopCodegenInfo:
    """Information for rendering a loop region as C code."""

    loop_type: str  # "while", "do_while", "for"
    condition_expr: Optional[str]  # Condition to evaluate
    init_stmt: Optional[str]  # Initialization (for loops)
    increment_stmt: Optional[str]  # Increment (for loops)
    body_regions: list[Region]  # Regions in loop body
    exit_label: Optional[str]  # Label for break target (if needed)
    uses_goto: bool  # True if fallback gotos needed
    structuring_variables: tuple[str, ...]  # Explicit abnormal loop selectors


@dataclass
class SwitchCodegenInfo:
    """Information for rendering a switch region as C code."""

    switch_expr: Optional[str]  # Expression being switched on
    case_targets: dict[str, Region]  # Constant->Region mapping
    default_target: Optional[Region]  # Default case target
    uses_fallthrough: bool  # True if case fallthrough
    uses_goto: bool  # True if complex gotos needed


@dataclass(frozen=True, slots=True)
class TypedEdgeSwitchAstMaterializationResult8616:
    """Result of building typed edge-guard switch AST artifacts."""

    attempted_count: int
    materialized_count: int
    refused_count: int
    refusal_reasons: tuple[str, ...]

    @property
    def changed(self) -> bool:
        """Return True when production C AST was modified."""
        return False


class StructuringCodegenPass:
    """Convertstructured regions to C code.

    This pass walks Loop and IncSwitch regions and emits appropriate C constructs.
    For Phase 1.3, this is a demonstration pass. Full integration with codegen
    happens in later phases.
    """

    def __init__(self) -> None:
        """Initialize the codegen pass."""
        self.stats = {
            "loops_rendered": 0,
            "switches_rendered": 0,
            "gotos_emitted": 0,
        }

    def render_loop(self, region: Region) -> str:
        """Render a loop region as C code.

        Args:
            region: Loop region to render

        Returns:
            C code string for the loop (simplified format)
        """
        loop_info = self._extract_loop_info(region)

        if loop_info.loop_type == "while":
            code = f"while ({loop_info.condition_expr or '1'}) {{\n"
            code += "  // loop body\n"
            code += "}"
        elif loop_info.loop_type == "do_while":
            code = "do {\n"
            code += "  // loop body\n"
            code += f"}} while ({loop_info.condition_expr});\n"
        elif loop_info.loop_type == "for":
            init = loop_info.init_stmt or ""
            cond = loop_info.condition_expr or "1"
            incr = loop_info.increment_stmt or ""
            code = f"for ({init}; {cond}; {incr}) {{\n"
            code += "  // loop body\n"
            code += "}"
        else:
            code = "// unknown loop type\n"

        if loop_info.uses_goto:
            code += f"\n{loop_info.exit_label}: // loop exit label\n"
        if loop_info.structuring_variables:
            joined = ", ".join(loop_info.structuring_variables)
            code += f"// structuring variables: {joined}\n"

        self.stats["loops_rendered"] += 1
        return code

    def render_switch(self, region: Region) -> str:
        """Render a switch region as C code.

        Args:
            region: IncSwitch region to render

        Returns:
            C code string for the switch
        """
        switch_info = self._extract_switch_info(region)

        code = f"switch ({switch_info.switch_expr or 'value'}) {{\n"

        for case_label, case_region in switch_info.case_targets.items():
            code += f"  case {case_label}:\n"
            code += "    // case body\n"
            if switch_info.uses_fallthrough:
                code += "    // fall through\n"
            else:
                code += "    break;\n"

        if switch_info.default_target:
            code += "  default:\n"
            code += "    // default case\n"
            code += "    break;\n"

        code += "}\n"

        if switch_info.uses_goto:
            code += "// complex switch with gotos\n"

        self.stats["switches_rendered"] += 1
        return code

    def _extract_loop_info(self, region: Region) -> LoopCodegenInfo:
        def _condition_expr_from_metadata() -> str:
            edge_guard_hints = region.metadata.get("typed_condition_edge_guard_hints") or ()
            edge_guard_hint = edge_guard_hints[0] if edge_guard_hints else None
            return (
                region.metadata.get("condition")
                or region.metadata.get("typed_ir_condition_hint")
                or edge_guard_hint
                or "cond"
            )

        def _impl() -> LoopCodegenInfo:
            """Extract loop information from a Loop region.

            Args:
                region: Loop region

            Returns:
                LoopCodegenInfo with rendering parameters
            """
            loop_meta = region.metadata.get("loop_info")
            exit_label = None

            if loop_meta and hasattr(loop_meta, "exit_edges"):
                if len(loop_meta.exit_edges) == 1:
                    loop_type = "while"
                else:
                    loop_type = "do_while"
                    exit_label = f"__loop_exit_{region.region_id:x}"
            else:
                loop_type = "while"

            unstructured_exits = region.metadata.get("unstructured_exits", [])
            unstructured_entries = region.metadata.get("unstructured_entries", [])
            abnormal_plan = region.metadata.get("abnormal_loop_plan", {})
            structuring_variables = tuple(region.metadata.get("structuring_variables", ()))
            uses_goto = len(unstructured_exits) > 0 or len(unstructured_entries) > 0
            if abnormal_plan and not exit_label and uses_goto:
                exit_label = f"__loop_exit_{region.region_id:x}"

            # Handle NaturalLoopInfo dataclass
            body_regions = []
            if loop_meta and hasattr(loop_meta, "body_regions"):
                body_regions = list(loop_meta.body_regions) if loop_meta.body_regions else []

            return LoopCodegenInfo(
                loop_type=loop_type,
                condition_expr=_condition_expr_from_metadata(),
                init_stmt=region.metadata.get("init"),
                increment_stmt=region.metadata.get("increment"),
                body_regions=body_regions,
                exit_label=exit_label,
                uses_goto=uses_goto,
                structuring_variables=structuring_variables,
            )

        return _impl()

    def _extract_switch_info(self, region: Region) -> SwitchCodegenInfo:
        """Extract switch information from an IncSwitch region.

        Args:
            region: IncSwitch region

        Returns:
            SwitchCodegenInfo with rendering parameters
        """
        switch_candidates = region.metadata.get("switch_candidates", [])
        case_values = tuple(region.metadata.get("switch_case_values", ()) or ())
        if len(case_values) == len(switch_candidates):
            case_targets = {str(value): target for value, target in zip(case_values, switch_candidates, strict=True)}
        else:
            case_targets = {f"0x{i:x}": target for i, target in enumerate(switch_candidates)}
        uses_goto = region.metadata.get("uses_goto", False)
        switch_lhs = region.metadata.get("switch_condition_lhs")
        switch_expr = region.metadata.get("switch_expr") or region.metadata.get("typed_ir_condition_hint")
        if switch_expr is None and switch_lhs is not None:
            switch_expr = render_condition_operand_8616(switch_lhs)

        return SwitchCodegenInfo(
            switch_expr=switch_expr or "value",
            case_targets=case_targets,
            default_target=region.metadata.get("switch_default_target"),
            uses_fallthrough=region.metadata.get("uses_fallthrough", False),
            uses_goto=uses_goto,
        )

    def apply(self, graph: RegionGraph) -> str:
        """Apply codegen to a structured region graph.

        Args:
            graph: The structured region graph

        Returns:
            Generated C code (simplified representation)
        """
        code = []

        for region in graph.nodes:
            if region.region_type == RegionType.Loop:
                code.append(self.render_loop(region))
            elif region.region_type == RegionType.IncSwitch:
                code.append(self.render_switch(region))

        result = "\n".join(code)
        logger.info(
            f"Codegen complete: {self.stats['loops_rendered']} loops, {self.stats['switches_rendered']} switches"
        )
        return result


def _typed_edge_switch_regions_8616(graph: RegionGraph | None) -> tuple[Region, ...]:
    if graph is None:
        return ()
    return tuple(
        region
        for region in graph.nodes
        if region.region_type == RegionType.IncSwitch
        and region.metadata.get("switch_detection") == "typed_condition_edge_cascade"
    )


def _statements_node_from_region_8616(region: Region, codegen: object) -> structured_c.CStatements | None:
    statements = tuple(getattr(region, "statements", ()) or ())
    if not statements:
        return None
    if len(statements) == 1 and isinstance(statements[0], structured_c.CStatements):
        return statements[0]
    return structured_c.CStatements(list(statements), addr=region.block_addr, codegen=codegen)


def materialize_typed_edge_switch_ast_8616(codegen: object) -> TypedEdgeSwitchAstMaterializationResult8616:
    """Build CSwitchCase artifacts for typed edge-guard switch regions when safe."""
    graph = getattr(codegen, "_inertia_grouped_structuring_graph", None)
    regions = _typed_edge_switch_regions_8616(graph if isinstance(graph, RegionGraph) else None)
    ast_nodes: list[structured_c.CSwitchCase] = []
    refusal_reasons: list[str] = []

    for region in regions:
        switch_expr = region.metadata.get("switch_expr_ast")
        if not isinstance(switch_expr, structured_c.CExpression):
            refusal_reasons.append("missing_switch_expr_ast")
            continue

        switch_candidates = tuple(region.metadata.get("switch_candidates", ()) or ())
        case_values = tuple(region.metadata.get("switch_case_values", ()) or ())
        if len(switch_candidates) != len(case_values):
            refusal_reasons.append("case_value_count_mismatch")
            continue

        cases: list[tuple[int, structured_c.CStatements]] = []
        missing_case_body = False
        for case_value, case_region in zip(case_values, switch_candidates, strict=True):
            case_body = _statements_node_from_region_8616(case_region, codegen)
            if case_body is None:
                missing_case_body = True
                break
            cases.append((int(case_value), case_body))
        if missing_case_body:
            refusal_reasons.append("missing_case_statements")
            continue

        default_body = None
        default_region = region.metadata.get("switch_default_target")
        if isinstance(default_region, Region):
            default_body = _statements_node_from_region_8616(default_region, codegen)
            if default_body is None:
                refusal_reasons.append("missing_default_statements")
                continue

        ast_nodes.append(
            structured_c.CSwitchCase(
                switch_expr,
                cases,
                default_body,
                codegen=codegen,
            )
        )

    result = TypedEdgeSwitchAstMaterializationResult8616(
        attempted_count=len(regions),
        materialized_count=len(ast_nodes),
        refused_count=len(refusal_reasons),
        refusal_reasons=tuple(refusal_reasons),
    )
    codegen._inertia_typed_edge_switch_ast_nodes_8616 = tuple(ast_nodes)
    codegen._inertia_typed_edge_switch_ast_materialization_8616 = {
        "attempted_count": result.attempted_count,
        "materialized_count": result.materialized_count,
        "refused_count": result.refused_count,
        "refusal_reasons": result.refusal_reasons,
        "changed": result.changed,
        "owner": "structuring.codegen",
    }
    return result


def apply_structuring_codegen_8616(codegen: object) -> bool:
    """Apply structuring-based code generation pass to codegen.

    This is the entry point for the decompiler framework integration,
    called after region-based structuring has completed.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if meaningful changes were made, False otherwise

    Note:
        This pass should only run after structuring analysis has completed.
        It generates information about loop/switch rendering but does not
        directly modify C text at this stage (that happens in simplification).
    """
    # Get the codegen cfunc if available
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    # Track that codegen was applied
    codegen._inertia_structuring_codegen_applied = True
    codegen._inertia_structuring_codegen_stats = {"loops_rendered": 0, "switches_rendered": 0}

    try:
        StructuringCodegenPass()
        materialize_typed_edge_switch_ast_8616(codegen)
        # In future phases, this will integrate with cfunc region graphs
        # For now, just track that codegen is enabled
        logger.debug("Structuring codegen pass completed")
        return False  # No direct modifications at this stage
    except Exception as ex:
        logger.warning("Structuring codegen pass failed: %s", ex)
        codegen._inertia_structuring_codegen_error = str(ex)
        return False
