"""
Array expression matching for Inertia decompiler Phase 2.2.

Detects array access patterns (base + index * stride + offset)
and loop induction variables with stride to enable array subscript
recovery instead of raw pointer arithmetic.

Pattern: base[index * stride + offset]
Evidence: loop-carried stride patterns, consistent field access
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Set

from .ir.core import IRAddress
from .type_storage_object_bridge import load_storage_object_bridge

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _typed_ir_array_candidates(codegen) -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}

    phi_registers = {
        getattr(phi.target, "name", None)
        for phi in tuple(getattr(function_ssa, "phi_nodes", ()) or ())
        if getattr(getattr(phi, "target", None), "name", None) is not None
    }
    candidates: dict[tuple[str, tuple[str, ...], int], dict[str, object]] = {}
    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        for instr in tuple(getattr(block, "instrs", ()) or ()):
            for atom in tuple(getattr(instr, "args", ()) or ()):
                if not isinstance(atom, IRAddress):
                    continue
                if len(getattr(atom, "base", ()) or ()) < 2:
                    continue
                if not phi_registers.intersection(set(atom.base)):
                    continue
                key = (atom.space.value, tuple(atom.base), int(atom.size or 0))
                candidates[key] = {
                    "space": atom.space.value,
                    "base": tuple(atom.base),
                    "element_size": int(atom.size or 0),
                    "has_phi_index": True,
                }
    return dict(sorted(candidates.items()))


@dataclass(frozen=True)
class InductionVariable:
    """Represents a loop-carried induction variable with stride."""

    var_name: str
    stride: int  # Bytes per iteration
    base_value: int  # Initial value
    loop_bound: Optional[int]  # Upper bound if known
    element_width: int  # Bit width of element (8, 16, 32)

    def __repr__(self) -> str:
        return f"IndVar({self.var_name}, stride={self.stride}, width={self.element_width})"


@dataclass
class ArrayAccessPattern:
    """Detected array access pattern."""

    base_expr: str  # Base pointer
    index_var: str  # Index variable
    stride: int  # Bytes per element
    offset: int  # Constant offset
    element_type: str  # "int", "char", "ptr", etc.
    element_width: int  # Bit width

    def __repr__(self) -> str:
        return f"Array({self.base_expr}[{self.index_var} * {self.stride} + {self.offset}]:{self.element_type})"


@dataclass
class ArrayRecoveryInfo:
    """Information about recovered array structure."""

    array_name: str
    base_ptr: str
    element_type: str
    element_width: int
    element_stride: int
    access_patterns: Set[str]  # Collected access patterns
    confidence: float  # 0.0-1.0 based on pattern consistency

    def __repr__(self) -> str:
        return f"ArrayInfo({self.array_name}: {self.element_type}[{len(self.access_patterns)} accesses])"


class InductionVariableCollector:
    """
    Collect loop induction variables with stride patterns.

    Identifies variables that are:
    - Incremented/decremented by constant stride each iteration
    - Used as array indices or pointer offsets
    - Loop-carried across function calls
    """

    def __init__(self):
        self.induction_vars: dict[str, InductionVariable] = {}
        self.stride_patterns: dict[str, int] = {}

    def collect(self, expressions: list[str]) -> dict[str, InductionVariable]:
        """
        Collect induction variables from expression list.

        Args:
            expressions: List of expression strings

        Returns:
            Dictionary mapping variable name to InductionVariable
        """
        # Placeholder: would analyze loop bodies and variable updates
        # For now, demonstrate structure

        for expr in expressions:
            if "+=" in expr or "-=" in expr:
                self._analyze_update_expr(expr)

        return self.induction_vars

    def _analyze_update_expr(self, expr: str) -> None:
        """Analyze variable update expression for stride patterns."""
        # Example: "si += 2" or "di -= 4"
        if "+=" in expr:
            parts = expr.split("+=")
            if len(parts) == 2:
                var = parts[0].strip()
                stride_str = parts[1].strip()
                try:
                    stride = int(stride_str)
                    self.stride_patterns[var] = stride
                    self.induction_vars[var] = InductionVariable(
                        var_name=var, stride=stride, base_value=0, loop_bound=None, element_width=16
                    )
                except ValueError:
                    pass


class ArrayExpressionMatcher:
    """
    Detect and match array access patterns.

    Recognizes:
    - Simple indexed access: base[index]
    - Strided access: base + index * stride
    - Offset access: base + index * stride + offset
    - Nested arrays: base[i][j]
    """

    def __init__(self):
        self.detected_patterns: list[ArrayAccessPattern] = []
        self.array_infos: dict[str, ArrayRecoveryInfo] = {}

    def match_patterns(
        self, expressions: list[str], induction_vars: dict[str, InductionVariable]
    ) -> list[ArrayAccessPattern]:
        """
        Match array access patterns in expressions.

        Args:
            expressions: List of expression strings
            induction_vars: Known induction variables with strides

        Returns:
            List of detected ArrayAccessPattern
        """
        patterns = []

        for expr in expressions:
            if self._looks_like_array_access(expr):
                pattern = self._extract_array_pattern(expr, induction_vars)
                if pattern:
                    patterns.append(pattern)
                    self.detected_patterns.append(pattern)

        return patterns

    def _looks_like_array_access(self, expr: str) -> bool:
        """Heuristic check if expression might be array access."""
        # Check for patterns like "[", "*", "+", "-"
        return any(marker in expr for marker in ["[", "mem[", "*"])

    def _extract_array_pattern(self, expr: str, induction_vars: dict[str, InductionVariable]) -> Optional[ArrayAccessPattern]:
        """Extract array pattern from expression if possible."""
        # Placeholder: would parse expression into base, index, stride, offset
        # For now, return generic pattern

        for var_name, ind_var in induction_vars.items():
            if var_name in expr:
                # Found expression with induction variable
                return ArrayAccessPattern(
                    base_expr="array_base",
                    index_var=var_name,
                    stride=ind_var.stride,
                    offset=0,
                    element_type="int",
                    element_width=ind_var.element_width,
                )

        return None

    def synthesize_arrays(self, patterns: list[ArrayAccessPattern]) -> dict[str, ArrayRecoveryInfo]:
        """
        Synthesize array recovery info from matched patterns.

        Groups patterns by base expression to recover array structure.

        Args:
            patterns: List of detected array access patterns

        Returns:
            Dictionary mapping base_expr to ArrayRecoveryInfo
        """
        arrays: dict[str, ArrayRecoveryInfo] = {}

        for pattern in patterns:
            if pattern.base_expr not in arrays:
                arrays[pattern.base_expr] = ArrayRecoveryInfo(
                    array_name=f"array_{pattern.base_expr}",
                    base_ptr=pattern.base_expr,
                    element_type=pattern.element_type,
                    element_width=pattern.element_width,
                    element_stride=pattern.stride,
                    access_patterns=set(),
                    confidence=0.5,
                )

            arrays[pattern.base_expr].access_patterns.add(str(pattern))

            # Increase confidence with more consistent patterns
            num_patterns = len(arrays[pattern.base_expr].access_patterns)
            arrays[pattern.base_expr].confidence = min(1.0, 0.5 + (num_patterns * 0.1))

        self.array_infos = arrays
        return arrays


def apply_x86_16_array_expression_matching(codegen) -> bool:
    """
    Apply array expression matching pass to codegen.

    This is the entry point for Phase 2.2 decompiler framework integration.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if array patterns were detected, False otherwise

    Note:
        This pass collects array recovery metadata but doesn't modify
        codegen text directly (that happens in later phases).
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    try:
        project = getattr(codegen, "project", None)
        function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        bridge = None
        if project is not None:
            bridge = load_storage_object_bridge(project, function_addr, codegen=codegen)
        lowerable_arrays = (
            {}
            if bridge is None
            else {
                base_key: fact
                for base_key, fact in bridge.array_facts.items()
                if bridge.allows_object_lowering(base_key)
            }
        )
        refused_arrays = (
            {}
            if bridge is None
            else {
                base_key: bridge.lowering_refusal_reason(base_key)
                for base_key in bridge.array_facts
                if not bridge.allows_object_lowering(base_key)
            }
        )
        typed_ir_candidates = _typed_ir_array_candidates(codegen)
        # Track that array matching pass ran
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_bridge = bridge
        codegen._inertia_array_matching_lowerable_arrays = lowerable_arrays
        codegen._inertia_array_matching_refused_arrays = refused_arrays
        codegen._inertia_array_matching_typed_ir_candidates = typed_ir_candidates
        codegen._inertia_array_matching_stats = {
            "induction_vars": len(typed_ir_candidates),
            "array_patterns": 0 if bridge is None else len(bridge.array_facts),
            "recovered_arrays": len(lowerable_arrays) + len(typed_ir_candidates),
            "refused_arrays": len(refused_arrays),
        }

        logger.debug("Array expression matching pass completed")
        return False  # No direct modifications at this stage
    except Exception as ex:
        logger.warning("Array expression matching pass failed: %s", ex)
        codegen._inertia_array_matching_error = str(ex)
        return False
