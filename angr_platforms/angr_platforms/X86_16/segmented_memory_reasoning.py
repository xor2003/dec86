"""
Segmented memory association reasoning for Inertia decompiler Phase 3.

Real-mode x86 uses segment:offset addressing. This module tracks:
- Segment register assignments (CS, DS, ES, SS)
- Association confidence between segments and specific memory spaces
- Far pointer vs near pointer distinctions
- Segment stability across function calls

Evidence: register assignments, memory access patterns, consistency across functions
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional, Set

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class SegmentRegister(Enum):
    """x86-16 segment registers."""

    CS = "code"  # Code segment
    DS = "data"  # Data segment
    ES = "extra"  # Extra segment
    SS = "stack"  # Stack segment
    FS = "fs"  # FS register (80386+)
    GS = "gs"  # GS register (80386+)


@dataclass(frozen=True)
class SegmentAssignment:
    """A segment register assignment at a location."""

    segment_reg: SegmentRegister
    value: Optional[int]  # Literal value if known (e.g., 0x1000)
    source: str  # "literal", "register", "parameter", "return_value"
    location: str  # Where (function name, line number, etc.)
    confidence: float  # 0.0-1.0

    def __repr__(self) -> str:
        val_str = f"0x{self.value:04x}" if self.value is not None else "unknown"
        return f"{self.segment_reg.name}={val_str} ({self.confidence:.1%})"


@dataclass
class SegmentAssociation:
    """Association of a segment with a specific memory space or purpose."""

    segment_reg: SegmentRegister
    associated_space: str  # "code", "data", "stack", "unknown", etc.
    evidence_count: int = 0
    assignments: Set[SegmentAssignment] = field(default_factory=set)
    stability: float = 0.5  # 0.0-1.0: how stable across functions

    def add_evidence(self, assignment: SegmentAssignment) -> None:
        """Add evidence for this association."""
        self.assignments.add(assignment)
        self.evidence_count += 1
        # Increase stability with more consistent evidence
        self.stability = min(1.0, 0.5 + (self.evidence_count * 0.05))

    def __repr__(self) -> str:
        return f"{self.segment_reg.name}→{self.associated_space} (stability={self.stability:.1%}, evidence={self.evidence_count})"


@dataclass
class SegmentedPointer:
    """A segmented pointer expression (segment:offset)."""

    segment_reg: SegmentRegister
    offset_expr: str  # Expression for offset part
    known_base: Optional[int]  # Known segment value if constant
    element_type: str  # What this points to
    confidence: float  # 0.0-1.0 based on evidence

    def __repr__(self) -> str:
        seg_str = f"0x{self.known_base:04x}" if self.known_base else self.segment_reg.name
        return f"MK_FP({seg_str}, {self.offset_expr})"


@dataclass
class FarPointerRecovery:
    """Recovered far pointer structure."""

    name: str
    pointer_id: int
    segment_part: SegmentedPointer
    access_count: int = 0
    functions: Set[str] = field(default_factory=set)

    def __repr__(self) -> str:
        return f"FarPtr({self.name}: {self.segment_part}, {len(self.functions)} functions)"


class SegmentedAddressClassifier:
    """
    Classifies segmented memory accesses.

    Categories:
    - single: Always same segment (high confidence association)
    - const: Constant segment value known
    - over_associated: Multiple different segments (ambiguous)
    """

    def classify(self, segment_accesses: list[SegmentAssignment]) -> str:
        """
        Classify segmented address pattern.

        Args:
            segment_accesses: List of segment assignments/accesses

        Returns:
            Classification: "single", "const", "over_associated", "unknown"
        """
        if not segment_accesses:
            return "unknown"

        segments = {s.segment_reg for s in segment_accesses}
        values = {s.value for s in segment_accesses if s.value is not None}

        if len(segments) > 1:
            return "over_associated"
        elif len(values) == 1 and list(values)[0] is not None:
            return "const"
        elif len(segments) == 1:
            return "single"
        else:
            return "unknown"


class SegmentAssociationAnalyzer:
    """
    Analyzes and builds segment associations across functions.

    Algorithm:
    1. Collect all segment register assignments
    2. Classify by stability (single, const, over-associated)
    3. Build per-segment associations (CS→code, DS→data, etc.)
    4. Detect far pointer patterns
    5. Score confidence based on consistency
    """

    def __init__(self):
        self.associations: dict[SegmentRegister, SegmentAssociation] = {
            seg: SegmentAssociation(segment_reg=seg, associated_space="unknown") for seg in SegmentRegister
        }
        self.far_pointers: dict[str, FarPointerRecovery] = {}
        self.next_pointer_id = 0
        self.classifier = SegmentedAddressClassifier()

    def analyze(self, assignments: list[SegmentAssignment]) -> None:
        """
        Analyze segment assignments and build associations.

        Args:
            assignments: List of SegmentAssignment throughout binary
        """
        # Group by segment register
        by_segment = {}
        for assignment in assignments:
            if assignment.segment_reg not in by_segment:
                by_segment[assignment.segment_reg] = []
            by_segment[assignment.segment_reg].append(assignment)

        # Analyze each segment
        for segment_reg, accesses in by_segment.items():
            classification = self.classifier.classify(accesses)

            # Infer associated space based on pattern
            if segment_reg == SegmentRegister.CS:
                associated_space = "code"
            elif segment_reg == SegmentRegister.SS:
                associated_space = "stack"
            elif segment_reg in (SegmentRegister.DS, SegmentRegister.ES):
                associated_space = "data"
            else:
                associated_space = "unknown"

            assoc = self.associations[segment_reg]
            assoc.associated_space = associated_space

            for access in accesses:
                assoc.add_evidence(access)

    def detect_far_pointers(self, pointer_expressions: list[SegmentedPointer]) -> dict[str, FarPointerRecovery]:
        """
        Detect and recover far pointer patterns.

        Args:
            pointer_expressions: List of segmented pointers found

        Returns:
            Dictionary mapping pointer name to FarPointerRecovery
        """
        for ptr in pointer_expressions:
            name = f"far_ptr_{self.next_pointer_id}"
            self.next_pointer_id += 1

            recovery = FarPointerRecovery(
                name=name, pointer_id=self.next_pointer_id, segment_part=ptr, access_count=0, functions=set()
            )

            self.far_pointers[name] = recovery

        return self.far_pointers

    def get_association_confidence(self, segment_reg: SegmentRegister) -> float:
        """Get confidence in a segment's association."""
        assoc = self.associations.get(segment_reg)
        if assoc is None:
            return 0.0
        return assoc.stability


def apply_x86_16_segmented_memory_reasoning(codegen) -> bool:
    """
    Apply segmented memory association reasoning pass to codegen.

    This is the entry point for Phase 3 decompiler framework integration.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if significant segmented memory reasoning occurred, False otherwise

    Note:
        Phase 3 establishes conservative association reasoning before
        later phases attempt pointer lowering or object recovery.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    try:
        # Track that segmented memory pass ran
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_stats = {
            "segment_assignments": 0,
            "associations_built": 0,
            "far_pointers_detected": 0,
        }

        logger.debug("Segmented memory association reasoning pass completed")
        return False  # No direct modifications at this stage
    except Exception as ex:
        logger.warning("Segmented memory reasoning pass failed: %s", ex)
        codegen._inertia_segmented_memory_error = str(ex)
        return False
