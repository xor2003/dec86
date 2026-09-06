"""Compatibility exports for generated-C quality reporting.

Layer: Recovery/reporting compatibility surface.
Responsibility: preserve the historical X86_16 quality API while the
CLI/reporting layer owns the implementation.
"""

from __future__ import annotations

from inertia_decompiler.acceptance_scorecard import (
    X86_16QualityMetrics,
    format_x86_16_quality_report_8616,
    measure_x86_16_codegen_quality_8616,
    measure_x86_16_function_quality_8616,
)

__all__ = [
    "X86_16QualityMetrics",
    "format_x86_16_quality_report_8616",
    "measure_x86_16_codegen_quality_8616",
    "measure_x86_16_function_quality_8616",
]
