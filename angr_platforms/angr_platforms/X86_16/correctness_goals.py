from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrectnessGoalSpec:
    code: str
    title: str
    priority: str
    status: str
    deterministic_goal: str
    owner_surfaces: tuple[str, ...]
    completion_signal: str


CORRECTNESS_GOALS: tuple[CorrectnessGoalSpec, ...] = (
    CorrectnessGoalSpec(
        code="C6.1",
        title="Keep semantic compare and runtime samples green",
        priority="P0",
        status="landed",
        deterministic_goal="Keep compare-style semantics and runtime sample probes stable on the canonical x86-16 validation slices.",
        owner_surfaces=(
            "validation_families",
            "tests/test_x86_16_compare_semantics.py",
            "tests/test_x86_16_runtime_samples.py",
        ),
        completion_signal="Semantic compare and runtime sample regressions stay explicit, bounded, and green.",
    ),
    CorrectnessGoalSpec(
        code="C6.2",
        title="Keep sample matrix and 80286 verifier aligned",
        priority="P0",
        status="landed",
        deterministic_goal="Keep the sample matrix representative and the 80286 verifier passing so coverage reflects real instruction behavior.",
        owner_surfaces=(
            "validation_families",
            "tests/test_x86_16_sample_matrix.py",
            "tests/test_x86_16_80286_verifier.py",
        ),
        completion_signal="Sample-matrix and hardware-backed verification stay green together.",
    ),
    CorrectnessGoalSpec(
        code="C6.3",
        title="Keep calling-convention and return compatibility faithful",
        priority="P0",
        status="landed",
        deterministic_goal="Keep call/return prototypes and decompiler return compatibility anchored to the shared compatibility helpers.",
        owner_surfaces=(
            "calling_convention_compat",
            "decompiler_return_compat",
            "tests/test_x86_16_package_exports.py",
            "tests/test_x86_16_helper_modeling.py",
        ),
        completion_signal="Prototype and return-compatibility helpers remain the source of truth for decompiler boundary behavior.",
    ),
    CorrectnessGoalSpec(
        code="C6.4",
        title="Keep interrupt lowering correctness-driven and bounded",
        priority="P1",
        status="landed",
        deterministic_goal="Keep interrupt-core semantics separate from DOS/BIOS/MS-C lowering and keep unresolved wrappers visible as bounded debt.",
        owner_surfaces=(
            "interrupt_api_surface",
            "interrupt_core_surface",
            "interrupt_lowering_boundary",
            "analysis_helpers",
            "decompile",
        ),
        completion_signal="Interrupt lowering remains helper-backed, boundary-aware, and visible in milestone reports.",
    ),
)


def describe_x86_16_correctness_goals() -> tuple[tuple[str, str, str, str, tuple[str, ...], str], ...]:
    return tuple(
        (
            goal.code,
            goal.title,
            goal.priority,
            goal.status,
            goal.owner_surfaces,
            goal.completion_signal,
        )
        for goal in CORRECTNESS_GOALS
    )


def summarize_x86_16_correctness_goals() -> dict[str, object]:
    landed = sum(1 for goal in CORRECTNESS_GOALS if goal.status == "landed")
    partial = sum(1 for goal in CORRECTNESS_GOALS if goal.status == "partial")
    open_ = sum(1 for goal in CORRECTNESS_GOALS if goal.status == "open")
    strict_percent = round(landed / len(CORRECTNESS_GOALS) * 100, 2) if CORRECTNESS_GOALS else 0.0
    weighted_percent = round((landed + 0.5 * partial) / len(CORRECTNESS_GOALS) * 100, 2) if CORRECTNESS_GOALS else 0.0
    return {
        "total": len(CORRECTNESS_GOALS),
        "landed": landed,
        "partial": partial,
        "open": open_,
        "strict_percent": strict_percent,
        "weighted_percent": weighted_percent,
        "landed_codes": tuple(goal.code for goal in CORRECTNESS_GOALS if goal.status == "landed"),
        "partial_codes": tuple(goal.code for goal in CORRECTNESS_GOALS if goal.status == "partial"),
        "open_codes": tuple(goal.code for goal in CORRECTNESS_GOALS if goal.status == "open"),
    }


__all__ = [
    "CORRECTNESS_GOALS",
    "CorrectnessGoalSpec",
    "describe_x86_16_correctness_goals",
    "summarize_x86_16_correctness_goals",
]
