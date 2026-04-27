from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Pass driver: runs optimization passes on structured codegen before postprocess.
Inserted early in the postprocess stage, before rewrite passes.

Forbidden: semantic recovery, alias decisions, type inference."""

from dataclasses import dataclass
from typing import Callable

from .const_prop import _constant_propagation_8616
from .copy_prop import _copy_propagation_8616
from .dce import _dead_code_elimination_8616

__all__ = [
    "OptimizationPassSpec",
    "OPTIMIZATION_PASSES",
    "_run_optimization_passes_8616",
    "describe_x86_16_optimization_passes",
]


@dataclass(frozen=True, slots=True)
class OptimizationPassSpec:
    name: str
    func: Callable[..., bool]
    description: str


OPTIMIZATION_PASSES: tuple[OptimizationPassSpec, ...] = (
    OptimizationPassSpec(
        "const_prop",
        _constant_propagation_8616,
        "Fold constant sub-expressions",
    ),
    OptimizationPassSpec(
        "copy_prop",
        _copy_propagation_8616,
        "Propagate copies using alias facts",
    ),
    OptimizationPassSpec(
        "dce",
        _dead_code_elimination_8616,
        "Eliminate dead assignments",
    ),
)


def describe_x86_16_optimization_passes() -> tuple[tuple[str, str], ...]:
    return tuple((spec.name, spec.description) for spec in OPTIMIZATION_PASSES)


def _run_optimization_passes_8616(codegen) -> bool:
    """Run optimization passes on codegen.

    Returns True if any pass modified the codegen.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    for spec in OPTIMIZATION_PASSES:
        if spec.func(codegen):
            changed = True

    return changed