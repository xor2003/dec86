"""Plan bounded x86-16 exact-slice recovery for CLI fallback lanes.

Layer: CLI/fallback/reporting.
Responsibility: plan bounded exact-slice fallback addresses without recovering semantics.
"""

from __future__ import annotations

import weakref
from dataclasses import dataclass

SAFE_X86_16_SLICE_BASE: int = 0x1000
_ORIGINAL_ADDR_BY_FUNCTION_ID: dict[int, tuple[weakref.ReferenceType[object] | None, int]] = {}


@dataclass(frozen=True)
class X86ExactSlicePlan:
    """Address plan for recovering one x86-16 function in a bounded slice."""

    original_start: int
    original_end: int
    slice_base: int

    @property
    def needs_rebased_slice(self) -> bool:
        """Return true when the bounded slice must run at a synthetic base."""
        return self.slice_base != self.original_start

    @property
    def slice_start(self) -> int:
        """Start address used inside the bounded recovery project."""
        return self.slice_base

    @property
    def slice_end(self) -> int:
        """End address used inside the bounded recovery project."""
        return self.slice_base + max(0, self.original_end - self.original_start)


def plan_x86_16_exact_slice(original_start: int, original_end: int) -> X86ExactSlicePlan:
    """Create a bounded exact-slice plan for one original function range."""
    slice_base = SAFE_X86_16_SLICE_BASE if original_start >= 0x10000 else original_start
    return X86ExactSlicePlan(
        original_start=original_start,
        original_end=original_end,
        slice_base=slice_base,
    )


def non_optimized_slice_codegen_policy(
    arch_name: str | None,
    slice_plan: X86ExactSlicePlan | None,
) -> tuple[bool, bool]:
    """Pick the bounded non-optimized codegen policy for one-function exact slices.

    Exact rebased x86-16 slices already carry original-address linkage and now
    depend on postprocess callsite repair to keep direct-call targets and push
    arguments visible. Keep structured simplify off in this lane, but do allow
    postprocess so the same typed callsite facts can survive across recovery
    paths.
    """
    if arch_name == "86_16" and slice_plan is not None:
        return False, True
    return False, False


def function_original_addr(function: object) -> int:
    """Return a function's original address, accounting for rebased exact slices."""
    original_record = _ORIGINAL_ADDR_BY_FUNCTION_ID.get(id(function))
    if original_record is not None:
        function_ref, original_addr = original_record
        if function_ref is None or function_ref() is function:
            return original_addr
        _ORIGINAL_ADDR_BY_FUNCTION_ID.pop(id(function), None)
    # dynamic angr compatibility boundary: recovered Function objects expose optional info.
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        original_addr = info.get("inertia_original_addr")
        if isinstance(original_addr, int):
            return original_addr
    # dynamic angr compatibility boundary: recovered Function objects expose optional addr.
    addr = getattr(function, "addr", 0)
    return addr if isinstance(addr, int) else 0


def mark_function_original_addr(function: object, original_addr: int) -> None:
    """Attach an original address to a recovered or rebased function object."""
    try:
        function_ref: weakref.ReferenceType[object] | None = weakref.ref(function)
    except TypeError:
        function_ref = None
    _ORIGINAL_ADDR_BY_FUNCTION_ID[id(function)] = (function_ref, original_addr)
    # dynamic angr compatibility boundary: recovered Function objects expose optional info.
    info = getattr(function, "info", None)
    if not isinstance(info, dict):
        return
    info["inertia_original_addr"] = original_addr
