"""Shared address contract for lifted x86-16 software interrupts.

Layer: Frontend contract.
Responsibility: assign disjoint synthetic address ranges to raw interrupt
vectors, DOS services, and non-DOS interrupt helpers. No semantic recovery or
C rendering belongs here.
"""

from __future__ import annotations

INTERRUPT_CORE_VECTOR_BASE: int = 0xFF000
INTERRUPT_CORE_VECTOR_COUNT: int = 0x100
INTERRUPT_SERVICE_BASE_ADDR: int = 0xFD000
DOS_SERVICE_BASE_ADDR: int = 0xFE000

__all__ = [
    "DOS_SERVICE_BASE_ADDR",
    "INTERRUPT_CORE_VECTOR_BASE",
    "INTERRUPT_CORE_VECTOR_COUNT",
    "INTERRUPT_SERVICE_BASE_ADDR",
    "interrupt_core_addr_8616",
    "interrupt_vector_from_core_addr_8616",
]


def interrupt_core_addr_8616(vector: int) -> int:
    """Return the raw lifted-call target for one interrupt vector."""
    if not 0 <= vector < INTERRUPT_CORE_VECTOR_COUNT:
        raise ValueError(f"interrupt vector out of range: {vector}")
    return INTERRUPT_CORE_VECTOR_BASE + vector


def interrupt_vector_from_core_addr_8616(target_addr: int) -> int | None:
    """Decode an exact interrupt vector from a raw lifted-call target."""
    vector = target_addr - INTERRUPT_CORE_VECTOR_BASE
    return vector if 0 <= vector < INTERRUPT_CORE_VECTOR_COUNT else None
