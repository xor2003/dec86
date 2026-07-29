"""Canonical evidence cache for raw semantic accesses.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.

An explicit lowering-owned collection context is populated during VEX re-lifting
and consumed immediately by the normalized collector. CFG-time lifts have no
function owner and therefore publish no semantic evidence.

Context-local ownership prevents projects that reuse DOS addresses from sharing
evidence and keeps concurrent collections isolated.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

__all__ = [
    "AccessRecord8616",
    "EvidenceCollection8616",
    "collect_accesses_for_function",
    "get_current_function_addr",
    "record_access",
]


@dataclass(frozen=True, slots=True)
class AccessRecord8616:
    """Raw semantic memory-access evidence captured during instruction lifting."""

    function_addr: int
    insn_addr: int | None
    mode: int
    addr: object


@dataclass(slots=True)
class EvidenceCollection8616:
    """Function-owned semantic accesses captured during one explicit re-lift."""

    function_addr: int
    accesses: list[AccessRecord8616] = field(default_factory=list)


_active_collection: ContextVar[EvidenceCollection8616 | None] = ContextVar(
    "x86_16_active_evidence_collection",
    default=None,
)


@contextmanager
def collect_accesses_for_function(function_addr: int) -> Iterator[EvidenceCollection8616]:
    """Capture semantic accesses for one function without process-global address keys."""
    if not isinstance(function_addr, int):
        raise TypeError("function_addr must be an integer")
    collection = EvidenceCollection8616(function_addr=function_addr)
    token = _active_collection.set(collection)
    try:
        yield collection
    finally:
        _active_collection.reset(token)


def get_current_function_addr() -> int | None:
    """Return the function owned by the active evidence collection, if any."""
    collection = _active_collection.get()
    return collection.function_addr if collection is not None else None


def record_access(
    function_addr: int,
    mode: int,
    addr: object,
    *,
    insn_addr: int | None = None,
) -> None:
    """Record an access only when the active collection owns the function."""
    collection = _active_collection.get()
    if collection is None or collection.function_addr != function_addr:
        return
    collection.accesses.append(
        AccessRecord8616(
            function_addr=function_addr,
            insn_addr=insn_addr,
            mode=mode,
            addr=addr,
        )
    )
