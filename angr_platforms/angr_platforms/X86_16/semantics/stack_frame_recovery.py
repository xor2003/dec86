"""Stack frame recovery — detects BP-frame usage and normalizes stack accesses.

AGENTS rule: SS:BP+offset → stack slot → variable (REQUIRED).
This must happen BEFORE alias sees the IR addresses.

Pipeline position:
    IR (raw) → stack_frame_recovery → normalized IR → Alias
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Any

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..pipeline.errors import PipelineHardError


@dataclass(frozen=True)
class StackFrameInfo8616:
    function_addr: int | None
    uses_bp_frame: bool
    bp_established: bool = True
    frame_base: str | None = "bp"
    evidence: tuple[str, ...] = ()


def _is_ss(addr: object) -> bool:
    return isinstance(addr, IRAddress) and addr.space == MemSpace.SS


def _is_bp_stable(addr: IRAddress) -> bool:
    return (
        addr.space == MemSpace.SS
        and addr.base == ("bp",)
        and isinstance(addr.offset, int)
        and addr.status == AddressStatus.STABLE
    )


def _looks_like_frame_evidence(obj: object) -> bool:
    """
    Conservative helper. Prefer real IR/CFG facts. This fallback exists only for
    structured artifacts that already expose instruction semantics.
    """
    text = str(obj).lower()
    return (
        ("push" in text and "bp" in text)
        or ("mov" in text and "bp" in text and "sp" in text)
        or ("enter" in text)
    )


def detect_stack_frame_8616(
    *,
    function_addr: int | None = None,
    ir_artifacts: Iterable[object] = (),
    semantic_accesses: Iterable[tuple[int, IRAddress]] = (),
) -> StackFrameInfo8616:
    evidence: list[str] = []

    for _mode, addr in semantic_accesses:
        if _is_ss(addr) and addr.base == ("bp",):
            evidence.append("ss:bp semantic access")
            return StackFrameInfo8616(
                function_addr=function_addr,
                uses_bp_frame=True,
                bp_established=True,
                frame_base="bp",
                evidence=tuple(evidence),
            )

    for artifact in ir_artifacts:
        if _looks_like_frame_evidence(artifact):
            evidence.append("frame setup instruction evidence")
            return StackFrameInfo8616(
                function_addr=function_addr,
                uses_bp_frame=True,
                bp_established=True,
                frame_base="bp",
                evidence=tuple(evidence),
            )

    return StackFrameInfo8616(
        function_addr=function_addr,
        uses_bp_frame=False,
        bp_established=False,
        frame_base=None,
        evidence=(),
    )


def compute_bp_offset(addr: IRAddress, frame: StackFrameInfo8616) -> int | None:
    """
    Exact rule:
      - SS:BP+const is already canonical.
      - SS:SP/SS+const must NOT be guessed into BP unless frame evidence exists.
      - Unknown symbolic/provisional SS remains unresolved.

    This function intentionally does not invent local/arg meaning.
    It only converts proven numeric SS offsets into a BP-based stack identity
    when the function has a proven BP frame.
    """
    if not isinstance(addr, IRAddress) or addr.space != MemSpace.SS:
        return None

    if not isinstance(addr.offset, int):
        return None

    if addr.base == ("bp",):
        return addr.offset

    if not frame.uses_bp_frame or not frame.bp_established:
        return None

    if addr.base in {("ss",), ("sp",), ()}:
        return addr.offset

    return None


def normalize_stack_address_8616(addr: IRAddress, frame: StackFrameInfo8616) -> IRAddress:
    if not isinstance(addr, IRAddress):
        return addr

    if addr.space != MemSpace.SS:
        return addr

    if _is_bp_stable(addr):
        return addr

    bp_offset = compute_bp_offset(addr, frame)
    if bp_offset is None:
        return addr

    return IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=bp_offset,
        size=addr.size,
        status=AddressStatus.STABLE,
        segment_origin=addr.segment_origin
        if addr.segment_origin is not None
        else SegmentOrigin.PROVEN,
        expr=addr.expr,
    )


def normalize_semantic_accesses_8616(
    semantic_accesses: Iterable[tuple[int, IRAddress]],
    frame: StackFrameInfo8616,
) -> list[tuple[int, IRAddress]]:
    normalized: list[tuple[int, IRAddress]] = []
    for mode, addr in semantic_accesses:
        if isinstance(addr, IRAddress):
            addr = normalize_stack_address_8616(addr, frame)
        normalized.append((mode, addr))
    return normalized


def assert_no_unresolved_stable_ss_before_alias_8616(
    semantic_accesses: Iterable[tuple[int, IRAddress]],
) -> None:
    for _mode, addr in semantic_accesses:
        if not isinstance(addr, IRAddress) or addr.space != MemSpace.SS:
            continue

        if addr.status == AddressStatus.STABLE and addr.base != ("bp",):
            raise PipelineHardError(
                f"stable SS address is not BP-relative before alias: "
                f"base={addr.base} offset={addr.offset}",
                layer="semantics.stack_frame_recovery",
            )


__all__ = [
    "StackFrameInfo8616",
    "detect_stack_frame_8616",
    "compute_bp_offset",
    "normalize_stack_address_8616",
    "normalize_semantic_accesses_8616",
    "assert_no_unresolved_stable_ss_before_alias_8616",
]