"""Classify call-return values stored directly into BP-relative locals.

Layer: Types/Lowering.
Responsibility: join typed callsite summaries to exact scalar stack-store
instructions without deciding structured placement.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: call discovery, name-based proof, AST mutation, or rendered-text
inspection.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..callsite_summary import CallsiteReturnUseKind8616, CallsiteSummary8616

__all__ = [
    "CallReturnStackStoreEvidence8616",
    "ZeroArgCallReturnStackStoreEvidence8616",
    "classify_call_return_stack_store_8616",
    "recover_zero_arg_call_return_stack_store_8616",
]


@dataclass(frozen=True)
class CallReturnStackStoreEvidence8616:
    """Exact typed call return stored into one BP-relative stack object."""

    callsite_addr: int
    target_addr: int
    return_addr: int
    dst_offset: int
    width: int
    source_register_name: str


@dataclass(frozen=True)
class ZeroArgCallReturnStackStoreEvidence8616:
    """Exact zero-argument call return stored through AX or its low byte."""

    callsite_addr: int
    target_addr: int
    store_ins_addr: int
    dst_offset: int
    width: int
    source_register_name: str


def classify_call_return_stack_store_8616(
    summary: CallsiteSummary8616,
) -> CallReturnStackStoreEvidence8616 | None:
    """Classify one exact value-return summary stored into a BP local."""
    destination = summary.return_store_destination
    width = summary.return_store_width
    if not isinstance(width, int):
        return None
    source_register = {1: "al", 2: "ax"}.get(width)
    if (
        not isinstance(summary.target_addr, int)
        or not isinstance(summary.return_addr, int)
        or not isinstance(destination, tuple)
        or len(destination) != 2
        or destination[0] != "bp"
        or not isinstance(destination[1], int)
        or source_register is None
        or summary.return_register != "ax"
        or summary.return_used is not True
        or summary.return_use_kind is not CallsiteReturnUseKind8616.VALUE
    ):
        return None
    return CallReturnStackStoreEvidence8616(
        callsite_addr=summary.callsite_addr,
        target_addr=summary.target_addr,
        return_addr=summary.return_addr,
        dst_offset=destination[1],
        width=width,
        source_register_name=source_register,
    )


def recover_zero_arg_call_return_stack_store_8616(
    inventory: Mapping[int, CallsiteSummary8616] | None,
    *,
    store_ins_addr: int,
    dst_offset: int,
    width: int,
    source_register_name: str | None,
) -> ZeroArgCallReturnStackStoreEvidence8616 | None:
    """Return unique typed evidence for an exact call-return stack store."""
    expected_register = {1: "al", 2: "ax"}.get(width)
    if inventory is None or expected_register is None or source_register_name != expected_register:
        return None
    candidates = tuple(
        summary
        for summary in inventory.values()
        if summary.return_addr == store_ins_addr
        and summary.return_store_destination == ("bp", dst_offset)
        and summary.return_store_width == width
        and summary.return_register == "ax"
        and summary.return_used is True
        and summary.return_use_kind is CallsiteReturnUseKind8616.VALUE
        and summary.arg_count == 0
        and not summary.arg_widths
        and summary.stack_cleanup == 0
        and isinstance(summary.target_addr, int)
    )
    if len(candidates) != 1:
        return None
    summary = candidates[0]
    assert isinstance(summary.target_addr, int)
    return ZeroArgCallReturnStackStoreEvidence8616(
        callsite_addr=summary.callsite_addr,
        target_addr=summary.target_addr,
        store_ins_addr=store_ins_addr,
        dst_offset=dst_offset,
        width=width,
        source_register_name=expected_register,
    )
