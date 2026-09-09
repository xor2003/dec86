"""Classify exact leaf sources for modular scalar tracing.

Layer: IR.
Responsibility: distinguish proven stack loads from function-entry register
values without inferring aliases, pointer types or cross-block origins.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .scalar_affine_contracts import ScalarAffineEntryRegister8616, ScalarAffineTerm8616


def stack_affine_source_8616(instruction: IRInstr, width: int) -> IRAddress | None:
    """Return one exact direct BP-relative scalar LOAD source."""
    address = instruction.args[0] if instruction.args else None
    if (
        instruction.op != "LOAD" or instruction.size != width
        or not isinstance(address, IRAddress)
        or address.space is not MemSpace.SS or address.base != ("bp",)
        or address.size != width or address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
    ):
        return None
    return address


def entry_register_affine_term_8616(
    value: IRValue, *, function_addr: int, block_addr: int,
) -> ScalarAffineTerm8616 | None:
    """Prove an entry SP/BP root, never a block-local live-in at a later block."""
    if block_addr != function_addr or value.name not in {"sp", "bp"}:
        return None
    source = ScalarAffineEntryRegister8616(function_addr, value.name, value.size)
    term = ScalarAffineTerm8616(value, source, 1)
    return term if term.complete else None
