"""Register offset and segment-space helpers for IR construction.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

__all__ = ["REG16_OFFSET_MAP", "register_name_from_offset", "segment_space_for_base"]


REG16_OFFSET_MAP: dict[int, str] = {
    0: "ax",
    2: "cx",
    4: "dx",
    6: "bx",
    8: "sp",
    10: "bp",
    12: "si",
    14: "di",
    16: "ip",
    18: "flags",
    20: "cs",
    22: "ds",
    24: "es",
    26: "fs",
    28: "gs",
    30: "ss",
}


def register_name_from_offset(offset: int) -> str:
    """Return the 16-bit register name for a VEX register offset."""
    return REG16_OFFSET_MAP.get(int(offset), f"r{offset}")


def segment_space_for_base(name: str | None) -> str:
    """Return the default segment space implied by a base register name."""
    if name in {"bp", "sp"}:
        return "ss"
    if name == "di":
        return "es"
    if name in {"si", "bx"}:
        return "ds"
    return "unknown"
