from __future__ import annotations

__all__ = ["REG16_OFFSET_MAP", "register_name_from_offset", "segment_space_for_base"]


REG16_OFFSET_MAP = {
    8: "ax",
    10: "cx",
    12: "dx",
    14: "bx",
    16: "sp",
    18: "bp",
    20: "si",
    22: "di",
}


def register_name_from_offset(offset: int) -> str:
    return REG16_OFFSET_MAP.get(int(offset), f"r{offset}")


def segment_space_for_base(name: str | None) -> str:
    if name in {"bp", "sp"}:
        return "ss"
    if name == "di":
        return "es"
    if name in {"si", "bx"}:
        return "ds"
    return "unknown"
