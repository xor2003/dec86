"""Normalize only width-proven identity masks in condition fingerprints.

Layer: IR.
Responsibility: owns lossless full-width mask identities for typed Condition
fingerprints and local Value canonicalization.
Consumes only explicit byte widths already carried by IR-owned tokens. It does
not recover widths from rendered C, names, compiler patterns, or sample data.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import re

__all__ = (
    "is_proven_full_width_mask_8616",
    "normalize_condition_full_width_masks_8616",
)

_EXPLICIT_SIZE_RE_8616 = re.compile(r"(?:^|:)size(?P<size>[1-9][0-9]*)(?=:|$)")
_CONTROL_FLOW_PREFIXES_8616 = (
    "if:",
    "ifbreak:",
    "while:",
    "dowhile:",
    "for:",
    "switch:",
)


def is_proven_full_width_mask_8616(mask: int, width_bytes: int | None) -> bool:
    """Return whether ``mask`` preserves every bit of a proven-width value."""
    if mask == -1:
        return True
    if not isinstance(width_bytes, int) or width_bytes <= 0:
        return False
    return mask == (1 << (width_bytes * 8)) - 1


def normalize_condition_full_width_masks_8616(value: str) -> str:
    """Remove identity ``And`` masks only when an operand states its byte width.

    Fingerprints are an internal IR/validation transport contract. An atom such
    as ``stack_slot:SS:BP-0x2:size2`` proves its width; an atom without exactly
    one explicit ``sizeN`` token is left unchanged.
    """
    for prefix in _CONTROL_FLOW_PREFIXES_8616:
        if value.startswith(prefix):
            return prefix + normalize_condition_full_width_masks_8616(value[len(prefix) :])

    call = _split_call_8616(value)
    if call is None:
        return value
    op, args_text = call
    args = tuple(normalize_condition_full_width_masks_8616(arg) for arg in _split_args_8616(args_text))
    if op == "And" and len(args) == 2:
        for operand, mask_token in ((args[0], args[1]), (args[1], args[0])):
            mask = _constant_value_8616(mask_token)
            width_bytes = _explicit_atom_width_bytes_8616(operand)
            if isinstance(mask, int) and is_proven_full_width_mask_8616(mask, width_bytes):
                return operand
    return f"{op}({','.join(args)})"


def _explicit_atom_width_bytes_8616(value: str) -> int | None:
    if _split_call_8616(value) is not None:
        return None
    sizes = tuple(int(match.group("size"), 10) for match in _EXPLICIT_SIZE_RE_8616.finditer(value))
    if len(sizes) != 1:
        return None
    return sizes[0]


def _constant_value_8616(value: str) -> int | None:
    if not value.startswith("const:"):
        return None
    try:
        return int(value[len("const:") :], 0)
    except ValueError:
        return None


def _split_call_8616(value: str) -> tuple[str, str] | None:
    if not value.endswith(")"):
        return None
    open_index = value.find("(")
    if open_index <= 0:
        return None
    return value[:open_index], value[open_index + 1 : -1]


def _split_args_8616(value: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for character in value:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if current:
        parts.append("".join(current).strip())
    return tuple(parts)
