"""Build relocatable analysis images from optional COD instruction rows.

Layer: Frontend.
Responsibility: preserve listed instruction bytes while assigning synthetic
targets to named direct calls whose linker relocations are absent from COD.
The resulting labels are optional naming evidence; call arguments and effects
must still be recovered from binary IR and typed pipeline facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .cod_extract import join_cod_entries_with_synthetic_globals
from .cod_known_objects import canonical_known_cod_object_name

__all__ = ["CODAnalysisImage8616", "build_cod_analysis_image_8616"]

_DIRECT_NEAR_CALL_RE = re.compile(r"\bcall\s+(?P<name>[A-Za-z_$?@][\w$?@]*)\b", re.IGNORECASE)
_INSTRUCTION_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF2, 0xF3})


@dataclass(frozen=True, slots=True)
class CODAnalysisImage8616:
    """One synthetic COD code image plus proven labels for its storage."""

    code: bytes
    synthetic_globals: dict[int, tuple[str, int]]
    call_target_offsets: dict[int, str]


def _entry_offset_8616(entry: dict[str, object]) -> int | None:
    """Return one typed COD instruction offset."""
    offset = entry.get("offset")
    return offset if isinstance(offset, int) else None


def _entry_bytes_8616(entry: dict[str, object]) -> bytes | None:
    """Return one typed COD instruction byte string."""
    data = entry.get("bytes")
    return data if isinstance(data, bytes) else None


def _selected_entries_8616(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None,
    end_offset: int | None,
) -> tuple[dict[str, object], ...]:
    """Select the same ordered COD rows used by the byte-image joiner."""
    return tuple(
        entry
        for entry in entries
        if (offset := _entry_offset_8616(entry)) is not None
        and (start_offset is None or offset >= start_offset)
        and (end_offset is None or offset < end_offset)
        and _entry_bytes_8616(entry) is not None
    )


def _near_call_prefix_length_8616(data: bytes) -> int | None:
    """Return the prefix length when one instruction is a direct near call."""
    prefix_length = 0
    while prefix_length < len(data) and data[prefix_length] in _INSTRUCTION_PREFIXES:
        prefix_length += 1
    if prefix_length + 3 != len(data) or data[prefix_length] != 0xE8:
        return None
    return prefix_length


def _canonical_call_name_8616(raw_name: str) -> str:
    """Return a readable optional label for one exact COD call operand."""
    return canonical_known_cod_object_name(raw_name) or raw_name.lstrip("_")


def build_cod_analysis_image_8616(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None = None,
    end_offset: int | None = None,
) -> CODAnalysisImage8616:
    """Build a COD image whose named direct calls cannot target fallthrough."""
    joined, synthetic_globals = join_cod_entries_with_synthetic_globals(
        entries,
        start_offset=start_offset,
        end_offset=end_offset,
    )
    selected_entries = _selected_entries_8616(
        entries,
        start_offset=start_offset,
        end_offset=end_offset,
    )
    calls: list[tuple[int, int, str]] = []
    cursor = 0
    for entry in selected_entries:
        data = _entry_bytes_8616(entry)
        if data is None:
            continue
        prefix_length = _near_call_prefix_length_8616(data)
        call_match = _DIRECT_NEAR_CALL_RE.search(str(entry.get("text", "")))
        if prefix_length is not None and call_match is not None:
            calls.append((cursor, prefix_length, _canonical_call_name_8616(call_match.group("name"))))
        cursor += len(data)
    if cursor != len(joined):
        raise ValueError("COD analysis-image row lengths do not match joined bytes")

    call_names = tuple(dict.fromkeys(name for _cursor, _prefix_length, name in calls))
    stub_offsets = {name: len(joined) + index for index, name in enumerate(call_names)}
    patched = bytearray(joined)
    for call_offset, prefix_length, name in calls:
        displacement_offset = call_offset + prefix_length + 1
        next_instruction = displacement_offset + 2
        displacement = stub_offsets[name] - next_instruction
        patched[displacement_offset : displacement_offset + 2] = (displacement & 0xFFFF).to_bytes(2, "little")
    patched.extend(b"\xc3" * len(call_names))
    return CODAnalysisImage8616(
        code=bytes(patched),
        synthetic_globals=synthetic_globals,
        call_target_offsets={offset: name for name, offset in stub_offsets.items()},
    )
