"""Detect stub-packed DOS MZ executables from their header and entry stub.

Layer: CLI/fallback/reporting.
Responsibility: classify known DOS packers (LZEXE, PKLITE, EXEPACK, UPX) for loader policy and
reporting, from exact header signatures first and entry-stub text second.
Forbidden: unpacking, guessing image contents, or any semantic recovery.

Strategy:

1. Header signatures (confidence 1.0): ``LZ90``/``LZ91`` at offset 0x1C, the ``PKLITE`` banner inside
   the header area before the relocation table, and the EXEPACK ``RB`` marker right below ``CS:0``.
2. Entry-region text (confidence 0.8): packer banners within 2 KiB of the entry stub.

Nothing else is scanned: packer stubs always live at the entry point, and scanning whole files for
ASCII banners produced false positives on source text and string tables.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

__all__ = [
    "PackerDetection",
    "PackerType",
    "detect_packer",
    "detect_packer_in_bytes",
    "get_packer_name",
    "is_packed",
]

_ENTRY_REGION_RADIUS: int = 2048


class PackerType(Enum):
    """Known DOS packer families."""

    PKLITE = "PKLITE"
    LZEXE = "LZEXE"
    EXEPACK = "EXEPACK"
    UPX = "UPX"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class PackerDetection:
    """Result of packer detection."""

    packer_type: PackerType
    signature: str
    offset: int
    scan_region: str
    confidence: float

    @property
    def label(self) -> str:
        """Return the packer name with its version suffix when the signature carries one."""
        if self.packer_type is PackerType.LZEXE and self.signature in {"LZ90", "LZ91"}:
            return f"LZEXE 0.{self.signature[2:]}"
        return self.packer_type.value


@dataclass(frozen=True, slots=True)
class _MZHeaderView:
    header_paragraphs: int
    entry_cs: int
    entry_ip: int
    relocation_offset: int
    relocation_count: int

    @classmethod
    def parse(cls, data: bytes) -> _MZHeaderView | None:
        """Parse the MZ header words needed for packer detection, or return ``None`` for non-MZ data."""
        if len(data) < 0x1C or data[:2] not in (b"MZ", b"ZM"):
            return None
        (_last_page, _pages, relocation_count, header_paragraphs, _min_alloc, _max_alloc, _ss, _sp, _checksum, ip, cs, relocation_offset) = struct.unpack_from("<12H", data, 2)
        return cls(
            header_paragraphs=header_paragraphs,
            entry_cs=cs,
            entry_ip=ip,
            relocation_offset=relocation_offset,
            relocation_count=relocation_count,
        )

    @property
    def header_size(self) -> int:
        """Return the header size in bytes."""
        return self.header_paragraphs * 16

    @property
    def entry_file_offset(self) -> int:
        """Return the file offset of the entry stub (``CS:IP`` relative to the load image)."""
        return self.header_size + ((self.entry_cs << 4) + self.entry_ip) % 0x100000


def _header_signature(data: bytes, header: _MZHeaderView) -> PackerDetection | None:
    tag = data[0x1C:0x20]
    if tag in (b"LZ90", b"LZ91"):
        return PackerDetection(PackerType.LZEXE, tag.decode("ascii"), 0x1C, "header", 1.0)
    banner_end = max(0x1C, min(header.relocation_offset, header.header_size, len(data)))
    banner = data[0x1C:banner_end].upper().find(b"PKLITE")
    if banner >= 0:
        return PackerDetection(PackerType.PKLITE, "PKLITE", 0x1C + banner, "header", 1.0)
    exepack_marker = header.header_size + (header.entry_cs << 4) - 2
    if 0 <= exepack_marker and exepack_marker + 2 <= len(data) and data[exepack_marker : exepack_marker + 2] == b"RB":
        return PackerDetection(PackerType.EXEPACK, "RB", exepack_marker, "header", 1.0)
    return None


def _entry_region_signature(data: bytes, header: _MZHeaderView) -> PackerDetection | None:
    entry = header.entry_file_offset
    start = max(0, entry - _ENTRY_REGION_RADIUS)
    end = min(len(data), entry + _ENTRY_REGION_RADIUS)
    region = data[start:end]
    for needle, packer in ((b"PKLITE", PackerType.PKLITE), (b"UPX!", PackerType.UPX), (b"LZ91", PackerType.LZEXE), (b"LZ90", PackerType.LZEXE)):
        position = region.upper().find(needle) if packer is PackerType.PKLITE else region.find(needle)
        if position >= 0:
            return PackerDetection(packer, needle.decode("ascii"), start + position, "entry", 0.8)
    return None


def detect_packer_in_bytes(data: bytes) -> PackerDetection | None:
    """Detect a known packer from the bytes of a DOS MZ executable."""
    header = _MZHeaderView.parse(data)
    if header is None:
        return None
    return _header_signature(data, header) or _entry_region_signature(data, header)


def detect_packer(binary_path: Path) -> PackerDetection | None:
    """Detect a known packer from a DOS MZ executable file."""
    try:
        data = binary_path.read_bytes()
    except OSError:
        return None
    return detect_packer_in_bytes(data)


def is_packed(binary_path: Path) -> bool:
    """Return whether a DOS EXE is packed by a known packer."""
    return detect_packer(binary_path) is not None


def get_packer_name(binary_path: Path) -> str | None:
    """Return the human-readable packer label (e.g. ``"PKLITE"``, ``"LZEXE 0.91"``) or ``None``."""
    detection = detect_packer(binary_path)
    return detection.label if detection is not None else None
