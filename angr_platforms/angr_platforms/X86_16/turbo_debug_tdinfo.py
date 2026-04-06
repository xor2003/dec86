from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
import struct


_TDINFO_MAGIC = 0x52FB
_PAGE_SIZE = 512


class TDInfoSymbolClass(IntEnum):
    STATIC = 0
    ABSOLUTE = 1
    AUTO = 2
    PASCAL_VAR = 3
    REGISTER = 4
    CONSTANT = 5
    TYPEDEF = 6
    STRUCT_UNION_OR_ENUM = 7


@dataclass(frozen=True)
class TDInfoHeader:
    major_version: int
    minor_version: int
    names_pool_size_in_bytes: int
    names_count: int
    types_count: int
    members_count: int
    symbols_count: int
    globals_count: int
    extension_size: int


@dataclass(frozen=True)
class TDInfoSymbolRecord:
    index: int
    type_index: int
    offset: int
    segment: int
    symbol_class: TDInfoSymbolClass

    def linear_addr(self, *, load_base_linear: int) -> int:
        return load_base_linear + (self.segment << 4) + self.offset


@dataclass(frozen=True)
class TDInfoEXEInfo:
    header: TDInfoHeader
    debug_info_offset: int
    symbols: tuple[TDInfoSymbolRecord, ...]
    names: tuple[str, ...]
    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)


def parse_tdinfo_exe(path: Path, *, load_base_linear: int = 0) -> TDInfoEXEInfo | None:
    return parse_tdinfo_exe_bytes(path.read_bytes(), load_base_linear=load_base_linear)


def parse_tdinfo_exe_bytes(data: bytes, *, load_base_linear: int = 0) -> TDInfoEXEInfo | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    used_bytes_in_last_page, file_size_in_pages = struct.unpack_from("<HH", data, 2)
    if file_size_in_pages == 0:
        return None
    used_bytes = used_bytes_in_last_page or _PAGE_SIZE
    debug_info_offset = file_size_in_pages * _PAGE_SIZE - (_PAGE_SIZE - used_bytes)
    if debug_info_offset < 0 or debug_info_offset + 44 > len(data):
        return None

    magic_number = struct.unpack_from("<H", data, debug_info_offset)[0]
    if magic_number != _TDINFO_MAGIC:
        return None

    (
        _magic,
        minor_version,
        major_version,
        names_pool_size_in_bytes,
        names_count,
        types_count,
        members_count,
        symbols_count,
        globals_count,
    ) = struct.unpack_from("<HBBIHHHHH", data, debug_info_offset)
    extension_size = struct.unpack_from("<H", data, debug_info_offset + 42)[0]
    symbol_records_offset = debug_info_offset + 44 + extension_size
    if symbol_records_offset + symbols_count * 9 > len(data):
        return None
    names_pool_offset = len(data) - names_pool_size_in_bytes
    if names_pool_offset < symbol_records_offset or names_pool_offset < 0:
        return None

    header = TDInfoHeader(
        major_version=major_version,
        minor_version=minor_version,
        names_pool_size_in_bytes=names_pool_size_in_bytes,
        names_count=names_count,
        types_count=types_count,
        members_count=members_count,
        symbols_count=symbols_count,
        globals_count=globals_count,
        extension_size=extension_size,
    )
    names = _parse_tdinfo_name_pool(data[names_pool_offset:], expected_count=names_count)

    symbols: list[TDInfoSymbolRecord] = []
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    for index in range(symbols_count):
        entry_offset = symbol_records_offset + index * 9
        name_index, type_index, offset, segment, bitfield = struct.unpack_from("<HHHHB", data, entry_offset)
        symbol_class = TDInfoSymbolClass(bitfield & 0x7)
        symbol = TDInfoSymbolRecord(
            index=name_index,
            type_index=type_index,
            offset=offset,
            segment=segment,
            symbol_class=symbol_class,
        )
        symbols.append(symbol)
        if symbol.symbol_class is not TDInfoSymbolClass.STATIC:
            continue
        if not (1 <= symbol.index <= len(names)):
            continue
        name = names[symbol.index - 1]
        if not name or name == "?":
            continue
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        if _tdinfo_name_looks_like_code(name):
            code_labels.setdefault(linear, name.lstrip("_"))
        else:
            data_labels.setdefault(linear, name)

    return TDInfoEXEInfo(
        header=header,
        debug_info_offset=debug_info_offset,
        symbols=tuple(symbols),
        names=names,
        code_labels=code_labels,
        data_labels=data_labels,
    )


def _parse_tdinfo_name_pool(data: bytes, *, expected_count: int) -> tuple[str, ...]:
    names: list[str] = []
    for raw_name in data.split(b"\x00"):
        if len(names) >= expected_count:
            break
        names.append(raw_name.decode("ascii", errors="ignore"))
    while len(names) < expected_count:
        names.append("")
    return tuple(names)


def _tdinfo_name_looks_like_code(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(("dgroup@", "byte_", "word_", "dword_", "off_", "stru_")):
        return False
    return True
