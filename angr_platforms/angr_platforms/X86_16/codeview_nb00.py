from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class CodeViewSubsectionType(IntEnum):
    MODULES = 0x101
    PUBLICS = 0x102
    TYPE = 0x103
    SYMBOLS = 0x104
    SRCLINES = 0x105
    LIBRARIES = 0x106
    COMPACTED = 0x108
    SRCLNSEG = 0x109


@dataclass(frozen=True)
class CodeViewDirectoryEntry:
    subsection_type: int
    module_index: int
    data_offset: int
    data_size: int


@dataclass(frozen=True)
class CodeViewNB00Module:
    module_index: int
    cs_base: int
    cs_offset: int
    cs_length: int
    overlay_number: int
    library_index: int
    segment_count: int
    name: str

    def linear_range(self, *, load_base_linear: int) -> tuple[int, int]:
        start = load_base_linear + (self.cs_base << 4) + self.cs_offset
        return start, start + self.cs_length


@dataclass(frozen=True)
class CodeViewNB00PublicSymbol:
    module_index: int
    offset: int
    segment: int
    type_index: int
    name: str

    def linear_addr(self, *, load_base_linear: int) -> int:
        return load_base_linear + (self.segment << 4) + self.offset


@dataclass(frozen=True)
class CodeViewNB00Info:
    version: str
    debug_base: int
    subsection_directory_offset: int
    modules: tuple[CodeViewNB00Module, ...]
    publics: tuple[CodeViewNB00PublicSymbol, ...]
    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)
    code_ranges: dict[int, tuple[int, int]] = field(default_factory=dict)


def find_codeview_nb00(data: bytes) -> tuple[str, int, int] | None:
    for trailer_offset in range(len(data) - 8, max(-1, len(data) - 256), -1):
        signature, debug_offset = struct.unpack_from("<4sI", data, trailer_offset)
        if not signature.startswith(b"NB0"):
            continue
        debug_base = trailer_offset + 8 - debug_offset
        if debug_base < 0 or debug_base + 8 > len(data):
            continue
        root_sig, subdir_offset = struct.unpack_from("<4sI", data, debug_base)
        if root_sig != b"NB00":
            continue
        return signature.decode("ascii", errors="ignore"), debug_base, debug_base + subdir_offset
    return None


def parse_codeview_nb00(path: Path, *, load_base_linear: int = 0) -> CodeViewNB00Info | None:
    return parse_codeview_nb00_bytes(path.read_bytes(), load_base_linear=load_base_linear)


def parse_codeview_nb00_bytes(data: bytes, *, load_base_linear: int = 0) -> CodeViewNB00Info | None:
    located = find_codeview_nb00(data)
    if located is None:
        return None
    version, debug_base, subsection_directory_offset = located
    directory_entries = _read_subsection_directory(data, subsection_directory_offset)

    modules: dict[int, CodeViewNB00Module] = {}
    publics: list[CodeViewNB00PublicSymbol] = []
    for entry in directory_entries:
        blob = data[debug_base + entry.data_offset : debug_base + entry.data_offset + entry.data_size]
        if entry.subsection_type == CodeViewSubsectionType.MODULES:
            module = _parse_module_subsection(entry.module_index, blob)
            modules[module.module_index] = module
        elif entry.subsection_type == CodeViewSubsectionType.PUBLICS:
            publics.extend(_parse_publics_subsection(entry.module_index, blob))

    code_ranges = _synthesize_code_ranges(tuple(modules.values()), tuple(publics), load_base_linear=load_base_linear)
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    module_ranges = tuple(
        (module.linear_range(load_base_linear=load_base_linear), module.module_index) for module in modules.values()
    )

    for symbol in publics:
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        name = symbol.name.lstrip("_")
        if _public_is_code_symbol(symbol, linear=linear, module_ranges=module_ranges):
            code_labels.setdefault(linear, name)
        else:
            data_labels.setdefault(linear, symbol.name)

    return CodeViewNB00Info(
        version=version,
        debug_base=debug_base,
        subsection_directory_offset=subsection_directory_offset,
        modules=tuple(sorted(modules.values(), key=lambda item: item.module_index)),
        publics=tuple(publics),
        code_labels=code_labels,
        data_labels=data_labels,
        code_ranges=code_ranges,
    )


def _read_subsection_directory(data: bytes, subsection_directory_offset: int) -> tuple[CodeViewDirectoryEntry, ...]:
    if subsection_directory_offset < 0 or subsection_directory_offset + 2 > len(data):
        raise ValueError("invalid CodeView subsection directory offset")
    count = struct.unpack_from("<H", data, subsection_directory_offset)[0]
    offset = subsection_directory_offset + 2
    entries: list[CodeViewDirectoryEntry] = []
    for _ in range(count):
        if offset + 10 > len(data):
            break
        subsection_type, module_index, data_offset, data_size = struct.unpack_from("<HHLH", data, offset)
        entries.append(
            CodeViewDirectoryEntry(
                subsection_type=subsection_type,
                module_index=module_index,
                data_offset=data_offset,
                data_size=data_size,
            )
        )
        offset += 10
    return tuple(entries)


def _parse_module_subsection(module_index: int, blob: bytes) -> CodeViewNB00Module:
    if len(blob) < 9:
        raise ValueError("short NB00 module subsection")
    cs_base, cs_offset, cs_length, overlay_number, library_index, segment_count, _, name_length = struct.unpack_from(
        "<HHHHHBBB", blob
    )
    name_bytes = blob[-name_length:] if name_length <= len(blob) else b""
    return CodeViewNB00Module(
        module_index=module_index,
        cs_base=cs_base,
        cs_offset=cs_offset,
        cs_length=cs_length,
        overlay_number=overlay_number,
        library_index=library_index,
        segment_count=segment_count,
        name=name_bytes.decode("ascii", errors="ignore"),
    )


def _parse_publics_subsection(module_index: int, blob: bytes) -> tuple[CodeViewNB00PublicSymbol, ...]:
    publics: list[CodeViewNB00PublicSymbol] = []
    offset = 0
    while offset + 7 <= len(blob):
        symbol_offset, segment, type_index, name_length = struct.unpack_from("<HHHB", blob, offset)
        offset += 7
        name_bytes = blob[offset : offset + name_length]
        offset += name_length
        publics.append(
            CodeViewNB00PublicSymbol(
                module_index=module_index,
                offset=symbol_offset,
                segment=segment,
                type_index=type_index,
                name=name_bytes.decode("ascii", errors="ignore"),
            )
        )
    return tuple(publics)


def _public_is_code_symbol(
    symbol: CodeViewNB00PublicSymbol,
    *,
    linear: int,
    module_ranges: tuple[tuple[tuple[int, int], int], ...],
) -> bool:
    if symbol.segment == 0:
        return True
    for (start, end), _module_index in module_ranges:
        if start <= linear < end:
            return True
    return False


def _synthesize_code_ranges(
    modules: tuple[CodeViewNB00Module, ...],
    publics: tuple[CodeViewNB00PublicSymbol, ...],
    *,
    load_base_linear: int,
) -> dict[int, tuple[int, int]]:
    module_ranges = {
        module.module_index: module.linear_range(load_base_linear=load_base_linear)
        for module in modules
        if module.cs_length > 0
    }
    by_module: dict[int, list[int]] = {}
    for symbol in publics:
        if symbol.segment != 0 and symbol.module_index not in module_ranges:
            continue
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        module_range = module_ranges.get(symbol.module_index)
        if module_range is None or not (module_range[0] <= linear < module_range[1]):
            continue
        by_module.setdefault(symbol.module_index, []).append(linear)

    ranges: dict[int, tuple[int, int]] = {}
    for module_index, starts in by_module.items():
        start_end = module_ranges[module_index][1]
        ordered = sorted(set(starts))
        for index, start in enumerate(ordered):
            end = ordered[index + 1] if index + 1 < len(ordered) else start_end
            if start < end:
                ranges[start] = (start, end)
    return ranges
