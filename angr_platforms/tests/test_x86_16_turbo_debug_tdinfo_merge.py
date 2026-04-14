from __future__ import annotations

import struct

from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoSymbolClass, parse_tdinfo_exe_bytes


def _build_minimal_tdinfo_image() -> bytes:
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    name_pool = b"func\x00MYTYPE\x00"
    data.extend(b"\x00" * 96)
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        1,
        3,
        len(name_pool),
        2,
        0,
        0,
        2,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    sym_off = debug_offset + 44
    struct.pack_into("<HHHHB", data, sym_off, 1, 0, 0x10, 0x20, TDInfoSymbolClass.STATIC)
    struct.pack_into("<HHHHB", data, sym_off + 9, 2, 0, 0, 0, TDInfoSymbolClass.TYPEDEF)
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_exposes_symbol_classes_and_type_names():
    parsed = parse_tdinfo_exe_bytes(_build_minimal_tdinfo_image())

    assert parsed is not None
    assert parsed.type_names == ("MYTYPE",)
    assert TDInfoSymbolClass.STATIC in parsed.symbols_by_class
    assert TDInfoSymbolClass.TYPEDEF in parsed.symbols_by_class
    assert parsed.code_labels
