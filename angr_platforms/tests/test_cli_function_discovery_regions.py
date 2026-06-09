from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.cli_function_discovery import (
    _derive_lst_exact_region_8616,
    _should_replace_function_with_stitched_graph_8616,
)


class _Memory:
    def __init__(self, data: bytes, base: int):
        self._data = data
        self._base = base

    def load(self, addr: int, size: int) -> bytes:
        start = addr - self._base
        return self._data[start : start + size]


def test_derive_lst_exact_region_skips_leading_x86_16_padding_to_prologue():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func"},
        code_ranges={0x1000: (0x1000, 0x1019)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=0x1018),
            memory=_Memory(b"\x90" * 0x15 + b"\x55\x8b\xec\xc3", 0x1000),
        ),
    )

    assert _derive_lst_exact_region_8616(project, metadata, addr=0x1000, name="Func") == (0x1015, 0x1019)


def test_derive_lst_exact_region_skips_long_sidecar_padding_to_prologue():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func"},
        code_ranges={0x1000: (0x1000, 0x1030)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=0x102F),
            memory=_Memory(b"\x90" * 0x27 + b"\x55\x8b\xec\xc3" + b"\x90" * 5, 0x1000),
        ),
    )

    assert _derive_lst_exact_region_8616(project, metadata, addr=0x1000, name="Func") == (0x1027, 0x1030)


def test_stitched_graph_replaces_overlapped_cfg_when_unique_coverage_is_preserved():
    current = SimpleNamespace(
        blocks=(
            SimpleNamespace(addr=0x1009, size=0x17),
            SimpleNamespace(addr=0x1010, size=0x10),
        )
    )
    reachable = {
        0x1009: SimpleNamespace(addr=0x1009, size=0x7, bytes=b"\x90" * 0x7),
        0x1010: SimpleNamespace(addr=0x1010, size=0x10, bytes=b"\x90" * 0x10),
    }

    assert _should_replace_function_with_stitched_graph_8616(current, reachable, (0x1009, 0x1020)) is True
