from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

import inertia_decompiler.cli_function_discovery as function_discovery
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


def test_recover_lst_function_keeps_callable_entry_for_rebased_return_use(monkeypatch):
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func"},
        code_ranges={0x1000: (0x1000, 0x1010)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(entry=0, arch=SimpleNamespace(name="86_16"))
    recovered = SimpleNamespace(name="recovered")
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        function_discovery,
        "_derive_lst_exact_region_8616",
        lambda *_args, **_kwargs: (0x1003, 0x1010),
    )

    def fake_rebased_recovery(_project, **kwargs):
        observed.update(kwargs)
        return recovered

    monkeypatch.setattr(
        function_discovery,
        "_try_rebased_exact_region_recovery_8616",
        fake_rebased_recovery,
    )

    result = function_discovery._recover_lst_function(
        project,
        metadata,
        0x1000,
        "Func",
        timeout=1,
        window=0x20,
    )

    assert result is recovered
    assert observed["exact_region"] == (0x1003, 0x1010)
    assert observed["caller_target_addrs"] == (0x1000,)


def test_recover_lst_function_keeps_label_alias_when_recovery_starts_after_padding(monkeypatch):
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x102CC: "RunMenu"},
        code_ranges={0x102CC: (0x102CC, 0x10491)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(entry=0, arch=SimpleNamespace(name="86_16"))
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        function_discovery,
        "_derive_lst_exact_region_8616",
        lambda *_args, **_kwargs: (0x102E0, 0x10491),
    )

    def fake_rebased_recovery(_project, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(name="recovered")

    monkeypatch.setattr(
        function_discovery,
        "_try_rebased_exact_region_recovery_8616",
        fake_rebased_recovery,
    )

    function_discovery._recover_lst_function(
        project,
        metadata,
        0x102E0,
        "RunMenu",
        timeout=1,
        window=0x200,
    )

    assert observed["caller_target_addrs"] == (0x102E0, 0x102CC)


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
