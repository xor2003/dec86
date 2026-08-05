from __future__ import annotations

from angr_platforms.X86_16.cod_analysis_image import build_cod_analysis_image_8616


def test_cod_analysis_image_relocates_named_call_away_from_fallthrough() -> None:
    entries: list[dict[str, object]] = [
        {"offset": 0x10, "bytes": b"\x50", "text": "push ax"},
        {"offset": 0x11, "bytes": b"\xe8\x00\x00", "text": "call _Message"},
        {"offset": 0x14, "bytes": b"\xc3", "text": "ret"},
    ]

    image = build_cod_analysis_image_8616(entries)

    assert image.code == b"\x50\xe8\x01\x00\xc3\xc3"
    assert image.call_target_offsets == {5: "Message"}


def test_cod_analysis_image_reuses_stub_for_repeated_named_calls() -> None:
    entries: list[dict[str, object]] = [
        {"offset": 0x20, "bytes": b"\xe8\x00\x00", "text": "call _DrawBar"},
        {"offset": 0x23, "bytes": b"\xe8\x00\x00", "text": "call _DrawBar"},
        {"offset": 0x26, "bytes": b"\xc3", "text": "ret"},
    ]

    image = build_cod_analysis_image_8616(entries)

    assert image.code == b"\xe8\x04\x00\xe8\x01\x00\xc3\xc3"
    assert image.call_target_offsets == {7: "DrawBar"}
