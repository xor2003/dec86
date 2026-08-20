from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest
from angr_platforms.X86_16.load_dos_mz import DOSMZHeader
from angr_platforms.X86_16.packed_mz_unpack import (
    MZHeaderFields,
    PackedExecutableUnpackError,
    UnpackedMZImage,
    UnpackFailureKind,
    emulator_available,
    unpack_stub_packed_mz,
)

import decompile
import inertia_decompiler.project_loading as project_loading
from inertia_decompiler.packer_detect import PackerType, detect_packer_in_bytes

# The "decompressed" program: mov ax,0x1234 ; mov dx,0x0001 (segment reference) ; mov ds,dx ; ret
_PROGRAM = bytes.fromhex("b83412" "ba0100" "8eda" "c3")
_PROGRAM_RELOCATION_OFFSET = 4
_PAYLOAD_OFFSET = 0x100
_HIGH_DELTA_PARAGRAPHS = 0x200


def _word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def _self_relocating_stub() -> bytes:
    """An 8086 stub that mimics packer behaviour: move itself up, 'decompress' down, fix a relocation, jump."""
    payload_words = (len(_PROGRAM) + 1) // 2
    relocated = 0x19
    stub = (
        b"\x0e\x1f"                                  # push cs ; pop ds
        + b"\x8c\xc8" + b"\x05" + _word(_HIGH_DELTA_PARAGRAPHS)  # mov ax,cs ; add ax,0x200
        + b"\x8e\xc0"                                # mov es,ax
        + b"\x31\xf6" + b"\x31\xff"                  # xor si,si ; xor di,di
        + b"\xb9" + _word(0x200)                     # mov cx,0x200 (1 KiB)
        + b"\xfc" + b"\xf3\xa5"                      # cld ; rep movsw
        + b"\x06" + b"\xb8" + _word(relocated) + b"\x50" + b"\xcb"  # push es ; mov ax,relocated ; push ax ; retf
    )
    assert len(stub) == relocated
    stub += (
        b"\x0e\x1f"                                  # push cs ; pop ds
        + b"\x8c\xc8" + b"\x2d" + _word(_HIGH_DELTA_PARAGRAPHS)  # mov ax,cs ; sub ax,0x200
        + b"\x8e\xc0"                                # mov es,ax (load segment)
        + b"\xbe" + _word(_PAYLOAD_OFFSET)           # mov si,payload
        + b"\x31\xff"                                # xor di,di
        + b"\xb9" + _word(payload_words)             # mov cx,payload words
        + b"\xf3\xa5"                                # rep movsw
        + b"\x8c\xc0"                                # mov ax,es
        + b"\x26\x01\x06" + _word(_PROGRAM_RELOCATION_OFFSET)  # add [es:reloc],ax
        + b"\x8c\xc0" + b"\x05" + _word(0x10)        # mov ax,es ; add ax,0x10
        + b"\x8e\xd0"                                # mov ss,ax
        + b"\xbc" + _word(0x100)                     # mov sp,0x100
        + b"\x06" + b"\x31\xc0" + b"\x50" + b"\xcb"  # push es ; xor ax,ax ; push ax ; retf -> load:0000
    )
    assert len(stub) <= _PAYLOAD_OFFSET
    return stub.ljust(_PAYLOAD_OFFSET, b"\x90") + _PROGRAM


def _mz(image: bytes, *, header_paragraphs: int, banner_at: int | None, banner: bytes, cs: int = 0, ip: int = 0, ss: int = 0x10, sp: int = 0x100, min_alloc: int = 0x300) -> bytes:
    header = bytearray(header_paragraphs * 16)
    total = len(header) + len(image)
    struct.pack_into("<2s12H", header, 0, b"MZ", total % 512, (total + 511) // 512, 0, header_paragraphs, min_alloc, 0xFFFF, ss, sp, 0, ip, cs, len(header))
    if banner_at is not None:
        header[banner_at : banner_at + len(banner)] = banner
    return bytes(header) + image


def _synthetic_pklite() -> bytes:
    return _mz(_self_relocating_stub(), header_paragraphs=3, banner_at=0x1E, banner=b"PKLITE Copr. 1990-92 PKWARE"[:0x12])


def test_detects_pklite_banner_after_the_version_word():
    detection = detect_packer_in_bytes(_synthetic_pklite())

    assert detection is not None
    assert detection.packer_type is PackerType.PKLITE
    assert detection.offset == 0x1E
    assert detection.confidence == 1.0
    assert detection.label == "PKLITE"


def test_detects_lzexe_exepack_and_entry_region_banners_but_not_plain_mz():
    lzexe = _mz(b"\x90" * 0x20, header_paragraphs=2, banner_at=0x1C, banner=b"LZ91")
    detection = detect_packer_in_bytes(lzexe)
    assert detection is not None and detection.packer_type is PackerType.LZEXE and detection.label == "LZEXE 0.91"

    exepack_image = b"\x00" * 0x1E + b"RB" + b"\x90" * 0x10
    exepack = _mz(exepack_image, header_paragraphs=2, banner_at=None, banner=b"", cs=0x2)
    detection = detect_packer_in_bytes(exepack)
    assert detection is not None and detection.packer_type is PackerType.EXEPACK and detection.signature == "RB"

    upx_image = b"\x90" * 0x40 + b"UPX!" + b"\x90" * 0x40
    upx = _mz(upx_image, header_paragraphs=2, banner_at=None, banner=b"")
    detection = detect_packer_in_bytes(upx)
    assert detection is not None and detection.packer_type is PackerType.UPX and detection.confidence == 0.8

    plain = _mz(_PROGRAM, header_paragraphs=2, banner_at=None, banner=b"")
    assert detect_packer_in_bytes(plain) is None
    assert detect_packer_in_bytes(b"not an executable") is None


def test_mz_header_fields_parse_and_refuse_non_mz():
    fields = MZHeaderFields.parse(_synthetic_pklite())
    assert fields.header_paragraphs == 3
    assert fields.relocation_offset == 0x30
    assert fields.image_size(len(_synthetic_pklite())) == len(_self_relocating_stub())
    with pytest.raises(PackedExecutableUnpackError) as refusal:
        MZHeaderFields.parse(b"PE\x00\x00")
    assert refusal.value.kind is UnpackFailureKind.NOT_MZ


@pytest.mark.skipif(not emulator_available(), reason="unicorn is not installed")
def test_stub_emulation_recovers_program_relocations_and_initial_stack():
    image = unpack_stub_packed_mz(_synthetic_pklite())

    assert image.image[: len(_PROGRAM)] == _PROGRAM
    assert image.relocations == ((0, _PROGRAM_RELOCATION_OFFSET),)
    assert image.stale_stack_words == 1  # the segment pushed for the final retf, below the initial SP
    assert (image.entry_cs, image.entry_ip) == (0, 0)
    assert (image.stack_ss, image.stack_sp) == (0x10, 0x100)
    assert image.stub_segment == _HIGH_DELTA_PARAGRAPHS
    assert len(image.image) == _HIGH_DELTA_PARAGRAPHS * 16
    assert image.emulated_blocks > 0

    mz = image.to_mz_bytes()
    header = DOSMZHeader.from_stream(io.BytesIO(mz))
    assert header.relocation_count == 1
    assert header.relocation_offset == 0x1C
    assert (header.initial_cs, header.initial_ip, header.initial_ss, header.initial_sp) == (0, 0, 0x10, 0x100)
    assert mz[header.header_paragraphs * 16 :][: len(_PROGRAM)] == _PROGRAM


@pytest.mark.skipif(not emulator_available(), reason="unicorn is not installed")
def test_stub_that_calls_dos_before_handoff_is_refused():
    stub = b"\xb4\x4c\xcd\x21" + b"\x90" * 0x10  # mov ah,4ch ; int 21h
    packed = _mz(stub, header_paragraphs=3, banner_at=0x1E, banner=b"PKLITE")

    with pytest.raises(PackedExecutableUnpackError) as refusal:
        unpack_stub_packed_mz(packed)

    assert refusal.value.kind is UnpackFailureKind.STUB_REQUESTED_DOS_SERVICE


@pytest.mark.skipif(not emulator_available(), reason="unicorn is not installed")
def test_build_project_loads_the_unpacked_image_through_the_mz_backend(monkeypatch, tmp_path):
    packed_path = tmp_path / "PACKED.EXE"
    packed_path.write_bytes(_synthetic_pklite())
    cache_dir = tmp_path / "unpacked-cache"
    monkeypatch.setattr(project_loading, "_UNPACKED_EXE_CACHE_DIR", cache_dir)
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    project = project_loading._build_project(packed_path, force_blob=False, base_addr=0x1000, entry_point=0x1000)

    assert project.entry == 0x10000
    assert project.loader.memory.load(0x10000, len(_PROGRAM))[:4] == _PROGRAM[:4]
    relocated = struct.unpack("<H", project.loader.memory.load(0x10000 + _PROGRAM_RELOCATION_OFFSET, 2))[0]
    assert relocated == 0x1000 + 1
    main_object = project.loader.main_object
    assert main_object.initial_register_values == {"cs": 0x1000, "ip": 0, "ss": 0x1010, "sp": 0x100}
    assert project._inertia_packed_exe == "PKLITE"
    unpacked_path = project._inertia_unpacked_path
    assert unpacked_path.parent == cache_dir and unpacked_path.suffix == ".exe"
    assert Path(main_object.binary) == unpacked_path

    again = project_loading._build_project(packed_path, force_blob=False, base_addr=0x1000, entry_point=0x1000)
    assert again._inertia_unpacked_path == unpacked_path
    assert len(list(cache_dir.iterdir())) == 1


def test_missing_emulator_is_an_explicit_typed_refusal_with_exit_code_7(monkeypatch, tmp_path, capsys):
    packed_path = tmp_path / "PACKED.EXE"
    packed_path.write_bytes(_synthetic_pklite())
    monkeypatch.setattr(project_loading, "_UNPACKED_EXE_CACHE_DIR", tmp_path / "unpacked-cache")
    monkeypatch.setattr(project_loading, "emulator_available", lambda: False)
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    with pytest.raises(project_loading.PackedExecutableRefusedError) as refusal:
        project_loading._build_project(packed_path, force_blob=False, base_addr=0x1000, entry_point=0x1000)
    assert refusal.value.packer == "PKLITE"
    assert "unicorn" in refusal.value.reason

    rc = decompile.main([str(packed_path), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 7
    assert "/* refused: PKLITE-packed executable" in out
    assert "pip install 'unicorn==2.1.4'" in out


def test_detect_packed_mz_executable_keeps_the_label_contract(tmp_path):
    path = tmp_path / "packed.exe"
    path.write_bytes(_synthetic_pklite())
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    assert project_loading._detect_packed_mz_executable(path) == "PKLITE"
    plain = tmp_path / "plain.exe"
    plain.write_bytes(_mz(_PROGRAM, header_paragraphs=2, banner_at=None, banner=b""))
    assert project_loading._detect_packed_mz_executable(plain) is None


class _LZEXEStreamWriter:
    """Encode literal bytes followed by the LZEXE end marker exactly as ``_LZEXEBitStream`` consumes them."""

    def __init__(self) -> None:
        self.out = bytearray(2)
        self.word_pos = 0
        self.bit_index = 0

    def bit(self, value: int) -> None:
        if value:
            self.out[self.word_pos + (self.bit_index // 8)] |= 1 << (self.bit_index % 8)
        self.bit_index += 1
        if self.bit_index == 16:
            self.word_pos = len(self.out)
            self.out += b"\x00\x00"
            self.bit_index = 0

    def byte(self, value: int) -> None:
        self.out.append(value & 0xFF)

    def literal(self, value: int) -> None:
        self.bit(1)
        self.byte(value)

    def end(self) -> None:
        self.bit(0)
        self.bit(1)
        self.byte(0xFF)
        self.byte(0x00)
        self.byte(0x00)


def _synthetic_lzexe() -> bytes:
    writer = _LZEXEStreamWriter()
    for value in _PROGRAM:
        writer.literal(value)
    writer.end()
    stream = bytes(writer.out)
    packed_paragraphs = (len(stream) + 15) // 16
    stream = stream.ljust(packed_paragraphs * 16, b"\x00")
    info = struct.pack("<6H", 0, 0, 0x100, 0x10, packed_paragraphs, 1)
    decompressor = info + b"\x06\x0e\x1f\x8b"
    decompressor = decompressor.ljust(0x158, b"\x90")
    relocation_table = bytes([_PROGRAM_RELOCATION_OFFSET, 0x00, 0x01, 0x00])
    image = stream + decompressor + relocation_table
    return _mz(image, header_paragraphs=2, banner_at=0x1C, banner=b"LZ91", cs=packed_paragraphs, ip=len(info))


def test_lzexe_decoder_returns_an_unapplied_relocation_table():
    image = project_loading._unpack_lzexe_image(_synthetic_lzexe())

    assert isinstance(image, UnpackedMZImage)
    assert image.image[: len(_PROGRAM)] == _PROGRAM
    assert image.relocations == ((0, _PROGRAM_RELOCATION_OFFSET),)
    assert (image.entry_cs, image.entry_ip, image.stack_ss, image.stack_sp) == (0, 0, 0x10, 0x100)


def test_build_project_routes_lzexe_through_the_decoder_without_an_emulator(monkeypatch, tmp_path):
    packed_path = tmp_path / "LZPACKED.EXE"
    packed_path.write_bytes(_synthetic_lzexe())
    monkeypatch.setattr(project_loading, "_UNPACKED_EXE_CACHE_DIR", tmp_path / "unpacked-cache")
    monkeypatch.setattr(project_loading, "emulator_available", lambda: False)
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    project = project_loading._build_project(packed_path, force_blob=False, base_addr=0x1000, entry_point=0x1000)

    assert project.entry == 0x10000
    assert project._inertia_packed_exe == "LZEXE 0.91"
    relocated = struct.unpack("<H", project.loader.memory.load(0x10000 + _PROGRAM_RELOCATION_OFFSET, 2))[0]
    assert relocated == 0x1000 + 1
