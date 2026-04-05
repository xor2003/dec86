from __future__ import annotations

from dataclasses import dataclass

from archinfo import arch_from_id
from cle.backends import Blob, register_backend


@dataclass(frozen=True)
class DOSMZHeader:
    header_paragraphs: int
    relocation_count: int
    relocation_offset: int
    initial_ip: int
    initial_cs: int
    initial_sp: int
    initial_ss: int

    @classmethod
    def from_stream(cls, stream) -> "DOSMZHeader":
        stream.seek(0)
        header = stream.read(0x40)
        if len(header) < 0x1C or header[:2] != b"MZ":
            raise ValueError("Not a DOS MZ executable")

        return cls(
            header_paragraphs=int.from_bytes(header[0x08:0x0A], "little"),
            relocation_count=int.from_bytes(header[0x06:0x08], "little"),
            relocation_offset=int.from_bytes(header[0x18:0x1A], "little"),
            initial_ip=int.from_bytes(header[0x14:0x16], "little"),
            initial_cs=int.from_bytes(header[0x16:0x18], "little"),
            initial_sp=int.from_bytes(header[0x10:0x12], "little"),
            initial_ss=int.from_bytes(header[0x0E:0x10], "little"),
        )


class DOSMZ(Blob):
    """
    Minimal DOS MZ loader for 16-bit real-mode executables.

    The loaded image is mapped starting at linear address 0 so segment-relative
    references inside the executable line up with the relocated program image.
    """

    is_default = True

    DEFAULT_LOAD_BASE = 0x1000

    def __init__(self, *args, offset=None, **kwargs):
        if len(args) < 2:
            raise ValueError("DOSMZ expects binary path and binary stream")
        stream = args[1]
        header = DOSMZHeader.from_stream(stream)
        image_offset = header.header_paragraphs * 0x10 if offset is None else offset
        load_base = kwargs.pop("base_addr", self.DEFAULT_LOAD_BASE)
        load_segment = load_base >> 4
        entry_point = load_base + (header.initial_cs << 4) + header.initial_ip
        arch = arch_from_id("86_16")
        # Real-mode code still executes with 16-bit registers, but MZ images can
        # span well beyond 64K in linear memory. CLE uses arch.bits for loader
        # address-space checks, so widen only the loader-visible address width.
        arch.bits = max(arch.bits, 32)

        super().__init__(
            *args,
            arch=arch,
            offset=image_offset,
            entry_point=entry_point,
            base_addr=load_base,
            **kwargs,
        )

        self._apply_relocations(stream, header, load_base, load_segment)

        self.os = "DOS"
        self.initial_register_values = {
            "cs": header.initial_cs + load_segment,
            "ip": header.initial_ip,
            "ss": header.initial_ss + load_segment,
            "sp": header.initial_sp,
        }
        self.mz_header_paragraphs = header.header_paragraphs
        self.mz_image_offset = image_offset
        self.mz_load_segment = load_segment

    def _apply_relocations(self, stream, header: DOSMZHeader, load_base: int, load_segment: int) -> None:
        for idx in range(header.relocation_count):
            entry_off = header.relocation_offset + idx * 4
            stream.seek(entry_off)
            reloc = stream.read(4)
            if len(reloc) < 4:
                break
            reloc_offset = int.from_bytes(reloc[0:2], "little")
            reloc_segment = int.from_bytes(reloc[2:4], "little")
            reloc_addr = load_base + (reloc_segment << 4) + reloc_offset
            current = int.from_bytes(self.memory.load(reloc_addr - self.linked_base, 2), "little")
            patched = (current + load_segment) & 0xFFFF
            self.memory.store(reloc_addr - self.linked_base, patched.to_bytes(2, "little"))

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        magic = stream.read(2)
        return magic == b"MZ"


register_backend("dos_mz", DOSMZ)
