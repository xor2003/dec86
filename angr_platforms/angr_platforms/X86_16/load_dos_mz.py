from __future__ import annotations

from archinfo import arch_from_id
from cle.backends import Blob, register_backend


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
        stream.seek(0)
        header = stream.read(0x40)
        if len(header) < 0x1C or header[:2] != b"MZ":
            raise ValueError("Not a DOS MZ executable")

        header_paragraphs = int.from_bytes(header[0x08:0x0A], "little")
        relocation_count = int.from_bytes(header[0x06:0x08], "little")
        relocation_offset = int.from_bytes(header[0x18:0x1A], "little")
        initial_ip = int.from_bytes(header[0x14:0x16], "little")
        initial_cs = int.from_bytes(header[0x16:0x18], "little")
        initial_sp = int.from_bytes(header[0x10:0x12], "little")
        initial_ss = int.from_bytes(header[0x0E:0x10], "little")
        image_offset = header_paragraphs * 0x10 if offset is None else offset
        load_base = kwargs.pop("base_addr", self.DEFAULT_LOAD_BASE)
        load_segment = load_base >> 4
        entry_point = load_base + (initial_cs << 4) + initial_ip

        super().__init__(
            *args,
            arch=arch_from_id("86_16"),
            offset=image_offset,
            entry_point=entry_point,
            base_addr=load_base,
            **kwargs,
        )

        for idx in range(relocation_count):
            entry_off = relocation_offset + idx * 4
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

        self.os = "DOS"
        self.initial_register_values = {
            "cs": initial_cs + load_segment,
            "ip": initial_ip,
            "ss": initial_ss + load_segment,
            "sp": initial_sp,
        }
        self.mz_header_paragraphs = header_paragraphs
        self.mz_image_offset = image_offset
        self.mz_load_segment = load_segment

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        magic = stream.read(2)
        return magic == b"MZ"


register_backend("dos_mz", DOSMZ)
