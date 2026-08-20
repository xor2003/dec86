"""Unpack stub-packed DOS MZ executables by emulating their 16-bit decompression stub.

Layer: frontend (loader).
Responsibility: recover the original MZ image (bytes, relocation table, entry point, initial stack) of a
self-extracting executable such as PKLITE, LZEXE, or EXEPACK by running the packer stub in a bounded
8086 emulator until it hands control to the decompressed program, or refuse with a typed reason.
Forbidden: knowledge of any specific compression format, guessing image contents, or semantic recovery.

The approach is packer-agnostic:

1. Load the packed executable the way DOS would (PSP, relocations, ``CS:IP``/``SS:SP`` from the header).
2. Emulate with unicorn while tracking the highest ``CS`` seen. Every stub of this family first moves
   itself above the space reserved for the decompressed program and later transfers control back down
   into the load area; that downward ``CS`` transition is the hand-off point.
3. Run twice with two different load segments. Words that differ by exactly the segment delta are
   segment references, i.e. relocation entries; their original value is ``word - load_segment``.
   Differing words below the program's initial stack pointer are stale stub stack content (the
   segment it pushed before its final ``retf``), not program data: they are zeroed and counted.
4. Any other difference, a DOS service request, an emulation fault, or a missing hand-off is refused
   explicitly instead of producing a guessed image.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum
from importlib.util import find_spec
from types import ModuleType
from typing import Protocol, cast

__all__ = [
    "DEFAULT_LOAD_SEGMENTS",
    "MZHeaderFields",
    "PackedExecutableUnpackError",
    "StubHandOff",
    "UnpackFailureKind",
    "UnpackedMZImage",
    "emulate_stub_handoff",
    "emulator_available",
    "unpack_stub_packed_mz",
]

DEFAULT_LOAD_SEGMENTS: tuple[int, int] = (0x0110, 0x0210)
_CONVENTIONAL_MEMORY_PARAGRAPHS: int = 0xA000
_PSP_PARAGRAPHS: int = 0x10
_IRET_VECTOR_SEGMENT: int = 0xF000
_IRET_VECTOR_OFFSET: int = 0xFFF0
_MZ_RELOCATION_TABLE_OFFSET: int = 0x1C
_DEFAULT_MAX_INSTRUCTIONS: int = 50_000_000


class UnpackFailureKind(StrEnum):
    """Why the emulation unpacker refused to produce an image."""

    EMULATOR_UNAVAILABLE = "emulator_unavailable"
    NOT_MZ = "not_mz"
    IMAGE_TOO_LARGE = "image_too_large"
    NO_HANDOFF = "no_handoff"
    STUB_REQUESTED_DOS_SERVICE = "stub_requested_dos_service"
    EMULATION_FAULT = "emulation_fault"
    INCONSISTENT_PASSES = "inconsistent_passes"
    UNEXPECTED_DIFFERENCE = "unexpected_difference"


class PackedExecutableUnpackError(Exception):
    """Typed refusal raised when a packed executable cannot be unpacked faithfully."""

    def __init__(self, kind: UnpackFailureKind, detail: str) -> None:
        """Record the refusal kind and a human-readable detail."""
        super().__init__(f"{kind.value}: {detail}")
        self.kind = kind
        self.detail = detail


@dataclass(frozen=True, slots=True)
class MZHeaderFields:
    """The MZ header words that matter for loading and unpacking."""

    last_page_bytes: int
    pages: int
    relocation_count: int
    header_paragraphs: int
    min_alloc: int
    max_alloc: int
    ss: int
    sp: int
    ip: int
    cs: int
    relocation_offset: int

    @classmethod
    def parse(cls, data: bytes) -> MZHeaderFields:
        """Parse the fixed MZ header or raise a typed ``NOT_MZ`` refusal."""
        if len(data) < 0x1C or data[:2] not in (b"MZ", b"ZM"):
            raise PackedExecutableUnpackError(UnpackFailureKind.NOT_MZ, "missing MZ signature or truncated header")
        fields = struct.unpack_from("<12H", data, 2)
        return cls(
            last_page_bytes=fields[0],
            pages=fields[1],
            relocation_count=fields[2],
            header_paragraphs=fields[3],
            min_alloc=fields[4],
            max_alloc=fields[5],
            ss=fields[6],
            sp=fields[7],
            ip=fields[9],
            cs=fields[10],
            relocation_offset=fields[11],
        )

    @property
    def header_size(self) -> int:
        """Return the header size in bytes."""
        return self.header_paragraphs * 16

    def image_size(self, file_size: int) -> int:
        """Return the load-image size in bytes, bounded by the real file size."""
        declared = self.pages * 512
        if self.last_page_bytes:
            declared -= 512 - self.last_page_bytes
        return max(0, min(declared, file_size) - self.header_size)


@dataclass(frozen=True, slots=True)
class StubHandOff:
    """Machine state captured the instant a packer stub jumps into the decompressed program."""

    load_segment: int
    memory: bytes
    cs: int
    ip: int
    ss: int
    sp: int
    stub_segment: int
    blocks: int


@dataclass(frozen=True, slots=True)
class UnpackedMZImage:
    """A decompressed MZ program with its relocation table and initial register state."""

    image: bytes
    relocations: tuple[tuple[int, int], ...]
    entry_cs: int
    entry_ip: int
    stack_ss: int
    stack_sp: int
    stub_segment: int
    emulated_blocks: int
    stale_stack_words: int = 0

    def to_mz_bytes(self) -> bytes:
        """Serialize as a conventional MZ executable with the relocation table at offset 0x1C."""
        reloc_bytes = len(self.relocations) * 4
        header_size = ((_MZ_RELOCATION_TABLE_OFFSET + reloc_bytes + 15) // 16) * 16
        total = header_size + len(self.image)
        header = bytearray(header_size)
        struct.pack_into(
            "<2sHHHHHHHHHHHH",
            header,
            0,
            b"MZ",
            total % 512,
            (total + 511) // 512,
            len(self.relocations),
            header_size // 16,
            0,
            0xFFFF,
            self.stack_ss,
            self.stack_sp,
            0,
            self.entry_ip,
            self.entry_cs,
            _MZ_RELOCATION_TABLE_OFFSET,
        )
        for index, (segment, offset) in enumerate(self.relocations):
            struct.pack_into("<HH", header, _MZ_RELOCATION_TABLE_OFFSET + index * 4, offset, segment)
        return bytes(header) + self.image


class _EmulatorEngine(Protocol):
    """The subset of the unicorn ``Uc`` surface this module relies on."""

    def reg_read(self, register: int) -> int:
        """Read a register."""

    def reg_write(self, register: int, value: int) -> None:
        """Write a register."""

    def mem_map(self, address: int, size: int) -> None:
        """Map guest memory."""

    def mem_read(self, address: int, size: int) -> bytearray:
        """Read guest memory."""

    def mem_write(self, address: int, data: bytes) -> None:
        """Write guest memory."""

    def hook_add(self, hook_type: int, callback: object) -> int:
        """Install a hook."""

    def emu_start(self, begin: int, until: int, timeout: int = 0, count: int = 0) -> None:
        """Run the emulator."""

    def emu_stop(self) -> None:
        """Stop the emulator from inside a hook."""


@dataclass(slots=True)
class _EmulationState:
    """Mutable bookkeeping shared between the block hook, the interrupt hook, and the driver."""

    cs: int
    high: int
    blocks: int = 0
    handoff: StubHandOff | None = None
    refusal: PackedExecutableUnpackError | None = None


def emulator_available() -> bool:
    """Return whether the unicorn engine can be imported on this host."""
    return find_spec("unicorn") is not None


def _require_unicorn() -> ModuleType:
    try:
        import unicorn  # noqa: PLC0415  # optional dependency, imported lazily on purpose
    except ImportError as ex:  # pragma: no cover - exercised only without the optional dependency
        raise PackedExecutableUnpackError(
            UnpackFailureKind.EMULATOR_UNAVAILABLE,
            "the unicorn engine is not installed (pip install 'unicorn==2.1.4')",
        ) from ex
    return cast(ModuleType, unicorn)


def emulate_stub_handoff(
    data: bytes,
    *,
    load_segment: int,
    max_instructions: int = _DEFAULT_MAX_INSTRUCTIONS,
) -> StubHandOff:
    """Run the packer stub of ``data`` loaded at ``load_segment`` until it hands control to the program."""
    unicorn = _require_unicorn()
    from unicorn import x86_const  # noqa: PLC0415  # optional dependency, imported lazily on purpose

    header = MZHeaderFields.parse(data)
    image = data[header.header_size : header.header_size + header.image_size(len(data))]
    psp_segment = load_segment - _PSP_PARAGRAPHS
    image_end_segment = load_segment + (len(image) + 15) // 16
    if image_end_segment + header.min_alloc >= _CONVENTIONAL_MEMORY_PARAGRAPHS:
        raise PackedExecutableUnpackError(
            UnpackFailureKind.IMAGE_TOO_LARGE,
            f"image of {len(image)} bytes plus min_alloc {header.min_alloc:#x} paragraphs does not fit below 640 KiB",
        )

    mu: _EmulatorEngine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    mu.mem_map(0, 0x100000)
    # Every interrupt vector points at an IRET so a stray INT never executes zeroed memory.
    iret_linear = (_IRET_VECTOR_SEGMENT << 4) + _IRET_VECTOR_OFFSET
    mu.mem_write(iret_linear, b"\xcf")
    mu.mem_write(0, struct.pack("<HH", _IRET_VECTOR_OFFSET, _IRET_VECTOR_SEGMENT) * 256)
    psp = bytearray(256)
    psp[0], psp[1] = 0xCD, 0x20
    struct.pack_into("<H", psp, 2, _CONVENTIONAL_MEMORY_PARAGRAPHS)
    mu.mem_write(psp_segment << 4, bytes(psp))
    mu.mem_write(load_segment << 4, bytes(image))
    for index in range(header.relocation_count):
        entry = header.relocation_offset + index * 4
        if entry + 4 > len(data):
            break
        offset, segment = struct.unpack_from("<HH", data, entry)
        linear = (load_segment << 4) + (segment << 4) + offset
        value = struct.unpack("<H", bytes(mu.mem_read(linear, 2)))[0]
        mu.mem_write(linear, struct.pack("<H", (value + load_segment) & 0xFFFF))

    initial_cs = (load_segment + header.cs) & 0xFFFF
    mu.reg_write(x86_const.UC_X86_REG_CS, initial_cs)
    mu.reg_write(x86_const.UC_X86_REG_IP, header.ip)
    mu.reg_write(x86_const.UC_X86_REG_SS, (load_segment + header.ss) & 0xFFFF)
    mu.reg_write(x86_const.UC_X86_REG_SP, header.sp)
    mu.reg_write(x86_const.UC_X86_REG_DS, psp_segment)
    mu.reg_write(x86_const.UC_X86_REG_ES, psp_segment)
    mu.reg_write(x86_const.UC_X86_REG_AX, 0)

    state = _EmulationState(cs=initial_cs, high=initial_cs)

    def _on_block(emu: _EmulatorEngine, _address: int, _size: int, _user_data: object) -> None:
        state.blocks += 1
        cs = emu.reg_read(x86_const.UC_X86_REG_CS)
        if cs == state.cs:
            return
        previous = state.cs
        state.cs = cs
        if cs > state.high:
            state.high = cs
        stub_moved_above_image = state.high >= image_end_segment
        transfers_back_into_load_area = load_segment <= cs < previous and cs < state.high
        if stub_moved_above_image and transfers_back_into_load_area:
            state.handoff = StubHandOff(
                load_segment=load_segment,
                memory=bytes(emu.mem_read(load_segment << 4, (state.high - load_segment) << 4)),
                cs=cs,
                ip=emu.reg_read(x86_const.UC_X86_REG_IP),
                ss=emu.reg_read(x86_const.UC_X86_REG_SS),
                sp=emu.reg_read(x86_const.UC_X86_REG_SP),
                stub_segment=state.high,
                blocks=state.blocks,
            )
            emu.emu_stop()

    def _on_interrupt(emu: _EmulatorEngine, interrupt: int, _user_data: object) -> None:
        ah = emu.reg_read(x86_const.UC_X86_REG_AH)
        if interrupt == 0x21 and ah == 0x30:
            emu.reg_write(x86_const.UC_X86_REG_AX, 0x0005)
            emu.reg_write(x86_const.UC_X86_REG_BX, 0)
            emu.reg_write(x86_const.UC_X86_REG_CX, 0)
            return
        state.refusal = PackedExecutableUnpackError(
            UnpackFailureKind.STUB_REQUESTED_DOS_SERVICE,
            f"stub raised INT {interrupt:#04x} (AH={ah:#04x}) before handing control to the program",
        )
        emu.emu_stop()

    mu.hook_add(unicorn.UC_HOOK_BLOCK, _on_block)
    mu.hook_add(unicorn.UC_HOOK_INTR, _on_interrupt)
    try:
        mu.emu_start((initial_cs << 4) + header.ip, 0xFFFFF, count=max_instructions)
    except unicorn.UcError as ex:
        if state.handoff is None and state.refusal is None:
            raise PackedExecutableUnpackError(
                UnpackFailureKind.EMULATION_FAULT,
                f"{ex} at CS:IP={mu.reg_read(x86_const.UC_X86_REG_CS):#06x}:{mu.reg_read(x86_const.UC_X86_REG_IP):#06x}",
            ) from ex
    if state.refusal is not None:
        raise state.refusal
    if state.handoff is None:
        raise PackedExecutableUnpackError(
            UnpackFailureKind.NO_HANDOFF,
            f"stub never transferred control into the load area within {state.blocks} blocks",
        )
    return state.handoff


def _fitting_load_segments(data: bytes, requested: tuple[int, int]) -> tuple[int, int]:
    header = MZHeaderFields.parse(data)
    image_paragraphs = (header.image_size(len(data)) + 15) // 16
    highest = _CONVENTIONAL_MEMORY_PARAGRAPHS - image_paragraphs - header.min_alloc - 1
    first, second = requested
    if second > highest:
        second = highest
    if second <= first:
        raise PackedExecutableUnpackError(
            UnpackFailureKind.IMAGE_TOO_LARGE,
            f"no room for two load segments below 640 KiB (image {image_paragraphs:#x} paragraphs)",
        )
    return first, second


def unpack_stub_packed_mz(
    data: bytes,
    *,
    load_segments: tuple[int, int] = DEFAULT_LOAD_SEGMENTS,
    max_instructions: int = _DEFAULT_MAX_INSTRUCTIONS,
) -> UnpackedMZImage:
    """Unpack a stub-packed MZ executable into an ``UnpackedMZImage`` or raise a typed refusal."""
    first_segment, second_segment = _fitting_load_segments(data, load_segments)
    first = emulate_stub_handoff(data, load_segment=first_segment, max_instructions=max_instructions)
    second = emulate_stub_handoff(data, load_segment=second_segment, max_instructions=max_instructions)
    delta = second_segment - first_segment

    entry_cs = (first.cs - first_segment) & 0xFFFF
    stack_ss = (first.ss - first_segment) & 0xFFFF
    if (
        entry_cs != (second.cs - second_segment) & 0xFFFF
        or first.ip != second.ip
        or stack_ss != (second.ss - second_segment) & 0xFFFF
        or first.sp != second.sp
        or first.stub_segment - first_segment != second.stub_segment - second_segment
    ):
        raise PackedExecutableUnpackError(
            UnpackFailureKind.INCONSISTENT_PASSES,
            "the two emulation passes disagree on entry, stack, or image extent",
        )

    size = min(len(first.memory), len(second.memory))
    image = bytearray(first.memory[:size])
    relocations: list[tuple[int, int]] = []
    stale_stack_words = 0
    stack_bottom = stack_ss << 4
    stack_top = stack_bottom + first.sp
    index = 0
    while index + 1 < size:
        low = first.memory[index] | (first.memory[index + 1] << 8)
        high = second.memory[index] | (second.memory[index + 1] << 8)
        if low == high:
            index += 1
            continue
        if stack_bottom <= index < stack_top:
            image[index] = 0
            image[index + 1] = 0
            stale_stack_words += 1
            index += 2
            continue
        if (high - low) & 0xFFFF != delta:
            raise PackedExecutableUnpackError(
                UnpackFailureKind.UNEXPECTED_DIFFERENCE,
                f"image offset {index:#x} differs between passes ({low:#06x} vs {high:#06x}) but is not a segment reference",
            )
        struct.pack_into("<H", image, index, (low - first_segment) & 0xFFFF)
        relocations.append((index // 16, index % 16))
        index += 2

    return UnpackedMZImage(
        image=bytes(image),
        relocations=tuple(relocations),
        entry_cs=entry_cs,
        entry_ip=first.ip,
        stack_ss=stack_ss,
        stack_sp=first.sp,
        stub_segment=first.stub_segment - first_segment,
        emulated_blocks=first.blocks,
        stale_stack_words=stale_stack_words,
    )
