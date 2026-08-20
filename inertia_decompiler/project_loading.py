"""Load angr projects and binary bytes for CLI orchestration.

Layer: CLI/fallback/reporting.
Responsibility: construct angr project objects and binary byte views without owning semantic recovery.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Protocol, cast

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.compiler_helpers import hook_x86_16_known_compiler_helpers_8616
from angr_platforms.X86_16.packed_mz_unpack import (
    PackedExecutableUnpackError,
    UnpackedMZImage,
    emulator_available,
    unpack_stub_packed_mz,
)

from inertia_decompiler.packer_detect import PackerDetection, PackerType, detect_packer_in_bytes
from inertia_decompiler.telemetry import trace_function

_ROOT = Path(__file__).resolve().parents[1]
_UNPACKED_EXE_CACHE_DIR = _ROOT / "angr_platforms" / ".cache" / "unpacked_exe"

_IDA_BASE_ADDRESS_RE = re.compile(r"Base Address:\s*([0-9A-Fa-f]+)h", re.IGNORECASE)
_TRACE_FUNCTION: Any = cast(Any, trace_function)


def _debug_print(message: str) -> None:
    if "PYTEST_CURRENT_TEST" in os.environ:
        print(message)
        return
    print(f"{time.strftime('[%H:%M:%S]')} {message}", file=sys.stderr)


def _describe_exception(ex: Exception) -> str:
    detail = str(ex).strip()
    ex_type = type(ex).__name__
    if detail:
        return f"{ex_type}: {detail}"
    rep = repr(ex).strip()
    if rep and rep != f"{ex_type}()":
        return f"{ex_type}: {rep}"
    return ex_type


def _finalize_x86_16_project(project: angr.Project) -> angr.Project:
    hook_x86_16_known_compiler_helpers_8616(project)
    return project


def _find_sidecar_file(binary: Path, suffix: str) -> Path | None:
    """Find a companion sidecar path for a binary using an exact basename match when possible.

    Caching this lookup avoids repeated directory scans during multi-function runs where the same
    binary is consulted for the same sidecar types.
    """
    return _find_sidecar_file_cached(binary.as_posix(), suffix.lower())


@lru_cache(maxsize=256)
def _find_sidecar_file_cached(binary: str, suffix: str) -> Path | None:
    """Resolve one normalized string cache key to an existing sidecar path."""
    binary_path = Path(binary)
    direct = binary_path.with_suffix(suffix)
    if direct.exists():
        return direct
    direct_appended = binary_path.with_name(f"{binary_path.name}{suffix}")
    if direct_appended.exists():
        return direct_appended
    try:
        siblings = binary_path.parent.iterdir()
    except OSError:
        return None
    wanted = binary_path.name.lower() + suffix.lower()
    for sibling in siblings:
        if sibling.name.lower() == wanted:
            return sibling
    return None


def _probe_ida_base_linear(binary: Path, fallback_linear: int) -> int:
    """Return the IDA listing base for a binary, or the supplied fallback."""
    return _probe_ida_base_linear_cached(binary, fallback_linear)


@lru_cache(maxsize=256)
def _probe_ida_base_linear_cached(binary: Path, fallback_linear: int) -> int:
    """Cache the bounded IDA listing base probe for one binary path."""
    try:
        lst_path = _find_sidecar_file_cached(binary.as_posix(), ".lst")
        if lst_path is None:
            return fallback_linear
        with lst_path.open("r", encoding="utf-8", errors="ignore") as fp:
            for _ in range(64):
                line = fp.readline()
                if not line:
                    break
                match = _IDA_BASE_ADDRESS_RE.search(line)
                if match is not None:
                    return int(match.group(1), 16) << 4
    except OSError:
        return fallback_linear
    return fallback_linear


def _looks_like_ne_executable(path: Path) -> bool:
    """Return whether the executable carries an NE header signature."""
    return _looks_like_ne_executable_cached(path)


@lru_cache(maxsize=256)
def _looks_like_ne_executable_cached(path: Path) -> bool:
    """Cache the bounded NE signature probe for one executable path."""
    try:
        with path.open("rb") as fp:
            header = fp.read(0x40)
            if len(header) < 0x40 or header[:2] != b"MZ":
                return False
            new_header_offset = int.from_bytes(header[0x3C:0x40], "little")
            if new_header_offset < 0x40:
                return False
            fp.seek(new_header_offset)
            return fp.read(2) == b"NE"
    except OSError:
        return False


def _detect_packed_mz_executable(path: Path) -> str | None:
    """Return the recognized MZ packer label (e.g. ``"PKLITE"``, ``"LZEXE 0.91"``), when one is present."""
    detection = _detect_packed_mz_executable_cached(path)
    return None if detection is None else detection.label


@lru_cache(maxsize=256)
def _detect_packed_mz_executable_cached(path: Path) -> PackerDetection | None:
    """Cache the typed packer signature probe for one executable path."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return detect_packer_in_bytes(data)


def _is_blob_only_input(path: Path) -> bool:
    return path.suffix.lower() in {".bin", ".raw", ".cod"}


class PackedExecutableRefusedError(RuntimeError):
    """A packed executable was recognized but cannot be unpacked faithfully on this host."""

    def __init__(self, *, path: Path, packer: str, reason: str) -> None:
        """Record the refused input, its packer label, and the typed refusal reason."""
        self.path = path
        self.packer = packer
        self.reason = reason
        super().__init__(
            f"{packer}-packed executable {path} was not loaded: {reason}. "
            "Unpack it first (for example with UNP) or install the optional unpacker "
            "dependency: pip install 'unicorn==2.1.4' (extra: .[unpack])."
        )


class _PackedProjectMarker(Protocol):
    _inertia_packed_exe: str
    _inertia_unpacked_path: Path


class _LZEXEBitStream:
    def __init__(self, data: bytes, offset: int) -> None:
        self._data = data
        self._pos = offset
        self._count = 0
        self._buffer = 0
        self._load_word()

    def _load_word(self) -> None:
        self._count = 0x10
        self._buffer = self._data[self._pos] | (self._data[self._pos + 1] << 8)
        self._pos += 2

    def bit(self) -> int:
        """Read one low-order bit from the packed LZEXE stream."""
        value = self._buffer & 1
        self._buffer >>= 1
        self._count -= 1
        if self._count == 0:
            self._load_word()
        return value

    def byte(self) -> int:
        """Read one literal byte from the packed LZEXE stream."""
        value = self._data[self._pos]
        self._pos += 1
        return value


def _unpack_lzexe_image(data: bytes) -> UnpackedMZImage:
    """Decode an LZEXE 0.91 image in pure Python, keeping its relocation table unapplied."""

    def _impl() -> UnpackedMZImage:
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("Not a DOS MZ executable.")
        signature = data[0x1C:0x20]
        if signature != b"LZ91":
            raise ValueError(f"Unsupported packed executable format: {signature!r}")

        header_paragraphs = int.from_bytes(data[0x08:0x0A], "little")
        initial_cs = int.from_bytes(data[0x16:0x18], "little")
        initial_ip = int.from_bytes(data[0x14:0x16], "little")
        lz_header_offset = (header_paragraphs + initial_cs) << 4
        lz_entry = lz_header_offset + initial_ip
        if data[lz_entry : lz_entry + 4] != b"\x06\x0e\x1f\x8b":
            raise ValueError("Packed executable entry does not match LZEXE 0.91 stub.")

        unpacked_ip = int.from_bytes(data[lz_header_offset : lz_header_offset + 2], "little")
        unpacked_cs = int.from_bytes(data[lz_header_offset + 2 : lz_header_offset + 4], "little")
        unpacked_sp = int.from_bytes(data[lz_header_offset + 4 : lz_header_offset + 6], "little")
        unpacked_ss = int.from_bytes(data[lz_header_offset + 6 : lz_header_offset + 8], "little")
        packed_paragraphs = int.from_bytes(data[lz_header_offset + 8 : lz_header_offset + 10], "little")
        unpacked_paragraphs = int.from_bytes(data[lz_header_offset + 10 : lz_header_offset + 12], "little")
        packed_stream_offset = lz_header_offset - (packed_paragraphs << 4)
        output = bytearray((unpacked_paragraphs * 2) << 4)

        stream = _LZEXEBitStream(data, packed_stream_offset)
        out_pos = 0
        while True:
            if stream.bit():
                output[out_pos] = stream.byte()
                out_pos += 1
                continue

            if stream.bit() == 0:
                length = (stream.bit() << 1) | stream.bit()
                length += 2
                span = stream.byte() | ~0xFF
            else:
                span = stream.byte()
                length = stream.byte()
                span |= ((length & ~0x07) << 5) | ~0x1FFF
                length = (length & 0x07) + 2
                if length == 2:
                    length = stream.byte()
                    if length == 0:
                        break
                    if length == 1:
                        continue
                    length += 1

            for _ in range(length):
                output[out_pos] = output[out_pos + span]
                out_pos += 1

        relocation_offset = lz_header_offset + 0x158
        rel_off = 0
        relocations: list[tuple[int, int]] = []
        while True:
            span = data[relocation_offset]
            relocation_offset += 1
            if span == 0:
                span = int.from_bytes(data[relocation_offset : relocation_offset + 2], "little")
                relocation_offset += 2
                if span == 0:
                    rel_off += 0x0FFF0
                    continue
                if span == 1:
                    break
            rel_off += span
            relocations.append((rel_off >> 4, rel_off & 0xF))

        image_size = max(out_pos, (max((seg << 4) + off for seg, off in relocations) + 2) if relocations else 0)
        return UnpackedMZImage(
            image=bytes(output[:image_size]),
            relocations=tuple(relocations),
            entry_cs=unpacked_cs,
            entry_ip=unpacked_ip,
            stack_ss=unpacked_ss,
            stack_sp=unpacked_sp,
            stub_segment=(image_size + 15) >> 4,
            emulated_blocks=0,
        )

    return _impl()


def _unpack_detected_executable(data: bytes, detection: PackerDetection, path: Path) -> tuple[UnpackedMZImage, str]:
    """Unpack a detected packed executable, returning the image and the method that produced it."""
    if detection.packer_type is PackerType.LZEXE and detection.signature == "LZ91":
        try:
            return _unpack_lzexe_image(data), "in-tree LZEXE 0.91 decoder"
        except (ValueError, IndexError) as ex:
            _debug_print(f"[dbg] LZEXE decoder rejected {path}: {_describe_exception(ex)}; trying stub emulation")
    if not emulator_available():
        raise PackedExecutableRefusedError(
            path=path,
            packer=detection.label,
            reason="the unicorn engine needed to emulate the packer stub is not installed",
        )
    try:
        return unpack_stub_packed_mz(data), "16-bit stub emulation (unicorn)"
    except PackedExecutableUnpackError as ex:
        raise PackedExecutableRefusedError(path=path, packer=detection.label, reason=str(ex)) from ex


def _materialize_unpacked_executable(path: Path, detection: PackerDetection) -> Path:
    """Return a cached, conventional MZ copy of a packed executable, unpacking it on first use."""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()[:12]
    cached = _UNPACKED_EXE_CACHE_DIR / f"{path.stem}.{digest}.exe"
    if cached.is_file() and cached.stat().st_size > 0x1C:
        print(
            f"/* packed executable: {detection.label} (signature at {detection.offset:#x}); "
            f"reusing unpacked image {cached} */",
            flush=True,
        )
        return cached
    image, method = _unpack_detected_executable(data, detection, path)
    _UNPACKED_EXE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    temporary = cached.with_name(f"{cached.name}.{os.getpid()}.tmp")
    temporary.write_bytes(image.to_mz_bytes())
    os.replace(temporary, cached)
    print(
        f"/* packed executable: {detection.label} (signature at {detection.offset:#x}); unpacked via {method}: "
        f"image {len(image.image)} bytes, {len(image.relocations)} relocations, "
        f"entry {image.entry_cs:04X}:{image.entry_ip:04X}, stack {image.stack_ss:04X}:{image.stack_sp:04X}; "
        f"cached at {cached} */",
        flush=True,
    )
    return cached


def _mark_packed_project(project: angr.Project, detection: PackerDetection | None, load_path: Path) -> angr.Project:
    """Record packer provenance on a project loaded from an unpacked image."""
    if detection is None:
        return project
    packed_project = cast(_PackedProjectMarker, project)
    packed_project._inertia_packed_exe = detection.label
    packed_project._inertia_unpacked_path = load_path
    return project


def _build_project(path: Path, *, force_blob: bool, base_addr: int, entry_point: int) -> angr.Project:
    def _impl() -> angr.Project:
        suffix = path.suffix.lower()

        _debug_print(f"[dbg] build_project: path={path} suffix={suffix} force_blob={force_blob}")
        if force_blob or _is_blob_only_input(path):
            return _finalize_x86_16_project(
                angr.Project(
                    path,
                    auto_load_libs=False,
                    main_opts={
                        "backend": "blob",
                        "arch": Arch86_16(),
                        "base_addr": base_addr,
                        "entry_point": entry_point,
                    },
                )
            )

        if suffix == ".com":
            return _finalize_x86_16_project(
                angr.Project(
                    path,
                    auto_load_libs=False,
                    main_opts={
                        "backend": "blob",
                        "arch": Arch86_16(),
                        "base_addr": base_addr,
                        "entry_point": entry_point,
                    },
                    simos="DOS",
                )
            )

        load_path = path
        packed_detection = _detect_packed_mz_executable_cached(path) if suffix == ".exe" else None
        if packed_detection is not None:
            load_path = _materialize_unpacked_executable(path, packed_detection)

        if suffix == ".exe":
            explicit_base = _probe_ida_base_linear(path, base_addr << 4 if base_addr < 0x10000 else base_addr)
            exe_backend = "dos_ne" if _looks_like_ne_executable(load_path) else "dos_mz"
            try:
                proj = angr.Project(
                    load_path,
                    auto_load_libs=False,
                    main_opts={
                        "backend": exe_backend,
                        "base_addr": explicit_base,
                    },
                    simos="DOS",
                )
                _debug_print(f"[dbg] {exe_backend} load base={hex(explicit_base)}")
                _debug_print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
                return _finalize_x86_16_project(_mark_packed_project(proj, packed_detection, load_path))
            except Exception as ex:
                _debug_print(
                    f"[dbg] explicit {exe_backend} load failed at {hex(explicit_base)}: {_describe_exception(ex)}"
                )

        try:
            proj = angr.Project(load_path, auto_load_libs=False)
        except Exception as ex:
            if suffix == ".exe" and "Position-DEPENDENT object" in str(ex):
                explicit_base = _probe_ida_base_linear(path, base_addr << 4 if base_addr < 0x10000 else base_addr)
                _debug_print(
                    f"[dbg] retrying DOS MZ load with explicit base_addr={hex(explicit_base)} after {type(ex).__name__}"
                )
                proj = angr.Project(
                    load_path,
                    auto_load_libs=False,
                    main_opts={
                        "backend": "dos_mz",
                        "base_addr": explicit_base,
                    },
                )
            else:
                raise
        _debug_print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
        return _finalize_x86_16_project(_mark_packed_project(proj, packed_detection, load_path))

    return _impl()


_build_project = cast(Callable[..., angr.Project], _TRACE_FUNCTION(name="project.build")(_build_project))


@lru_cache(maxsize=16)
def _build_project_cached_impl(
    path: str,
    *,
    force_blob: bool,
    base_addr: int,
    entry_point: int,
) -> angr.Project:
    return _build_project(
        Path(path),
        force_blob=force_blob,
        base_addr=base_addr,
        entry_point=entry_point,
    )

_build_project_cached = cast(
    Callable[..., angr.Project], _TRACE_FUNCTION(name="project.build_cached")(_build_project_cached_impl)
)

def _build_project_from_bytes(code: bytes, *, base_addr: int, entry_point: int) -> angr.Project:
    arch = Arch86_16()
    arch.bits = max(arch.bits, 32)
    return _finalize_x86_16_project(
        angr.Project(
            io.BytesIO(code),
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": arch,
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
            simos="DOS",
        )
    )


_build_project_from_bytes = cast(
    Callable[..., angr.Project], _TRACE_FUNCTION(name="project.build_from_bytes")(_build_project_from_bytes)
)
