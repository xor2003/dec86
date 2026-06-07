from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .callee_name_normalization import normalize_callee_name_8616

__all__ = [
    "CompilerHelperEvidenceKind8616",
    "CompilerHelperEvidence8616",
    "identify_x86_16_compiler_helper_at_8616",
    "is_x86_16_stack_probe_name_8616",
]


class CompilerHelperEvidenceKind8616(Enum):
    STACK_PROBE = "stack_probe"


@dataclass(frozen=True, slots=True)
class CompilerHelperEvidence8616:
    addr: int
    name: str
    kind: CompilerHelperEvidenceKind8616
    pattern_name: str
    matched_bytes: int


_STACK_PROBE_NORMALIZED_NAMES_8616 = frozenset(
    {
        "anchkstk",
        "chkstk",
        "analloca_probe",
    }
)


_MSC_ANCHKSTK_PATTERN_8616: tuple[int | None, ...] = (
    0x59,  # pop cx
    0x8B,
    0xDC,  # mov bx, sp
    0x2B,
    0xD8,  # sub bx, ax
    0x72,
    None,  # jb stack_overflow
    0x3B,
    0x1E,
    None,
    None,  # cmp bx, word ptr [limit]
    0x72,
    None,  # jb stack_overflow
    0x8B,
    0xE3,  # mov sp, bx
    0xFF,
    0xE1,  # jmp cx
)


def is_x86_16_stack_probe_name_8616(name: str | None) -> bool:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return normalized.strip().lower().lstrip("_") in _STACK_PROBE_NORMALIZED_NAMES_8616


def _project_arch_name_8616(project) -> str | None:
    return getattr(getattr(project, "arch", None), "name", None)


def _load_project_bytes_8616(project, addr: int, size: int) -> bytes | None:
    loader = getattr(project, "loader", None)
    memories = (
        getattr(loader, "memory", None),
        getattr(getattr(loader, "main_object", None), "memory", None),
    )
    for memory in memories:
        load = getattr(memory, "load", None)
        if not callable(load):
            continue
        try:
            raw = load(addr, size)
        except Exception:
            continue
        if isinstance(raw, bytes):
            return raw
        try:
            return bytes(raw)
        except Exception:
            continue
    return None


def _matches_masked_prefix_8616(data: bytes, pattern: tuple[int | None, ...]) -> bool:
    if len(data) < len(pattern):
        return False
    for index, expected in enumerate(pattern):
        if expected is not None and data[index] != expected:
            return False
    return True


def identify_x86_16_compiler_helper_at_8616(project, addr: int | None) -> CompilerHelperEvidence8616 | None:
    if not isinstance(addr, int) or _project_arch_name_8616(project) != "86_16":
        return None

    code = _load_project_bytes_8616(project, addr, len(_MSC_ANCHKSTK_PATTERN_8616))
    if code is not None and _matches_masked_prefix_8616(code, _MSC_ANCHKSTK_PATTERN_8616):
        return CompilerHelperEvidence8616(
            addr=addr,
            name="aNchkstk",
            kind=CompilerHelperEvidenceKind8616.STACK_PROBE,
            pattern_name="msc_aNchkstk_popcx_sp_ax",
            matched_bytes=len(_MSC_ANCHKSTK_PATTERN_8616),
        )
    return None
