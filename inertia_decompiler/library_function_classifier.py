from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class LibraryFunctionClass(Enum):
    USER_SOURCE_PROC = "user_source_proc"
    USER_UNCLASSIFIED = "user_unclassified"
    IMPORT_STUB = "import_stub"
    SIGNATURE_MATCH = "signature_match"
    RUNTIME_PREFIX = "runtime_prefix"
    RUNTIME_KNOWN_NAME = "runtime_known_name"
    NON_SOURCE_SIDECAR_LABEL = "non_source_sidecar_label"


_LIBRARY_CLASSES = frozenset(
    {
        LibraryFunctionClass.IMPORT_STUB,
        LibraryFunctionClass.SIGNATURE_MATCH,
        LibraryFunctionClass.RUNTIME_PREFIX,
        LibraryFunctionClass.RUNTIME_KNOWN_NAME,
        LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL,
    }
)


@dataclass(frozen=True)
class LibraryLabelFilterResult:
    labels: dict[int, str]
    decisions: dict[int, LibraryFunctionClass]
    skipped_by_class: Mapping[LibraryFunctionClass, int]

    @property
    def skipped_count(self) -> int:
        return sum(self.skipped_by_class.values())


_GENERIC_C_RUNTIME_NAMES = frozenset(
    {
        "abs",
        "atoi",
        "atol",
        "clock",
        "exit",
        "fclose",
        "fflush",
        "fopen",
        "fprintf",
        "fread",
        "free",
        "fwrite",
        "getc",
        "getch",
        "getche",
        "getenv",
        "inp",
        "labs",
        "lseek",
        "malloc",
        "memcmp",
        "memcpy",
        "memset",
        "outp",
        "printf",
        "putc",
        "puts",
        "rand",
        "realloc",
        "scanf",
        "sprintf",
        "srand",
        "strcat",
        "strcmp",
        "strcpy",
        "strlen",
        "strncat",
        "strncmp",
        "strncpy",
        "time",
        "toupper",
        "write",
    }
)

_MS_C_RUNTIME_NAMES = frozenset(
    {
        "amsg_exit",
        "anldiv",
        "anlmul",
        "anchkstk",
        "astart",
        "catox",
        "cexit",
        "c_exit",
        "cintdiv",
        "cinit",
        "clearscreen",
        "clock",
        "ctermsub",
        "dataseg",
        "displaycursor",
        "dos_getdate",
        "dos_gettime",
        "dosret0",
        "dosretax",
        "dosreturn",
        "dtoxtime",
        "ff_msgbanner",
        "findlast",
        "flsbuf",
        "flushall",
        "fptrap",
        "ftime",
        "getbkcolor",
        "getbuf",
        "gettextcolor",
        "gettextcursor",
        "gettextposition",
        "getvideoconfig",
        "growseg",
        "grstatus",
        "incseg",
        "inittime",
        "isindst",
        "maperror",
        "myalloc",
        "nfree",
        "nmalloc",
        "nmsg_text",
        "nmsg_write",
        "nullcheck",
        "outmem",
        "output",
        "outtext",
        "searchseg",
        "setargv",
        "setbkcolor",
        "setenvp",
        "settextcolor",
        "settextcursor",
        "settextposition",
        "settextrows",
        "setvideomode",
        "setvideomoderows",
        "stackavail",
        "tzset",
    }
)

_RUNTIME_PREFIXES = (
    "__",
    "_ci",
    "_nci",
    "$",
    "b$",
)

_MS_HELPER_PREFIXES = (
    "an",
    "b$",
    "ff_",
    "nmsg_",
)


def normalize_library_symbol_name(name: str) -> str:
    return (name or "").strip().lstrip("_").lower()


def classify_library_function_name(name: str) -> LibraryFunctionClass:
    raw = (name or "").strip()
    lowered = raw.lower()
    if (
        lowered.startswith("sym.imp.")
        or lowered.startswith("fcn.imp.")
        or ".imp." in lowered
        or lowered.startswith("import_")
        or lowered.startswith("imp.")
    ):
        return LibraryFunctionClass.IMPORT_STUB
    normalized = normalize_library_symbol_name(raw)
    if not normalized:
        return LibraryFunctionClass.USER_UNCLASSIFIED
    if normalized in _GENERIC_C_RUNTIME_NAMES or normalized in _MS_C_RUNTIME_NAMES:
        return LibraryFunctionClass.RUNTIME_KNOWN_NAME
    if lowered.startswith("_") and len(lowered) > 1 and lowered[1].isalpha():
        return LibraryFunctionClass.RUNTIME_PREFIX
    if any(lowered.startswith(prefix) for prefix in _RUNTIME_PREFIXES):
        return LibraryFunctionClass.RUNTIME_PREFIX
    if any(normalized.startswith(prefix) for prefix in _MS_HELPER_PREFIXES):
        return LibraryFunctionClass.RUNTIME_PREFIX
    return LibraryFunctionClass.USER_UNCLASSIFIED


def is_library_like_function_name(name: str) -> bool:
    return classify_library_function_name(name) in _LIBRARY_CLASSES


def classify_sidecar_function_label(
    addr: int,
    name: str,
    metadata: object | None,
) -> LibraryFunctionClass:
    proc_addrs = set((getattr(metadata, "cod_proc_kinds", None) or {}).keys())
    if addr in proc_addrs:
        return LibraryFunctionClass.USER_SOURCE_PROC
    signature_addrs = set(getattr(metadata, "signature_code_addrs", frozenset()) or frozenset())
    if addr in signature_addrs:
        return LibraryFunctionClass.SIGNATURE_MATCH
    source_format = str(getattr(metadata, "source_format", "") or "")
    if proc_addrs and "cod_listing" in source_format:
        return LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL
    return classify_library_function_name(name)


def filter_code_labels_for_library_policy(
    metadata: object | None,
    labels: Mapping[int, str],
) -> LibraryLabelFilterResult:
    kept: dict[int, str] = {}
    decisions: dict[int, LibraryFunctionClass] = {}
    skipped: Counter[LibraryFunctionClass] = Counter()
    for addr, name in labels.items():
        decision = classify_sidecar_function_label(int(addr), str(name), metadata)
        decisions[int(addr)] = decision
        if decision in _LIBRARY_CLASSES:
            skipped[decision] += 1
            continue
        kept[int(addr)] = str(name)
    return LibraryLabelFilterResult(
        labels=kept,
        decisions=decisions,
        skipped_by_class=dict(skipped),
    )
