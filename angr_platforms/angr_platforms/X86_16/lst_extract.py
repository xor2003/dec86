from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path


@dataclass(frozen=True)
class LSTMetadata:
    data_labels: dict[int, str]
    code_labels: dict[int, str]
    code_ranges: dict[int, tuple[int, int]] = field(default_factory=dict)
    absolute_addrs: bool = False
    source_format: str = "generic_lst"
    struct_names: tuple[str, ...] = ()


_DATA_LABEL_RE = re.compile(
    r"^([0-9A-Fa-f]{8})\s+(?:[0-9A-Fa-f]{2}\s+)+([A-Za-z_$?@][\w$?@]*)\s+(db|dw|dd|dq|dt)\b",
    re.IGNORECASE,
)
_CODE_LABEL_RE = re.compile(
    r"^([0-9A-Fa-f]{8})\s+([A-Za-z_$?@][\w$?@]*)\s+proc\b",
    re.IGNORECASE,
)


def extract_lst_metadata(lst_path: Path) -> LSTMetadata:
    lines = lst_path.read_text(errors="ignore").splitlines()
    data_labels: dict[int, str] = {}
    code_labels: dict[int, str] = {}

    current_segment: str | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        upper = stripped.upper()
        if "SEGMENT" in upper and "USE16" in upper:
            if "CODE" in upper:
                current_segment = "CODE"
            elif "DATA" in upper:
                current_segment = "DATA"
            continue

        if current_segment == "DATA":
            match = _DATA_LABEL_RE.match(stripped)
            if match is not None:
                offset = int(match.group(1), 16)
                data_labels.setdefault(offset, match.group(2))
            continue

        if current_segment == "CODE":
            match = _CODE_LABEL_RE.match(stripped)
            if match is not None:
                offset = int(match.group(1), 16)
                code_labels.setdefault(offset, match.group(2))

    return LSTMetadata(data_labels=data_labels, code_labels=code_labels, code_ranges={})
