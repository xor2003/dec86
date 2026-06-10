from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools.dosunit.model import DosUnitError, normalize_hex, stable_id


_MZRE_SEGMENT_RE = re.compile(r"^([A-Za-z_]\w*)\s+(CODE|DATA|STACK)\s+([0-9A-Fa-f]+)$", re.IGNORECASE)
_MZRE_ROUTINE_RE = re.compile(
    r"^([A-Za-z_]\w*):\s+([A-Za-z_]\w*)\s+(NEAR|FAR)\s+([0-9A-Fa-f]+)-([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_IDA_SEGMENT_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+"
    r"(?P<name>[A-Za-z_]\w*)\s+segment\b.*'(?P<class>[A-Za-z_]\w*)'",
    re.IGNORECASE,
)
_IDA_PROC_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+"
    r"(?P<name>[A-Za-z_$?@][\w$?@]*)\s+proc\s+(?P<kind>near|far)\b",
    re.IGNORECASE,
)
_LINK_SEGMENT_RE = re.compile(
    r"^\s*(?P<start>[0-9A-Fa-f]+)H\s+(?P<stop>[0-9A-Fa-f]+)H\s+"
    r"(?P<length>[0-9A-Fa-f]+)H\s+(?P<name>\S+)\s+(?P<class>\S+)\s*$"
)
_LINK_PUBLIC_RE = re.compile(
    r"^\s*(?P<seg>[0-9A-Fa-f]{4}):(?P<off>[0-9A-Fa-f]{4})\s+(?P<name>\S+)\s*$"
)
_LINK_GROUP_RE = re.compile(r"^\s*(?P<seg>[0-9A-Fa-f]{4}):(?P<off>[0-9A-Fa-f]+)\s+(?P<name>\S+)\s*$")


def read_mz_program_info(exe_path: Path | None) -> dict[str, Any]:
    if exe_path is None:
        return {"program_kind": "unknown"}
    data = exe_path.read_bytes()
    if exe_path.suffix.lower() == ".com" or data[:2] != b"MZ":
        return {
            "program_kind": "com",
            "entry": {"cs": "auto", "ip": "0x0100", "kind": "near"},
            "image_size": len(data),
        }
    if len(data) < 0x1C:
        raise DosUnitError(f"truncated MZ executable: {exe_path}")
    header_paragraphs = int.from_bytes(data[0x08:0x0A], "little")
    relocation_count = int.from_bytes(data[0x06:0x08], "little")
    relocation_offset = int.from_bytes(data[0x18:0x1A], "little")
    initial_ip = int.from_bytes(data[0x14:0x16], "little")
    initial_cs = int.from_bytes(data[0x16:0x18], "little")
    initial_sp = int.from_bytes(data[0x10:0x12], "little")
    initial_ss = int.from_bytes(data[0x0E:0x10], "little")
    return {
        "program_kind": "mz_exe",
        "mz": {
            "header_paragraphs": header_paragraphs,
            "relocation_count": relocation_count,
            "relocation_offset": relocation_offset,
            "initial_cs": normalize_hex(initial_cs, width=4),
            "initial_ip": normalize_hex(initial_ip, width=4),
            "initial_ss": normalize_hex(initial_ss, width=4),
            "initial_sp": normalize_hex(initial_sp, width=4),
            "image_offset": header_paragraphs * 16,
            "image_size": max(0, len(data) - header_paragraphs * 16),
        },
        "entry": {
            "cs": normalize_hex(initial_cs, width=4),
            "ip": normalize_hex(initial_ip, width=4),
            "kind": "near",
        },
    }


def _function_id(module: str, name: str, segment: str, offset: int) -> str:
    stable_name = name or f"{segment}_{offset:04x}"
    return f"{module}:{stable_name}"


def _normalize_symbol_name(name: str) -> str:
    if name.startswith("__"):
        return name
    if name.startswith("_"):
        return name[1:]
    return name


def _catalog_entry(
    *,
    module: str,
    name: str,
    segment: str,
    offset: int,
    source: str,
    return_kind: str = "near",
    segment_para: int | None = None,
    end: int | None = None,
    confidence: str = "medium",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": _function_id(module, name, segment, offset),
        "names": [name] if name else [],
        "entry": {
            "kind": "module_relative",
            "segment": segment,
            "offset": normalize_hex(offset, width=4),
        },
        "return_kind": return_kind.lower(),
        "sources": [source],
        "confidence": confidence,
        "size": None if end is None else max(0, end - offset + 1),
        "safe_traps": [],
    }
    if segment_para is not None:
        entry["entry"]["segment_para"] = normalize_hex(segment_para, width=4)
        entry["entry"]["linear"] = normalize_hex((segment_para << 4) + offset)
    if end is not None:
        entry["end_offset"] = normalize_hex(end, width=4)
    return entry


def _merge_entry(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    for name in incoming.get("names", ()):
        if name not in existing["names"]:
            existing["names"].append(name)
    for source in incoming.get("sources", ()):
        if source not in existing["sources"]:
            existing["sources"].append(source)
    if existing.get("confidence") != "high" and len(existing.get("sources", ())) >= 2:
        existing["confidence"] = "high"
    for key in ("size", "end_offset"):
        if existing.get(key) is None and incoming.get(key) is not None:
            existing[key] = incoming[key]
    entry = existing.setdefault("entry", {})
    for key, value in incoming.get("entry", {}).items():
        entry.setdefault(key, value)


def parse_mzre_segments(map_path: Path) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _MZRE_SEGMENT_RE.match(line.strip())
        if segment_match is None:
            continue
        segments.append(
            {
                "name": segment_match.group(1),
                "class": segment_match.group(2).upper(),
                "paragraph": normalize_hex(int(segment_match.group(3), 16), width=4),
                "source": "mzre_map",
            }
        )
    return segments


def parse_linker_segments(map_path: Path) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    in_group_section = False
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _LINK_SEGMENT_RE.match(line)
        if segment_match is not None:
            start = int(segment_match.group("start"), 16)
            segments.append(
                {
                    "name": segment_match.group("name"),
                    "class": segment_match.group("class").upper(),
                    "paragraph": normalize_hex(start >> 4, width=4),
                    "linear_start": normalize_hex(start),
                    "linear_stop": normalize_hex(int(segment_match.group("stop"), 16)),
                    "source": "link_map",
                }
            )
            continue
        if line.strip() == "Origin   Group":
            in_group_section = True
            continue
        if in_group_section:
            group_match = _LINK_GROUP_RE.match(line)
            if group_match is not None:
                segments.append(
                    {
                        "name": group_match.group("name"),
                        "class": "DATA",
                        "paragraph": normalize_hex(int(group_match.group("seg"), 16), width=4),
                        "source": "link_map_group",
                    }
                )
                continue
            if line.strip() == "":
                in_group_section = False
    return segments


def parse_mzre_map(map_path: Path, *, module: str) -> list[dict[str, Any]]:
    segment_paragraphs: dict[str, int] = {}
    entries: list[dict[str, Any]] = []
    for line in map_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        segment_match = _MZRE_SEGMENT_RE.match(stripped)
        if segment_match is not None:
            segment_paragraphs[segment_match.group(1)] = int(segment_match.group(3), 16)
            continue
        routine_match = _MZRE_ROUTINE_RE.match(stripped)
        if routine_match is None:
            continue
        name = _normalize_symbol_name(routine_match.group(1))
        segment = routine_match.group(2)
        return_kind = routine_match.group(3).lower()
        start = int(routine_match.group(4), 16)
        end = int(routine_match.group(5), 16)
        entries.append(
            _catalog_entry(
                module=module,
                name=name,
                segment=segment,
                offset=start,
                end=end,
                return_kind=return_kind,
                segment_para=segment_paragraphs.get(segment),
                source="mzre_map",
                confidence="medium",
            )
        )
    return entries


def parse_linker_map(map_path: Path, *, module: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    entries_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _LINK_SEGMENT_RE.match(line)
        if segment_match is not None:
            start = int(segment_match.group("start"), 16)
            stop = int(segment_match.group("stop"), 16)
            segments.append(
                {
                    "start": start,
                    "stop": stop,
                    "class": segment_match.group("class").upper(),
                    "name": segment_match.group("name"),
                }
            )
            continue
        public_match = _LINK_PUBLIC_RE.match(line)
        if public_match is None:
            continue
        seg = int(public_match.group("seg"), 16)
        off = int(public_match.group("off"), 16)
        linear = (seg << 4) + off
        if not _linear_in_code_segment(linear, segments):
            continue
        raw_name = public_match.group("name")
        name = _normalize_symbol_name(raw_name)
        if not name:
            continue
        key = (name, linear)
        entries_by_key.setdefault(
            key,
            _catalog_entry(
                module=module,
                name=name,
                segment=f"{seg:04x}",
                offset=off,
                return_kind="near",
                segment_para=seg,
                source="link_map",
                confidence="medium",
            ),
        )
    return sorted(entries_by_key.values(), key=lambda item: int(item["entry"].get("linear", "0"), 0))


def _linear_in_code_segment(linear: int, segments: list[dict[str, Any]]) -> bool:
    for segment in segments:
        if segment.get("class") == "CODE" and int(segment["start"]) <= linear <= int(segment["stop"]):
            return True
    return False


def parse_ida_listing(listing_path: Path, *, module: str) -> list[dict[str, Any]]:
    segment_classes: dict[str, str] = {}
    entries: list[dict[str, Any]] = []
    for line in listing_path.read_text(errors="ignore").splitlines():
        segment_match = _IDA_SEGMENT_RE.match(line.strip())
        if segment_match is not None:
            segment_classes[segment_match.group("name")] = segment_match.group("class").upper()
            continue
        proc_match = _IDA_PROC_RE.match(line.strip())
        if proc_match is None:
            continue
        segment = proc_match.group("seg")
        segment_class = segment_classes.get(segment)
        if segment_class is not None and segment_class != "CODE":
            continue
        offset = int(proc_match.group("off"), 16)
        name = _normalize_symbol_name(proc_match.group("name"))
        confidence = "medium" if segment_class == "CODE" else "low"
        entries.append(
            _catalog_entry(
                module=module,
                name=name,
                segment=segment,
                offset=offset,
                return_kind=proc_match.group("kind").lower(),
                source="ida_lst",
                confidence=confidence,
            )
        )
    return entries


def discover_functions(
    *,
    exe_path: Path | None = None,
    map_path: Path | None = None,
    ida_listing_path: Path | None = None,
    module: str | None = None,
) -> dict[str, Any]:
    module_name = module or (exe_path.name if exe_path is not None else None)
    if module_name is None:
        if map_path is not None:
            module_name = map_path.with_suffix(".exe").name
        elif ida_listing_path is not None:
            module_name = ida_listing_path.with_suffix(".exe").name
        else:
            raise DosUnitError("module name is required when no input paths are provided")

    program_info = read_mz_program_info(exe_path)
    by_id: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []
    segments: list[dict[str, Any]] = []
    if map_path is not None:
        try:
            segments.extend(parse_mzre_segments(map_path))
            segments.extend(parse_linker_segments(map_path))
        except Exception as ex:  # noqa: BLE001 - surfaced as structured diagnostic
            diagnostics.append(
                {
                    "source": str(map_path),
                    "status": "refused",
                    "reason": "backend_error",
                    "message": str(ex),
                }
            )
    for source_path, parser in ((map_path, parse_mzre_map), (map_path, parse_linker_map), (ida_listing_path, parse_ida_listing)):
        if source_path is None:
            continue
        try:
            entries = parser(source_path, module=module_name)
        except Exception as ex:  # noqa: BLE001 - surfaced as structured diagnostic
            diagnostics.append(
                {
                    "source": str(source_path),
                    "status": "refused",
                    "reason": "backend_error",
                    "message": str(ex),
                }
            )
            continue
        for entry in entries:
            key = entry["id"]
            if key in by_id:
                _merge_entry(by_id[key], entry)
            else:
                by_id[key] = entry

    def _sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
        linear = item.get("entry", {}).get("linear")
        if isinstance(linear, str):
            try:
                return (0, int(linear, 0), str(item.get("id", "")))
            except ValueError:
                pass
        return (1, 0, str(item.get("id", "")))

    functions = sorted(by_id.values(), key=_sort_key)
    catalog_without_id = {
        "schema": "dosunit.functions.v1",
        "module": module_name,
        "program_kind": program_info.get("program_kind", "unknown"),
        "program": program_info,
        "segments": segments,
        "functions": functions,
        "diagnostics": diagnostics,
    }
    catalog = dict(catalog_without_id)
    catalog["id"] = stable_id("functions", catalog_without_id)
    return catalog


def function_for_linear(catalog: dict[str, Any], linear: int) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    best_start = -1
    for function in catalog.get("functions", ()) or ():
        entry = function.get("entry", {})
        linear_text = entry.get("linear")
        if not isinstance(linear_text, str):
            continue
        try:
            start = int(linear_text, 0)
        except ValueError:
            continue
        size = function.get("size")
        end = start + int(size) if isinstance(size, int) and size > 0 else start + 1
        if start <= linear < end and start > best_start:
            best = function
            best_start = start
    return best
