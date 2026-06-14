from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re


_COMMENT_PREFIXES = ("/*", "*", "*/", "//")


def _strip_c_comments_and_strings(line: str) -> str:
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r"//.*$", "", line)
    return line


@lru_cache(maxsize=16)
def _read_lines(path: Path) -> tuple[str, ...]:
    return tuple(path.read_text(errors="ignore").splitlines())


def _candidate_source_paths(binary_path: Path | None) -> tuple[Path, ...]:
    if binary_path is None:
        return ()
    stem = binary_path.with_suffix("")
    candidates = []
    for suffix in (".c", ".C"):
        path = stem.with_suffix(suffix)
        if path.exists():
            candidates.append(path)
    return tuple(candidates)


_FUNCTION_HEADER_KEYWORDS = frozenset(
    {
        "for",
        "if",
        "switch",
        "while",
    }
)


def _looks_like_function_header(line: str, function_name: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES):
        return False
    if ";" in stripped:
        return False
    if not re.search(rf"\b{re.escape(function_name)}\s*\(", stripped):
        return False
    return bool(
        re.match(rf"^\s*(?:[A-Za-z_][\w\s\*\[\]]+\s+)?{re.escape(function_name)}\s*\(", stripped)
    )


def _extract_function_from_lines(lines: tuple[str, ...], function_name: str) -> str | None:
    def _impl():
        start_idx = None
        open_idx = None
        for idx, raw in enumerate(lines):
            line = _strip_c_comments_and_strings(raw)
            if not _looks_like_function_header(line, function_name):
                continue
            start_idx = idx
            if "{" in line:
                open_idx = idx
                break
            for probe in range(idx + 1, min(idx + 12, len(lines))):
                probe_line = _strip_c_comments_and_strings(lines[probe])
                if "{" in probe_line:
                    open_idx = probe
                    break
            if open_idx is not None:
                break
        if start_idx is None or open_idx is None:
            return None

        comment_start = start_idx
        while comment_start > 0:
            prev = lines[comment_start - 1].strip()
            if not prev:
                comment_start -= 1
                continue
            if prev.startswith(_COMMENT_PREFIXES):
                comment_start -= 1
                continue
            break

        depth = 0
        end_idx = None
        for idx in range(open_idx, len(lines)):
            line = _strip_c_comments_and_strings(lines[idx])
            depth += line.count("{")
            depth -= line.count("}")
            if idx > open_idx and depth <= 0 and "}" in line:
                end_idx = idx
                break
        if end_idx is None:
            return None
        selected = list(lines[comment_start : end_idx + 1])
        while selected and not selected[0].strip():
            selected.pop(0)
        return "\n".join(selected).rstrip() + "\n"

    return _impl()


def _source_function_header_match(line: str) -> re.Match[str] | None:
    stripped = _strip_c_comments_and_strings(line).strip()
    if not stripped or stripped.startswith("#") or ";" in stripped or "}" in stripped:
        return None
    match = re.match(
        r"^(?:(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+)?"
        r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}()]*\)\s*\{?\s*$",
        stripped,
    )
    if match is None:
        return None
    if match.group("name") in _FUNCTION_HEADER_KEYWORDS:
        return None
    return match


def _source_header_has_body(lines: tuple[str, ...], header_index: int) -> bool:
    if "{" in _strip_c_comments_and_strings(lines[header_index]):
        return True
    for probe in range(header_index + 1, min(header_index + 12, len(lines))):
        stripped = _strip_c_comments_and_strings(lines[probe]).strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "{" in stripped:
            return True
        if ";" in stripped:
            return False
    return False


@lru_cache(maxsize=16)
def _collect_source_return_types_for_path(path: Path) -> dict[str, str]:
    lines = _read_lines(path)
    result: dict[str, str] = {}
    for index, line in enumerate(lines):
        match = _source_function_header_match(line)
        if match is None or not _source_header_has_body(lines, index):
            continue
        name = match.group("name")
        return_type = " ".join((match.group("ret") or "int").split())
        if not name or name in result:
            continue
        result[name] = return_type
    for name, return_type in list(result.items()):
        if name.startswith("_"):
            result.setdefault(name[1:], return_type)
    return result


def collect_local_source_sidecar_return_types(binary_path: Path | None) -> dict[str, str]:
    if binary_path is None:
        return {}
    merged: dict[str, str] = {}
    for path in _candidate_source_paths(binary_path):
        for name, return_type in _collect_source_return_types_for_path(path).items():
            merged.setdefault(name, return_type)
    return merged


def render_local_source_sidecar_function(binary_path: Path | None, function_name: str | None) -> str | None:
    if binary_path is None or not isinstance(function_name, str) or not function_name:
        return None
    source_name = function_name.lstrip("_")
    if not source_name:
        return None
    for path in _candidate_source_paths(binary_path):
        rendered = _extract_function_from_lines(_read_lines(path), source_name)
        if rendered is not None:
            return rendered
    return None
