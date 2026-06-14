from __future__ import annotations

import builtins as _builtins
import os
import re
import sys
import time

_RAW_PRINT = _builtins.print


def _brief_mode() -> bool:
    return os.environ.get("INERTIA_BRIEF", "").lower() in ("1", "true", "yes")


def _timestamp_prefix() -> str:
    if _brief_mode():
        return ""
    return time.strftime("[%H:%M:%S]")


def _looks_like_diagnostic_line(line: str) -> bool:
    stripped = line.lstrip()
    if re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+", stripped):
        stripped = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s+", "", stripped, count=1)
    return (
        stripped.startswith("/*")
        or stripped.startswith("[dbg]")
        or stripped.startswith("summary:")
        or stripped.startswith("WARNING")
        or stripped.startswith("ERROR")
    )


def _timestamped_print(*args, **kwargs):
    def _impl():
        sep = kwargs.pop("sep", " ")
        end = kwargs.pop("end", "\n")
        file = kwargs.pop("file", None)
        flush = kwargs.pop("flush", False)
        text = sep.join(str(arg) for arg in args)
        pytest_mode = "PYTEST_CURRENT_TEST" in os.environ
        if pytest_mode or _brief_mode():
            return _RAW_PRINT(text, end=end, file=file, flush=flush)
        if file is None and text:
            lines = text.splitlines()
            if lines and all((not line.strip()) or _looks_like_diagnostic_line(line) for line in lines):
                target = sys.stderr
                stamped = "\n".join(
                    (line if re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+", line.lstrip()) else f"{_timestamp_prefix()} {line}")
                    if line.strip()
                    else line
                    for line in lines
                )
                return _RAW_PRINT(stamped, end=end, file=target, flush=flush)
        return _RAW_PRINT(text, end=end, file=file, flush=flush)

    return _impl()


def _print_diagnostic_text(text: str) -> None:
    if not text:
        return
    pytest_mode = "PYTEST_CURRENT_TEST" in os.environ
    if _brief_mode() or pytest_mode:
        for line in text.splitlines():
            _RAW_PRINT(line)
        return
    for line in text.splitlines():
        stamped = line if re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+", line.lstrip()) else f"{_timestamp_prefix()} {line}"
        _RAW_PRINT(stamped, file=sys.stderr)


def _asm_fallback_pattern_note(asm_text: str) -> str | None:
    if _brief_mode():
        return None
    stripped = asm_text.strip()
    if not stripped or stripped.startswith("<"):
        return None
    lowered = stripped.lower()
    patterns: list[str] = []
    if re.search(r"\brep(?:e|ne)?\s+movs[bdqw]?\b", lowered):
        patterns.append("copy loop")
    if re.search(r"\brep(?:e|ne)?\s+stos[bdqw]?\b", lowered):
        patterns.append("fill loop")
    if re.search(r"\brepne\s+scas[bdqw]?\b", lowered):
        patterns.append("scan loop")
    if re.search(r"\brepe\s+cmps[bdqw]?\b", lowered):
        patterns.append("compare loop")
    if not patterns:
        return None
    joined = ", ".join(patterns)
    return f"assembly pattern: x86 string-instruction {joined}; evidence from asm, not guessed C"


def _print_asm_fallback_text(asm_text: str) -> None:
    note = _asm_fallback_pattern_note(asm_text)
    if note is not None:
        _timestamped_print(f"/* note: {note} */")
    _print_diagnostic_text(asm_text)


def _emit_exit_marker() -> None:
    if "PYTEST_CURRENT_TEST" in os.environ or _brief_mode():
        return
    _RAW_PRINT(f"{_timestamp_prefix()} /* exiting cli */", file=sys.stderr)
