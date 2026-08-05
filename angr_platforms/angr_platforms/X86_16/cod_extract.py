"""Layer: Optional evidence/reporting.

Responsibility: parse COD listings into labels, bounds, source lines, and diagnostic metadata.
Forbidden: using COD text as required proof for arguments, types, control flow, or validation success.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .cod_known_objects import canonical_known_cod_object_name


@dataclass(frozen=True)
class CODGlobalRef:
    """Optional COD evidence for a global memory reference in one instruction."""

    offset: int
    name: str
    relative_disp: int
    width: int
    indexed: bool
    instruction_bytes: bytes
    source_alias: str | None = None


@dataclass(frozen=True)
class CODGlobalAddressRef:
    """Optional COD evidence for an immediate global-address reference."""

    offset: int
    name: str
    relative_disp: int
    width: int
    instruction_bytes: bytes
    string_literal: str | None = None
    source_alias: str | None = None


@dataclass(frozen=True)
class CODProcMetadata:
    """Optional COD procedure metadata used as labels and diagnostics only."""

    stack_aliases: dict[int, str]
    call_names: tuple[str, ...]
    call_sources: tuple[tuple[str, str], ...]
    global_names: tuple[str, ...]
    source_lines: tuple[str, ...]
    source_line_set: frozenset[str]
    global_refs: tuple[CODGlobalRef, ...] = ()
    global_address_refs: tuple[CODGlobalAddressRef, ...] = ()
    instruction_offsets: tuple[int, ...] = ()
    cod_raw_entries: tuple[dict[str, object], ...] = ()
    cod_path: str | None = None

    def has_source_lines(self, required_lines: tuple[str, ...]) -> bool:
        """Return whether this COD procedure includes all required source lines."""
        if not required_lines:
            return True
        return set(required_lines).issubset(self.source_line_set)


@dataclass(frozen=True)
class CODListingMetadata:
    """Procedure labels and ranges parsed from one COD listing."""

    code_labels: dict[int, str]
    code_ranges: dict[int, tuple[int, int]]
    proc_kinds: dict[int, str]


def extract_cod_function_entries(cod_path: Path, proc_name: str, proc_kind: str = "NEAR") -> list[dict[str, object]]:
    """Extract instruction rows for a named COD procedure."""
    lines = cod_path.read_text(errors="ignore").splitlines()
    start_marker = f"{proc_name}\tPROC {proc_kind}"
    end_marker = f"{proc_name}\tENDP"

    collect = False
    entries: list[dict[str, object]] = []
    for line in lines:
        if start_marker in line:
            collect = True
            continue
        if collect and end_marker in line:
            break
        if not collect:
            continue

        match = re.search(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$", line)
        if not match:
            continue

        entries.append(
            {
                "offset": int(match.group(1), 16),
                "bytes": bytes.fromhex("".join(match.group(2).split())),
                "text": match.group(3).strip(),
            }
        )

    if not entries:
        raise ValueError(f"did not find {proc_name} ({proc_kind}) in {cod_path}")
    return entries


def extract_cod_listing_metadata(cod_path: Path) -> CODListingMetadata:
    """Extract procedure names, ranges, and kinds from a COD listing."""
    lines = cod_path.read_text(errors="ignore").splitlines()
    proc_re = re.compile(r"^\s*(?P<name>[A-Za-z_$?@][\w$?@]*)\s+PROC\s+(?P<kind>[A-Za-z]+)\b", re.IGNORECASE)
    endp_re = re.compile(r"^\s*(?P<name>[A-Za-z_$?@][\w$?@]*)\s+ENDP\b", re.IGNORECASE)
    entry_re = re.compile(r"\*\*\*\s+(?P<offset>[0-9A-Fa-f]+)\s+(?P<bytes>(?:[0-9A-Fa-f]{2}\s+)+)")

    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    proc_kinds: dict[int, str] = {}

    current_name: str | None = None
    current_kind: str | None = None
    current_start: int | None = None
    current_end: int | None = None

    def _finalize_current() -> None:
        nonlocal current_name, current_kind, current_start, current_end
        if current_name is None or current_kind is None or current_start is None:
            current_name = None
            current_kind = None
            current_start = None
            current_end = None
            return
        end = current_end if current_end is not None and current_end > current_start else current_start + 1
        code_labels.setdefault(current_start, current_name)
        code_ranges.setdefault(current_start, (current_start, end))
        proc_kinds.setdefault(current_start, current_kind)
        current_name = None
        current_kind = None
        current_start = None
        current_end = None

    for line in lines:
        proc_match = proc_re.match(line)
        if proc_match is not None:
            _finalize_current()
            current_name = proc_match.group("name")
            current_kind = proc_match.group("kind").upper()
            continue
        if current_name is None:
            continue
        end_match = endp_re.match(line)
        if end_match is not None and end_match.group("name") == current_name:
            _finalize_current()
            continue
        entry_match = entry_re.search(line)
        if entry_match is None:
            continue
        offset = int(entry_match.group("offset"), 16)
        byte_count = len(entry_match.group("bytes").split())
        if current_start is None:
            current_start = offset
        current_end = max(current_end or 0, offset + max(byte_count, 1))

    _finalize_current()
    return CODListingMetadata(code_labels=code_labels, code_ranges=code_ranges, proc_kinds=proc_kinds)


def extract_cod_proc_metadata(cod_path: Path, proc_name: str, proc_kind: str = "NEAR") -> CODProcMetadata:
    """Extract optional COD labels and source comments for one procedure."""

    def _impl() -> CODProcMetadata:
        def _marker_indices_or_raise(lines: list[str]) -> tuple[int, int]:
            start_marker = f"{proc_name}\tPROC {proc_kind}"
            end_marker = f"{proc_name}\tENDP"
            start_index = next((idx for idx, line in enumerate(lines) if start_marker in line), None)
            end_index = next((idx for idx, line in enumerate(lines) if end_marker in line), None)
            if start_index is None or end_index is None or end_index <= start_index:
                raise ValueError(f"did not find {proc_name} ({proc_kind}) in {cod_path}")
            return start_index, end_index

        def _cod_source_comment_text(line: str) -> str:
            return re.sub(r"^\s*;\|\*+\s*", "", line).strip()

        def _canonical_name(name: str) -> str:
            return canonical_known_cod_object_name(name) or name

        def _remember_call_source(
            source_text: str, call_sources: list[tuple[str, str]], seen_call_texts: set[str]
        ) -> None:
            for call_name, call_text in _extract_source_call_expressions(source_text):
                if call_name in {"if", "while", "for", "switch", "return"} or call_name.startswith("$"):
                    continue
                if call_text in seen_call_texts:
                    continue
                seen_call_texts.add(call_text)
                call_sources.append((_canonical_name(call_name), call_text))

        asm_call_operand_markers = {"BYTE", "WORD", "DWORD", "QWORD", "FWORD", "PTR", "NEAR", "FAR"}

        def _remember_asm_calls(asm_text: str, call_re: re.Pattern[str], call_names: list[str]) -> None:
            for call_match in call_re.finditer(asm_text):
                callee = call_match.group(1)
                if callee == "__chkstk" or callee.startswith("$") or callee.upper() in asm_call_operand_markers:
                    continue
                canonical_callee = _canonical_name(callee)
                call_names.append(canonical_callee)

        def _remember_asm_globals(
            asm_text: str,
            pattern: re.Pattern[str],
            global_names: list[str],
            seen_globals: set[str],
            segment_registers: set[str],
        ) -> None:
            for match in pattern.finditer(asm_text):
                global_name = match.group(1)
                if global_name.startswith("$") or global_name == proc_name or global_name.lower() in segment_registers:
                    continue
                canonical_name = _canonical_name(global_name)
                if canonical_name not in seen_globals:
                    seen_globals.add(canonical_name)
                    global_names.append(canonical_name)

        lines = cod_path.read_text(errors="ignore").splitlines()
        start_index, end_index = _marker_indices_or_raise(lines)

        collect = False
        stack_aliases: dict[int, str] = {}
        call_names: list[str] = []
        call_sources: list[tuple[str, str]] = []
        global_names: list[str] = []
        seen_call_texts: set[str] = set()
        seen_globals: set[str] = set()
        source_lines: list[str] = []

        previous_end_index = next(
            (idx for idx in range(start_index - 1, -1, -1) if lines[idx].strip().endswith("ENDP")),
            -1,
        )
        prelude_lines = [line for line in lines[previous_end_index + 1 : start_index] if line.lstrip().startswith(";")]

        alias_re = re.compile(r"^\s*;\s*([A-Za-z_$?@][\w$?@]*)\s*=\s*(-?[0-9A-Fa-f]+)\s*$")
        entry_re = re.compile(r"\*\*\*\s+[0-9A-Fa-f]+\s+(?:[0-9A-Fa-f]{2}\s+)+(.*)$")
        call_re = re.compile(r"\bcall\b(?:\s+far ptr)?\s+([A-Za-z_$?@][\w$?@]*)", re.IGNORECASE)
        global_re = re.compile(r"\b(?:BYTE|WORD|DWORD)\s+PTR\s+([A-Za-z_$?@][\w$?@]*)", re.IGNORECASE)
        offset_global_re = re.compile(
            r"\bOFFSET\s+(?:[A-Za-z_$?@][\w$?@]*:)?\$?([A-Za-z_$?@][\w$?@]*)",
            re.IGNORECASE,
        )
        segment_registers = {"cs", "ds", "es", "ss", "fs", "gs"}

        source_lines.extend(
            _cod_source_comment_text(line) for line in prelude_lines if line.lstrip().startswith(";|***")
        )

        for line in lines[start_index : end_index + 1]:
            if f"{proc_name}\tPROC {proc_kind}" in line:
                collect = True
                continue
            if line.endswith("ENDP") and f"{proc_name}\tENDP" in line:
                break
            if not collect:
                continue

            alias_match = alias_re.match(line)
            if alias_match:
                alias_name = canonical_known_cod_object_name(alias_match.group(1))
                if alias_name is not None:
                    stack_aliases[int(alias_match.group(2), 0)] = alias_name
                continue

            if line.lstrip().startswith(";|***"):
                source_text = _cod_source_comment_text(line)
                if source_text:
                    source_lines.append(source_text)
                    _remember_call_source(source_text, call_sources, seen_call_texts)
                continue

            entry_match = entry_re.search(line)
            if entry_match is None:
                continue
            asm_text = entry_match.group(1).strip()
            _remember_asm_calls(asm_text, call_re, call_names)
            _remember_asm_globals(asm_text, global_re, global_names, seen_globals, segment_registers)
            _remember_asm_globals(asm_text, offset_global_re, global_names, seen_globals, segment_registers)

        raw_entries: list[dict[str, object]] = []
        try:
            raw_entries = extract_cod_function_entries(cod_path, proc_name, proc_kind)
        except Exception:
            pass
        string_literals = _extract_cod_data_string_literals(lines)
        symbol_aliases = _extract_cod_symbol_aliases(lines)
        global_refs = _extract_cod_global_refs_from_entries(raw_entries, symbol_aliases)
        global_address_refs = _extract_cod_global_address_refs_from_entries(
            raw_entries,
            string_literals,
            symbol_aliases,
        )

        return CODProcMetadata(
            stack_aliases=stack_aliases,
            call_names=tuple(call_names),
            call_sources=tuple(call_sources),
            global_names=tuple(global_names),
            source_lines=tuple(source_lines),
            source_line_set=frozenset(source_lines),
            global_refs=tuple(global_refs),
            global_address_refs=tuple(global_address_refs),
            instruction_offsets=tuple(
                offset for entry in raw_entries if (offset := _cod_entry_offset_8616(entry)) is not None
            ),
            cod_raw_entries=tuple(raw_entries),
            cod_path=str(cod_path),
        )

    return _impl()


_COD_GLOBAL_DISP_RE = re.compile(r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))", re.IGNORECASE)
_COD_DIRECT_GLOBAL_REF_RE = re.compile(
    r"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))?(?!\[)",
    re.IGNORECASE,
)
_COD_INDEXED_GLOBAL_REF_RE = re.compile(
    r"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"\[(?P<bracket>[^\]]*)\]",
    re.IGNORECASE,
)
_COD_OFFSET_GLOBAL_REF_RE = re.compile(
    r"\bOFFSET\s+(?:[A-Za-z_$?@][\w$?@]*:)?_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))?",
    re.IGNORECASE,
)
_COD_SYMBOL_ALIAS_RE = re.compile(
    r"^\s*;\s*(?P<generated>\$[A-Za-z][\w$?@]*)\s+EQU\s+(?P<source>[A-Za-z_][\w$?@]*)\s*$",
    re.IGNORECASE,
)


def _extract_cod_symbol_aliases(lines: list[str]) -> dict[str, str]:
    """Return exact compiler-symbol aliases declared by COD ``EQU`` comments."""
    aliases: dict[str, str] = {}
    for line in lines:
        match = _COD_SYMBOL_ALIAS_RE.match(line)
        if match is None:
            continue
        aliases.setdefault(match.group("generated").casefold(), match.group("source"))
    return aliases


def _cod_entry_offset_8616(entry: dict[str, object]) -> int | None:
    """Return a typed COD row offset when the parsed row carries one."""
    offset = entry.get("offset")
    return offset if isinstance(offset, int) else None


def _cod_entry_bytes_8616(entry: dict[str, object]) -> bytes | None:
    """Return typed COD row instruction bytes when the parsed row carries them."""
    data = entry.get("bytes")
    return data if isinstance(data, bytes) else None


def _parse_cod_global_disp(text: str | None) -> int:
    if not text:
        return 0
    sign = -1 if text[0] == "-" else 1
    body = text[1:]
    if body.lower().startswith("0x"):
        value = int(body, 16)
    elif body.upper().endswith("H"):
        value = int(body[:-1], 16)
    else:
        value = int(body, 10)
    return sign * value


def _canonical_cod_global_ref_name(
    raw_name: str | None,
    symbol_aliases: dict[str, str] | None = None,
) -> str | None:
    """Canonicalize one COD global while preserving unique storage identity."""
    if not isinstance(raw_name, str) or not raw_name:
        return None
    raw = raw_name.lstrip("_")
    static_match = re.match(r"^\$[A-Za-z]+\d+_(?P<name>[A-Za-z_]\w*)$", raw)
    if static_match is not None:
        name = f"_{raw.removeprefix('$')}"
        return name if re.fullmatch(r"[A-Za-z_]\w*", name) is not None else None
    alias_name = (symbol_aliases or {}).get(raw.casefold())
    name = canonical_known_cod_object_name(alias_name or raw_name) or alias_name or raw
    name = name.lstrip("_")
    return name if re.fullmatch(r"[A-Za-z_]\w*", name) is not None else None


def _canonical_cod_address_ref_name(
    raw_name: str | None,
    symbol_aliases: dict[str, str] | None = None,
) -> str | None:
    """Canonicalize one COD address while preserving unique storage identity."""
    if not isinstance(raw_name, str) or not raw_name:
        return None
    generated = raw_name.lstrip("_")
    if re.fullmatch(r"\$[A-Za-z]+\d+_[A-Za-z_]\w*", generated) is not None:
        return f"_{generated.removeprefix('$')}"
    raw = raw_name.lstrip("_").lstrip("$")
    alias_name = (symbol_aliases or {}).get(raw_name.lstrip("_").casefold())
    name = canonical_known_cod_object_name(alias_name or raw_name)
    if name is None or not re.fullmatch(r"[A-Za-z_]\w*", name):
        name = alias_name or raw
    return name if re.fullmatch(r"[A-Za-z_]\w*", name) is not None else None


def _extract_cod_global_refs_from_entries(
    entries: list[dict[str, object]],
    symbol_aliases: dict[str, str] | None = None,
) -> tuple[CODGlobalRef, ...]:
    """Extract typed global references from COD instruction rows."""
    width_by_name = {"BYTE": 1, "WORD": 2, "DWORD": 4}
    refs: list[CODGlobalRef] = []
    for entry in entries:
        offset = entry.get("offset")
        instruction_bytes = entry.get("bytes")
        text = str(entry.get("text", ""))
        if not isinstance(offset, int) or not isinstance(instruction_bytes, bytes):
            continue
        indexed_match = _COD_INDEXED_GLOBAL_REF_RE.search(text)
        direct_match = _COD_DIRECT_GLOBAL_REF_RE.search(text) if indexed_match is None else None
        match = indexed_match if indexed_match is not None else direct_match
        if match is None:
            continue
        name = _canonical_cod_global_ref_name(match.group("name"), symbol_aliases)
        width = width_by_name.get(str(match.group("width")).upper())
        if name is None or width is None:
            continue
        if indexed_match is not None:
            disp_match = _COD_GLOBAL_DISP_RE.search(indexed_match.group("bracket") or "")
            relative_disp = _parse_cod_global_disp(disp_match.group("disp")) if disp_match is not None else 0
        else:
            relative_disp = _parse_cod_global_disp(match.group("disp"))
        refs.append(
            CODGlobalRef(
                offset=offset,
                name=name,
                relative_disp=relative_disp,
                width=width,
                indexed=indexed_match is not None,
                instruction_bytes=instruction_bytes,
                source_alias=(symbol_aliases or {}).get(match.group("name").lstrip("_").casefold()),
            )
        )
    return tuple(refs)


def _extract_cod_global_address_refs_from_entries(
    entries: list[dict[str, object]],
    string_literals: dict[str, str] | None = None,
    symbol_aliases: dict[str, str] | None = None,
) -> tuple[CODGlobalAddressRef, ...]:
    """Extract typed global-address references from COD instruction rows."""
    refs: list[CODGlobalAddressRef] = []
    literals = string_literals or {}
    for entry in entries:
        offset = entry.get("offset")
        instruction_bytes = entry.get("bytes")
        text = str(entry.get("text", ""))
        if not isinstance(offset, int) or not isinstance(instruction_bytes, bytes):
            continue
        match = _COD_OFFSET_GLOBAL_REF_RE.search(text)
        if match is None:
            continue
        name = _canonical_cod_address_ref_name(match.group("name"), symbol_aliases)
        if name is None:
            continue
        refs.append(
            CODGlobalAddressRef(
                offset=offset,
                name=name,
                relative_disp=_parse_cod_global_disp(match.group("disp")),
                width=2,
                instruction_bytes=instruction_bytes,
                string_literal=literals.get(name),
                source_alias=(symbol_aliases or {}).get(match.group("name").lstrip("_").casefold()),
            )
        )
    return tuple(refs)


def _extract_cod_data_string_literals(lines: list[str]) -> dict[str, str]:
    literals: dict[str, str] = {}
    data_re = re.compile(r"^\s*(?P<label>[A-Za-z_$?@][\w$?@]*)\s+DB\s+(?P<body>.*)$", re.IGNORECASE)
    for line in lines:
        match = data_re.match(line)
        if match is None:
            continue
        name = _canonical_cod_address_ref_name(match.group("label"))
        if name is None:
            continue
        parsed = _parse_cod_db_string_literal(match.group("body"))
        if parsed is not None:
            literals[name] = parsed
    return literals


def _parse_cod_db_string_literal(body: str) -> str | None:
    text = body.strip()
    if not text.startswith("'"):
        return None
    chars: list[str] = []
    idx = 1
    while idx < len(text):
        char = text[idx]
        if char == "'":
            if idx + 1 < len(text) and text[idx + 1] == "'":
                chars.append("'")
                idx += 2
                continue
            idx += 1
            break
        chars.append(char)
        idx += 1
    else:
        return None
    suffix = text[idx:].strip()
    if suffix.startswith(","):
        suffix = suffix[1:].strip()
    first_token = suffix.split(",", 1)[0].strip().upper()
    if first_token not in {"0", "00H", "0H"}:
        return None
    return "".join(chars)


def _extract_source_call_expressions(source_text: str) -> list[tuple[str, str]]:
    def _match_call(start: int) -> tuple[str, str, int] | None:
        match = re.match(r"([A-Za-z_$?@][\w$?@]*)\s*\(", source_text[start:])
        if match is None:
            return None
        name = match.group(1)
        open_idx = start + match.end() - 1
        depth = 0
        for idx in range(open_idx, len(source_text)):
            ch = source_text[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return name, source_text[start : idx + 1], idx + 1
        return None

    calls: list[tuple[str, str]] = []
    idx = 0
    while idx < len(source_text):
        match = _match_call(idx)
        if match is None:
            idx += 1
            continue
        name, call_text, end_idx = match
        calls.append((name, call_text))
        inner = call_text[call_text.find("(") + 1 : -1]
        calls.extend(_extract_source_call_expressions(inner))
        idx = end_idx
    return calls


def join_cod_entries(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None = None,
    end_offset: int | None = None,
) -> bytes:
    """Join COD instruction bytes for rows inside an optional offset range."""
    return b"".join(
        data
        for entry in entries
        if (offset := _cod_entry_offset_8616(entry)) is not None
        and (data := _cod_entry_bytes_8616(entry)) is not None
        and (start_offset is None or start_offset <= offset)
        and (end_offset is None or offset < end_offset)
    )


def join_cod_entries_with_synthetic_globals(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None = None,
    end_offset: int | None = None,
    symbol_base: int = 0x7000,
) -> tuple[bytes, dict[int, tuple[str, int]]]:
    """Patch COD bytes with synthetic addresses for optional global references."""

    def _impl() -> tuple[bytes, dict[int, tuple[str, int]]]:
        displacement_re = r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))?"
        global_re = re.compile(
            rf"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+(?P<symbol>[A-Za-z_$?@][\w$?@]*){displacement_re}",
            re.IGNORECASE,
        )
        offset_global_re = re.compile(
            rf"\bOFFSET\s+(?:[A-Za-z_$?@][\w$?@]*:)?\$?(?P<symbol>[A-Za-z_$?@][\w$?@]*){displacement_re}",
            re.IGNORECASE,
        )
        segment_registers = {"cs", "ds", "es", "ss", "fs", "gs"}
        instruction_prefixes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF2, 0xF3}
        immediate_addr_opcodes = {0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0x68}

        def parse_disp(value: str | None) -> int:
            if not value:
                return 0
            sign = -1 if value[0] == "-" else 1
            text = value[1:]
            if text.lower().startswith("0x"):
                parsed = int(text, 16)
            elif text.upper().endswith("H"):
                parsed = int(text[:-1], 16)
            else:
                parsed = int(text, 10)
            return sign * parsed

        def width_for(name: str) -> int:
            return {"BYTE": 1, "WORD": 2, "DWORD": 4}[name.upper()]

        def prefix_len_for_chunk(chunk: bytearray) -> int:
            prefix_len = 0
            while prefix_len < len(chunk) and chunk[prefix_len] in instruction_prefixes:
                prefix_len += 1
            return prefix_len

        def canonical_symbol_name(symbol: str) -> str:
            return canonical_known_cod_object_name(symbol) or symbol

        def should_ignore_symbol(symbol: str) -> bool:
            return symbol.lower() in segment_registers

        symbol_order: list[str] = []
        symbol_spans: dict[str, tuple[int, int, int]] = {}

        def remember_symbol(symbol: str, displacement: int, width: int) -> None:
            if should_ignore_symbol(symbol):
                return
            canonical_symbol = canonical_symbol_name(symbol)
            if canonical_symbol not in symbol_spans:
                symbol_order.append(canonical_symbol)
                symbol_spans[canonical_symbol] = (displacement, displacement + width, width)
                return
            start, end, max_width = symbol_spans[canonical_symbol]
            symbol_spans[canonical_symbol] = (
                min(start, displacement),
                max(end, displacement + width),
                max(max_width, width),
            )

        selected_entries: list[dict[str, object]] = []
        for entry in entries:
            offset = _cod_entry_offset_8616(entry)
            if offset is None:
                continue
            if start_offset is not None and offset < start_offset:
                continue
            if end_offset is not None and offset >= end_offset:
                continue
            selected_entries.append(entry)
            text = str(entry.get("text", ""))
            global_match = global_re.search(text)
            if global_match is not None:
                remember_symbol(
                    global_match.group("symbol"),
                    parse_disp(global_match.group("disp")),
                    width_for(global_match.group("width")),
                )
                continue
            offset_match = offset_global_re.search(text)
            if offset_match is not None:
                remember_symbol(offset_match.group("symbol"), parse_disp(offset_match.group("disp")), 2)

        symbol_addrs: dict[str, int] = {}
        addr_to_name: dict[int, tuple[str, int]] = {}
        next_addr = symbol_base
        for symbol in symbol_order:
            start, end, max_width = symbol_spans[symbol]
            align = min(max_width, 2)
            if next_addr % align:
                next_addr += align - (next_addr % align)
            bias = -start if start < 0 else 0
            base_addr = next_addr + bias
            symbol_addrs[symbol] = base_addr
            addr_to_name[base_addr] = (symbol, max(end - min(start, 0), max_width))
            next_addr += max(end - min(start, 0), max_width)

        patched_chunks: list[bytes] = []

        def patch_memory_global_reference(chunk: bytearray, target_addr: int) -> bool:
            prefix_len = prefix_len_for_chunk(chunk)
            if prefix_len >= len(chunk):
                return False
            opcode = chunk[prefix_len]
            if opcode in {0xA0, 0xA1, 0xA2, 0xA3} and prefix_len + 2 < len(chunk):
                chunk[prefix_len + 1 : prefix_len + 3] = target_addr.to_bytes(2, "little")
                return True
            if prefix_len + 3 < len(chunk):
                modrm = chunk[prefix_len + 1]
                if ((modrm >> 6) & 0x3) == 0 and (modrm & 0x7) == 0x6:
                    chunk[prefix_len + 2 : prefix_len + 4] = target_addr.to_bytes(2, "little")
                    return True
            return False

        def patch_offset_immediate_reference(chunk: bytearray, target_addr: int) -> bool:
            prefix_len = prefix_len_for_chunk(chunk)
            if prefix_len >= len(chunk):
                return False
            opcode = chunk[prefix_len]
            if opcode in immediate_addr_opcodes and prefix_len + 2 < len(chunk):
                chunk[prefix_len + 1 : prefix_len + 3] = target_addr.to_bytes(2, "little")
                return True
            if opcode in {0xC6, 0xC7} and prefix_len + 4 < len(chunk):
                chunk[prefix_len + 3 : prefix_len + 5] = target_addr.to_bytes(2, "little")
                return True
            return False

        for entry in selected_entries:
            entry_bytes = _cod_entry_bytes_8616(entry)
            if entry_bytes is None:
                continue
            chunk = bytearray(entry_bytes)
            text = str(entry.get("text", ""))
            patched = False

            global_match = global_re.search(text)
            offset_match = offset_global_re.search(text)
            if global_match is not None:
                symbol = global_match.group("symbol")
                if should_ignore_symbol(symbol):
                    patched_chunks.append(entry_bytes)
                    continue

                symbol = canonical_symbol_name(symbol)
                target_addr = symbol_addrs[symbol] + parse_disp(global_match.group("disp"))
                patched = patch_memory_global_reference(chunk, target_addr)

            elif offset_match is not None:
                symbol = canonical_symbol_name(offset_match.group("symbol"))
                if should_ignore_symbol(symbol):
                    patched_chunks.append(entry_bytes)
                    continue

                target_addr = symbol_addrs[symbol] + parse_disp(offset_match.group("disp"))
                patched = patch_offset_immediate_reference(chunk, target_addr)

            patched_chunks.append(bytes(chunk) if patched else entry_bytes)

        return b"".join(patched_chunks), addr_to_name

    return _impl()


def infer_cod_logic_start(entries: list[dict[str, object]]) -> int | None:
    """Return the first likely logic instruction in a small MSC procedure.

    Skip a leading ``__chkstk`` call when it appears in the entry prologue so
    the decompiler can focus on the actual function body.
    """
    call_re = re.compile(r"\bcall\b", re.IGNORECASE)
    chkstk_re = re.compile(r"\b(?:__)?(?:aN?|a)?chkstk\b", re.IGNORECASE)

    for idx, entry in enumerate(entries[:8]):
        text = str(entry.get("text", "")).lower()
        if "call" not in text or "chkstk" not in text:
            continue
        if not (call_re.search(text) and chkstk_re.search(text)):
            continue
        for later_entry in entries[idx + 1 :]:
            later_text = str(later_entry.get("text", "")).lower()
            if call_re.search(later_text):
                if "chkstk" not in later_text:
                    return None
        if idx + 1 < len(entries):
            return _cod_entry_offset_8616(entries[idx + 1])
    return None


def extract_simple_cod_logic_entries(entries: list[dict[str, object]]) -> list[dict[str, object]] | None:
    """Return simple COD procedure body rows with frame scaffolding removed."""

    def _impl() -> list[dict[str, object]] | None:
        """Normalize simple MSC-style framed procedures for decompilation.

        For straight-line helpers like ``_mset_pos`` the standard ``push bp`` /
        ``mov bp, sp`` prologue and matching ``pop bp`` epilogue can confuse stack
        argument recovery and introduce bogus saved-frame stores into the
        decompiled C. When the procedure is linear and has a conventional frame,
        strip only that scaffolding and keep the real body bytes.
        """
        if len(entries) < 4:
            return None

        first = str(entries[0].get("text", "")).strip().lower()
        second = str(entries[1].get("text", "")).strip().lower()
        if first != "push\tbp" or second != "mov\tbp,sp":
            return None

        control_flow_prefixes = ("j", "call", "loop", "int")
        body_entries: list[dict[str, object]] = []
        saw_ret = False

        for idx, entry in enumerate(entries[2:], start=2):
            text = str(entry.get("text", "")).strip().lower()
            mnemonic = text.split(None, 1)[0] if text else ""

            if mnemonic.startswith(control_flow_prefixes) and mnemonic != "ret":
                return None

            next_text = str(entries[idx + 1].get("text", "")).strip().lower() if idx + 1 < len(entries) else ""
            if text == "pop\tbp" and next_text == "ret":
                continue
            if text == "nop" and saw_ret:
                continue

            body_entries.append(entry)
            if mnemonic == "ret":
                saw_ret = True

        if not saw_ret:
            return None

        return body_entries

    return _impl()


def extract_simple_cod_logic_bytes(entries: list[dict[str, object]]) -> bytes | None:
    """Return simple COD procedure body bytes with frame scaffolding removed."""
    selected = extract_simple_cod_logic_entries(entries)
    if selected is None:
        return None
    return b"".join(data for entry in selected if (data := _cod_entry_bytes_8616(entry)) is not None)


def extract_small_two_arg_cod_logic_entries(entries: list[dict[str, object]]) -> list[dict[str, object]] | None:
    """Return tiny two-argument COD body rows with frame scaffolding removed."""

    def _impl() -> list[dict[str, object]] | None:
        """Normalize tiny ``bp``-framed two-argument helpers.

        This keeps the body bytes for small helpers that only reference
        ``[bp+4]`` / ``[bp+6]`` and do not allocate locals, which avoids bogus
        saved-frame stores in the recovered C while still keeping the real
        argument-relative accesses visible.
        """
        if len(entries) < 4:
            return None

        first = str(entries[0].get("text", "")).strip().lower()
        second = str(entries[1].get("text", "")).strip().lower()
        if first != "push\tbp" or second != "mov\tbp,sp":
            return None

        saw_ret = False
        arg_disps: set[int] = set()
        body_entries: list[dict[str, object]] = []
        for idx, entry in enumerate(entries[2:], start=2):
            text = str(entry.get("text", "")).strip().lower()
            mnemonic = text.split(None, 1)[0] if text else ""
            if "[bp-" in text or "sub\tsp," in text or "enter" in text:
                return None
            if mnemonic in {"call", "iret"}:
                return None

            for match in re.finditer(r"\[bp\+([0-9a-f]+)\]", text):
                arg_disps.add(int(match.group(1), 16))

            next_text = str(entries[idx + 1].get("text", "")).strip().lower() if idx + 1 < len(entries) else ""
            if text == "mov\tsp,bp":
                data = _cod_entry_bytes_8616(entry)
                if data is None:
                    return None
                replacement = dict(entry)
                replacement["bytes"] = b"\x90" * len(data)
                replacement["text"] = "nop"
                body_entries.append(replacement)
                continue
            if text == "pop\tbp" and next_text == "ret":
                data = _cod_entry_bytes_8616(entry)
                if data is None:
                    return None
                replacement = dict(entry)
                replacement["bytes"] = b"\x90" * len(data)
                replacement["text"] = "nop"
                body_entries.append(replacement)
                continue
            body_entries.append(entry)
            if text == "ret":
                saw_ret = True

        if not saw_ret or not body_entries:
            return None
        if arg_disps - {4, 6}:
            return None
        return body_entries

    return _impl()


def extract_small_two_arg_cod_logic_bytes(entries: list[dict[str, object]]) -> bytes | None:
    """Return tiny two-argument COD body bytes with frame scaffolding removed."""
    selected = extract_small_two_arg_cod_logic_entries(entries)
    if selected is None:
        return None
    return b"".join(data for entry in selected if (data := _cod_entry_bytes_8616(entry)) is not None)
