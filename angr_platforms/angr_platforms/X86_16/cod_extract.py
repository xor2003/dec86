from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path


@dataclass(frozen=True)
class CODProcMetadata:
    stack_aliases: dict[int, str]
    call_names: tuple[str, ...]
    global_names: tuple[str, ...]


def extract_cod_function_entries(cod_path: Path, proc_name: str, proc_kind: str = "NEAR") -> list[dict[str, object]]:
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


def extract_cod_proc_metadata(cod_path: Path, proc_name: str, proc_kind: str = "NEAR") -> CODProcMetadata:
    lines = cod_path.read_text(errors="ignore").splitlines()
    start_marker = f"{proc_name}\tPROC {proc_kind}"
    end_marker = f"{proc_name}\tENDP"

    collect = False
    stack_aliases: dict[int, str] = {}
    call_names: list[str] = []
    global_names: list[str] = []

    alias_re = re.compile(r"^\s*;\s*([A-Za-z_$?@][\w$?@]*)\s*=\s*(-?[0-9A-Fa-f]+)\s*$")
    entry_re = re.compile(r"\*\*\*\s+[0-9A-Fa-f]+\s+(?:[0-9A-Fa-f]{2}\s+)+(.*)$")
    call_re = re.compile(r"\bcall\b(?:\s+far ptr)?\s+([A-Za-z_$?@][\w$?@]*)", re.IGNORECASE)
    global_re = re.compile(r"\b(?:BYTE|WORD|DWORD)\s+PTR\s+([A-Za-z_$?@][\w$?@]*)", re.IGNORECASE)

    for line in lines:
        if start_marker in line:
            collect = True
            continue
        if collect and end_marker in line:
            break
        if not collect:
            continue

        alias_match = alias_re.match(line)
        if alias_match:
            stack_aliases[int(alias_match.group(2), 0)] = alias_match.group(1)
            continue

        entry_match = entry_re.search(line)
        if entry_match is None:
            continue
        asm_text = entry_match.group(1).strip()

        for call_match in call_re.finditer(asm_text):
            callee = call_match.group(1)
            if callee == "__chkstk":
                continue
            if not callee.startswith("$") and callee not in call_names:
                call_names.append(callee)

        for global_match in global_re.finditer(asm_text):
            global_name = global_match.group(1)
            if global_name.startswith("$") or global_name == proc_name:
                continue
            if global_name not in global_names:
                global_names.append(global_name)

    return CODProcMetadata(
        stack_aliases=stack_aliases,
        call_names=tuple(call_names),
        global_names=tuple(global_names),
    )


def join_cod_entries(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None = None,
    end_offset: int | None = None,
) -> bytes:
    return b"".join(
        entry["bytes"]
        for entry in entries
        if (start_offset is None or start_offset <= int(entry["offset"]))
        and (end_offset is None or int(entry["offset"]) < end_offset)
    )


def join_cod_entries_with_synthetic_globals(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None = None,
    end_offset: int | None = None,
    symbol_base: int = 0x7000,
) -> tuple[bytes, dict[int, str]]:
    global_re = re.compile(r"\b(?:BYTE|WORD|DWORD)\s+PTR\s+([A-Za-z_$?@][\w$?@]*)", re.IGNORECASE)
    size_re = re.compile(r"\b(BYTE|WORD|DWORD)\s+PTR\b", re.IGNORECASE)

    symbol_addrs: dict[str, int] = {}
    addr_to_name: dict[int, str] = {}
    next_addr = symbol_base
    patched_chunks: list[bytes] = []

    for entry in entries:
        offset = int(entry["offset"])
        if start_offset is not None and offset < start_offset:
            continue
        if end_offset is not None and offset >= end_offset:
            continue

        chunk = bytearray(entry["bytes"])
        text = str(entry.get("text", ""))
        patched = False

        global_match = global_re.search(text)
        size_match = size_re.search(text)
        if global_match is not None and size_match is not None:
            symbol = global_match.group(1)
            width_name = size_match.group(1).upper()
            width = {"BYTE": 1, "WORD": 2, "DWORD": 4}[width_name]

            if symbol not in symbol_addrs:
                align = min(width, 2)
                if next_addr % align:
                    next_addr += align - (next_addr % align)
                symbol_addrs[symbol] = next_addr
                addr_to_name[next_addr] = symbol
                next_addr += width

            target_addr = symbol_addrs[symbol]

            prefix_len = 0
            while prefix_len < len(chunk) and chunk[prefix_len] in {
                0x26,
                0x2E,
                0x36,
                0x3E,
                0x64,
                0x65,
                0x66,
                0x67,
                0xF2,
                0xF3,
            }:
                prefix_len += 1

            if prefix_len < len(chunk):
                opcode = chunk[prefix_len]

                if opcode in {0xA0, 0xA1, 0xA2, 0xA3} and prefix_len + 2 < len(chunk):
                    chunk[prefix_len + 1 : prefix_len + 3] = target_addr.to_bytes(2, "little")
                    patched = True
                elif prefix_len + 3 < len(chunk):
                    modrm = chunk[prefix_len + 1]
                    if ((modrm >> 6) & 0x3) == 0 and (modrm & 0x7) == 0x6:
                        chunk[prefix_len + 2 : prefix_len + 4] = target_addr.to_bytes(2, "little")
                        patched = True

        patched_chunks.append(bytes(chunk) if patched else entry["bytes"])

    return b"".join(patched_chunks), addr_to_name


def infer_cod_logic_start(entries: list[dict[str, object]]) -> int | None:
    """
    For small MSC-style procedures extracted from .COD, skip a leading
    ``__chkstk`` call when it appears in the entry prologue so the decompiler
    can focus on the actual function body.
    """

    for idx, entry in enumerate(entries[:8]):
        text = str(entry.get("text", "")).lower()
        if "call" not in text or "__chkstk" not in text:
            continue
        if idx + 1 < len(entries):
            return int(entries[idx + 1]["offset"])
    return None


def extract_simple_cod_logic_entries(entries: list[dict[str, object]]) -> list[dict[str, object]] | None:
    """
    Normalize simple MSC-style framed procedures for decompilation.

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


def extract_simple_cod_logic_bytes(entries: list[dict[str, object]]) -> bytes | None:
    selected = extract_simple_cod_logic_entries(entries)
    if selected is None:
        return None
    return b"".join(entry["bytes"] for entry in selected)


def extract_small_two_arg_cod_logic_entries(entries: list[dict[str, object]]) -> list[dict[str, object]] | None:
    """
    Normalize tiny ``bp``-framed two-argument helpers.

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
        if "[bp-" in text or "sub\tsp," in text or "enter" in text:
            return None
        if "call" in text:
            return None

        for match in re.finditer(r"\[bp\+([0-9a-f]+)\]", text):
            arg_disps.add(int(match.group(1), 16))

        next_text = str(entries[idx + 1].get("text", "")).strip().lower() if idx + 1 < len(entries) else ""
        if text == "mov\tsp,bp":
            continue
        if text == "pop\tbp" and next_text == "ret":
            continue
        if text == "nop":
            continue

        body_entries.append(entry)
        if text == "ret":
            saw_ret = True

    if not saw_ret or not body_entries:
        return None
    if arg_disps - {4, 6}:
        return None
    return body_entries


def extract_small_two_arg_cod_logic_bytes(entries: list[dict[str, object]]) -> bytes | None:
    selected = extract_small_two_arg_cod_logic_entries(entries)
    if selected is None:
        return None
    return b"".join(entry["bytes"] for entry in selected)
