from __future__ import annotations

import re
from pathlib import Path


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


def extract_simple_cod_logic_bytes(entries: list[dict[str, object]]) -> bytes | None:
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

    return b"".join(entry["bytes"] for entry in body_entries)
