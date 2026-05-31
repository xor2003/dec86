from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .cache import _load_cache_json, _recovery_cache_key, _store_cache_json

__all__ = [
    "RizinDiscoveryStatus",
    "RizinDiscoveryResult",
    "discover_rizin_function_entries",
    "discover_function_offsets_with_rizin",
]


class RizinDiscoveryStatus(Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"
    EMPTY = "empty"


@dataclass(frozen=True)
class RizinDiscoveryResult:
    status: RizinDiscoveryStatus
    offsets: tuple[int, ...]
    elapsed_ms: float
    detail: str = ""


def _rizin_available() -> bool:
    return shutil.which("rizin") is not None


def _score_aflj_entry(entry: dict[str, object]) -> tuple[int, int]:
    name = str(entry.get("name", "") or "")
    size = int(entry.get("size", 0) or 0)
    nbbs = int(entry.get("nbbs", 0) or 0)
    ncallrefs = int(entry.get("ncallrefs", 0) or 0)
    imported_penalty = 1000 if name.startswith("sym.imp.") else 0
    score = (ncallrefs * 10) + (nbbs * 4) + min(size, 512) - imported_penalty
    offset = int(entry.get("offset", 0) or 0)
    return score, -offset


def _cache_key(binary_path: Path, *, timeout_sec: int, max_count: int | None) -> dict[str, object] | None:
    return _recovery_cache_key(
        binary_path=binary_path,
        kind="rizin_aflj_function_seeds",
        extra={"timeout_sec": timeout_sec, "max_count": max_count or 0},
    )


def _run_rizin_json(binary_path: Path, command: str, *, timeout_sec: int) -> Any:
    cmd = ["rizin", "-2", "-q", "-c", command, str(binary_path)]
    completed = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=max(1, int(timeout_sec)),
    )
    if completed.returncode != 0:
        return None
    try:
        return json.loads(completed.stdout)
    except Exception:
        return None


def _mz_linear_candidates_from_prologues(binary_path: Path) -> tuple[list[int], str]:
    data = binary_path.read_bytes()
    segments = _run_rizin_json(binary_path, "iSj", timeout_sec=3)
    if not isinstance(segments, list):
        return [], "no_segment_map"
    chosen = None
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        paddr = int(seg.get("paddr", 0) or 0)
        vaddr = int(seg.get("vaddr", 0) or 0)
        # Prefer the DOS code segment mapping near header end.
        if paddr > 0 and vaddr >= 0:
            if chosen is None or paddr < int(chosen.get("paddr", 0) or 0):
                chosen = {"paddr": paddr, "vaddr": vaddr}
    if chosen is None:
        return [], "no_mappable_segment"
    pbase = int(chosen["paddr"])
    vbase = int(chosen["vaddr"])
    patterns = (b"\x55\x8b\xec", b"\x55\x89\xe5")
    candidates: list[int] = []
    for pat in patterns:
        start = 0
        while True:
            idx = data.find(pat, start)
            if idx < 0:
                break
            start = idx + 1
            if idx < pbase:
                continue
            vaddr = vbase + (idx - pbase)
            if vaddr < 0:
                continue
            # angr DOS MZ loader base is 0x10000 in this pipeline.
            candidates.append(0x10000 + vaddr)
    entry_raw = subprocess.run(
        ["rizin", "-2", "-q", "-c", "ieq", str(binary_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=2,
    )
    if entry_raw.returncode == 0:
        entry_text = entry_raw.stdout.strip()
        if entry_text.startswith("0x"):
            try:
                candidates.append(0x10000 + int(entry_text, 16))
            except Exception:
                pass
    dedup: set[int] = set()
    ordered: list[int] = []
    for addr in sorted(candidates):
        if addr in dedup:
            continue
        dedup.add(addr)
        ordered.append(addr)
    return ordered, "mz_prologue_fallback"


def discover_rizin_function_entries(binary_path: Path, *, timeout_sec: int = 8) -> RizinDiscoveryResult:
    started = time.perf_counter()
    if not _rizin_available():
        return RizinDiscoveryResult(RizinDiscoveryStatus.UNAVAILABLE, (), 0.0, "rizin not found")
    key = _cache_key(binary_path, timeout_sec=timeout_sec, max_count=None)
    if key is not None:
        cached = _load_cache_json("recovery", key)
        if isinstance(cached, dict):
            cached_status_raw = str(cached.get("status", "") or "").strip().lower()
            cached_detail = str(cached.get("detail", "") or "")
            offsets_raw = cached.get("offsets")
            if isinstance(offsets_raw, list):
                offsets = tuple(int(x) for x in offsets_raw)
            else:
                offsets = ()
            if cached_status_raw:
                for status in RizinDiscoveryStatus:
                    if status.value == cached_status_raw:
                        return RizinDiscoveryResult(
                            status,
                            offsets,
                            (time.perf_counter() - started) * 1000.0,
                            f"cache_hit:{cached_detail or cached_status_raw}",
                        )
    cmd = ["rizin", "-2", "-q", "-c", "aaa;aflj", str(binary_path)]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(1, int(timeout_sec)),
        )
    except subprocess.TimeoutExpired:
        timeout_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.TIMEOUT,
            (),
            (time.perf_counter() - started) * 1000.0,
            "subprocess timeout",
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": timeout_result.status.value, "offsets": [], "detail": timeout_result.detail})
        return timeout_result
    except Exception as ex:
        error_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            str(ex),
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": error_result.status.value, "offsets": [], "detail": error_result.detail})
        return error_result
    if completed.returncode != 0:
        error_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            f"exit={completed.returncode}",
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": error_result.status.value, "offsets": [], "detail": error_result.detail})
        return error_result
    try:
        payload = json.loads(completed.stdout)
    except Exception:
        error_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            "invalid JSON",
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": error_result.status.value, "offsets": [], "detail": error_result.detail})
        return error_result
    if not isinstance(payload, list):
        error_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            "aflj payload is not a list",
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": error_result.status.value, "offsets": [], "detail": error_result.detail})
        return error_result
    candidates: list[dict[str, object]] = [item for item in payload if isinstance(item, dict)]
    if not candidates:
        mz_fallback, fallback_detail = _mz_linear_candidates_from_prologues(binary_path)
        if mz_fallback:
            if key is not None:
                _store_cache_json(
                    "recovery",
                    key,
                    {
                        "status": RizinDiscoveryStatus.OK.value,
                        "offsets": mz_fallback,
                        "detail": fallback_detail,
                        "engine": "rizin",
                    },
                )
            return RizinDiscoveryResult(
                RizinDiscoveryStatus.OK,
                tuple(mz_fallback),
                (time.perf_counter() - started) * 1000.0,
                fallback_detail,
            )
        empty_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.EMPTY,
            (),
            (time.perf_counter() - started) * 1000.0,
            "no function entries",
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": empty_result.status.value, "offsets": [], "detail": empty_result.detail})
        return empty_result
    ordered = sorted(candidates, key=_score_aflj_entry, reverse=True)
    dedup: set[int] = set()
    offsets: list[int] = []
    for item in ordered:
        offset = int(item.get("offset", 0) or 0)
        if offset <= 0 or offset in dedup:
            continue
        dedup.add(offset)
        offsets.append(offset)
    if not offsets:
        empty_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.EMPTY,
            (),
            (time.perf_counter() - started) * 1000.0,
            "no valid offsets",
        )
        if key is not None:
            _store_cache_json("recovery", key, {"status": empty_result.status.value, "offsets": [], "detail": empty_result.detail})
        return empty_result
    if key is not None:
        _store_cache_json(
            "recovery",
            key,
            {"status": RizinDiscoveryStatus.OK.value, "offsets": offsets, "detail": "ok", "engine": "rizin"},
        )
    return RizinDiscoveryResult(
        RizinDiscoveryStatus.OK,
        tuple(offsets),
        (time.perf_counter() - started) * 1000.0,
        "ok",
    )


def discover_function_offsets_with_rizin(
    binary_path: Path,
    *,
    max_count: int | None = None,
) -> tuple[list[int], str]:
    result = discover_rizin_function_entries(binary_path, timeout_sec=8)
    if result.status is not RizinDiscoveryStatus.OK:
        return [], result.status.value
    offsets = list(result.offsets)
    if max_count:
        offsets = offsets[:max_count]
    return offsets, result.detail or "ok"
