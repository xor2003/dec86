from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

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


def discover_rizin_function_entries(binary_path: Path, *, timeout_sec: int = 8) -> RizinDiscoveryResult:
    started = time.perf_counter()
    if not _rizin_available():
        return RizinDiscoveryResult(RizinDiscoveryStatus.UNAVAILABLE, (), 0.0, "rizin not found")
    key = _cache_key(binary_path, timeout_sec=timeout_sec, max_count=None)
    if key is not None:
        cached = _load_cache_json("recovery", key)
        if isinstance(cached, dict) and isinstance(cached.get("offsets"), list):
            offsets = tuple(int(x) for x in cached["offsets"])
            return RizinDiscoveryResult(
                RizinDiscoveryStatus.OK,
                offsets,
                (time.perf_counter() - started) * 1000.0,
                "cache_hit",
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
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.TIMEOUT,
            (),
            (time.perf_counter() - started) * 1000.0,
            "subprocess timeout",
        )
    except Exception as ex:
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            str(ex),
        )
    if completed.returncode != 0:
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            f"exit={completed.returncode}",
        )
    try:
        payload = json.loads(completed.stdout)
    except Exception:
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            "invalid JSON",
        )
    if not isinstance(payload, list):
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.ERROR,
            (),
            (time.perf_counter() - started) * 1000.0,
            "aflj payload is not a list",
        )
    candidates: list[dict[str, object]] = [item for item in payload if isinstance(item, dict)]
    if not candidates:
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.EMPTY,
            (),
            (time.perf_counter() - started) * 1000.0,
            "no function entries",
        )
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
        return RizinDiscoveryResult(
            RizinDiscoveryStatus.EMPTY,
            (),
            (time.perf_counter() - started) * 1000.0,
            "no valid offsets",
        )
    if key is not None:
        _store_cache_json("recovery", key, {"offsets": offsets, "engine": "rizin"})
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
