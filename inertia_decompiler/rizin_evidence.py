"""Collect optional rizin evidence for diagnostics and candidate ranking.

Layer: CLI/fallback/reporting.
Responsibility: collect optional rizin diagnostics without making them semantic proof.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class RizinEvidenceStatus(Enum):
    """Status of one optional rizin evidence collection attempt."""

    OK = "ok"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class RizinFunctionFact:
    """Function-level fact reported by rizin for diagnostics."""

    addr: int
    size: int
    name: str
    n_blocks: int
    n_callrefs: int


@dataclass(frozen=True)
class RizinXrefFact:
    """Cross-reference fact reported by rizin for diagnostics."""

    src: int
    dst: int
    kind: str


@dataclass(frozen=True)
class RizinStringFact:
    """String fact reported by rizin for diagnostics."""

    vaddr: int
    value: str


@dataclass(frozen=True)
class RizinSymbolFact:
    """Symbol fact reported by rizin for diagnostics."""

    vaddr: int
    name: str
    kind: str


@dataclass(frozen=True)
class RizinStackVarFact:
    """Stack-variable fact reported by rizin for diagnostics."""

    function_addr: int
    name: str
    kind: str
    offset: int | None


@dataclass(frozen=True)
class RizinCcFact:
    """Calling-convention fact reported by rizin for diagnostics."""

    function_addr: int
    cc: str
    nargs: int | None


@dataclass(frozen=True)
class RizinEvidence:
    """Collected optional rizin evidence for one binary."""

    status: RizinEvidenceStatus
    elapsed_ms: float
    detail: str
    functions: tuple[RizinFunctionFact, ...]
    xrefs: tuple[RizinXrefFact, ...]
    strings: tuple[RizinStringFact, ...]
    symbols: tuple[RizinSymbolFact, ...]
    stack_vars: tuple[RizinStackVarFact, ...]
    calling_conventions: tuple[RizinCcFact, ...]

    @property
    def function_offsets(self) -> tuple[int, ...]:
        """Return discovered function offsets from optional rizin evidence."""
        return tuple(f.addr for f in self.functions)

    @property
    def function_name_by_addr(self) -> dict[int, str]:
        """Return rizin function names keyed by address."""
        out: dict[int, str] = {}
        for fact in self.functions:
            if fact.name:
                out[fact.addr] = fact.name
        return out


def _rizin_available() -> bool:
    return shutil.which("rizin") is not None


def _run_json(binary_path: Path, command: str, *, timeout_sec: int) -> object:
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


def collect_rizin_evidence(binary_path: Path, *, timeout_sec: int = 8) -> RizinEvidence:
    """Collect optional rizin facts for diagnostics and candidate ranking."""
    started = time.perf_counter()
    if not _rizin_available():
        return RizinEvidence(
            status=RizinEvidenceStatus.UNAVAILABLE,
            elapsed_ms=0.0,
            detail="rizin not found",
            functions=(),
            xrefs=(),
            strings=(),
            symbols=(),
            stack_vars=(),
            calling_conventions=(),
        )
    try:
        fn_payload = _run_json(binary_path, "aaa;aflj", timeout_sec=timeout_sec)
        xref_payload = _run_json(binary_path, "axtj", timeout_sec=timeout_sec)
        str_payload = _run_json(binary_path, "izj", timeout_sec=timeout_sec)
        sym_payload = _run_json(binary_path, "isj", timeout_sec=timeout_sec)
        # `afvrj` and `afcfj` are function-scoped in rizin. If unavailable, keep empty.
        stack_payload = _run_json(binary_path, "afvrj", timeout_sec=timeout_sec)
        cc_payload = _run_json(binary_path, "afcfj", timeout_sec=timeout_sec)
    except subprocess.TimeoutExpired:
        return RizinEvidence(
            status=RizinEvidenceStatus.TIMEOUT,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            detail="subprocess timeout",
            functions=(),
            xrefs=(),
            strings=(),
            symbols=(),
            stack_vars=(),
            calling_conventions=(),
        )
    except Exception as ex:
        return RizinEvidence(
            status=RizinEvidenceStatus.ERROR,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            detail=str(ex),
            functions=(),
            xrefs=(),
            strings=(),
            symbols=(),
            stack_vars=(),
            calling_conventions=(),
        )

    fn_facts: list[RizinFunctionFact] = []
    if isinstance(fn_payload, list):
        for item in fn_payload:
            if not isinstance(item, dict):
                continue
            try:
                addr = int(item.get("offset", 0) or 0)
            except Exception:
                continue
            if addr <= 0:
                continue
            fn_facts.append(
                RizinFunctionFact(
                    addr=addr,
                    size=int(item.get("size", 0) or 0),
                    name=str(item.get("name", "") or ""),
                    n_blocks=int(item.get("nbbs", 0) or 0),
                    n_callrefs=int(item.get("ncallrefs", 0) or 0),
                )
            )

    xref_facts: list[RizinXrefFact] = []
    if isinstance(xref_payload, list):
        for item in xref_payload:
            if not isinstance(item, dict):
                continue
            src = int(item.get("from", 0) or 0)
            dst = int(item.get("to", 0) or 0)
            if src > 0 and dst > 0:
                xref_facts.append(RizinXrefFact(src=src, dst=dst, kind=str(item.get("type", "") or "")))

    str_facts: list[RizinStringFact] = []
    if isinstance(str_payload, list):
        for item in str_payload:
            if not isinstance(item, dict):
                continue
            vaddr = int(item.get("vaddr", 0) or 0)
            value = str(item.get("string", "") or "")
            if vaddr > 0 and value:
                str_facts.append(RizinStringFact(vaddr=vaddr, value=value))

    sym_facts: list[RizinSymbolFact] = []
    if isinstance(sym_payload, list):
        for item in sym_payload:
            if not isinstance(item, dict):
                continue
            vaddr = int(item.get("vaddr", 0) or 0)
            name = str(item.get("name", "") or "")
            if vaddr > 0 and name:
                sym_facts.append(RizinSymbolFact(vaddr=vaddr, name=name, kind=str(item.get("type", "") or "")))

    stack_facts: list[RizinStackVarFact] = []
    if isinstance(stack_payload, list):
        for item in stack_payload:
            if not isinstance(item, dict):
                continue
            fn = int(item.get("fcn_addr", 0) or 0)
            name = str(item.get("name", "") or "")
            if fn <= 0 or not name:
                continue
            raw_delta = item.get("delta", None)
            offset: int | None
            try:
                offset = int(raw_delta) if raw_delta is not None else None
            except Exception:
                offset = None
            stack_facts.append(
                RizinStackVarFact(
                    function_addr=fn,
                    name=name,
                    kind=str(item.get("kind", "") or ""),
                    offset=offset,
                )
            )

    cc_facts: list[RizinCcFact] = []
    if isinstance(cc_payload, list):
        for item in cc_payload:
            if not isinstance(item, dict):
                continue
            fn = int(item.get("addr", 0) or 0)
            if fn <= 0:
                continue
            raw_nargs = item.get("nargs", None)
            nargs: int | None
            try:
                nargs = int(raw_nargs) if raw_nargs is not None else None
            except Exception:
                nargs = None
            cc_facts.append(
                RizinCcFact(
                    function_addr=fn,
                    cc=str(item.get("cc", "") or ""),
                    nargs=nargs,
                )
            )

    return RizinEvidence(
        status=RizinEvidenceStatus.OK,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        detail="ok",
        functions=tuple(fn_facts),
        xrefs=tuple(xref_facts),
        strings=tuple(str_facts),
        symbols=tuple(sym_facts),
        stack_vars=tuple(stack_facts),
        calling_conventions=tuple(cc_facts),
    )
