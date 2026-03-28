from __future__ import annotations

import io
import logging
import re
import resource
import signal
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

import angr

from .arch_86_16 import Arch86_16
from .lift_86_16 import Lifter86_16  # noqa: F401


logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)


ENTRY_RE = re.compile(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$")
PROC_RE = re.compile(r"^([^\s]+)\tPROC (NEAR|FAR)$")


@dataclass
class StageResult:
    stage: str
    ok: bool
    reason: str | None = None
    detail: str | None = None


@dataclass
class FunctionScanResult:
    cod_file: str
    proc_name: str
    proc_kind: str
    byte_len: int
    has_near_call_reloc: bool
    has_far_call_reloc: bool
    ok: bool = False
    stage_reached: str = "init"
    failure_class: str | None = None
    reason: str | None = None
    fallback_kind: str | None = None
    function_count: int = 0
    decompiled_count: int = 0
    stages: list[StageResult] = field(default_factory=list)


class ScanTimeout(Exception):
    pass


def _alarm_handler(_signum, _frame):
    raise ScanTimeout("timed out")


def set_memory_limit(max_memory_mb: int) -> None:
    if max_memory_mb <= 0:
        return
    limit_bytes = max_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def extract_cod_functions(cod_path: Path) -> list[tuple[str, str, bytes]]:
    lines = cod_path.read_text(errors="ignore").splitlines()
    out: list[tuple[str, str, bytes]] = []
    collect = False
    proc_name = ""
    proc_kind = ""
    chunks: list[bytes] = []

    for line in lines:
        proc_match = PROC_RE.match(line)
        if proc_match:
            collect = True
            proc_name, proc_kind = proc_match.groups()
            chunks = []
            continue

        if collect and f"{proc_name}\tENDP" in line:
            out.append((proc_name, proc_kind, b"".join(chunks)))
            collect = False
            proc_name = ""
            proc_kind = ""
            chunks = []
            continue

        if not collect:
            continue

        entry_match = ENTRY_RE.search(line)
        if entry_match:
            chunks.append(bytes.fromhex("".join(entry_match.group(2).split())))

    return out


def project_from_bytes(code: bytes) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def classify_failure(stage: str, exc: Exception | None, *, empty_codegen: bool = False) -> tuple[str, str]:
    if empty_codegen:
        return "no_code_produced", "Decompiler did not produce code."
    if isinstance(exc, ScanTimeout):
        return "timeout", "timed out"
    if exc is None:
        return "unknown_failure", "unknown failure"

    message = str(exc)
    lowered = message.lower()

    if "recursion" in lowered or "maximum recursion depth" in lowered:
        return "recursion_or_explosion", message
    if "unsupported" in lowered or "unknown opcode" in lowered or "not implemented" in lowered:
        return "unknown_opcode_or_semantic", message
    if "render" in lowered or "codegen" in lowered:
        return "renderer_failure", message
    if "postprocess" in lowered or "simplify" in lowered:
        return "postprocess_failure", message
    if stage == "load":
        return "load_failure", message
    if stage == "lift":
        return "lift_failure", message
    if stage == "cfg":
        return "cfg_failure", message
    if stage == "decompile":
        return "decompiler_crash", message
    return "unknown_failure", message


def _mark_stage(result: FunctionScanResult, stage: str, ok: bool, *, reason: str | None = None, detail: str | None = None) -> None:
    result.stages.append(StageResult(stage=stage, ok=ok, reason=reason, detail=detail))
    result.stage_reached = stage


def _scan_cfg(project: angr.Project, code_len: int):
    return project.analyses.CFGFast(
        normalize=True,
        force_complete_scan=False,
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1000 + max(code_len, 1))],
    )


def scan_function(
    cod_file: Path,
    proc_name: str,
    proc_kind: str,
    code: bytes,
    timeout_sec: int,
    mode: str,
) -> FunctionScanResult:
    result = FunctionScanResult(
        cod_file=cod_file.name,
        proc_name=proc_name,
        proc_kind=proc_kind,
        byte_len=len(code),
        has_near_call_reloc=b"\xe8\x00\x00" in code,
        has_far_call_reloc=b"\x9a\x00\x00\x00\x00" in code,
    )

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(timeout_sec)
    try:
        try:
            project = project_from_bytes(code)
            _mark_stage(result, "load", True)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("load", exc)
            result.failure_class = failure_class
            result.reason = reason
            _mark_stage(result, "load", False, reason=failure_class, detail=reason)
            return result

        _mark_stage(result, "normalize", True, detail="bounded blob pipeline")

        try:
            project.factory.block(0x1000, len(code)).vex
            _mark_stage(result, "lift", True)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("lift", exc)
            result.failure_class = failure_class
            result.reason = reason
            _mark_stage(result, "lift", False, reason=failure_class, detail=reason)
            return result

        result.function_count = 1
        if mode == "lift":
            result.ok = True
            return result

        if mode == "decompile-reloc-free" and (result.has_near_call_reloc or result.has_far_call_reloc):
            result.failure_class = "skipped_relocation"
            result.reason = "contains unresolved call relocation pattern"
            result.fallback_kind = "block_lift"
            _mark_stage(result, "cfg", False, reason="skipped_relocation", detail=result.reason)
            return result

        try:
            cfg = _scan_cfg(project, len(code))
            func = cfg.functions[0x1000]
            _mark_stage(result, "cfg", True)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("cfg", exc)
            result.failure_class = failure_class
            result.reason = reason
            result.fallback_kind = "block_lift"
            _mark_stage(result, "cfg", False, reason=failure_class, detail=reason)
            return result

        _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")

        try:
            dec = project.analyses.Decompiler(func, cfg=cfg)
            codegen = getattr(dec, "codegen", None)
            if codegen is None or not getattr(codegen, "text", ""):
                failure_class, reason = classify_failure("decompile", None, empty_codegen=True)
                result.failure_class = failure_class
                result.reason = reason
                result.fallback_kind = "block_lift"
                _mark_stage(result, "decompile", False, reason=failure_class, detail=reason)
                return result
            result.decompiled_count = 1
            result.ok = True
            _mark_stage(result, "decompile", True)
            return result
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("decompile", exc)
            result.failure_class = failure_class
            result.reason = reason
            result.fallback_kind = "block_lift"
            _mark_stage(result, "decompile", False, reason=failure_class, detail=reason)
            return result
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def summarize_results(results: list[FunctionScanResult], mode: str) -> dict[str, object]:
    failure_counter = Counter(result.failure_class for result in results if result.failure_class is not None)
    per_file: dict[str, dict[str, int]] = defaultdict(lambda: {"scanned": 0, "ok": 0})

    for result in results:
        per_file[result.cod_file]["scanned"] += 1
        if result.ok:
            per_file[result.cod_file]["ok"] += 1

    files_zero_success = sorted(name for name, stats in per_file.items() if stats["ok"] == 0)
    files_scan_clean = sorted(name for name, stats in per_file.items() if stats["ok"] == stats["scanned"])
    files_partial_success = sorted(
        name for name, stats in per_file.items() if 0 < stats["ok"] < stats["scanned"]
    )

    return {
        "mode": mode,
        "scanned": len(results),
        "ok": sum(1 for result in results if result.ok),
        "failed": sum(1 for result in results if not result.ok),
        "failure_counts": dict(sorted(failure_counter.items())),
        "files_zero_success": files_zero_success,
        "files_partial_success": files_partial_success,
        "files_scan_clean": files_scan_clean,
        "results": [asdict(result) for result in results],
    }


__all__ = [
    "FunctionScanResult",
    "ScanTimeout",
    "StageResult",
    "classify_failure",
    "extract_cod_functions",
    "scan_function",
    "set_memory_limit",
    "summarize_results",
]
