#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.project_loading import _build_project  # noqa: E402
from inertia_decompiler.sidecar_metadata import _load_lst_metadata  # noqa: E402

DEFAULT_EXAMPLES_DIR = REPO_ROOT / "examples" / "msc6_constructs"
DEFAULT_OUT_DIR = REPO_ROOT / "examples" / "build_msc6"
DEFAULT_KVIKDOS = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_DECOMPILE = REPO_ROOT / "decompile.py"
DEFAULT_DECOMPILE_SKIP = ("enum_union", "medium_structs")
HARNESS_SUCCESS_EXIT_CODE = 255
DECOMPILE_MAIN_NAMES = ("main", "MAIN", "_main", "_MAIN", "start", "_start")
DECOMPILE_MAIN_TIMEOUT_SECONDS_DEFAULT = 60
DECOMPILE_MAIN_RUN_TIMEOUT_SECONDS_DEFAULT = 60
DECOMPILE_SLOW_FUNCTION_SECONDS = 1.0
DECOMPILE_SLOW_PASS_SECONDS = 1.0


@dataclass(frozen=True)
class ExampleResult:
    name: str
    source: str
    exe: str
    obj: str
    map: str
    cod: str
    build_ok: bool
    run_ok: bool
    run_exit_code: int | None
    run_stdout: str
    run_stderr: str
    decompile_skipped: bool
    decompile_ok: bool
    decompile_recompiled: bool
    decompile_recompile_ok: bool
    decompile_run_ok: bool
    decompile_run_exit_code: int | None
    decompile_recompiled_exe: str
    decompile_recompiled_obj: str
    decompile_recompiled_map: str
    decompile_compile_stdout: str
    decompile_compile_stderr: str
    decompile_link_stdout: str
    decompile_link_stderr: str
    decompile_run_stdout: str
    decompile_run_stderr: str
    compile_stdout: str
    compile_stderr: str
    link_stdout: str
    link_stderr: str
    decompile_stdout_path: str | None
    decompile_stderr_path: str | None
    decompile_wall_seconds: float
    decompile_selected_functions: int
    decompile_profile: str


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    runtime_env = os.environ.copy()
    if env is not None:
        runtime_env.update(env)
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
        env=runtime_env,
    )


def _dos_safe_names(stem: str, counter: int | None = None) -> tuple[str, str, str, str]:
    """
    Return short DOS-friendly base names for C source, OBJ, EXE and MAP outputs.
    """
    normalized = "".join(ch for ch in stem.upper() if ch.isalnum())
    if not normalized:
        normalized = "DECOMPILE"

    # Keep short names within 8.3 constraints and avoid collisions by suffixing an index.
    short_core = normalized[:6]
    if counter is not None and counter > 0:
        short_core = f"{short_core[:5]}{counter % 10}"
    if not short_core:
        short_core = "DECOM1"[:6]

    return (
        f"{short_core}.C",
        f"{short_core}.OBJ",
        f"{short_core}.EXE",
        f"{short_core}.MAP",
    )


def _ensure_msvc6_compat_headers(out_dir: Path) -> None:
    """
    MS C 6 in this test harness may miss stdbool/stdint, so emit minimal shims.
    """
    stdbool = """#ifndef _STDBOOL_H\n#define _STDBOOL_H\n\n#define bool unsigned char\n#define true 1\n#define false 0\n\n#endif\n"""
    stdint = """#ifndef _STDINT_H\n#define _STDINT_H\n\ntypedef unsigned char uint8_t;\ntypedef signed char int8_t;\ntypedef unsigned short uint16_t;\ntypedef signed short int16_t;\ntypedef unsigned long uint32_t;\ntypedef signed long int32_t;\ntypedef unsigned int uintptr_t;\n\ntypedef unsigned long size_t;\n\ntypedef uint8_t u8;\ntypedef uint16_t u16;\ntypedef uint32_t u32;\n\ntypedef int32_t ptrdiff_t;\n\ntypedef int16_t int_fast16_t;\ntypedef uint16_t uint_fast16_t;\n\ntypedef int32_t int_least32_t;\ntypedef uint32_t uint_least32_t;\n\ntypedef int16_t int_least16_t;\ntypedef uint16_t uint_least16_t;\n\n#endif\n"""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "STDBOOL.H").write_text(stdbool, encoding="utf-8")
    (out_dir / "STDINT.H").write_text(stdint, encoding="utf-8")


def _sanitize_decompiled_source(raw_c_text: str) -> str:
    keep_lines: list[str] = []
    for line in raw_c_text.splitlines():
        stripped = line.lstrip()
        if (
            stripped.startswith("[dbg]")
            or stripped.startswith("[metric]")
            or stripped.startswith("[warn]")
            or stripped.startswith("[err]")
        ):
            continue
        keep_lines.append(line)
    return "\n".join(keep_lines) + ("\n" if raw_c_text.endswith("\n") else "")


def _lookup_sidecar_code_labels(binary_path: Path) -> dict[str, int]:
    project = _build_project(
        binary_path,
        force_blob=False,
        base_addr=0x10000,
        entry_point=None,
    )
    metadata = _load_lst_metadata(binary_path, project, pat_backend=None, signature_catalog=None)
    labels: dict[str, int] = {}
    if metadata is None:
        return labels
    for addr, name in getattr(metadata, "code_labels", {}).items():
        if not isinstance(name, str):
            continue
        normalized = name.lower()
        labels[normalized] = int(addr)
        labels[normalized.lstrip("_")] = int(addr)
    return labels


def _compile_and_link(
    source_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    msc6_root: Path,
    obj_name: str,
    exe_name: str,
    map_name: str,
    cod_name: str | None = None,
) -> tuple[bool, str, str, str, str]:
    _ensure_msvc6_compat_headers(out_dir)
    compile_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--path-dos=e:\\BIN",
        "--env=INCLUDE=E:\\INCLUDE",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\CL.EXE",
        "e:\\BIN\\CL.EXE",
        "/Ic:\\",
        "/nologo",
        "/Od",
        "/c",
        f"/Foc:\\{obj_name}",
    ]
    if cod_name is not None:
        compile_cmd += [f"/Fcc:\\{cod_name}"]

    compile_cmd.append(f"c:\\{source_path.name}")
    compile_proc = _run(compile_cmd, timeout=120)

    link_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\LINK.EXE",
        "e:\\BIN\\LINK.EXE",
        f"c:\\{obj_name},c:\\{exe_name},c:\\{map_name},E:\\LIB\\SLIBCE.LIB;",
    ]
    link_proc = _run(link_cmd, timeout=120)

    map_path = out_dir / map_name
    map_text = ""
    if map_path.exists():
        try:
            map_text = map_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            map_text = ""
    link_diagnostics = "\n".join((link_proc.stdout, link_proc.stderr, map_text))
    link_failed = "error L" in link_diagnostics or "unresolved external" in link_diagnostics.lower()
    built = (out_dir / exe_name).exists() and not link_failed
    return built, compile_proc.stdout, compile_proc.stderr, link_proc.stdout, link_proc.stderr


def _run_example(
    exe_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    timeout: int = 30,
) -> tuple[bool, int | None, str, str]:
    cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--prog=" + f"c:\\{exe_path.name}",
        f"c:\\{exe_path.name}",
    ]
    proc = _run(cmd, timeout=timeout)
    return proc.returncode == 0, proc.returncode, proc.stdout, proc.stderr


def _pick_main_proc_candidates_from_cod(
    cod_path: Path | None,
) -> list[tuple[str, str | None, int | None]]:
    if cod_path is None or not cod_path.is_file():
        return []
    proc_re = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+PROC\s+(NEAR|FAR)\b",
        re.IGNORECASE,
    )
    proc_addr_re = re.compile(r"^\s*\*\*\*\s+([0-9A-Fa-f]+)\s+")
    public_re = re.compile(r"^\s*PUBLIC\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)
    proc_kinds: dict[str, set[str]] = {}
    proc_addrs: dict[str, int] = {}
    public_names: set[str] = set()
    current_proc: str | None = None
    try:
        for line in cod_path.read_text(encoding="utf-8", errors="replace").splitlines():
            proc_match = proc_re.match(line)
            if proc_match is not None:
                name = proc_match.group(1)
                kind = proc_match.group(2).upper()
                proc_kinds.setdefault(name, set()).add(kind)
                current_proc = name
                continue
            if current_proc is not None and current_proc not in proc_addrs:
                addr_match = proc_addr_re.match(line)
                if addr_match is not None:
                    proc_addrs[current_proc] = int(addr_match.group(1), 16)
                    current_proc = None
            public_match = public_re.match(line)
            if public_match is not None:
                public_names.add(public_match.group(1))
    except Exception:
        return []
    for candidate in DECOMPILE_MAIN_NAMES:
        if candidate in proc_kinds and (not public_names or candidate in public_names):
            kinds = sorted(proc_kinds[candidate])
            return [(candidate, kinds[0], proc_addrs.get(candidate))] + [
                (candidate, kind, proc_addrs.get(candidate)) for kind in kinds[1:]
            ]
    if proc_kinds:
        name, kinds = next(iter(sorted(proc_kinds.items())))
        first = next(iter(sorted(kinds)))
        return [(name, first, proc_addrs.get(name))]
    return []


def _resolve_main_candidates_from_metadata(
    exe_path: Path,
    cod_path: Path | None,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    sidecar_labels = _lookup_sidecar_code_labels(exe_path)
    for candidate in DECOMPILE_MAIN_NAMES:
        candidate_lower = candidate.lower()
        mapped_addr = sidecar_labels.get(candidate_lower)
        if mapped_addr is None:
            continue
        key = ("sidecar", int(mapped_addr))
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "addr",
                "source": "sidecar_labels",
                "name": candidate_lower,
                "value": int(mapped_addr),
            }
        )

    if cod_path is not None and cod_path.is_file():
        proc_candidates = _pick_main_proc_candidates_from_cod(cod_path)
        map_path = exe_path.with_suffix(".MAP")
        if not map_path.exists():
            alt_map_path = exe_path.with_suffix(".map")
            if alt_map_path.exists():
                map_path = alt_map_path
            else:
                map_path = None

        for candidate_name, candidate_kind, candidate_addr in proc_candidates:
            if candidate_name is None:
                continue
            mapped_addr = None
            if candidate_addr is not None:
                mapped_addr = _resolve_cod_offset_to_exe_addr(
                    candidate_addr,
                    map_path,
                    proc_name=candidate_name,
                )
            if mapped_addr is None:
                continue
            key = ("cod", int(mapped_addr))
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "kind": "proc",
                    "source": "cod",
                    "name": candidate_name,
                    "proc_kind": candidate_kind,
                    "value": int(mapped_addr),
                    "cod_offset": int(candidate_addr),
                }
            )

    return candidates


def _read_map_obj_base_offset(map_path: Path) -> tuple[int | None, dict[int, int], dict[str, int]]:
    entry_off = None
    code_starts: dict[int, int] = {}
    if not map_path.exists():
        return None, code_starts, {}

    prog_re = re.compile(r"Program entry point at ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{1,4})", re.IGNORECASE)
    seg_re = re.compile(
        r"^\s*([0-9A-Fa-f]+)H\s+[0-9A-Fa-f]+H\s+[0-9A-Fa-f]+H\s+([A-Za-z_][\w$?@]*)\s+([A-Za-z]+)\s*$",
        re.IGNORECASE,
    )
    publics_re = re.compile(r"^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+([A-Za-z_$?@][\w$?@]*)\s*$", re.IGNORECASE)
    public_name_to_addr: dict[str, int] = {}

    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if entry_off is None:
            m_entry = prog_re.search(stripped)
            if m_entry is not None:
                entry_seg = int(m_entry.group(1), 16)
                entry_off = (entry_seg << 4) + int(m_entry.group(2), 16)
                continue
        match = seg_re.match(stripped)
        if match is not None:
            cls = match.group(3).upper()
            if cls == "CODE":
                code_start = int(match.group(1), 16)
                code_starts[code_start] = code_start
            continue
        public_match = publics_re.match(stripped)
        if public_match is not None:
            public_seg = int(public_match.group(1), 16)
            public_off = int(public_match.group(2), 16)
            symbol = public_match.group(3)
            public_name_to_addr[symbol.lower()] = (public_seg << 4) + public_off
            public_name_to_addr.setdefault(symbol.lstrip("_").lower(), (public_seg << 4) + public_off)

    return entry_off, code_starts, public_name_to_addr

def _resolve_cod_offset_to_exe_addr(
    cod_offset: int,
    map_path: Path | None,
    proc_name: str | None = None,
) -> int | None:
    if cod_offset < 0:
        return None

    if map_path is not None and map_path.exists():
        entry_off, code_starts, public_addrs = _read_map_obj_base_offset(map_path)
        if proc_name is not None:
            cod_symbol = proc_name.lower()
            for candidate in (cod_symbol, cod_symbol.lstrip("_")):
                if candidate in {"", "_"}:
                    continue
                if candidate in public_addrs:
                    return 0x10000 + public_addrs[candidate]
            # symbol not found; continue to offset heuristic fallback.

        if code_starts:
            code_base = min(code_starts.keys())
            # Heuristic for MS DOS real-mode objects: default load base is 0x10000.
            # Use code segment start when map addresses are in non-zero offset space.
            if entry_off is None:
                return 0x10000 + code_base + cod_offset
            # Keep compatibility with common map formats where segment offsets are
            # still relative to image origin, while runtime is linked at 0x10000.
            return 0x10000 + code_base + cod_offset

    # Last-resort fallback: legacy object/procedure offsets are often 0-based
    # relative to linked image + image base.
    return 0x10000 + cod_offset


def _is_proc_selection_failure(stderr_text: str) -> bool:
    return "did not find" in stderr_text and "PROC" in stderr_text


def _parse_decompile_profile(stderr_text: str) -> dict[str, object]:
    profile: dict[str, object] = {
        "functions_queued": None,
        "functions_selected": None,
        "function_times": [],
        "stage_times": [],
        "slow_passes": [],
        "decompiled_count": None,
        "attempted_count": None,
        "attempted_total": None,
        "timed_out_functions": 0,
        "tail_failures": 0,
        "timeout": False,
        "wall_seconds": 0.0,
        "asm_fallback": False,
        "tail_validation_status": None,
        "tail_validation_uncollected": False,
        "tail_validation_changed": False,
        "validation_state": [],
    }
    queued_re = re.compile(r"functions queued for decompilation:\s*(\d+)")
    selected_re = re.compile(r"selected\s+(\d+)\s+function\(s\)\s+for display")
    time_re = re.compile(r"decompilation time for\s+(0x[0-9a-fA-F]+)\s+([^:]+):\s*([0-9]+(?:\.[0-9]+)?)s")
    pass_re = re.compile(r"(?:structuring|postprocess) pass: ([^\\s]+) \\(\\+([0-9]+(?:\\.[0-9]+)?)s\\)")
    stage_time_re = re.compile(r"stage-time: ([^\\s]+) elapsed=([0-9]+(?:\\.[0-9]+)?)s")
    decomp_summary_re = re.compile(r"summary: decompiled (\\d+)/(\\d+) shown functions")
    attempted_summary_re = re.compile(r"summary: decompilation attempted for (\\d+)/(\\d+) displayed function\\(s\\)")
    timed_out_summary_re = re.compile(r"summary: (\\d+) discovered function\\(s\\) timed out during decompilation")
    tail_validation_re = re.compile(r"\[tail-validation\] whole-tail validation (passed|failed|uncollected)", re.IGNORECASE)
    validation_state_re = re.compile(r"validation=([a-z_]+)")
    asm_fallback_re = re.compile(r"== asm fallback ==")
    severity_changed_re = re.compile(r"\[tail-validation\] severity=changed")
    severity_uncollected_re = re.compile(r"\[tail-validation\] severity=uncollected")
    for line in stderr_text.splitlines():
        queue_match = queued_re.search(line)
        if queue_match is not None:
            profile["functions_queued"] = int(queue_match.group(1))
            continue
        selected_match = selected_re.search(line)
        if selected_match is not None:
            profile["functions_selected"] = int(selected_match.group(1))
            continue
        time_match = time_re.search(line)
        if time_match is not None:
            profile["function_times"].append(
                {
                    "addr": time_match.group(1),
                    "name": time_match.group(2).strip(),
                    "seconds": float(time_match.group(3)),
                }
            )
            continue
        pass_match = pass_re.search(line)
        if pass_match is not None:
            seconds = float(pass_match.group(2))
            profile["stage_times"].append(
                {
                    "scope": "post_or_struct",
                    "name": pass_match.group(1),
                    "seconds": seconds,
                }
            )
            if seconds > DECOMPILE_SLOW_PASS_SECONDS:
                profile.setdefault("slow_passes", []).append(
                    {"scope": "post_or_struct", "name": pass_match.group(1), "seconds": seconds}
                )
            continue
        stage_match = stage_time_re.search(line)
        if stage_match is not None:
            seconds = float(stage_match.group(2))
            profile["stage_times"].append(
                {
                    "scope": "stage_time",
                    "name": stage_match.group(1),
                    "seconds": seconds,
                }
            )
            if seconds > DECOMPILE_SLOW_PASS_SECONDS:
                profile.setdefault("slow_passes", []).append(
                    {"scope": "stage_time", "name": stage_match.group(1), "seconds": seconds}
                )
            continue
        decomp_match = decomp_summary_re.search(line)
        if decomp_match is not None:
            profile["decompiled_count"] = {
                "success": int(decomp_match.group(1)),
                "shown": int(decomp_match.group(2)),
            }
            continue
        attempted_match = attempted_summary_re.search(line)
        if attempted_match is not None:
            profile["attempted_count"] = int(attempted_match.group(1))
            profile["attempted_total"] = int(attempted_match.group(2))
            continue
        timed_out_match = timed_out_summary_re.search(line)
        if timed_out_match is not None:
            profile["timed_out_functions"] = int(timed_out_match.group(1))
            continue
        tail_match = tail_validation_re.search(line)
        if tail_match is not None:
            status = tail_match.group(1).lower()
            profile["tail_validation_status"] = status
            if status == "uncollected":
                profile["tail_validation_uncollected"] = True
            if status == "failed":
                profile["tail_validation_changed"] = True
            continue
        if severity_changed_re.search(line) is not None:
            profile["tail_validation_changed"] = True
        if severity_uncollected_re.search(line) is not None:
            profile["tail_validation_uncollected"] = True
        if asm_fallback_re.search(line) is not None:
            profile["asm_fallback"] = True
        if "failure family:" in line:
            profile["tail_failures"] += 1
            validation_match = validation_state_re.search(line)
            if validation_match is not None and isinstance(profile.get("validation_state"), list):
                validation_state = validation_match.group(1).lower()
                states = profile["validation_state"]
                assert isinstance(states, list)
                if validation_state not in states:
                    states.append(validation_state)
    return profile


def _is_decompile_output_acceptable(
    stdout_text: str,
    stderr_text: str,
    profile: dict[str, object],
) -> tuple[bool, str | None]:
    if profile.get("timeout"):
        return False, "timeout"

    tail_status = profile.get("tail_validation_status")
    if tail_status in {"failed", "uncollected"}:
        return False, f"tail_validation_{tail_status}"
    if profile.get("tail_validation_changed"):
        return False, "tail_validation_changed"
    if profile.get("asm_fallback"):
        return False, "asm_fallback"

    validation_state = profile.get("validation_state")
    if isinstance(validation_state, list):
        if "failed" in validation_state:
            return False, "validation_failed"
        if "changed" in validation_state:
            return False, "validation_changed"
        if "uncollected" in validation_state:
            return False, "validation_uncollected"

    combined = f"{stdout_text}\n{stderr_text}".lower()
    if "== asm fallback ==" in combined:
        return False, "asm_fallback"
    if "decompile timeout" in combined:
        return False, "timeout"
    if "whole-tail validation failed" in combined:
        return False, "tail_validation_failed"
    return True, None


def _extract_profile_summary(profile: dict[str, object]) -> str:
    function_times = profile.get("function_times", [])
    if not isinstance(function_times, list):
        return ""
    if not function_times:
        return ""
    slow = [item for item in function_times if isinstance(item, dict) and item.get("seconds", 0.0) > DECOMPILE_SLOW_FUNCTION_SECONDS]
    slow_passes = profile.get("slow_passes", [])
    if not isinstance(slow_passes, list):
        slow_passes = []
    if not slow:
        if not slow_passes:
            return ""
    slowest = max(
        (
            item
            for item in function_times
            if isinstance(item, dict) and isinstance(item.get("seconds"), (int, float))
        ),
        key=lambda item: float(item["seconds"]),
        default=None,
    )
    if slowest is None:
        return ""
    return json.dumps(
        {
            "slow_functions": slow,
            "slowest": slowest,
            "slow_passes": [
                item
                for item in slow_passes
                if isinstance(item, dict) and isinstance(item.get("seconds"), (int, float))
            ],
        },
        sort_keys=True,
    )


def _json_safe_profile(value: object, seen: set[int] | None = None) -> object:
    if seen is None:
        seen = set()
    if isinstance(value, dict):
        obj_id = id(value)
        if obj_id in seen:
            return "<recursive>"
        seen.add(obj_id)
        try:
            return {str(key): _json_safe_profile(item, seen) for key, item in value.items()}
        finally:
            seen.remove(obj_id)
    if isinstance(value, (list, tuple)):
        obj_id = id(value)
        if obj_id in seen:
            return "<recursive>"
        seen.add(obj_id)
        try:
            return [_json_safe_profile(item, seen) for item in value]
        finally:
            seen.remove(obj_id)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _decompile(
    exe_path: Path,
    out_dir: Path,
    *,
    decompile_py: Path,
    decompile_timeout: int,
    decompile_run_timeout: int,
    decompile_mode: str,
    decompile_cod_path: Path | None,
    decompile_max_functions: int,
) -> tuple[bool, Path, Path, float, dict[str, object]]:
    stdout_path = out_dir / f"{exe_path.stem}.dec.txt"
    stderr_path = out_dir / f"{exe_path.stem}.dec.err.txt"
    cmd = [
        str(shutil.which("python3") or "python3"),
        str(decompile_py),
        "--alternate-source-c",
        "--timeout",
        str(decompile_timeout),
    ]
    profile: dict[str, object] = {
        "decompile_mode": decompile_mode,
        "selected": {},
    }
    if decompile_mode == "main":
        candidates = _resolve_main_candidates_from_metadata(exe_path, decompile_cod_path)
        if not candidates:
            selected_count = max(1, decompile_max_functions)
            candidates = [
                {
                    "kind": "max-functions",
                    "source": "default",
                    "value_type": "max-functions",
                    "value": selected_count,
                }
            ]
            profile["selected"] = {"kind": "max-functions", "value": selected_count}
        else:
            profile["selected"] = {"kind": "candidates", "candidates": candidates}
    else:
        selected_count = max(1, decompile_max_functions) if decompile_max_functions > 0 else 0
        candidates = [
            {
                "kind": "max-functions",
                "source": "command-line",
                "value_type": "max-functions",
                "value": selected_count,
            }
        ]
        profile["selected"] = {"kind": "max-functions", "value": selected_count}

    def _candidate_command(candidate: dict[str, object]) -> list[str]:
        cmd_for_candidate = list(cmd)
        kind = candidate.get("kind")
        if kind == "addr":
            candidate_addr = candidate.get("value")
            if isinstance(candidate_addr, int):
                cmd_for_candidate.extend(["--addr", f"0x{candidate_addr:x}"])
        elif kind == "proc":
            candidate_name = candidate.get("name")
            candidate_kind = candidate.get("proc_kind")
            candidate_cod_offset = candidate.get("cod_offset")
            if isinstance(candidate_name, str) and candidate_name:
                cmd_for_candidate.extend(["--proc", candidate_name, "--proc-kind", str(candidate_kind or "NEAR")])
            elif isinstance(candidate_cod_offset, int):
                map_path = exe_path.with_suffix(".MAP")
                if not map_path.exists():
                    alt_map_path = exe_path.with_suffix(".map")
                    if alt_map_path.exists():
                        map_path = alt_map_path
                    else:
                        map_path = None
                mapped_addr = _resolve_cod_offset_to_exe_addr(
                    candidate_cod_offset,
                    map_path,
                    proc_name=None,
                )
                if mapped_addr is not None:
                    cmd_for_candidate.extend(["--addr", f"0x{mapped_addr:x}"])
        elif kind == "max-functions":
            candidate_value = candidate.get("value")
            if isinstance(candidate_value, int) and candidate_value > 0:
                cmd_for_candidate.extend(["--max-functions", str(candidate_value)])
        cmd_for_candidate.append(str(exe_path))
        return cmd_for_candidate

    def _candidate_run_timeout(candidate: dict[str, object]) -> int:
        if decompile_mode != "functions":
            return int(decompile_run_timeout)
        count = candidate.get("value") if candidate.get("kind") == "max-functions" else decompile_max_functions
        if not isinstance(count, int) or count <= 0:
            count = max(1, decompile_max_functions)
        setup_budget = 90
        return max(int(decompile_run_timeout), int(decompile_timeout) * int(count) + setup_budget)

    attempts: list[dict[str, object]] = []
    start = time.perf_counter()
    last_proc: subprocess.CompletedProcess[str] | None = None
    last_profile: dict[str, object] | None = None

    try:
        all_selection_failures = True
        saw_decompile_timeout = False
        for candidate in candidates:
            candidate_cmd = _candidate_command(candidate)
            candidate_attempt: dict[str, object] = {
                "candidate": candidate,
                "command": " ".join(candidate_cmd),
            }
            attempts.append(candidate_attempt)

            proc = _run(
                candidate_cmd,
                cwd=REPO_ROOT,
                timeout=_candidate_run_timeout(candidate),
                env={"INERTIA_DEBUG_TIMING": "1"},
            )
            last_proc = proc
            run_profile = _parse_decompile_profile(proc.stderr)
            acceptable, reason = _is_decompile_output_acceptable(proc.stdout, proc.stderr, run_profile)
            run_profile["acceptance_reason"] = None if acceptable else reason
            run_profile["candidate"] = candidate
            candidate_attempt["returncode"] = proc.returncode
            candidate_attempt["profile"] = run_profile

            if acceptable and proc.returncode == 0:
                elapsed = time.perf_counter() - start
                run_profile["commands_tried"] = attempts
                run_profile["wall_seconds"] = elapsed
                run_profile["selected"] = profile.get("selected", {})
                run_profile["slowest_function_summary"] = _extract_profile_summary(run_profile)
                stdout_path.write_text(_sanitize_decompiled_source(proc.stdout), encoding="utf-8")
                stderr_path.write_text(proc.stderr, encoding="utf-8")
                return True, stdout_path, stderr_path, elapsed, run_profile

            if run_profile.get("timeout"):
                saw_decompile_timeout = True
            if not _is_proc_selection_failure(proc.stderr):
                all_selection_failures = False

            if decompile_mode == "main" and attempts:
                if run_profile.get("timeout"):
                    # Timeout can be backend-specific; try alternate entrypoint candidate if present.
                    continue
                if not all_selection_failures:
                    # Real rejection is enough to stop probing this candidate chain.
                    break
            last_profile = run_profile
            if decompile_mode != "main":
                break

        if (
            decompile_mode == "main"
            and (
                all_selection_failures
                or (saw_decompile_timeout and attempts and attempts[-1]["candidate"].get("kind") != "max-functions")
            )
            and attempts
            and attempts[-1]["candidate"].get("kind") != "max-functions"
        ):
            fallback_count = max(1, decompile_max_functions)
            fallback_candidate = {
                "kind": "max-functions",
                "source": "fallback-after-failed-main-candidates",
                "value_type": "max-functions",
                "value": fallback_count,
            }
            fallback_cmd = _candidate_command(fallback_candidate)
            fallback_attempt = {
                "candidate": fallback_candidate,
                "command": " ".join(fallback_cmd),
            }
            attempts.append(fallback_attempt)
            proc = _run(
                fallback_cmd,
                cwd=REPO_ROOT,
                timeout=_candidate_run_timeout(fallback_candidate),
                env={"INERTIA_DEBUG_TIMING": "1"},
            )
            last_proc = proc
            run_profile = _parse_decompile_profile(proc.stderr)
            acceptable, reason = _is_decompile_output_acceptable(proc.stdout, proc.stderr, run_profile)
            run_profile["acceptance_reason"] = None if acceptable else reason
            run_profile["candidate"] = fallback_candidate
            fallback_attempt["returncode"] = proc.returncode
            fallback_attempt["profile"] = run_profile
            if acceptable and proc.returncode == 0:
                elapsed = time.perf_counter() - start
                run_profile["commands_tried"] = attempts
                run_profile["wall_seconds"] = elapsed
                run_profile["selected"] = profile.get("selected", {})
                run_profile["slowest_function_summary"] = _extract_profile_summary(run_profile)
                stdout_path.write_text(_sanitize_decompiled_source(proc.stdout), encoding="utf-8")
                stderr_path.write_text(proc.stderr, encoding="utf-8")
                return True, stdout_path, stderr_path, elapsed, run_profile
            last_profile = run_profile

        elapsed = time.perf_counter() - start
        profile["commands_tried"] = attempts
        merged_profile = last_profile if isinstance(last_profile, dict) else _parse_decompile_profile((last_proc.stderr if last_proc else ""))
        merged_profile["commands_tried"] = attempts
        merged_profile["selected"] = profile.get("selected", {})
        merged_profile["wall_seconds"] = elapsed
        merged_profile["slowest_function_summary"] = _extract_profile_summary(merged_profile)
        if merged_profile.get("acceptance_reason") is None and last_proc is not None:
            merged_profile["acceptance_reason"] = "no_acceptable_candidate"
        stdout_text = ""
        stderr_text = ""
        if last_proc is not None:
            stdout_text = last_proc.stdout
            stderr_text = last_proc.stderr
        stdout_path.write_text(_sanitize_decompiled_source(stdout_text), encoding="utf-8")
        stderr_path.write_text(stderr_text, encoding="utf-8")
        return False, stdout_path, stderr_path, elapsed, merged_profile
    except subprocess.TimeoutExpired as ex:
        elapsed = time.perf_counter() - start
        stdout_data = ex.stdout.decode("utf-8", errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        stderr_data = ex.stderr.decode("utf-8", errors="replace") if isinstance(ex.stderr, bytes) else (ex.stderr or "")
        timeout_text = stderr_data + "\ndecompile timeout\n"
        merged_profile = _parse_decompile_profile(timeout_text)
        merged_profile["commands_tried"] = attempts
        merged_profile["wall_seconds"] = elapsed
        merged_profile["timeout"] = True
        merged_profile["selected"] = profile.get("selected", {})
        merged_profile["acceptance_reason"] = "timeout"
        stdout_path.write_text(_sanitize_decompiled_source(stdout_data), encoding="utf-8")
        stderr_path.write_text(timeout_text, encoding="utf-8")
        return False, stdout_path, stderr_path, elapsed, merged_profile


def _decompile_and_validate(
    exe_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    msc6_root: Path,
    decompile_py: Path,
    decompile_timeout: int,
    decompile_run_timeout: int,
    decompile_mode: str,
    decompile_cod_path: Path | None,
    decompile_max_functions: int,
    expected_exit_code: int,
    decompile_safe_names: tuple[str, str, str, str] | None = None,
) -> tuple[bool, Path, Path, bool, bool, int | None, str, str, str, str, str, str, float, int, str]:
    decompile_ok, dec_out, dec_err, decompile_elapsed, decompile_profile = _decompile(
        exe_path,
        out_dir,
        decompile_py=decompile_py,
        decompile_timeout=decompile_timeout,
        decompile_run_timeout=decompile_run_timeout,
        decompile_mode=decompile_mode,
        decompile_cod_path=decompile_cod_path,
        decompile_max_functions=decompile_max_functions,
    )
    if not decompile_ok:
        selected_functions = 0
        attempted_count = decompile_profile.get("attempted_count")
        if isinstance(attempted_count, int):
            selected_functions = attempted_count
        return (
            False,
            dec_out,
            dec_err,
            False,
            False,
            None,
            "",
            "",
            "",
            "",
            "",
            "",
            decompile_elapsed,
            selected_functions,
            json.dumps(_json_safe_profile(decompile_profile), sort_keys=True),
        )

    if decompile_safe_names is None:
        stem = exe_path.stem.upper()
        decomp_name, obj_name, exe_name, map_name = (
            f"{stem}_DECOMPILE.C",
            f"{stem}_DECOMPILE.OBJ",
            f"{stem}_DECOMPILE.EXE",
            f"{stem}_DECOMPILE.MAP",
        )
    else:
        decomp_name, obj_name, exe_name, map_name = decompile_safe_names

    decomp_src = out_dir / decomp_name
    reexe = out_dir / exe_name
    shutil.copy2(dec_out, decomp_src)

    recompiled_ok, rec_out, rec_err, rel_out, rel_err = _compile_and_link(
        decomp_src,
        out_dir,
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        obj_name=obj_name,
        exe_name=exe_name,
        map_name=map_name,
    )
    decompile_run_exit: int | None = None
    decompile_run_stdout = ""
    decompile_run_stderr = ""
    if recompiled_ok and reexe.exists():
        _, decompile_run_exit, decompile_run_stdout, decompile_run_stderr = _run_example(
            reexe,
            out_dir,
            kvikdos=kvikdos,
            timeout=decompile_run_timeout,
        )

    return (
        decompile_ok,
        dec_out,
        dec_err,
        recompiled_ok,
        decompile_run_exit == expected_exit_code,
        decompile_run_exit,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_stdout,
        decompile_run_stderr,
        decompile_elapsed,
        int(
            (
                (decompile_profile.get("decompiled_count") if isinstance(decompile_profile.get("decompiled_count"), dict) else None)
                or {}
            ).get("shown", 0)
            if isinstance(decompile_profile.get("decompiled_count"), dict)
            else 0
        ),
        json.dumps(_json_safe_profile(decompile_profile), sort_keys=True),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Build simple/medium MS C 6 examples via kvikdos and try decompilation.")
    ap.add_argument("--examples-dir", type=Path, default=DEFAULT_EXAMPLES_DIR)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    ap.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    ap.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    ap.add_argument("--decompile-py", type=Path, default=DEFAULT_DECOMPILE)
    ap.add_argument(
        "--skip-constructs",
        type=lambda text: [item.strip() for item in text.split(",") if item.strip()],
        default=list(DEFAULT_DECOMPILE_SKIP),
        help="Comma-separated source stems to skip decompilation for (default: enum_union,medium_structs)",
    )
    ap.add_argument(
        "--decompile-mode",
        choices=("main", "functions"),
        default="main",
        help="Decompilation mode. 'main' decompiles the main/entry proc when available; 'functions' decompiles the configured count.",
    )
    ap.add_argument(
        "--decompile-max-functions",
        type=int,
        default=1,
        help="Maximum number of recovered functions to decompile when mode=functions.",
    )
    ap.add_argument(
        "--decompile-timeout",
        type=int,
        default=DECOMPILE_MAIN_TIMEOUT_SECONDS_DEFAULT,
        help="Per-function decompiler timeout in seconds.",
    )
    ap.add_argument(
        "--decompile-run-timeout",
        type=int,
        default=DECOMPILE_MAIN_RUN_TIMEOUT_SECONDS_DEFAULT,
        help="Wall-clock timeout for one decompile invocation in seconds.",
    )
    ap.add_argument(
        "--only-constructs",
        type=lambda text: [item.strip() for item in text.split(",") if item.strip()],
        default=[],
        help="Comma-separated example stems to run. If provided, only these examples are processed.",
    )
    ap.add_argument(
        "--harvest-success-code",
        type=int,
        default=HARNESS_SUCCESS_EXIT_CODE,
        help="Exit code to return when all checks pass.",
    )
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    results: list[ExampleResult] = []
    only_set = {item for item in args.only_constructs}
    dos_names = {
        "compare16": "CMP16.C",
        "simple_control": "SIMPLE.C",
        "medium_structs": "MEDIUM.C",
        "compare32": "COMP32.C",
        "loops_jumps": "LOOPS.C",
        "scalar_types_io": "TYPES.C",
        "pointer_memory": "POINT.C",
        "enum_union": "EUNION.C",
        "function_pointers": "FPTR.C",
        "storage_classes": "STORE.C",
    }
    decompile_skip = set(args.skip_constructs)
    decompile_idx = 0

    for source_path in sorted(args.examples_dir.glob("*.c")):
        if only_set and source_path.stem not in only_set:
            continue
        decompile_idx += 1
        dos_name = dos_names.get(source_path.stem, source_path.name.upper())
        local_source = args.out_dir / dos_name
        shutil.copy2(source_path, local_source)
        build_ok, c_out, c_err, l_out, l_err = _compile_and_link(
            local_source,
            args.out_dir,
            kvikdos=args.kvikdos,
            msc6_root=args.msc6_root,
            obj_name=f"{local_source.stem.upper()}.OBJ",
            exe_name=f"{local_source.stem.upper()}.EXE",
            map_name=f"{local_source.stem.upper()}.MAP",
            cod_name=f"{local_source.stem.upper()}.COD",
        )
        exe_path = args.out_dir / f"{local_source.stem.upper()}.EXE"
        obj_path = args.out_dir / f"{local_source.stem.upper()}.OBJ"
        map_path = args.out_dir / f"{local_source.stem.upper()}.MAP"
        cod_path = args.out_dir / f"{local_source.stem.upper()}.COD"

        run_ok = False
        run_exit_code: int | None = None
        run_stdout = ""
        run_stderr = ""
        if build_ok and exe_path.exists():
            _, run_exit_code, run_stdout, run_stderr = _run_example(
                exe_path,
                args.out_dir,
                kvikdos=args.kvikdos,
            )
            run_ok = run_exit_code == args.harvest_success_code

        decompile_skipped = source_path.stem in decompile_skip
        decompile_ok = False
        decompile_recompiled_ok = False
        decompile_run_ok = False
        decompile_run_exit_code: int | None = None
        decompile_stdout: Path | None = None
        decompile_stderr: Path | None = None
        decompile_wall_seconds = 0.0
        decompile_selected_functions = 0
        decompile_profile = "{}"
        decompile_recompiled_exe = str(args.out_dir / f"{local_source.stem.upper()}_DECOMPILE.EXE")
        decompile_recompiled_obj = str(args.out_dir / f"{local_source.stem.upper()}_DECOMPILE.OBJ")
        decompile_recompiled_map = str(args.out_dir / f"{local_source.stem.upper()}_DECOMPILE.MAP")
        decompile_compile_stdout = ""
        decompile_compile_stderr = ""
        decompile_link_stdout = ""
        decompile_link_stderr = ""
        decompile_run_stdout = ""
        decompile_run_stderr = ""

        if build_ok and run_ok and exe_path.exists() and not decompile_skipped:
            decompile_c_name, decompile_obj_name, decompile_exe_name, decompile_map_name = _dos_safe_names(
                local_source.stem.upper(),
                counter=decompile_idx,
            )
            (
                decompile_ok,
                decompile_stdout,
                decompile_stderr,
                decompile_recompiled_ok,
                decompile_run_ok,
                decompile_run_exit_code,
                decompile_compile_stdout,
                decompile_compile_stderr,
                decompile_link_stdout,
                decompile_link_stderr,
                decompile_run_stdout,
                decompile_run_stderr,
                decompile_wall_seconds,
                decompile_selected_functions,
                decompile_profile,
            ) = _decompile_and_validate(
                exe_path,
                args.out_dir,
                kvikdos=args.kvikdos,
                msc6_root=args.msc6_root,
                decompile_py=args.decompile_py,
                decompile_timeout=args.decompile_timeout,
                decompile_run_timeout=args.decompile_run_timeout,
                decompile_mode=args.decompile_mode,
                decompile_cod_path=cod_path,
                decompile_max_functions=args.decompile_max_functions,
                expected_exit_code=args.harvest_success_code,
                decompile_safe_names=(
                    decompile_c_name,
                    decompile_obj_name,
                    decompile_exe_name,
                    decompile_map_name,
                ),
            )
            decompile_recompiled_exe = str(args.out_dir / decompile_exe_name)
            decompile_recompiled_obj = str(args.out_dir / decompile_obj_name)
            decompile_recompiled_map = str(args.out_dir / decompile_map_name)

        results.append(
            ExampleResult(
                name=source_path.stem,
                source=str(local_source),
                exe=str(exe_path),
                obj=str(obj_path),
                map=str(map_path),
                cod=str(cod_path),
                build_ok=build_ok,
                run_ok=run_ok,
                run_exit_code=run_exit_code,
                run_stdout=run_stdout,
                run_stderr=run_stderr,
                decompile_skipped=decompile_skipped,
                decompile_ok=decompile_ok,
                decompile_recompiled=not decompile_skipped and build_ok and run_ok,
                decompile_recompile_ok=decompile_recompiled_ok,
                decompile_run_ok=decompile_run_ok,
                decompile_run_exit_code=decompile_run_exit_code,
                decompile_recompiled_exe=decompile_recompiled_exe,
                decompile_recompiled_obj=decompile_recompiled_obj,
                decompile_recompiled_map=decompile_recompiled_map,
                decompile_compile_stdout=decompile_compile_stdout,
                decompile_compile_stderr=decompile_compile_stderr,
                decompile_link_stdout=decompile_link_stdout,
                decompile_link_stderr=decompile_link_stderr,
                decompile_run_stdout=decompile_run_stdout,
                decompile_run_stderr=decompile_run_stderr,
                compile_stdout=c_out,
                compile_stderr=c_err,
                link_stdout=l_out,
                link_stderr=l_err,
                decompile_stdout_path=str(decompile_stdout) if decompile_stdout is not None else None,
                decompile_stderr_path=str(decompile_stderr) if decompile_stderr is not None else None,
                decompile_wall_seconds=decompile_wall_seconds,
                decompile_selected_functions=decompile_selected_functions,
                decompile_profile=decompile_profile,
            )
        )

    report_path = args.out_dir / "report.json"
    report_path.write_text(json.dumps([asdict(item) for item in results], indent=2), encoding="utf-8")
    print(report_path)
    for item in results:
        print(
            f"{item.name}: "
            f"build={'ok' if item.build_ok else 'fail'} "
            f"run={'ok' if item.run_ok else f'fail({item.run_exit_code})'} "
            f"decompile={'skipped' if item.decompile_skipped else ('ok' if item.decompile_ok else 'fail')} "
            f"decomp_time={item.decompile_wall_seconds:.2f}s "
            f"decomp_funcs={item.decompile_selected_functions} "
            f"decompile_profile={item.decompile_profile} "
            f"recompile={'skipped' if item.decompile_skipped else ('ok' if item.decompile_recompile_ok else 'fail')} "
            f"decompile_run={'skipped' if item.decompile_skipped else ('ok' if item.decompile_run_ok else f'fail({item.decompile_run_exit_code})')} "
            f"exe={item.exe}"
        )

    all_examples_ok = all(
        item.build_ok
        and item.run_ok
        and (item.decompile_ok or item.decompile_skipped)
        and ((item.decompile_recompile_ok and item.decompile_run_ok) or item.decompile_skipped)
        for item in results
    )
    if all_examples_ok:
        return args.harvest_success_code
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
