#!/usr/bin/env python3
"""Curated fast/default/expanded decompiler regression pipeline.

Layer: Tooling/gates.
Responsibility: run curated fast/default/expanded decompiler regression tiers.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import cast

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
DEFAULT_OUT: Path = REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "summary.json"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_ULTRA_QUICKC_ROOT: Path = REPO_ROOT / "borrow" / "UltraDecompiler" / "QuickC"

FOCUSED_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_x86_16_smoketest.py",
    "angr_platforms/tests/test_build_msc6_examples.py",
    "angr_platforms/tests/test_msc6_toolchain_lock.py",
    "angr_platforms/tests/test_check_changed_non_test_types.py",
    "angr_platforms/tests/test_import_ultra_quickc_fixtures.py",
    "angr_platforms/tests/test_omf_pat_lidata.py",
    "angr_platforms/tests/test_test_pipeline.py",
    "angr_platforms/tests/test_check_sortd_sidecar_free.py",
    "angr_platforms/tests/test_compare_ghidra_function_coverage.py",
    "angr_platforms/tests/test_generated_c_artifacts.py",
    "angr_platforms/tests/test_generated_translation_unit_assembly.py",
    "angr_platforms/tests/test_generated_translation_unit_gate.py",
    "angr_platforms/tests/test_cli_direct_argument_evidence_context.py",
    "angr_platforms/tests/test_x86_16_corpus_scan_timeout.py",
    "angr_platforms/tests/test_decompilation_quality.py",
    "angr_platforms/tests/test_cli_regeneration.py",
    "angr_platforms/tests/test_x86_16_alias_register_mvp.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py",
    "angr_platforms/tests/test_x86_16_protected_call_arguments.py",
    "angr_platforms/tests/test_x86_16_condition_lowering.py",
    "angr_platforms/tests/test_x86_16_condition_register_carriers.py",
    "angr_platforms/tests/test_x86_16_condition_transfer.py",
    "angr_platforms/tests/test_x86_16_frontend_condition_evidence.py",
    "angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py",
    "angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",
    "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py",
    "angr_platforms/tests/test_x86_16_unused_void_return_types.py",
    "angr_platforms/tests/test_x86_16_alu_helpers.py",
    "angr_platforms/tests/test_x86_16_object_lowering.py",
    "angr_platforms/tests/test_x86_16_semantics_alias_query.py",
    "angr_platforms/tests/test_x86_16_semantics_expression_analysis.py",
    "angr_platforms/tests/test_x86_16_stack_frame_recovery.py",
    "angr_platforms/tests/test_x86_16_validation_canonicalize.py",
    "angr_platforms/tests/test_x86_16_validation_call_argument_sources.py",
    "angr_platforms/tests/test_x86_16_validation_calls.py",
    "angr_platforms/tests/test_x86_16_package_exports.py",
    "angr_platforms/tests/test_x86_16_pipeline_contracts.py",
    "angr_platforms/tests/test_x86_16_rewrite_boundary.py",
    "angr_platforms/tests/test_x86_16_array_matching.py",
    "angr_platforms/tests/test_x86_16_struct_merging.py",
    "angr_platforms/tests/test_x86_16_structuring_condition_materialization.py",
    "angr_platforms/tests/test_x86_16_structuring_multi_arm_condition_ownership.py",
    "angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py",
    "angr_platforms/tests/test_x86_16_dce_optimization.py",
    "angr_platforms/tests/test_x86_16_trivial_copy_optimization.py",
    "angr_platforms/tests/test_x86_16_widening_copyprop.py",
    "angr_platforms/tests/test_x86_16_widening_memory_fold.py",
    "angr_platforms/tests/test_x86_16_stack_subview_call_writes.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py",
    "angr_platforms/tests/test_x86_16_widening_rules.py",
    "angr_platforms/tests/test_x86_16_generated_c_acceptance.py",
    "angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py",
    "angr_platforms/tests/test_x86_16_segment_access_policy.py",
    "angr_platforms/tests/test_x86_16_segment_address_policy.py",
    "angr_platforms/tests/test_x86_16_segment_state.py",
    "angr_platforms/tests/test_x86_16_vex_import.py",
    "angr_platforms/tests/test_x86_16_cod_global_identity.py",
    "angr_platforms/tests/test_x86_16_cod_module_caller_evidence.py",
    "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
    "angr_platforms/tests/test_x86_16_segmented_lowering.py",
    "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py",
    "angr_platforms/tests/test_x86_16_direct_stack_move_loop_entries.py",
    "angr_platforms/tests/test_x86_16_decompilation_cache_surface.py",
    "angr_platforms/tests/test_x86_16_return_compat_counters.py",
)

MSC6_TINY_CONSTRUCTS: tuple[str, ...] = (
    "compare16",
    "simple_control",
    "loops_jumps",
    "storage_classes",
    "function_pointers",
    "pointer_memory",
    "scalar_types_io",
)
MSC6_TINY_SMOKE_CONSTRUCTS: tuple[str, ...] = ("storage_classes",)
MSC6_TINY_NEXT_CONSTRUCTS: tuple[str, ...] = ()

LANE_BUDGET_SECONDS: dict[str, float] = {
    "unit-focused": 30.0,
    "msc6-tiny-smoke": 90.0,
    "msc6-tiny-full-pipeline": 300.0,
    "ultra-quickc-fixtures": 180.0,
    "sortdemo-status": 2460.0,
    "sortdemo-status-proc-diagnostic": 2460.0,
    "sortd-sidecar-free": 1200.0,
    "sortd-generated-sort-core": 60.0,
    "sortd-generated-translation-unit": 60.0,
}

PIPELINE_TIERS: dict[str, tuple[str, ...]] = {
    "fast": ("unit-focused",),
    "default": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),
    "expanded": (
        "unit-focused",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
        "sortd-sidecar-free",
        "sortdemo-status",
    ),
}


class LaneStatus(str, Enum):
    """Structured terminal status for one curated pipeline lane."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


class BudgetStatus(str, Enum):
    """Structured runtime-budget verdict for a completed lane."""

    PASSED = "passed"
    OVER_BUDGET = "over_budget"


@dataclass(frozen=True, slots=True)
class LaneResult:
    """Serializable result contract for one curated pipeline lane."""

    name: str
    status: LaneStatus
    command: list[str]
    elapsed_seconds: float
    returncode: int | None = None
    reason: str | None = None
    budget_seconds: float | None = None
    budget_status: BudgetStatus | None = None
    children: list[dict[str, object]] | None = None
    details: dict[str, object] | None = None


def _budget_status(name: str, elapsed_seconds: float) -> tuple[float | None, BudgetStatus | None]:
    budget = LANE_BUDGET_SECONDS.get(name)
    if budget is None:
        return None, None
    return budget, BudgetStatus.PASSED if elapsed_seconds <= budget else BudgetStatus.OVER_BUDGET


def _run_command(name: str, cmd: list[str], *, env: dict[str, str] | None = None) -> LaneResult:
    start = time.monotonic()
    try:
        completed = subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        rounded_elapsed = round(elapsed, 3)
        budget, budget_status = _budget_status(name, rounded_elapsed)
        return LaneResult(
            name=name,
            status=LaneStatus.TIMED_OUT,
            command=cmd,
            elapsed_seconds=rounded_elapsed,
            returncode=None,
            reason=f"timed out after {exc.timeout} seconds",
            budget_seconds=budget,
            budget_status=budget_status,
        )
    elapsed = time.monotonic() - start
    rounded_elapsed = round(elapsed, 3)
    budget, budget_status = _budget_status(name, rounded_elapsed)
    return LaneResult(
        name=name,
        status=LaneStatus.PASSED if completed.returncode == 0 else LaneStatus.FAILED,
        command=cmd,
        elapsed_seconds=rounded_elapsed,
        returncode=completed.returncode,
        budget_seconds=budget,
        budget_status=budget_status,
    )


def _captured_text(value: str | bytes | None) -> str:
    """Return captured subprocess output as text for JSON-safe lane details."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _run_captured_command(name: str, cmd: list[str], *, env: dict[str, str] | None = None) -> LaneResult:
    start = time.monotonic()
    try:
        completed = subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=False, capture_output=True, text=True)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        rounded_elapsed = round(elapsed, 3)
        budget, budget_status = _budget_status(name, rounded_elapsed)
        child: dict[str, object] = {
            "stdout": _captured_text(exc.stdout),
            "stderr": _captured_text(exc.stderr),
        }
        return LaneResult(
            name=name,
            status=LaneStatus.TIMED_OUT,
            command=cmd,
            elapsed_seconds=rounded_elapsed,
            returncode=None,
            reason=f"timed out after {exc.timeout} seconds",
            budget_seconds=budget,
            budget_status=budget_status,
            children=[child],
        )
    elapsed = time.monotonic() - start
    rounded_elapsed = round(elapsed, 3)
    budget, budget_status = _budget_status(name, rounded_elapsed)
    reason = None
    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout).strip()[:1000] or f"exit {completed.returncode}"
    completed_child: dict[str, object] = {
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    return LaneResult(
        name=name,
        status=LaneStatus.PASSED if completed.returncode == 0 else LaneStatus.FAILED,
        command=cmd,
        elapsed_seconds=rounded_elapsed,
        returncode=completed.returncode,
        reason=reason,
        budget_seconds=budget,
        budget_status=budget_status,
        children=[completed_child],
    )


def _external_tools_available(kvikdos: Path, msc6_root: Path) -> tuple[bool, str | None]:
    if not kvikdos.is_file() or not os.access(kvikdos, os.X_OK):
        return False, f"kvikdos not executable: {kvikdos}"
    if not msc6_root.is_dir():
        return False, f"MS C 6 root not found: {msc6_root}"
    return True, None


def _ultra_quickc_tools_available(kvikdos: Path, quickc_root: Path) -> tuple[bool, str | None]:
    if not kvikdos.is_file() or not os.access(kvikdos, os.X_OK):
        return False, f"kvikdos not executable: {kvikdos}"
    if not (quickc_root / "QCL.EXE").is_file():
        return False, f"Ultra QuickC compiler not found: {quickc_root / 'QCL.EXE'}"
    if not (quickc_root / "LINK.EXE").is_file():
        return False, f"Ultra QuickC linker not found: {quickc_root / 'LINK.EXE'}"
    return True, None


def _unit_lane() -> LaneResult:
    return _run_command(
        "unit-focused",
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-n",
            "7",
            "--dist",
            "loadgroup",
            "--durations=25",
            "--durations-min=1.0",
            *FOCUSED_PYTEST_TARGETS,
        ],
    )


def _msc6_construct_command(
    args: argparse.Namespace,
    *,
    construct: str,
    out_dir: Path,
) -> list[str]:
    return [
        sys.executable,
        "scripts/build_msc6_examples.py",
        "--only-constructs",
        construct,
        "--out-dir",
        str(out_dir),
        "--kvikdos",
        str(args.kvikdos),
        "--msc6-root",
        str(args.msc6_root),
        "--decompile-mode",
        "functions",
        "--decompile-max-functions",
        "0",
        "--decompile-timeout",
        str(args.decompile_timeout),
        "--decompile-run-timeout",
        str(args.decompile_run_timeout),
    ]


def _missing_external_lane(name: str, cmd: list[str], *, reason: str | None, require_external: bool) -> LaneResult:
    budget, budget_status = _budget_status(name, 0.0)
    if require_external:
        return LaneResult(
            name,
            LaneStatus.FAILED,
            cmd,
            0.0,
            returncode=1,
            reason=reason,
            budget_seconds=budget,
            budget_status=budget_status,
        )
    return LaneResult(
        name,
        LaneStatus.SKIPPED,
        cmd,
        0.0,
        reason=reason,
        budget_seconds=budget,
        budget_status=budget_status,
    )


def _sortdemo_status_command(
    args: argparse.Namespace,
    *,
    per_function_proc: bool = False,
) -> list[str]:
    """Build an authoritative whole-binary or explicit per-PROC diagnostic command."""
    status_out = args.sortdemo_status_out
    transcript_out = args.sortdemo_transcript_out
    command = [
        sys.executable,
        "scripts/sortdemo_decompiler_status.py",
        "--run-sortdemo",
        "--require-passed",
        "--binary",
        str(args.sortdemo_binary),
        "--decompile-timeout",
        str(args.sortdemo_decompile_timeout),
        "--run-timeout",
        str(args.sortdemo_run_timeout),
    ]
    if per_function_proc:
        command.append("--per-function-proc")
        status_out = status_out.with_name(f"{status_out.stem}_proc_diagnostic{status_out.suffix}")
        transcript_out = transcript_out.with_name(f"{transcript_out.stem}_proc_diagnostic{transcript_out.suffix}")
    if args.sortdemo_max_functions > 0:
        command.extend(("--max-functions", str(args.sortdemo_max_functions)))
    command.extend(
        [
            "--transcript-out",
            str(transcript_out),
            "--out",
            str(status_out),
            "--pretty",
        ]
    )
    return command


def _sortdemo_status_lane(
    args: argparse.Namespace,
    *,
    per_function_proc: bool = False,
) -> LaneResult:
    """Run the normal whole binary or the explicitly diagnostic per-PROC lane."""
    name = "sortdemo-status-proc-diagnostic" if per_function_proc else "sortdemo-status"
    cmd = _sortdemo_status_command(args, per_function_proc=per_function_proc)
    if not args.sortdemo_binary.is_file():
        return _missing_external_lane(
            name,
            cmd,
            reason=f"SORTDEMO binary not found: {args.sortdemo_binary}",
            require_external=bool(args.require_external),
        )
    env = dict(os.environ)
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    env["INERTIA_DISABLE_TIMING"] = "1"
    Path(cmd[cmd.index("--out") + 1]).parent.mkdir(parents=True, exist_ok=True)
    Path(cmd[cmd.index("--transcript-out") + 1]).parent.mkdir(parents=True, exist_ok=True)
    return _run_command(name, cmd, env=env)


def _sortd_sidecar_free_lane(args: argparse.Namespace) -> LaneResult:
    """Run the executable-only whole-binary discovery and acceptance ratchet."""
    args.sortd_report_out.parent.mkdir(parents=True, exist_ok=True)
    if not args.sortdemo_binary.is_file():
        cmd = [sys.executable, "scripts/check_sortd_sidecar_free.py"]
        return _missing_external_lane(
            "sortd-sidecar-free",
            cmd,
            reason=f"SORTDEMO source binary not found: {args.sortdemo_binary}",
            require_external=bool(args.require_external),
        )
    with tempfile.TemporaryDirectory(
        prefix="sortd-generated-functions-",
        dir=args.sortd_report_out.parent,
    ) as function_c_dir_text:
        function_c_dir = Path(function_c_dir_text)
        cmd = [
            sys.executable,
            "scripts/check_sortd_sidecar_free.py",
            "--source-binary",
            str(args.sortdemo_binary),
            "--run-timeout",
            str(args.sortd_run_timeout),
            "--transcript-out",
            str(args.sortd_transcript_out),
            "--report-out",
            str(args.sortd_report_out),
            "--function-c-dir",
            str(function_c_dir),
        ]
        sidecar_result = _run_command("sortd-sidecar-free", cmd)
        if sidecar_result.status is not LaneStatus.PASSED:
            return sidecar_result
        translation_unit_out = args.sortd_report_out.with_name("sortd_generated_translation_unit.c")
        translation_unit_report = args.sortd_report_out.with_name("sortd_generated_translation_unit.json")
        translation_unit_cmd = [
            sys.executable,
            "scripts/check_generated_translation_unit.py",
            "--function-c-dir",
            str(function_c_dir),
            "--output",
            str(translation_unit_out),
            "--report-out",
            str(translation_unit_report),
        ]
        translation_unit_result = _run_command(
            "sortd-generated-translation-unit",
            translation_unit_cmd,
        )
        behavior_cmd = [
            sys.executable,
            "scripts/check_sortd_generated_sort_core.py",
            "--transcript",
            str(args.sortd_transcript_out),
            "--function-c-dir",
            str(function_c_dir),
        ]
        behavior_result = _run_command("sortd-generated-sort-core", behavior_cmd)
    elapsed = round(
        sidecar_result.elapsed_seconds + translation_unit_result.elapsed_seconds + behavior_result.elapsed_seconds,
        3,
    )
    budget, budget_status = _budget_status("sortd-sidecar-free", elapsed)
    terminal_result = (
        translation_unit_result if translation_unit_result.status is not LaneStatus.PASSED else behavior_result
    )
    return LaneResult(
        name="sortd-sidecar-free",
        status=terminal_result.status,
        command=cmd,
        elapsed_seconds=elapsed,
        returncode=terminal_result.returncode,
        reason=terminal_result.reason,
        budget_seconds=budget,
        budget_status=budget_status,
        children=[
            asdict(sidecar_result),
            asdict(translation_unit_result),
            asdict(behavior_result),
        ],
    )


def _ultra_quickc_fixtures_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "scripts/import_ultra_quickc_fixtures.py",
        "--kvikdos",
        str(args.kvikdos),
        "--quickc-root",
        str(args.ultra_quickc_root),
        "--output-root",
        str(args.ultra_quickc_out_dir),
        "--decompile-timeout",
        str(args.ultra_quickc_decompile_timeout),
    ]


def _ultra_quickc_fixtures_lane(args: argparse.Namespace) -> LaneResult:
    cmd = _ultra_quickc_fixtures_command(args)
    available, reason = _ultra_quickc_tools_available(args.kvikdos, args.ultra_quickc_root)
    if not available:
        return _missing_external_lane(
            "ultra-quickc-fixtures",
            cmd,
            reason=reason,
            require_external=bool(args.require_external),
        )
    result = _run_captured_command("ultra-quickc-fixtures", cmd)
    report_path = args.ultra_quickc_out_dir / "ultra_quickc_fixtures.json"
    details: dict[str, object] = {"report_path": str(report_path)}
    if report_path.is_file():
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as ex:
            details["report_error"] = f"invalid JSON: {ex}"
        else:
            summary = payload.get("summary") if isinstance(payload, dict) else None
            if isinstance(summary, dict):
                details.update(summary)
    else:
        details["report_error"] = "fixture report not produced"
    return LaneResult(
        name=result.name,
        status=result.status,
        command=result.command,
        elapsed_seconds=result.elapsed_seconds,
        returncode=result.returncode,
        reason=result.reason,
        budget_seconds=result.budget_seconds,
        budget_status=result.budget_status,
        children=result.children,
        details=details,
    )


def _merge_msc6_reports(out_dir: Path, constructs: tuple[str, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for construct in constructs:
        report_path = out_dir / construct / "report.json"
        if not report_path.exists():
            continue
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            rows.extend(dict(row) for row in payload if isinstance(row, dict))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rows


def _float_field(row: dict[str, object], field_name: str) -> float | None:
    """Return a finite float field from a JSON row, if present."""

    value = row.get(field_name)
    if not isinstance(value, int | float):
        return None
    return float(value)


def _msc6_construct_timing_details(rows: list[dict[str, object]], *, limit: int = 5) -> dict[str, object]:
    """Return compact timing details from merged MS C construct reports."""

    timed_rows: list[dict[str, object]] = []
    for row in rows:
        seconds = _float_field(row, "decompile_wall_seconds")
        name = row.get("name")
        if seconds is None or not isinstance(name, str):
            continue
        timed_rows.append(
            {
                "construct": name,
                "decompile_wall_seconds": round(seconds, 3),
                "selected_functions": row.get("decompile_selected_functions"),
                "run_exit_code": row.get("decompile_run_exit_code"),
            }
        )
    timed_rows.sort(key=lambda item: cast(float, item["decompile_wall_seconds"]), reverse=True)
    total_seconds = round(sum(cast(float, item["decompile_wall_seconds"]) for item in timed_rows), 3)
    return {
        "construct_count": len(rows),
        "timed_construct_count": len(timed_rows),
        "decompile_wall_seconds_total": total_seconds,
        "slowest_constructs": timed_rows[: max(0, limit)],
    }


def _msc6_tiny_lane(args: argparse.Namespace, *, name: str, constructs: tuple[str, ...]) -> LaneResult:
    available, reason = _external_tools_available(args.kvikdos, args.msc6_root)
    representative_cmd = _msc6_construct_command(args, construct=",".join(constructs), out_dir=args.msc6_out_dir)
    if not available:
        return _missing_external_lane(
            name,
            representative_cmd,
            reason=reason,
            require_external=bool(args.require_external),
        )

    env = dict(os.environ)
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    env["INERTIA_DISABLE_TIMING"] = "1"
    env["INERTIA_DISABLE_SIGNATURES"] = "1"
    start = time.monotonic()
    requested_workers = int(args.msc6_workers or 1)
    allow_parallel = str(os.environ.get("INERTIA_ALLOW_PARALLEL_MSC6_WORKERS", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if requested_workers > 1 and not allow_parallel:
        print(
            "[test-pipeline] --msc6-workers > 1 ignored: construct-level parallelism is currently "
            "disabled by default; set INERTIA_ALLOW_PARALLEL_MSC6_WORKERS=1 to run with the requested "
            "parallelism.",
            file=sys.stderr,
        )
        requested_workers = 1

    max_workers = max(1, min(requested_workers, len(constructs)))
    child_results_by_construct: dict[str, LaneResult] = {}

    def run_construct(construct: str) -> LaneResult:
        out_dir = args.msc6_out_dir / construct
        cmd = _msc6_construct_command(args, construct=construct, out_dir=out_dir)
        return _run_captured_command(f"msc6-tiny:{construct}", cmd, env=env)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(run_construct, construct): construct for construct in constructs}
        for future in concurrent.futures.as_completed(future_map):
            construct = future_map[future]
            child_results_by_construct[construct] = future.result()

    child_results = [child_results_by_construct[construct] for construct in constructs]
    for child in child_results:
        if child.children:
            stdout = str(child.children[0].get("stdout", ""))
            stderr = str(child.children[0].get("stderr", ""))
            if stdout:
                print(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                print(stderr, file=sys.stderr, end="" if stderr.endswith("\n") else "\n")

    report_rows = _merge_msc6_reports(args.msc6_out_dir, constructs)
    elapsed = round(time.monotonic() - start, 3)
    budget, budget_status = _budget_status(name, elapsed)
    unsuccessful_children = [child for child in child_results if child.status != LaneStatus.PASSED]
    timed_out_children = [child for child in unsuccessful_children if child.status == LaneStatus.TIMED_OUT]
    status = (
        LaneStatus.TIMED_OUT
        if timed_out_children
        else LaneStatus.FAILED
        if unsuccessful_children
        else LaneStatus.PASSED
    )
    reason_text = (
        "; ".join(f"{child.name}: {child.reason or child.returncode}" for child in unsuccessful_children) or None
    )
    return LaneResult(
        name=name,
        status=status,
        command=representative_cmd,
        elapsed_seconds=elapsed,
        returncode=None if timed_out_children else 1 if unsuccessful_children else 0,
        reason=reason_text,
        budget_seconds=budget,
        budget_status=budget_status,
        children=[asdict(child) for child in child_results],
        details=_msc6_construct_timing_details(report_rows),
    )


def _selected_lanes(args: argparse.Namespace) -> tuple[str, ...]:
    if args.lane:
        return tuple(args.lane)
    return PIPELINE_TIERS[args.tier]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the curated decompiler regression pipeline.")
    parser.add_argument("--tier", choices=tuple(PIPELINE_TIERS), default="default")
    parser.add_argument(
        "--lane",
        action="append",
        choices=(
            "unit-focused",
            "ultra-quickc-fixtures",
            "msc6-tiny-smoke",
            "msc6-tiny-full-pipeline",
            "sortdemo-status",
            "sortdemo-status-proc-diagnostic",
            "sortd-sidecar-free",
        ),
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--msc6-out-dir", type=Path, default=REPO_ROOT / "examples" / "build_msc6_tiny")
    parser.add_argument("--ultra-quickc-root", type=Path, default=DEFAULT_ULTRA_QUICKC_ROOT)
    parser.add_argument(
        "--ultra-quickc-out-dir",
        type=Path,
        default=REPO_ROOT / "examples" / "build_ultra_quickc_pipeline",
    )
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    parser.add_argument("--require-external", action="store_true")
    parser.add_argument("--decompile-timeout", type=int, default=60)
    parser.add_argument("--ultra-quickc-decompile-timeout", type=int, default=180)
    parser.add_argument("--decompile-run-timeout", type=int, default=600)
    parser.add_argument("--sortdemo-binary", type=Path, default=REPO_ROOT / "SORTDEMO.EXE")
    parser.add_argument("--sortdemo-max-functions", type=int, default=0)
    parser.add_argument("--sortdemo-decompile-timeout", type=int, default=240)
    parser.add_argument("--sortdemo-run-timeout", type=int, default=2400)
    parser.add_argument("--sortd-run-timeout", type=int, default=1200)
    parser.add_argument(
        "--sortdemo-status-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortdemo_status.json",
    )
    parser.add_argument(
        "--sortdemo-transcript-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortdemo_status.txt",
    )
    parser.add_argument(
        "--sortd-report-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortd_sidecar_free.json",
    )
    parser.add_argument(
        "--sortd-transcript-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortd_sidecar_free.txt",
    )
    parser.add_argument(
        "--msc6-workers",
        type=int,
        default=1,
        help=(
            "Maximum parallel MS C construct subprocesses. Defaults to serial because concurrent decompiler/toolchain "
            "runs still share cache/runtime state. Function fallback rebuilds inside each construct remain serial. "
            "Set INERTIA_ALLOW_PARALLEL_MSC6_WORKERS=1 to opt in to parallel construct execution."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run selected pipeline lanes and write the structured summary report."""

    args = _parse_args(argv)
    lane_names = _selected_lanes(args)
    lane_fns: dict[str, Callable[[], LaneResult]] = {
        "unit-focused": _unit_lane,
        "ultra-quickc-fixtures": lambda: _ultra_quickc_fixtures_lane(args),
        "msc6-tiny-smoke": lambda: _msc6_tiny_lane(args, name="msc6-tiny-smoke", constructs=MSC6_TINY_SMOKE_CONSTRUCTS),
        "msc6-tiny-full-pipeline": lambda: _msc6_tiny_lane(
            args,
            name="msc6-tiny-full-pipeline",
            constructs=MSC6_TINY_CONSTRUCTS,
        ),
        "sortdemo-status": lambda: _sortdemo_status_lane(args),
        "sortd-sidecar-free": lambda: _sortd_sidecar_free_lane(args),
        "sortdemo-status-proc-diagnostic": lambda: _sortdemo_status_lane(args, per_function_proc=True),
    }
    results = [lane_fns[name]() for name in lane_names]
    summary = {
        "schema": "inertia.test_pipeline.v1",
        "selected": len(results),
        "passed": sum(1 for item in results if item.status == LaneStatus.PASSED),
        "failed": sum(1 for item in results if item.status == LaneStatus.FAILED),
        "skipped": sum(1 for item in results if item.status == LaneStatus.SKIPPED),
        "timed_out": sum(1 for item in results if item.status == LaneStatus.TIMED_OUT),
        "results": [asdict(item) for item in results],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {key: summary[key] for key in ("selected", "passed", "failed", "skipped", "timed_out")},
            sort_keys=True,
        )
    )
    return 1 if summary["failed"] or summary["timed_out"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
