from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Mapping, Sequence

from .alias_model import describe_x86_16_alias_recovery_api
from .cod_source_rewrites import describe_x86_16_source_backed_rewrite_status
from .recovery_manifest import describe_x86_16_recovery_layers
from .readability_set import describe_x86_16_golden_readability_set, summarize_x86_16_golden_readability_set
from .validation_manifest import describe_x86_16_validation_layers
from .widening_model import describe_x86_16_widening_pipeline


@dataclass(frozen=True)
class MilestoneReportSection:
    name: str
    summary: Mapping[str, object]


def _success_rate(summary: Mapping[str, object]) -> float:
    scanned = int(summary.get("scanned", 0) or 0)
    ok = int(summary.get("ok", 0) or 0)
    if scanned <= 0:
        return 0.0
    return round(ok / scanned, 6)


def _readability_tier(result: Mapping[str, object], golden_cases: set[tuple[str, str]]) -> str:
    if not bool(result.get("ok", False)):
        return "R0"
    fallback_kind = result.get("fallback_kind")
    if fallback_kind not in (None, "none"):
        return "R1"
    if int(result.get("decompiled_count", 0) or 0) <= 0:
        return "R1"
    golden_key = (str(result.get("cod_file", "")), str(result.get("proc_name", "")))
    if golden_key in golden_cases:
        return "R3"
    return "R2"


def build_x86_16_milestone_report(
    scan_summary: Mapping[str, object],
    *,
    corpus_name: str = "x86-16",
    corpus_slice: str | None = None,
    blocked_mnemonics: Sequence[str] | None = None,
) -> dict[str, object]:
    validation_layers = describe_x86_16_validation_layers()
    readability_set = describe_x86_16_golden_readability_set()
    alias_api = describe_x86_16_alias_recovery_api()
    widening_pipeline = describe_x86_16_widening_pipeline()
    recovery_layers = describe_x86_16_recovery_layers()
    failure_counts = dict(scan_summary.get("failure_counts", {}) or {})
    fallback_counts = dict(scan_summary.get("fallback_counts", {}) or {})
    top_failure_classes = list(scan_summary.get("top_failure_classes", []) or [])
    top_fallback_kinds = list(scan_summary.get("top_fallback_kinds", []) or [])
    top_failure_stages = list(scan_summary.get("top_failure_stages", []) or [])
    top_failure_files = list(scan_summary.get("top_failure_files", []) or [])
    top_failure_functions = list(scan_summary.get("top_failure_functions", []) or [])
    top_fallback_files = list(scan_summary.get("top_fallback_files", []) or [])
    top_fallback_functions = list(scan_summary.get("top_fallback_functions", []) or [])
    blind_spot_budget = dict(scan_summary.get("blind_spot_budget", {}) or {})
    debt = dict(scan_summary.get("debt", {}) or {})
    top_ugly_clusters = list(scan_summary.get("top_ugly_clusters", []) or [])
    scan_results = list(scan_summary.get("results", []) or [])
    golden_cases = {(case.source, case.proc_name) for case in readability_set}
    readability_tier_counts = {"R0": 0, "R1": 0, "R2": 0, "R3": 0}
    for result in scan_results:
        readability_tier_counts[_readability_tier(result, golden_cases)] += 1
    source_backed_rewrites = describe_x86_16_source_backed_rewrite_status()

    report = {
        "corpus": corpus_name,
        "corpus_slice": corpus_slice or scan_summary.get("slice", "active"),
        "scan_summary": dict(scan_summary),
        "validation_layers": [
            {"name": name, "default_checks": list(checks)} for name, checks in validation_layers
        ],
        "alias_api": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in alias_api
        ],
        "widening_pipeline": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in widening_pipeline
        ],
        "recovery_layers": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in recovery_layers
        ],
        "readability_set_summary": [
            {"source": source, "proc_name": proc_name, "anchor_count": anchor_count}
            for source, proc_name, anchor_count in summarize_x86_16_golden_readability_set()
        ],
        "readability_set": [asdict(case) for case in readability_set],
        "blocked_mnemonics": list(blocked_mnemonics or ()),
        "corpus_rates": {
            "success_rate": _success_rate(scan_summary),
            "failure_rate": round(1.0 - _success_rate(scan_summary), 6),
            "full_decompile_rate": round(int(scan_summary.get("full_decompile_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
            "cfg_only_rate": round(int(scan_summary.get("cfg_only_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
            "lift_only_rate": round(int(scan_summary.get("lift_only_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
            "block_lift_rate": round(int(scan_summary.get("block_lift_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
        },
        "blind_spot_budget": blind_spot_budget,
        "debt": debt,
        "readability_tiers": readability_tier_counts,
        "hotspots": {
            "failure_counts": failure_counts,
            "fallback_counts": fallback_counts,
            "top_failure_classes": top_failure_classes,
            "top_fallback_kinds": top_fallback_kinds,
            "top_failure_stages": top_failure_stages,
            "top_failure_files": top_failure_files,
            "top_failure_functions": top_failure_functions,
            "top_fallback_files": top_fallback_files,
            "top_fallback_functions": top_fallback_functions,
            "top_ugly_clusters": top_ugly_clusters,
        },
        "source_backed_rewrites": source_backed_rewrites,
    }
    return report


def write_x86_16_milestone_report(
    output_path: str | Path,
    scan_summary: Mapping[str, object],
    *,
    corpus_name: str = "x86-16",
    corpus_slice: str | None = None,
    blocked_mnemonics: Sequence[str] | None = None,
) -> Path:
    path = Path(output_path)
    path.write_text(
        json.dumps(
            build_x86_16_milestone_report(
                scan_summary,
                corpus_name=corpus_name,
                corpus_slice=corpus_slice,
                blocked_mnemonics=blocked_mnemonics,
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return path


__all__ = [
    "MilestoneReportSection",
    "build_x86_16_milestone_report",
    "write_x86_16_milestone_report",
]
