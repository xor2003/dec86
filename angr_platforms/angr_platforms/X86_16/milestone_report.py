from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Mapping, Sequence

from .readability_set import describe_x86_16_golden_readability_set
from .validation_manifest import describe_x86_16_validation_layers


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


def build_x86_16_milestone_report(
    scan_summary: Mapping[str, object],
    *,
    corpus_name: str = "x86-16",
    corpus_slice: str | None = None,
    blocked_mnemonics: Sequence[str] | None = None,
) -> dict[str, object]:
    validation_layers = describe_x86_16_validation_layers()
    readability_set = describe_x86_16_golden_readability_set()
    failure_counts = dict(scan_summary.get("failure_counts", {}) or {})
    top_failure_classes = list(scan_summary.get("top_failure_classes", []) or [])
    top_failure_stages = list(scan_summary.get("top_failure_stages", []) or [])
    top_failure_files = list(scan_summary.get("top_failure_files", []) or [])
    top_failure_functions = list(scan_summary.get("top_failure_functions", []) or [])

    report = {
        "corpus": corpus_name,
        "corpus_slice": corpus_slice or scan_summary.get("slice", "active"),
        "scan_summary": dict(scan_summary),
        "validation_layers": [
            {"name": name, "default_checks": list(checks)} for name, checks in validation_layers
        ],
        "readability_set": [asdict(case) for case in readability_set],
        "blocked_mnemonics": list(blocked_mnemonics or ()),
        "corpus_rates": {
            "success_rate": _success_rate(scan_summary),
            "failure_rate": round(1.0 - _success_rate(scan_summary), 6),
        },
        "hotspots": {
            "failure_counts": failure_counts,
            "top_failure_classes": top_failure_classes,
            "top_failure_stages": top_failure_stages,
            "top_failure_files": top_failure_files,
            "top_failure_functions": top_failure_functions,
        },
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
