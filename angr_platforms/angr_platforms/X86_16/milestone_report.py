from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Mapping, Sequence

from .alias_model import describe_x86_16_alias_recovery_api
from .addressing_helpers import (
    describe_x86_16_decode_width_matrix,
    describe_x86_16_mixed_width_extension_surface,
    describe_x86_16_mixed_width_instruction_surface,
)
from .analysis_helpers import (
    describe_x86_16_interrupt_api_surface,
    describe_x86_16_interrupt_core_surface,
    describe_x86_16_interrupt_lowering_boundary,
)
from .cod_source_rewrites import (
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
)
from .decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules
from .instruction import describe_x86_16_instruction_metadata_surface
from .recovery_manifest import describe_x86_16_recovery_layers
from .readability_set import describe_x86_16_golden_readability_set, summarize_x86_16_golden_readability_set
from .validation_manifest import describe_x86_16_validation_families, describe_x86_16_validation_layers
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


def _build_corpus_completion_surface(scan_summary: Mapping[str, object]) -> dict[str, object]:
    scanned = int(scan_summary.get("scanned", 0) or 0)
    failed = int(scan_summary.get("failed", 0) or 0)
    full_decompile_count = int(scan_summary.get("full_decompile_count", 0) or 0)
    cfg_only_count = int(scan_summary.get("cfg_only_count", 0) or 0)
    lift_only_count = int(scan_summary.get("lift_only_count", 0) or 0)
    block_lift_count = int(scan_summary.get("block_lift_count", 0) or 0)
    debt = dict(scan_summary.get("debt", {}) or {})
    visibility_debt = int(scan_summary.get("visibility_debt", debt.get("traversal", 0)) or 0)
    recovery_debt = int(scan_summary.get("recovery_debt", debt.get("recovery", 0)) or 0)
    readability_debt = int(scan_summary.get("readability_debt", debt.get("readability", 0)) or 0)
    unclassified_failure_count = int(scan_summary.get("unclassified_failure_count", 0) or 0)
    blind_spot_budget = dict(scan_summary.get("blind_spot_budget", {}) or {})
    return {
        "no_crashes": failed == 0,
        "no_blind_spots": unclassified_failure_count == 0,
        "unclassified_failure_count": unclassified_failure_count,
        "scanned": scanned,
        "fallback_coverage": {
            "full_decompile_count": full_decompile_count,
            "cfg_only_count": cfg_only_count,
            "lift_only_count": lift_only_count,
            "block_lift_count": block_lift_count,
        },
        "debt": {
            "visibility": visibility_debt,
            "recovery": recovery_debt,
            "readability": readability_debt,
        },
        "blind_spot_budget": blind_spot_budget,
        "stable_by_traversal": failed == 0 and unclassified_failure_count == 0,
    }


def build_x86_16_milestone_report(
    scan_summary: Mapping[str, object],
    *,
    corpus_name: str = "x86-16",
    corpus_slice: str | None = None,
    blocked_mnemonics: Sequence[str] | None = None,
) -> dict[str, object]:
    validation_layers = describe_x86_16_validation_layers()
    validation_families = describe_x86_16_validation_families()
    readability_set = describe_x86_16_golden_readability_set()
    alias_api = describe_x86_16_alias_recovery_api()
    widening_pipeline = describe_x86_16_widening_pipeline()
    recovery_layers = describe_x86_16_recovery_layers()
    projection_cleanup_rules = describe_x86_16_projection_cleanup_rules()
    decode_width_matrix = describe_x86_16_decode_width_matrix()
    mixed_width_extension_surface = describe_x86_16_mixed_width_extension_surface()
    mixed_width_instruction_surface = describe_x86_16_mixed_width_instruction_surface()
    interrupt_api_surface = describe_x86_16_interrupt_api_surface()
    interrupt_core_surface = describe_x86_16_interrupt_core_surface()
    interrupt_lowering_boundary = describe_x86_16_interrupt_lowering_boundary()
    instruction_metadata_surface = describe_x86_16_instruction_metadata_surface()
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
    visibility_debt = int(scan_summary.get("visibility_debt", debt.get("traversal", 0)) or 0)
    recovery_debt = int(scan_summary.get("recovery_debt", debt.get("recovery", 0)) or 0)
    readability_debt = int(scan_summary.get("readability_debt", debt.get("readability", 0)) or 0)
    top_ugly_clusters = list(scan_summary.get("top_ugly_clusters", []) or [])
    family_ownership = dict(scan_summary.get("family_ownership", {}) or {})
    interrupt_api = dict(scan_summary.get("interrupt_api", {}) or {})
    scan_results = list(scan_summary.get("results", []) or [])
    golden_cases = {(case.source, case.proc_name) for case in readability_set}
    readability_tier_counts = {"R0": 0, "R1": 0, "R2": 0, "R3": 0}
    for result in scan_results:
        readability_tier_counts[_readability_tier(result, golden_cases)] += 1
    source_backed_rewrites = describe_x86_16_source_backed_rewrite_status()
    source_backed_rewrite_debt = describe_x86_16_source_backed_rewrite_debt()
    corpus_completion = _build_corpus_completion_surface(scan_summary)

    report = {
        "corpus": corpus_name,
        "corpus_slice": corpus_slice or scan_summary.get("slice", "active"),
        "scan_summary": dict(scan_summary),
        "validation_layers": [
            {"name": name, "default_checks": list(checks)} for name, checks in validation_layers
        ],
        "validation_families": [
            {"name": name, "default_checks": list(checks)} for name, checks in validation_families
        ],
        "alias_api": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in alias_api
        ],
        "decode_width_matrix": [
            {"name": name, "operand_bits": operand_bits, "address_bits": address_bits}
            for name, operand_bits, address_bits in decode_width_matrix
        ],
        "mixed_width_extension_surface": mixed_width_extension_surface,
        "mixed_width_instruction_surface": mixed_width_instruction_surface,
        "widening_pipeline": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in widening_pipeline
        ],
        "recovery_layers": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in recovery_layers
        ],
        "projection_cleanup_rules": [
            {"name": name, "purpose": purpose}
            for name, purpose in projection_cleanup_rules
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
        "debt_breakdown": {
            "visibility": visibility_debt,
            "recovery": recovery_debt,
            "readability": readability_debt,
        },
        "interrupt_api": {
            "dos_helpers": int(interrupt_api.get("dos_helpers", 0) or 0),
            "bios_helpers": int(interrupt_api.get("bios_helpers", 0) or 0),
            "wrapper_calls": int(interrupt_api.get("wrapper_calls", 0) or 0),
            "unresolved_wrappers": int(interrupt_api.get("unresolved_wrappers", 0) or 0),
        },
        "interrupt_api_surface": interrupt_api_surface,
        "interrupt_core_surface": interrupt_core_surface,
        "interrupt_lowering_boundary": interrupt_lowering_boundary,
        "instruction_metadata_surface": instruction_metadata_surface,
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
            "family_ownership": family_ownership,
        },
        "source_backed_rewrites": source_backed_rewrites,
        "source_backed_rewrite_debt": source_backed_rewrite_debt,
        "corpus_completion": corpus_completion,
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
