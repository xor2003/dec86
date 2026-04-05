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
from .cod_known_objects import describe_x86_16_cod_known_objects
from .correctness_goals import describe_x86_16_correctness_goals, summarize_x86_16_correctness_goals
from .decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules
from .recovery_confidence import describe_x86_16_recovery_confidence_axes
from .instruction import describe_x86_16_instruction_metadata_surface
from .readability_goals import (
    describe_x86_16_readability_goals,
    summarize_readability_focus,
    summarize_readability_goals,
)
from .recovery_manifest import describe_x86_16_object_recovery_focus
from .recovery_manifest import describe_x86_16_recovery_layers
from .readability_set import describe_x86_16_golden_readability_set, summarize_x86_16_golden_readability_set
from .validation_manifest import (
    describe_x86_16_validation_triage,
    describe_x86_16_validation_families,
    describe_x86_16_validation_layers,
)
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


def _build_corpus_completion_surface(
    scan_summary: Mapping[str, object],
    *,
    readability_tiers: Mapping[str, int],
    timeout_stage_counts: Mapping[str, int],
    top_fallback_files: list[dict[str, object]],
    top_fallback_functions: list[dict[str, object]],
    top_ugly_clusters: list[dict[str, object]],
    readability_clusters: list[dict[str, object]],
    family_ownership: Mapping[str, object],
    readability_focus: Mapping[str, object],
) -> dict[str, object]:
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
    rewrite_failure_count = int(scan_summary.get("rewrite_failure_count", 0) or 0)
    structuring_failure_count = int(scan_summary.get("structuring_failure_count", 0) or 0)
    regeneration_failure_count = int(scan_summary.get("regeneration_failure_count", 0) or 0)
    confidence = dict(scan_summary.get("confidence", {}) or {})
    confidence_status_counts = dict(scan_summary.get("confidence_status_counts", {}) or {})
    confidence_scan_safe_counts = dict(scan_summary.get("confidence_scan_safe_counts", {}) or {})
    confidence_assumption_counts = dict(scan_summary.get("confidence_assumption_counts", {}) or {})
    confidence_evidence_counts = dict(scan_summary.get("confidence_evidence_counts", {}) or {})
    confidence_diagnostic_counts = dict(scan_summary.get("confidence_diagnostic_counts", {}) or {})
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
        "postprocess_failures": {
            "rewrite_failure_count": rewrite_failure_count,
            "structuring_failure_count": structuring_failure_count,
            "regeneration_failure_count": regeneration_failure_count,
        },
        "confidence": confidence,
        "confidence_status_counts": confidence_status_counts,
        "confidence_scan_safe_counts": confidence_scan_safe_counts,
        "confidence_assumption_counts": confidence_assumption_counts,
        "confidence_evidence_counts": confidence_evidence_counts,
        "confidence_diagnostic_counts": confidence_diagnostic_counts,
        "blind_spot_budget": blind_spot_budget,
        "stable_by_traversal": failed == 0 and unclassified_failure_count == 0,
        "merge_gate": failed == 0 and unclassified_failure_count == 0,
        "readability_tiers": dict(readability_tiers),
        "timeout_stage_counts": timeout_stage_counts,
        "fallback_backlog": {
            "top_fallback_files": top_fallback_files,
            "top_fallback_functions": top_fallback_functions,
        },
        "readability_backlog": {
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
        "readability_focus": {
            "goal_queue": [
                {
                    "step": item["step"],
                    "title": item["title"],
                    "priority": item["priority"],
                    "deterministic_goal": item["deterministic_goal"],
                    "target_clusters": list(item["target_clusters"]),
                    "owner_surfaces": list(item["owner_surfaces"]),
                    "completion_signal": item["completion_signal"],
                    "observed_cluster_count": item["observed_cluster_count"],
                    "observed_family_count": item["observed_family_count"],
                    "rank": item["rank"],
                    "is_next_focus": item["is_next_focus"],
                }
                for item in readability_focus["goal_queue"]
            ],
            "next_goal": None
            if readability_focus.get("next_goal") is None
            else {
                "step": readability_focus["next_goal"]["step"],
                "title": readability_focus["next_goal"]["title"],
                "priority": readability_focus["next_goal"]["priority"],
                "deterministic_goal": readability_focus["next_goal"]["deterministic_goal"],
                "target_clusters": list(readability_focus["next_goal"]["target_clusters"]),
                "owner_surfaces": list(readability_focus["next_goal"]["owner_surfaces"]),
                "completion_signal": readability_focus["next_goal"]["completion_signal"],
                "observed_cluster_count": readability_focus["next_goal"]["observed_cluster_count"],
                "observed_family_count": readability_focus["next_goal"]["observed_family_count"],
                "rank": readability_focus["next_goal"]["rank"],
                "is_next_focus": readability_focus["next_goal"]["is_next_focus"],
            },
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
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
    validation_triage = describe_x86_16_validation_triage()
    readability_set = describe_x86_16_golden_readability_set()
    correctness_goals = describe_x86_16_correctness_goals()
    alias_api = describe_x86_16_alias_recovery_api()
    widening_pipeline = describe_x86_16_widening_pipeline()
    recovery_layers = describe_x86_16_recovery_layers()
    object_recovery_focus = describe_x86_16_object_recovery_focus()
    recovery_confidence_axes = describe_x86_16_recovery_confidence_axes()
    projection_cleanup_rules = describe_x86_16_projection_cleanup_rules()
    readability_goals = describe_x86_16_readability_goals()
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
    timeout_stage_counts = dict(scan_summary.get("timeout_stage_counts", {}) or {})
    top_failure_files = list(scan_summary.get("top_failure_files", []) or [])
    top_failure_functions = list(scan_summary.get("top_failure_functions", []) or [])
    top_fallback_files = list(scan_summary.get("top_fallback_files", []) or [])
    top_fallback_functions = list(scan_summary.get("top_fallback_functions", []) or [])
    blind_spot_budget = dict(scan_summary.get("blind_spot_budget", {}) or {})
    debt = dict(scan_summary.get("debt", {}) or {})
    visibility_debt = int(scan_summary.get("visibility_debt", debt.get("traversal", 0)) or 0)
    recovery_debt = int(scan_summary.get("recovery_debt", debt.get("recovery", 0)) or 0)
    readability_debt = int(scan_summary.get("readability_debt", debt.get("readability", 0)) or 0)
    rewrite_failure_count = int(scan_summary.get("rewrite_failure_count", 0) or 0)
    structuring_failure_count = int(scan_summary.get("structuring_failure_count", 0) or 0)
    regeneration_failure_count = int(scan_summary.get("regeneration_failure_count", 0) or 0)
    confidence = dict(scan_summary.get("confidence", {}) or {})
    confidence_status_counts = dict(scan_summary.get("confidence_status_counts", {}) or {})
    confidence_scan_safe_counts = dict(scan_summary.get("confidence_scan_safe_counts", {}) or {})
    confidence_assumption_counts = dict(scan_summary.get("confidence_assumption_counts", {}) or {})
    confidence_evidence_counts = dict(scan_summary.get("confidence_evidence_counts", {}) or {})
    confidence_diagnostic_counts = dict(scan_summary.get("confidence_diagnostic_counts", {}) or {})
    top_ugly_clusters = list(scan_summary.get("top_ugly_clusters", []) or [])
    readability_clusters = list(scan_summary.get("readability_clusters", []) or [])
    family_ownership = dict(scan_summary.get("family_ownership", {}) or {})
    interrupt_api = dict(scan_summary.get("interrupt_api", {}) or {})
    scan_results = list(scan_summary.get("results", []) or [])
    golden_cases = {(case.source, case.proc_name) for case in readability_set}
    readability_tier_counts = {"R0": 0, "R1": 0, "R2": 0, "R3": 0}
    for result in scan_results:
        readability_tier_counts[_readability_tier(result, golden_cases)] += 1
    source_backed_rewrites = describe_x86_16_source_backed_rewrite_status()
    source_backed_rewrite_debt = describe_x86_16_source_backed_rewrite_debt()
    cod_known_objects = describe_x86_16_cod_known_objects()
    correctness_goal_summary = summarize_x86_16_correctness_goals()
    readability_focus = summarize_readability_focus(top_ugly_clusters, readability_clusters, family_ownership)
    corpus_completion = _build_corpus_completion_surface(
        scan_summary,
        readability_tiers=readability_tier_counts,
        timeout_stage_counts=timeout_stage_counts,
        top_fallback_files=top_fallback_files,
        top_fallback_functions=top_fallback_functions,
        top_ugly_clusters=top_ugly_clusters,
        readability_clusters=readability_clusters,
        family_ownership=family_ownership,
        readability_focus=readability_focus,
    )
    readability_goal_summary = summarize_readability_goals(top_ugly_clusters, readability_clusters, family_ownership)

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
        "validation_triage": validation_triage,
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
        "recovery_confidence_axes": [
            {"status": status, "meaning": meaning}
            for status, meaning in recovery_confidence_axes
        ],
        "object_recovery_focus": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in object_recovery_focus
        ],
        "projection_cleanup_rules": [
            {"name": name, "purpose": purpose}
            for name, purpose in projection_cleanup_rules
        ],
        "readability_goals": [
            {
                "step": step,
                "title": title,
                "deterministic_goal": deterministic_goal,
                "target_clusters": list(target_clusters),
                "owner_surfaces": list(owner_surfaces),
                "completion_signal": completion_signal,
            }
            for step, title, deterministic_goal, target_clusters, owner_surfaces, completion_signal in readability_goals
        ],
        "readability_set_summary": [
            {"source": source, "proc_name": proc_name, "anchor_count": anchor_count}
            for source, proc_name, anchor_count in summarize_x86_16_golden_readability_set()
        ],
        "readability_set": [asdict(case) for case in readability_set],
        "correctness_goals": [
            {
                "code": code,
                "title": title,
                "priority": priority,
                "status": status,
                "owner_surfaces": list(owner_surfaces),
                "completion_signal": completion_signal,
            }
            for code, title, priority, status, owner_surfaces, completion_signal in correctness_goals
        ],
        "correctness_goal_summary": correctness_goal_summary,
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
        "postprocess_failures": {
            "rewrite_failure_count": rewrite_failure_count,
            "structuring_failure_count": structuring_failure_count,
            "regeneration_failure_count": regeneration_failure_count,
        },
        "confidence": confidence,
        "confidence_status_counts": confidence_status_counts,
        "confidence_scan_safe_counts": confidence_scan_safe_counts,
        "confidence_assumption_counts": confidence_assumption_counts,
        "confidence_evidence_counts": confidence_evidence_counts,
        "confidence_diagnostic_counts": confidence_diagnostic_counts,
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
        "readability_goal_summary": [
            {
                "step": item["step"],
                "title": item["title"],
                "priority": item["priority"],
                "deterministic_goal": item["deterministic_goal"],
                "target_clusters": list(item["target_clusters"]),
                "owner_surfaces": list(item["owner_surfaces"]),
                "completion_signal": item["completion_signal"],
                "observed_cluster_count": item["observed_cluster_count"],
                "observed_family_count": item["observed_family_count"],
            }
            for item in readability_goal_summary
        ],
        "readability_goal_queue": [
            {
                "step": item["step"],
                "title": item["title"],
                "priority": item["priority"],
                "deterministic_goal": item["deterministic_goal"],
                "target_clusters": list(item["target_clusters"]),
                "owner_surfaces": list(item["owner_surfaces"]),
                "completion_signal": item["completion_signal"],
                "observed_cluster_count": item["observed_cluster_count"],
                "observed_family_count": item["observed_family_count"],
                "rank": item["rank"],
                "is_next_focus": item["is_next_focus"],
            }
            for item in readability_focus["goal_queue"]
        ],
        "readability_focus": {
            "next_goal": None
            if readability_focus.get("next_goal") is None
            else {
                "step": readability_focus["next_goal"]["step"],
                "title": readability_focus["next_goal"]["title"],
                "priority": readability_focus["next_goal"]["priority"],
                "deterministic_goal": readability_focus["next_goal"]["deterministic_goal"],
                "target_clusters": list(readability_focus["next_goal"]["target_clusters"]),
                "owner_surfaces": list(readability_focus["next_goal"]["owner_surfaces"]),
                "completion_signal": readability_focus["next_goal"]["completion_signal"],
                "observed_cluster_count": readability_focus["next_goal"]["observed_cluster_count"],
                "observed_family_count": readability_focus["next_goal"]["observed_family_count"],
                "rank": readability_focus["next_goal"]["rank"],
                "is_next_focus": readability_focus["next_goal"]["is_next_focus"],
            },
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
        "hotspots": {
            "failure_counts": failure_counts,
            "fallback_counts": fallback_counts,
            "top_failure_classes": top_failure_classes,
            "top_fallback_kinds": top_fallback_kinds,
        "top_failure_stages": top_failure_stages,
        "timeout_stage_counts": timeout_stage_counts,
        "top_failure_files": top_failure_files,
            "top_failure_functions": top_failure_functions,
            "top_fallback_files": top_fallback_files,
            "top_fallback_functions": top_fallback_functions,
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
        "source_backed_rewrites": source_backed_rewrites,
        "source_backed_rewrite_debt": source_backed_rewrite_debt,
        "cod_known_objects": cod_known_objects,
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
