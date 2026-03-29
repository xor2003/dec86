from angr_platforms.X86_16.milestone_report import build_x86_16_milestone_report


def test_x86_16_milestone_report_combines_scan_and_quality_context():
    scan_summary = {
        "mode": "scan-safe",
        "scanned": 10,
        "ok": 7,
        "failed": 3,
        "failure_counts": {"cfg_failure": 2, "lift_failure": 1},
        "top_failure_classes": [{"failure_class": "cfg_failure", "count": 2}],
        "top_failure_stages": [{"stage": "cfg", "count": 2}],
        "top_failure_files": [{"cod_file": "A.COD", "count": 2}],
        "top_failure_functions": [{"cod_file": "A.COD", "proc_name": "_x", "proc_kind": "NEAR", "failure_class": "cfg_failure", "count": 2}],
    }

    report = build_x86_16_milestone_report(scan_summary, corpus_slice="active-corpus")

    assert report["corpus"] == "x86-16"
    assert report["corpus_slice"] == "active-corpus"
    assert report["scan_summary"]["failed"] == 3
    assert report["corpus_rates"] == {"success_rate": 0.7, "failure_rate": 0.3}
    assert [layer["name"] for layer in report["validation_layers"]] == ["unit", "focused_corpus", "whole_program"]
    assert [item["name"] for item in report["alias_api"]] == ["same_domain", "compatible_view", "needs_synthesis", "can_join"]
    assert [item["name"] for item in report["widening_pipeline"]] == [
        "candidate_extraction",
        "compatibility_proof",
        "join_decision",
    ]
    assert [item["name"] for item in report["recovery_layers"]] == [
        "segmented_memory_association",
        "member_and_array_recovery",
        "stable_stack_object_recovery",
        "stable_global_object_recovery",
        "store_side_widening",
        "segment_aware_object_roots",
        "trait_to_type_handoff",
        "prototype_evidence_layer",
        "far_near_prototype_recovery",
        "thin_late_rewrite_boundary",
    ]
    assert report["source_backed_rewrites"]["count"] >= 6
    assert report["readability_set_summary"][0] == {
        "source": "cod/f14/MONOPRIN.COD",
        "proc_name": "_mset_pos",
        "anchor_count": 5,
    }
    assert len(report["readability_set"]) >= 4
    assert report["hotspots"]["top_failure_classes"][0]["failure_class"] == "cfg_failure"
