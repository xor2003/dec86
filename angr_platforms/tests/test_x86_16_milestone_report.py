from angr_platforms.X86_16.milestone_report import build_x86_16_milestone_report


def test_x86_16_milestone_report_combines_scan_and_quality_context():
    scan_summary = {
        "mode": "scan-safe",
        "scanned": 10,
        "ok": 7,
        "failed": 3,
        "failure_counts": {"cfg_failure": 2, "lift_failure": 1},
        "fallback_counts": {"cfg_only": 2, "block_lift": 1},
        "top_failure_classes": [{"failure_class": "cfg_failure", "count": 2}],
        "top_fallback_kinds": [{"fallback_kind": "cfg_only", "count": 2}],
        "top_failure_stages": [{"stage": "cfg", "count": 2}],
        "top_failure_files": [{"cod_file": "A.COD", "count": 2}],
        "top_failure_functions": [{"cod_file": "A.COD", "proc_name": "_x", "proc_kind": "NEAR", "failure_class": "cfg_failure", "count": 2}],
        "top_fallback_files": [{"cod_file": "A.COD", "count": 2}],
        "top_fallback_functions": [{"cod_file": "A.COD", "proc_name": "_x", "proc_kind": "NEAR", "fallback_kind": "cfg_only", "count": 2}],
        "full_decompile_count": 7,
        "cfg_only_count": 2,
        "lift_only_count": 0,
        "block_lift_count": 1,
        "blind_spot_budget": {
            "full_decompile_rate": 0.7,
            "cfg_only_rate": 0.2,
            "lift_only_rate": 0.0,
            "block_lift_rate": 0.1,
            "true_failure_rate": 0.3,
        },
        "debt": {"traversal": 3, "recovery": 2, "readability": 7},
        "interrupt_api": {
            "dos_helpers": 4,
            "bios_helpers": 2,
            "wrapper_calls": 6,
            "unresolved_wrappers": 1,
        },
        "results": [
            {
                "cod_file": "cod/f14/MONOPRIN.COD",
                "proc_name": "_mset_pos",
                "proc_kind": "NEAR",
                "ok": True,
                "decompiled_count": 1,
                "fallback_kind": None,
            },
            {
                "cod_file": "cod/f14/OTHER.COD",
                "proc_name": "_other",
                "proc_kind": "NEAR",
                "ok": True,
                "decompiled_count": 1,
                "fallback_kind": None,
            },
            {
                "cod_file": "cod/f14/MAX.COD",
                "proc_name": "_max",
                "proc_kind": "NEAR",
                "ok": True,
                "decompiled_count": 0,
                "fallback_kind": "cfg_only",
            },
            {
                "cod_file": "cod/f14/BROKEN.COD",
                "proc_name": "_broken",
                "proc_kind": "NEAR",
                "ok": False,
                "decompiled_count": 0,
                "fallback_kind": "block_lift",
            },
        ],
        "top_ugly_clusters": [{"cluster": "byte_pair_arithmetic", "count": 4}],
    }

    report = build_x86_16_milestone_report(scan_summary, corpus_slice="active-corpus")

    assert report["corpus"] == "x86-16"
    assert report["corpus_slice"] == "active-corpus"
    assert report["scan_summary"]["failed"] == 3
    assert report["corpus_rates"] == {
        "success_rate": 0.7,
        "failure_rate": 0.3,
        "full_decompile_rate": 0.7,
        "cfg_only_rate": 0.2,
        "lift_only_rate": 0.0,
        "block_lift_rate": 0.1,
    }
    assert report["blind_spot_budget"] == scan_summary["blind_spot_budget"]
    assert report["debt"] == scan_summary["debt"]
    assert report["debt_breakdown"] == {
        "visibility": 3,
        "recovery": 2,
        "readability": 7,
    }
    assert report["interrupt_api"] == {
        "dos_helpers": 4,
        "bios_helpers": 2,
        "wrapper_calls": 6,
        "unresolved_wrappers": 1,
    }
    assert report["readability_tiers"] == {"R0": 1, "R1": 1, "R2": 1, "R3": 1}
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
    assert report["hotspots"]["fallback_counts"] == {"block_lift": 1, "cfg_only": 2}
    assert report["hotspots"]["top_fallback_kinds"][0]["fallback_kind"] == "cfg_only"
    assert report["hotspots"]["top_ugly_clusters"] == [{"cluster": "byte_pair_arithmetic", "count": 4}]
    assert report["readability_set_summary"][0] == {
        "source": "cod/f14/MONOPRIN.COD",
        "proc_name": "_mset_pos",
        "anchor_count": 5,
    }
    assert len(report["readability_set"]) >= 4
    assert report["hotspots"]["top_failure_classes"][0]["failure_class"] == "cfg_failure"
