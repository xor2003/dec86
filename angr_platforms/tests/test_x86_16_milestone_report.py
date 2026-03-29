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
    assert len(report["readability_set"]) >= 4
    assert report["hotspots"]["top_failure_classes"][0]["failure_class"] == "cfg_failure"
