from angr_platforms.X86_16.recovery_confidence import (
    classify_x86_16_recovery_confidence,
    summarize_recovery_confidence,
)


def test_recovery_confidence_attaches_helper_summary_and_refusal_assumption():
    summary = classify_x86_16_recovery_confidence(
        {
            "ok": True,
            "decompiled_count": 1,
            "interrupt_wrapper_call_count": 1,
            "interrupt_dos_helper_count": 0,
            "interrupt_bios_helper_count": 0,
            "direct_call_count": 2,
            "return_kind": "scalar",
        }
    )

    assert summary.helper_summary is not None
    assert summary.helper_summary.status == "refused"
    assert any(item.kind == "helper_shape_refused" for item in summary.assumptions)
    assert any(item.startswith("helper_summary=") for item in summary.diagnostics)


def test_recovery_confidence_summary_accumulates_helper_counts():
    counts = summarize_recovery_confidence(
        [
            {
                "ok": True,
                "decompiled_count": 1,
                "direct_call_count": 1,
                "return_kind": "scalar",
            },
            {
                "ok": True,
                "decompiled_count": 1,
                "direct_call_count": 2,
                "return_kind": "scalar",
            },
        ]
    )

    assert counts["helper_status_counts"] == {"eligible": 1, "refused": 1}
    assert counts["helper_candidate_counts"] == {"single_direct_call_wrapper": 1}
    assert counts["helper_refusal_counts"] == {"call_count_not_single": 1}
    assert counts["helper_family_rows"] == [
        {
            "family": "helper_wrapper_candidate",
            "count": 1,
            "likely_layer": "helper_modeling",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
            "signal": "eligible",
        },
        {
            "family": "helper_wrapper_signature_shape",
            "count": 1,
            "likely_layer": "helper_modeling",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
            "signal": "call_count_not_single",
        },
    ]
