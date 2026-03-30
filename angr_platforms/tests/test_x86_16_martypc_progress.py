from angr_platforms.X86_16.martypc_progress import (
    describe_x86_16_martypc_improvement_progress,
    summarize_x86_16_martypc_improvement_progress,
)


def test_x86_16_martypc_progress_surface_is_deterministic():
    progress = describe_x86_16_martypc_improvement_progress()

    assert len(progress) == 13
    assert progress[0][0] == "P0.1"
    assert progress[0][3] == "landed"
    assert progress[6][0] == "P1.2"
    assert progress[6][3] == "landed"
    assert progress[9][0] == "P2.2"
    assert progress[9][3] == "landed"


def test_x86_16_martypc_progress_summary_reports_completion_percentages():
    summary = summarize_x86_16_martypc_improvement_progress()

    assert summary["total"] == 13
    assert summary["landed"] == 13
    assert summary["partial"] == 0
    assert summary["open"] == 0
    assert summary["strict_percent"] == 100.0
    assert summary["weighted_percent"] == 100.0
    assert summary["landed_codes"] == (
        "P0.1",
        "P0.2",
        "P0.3",
        "P0.4",
            "P0.5",
            "P1.1",
            "P1.2",
            "P1.3",
            "P2.1",
            "P2.2",
            "P2.3",
            "P3.1",
            "P3.2",
        )
    assert summary["partial_codes"] == ()
    assert summary["open_codes"] == ()
