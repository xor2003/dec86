from angr_platforms.X86_16.exact_region_diagnostics import (
    build_exact_region_diagnostics_8616,
    classify_region_split_8616,
    format_exact_region_diagnostics_8616,
)


def test_exact_region_diagnostics_reports_split_entries_deterministically():
    diagnostics = build_exact_region_diagnostics_8616(
        "Proc",
        requested_start=0x1000,
        requested_end=0x1020,
        covered_block_addrs=(0x1010, 0x1004),
        cfg_functions={0x1010: object(), 0x1000: object(), 0x2000: object()},
        proc_identity="PROC:Proc",
    )

    assert diagnostics.split_detected is True
    assert diagnostics.actual_cfg_entries == (0x1000, 0x1010)
    assert diagnostics.covered_block_addrs == (0x1004, 0x1010)

    payload = diagnostics.to_dict()
    assert payload["requested_start"] == "0x1000"
    assert payload["actual_cfg_entries"] == ["0x1000", "0x1010"]

    split = classify_region_split_8616(diagnostics)
    assert split.is_split is True
    assert split.entries == (0x1000, 0x1010)

    formatted = format_exact_region_diagnostics_8616(diagnostics)
    assert "SPLIT entries=[0x1000,0x1010]" in formatted


def test_exact_region_diagnostics_keeps_single_entry_as_non_split():
    diagnostics = build_exact_region_diagnostics_8616(
        "Leaf",
        requested_start=0x2000,
        requested_end=0x2010,
        covered_block_addrs=(0x2002,),
        cfg_functions={0x2000: object()},
    )

    split = classify_region_split_8616(diagnostics)

    assert diagnostics.split_detected is False
    assert split.is_split is False
    assert split.entries == (0x2000,)
    assert format_exact_region_diagnostics_8616(diagnostics).endswith("ok")
