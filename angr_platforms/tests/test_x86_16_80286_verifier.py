from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from angr_platforms.X86_16.coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES
from angr_platforms.X86_16.verification_80286 import (
    REPO_ROOT,
    load_moo_cases,
    summarize_results,
    summary_to_json,
    verify_case,
    verify_moo_file,
)
from scripts.verify_80286_real_mode import (
    _exclude_cached_passes,
    _exclude_compare_covered,
    _load_passed_cache,
    _sample_compare_covered,
    _update_passed_cache,
)


SUITE_DIR = REPO_ROOT / "80286" / "v1_real_mode"


def _moo(opcode: str) -> Path:
    return SUITE_DIR / f"{opcode}.MOO.gz"


def test_verify_80286_add_rm8_r8_case_passes():
    summary = verify_moo_file(_moo("00"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_pusha_case_passes():
    summary = verify_moo_file(_moo("60"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_pushf_case_passes():
    summary = verify_moo_file(_moo("9C"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_in_al_imm8_case_passes():
    summary = verify_moo_file(_moo("E4"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_in_al_dx_case_passes():
    summary = verify_moo_file(_moo("EC"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_rep_insb_case_passes():
    summary = verify_moo_file(_moo("6C"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_rep_insw_case_passes():
    summary = verify_moo_file(_moo("6D"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_case_checks_unchanged_registers_and_memory():
    _, cases = load_moo_cases(_moo("00"))
    result = verify_case(cases[0], opcode="00")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_xlat_case_passes():
    summary = verify_moo_file(_moo("D7"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_add_rm16_r16_case_passes():
    summary = verify_moo_file(_moo("01"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_adc_rm16_r16_case_passes():
    summary = verify_moo_file(_moo("11"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_sbb_rm8_r8_case_passes():
    summary = verify_moo_file(_moo("18"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_cwd_case_passes():
    summary = verify_moo_file(_moo("99"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_gp_faulting_memory_operand_case_passes():
    summary = verify_moo_file(_moo("D1.6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_jmp_short_case_passes():
    summary = verify_moo_file(_moo("EB"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_far_jmp_case_passes():
    summary = verify_moo_file(_moo("EA"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_int_case_passes():
    summary = verify_moo_file(_moo("CD"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_iret_case_passes():
    summary = verify_moo_file(_moo("CF"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_hlt_case_passes():
    summary = verify_moo_file(_moo("F4"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_far_indirect_call_case_passes():
    summary = verify_moo_file(_moo("FF.3"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_build_80286_verification_table_script(tmp_path):
    summary = summarize_results([verify_moo_file(_moo("00"), limit=1), verify_moo_file(_moo("60"), limit=1)])
    summary_json = tmp_path / "summary.json"
    summary_json.write_text(summary_to_json(summary) + "\n")
    output_md = tmp_path / "verification.md"

    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "angr_platforms" / "scripts" / "build_80286_real_mode_verification_table.py"),
            str(summary_json),
            "--output",
            str(output_md),
        ],
        check=True,
        cwd=REPO_ROOT / "angr_platforms",
    )

    text = output_md.read_text()
    assert "`00`" in text
    assert "`60`" in text
    assert "80286 Real-Mode Verification Table" in text


def test_compare_verified_manifest_covers_known_upstream_compare_cases():
    assert "AA" in COMPARE_VERIFIED_MOO_OPCODES
    assert "D3.4" in COMPARE_VERIFIED_MOO_OPCODES
    assert "F7.3" in COMPARE_VERIFIED_MOO_OPCODES


def test_exclude_compare_covered_filters_known_cases():
    kept, skipped = _exclude_compare_covered([_moo("AA"), _moo("00"), _moo("D3.4")])

    assert _moo("00") in kept
    assert _moo("AA") in skipped
    assert _moo("D3.4") in skipped


def test_sample_compare_covered_is_deterministic_for_day():
    files = [_moo("AA"), _moo("00"), _moo("D3.4"), _moo("F7.3")]

    kept_a, sampled_a, skipped_a = _sample_compare_covered(files, day_of_month=22)
    kept_b, sampled_b, skipped_b = _sample_compare_covered(files, day_of_month=22)

    assert kept_a == kept_b
    assert sampled_a == sampled_b
    assert skipped_a == skipped_b
    assert _moo("00") in kept_a
    assert set(sampled_a).issubset(set(kept_a))
    assert set(sampled_a).isdisjoint(set(skipped_a))


def test_sample_compare_covered_changes_with_day():
    files = [_moo("AA"), _moo("D3.4"), _moo("F7.3")]

    _, sampled_day_1, _ = _sample_compare_covered(files, day_of_month=1)
    _, sampled_day_2, _ = _sample_compare_covered(files, day_of_month=2)

    assert sampled_day_1 != sampled_day_2 or not sampled_day_1 or not sampled_day_2


def test_passed_cache_roundtrip_and_filtering(tmp_path):
    cache = tmp_path / "passed.txt"
    cache.write_text("00\nD3.4\n")

    loaded = _load_passed_cache(cache)
    kept, skipped = _exclude_cached_passes([_moo("00"), _moo("60"), _moo("D3.4")], loaded)

    assert loaded == {"00", "D3.4"}
    assert _moo("60") in kept
    assert _moo("00") in skipped
    assert _moo("D3.4") in skipped


def test_update_passed_cache_adds_new_passing_opcodes(tmp_path):
    cache = tmp_path / "passed.txt"
    cache.write_text("00\n")

    updated = _update_passed_cache(
        cache,
        [
            {"opcode": "60", "failed": 0},
            {"opcode": "D0.0", "failed": 1},
        ],
    )

    assert updated == {"00", "60"}
    assert cache.read_text().splitlines() == ["00", "60"]
