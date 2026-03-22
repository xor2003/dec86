from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from angr_platforms.X86_16.verification_80286 import (
    REPO_ROOT,
    load_moo_cases,
    summarize_results,
    summary_to_json,
    verify_case,
    verify_moo_file,
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
