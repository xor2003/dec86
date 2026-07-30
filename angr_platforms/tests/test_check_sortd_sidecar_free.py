from __future__ import annotations

import sys
from pathlib import Path

from scripts.check_sortd_sidecar_free import (
    DEFAULT_MAXIMUM_EMPTY,
    DEFAULT_MAXIMUM_TIMEOUTS,
    DEFAULT_MINIMUM_DECOMPILED,
    EXPECTED_SORTD_FUNCTION_ADDRS,
    REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS,
    _parse_args,
    default_decompiler_command,
    default_decompiler_environment,
    evaluate_sortd_transcript,
    mz_executable_image,
)


def _passing_transcript() -> str:
    function_rows = "\n".join(
        f"/* == function {addr:#x} sub_{addr:x} == */\n"
        f"/* failure family: status={'ok' if addr in REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS else 'validation_failed'} "
        "stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=file_sweep "
        f"validation={'passed' if addr in REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS else 'failed'} */"
        for addr in EXPECTED_SORTD_FUNCTION_ADDRS
    )
    return (
        "/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis. */\n"
        "/* source-region discovery evidence: raw_fact_count=20 normalized_fact_count=20 "
        "classified_fact_count=20 materialized_count=20 failure_count=0 failed_addrs=none */\n"
        "/* functions queued for decompilation: 20 */\n"
        "/* info: selected 20 function(s) for decompilation */\n"
        f"{function_rows}\n"
        "/* info: decompilation attempted for 20/20 selected function(s) */\n"
        f"/* summary: decompiled {DEFAULT_MINIMUM_DECOMPILED}/20 selected functions */\n"
    )


def test_mz_executable_image_removes_appended_debug_overlay():
    header = bytearray(32)
    header[:2] = b"MZ"
    header[2:4] = (16).to_bytes(2, "little")
    header[4:6] = (2).to_bytes(2, "little")
    data = bytes(header) + b"\0" * (528 - len(header)) + b"NB02debug"

    assert mz_executable_image(data) == data[:528]


def test_sidecar_free_ratchet_defaults_track_current_whole_file_floor():
    args = _parse_args([])

    assert DEFAULT_MINIMUM_DECOMPILED == 20
    assert DEFAULT_MAXIMUM_EMPTY == 0
    assert DEFAULT_MAXIMUM_TIMEOUTS == 0
    assert args.minimum_decompiled == DEFAULT_MINIMUM_DECOMPILED
    assert args.maximum_empty == DEFAULT_MAXIMUM_EMPTY
    assert args.maximum_timeouts == DEFAULT_MAXIMUM_TIMEOUTS


def test_sidecar_free_lane_runs_default_cli_without_forced_serial_override(monkeypatch):
    monkeypatch.setenv("INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION", "1")
    binary = Path("/tmp/SORTD.EXE")

    assert default_decompiler_command(binary) == (sys.executable, "decompile.py", str(binary))
    assert "INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION" not in default_decompiler_environment()


def test_sidecar_free_ratchet_accepts_complete_catalog_and_current_floor():
    result = evaluate_sortd_transcript(
        _passing_transcript(),
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert result.passed
    assert result.materialized_count == 20
    assert result.attempted_count == 20
    assert result.decompiled_count == 20
    assert result.decompiled_function_addrs == REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS
    assert result.timeout_count == 0


def test_sidecar_free_ratchet_rejects_silent_function_loss():
    transcript = _passing_transcript().replace(
        f"/* == function {EXPECTED_SORTD_FUNCTION_ADDRS[-1]:#x} sub_{EXPECTED_SORTD_FUNCTION_ADDRS[-1]:x} == */",
        "/* == function 0x10f39 sub_10f39 == */",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=5,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "emitted function address set differs from the executable-only oracle" in result.violations


def test_sidecar_free_ratchet_rejects_required_function_acceptance_regression() -> None:
    required_addr = REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS[0]
    transcript = _passing_transcript().replace(
        f"/* == function {required_addr:#x} sub_{required_addr:x} == */\n"
        "/* failure family: status=ok",
        f"/* == function {required_addr:#x} sub_{required_addr:x} == */\n"
        "/* failure family: status=validation_failed",
        1,
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert f"required decompiled function regressions: {required_addr:#x}" in result.violations


def test_sidecar_free_ratchet_rejects_any_traceback():
    result = evaluate_sortd_transcript(
        _passing_transcript() + "\nTraceback (most recent call last):\n",
        decompiler_returncode=2,
        minimum_decompiled=5,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "traceback count 1 exceeds 0" in result.violations


def test_sidecar_free_ratchet_rejects_timeout_label_on_validation_failure():
    transcript = _passing_transcript().replace(
        "/* failure family: status=ok",
        "/* -- c (partial timeout) -- */\n/* failure family: status=validation_failed",
        1,
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=5,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert result.timeout_count == 1
    assert "timeout signal count 1 exceeds 0" in result.violations
