"""Regression tests for accepted generated-C payload identity."""

from __future__ import annotations

import hashlib
import inspect
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

import inertia_decompiler.cli_core as cli_core
from inertia_decompiler.accepted_payload_integrity import (
    AcceptedPayloadIntegrityVerdict8616,
    verify_accepted_payload_integrity_8616,
)
from inertia_decompiler.direct_addr_failure_family import build_failure_family_snapshot
from inertia_decompiler.work_items import FunctionWorkResult


def _accepted_result(payload: str) -> FunctionWorkResult:
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return FunctionWorkResult(
        index=1,
        status="ok",
        payload=payload,
        debug_output="",
        function=SimpleNamespace(addr=0x1000, name="sub_1000"),
        function_cfg=None,
        tail_validation={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "stable"},
        },
        validated_payload_hash=digest,
        gcc_checked_payload_hash=digest,
        failure_family_snapshot=build_failure_family_snapshot(
            status="ok",
            failure_stage=None,
            fallback_kind="direct_addr",
            tail_validation_verdict="passed",
            artifact_path="0x1000:sub_1000",
        ),
    )


def test_accepted_payload_integrity_rejects_post_validation_replacement() -> None:
    accepted = "int sub_1000(void) { return 1; }\n"
    digest = hashlib.sha256(accepted.encode("utf-8")).hexdigest()

    report = verify_accepted_payload_integrity_8616(
        "int sub_1000(void) { return 0; }\n",
        validated_payload_hash=digest,
        gcc_checked_payload_hash=digest,
    )

    assert report.verdict is AcceptedPayloadIntegrityVerdict8616.VALIDATED_PAYLOAD_MISMATCH
    assert not report.passed


def test_accepted_payload_integrity_import_stays_outside_work_item_graph() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "import inertia_decompiler.accepted_payload_integrity; "
                "raise SystemExit(int('inertia_decompiler.work_items' in sys.modules))"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_direct_cache_artifact_refuses_post_validation_replacement() -> None:
    result = _accepted_result("int sub_1000(void) { return 1; }\n")
    replaced_result = replace(result, payload="int sub_1000(void) { return 0; }\n")
    context = SimpleNamespace(
        args=SimpleNamespace(
            ignore_local_sidecar_hints=False,
            binary=SimpleNamespace(),
            c_target="portable-flat",
        ),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x1000),
        lst_metadata=object(),
    )

    artifact = cli_core._direct_request_cache_artifact_for_result_8616(
        context,
        replaced_result,
        function_addr=0x1000,
        function_name="sub_1000",
    )

    assert artifact is None


def test_direct_emitter_refuses_post_validation_replacement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _accepted_result("int sub_1000(void) { return 1; }\n")
    replaced_result = replace(result, payload="int sub_1000(void) { return 0; }\n")

    status = cli_core._emit_direct_cache_hit_8616(
        SimpleNamespace(args=SimpleNamespace()),
        replaced_result,
        function=result.function,
        function_cfg=None,
        emit_function_header=False,
        project_for_worker_result=None,
    )
    captured = capsys.readouterr()

    assert status == 4
    assert captured.out == ""
    assert "accepted generated-C payload integrity=validated_payload_mismatch" in captured.err


def test_direct_cli_contains_no_function_specific_result_substitution() -> None:
    source = inspect.getsource(cli_core._run_direct_addr_cli_8616).lower()

    assert "tidshowrange" not in source
    assert "drawradaralt" not in source
    assert "drawcockpit" not in source
    assert "cod annotations: calls" not in source
