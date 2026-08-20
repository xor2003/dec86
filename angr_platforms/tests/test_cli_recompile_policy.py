from __future__ import annotations

from pathlib import Path

import pytest

import inertia_decompiler.cli_core as cli_core
import inertia_decompiler.cli_decompilation as cli_decompilation
import inertia_decompiler.recompile_check as recompile_check
from inertia_decompiler.cli_arg_parser import parse_cli_arguments
from inertia_decompiler.recompile_check import (
    MSC_DOS_CHECK_POLICY_ENV,
    MscDosCheckPolicy,
    RecompileCheckOutcome,
    RecompileCheckResult,
    check_c_recompiles_8616,
    msc_dos_check_policy_8616,
    msc_dos_check_skip_reason_8616,
    msc_dos_toolchain_unavailable_reason_8616,
    recompile_policy_notice_8616,
)

_PAYLOAD = "int sub_1000(void)\n{\n    return 0;\n}\n"


def _result(
    *,
    target: str,
    passed: bool,
    stderr: str = "",
    outcome: RecompileCheckOutcome | None = None,
    payload: str = _PAYLOAD,
) -> RecompileCheckResult:
    return RecompileCheckResult(
        passed=passed,
        target=target,
        exit_code=0 if passed else 1,
        compiler="fake",
        stdout="",
        stderr=stderr,
        command=("fake",),
        checked_payload=payload,
        checked_payload_hash="hash",
        outcome=outcome,
    )


def _fake_checker(msc_result: RecompileCheckResult):
    calls: list[str] = []

    def _check(payload: str, *, target: str = "portable-flat") -> RecompileCheckResult:
        calls.append(target)
        if target == "msc-dos":
            return msc_result
        return _result(target=target, passed=True, payload=payload)

    return _check, calls


@pytest.fixture(autouse=True)
def _isolated_recompile_state(monkeypatch):
    monkeypatch.delenv(MSC_DOS_CHECK_POLICY_ENV, raising=False)
    cli_core._RECOMPILE_RESULT_CACHE_8616.clear()
    cli_decompilation._REPLACEMENT_RECOMPILE_CACHE_8616.clear()
    yield
    cli_core._RECOMPILE_RESULT_CACHE_8616.clear()
    cli_decompilation._REPLACEMENT_RECOMPILE_CACHE_8616.clear()


def test_missing_kvikdos_is_a_typed_toolchain_unavailable_outcome(monkeypatch):
    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: None)

    result = check_c_recompiles_8616(_PAYLOAD, target="msc-dos")

    assert result.passed is False
    assert result.outcome is RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE
    assert result.toolchain_unavailable is True
    assert result.stderr == "kvikdos not found"


def test_missing_msc51_root_is_a_typed_toolchain_unavailable_outcome(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("")
    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: kvikdos)
    monkeypatch.setattr(recompile_check, "_resolve_msc51_root", lambda: None)

    result = check_c_recompiles_8616(_PAYLOAD, target="msc-dos")

    assert result.outcome is RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE
    assert result.stderr == "Microsoft C v5.1 root not found"
    assert msc_dos_toolchain_unavailable_reason_8616() == "Microsoft C v5.1 root not found"


def test_result_outcome_is_derived_from_passed_and_must_stay_consistent():
    assert _result(target="portable-flat", passed=True).outcome is RecompileCheckOutcome.PASSED
    assert _result(target="portable-flat", passed=False).outcome is RecompileCheckOutcome.FAILED
    with pytest.raises(ValueError):
        _result(target="portable-flat", passed=True, outcome=RecompileCheckOutcome.FAILED)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, MscDosCheckPolicy.REQUIRED),
        ("optional", MscDosCheckPolicy.OPTIONAL),
        (" OFF ", MscDosCheckPolicy.OFF),
        ("sometimes", MscDosCheckPolicy.REQUIRED),
    ],
)
def test_policy_env_parsing_falls_back_to_the_strict_default(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv(MSC_DOS_CHECK_POLICY_ENV, raising=False)
    else:
        monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, raw)

    assert msc_dos_check_policy_8616() is expected


def test_skip_reason_only_covers_unavailable_toolchains_or_disabled_policy():
    unavailable = _result(target="msc-dos", passed=False, stderr="kvikdos not found", outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE)
    rejected = _result(target="msc-dos", passed=False, stderr="GEN.C(3) : error C2065: undefined")

    assert msc_dos_check_skip_reason_8616(None, MscDosCheckPolicy.OFF) == "disabled by policy"
    assert msc_dos_check_skip_reason_8616(unavailable, MscDosCheckPolicy.OPTIONAL) == "kvikdos not found"
    assert msc_dos_check_skip_reason_8616(rejected, MscDosCheckPolicy.OPTIONAL) is None
    assert msc_dos_check_skip_reason_8616(unavailable, MscDosCheckPolicy.REQUIRED) is None


def test_collector_required_policy_fails_when_msc_toolchain_is_missing(monkeypatch):
    unavailable = _result(target="msc-dos", passed=False, stderr="kvikdos not found", outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE)
    checker, calls = _fake_checker(unavailable)
    monkeypatch.setattr(cli_core, "check_c_recompiles_8616", checker)

    checked, failure = cli_core._collect_recompilation_payloads_8616(_PAYLOAD + "/* required */\n")

    assert failure == "MS C 5.1 msc-dos syntax check failed: kvikdos not found"
    assert [target for target, _payload in checked] == ["portable-flat"]
    assert calls == ["portable-flat", "msc-dos"]


def test_collector_optional_policy_skips_only_an_unavailable_msc_toolchain(monkeypatch):
    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "optional")
    unavailable = _result(target="msc-dos", passed=False, stderr="kvikdos not found", outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE)
    checker, calls = _fake_checker(unavailable)
    monkeypatch.setattr(cli_core, "check_c_recompiles_8616", checker)

    checked, failure = cli_core._collect_recompilation_payloads_8616(_PAYLOAD + "/* optional */\n")

    assert failure is None
    assert [target for target, _payload in checked] == ["portable-flat"]
    assert calls == ["portable-flat", "msc-dos"]


def test_collector_optional_policy_still_fails_when_msc_compiler_rejects_the_c(monkeypatch):
    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "optional")
    rejected = _result(target="msc-dos", passed=False, stderr="GEN.C(3) : error C2065: 'x' : undefined")
    checker, _calls = _fake_checker(rejected)
    monkeypatch.setattr(cli_core, "check_c_recompiles_8616", checker)

    _checked, failure = cli_core._collect_recompilation_payloads_8616(_PAYLOAD + "/* rejected */\n")

    assert failure == "MS C 5.1 msc-dos syntax check failed: GEN.C(3) : error C2065: 'x' : undefined"


def test_collector_off_policy_never_invokes_the_msc_check(monkeypatch):
    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "off")
    checker, calls = _fake_checker(_result(target="msc-dos", passed=False, stderr="must not run"))
    monkeypatch.setattr(cli_core, "check_c_recompiles_8616", checker)

    checked, failure = cli_core._collect_recompilation_payloads_8616(_PAYLOAD + "/* off */\n")

    assert failure is None
    assert [target for target, _payload in checked] == ["portable-flat"]
    assert calls == ["portable-flat"]


def _stable_snapshot() -> dict[str, dict[str, object]]:
    return {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }


@pytest.mark.parametrize(
    ("policy", "expected_status"),
    [("required", "validation_failed"), ("optional", "ok")],
)
def test_acceptance_gate_follows_the_msc_policy_when_toolchain_is_missing(monkeypatch, policy, expected_status):
    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, policy)
    unavailable = _result(target="msc-dos", passed=False, stderr="kvikdos not found", outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE)
    checker, _calls = _fake_checker(unavailable)
    monkeypatch.setattr(cli_core, "check_c_recompiles_8616", checker)

    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=f"/* {policy} */\n" + _PAYLOAD,
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == expected_status
    if expected_status == "ok":
        assert result.blocker is None
    else:
        assert result.blocker == "MS C 5.1 msc-dos syntax check failed: kvikdos not found"


def test_replacement_recompile_check_respects_the_msc_policy(monkeypatch):
    unavailable = _result(target="msc-dos", passed=False, stderr="kvikdos not found", outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE)
    checker, _calls = _fake_checker(unavailable)
    monkeypatch.setattr(cli_decompilation, "check_c_recompiles_8616", checker)

    assert cli_decompilation._validated_payload_replacement_recompiles_8616(_PAYLOAD + "/* r1 */\n") is False

    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "optional")
    cli_decompilation._REPLACEMENT_RECOMPILE_CACHE_8616.clear()
    assert cli_decompilation._validated_payload_replacement_recompiles_8616(_PAYLOAD + "/* r2 */\n") is True


def test_cli_flag_publishes_policy_through_the_environment(monkeypatch):
    assert parse_cli_arguments(["x.exe"]).msc_dos_check == "required"
    assert parse_cli_arguments(["x.exe", "--msc-dos-check", "optional"]).msc_dos_check == "optional"
    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "off")
    assert parse_cli_arguments(["x.exe"]).msc_dos_check == "off"

    assert cli_core._publish_msc_dos_check_policy_8616("optional") is MscDosCheckPolicy.OPTIONAL
    assert msc_dos_check_policy_8616() is MscDosCheckPolicy.OPTIONAL
    assert cli_core._publish_msc_dos_check_policy_8616("required") is MscDosCheckPolicy.REQUIRED
    assert MSC_DOS_CHECK_POLICY_ENV not in __import__("os").environ
    assert cli_core._publish_msc_dos_check_policy_8616("nonsense") is MscDosCheckPolicy.REQUIRED


def test_policy_notice_explains_the_effective_policy(monkeypatch, tmp_path):
    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: None)
    required_notice = recompile_policy_notice_8616()
    assert required_notice is not None
    assert "--msc-dos-check optional" in required_notice

    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "optional")
    optional_notice = recompile_policy_notice_8616()
    assert optional_notice is not None
    assert "skipped" in optional_notice and "kvikdos not found" in optional_notice

    monkeypatch.setenv(MSC_DOS_CHECK_POLICY_ENV, "off")
    off_notice = recompile_policy_notice_8616()
    assert off_notice is not None
    assert "off" in off_notice

    msc_root = tmp_path / "msc51"
    (msc_root / "bin").mkdir(parents=True)
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("")
    monkeypatch.delenv(MSC_DOS_CHECK_POLICY_ENV, raising=False)
    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: Path(kvikdos))
    monkeypatch.setattr(recompile_check, "_resolve_msc51_root", lambda: Path(msc_root))
    assert recompile_policy_notice_8616() is None
