from __future__ import annotations

from types import SimpleNamespace

import inertia_decompiler.cli_core as cli_core
from inertia_decompiler.cli_core import (
    DirectClinicPolicy8616,
    _direct_clinic_policy_8616,
    _direct_addr_wall_clock_budget,
    _enforce_function_timeout_cap,
    _missing_expected_return_values_from_embedded_evidence_8616,
    _safe_function_callsite_count_8616,
)


def test_direct_clinic_policy_keeps_non_x86_standard():
    assert (
        _direct_clinic_policy_8616(
            arch_name="AMD64",
            direct_addr_mode=True,
            block_count=80,
            byte_count=700,
            call_site_count=12,
        )
        is DirectClinicPolicy8616.STANDARD
    )


def test_direct_clinic_policy_keeps_whole_binary_standard():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=False,
            block_count=80,
            byte_count=700,
            call_site_count=12,
        )
        is DirectClinicPolicy8616.STANDARD
    )


def test_direct_clinic_policy_uses_aggressive_guard_for_large_x86_function():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=32,
            byte_count=188,
            call_site_count=8,
        )
        is DirectClinicPolicy8616.AGGRESSIVE_GUARD
    )


def test_direct_clinic_policy_uses_fast_peephole_for_call_heavy_medium_x86_function():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=15,
            byte_count=188,
            call_site_count=8,
        )
        is DirectClinicPolicy8616.FAST_PEEPHOLE
    )


def test_direct_clinic_policy_keeps_sparse_medium_x86_function_standard():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=15,
            byte_count=188,
            call_site_count=2,
        )
        is DirectClinicPolicy8616.STANDARD
    )


def test_safe_function_callsite_count_handles_missing_or_failing_getter():
    assert _safe_function_callsite_count_8616(SimpleNamespace()) == 0

    def _raises():
        raise RuntimeError("boom")

    assert _safe_function_callsite_count_8616(SimpleNamespace(get_call_sites=_raises)) == 0
    assert _safe_function_callsite_count_8616(SimpleNamespace(get_call_sites=lambda: [1, 2, 3])) == 3


def test_safe_function_callsite_count_uses_neighbor_call_evidence(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "collect_neighbor_call_targets",
        lambda _func: tuple(range(7)),
    )

    assert _safe_function_callsite_count_8616(SimpleNamespace(get_call_sites=lambda: ())) == 7


def test_function_timeout_cap_keeps_default_cap_without_explicit_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    assert _enforce_function_timeout_cap(240, context="test") == 60


def test_function_timeout_cap_respects_explicit_cli_floor(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    assert _enforce_function_timeout_cap(272, context="test", explicit_timeout_floor=240) == 240


def test_function_timeout_cap_respects_explicit_env_cap(monkeypatch):
    monkeypatch.setenv("INERTIA_MAX_FUNCTION_TIMEOUT", "90")

    assert _enforce_function_timeout_cap(272, context="test", explicit_timeout_floor=240) == 90


def test_direct_addr_wall_clock_budget_respects_explicit_cli_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    assert _direct_addr_wall_clock_budget(240, explicit_timeout=True) >= 240


def test_source_evidence_return_gate_catches_missing_variable_return():
    emitted = """
/// unsigned int clamp_u16(unsigned int value, unsigned int limit)
/// {
///     if (value <= limit) {
///         return value;
///     }
///     return limit;
/// }
unsigned int clamp_u16(unsigned int value, unsigned int limit)
{
    return limit;
}
"""

    missing = _missing_expected_return_values_from_embedded_evidence_8616(emitted)

    assert missing == ["return value(0/1)"]


def test_source_evidence_return_gate_accepts_all_variable_returns():
    emitted = """
/// unsigned int clamp_u16(unsigned int value, unsigned int limit)
/// {
///     if (value <= limit) {
///         return value;
///     }
///     return limit;
/// }
unsigned int clamp_u16(unsigned int value, unsigned int limit)
{
    if (value <= limit)
        return value;
    return limit;
}
"""

    assert _missing_expected_return_values_from_embedded_evidence_8616(emitted) == []


def test_source_evidence_return_gate_accepts_renamed_emitted_arguments():
    emitted = """
/// unsigned int clamp_u16(unsigned int value, unsigned int limit)
/// {
///     if (value <= limit) {
///         return value;
///     }
///     return limit;
/// }
unsigned int clamp_u16(unsigned int limit, unsigned short limit_3)
{
    if (limit_3 >= limit)
        return limit;
    return limit_3;
}
"""

    assert _missing_expected_return_values_from_embedded_evidence_8616(emitted) == []


def test_source_evidence_return_gate_accepts_power_of_two_shift_equivalence():
    emitted = """
/// int switch_fold(int x)
/// {
///     if (x == 3) {
///         return x * 2;
///     }
///     return x - 5;
/// }
int switch_fold(int x)
{
    if (x == 3)
        return x << 1;
    return x - 5;
}
"""

    assert _missing_expected_return_values_from_embedded_evidence_8616(emitted) == []
