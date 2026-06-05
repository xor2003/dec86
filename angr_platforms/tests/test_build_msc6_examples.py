from scripts.build_msc6_examples import (
    COMPARE16_HARNESS_MAIN,
    _child_trace_path,
    _extract_decompiled_function_definition,
    _make_decompile_env,
)


def test_extract_decompiled_function_definition_handles_multiline_header():
    text = """
#include <stdint.h>

/// int cmp_i16(int a, int b)
int cmp_i16(int a, int b)

{
    if (b > a)
        return -1;
    return 0;
}
"""

    body = _extract_decompiled_function_definition(text, "cmp_i16")

    assert body.startswith("int cmp_i16(int a, int b)")
    assert "return -1;" in body


def test_compare16_fallback_harness_checks_rel_i16_calls():
    assert "rel_i16(-2, 5)" in COMPARE16_HARNESS_MAIN
    assert "rel_i16(9, 3)" in COMPARE16_HARNESS_MAIN
    assert "rel_i16(7, 7)" in COMPARE16_HARNESS_MAIN
    assert "in_window_i16(-2, 5)" not in COMPARE16_HARNESS_MAIN


def test_child_trace_path_keeps_suffix_and_sanitizes_label():
    assert _child_trace_path("trace.agent.txt", "CMP32 compare_unsigned") == "trace.agent.CMP32_compare_unsigned.txt"
    assert _child_trace_path("trace", "CMP32/attempt:1") == "trace.CMP32_attempt_1"


def test_decompile_env_derives_child_trace_file(monkeypatch, tmp_path):
    trace_path = tmp_path / "msc.trace.txt"
    monkeypatch.setenv("INERTIA_OTEL_SPAN_FILE", str(trace_path))

    env = _make_decompile_env(False, trace_label="CMP32.compare_unsigned")

    assert env["INERTIA_ENABLE_TAIL_VALIDATION"] == "1"
    assert env["INERTIA_OTEL_SPAN_FILE"] == str(tmp_path / "msc.trace.CMP32.compare_unsigned.txt")
