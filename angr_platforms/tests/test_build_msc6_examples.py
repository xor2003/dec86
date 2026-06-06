from scripts.build_msc6_examples import (
    COMPARE16_HARNESS_MAIN,
    DEFAULT_DECOMPILE_SKIP,
    ENUM_UNION_HARNESS_MAIN,
    FALLBACK_EXAMPLE_REBUILD,
    _child_trace_path,
    _extract_decompiled_function_definition,
    _is_decompile_output_acceptable,
    _make_decompile_env,
    _parse_decompile_profile,
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


def test_acceptance_uses_final_clean_tail_validation_over_rejected_lanes():
    stderr = """
[dbg] direct failure family: status=empty validation=failed
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("int f(void) { return 1; }", stderr, profile)

    assert ok is True
    assert reason is None


def test_enum_union_fallback_is_enabled_by_default():
    assert "enum_union" not in DEFAULT_DECOMPILE_SKIP
    assert FALLBACK_EXAMPLE_REBUILD["enum_union"]["functions"] == ("token_cost", "combine_bytes")
    assert "token_cost(TOK_TWO)" in ENUM_UNION_HARNESS_MAIN


def test_medium_structs_has_function_fallback_contract():
    assert "medium_structs" not in DEFAULT_DECOMPILE_SKIP
    assert FALLBACK_EXAMPLE_REBUILD["medium_structs"]["functions"] == (
        "accumulate_pairs",
        "rotate_triplet",
        "find_first_gt",
    )
    assert "struct Pair" in FALLBACK_EXAMPLE_REBUILD["medium_structs"]["prefix"]
    assert "return 255;" in FALLBACK_EXAMPLE_REBUILD["medium_structs"]["harness"]
