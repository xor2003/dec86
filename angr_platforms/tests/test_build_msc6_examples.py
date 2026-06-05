from scripts.build_msc6_examples import COMPARE16_HARNESS_MAIN, _extract_decompiled_function_definition


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
