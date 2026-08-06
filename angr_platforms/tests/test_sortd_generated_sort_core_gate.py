"""Tests for the generated SORTD sort-core parity gate."""

from pathlib import Path

from inertia_decompiler.generated_c_function_extraction import (
    load_generated_function_artifacts,
)
from scripts.check_sortd_generated_sort_core import (
    SORT_FUNCTIONS,
    _map_binary_globals,
    extract_generated_functions,
)


def test_behavior_slice_includes_timing_and_speaker_functions() -> None:
    assert 0x10E70 in SORT_FUNCTIONS
    assert 0x10F38 in SORT_FUNCTIONS


def test_extracts_function_definition_without_following_diagnostics() -> None:
    transcript = """
/* == function 0x107b8 sub_107b8 == */
/* -- c -- */
extern unsigned short g_0BA4;
void sub_107b8(unsigned short *left, unsigned short *right)
{
    g_0BA4 += 1;
    left[0] = right[0];
}
[dbg] next worker
/* == function 0x10808 sub_10808 == */
/* -- c -- */
void sub_10808(void)
{
    return;
}
"""

    functions = extract_generated_functions(transcript)

    assert tuple(functions) == (0x107B8, 0x10808)
    assert functions[0x107B8].source.endswith("}\n")
    assert "[dbg]" not in functions[0x107B8].source


def test_extracts_numeric_worker_definition_under_source_label() -> None:
    transcript = """
/* == function 0x10010 main == */
/* -- c -- */
unsigned short sub_10010(void)
{
    return 0;
}
/* == function 0x107b8 Swaps == */
/* -- c -- */
void sub_107b8(unsigned short *left, unsigned short *right)
{
    left[0] = right[0];
}
"""

    functions = extract_generated_functions(transcript)

    assert tuple(functions) == (0x107B8,)
    assert functions[0x107B8].name == "sub_107b8"
    assert "void sub_107b8" in functions[0x107B8].source


def test_extracts_deferred_c_independently_of_marker_order() -> None:
    transcript = """
/* == function 0x10808 sub_10808 == */
/* == function 0x107b8 sub_107b8 == */
#include <DOS.H>
extern unsigned short g_0BA4;
void sub_10808(void) { g_0BA4 = 1; }
void sub_107b8(void) { g_0BA4 = 2; }
"""

    functions = extract_generated_functions(transcript)

    assert 0x107B8 in functions
    assert 0x10808 in functions
    assert "sub_10808" not in functions[0x107B8].source
    assert "sub_107b8" not in functions[0x10808].source


def test_loads_exact_address_named_function_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "000107b8-sub_107b8.c"
    artifact.write_text("void sub_107b8(void) { return; }\n")

    sources = load_generated_function_artifacts(tmp_path, (0x107B8,))

    assert sources == {0x107B8: "void sub_107b8(void) { return; }\n"}


def test_maps_scalar_and_array_globals_to_exact_ds_offsets() -> None:
    source = """
extern g_0B4C_entry g_0B4C[];
extern unsigned short g_0B50[3];
extern unsigned short g_0BA4;
extern long g_0132;
extern unsigned long g_0B48;
"""

    mapped = _map_binary_globals(source)

    assert "#define g_0B4C ((g_0B4C_entry *)(inertia_memory + 0x0B4Cu))" in mapped
    assert "#define g_0B50 ((unsigned short *)(inertia_memory + 0x0B50u))" in mapped
    assert "#define g_0BA4 (*(unsigned short *)(inertia_memory + 0x0BA4u))" in mapped
    assert "#define g_0132 (*(inertia_i32 *)(inertia_memory + 0x0132u))" in mapped
    assert "#define g_0B48 (*(inertia_u32 *)(inertia_memory + 0x0B48u))" in mapped
