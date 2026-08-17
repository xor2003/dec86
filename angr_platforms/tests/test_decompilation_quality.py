from __future__ import annotations

from angr_platforms.X86_16.quality import (
    format_x86_16_quality_report_8616,
    measure_x86_16_codegen_quality_8616,
    measure_x86_16_function_quality_8616,
)

from inertia_decompiler.decompilation_quality import assess_decompiled_c_text, assess_final_generated_c_text


def test_x86_16_quality_metrics_count_raw_patterns_and_score() -> None:
    metrics = measure_x86_16_codegen_quality_8616(
        "void f(void) { if (tmp_14 && flags) { x = ((ss << 4) + 2); } CmpNE(a, b); }",
        function_name="f",
        function_addr=0x1234,
        validation_uncollected=True,
    )

    assert metrics.function_name == "f"
    assert metrics.function_addr == 0x1234
    assert metrics.total_bad_patterns == 3
    assert metrics.typed_condition_count == 1
    assert metrics.quality_score == 0.2
    assert metrics.to_dict()["raw_ss_linear_expr_count"] == 1


def test_x86_16_quality_report_aggregates_metrics() -> None:
    aggregate = measure_x86_16_function_quality_8616(
        [
            measure_x86_16_codegen_quality_8616("if (tmp_1) {}", function_name="a"),
            measure_x86_16_codegen_quality_8616("CmpEQ(a, b);", function_name="b"),
        ]
    )

    assert aggregate["function_count"] == 2
    assert aggregate["total_tmp_conditions"] == 1
    assert aggregate["total_typed_conditions"] == 1

    report = format_x86_16_quality_report_8616(aggregate)
    assert "Quality Report (2 functions)" in report
    assert "tmp conditions:          1" in report


def test_assess_decompiled_c_text_rejects_raw_ir_shaped_output() -> None:
    assessment = assess_decompiled_c_text(
        "void sub(void) {\n"
        "    STORE(addr=stack_base-2, data=(Reference vvar_4{s0|1b}), size=2, endness=Iend_LE, guard=None)\n"
        "    if (...) { Goto None }\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "store-op" in assessment.markers
    assert "raw-reference" in assessment.markers
    assert "goto-none" in assessment.markers


def test_assess_decompiled_c_text_accepts_normal_c() -> None:
    assessment = assess_decompiled_c_text(
        "int rand(void)\n{\n    int value;\n    value = sub_2cc0();\n    return value;\n}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()


def test_assess_decompiled_c_text_rejects_stack_base_return_escape() -> None:
    assessment = assess_decompiled_c_text(
        "int rel_i16(int a, int b)\n{\n    unsigned short sp_0;\n    return sp_0;\n}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "stack-base-return-escape" in assessment.markers


def test_assess_decompiled_c_text_rejects_stack_base_address_escape() -> None:
    assessment = assess_decompiled_c_text(
        "int nested_loops(int limit)\n"
        "{\n"
        "    unsigned short stack_base;\n"
        "    return *((short *)(v2 * 16 + (unsigned int)(stack_base + -2)));\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "stack-base" in assessment.markers


def test_assess_final_generated_c_text_rejects_unresolved_temporaries() -> None:
    assessment = assess_final_generated_c_text("int SwapBars(void)\n{\n    return vvar_18;\n}\n")

    assert assessment.reject_as_decompiled is True
    assert "unresolved-vvar" in assessment.markers


def test_assess_final_generated_c_text_accepts_declared_generic_temporary() -> None:
    assessment = assess_final_generated_c_text(
        "int SwapBars(void)\n{\n    int vvar_18;\n    vvar_18 = 1;\n    return vvar_18;\n}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert "unresolved-vvar" not in assessment.markers


def test_assess_final_generated_c_text_rejects_raw_segmented_globals() -> None:
    assessment = assess_final_generated_c_text("void DrawBar(void)\n{\n    DrawOne(SEG_U16(ds, 0x0b4c), mem_0B4E);\n}\n")

    assert assessment.reject_as_decompiled is True
    assert "raw-ds-segmented-access" in assessment.markers
    assert "raw-memory-symbol" in assessment.markers


def test_assess_final_generated_c_text_accepts_generic_c() -> None:
    assessment = assess_final_generated_c_text(
        "void HeapSort(void)\n{\n    while (i > 1) {\n        SwapBars(i, 1);\n        i -= 1;\n    }\n}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()


def test_assess_final_generated_c_text_rejects_read_unassigned_stack_local() -> None:
    assessment = assess_final_generated_c_text(
        "void InsertionSort(void)\n"
        "{\n"
        "    unsigned short barTemp; // [bp-0x8] barTemp\n"
        "    unsigned short iLength; // [bp-0x6] iLength\n"
        "    unsigned short iRow; // [bp-0x2] iRow\n"
        "    for (iRow = 0; cRow > iRow; iRow = iRow + 1)\n"
        "    {\n"
        "        if (abarWork[iRow] <= iLength)\n"
        "            break;\n"
        "        abarWork[iRow] = barTemp;\n"
        "    }\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "unassigned-stack-local" in assessment.markers


def test_assess_final_generated_c_text_accepts_assigned_stack_local() -> None:
    assessment = assess_final_generated_c_text(
        "void InsertionSort(void)\n"
        "{\n"
        "    unsigned short barTemp; // [bp-0x8] barTemp\n"
        "    unsigned short iLength; // [bp-0x6] iLength\n"
        "    barTemp = abarWork[iRow];\n"
        "    iLength = barTemp;\n"
        "    if (abarWork[iRow] <= iLength)\n"
        "        abarWork[iRow] = barTemp;\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False


def test_assess_final_generated_c_text_accepts_address_taken_stack_buffer() -> None:
    assessment = assess_final_generated_c_text(
        "void DrawBar(void)\n"
        "{\n"
        "    unsigned int cSpace; // [bp-0x2e] cSpace\n"
        "    unsigned int achT; // [bp-0x2c] achT\n"
        "    cSpace = cRow - (abarWork[iRow] & 255);\n"
        "    memset(&achT, 223, abarWork[iRow] & 255);\n"
        "    memset(achT + (abarWork[iRow] & 255), 32, cSpace);\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()
