from __future__ import annotations

from inertia_decompiler.decompilation_quality import assess_decompiled_c_text, assess_source_backed_c_text


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
        "int rand(void)\n"
        "{\n"
        "    int value;\n"
        "    value = sub_2cc0();\n"
        "    return value;\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()


def test_assess_decompiled_c_text_rejects_stack_base_return_escape() -> None:
    assessment = assess_decompiled_c_text(
        "int rel_i16(int a, int b)\n"
        "{\n"
        "    unsigned short sp_0;\n"
        "    return sp_0;\n"
        "}\n"
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


def test_assess_source_backed_c_text_rejects_unresolved_temporaries() -> None:
    assessment = assess_source_backed_c_text(
        "void SwapBars(void)\n"
        "{\n"
        "    int v1;\n"
        "    int *vvar_18;\n"
        "    vvar_18 = &v1;\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "unresolved-vvar" in assessment.markers


def test_assess_source_backed_c_text_rejects_raw_segmented_globals() -> None:
    assessment = assess_source_backed_c_text(
        "void DrawBar(void)\n"
        "{\n"
        "    DrawOne(SEG_U16(ds, 0x0b4c), mem_0B4E);\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "raw-ds-segmented-access" in assessment.markers
    assert "raw-memory-symbol" in assessment.markers


def test_assess_source_backed_c_text_accepts_generic_c() -> None:
    assessment = assess_source_backed_c_text(
        "void HeapSort(void)\n"
        "{\n"
        "    while (i > 1) {\n"
        "        SwapBars(i, 1);\n"
        "        i -= 1;\n"
        "    }\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()
