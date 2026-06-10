from __future__ import annotations

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.library_function_classifier import (
    LibraryFunctionClass,
    classify_library_function_name,
    filter_code_labels_for_library_policy,
    is_library_like_function_name,
)


def test_cod_proc_labels_are_kept_while_map_runtime_labels_are_filtered():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={
            0x1000: "main",
            0x1010: "Sleep",
            0x1100: "strcpy",
            0x1200: "gettextcolor",
            0x1300: "B$Screen4",
        },
        code_ranges={},
        absolute_addrs=True,
        source_format="ida_map+cod_listing",
        cod_proc_kinds={0x1000: "NEAR", 0x1010: "NEAR"},
    )

    result = filter_code_labels_for_library_policy(metadata, metadata.code_labels)

    assert result.labels == {0x1000: "main", 0x1010: "Sleep"}
    assert result.decisions[0x1000] is LibraryFunctionClass.USER_SOURCE_PROC
    assert result.decisions[0x1010] is LibraryFunctionClass.USER_SOURCE_PROC
    assert result.decisions[0x1100] is LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL
    assert result.decisions[0x1200] is LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL
    assert result.decisions[0x1300] is LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL
    assert result.skipped_count == 3


def test_library_name_classifier_is_conservative_for_sortdemo_sleep():
    assert classify_library_function_name("Sleep") is LibraryFunctionClass.USER_UNCLASSIFIED
    assert not is_library_like_function_name("Sleep")
    assert is_library_like_function_name("strcpy")
    assert is_library_like_function_name("sym.imp.printf")
    assert is_library_like_function_name("B$Screen4")
    assert is_library_like_function_name("$_scroll_window")
