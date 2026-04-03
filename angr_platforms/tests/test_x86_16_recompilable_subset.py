from angr_platforms.X86_16.recompilable_subset import (
    describe_x86_16_recompilable_subset,
    run_x86_16_recompilable_subset_syntax_checks,
)


def test_x86_16_recompilable_subset_description_is_stable():
    desc = describe_x86_16_recompilable_subset()

    assert [item["name"] for item in desc] == [
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "loadprog_real",
        "dos_loadOverlay_real",
    ]
    assert all("expected_kind" in item and "note" in item for item in desc)


def test_x86_16_recompilable_subset_syntax_checks_pass():
    results = run_x86_16_recompilable_subset_syntax_checks()

    assert all(result["syntax_ok"] for result in results)
    assert all(result["compile_ok"] for result in results)
    assert all(result["shape_ok"] for result in results)
    assert {result["name"] for result in results} == {
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "loadprog_real",
        "dos_loadOverlay_real",
    }
