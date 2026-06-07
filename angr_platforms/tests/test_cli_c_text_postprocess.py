from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler.cli_c_text_postprocess import (
    _align_unknown_call_names_from_cod_evidence_text,
    _materialize_annotated_cod_declarations_text,
    _materialize_missing_generic_local_declarations_text,
    _materialize_missing_synthetic_global_declarations_text,
    _normalize_portable_flat_main_signature_text,
    _collapse_annotated_stack_aliases_text,
    _prune_non_lvalue_arithmetic_assignments,
    _prune_parameter_shadow_declarations_text,
    _prune_weaker_conflicting_prototypes_text,
    _prune_unused_local_declarations_text,
    _prune_unused_staging_assignments,
    _prune_void_function_return_values_text,
    _rewrite_known_helper_signature_text,
    _source_function_prototype_decls_from_cod_source_lines,
)


def test_text_cod_call_alignment_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("INERTIA_ENABLE_LEGACY_TEXT_CALL_NAME_ALIGNMENT", raising=False)
    c_text = """/* COD annotations:
 * calls = aNchkstk
 */
void f(void)
{
    sub_10079();
}
"""

    rewritten = _align_unknown_call_names_from_cod_evidence_text(c_text)

    assert rewritten == c_text
    assert "sub_10079();" in rewritten
    assert "aNchkstk();" not in rewritten


def test_materialize_annotated_cod_declarations_text_ignores_comment_pointer_false_positive():
    c_text = """
/* comment:
 * iRow2 is mentioned here but is not a pointer.
 */
int SwapBars(int iRow1, int iRow2)
{
    DrawBar(iRow1);
    DrawBar(iRow2);
    DrawTime(iRow1);
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "/* SwapBars - Calls DrawBar twice to switch the two bars in iRow1 and",
            " * iRow2, then calls DrawTime to update the time.",
            " */",
            "void SwapBars( int iRow1, int iRow2 )",
            "{",
            "DrawBar( iRow1 );",
            "DrawBar( iRow2 );",
            "DrawTime( iRow1 );",
            "}",
        ),
        global_names=(),
    )
    function = SimpleNamespace(name="SwapBars")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "int *iRow2" not in rewritten
    assert "SwapBars(int iRow1, int iRow2)" in rewritten or "SwapBars( int iRow1, int iRow2 )" in rewritten


def test_known_helper_signature_text_refuses_authoritative_codegen_signature():
    c_text = """void _dos_getProcessId(int pid)
{
    return;
}
"""
    function = SimpleNamespace(name="_dos_getProcessId")
    codegen = SimpleNamespace(_inertia_codegen_signature_authoritative_8616=True)

    rewritten = _rewrite_known_helper_signature_text(c_text, function, codegen=codegen)

    assert rewritten == c_text


def test_prune_void_function_return_values_text_preserves_call_side_effect():
    c_text = """void SwapBars(int iRow1)
{
    return DrawTime(iRow1);
}
"""

    rewritten = _prune_void_function_return_values_text(c_text)

    assert "return DrawTime" not in rewritten
    assert "DrawTime(iRow1);" in rewritten
    assert "return;" not in rewritten


def test_prune_unused_staging_assignments_drops_self_only_and_decorated_staging_lines():
    c_text = """
void SwapBars(int iRow1, int iRow2)
{
    unsigned short vvar_16;
    char s_2;
    unsigned int arg_1;

    s_2 = &s_2 + 2;
    arg_1 = ir_1;
    vvar_16{r8|2b} = &s_6;
    DrawBar(iRow1);
    DrawBar(iRow2);
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "s_2 = &s_2 + 2;" not in rewritten
    assert "arg_1 = ir_1;" not in rewritten
    assert "vvar_16{r8|2b} = &s_6;" not in rewritten
    assert "DrawBar(iRow1);" in rewritten


def test_prune_unused_local_declarations_text_removes_unused_arg_placeholder_locals():
    c_text = """
void SwapBars(int iRow1, int iRow2)
{
    unsigned int arg_1;  // [bp+0x0]

    DrawBar(iRow1);
    DrawBar(iRow2);
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned int arg_1;" not in rewritten
    assert "DrawBar(iRow2);" in rewritten


def test_prune_parameter_shadow_declarations_text_keeps_return_of_parameter_name():
    c_text = """
unsigned int clamp_u16(unsigned int value, unsigned int limit)
{
    unsigned short limit;  // [bp+0x6]

    return limit;
}
"""

    rewritten = _prune_parameter_shadow_declarations_text(c_text)

    assert "unsigned short limit;" not in rewritten
    assert "return limit;" in rewritten


def test_collapse_annotated_stack_aliases_text_collapses_same_slot_local_aliases():
    c_text = """
int rel_i16(int a, int b)
{
    unsigned short mask_2;  // [bp-0x2] mask
    unsigned short mask_3;  // [bp-0x2] mask
    mask_2 = 0;
    if (b > a)
        mask_2 = mask_2 | 1;
    return mask_2;
}
"""

    rewritten = _collapse_annotated_stack_aliases_text(c_text)

    assert "unsigned short mask; // [bp-0x2] mask" in rewritten
    assert "mask_2" not in rewritten
    assert "mask_3" not in rewritten
    assert "return mask;" in rewritten


def test_normalize_portable_flat_main_signature_text_promotes_void_main_and_return_zero():
    c_text = """
void main(void)
{
    InitBars();
    return;
}
"""
    function = SimpleNamespace(name="main")

    rewritten = _normalize_portable_flat_main_signature_text(
        c_text,
        function,
        c_target="portable-flat",
    )

    assert "int main(void)" in rewritten
    assert "return 0;" in rewritten
    assert "void main(void)" not in rewritten


def test_materialize_annotated_cod_declarations_text_inserts_source_prototypes_for_called_functions():
    c_text = """
int main(void)
{
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void main( void );",
            "void InitBars( void );",
            "void InitMenu( void );",
            "void RunMenu( void );",
        ),
        global_names=(),
        call_names=("InitBars", "InitMenu", "RunMenu"),
    )
    function = SimpleNamespace(name="main")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "void InitBars( void );" in rewritten
    assert "void InitMenu( void );" in rewritten
    assert "void RunMenu( void );" in rewritten


def test_materialize_synthetic_globals_uses_function_designator_evidence_for_funcptr_targets():
    c_text = """
int select_and_apply(int which, int value)
{
    unsigned short (*fn)(unsigned short);

    if (which)
        fn = inc_one;
    else
        fn = dec_one;
    return apply_twice(fn, value);
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "int select_and_apply(int which, int value)",
            "{",
            "    int (*fn)(int);",
            "    if (which != 0) {",
            "        fn = inc_one;",
            "    } else {",
            "        fn = dec_one;",
            "    }",
            "    return apply_twice(fn, value);",
            "}",
        ),
        global_names=("inc_one", "dec_one"),
    )

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "int inc_one();" in rewritten
    assert "int dec_one();" in rewritten
    assert "extern unsigned short inc_one" not in rewritten
    assert "extern unsigned short dec_one" not in rewritten


def test_source_function_prototype_decls_from_cod_source_lines_extracts_simple_prototypes():
    prototypes = _source_function_prototype_decls_from_cod_source_lines(
        (
            "void main( void );",
            "void InitBars( void );",
            "int helper(unsigned short x);",
            "{",
        )
    )

    assert prototypes["main"] == "void main( void );"
    assert prototypes["InitBars"] == "void InitBars( void );"
    assert prototypes["helper"] == "int helper(unsigned short x);"


def test_source_function_prototype_decls_from_cod_source_lines_keeps_comment_suffixed_prototypes():
    prototypes = _source_function_prototype_decls_from_cod_source_lines(
        (
            "void InitMenu( void  );             // Menu Functions",
            "void InitBars( void  );             // Bar functions",
        )
    )

    assert prototypes["InitMenu"] == "void InitMenu( void  );"
    assert prototypes["InitBars"] == "void InitBars( void  );"


def test_prune_unused_staging_assignments_drops_transitively_dead_assignment_chains():
    c_text = """
int main(void)
{
    unsigned short vvar_20;
    unsigned short vvar_24;

    vvar_20 = &s_8;
    vvar_24 = vvar_20 - 2 + -2;
    return 0;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "vvar_20 = &s_8;" not in rewritten
    assert "vvar_24 = vvar_20 - 2 + -2;" not in rewritten


def test_prune_unused_staging_assignments_drops_unused_split_stack_suffix_names():
    c_text = """
int main(void)
{
    char s_2_2;

    s_2_2 = vvar_2;
    return 0;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "s_2_2 = vvar_2;" not in rewritten


def test_prune_non_lvalue_arithmetic_assignments_keeps_compound_updates():
    c_text = """
int f(int x)
{
    x -= 1;
    x += 2;
    a + b = c;
    return x;
}
"""

    rewritten = _prune_non_lvalue_arithmetic_assignments(c_text)

    assert "x -= 1;" in rewritten
    assert "x += 2;" in rewritten
    assert "a + b = c;" not in rewritten


def test_materialize_missing_generic_local_declarations_text_handles_mangled_function_names():
    c_text = """
void $_nfree(void)
{
    unsigned short ir_0;
    unsigned short ir_1;
    unsigned short ir_2;

    SEG_U8(ir_0, ir_1 + vvar_2) = SEG_U8(ir_0, ir_1 + vvar_2) + ir_2;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short vvar_2;" in rewritten


def test_materialize_missing_generic_local_declarations_text_handles_generated_locals():
    c_text = """
int main(void)
{
    unsigned short ub;  // [bp-0x16]

    local_16 = ub;
    return local_18;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short ub;" in rewritten
    assert "unsigned short local_16;" in rewritten
    assert "unsigned short local_18;" in rewritten


def test_prune_weaker_conflicting_prototypes_text_downgrades_typed_proto_on_lower_observed_arity():
    c_text = """\
void *memset(void *dst, int ch, unsigned long count);

void DrawBar(int iRow)
{
    memset();
    memset(iRow, 0);
}
"""
    rewritten = _prune_weaker_conflicting_prototypes_text(c_text)
    assert "int memset();" in rewritten
    assert "void *memset(void *dst, int ch, unsigned long count);" not in rewritten
