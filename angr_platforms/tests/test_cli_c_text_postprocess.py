from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler.cli_c_text_postprocess import (
    _align_unknown_call_names_from_cod_evidence_text,
    _align_function_header_with_cod_source_decl_text,
    _annotate_cod_proc_output,
    _materialize_annotated_cod_declarations_text,
    _materialize_missing_generic_local_declarations_text,
    _materialize_missing_direct_call_prototypes_text,
    _materialize_missing_synthetic_global_declarations_text,
    _normalize_integer_dereference_stores_text,
    _normalize_boolean_conditions,
    _normalize_portable_flat_main_signature_text,
    _dedupe_duplicate_local_declarations_text,
    _collapse_annotated_stack_aliases_text,
    _prune_non_lvalue_arithmetic_assignments,
    _prune_parameter_shadow_declarations_text,
    _prune_standalone_stack_probe_calls_text,
    _prune_weaker_conflicting_prototypes_text,
    _prune_unused_local_declarations_text,
    _prune_unused_staging_assignments,
    _prune_void_call_assignments_text,
    _prune_void_function_return_values_text,
    _rewrite_known_helper_signature_text,
    _source_header_args_unmaterialized_8616,
    _source_function_prototype_decls_from_cod_source_lines,
)


def test_dedupe_duplicate_local_declarations_prefers_function_pointer_decl():
    c_text = """\
int select_and_apply(int which, int value)
{
    unsigned short local_2;
    unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn

    return apply_twice(local_2, value);
}
"""

    rewritten = _dedupe_duplicate_local_declarations_text(c_text)

    assert "unsigned short local_2;\n" not in rewritten
    assert "unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn" in rewritten


def test_dedupe_duplicate_local_declarations_handles_pointer_declarator():
    c_text = """\
int sortdemo_single_pass_swap(void)
{
    unsigned short v24;
    unsigned short changed;
    char *v24;  // 4113

    changed = 0;
    return changed;
}
"""

    rewritten = _dedupe_duplicate_local_declarations_text(c_text)

    assert "unsigned short v24;\n" not in rewritten
    assert "char *v24;  // 4113" in rewritten
    assert "return changed;" in rewritten


def test_missing_generic_local_declarations_recognizes_function_pointer_decl():
    c_text = """\
int select_and_apply(int value)
{
    unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn

    return local_2(value);
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short local_2;\n" not in rewritten
    assert "unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn" in rewritten


def test_dedupe_duplicate_local_declarations_parses_function_pointer_parameter():
    c_text = """\
short apply_twice(unsigned short (*arg)(unsigned short), unsigned short value)
{
    int local_2;  // [bp-0x2]
    int local_2;  // [bp+0x2] fn

    value = arg(value);
    return value;
}
"""

    rewritten = _dedupe_duplicate_local_declarations_text(c_text)

    assert rewritten.count("int local_2;") == 1
    assert "// [bp+0x2] fn" not in rewritten
    assert "value = arg(value);" in rewritten


def test_prune_unused_local_declarations_parses_function_pointer_parameter():
    c_text = """\
short apply_twice(unsigned short (*arg)(unsigned short), unsigned short value)
{
    unsigned short v6;  // ss

    value = arg(value);
    return value;
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned short v6;" not in rewritten
    assert "value = arg(value);" in rewritten


def test_missing_generic_local_declarations_materializes_tmp_temps():
    c_text = """\
int f(void)
{
    vvar_1 = tmp_35 + 1;
    return tmp_35;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short tmp_35;" in rewritten
    assert "unsigned short vvar_1;" in rewritten


def test_collapse_annotated_stack_aliases_renames_function_pointer_decl():
    c_text = """\
int select_and_apply(int value)
{
    unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn

    return local_2(value);
}
"""

    rewritten = _collapse_annotated_stack_aliases_text(c_text)

    assert "unsigned short (*fn)(unsigned short);" in rewritten
    assert "// [bp-0x2] fn" in rewritten
    assert "return fn(value);" in rewritten
    assert "local_2" not in rewritten


def test_cod_annotation_renames_function_pointer_parameter_from_stack_alias():
    c_text = """\
short apply_twice(unsigned short (*arg)(unsigned short), unsigned short value)
{
    value = arg(value);
    value = arg(value);
    return value;
}
"""
    metadata = SimpleNamespace(
        stack_aliases={4: "fn", 6: "value"},
        call_names=(),
        global_names=(),
        source_lines=(
            "int apply_twice(int (*fn)(int), int value)",
            "{",
            "value = fn(value);",
            "value = fn(value);",
            "return value;",
            "}",
        ),
    )
    function = SimpleNamespace(name="apply_twice")

    rewritten = _annotate_cod_proc_output(c_text, function, metadata)

    assert "unsigned short (*fn)(unsigned short)" in rewritten
    assert "value = fn(value);" in rewritten
    assert "arg(value)" not in rewritten


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


def test_prune_standalone_stack_probe_calls_removes_prototype_and_call():
    c_text = """\
/* COD annotations:
 * calls = aNchkstk, DrawBar
 */
void aNchkstk(void);
void DrawBar(unsigned short row);

int f(void)
{
    aNchkstk();
    DrawBar(1);
    return 0;
}
"""

    rewritten = _prune_standalone_stack_probe_calls_text(c_text)

    assert "void aNchkstk(void);" not in rewritten
    assert "    aNchkstk();" not in rewritten
    assert "calls = aNchkstk, DrawBar" in rewritten
    assert "DrawBar(1);" in rewritten


def test_source_header_args_unmaterialized_refuses_void_header_when_generated_arg_is_live():
    c_text = """\
void InsertionSort(char arg, char arg_6)
{
    arg_6 = 1;
    return;
}
"""

    blocked = _source_header_args_unmaterialized_8616(
        c_text,
        func_name="InsertionSort",
        source_decl="void InsertionSort(void)",
        source_arg_text=None,
    )

    assert blocked is True

    old_style_blocked = _source_header_args_unmaterialized_8616(
        c_text,
        func_name="InsertionSort",
        source_decl="void InsertionSort()",
        source_arg_text=None,
    )

    assert old_style_blocked is True


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


def test_materialize_annotated_cod_declarations_uses_source_void_return_for_callee():
    c_text = """void Caller(void) {
    Swaps(1, 2);
}
"""
    metadata = SimpleNamespace(
        source_lines=("void Caller(void)", "{", "Swaps(1, 2);", "}"),
        call_names=("Swaps",),
        global_names=(),
    )
    function = SimpleNamespace(name="Caller")

    rewritten = _materialize_annotated_cod_declarations_text(
        c_text,
        function,
        metadata,
        source_return_types={"Swaps": "void"},
    )

    assert "void Swaps();" in rewritten
    assert "int Swaps();" not in rewritten


def test_materialize_annotated_cod_declarations_uses_local_source_void_return_for_header():
    c_text = """short Swaps(unsigned short *bar1, unsigned short *bar2)
{
    bar1[0] = bar2[0];
}
"""
    metadata = SimpleNamespace(
        source_lines=("short Swaps(unsigned short *bar1, unsigned short *bar2)", "{", "bar1[0] = bar2[0];", "}"),
        source_return_lines=(),
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _materialize_annotated_cod_declarations_text(
        c_text,
        function,
        metadata,
        source_return_types={"Swaps": "void"},
    )

    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" in rewritten
    assert "short Swaps(unsigned short *bar1, unsigned short *bar2)" not in rewritten


def test_materialize_missing_direct_call_prototypes_uses_source_void_return():
    c_text = """void Caller(void)
{
    Swaps(1, 2);
}
"""

    rewritten = _materialize_missing_direct_call_prototypes_text(
        c_text,
        source_return_types={"Swaps": "void"},
    )

    assert "void Swaps();" in rewritten
    assert "int Swaps();" not in rewritten


def test_helper_call_format_keeps_codegen_header_for_custom_source_pointer_type():
    c_text = """void Swaps(unsigned short *bar1, unsigned short *bar2)
{
    bar1[0] = bar2[0];
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void Swaps( BAR *bar1, BAR *bar2 )",
            "{",
            "}",
        )
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _align_function_header_with_cod_source_decl_text(c_text, function, metadata)

    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" in rewritten
    assert "BAR *" not in rewritten


def test_cod_annotation_keeps_codegen_header_for_custom_source_pointer_type():
    c_text = """void Swaps(unsigned short *bar1, unsigned short *bar2)
{
    unsigned short local_2;
    local_2 = bar1[0];
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void Swaps( BAR *bar1, BAR *bar2 )",
            "{",
            "}",
        ),
        stack_aliases={4: "bar1", 6: "bar2"},
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" in rewritten
    assert "BAR *" not in rewritten


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


def test_prune_void_function_return_values_text_preserves_address_qualified_call_side_effect():
    c_text = """void main(void)
{
    return ::0x1294f::setvideomode(65535);
}
"""

    rewritten = _prune_void_function_return_values_text(c_text)

    assert "return ::0x1294f::setvideomode" not in rewritten
    assert "::0x1294f::setvideomode(65535);" in rewritten
    assert "return;" not in rewritten


def test_prune_void_call_assignments_preserves_call_side_effect():
    c_text = """void DrawTime();
void f(void)
{
    ax_3 = DrawTime(2189);
}
"""

    rewritten = _prune_void_call_assignments_text(c_text)

    assert "ax_3 = DrawTime" not in rewritten
    assert "DrawTime(2189);" in rewritten


def test_known_helper_arity_mismatch_preserves_return_type():
    c_text = """void f(void)
{
    ax_2 = aNldiv(3761);
}
"""

    rewritten = _materialize_missing_direct_call_prototypes_text(c_text)

    assert "long aNldiv();" in rewritten
    assert "int aNldiv();" not in rewritten


def test_normalize_boolean_conditions_materializes_empty_label_statement():
    c_text = """void f(void)
{
    if (x)
    {
LABEL_114d:
    }
}
"""

    rewritten = _normalize_boolean_conditions(c_text)

    assert "LABEL_114d:;" in rewritten
    assert "LABEL_114d:\n    }" not in rewritten


def test_normalize_boolean_conditions_simplifies_negated_zero_one_ternary_for_loop():
    c_text = """void f(void)
{
    for (i = 1; !((i < g_rows ? 0 : 1)); i = i + 1)
    {
        step(i);
    }
}
"""

    rewritten = _normalize_boolean_conditions(c_text)

    assert "for (i = 1; i < g_rows; i = i + 1)" in rewritten
    assert "? 0 : 1" not in rewritten


def test_normalize_integer_dereference_stores_text_refuses_fake_segment_zero_store():
    c_text = """\
void f(void)
{
    *(vvar_1398 + 1) = vvar_1401;
}
"""

    rewritten = _normalize_integer_dereference_stores_text(c_text)

    assert rewritten == c_text
    assert "SEG_U8(0," not in rewritten


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


def test_prune_unused_local_declarations_text_removes_commented_generated_memory_and_segment_locals():
    c_text = """
int demo(int i)
{
    unsigned short ds;  // ds
    char mem_0042;  // [0x42]
    char tmp_2;  // [bp-0x4]
    unsigned short tmp; // [bp-0x2] tmp
    tmp = i;
    return tmp;
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned short ds;" not in rewritten
    assert "char mem_0042;" not in rewritten
    assert "char tmp_2;" not in rewritten
    assert "unsigned short tmp;" in rewritten
    assert "return tmp;" in rewritten


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


def test_materialize_synthetic_globals_declares_generated_scalar_hex_global_without_metadata():
    c_text = """
int f(void)
{
    return g_ba4 >> 8;
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short g_ba4;" in rewritten
    assert rewritten.index("extern unsigned short g_ba4;") < rewritten.index("int f(void)")


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


def test_source_function_prototype_decls_from_cod_source_lines_refuses_return_call_statement():
    prototypes = _source_function_prototype_decls_from_cod_source_lines(
        (
            "int helper(int value);",
            "return apply_twice(fn, value);",
            "if (which) inc_one(value);",
        )
    )

    assert prototypes == {"helper": "int helper(int value);"}


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


def test_prune_unused_staging_assignments_keeps_unused_call_result_side_effects():
    c_text = """
void QuickSort(int iLow, int iHigh)
{
    unsigned short vvar_97;
    unsigned short vvar_arg;

    vvar_arg = iLow;
    vvar_97 = Swaps(SEG_PTR(ds, (vvar_arg << 1) + 2892), SEG_PTR(ds, (iHigh << 1) + 2892));
    return;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "vvar_arg = iLow;" in rewritten
    assert "vvar_97 = Swaps" not in rewritten
    assert "    Swaps(SEG_PTR(ds, (vvar_arg << 1) + 2892), SEG_PTR(ds, (iHigh << 1) + 2892));" in rewritten


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


def test_materialize_missing_generic_local_declarations_text_does_not_declare_runtime_mem_helpers():
    c_text = """
void ReInitBars(void)
{
    char mem_08F0;
    unsigned short v15;

    v15 = MEM_U16(&mem_08F0);
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "int MEM_U16();" not in rewritten
    assert "MEM_U16(&mem_08F0)" in rewritten


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
