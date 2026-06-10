from types import SimpleNamespace

from inertia_decompiler import cli_decompilation


def test_regenerate_prefers_cfunc_text_after_call_arg_materialization(monkeypatch):
    stale_text = "void f(void) { Sleep(); }\n"
    fresh_text = "void f(void) { Sleep(SEG_U32(ds, 306)); }\n"

    codegen = SimpleNamespace(
        text=stale_text,
        cfunc=SimpleNamespace(c_repr=lambda: fresh_text),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        _inertia_callsite_args_ast_materialized_8616=True,
        _inertia_codegen_call_args_render_refresh_required_8616=True,
    )

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == fresh_text
    assert codegen.text == fresh_text


def test_render_candidate_score_refuses_stale_stack_base_when_calls_tie():
    stale_text = """
int main(void)
{
    unsigned short v;
    v = stack_base + -8;
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""
    clean_text = """
int main(void)
{
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""

    assert cli_decompilation._render_candidate_score_8616(clean_text, None) > (
        cli_decompilation._render_candidate_score_8616(stale_text, None)
    )
