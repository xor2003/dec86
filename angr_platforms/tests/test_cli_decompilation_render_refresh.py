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


def test_expected_loop_presence_score_uses_cod_source_evidence():
    cod_metadata = SimpleNamespace(
        source_lines=(
            "int f(void)",
            "{",
            "    for (i = 0; i < 3; ++i) {",
            "        x += i;",
            "    }",
            "}",
        )
    )
    loop_text = "int f(void) { for (i = 0; i < 3; ++i) { x += i; } return x; }"
    linear_text = "int f(void) { x += 0; return x; }"

    assert cli_decompilation._expected_loop_presence_score_8616(loop_text, cod_metadata) == 1
    assert cli_decompilation._expected_loop_presence_score_8616(linear_text, cod_metadata) == 0


def test_validated_payload_replacement_rejects_source_evidenced_loop_loss():
    cod_metadata = SimpleNamespace(
        source_lines=(
            "int f(void)",
            "{",
            "    for (i = 0; i < 3; ++i) {",
            "        x += i;",
            "    }",
            "    return x;",
            "}",
        ),
        call_names=(),
    )
    current_payload = "int f(void) { for (i = 0; i < 3; ++i) { x += i; } return x; }"
    validated_payload = "int f(void) { x += 0; return x; }"

    evidence = cli_decompilation._validated_payload_replacement_evidence_8616(
        current_payload,
        validated_payload,
        cod_metadata,
    )

    assert evidence.decision is cli_decompilation.ValidatedPayloadReplacementDecision8616.REJECT_WORSE_LOOP_EVIDENCE
    assert evidence.current_loop_score == 1
    assert evidence.validated_loop_score == 0


def test_sidecar_cod_metadata_resolver_accepts_structural_metadata(tmp_path):
    cod_path = tmp_path / "TEST.COD"
    cod_path.write_text(
        "\n".join(
            (
                "_f\tPROC NEAR",
                ";|*** int f(void)",
                ";|*** {",
                ";|***     for (i = 0; i < 3; ++i) {",
                ";|***         x += i;",
                ";|***     }",
                ";|***     return x;",
                ";|*** }",
                "\t*** 0000\tc3 \t\tret",
                "_f\tENDP",
            )
        ),
        encoding="utf-8",
    )
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(
            cod_path=str(cod_path),
            cod_proc_kinds={0x1000: "NEAR"},
        )
    )
    function = SimpleNamespace(addr=0x1000, name="f")

    metadata = cli_decompilation._sidecar_cod_metadata_for_function(
        project,
        function,
        tmp_path / "TEST.EXE",
        None,
    )

    assert metadata is not None
    assert cli_decompilation._expected_loop_count_from_cod_metadata_8616(metadata) == 1


def test_function_profile_ignores_proven_stack_probe_calls(monkeypatch):
    stack_probe_target = 0x1504
    operand = SimpleNamespace(type=2, imm=stack_probe_target)
    call_insn = SimpleNamespace(mnemonic="call", op_str=f"{stack_probe_target:#x}", operands=(operand,))
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(call_insn,)))
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda _addr, opt_level=0: block),
        _inertia_original_linear_delta=0xF132,
        _inertia_original_project=SimpleNamespace(),
    )
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1000},
        get_call_sites=lambda: (0x1006,),
    )

    def identify_helper(candidate_project, candidate_addr):
        if candidate_project is project:
            return None
        if candidate_addr == 0x10636:
            return SimpleNamespace(kind=cli_decompilation.CompilerHelperEvidenceKind8616.STACK_PROBE)
        return None

    monkeypatch.setattr(cli_decompilation, "identify_x86_16_compiler_helper_at_8616", identify_helper)

    profile = cli_decompilation._function_decompilation_profile(function, 11, 0x83)

    assert profile["raw_call_site_count"] == 1
    assert profile["call_site_count"] == 0
    assert profile["internal_call_count"] == 0
    assert profile["stack_probe_call_count"] == 1


def test_preferred_options_can_disable_dead_memdefs_without_no_call_guard():
    options = cli_decompilation._preferred_decompiler_options(
        11,
        0x83,
        disable_dead_memdefs=True,
    )

    assert options == [("remove_dead_memdefs", False)]
